"""Finite OpenSSH metadata pins do not silently grant helper execution."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import struct
import threading
import time

import pytest

from recon_cockpit.secure_agent import stock_ssh_runtime as runtime
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def control():
    return ExecutionControl(time.monotonic() + 30)


def elf(*, executable=False):
    raw = bytearray(128 if executable else 64)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', raw, 16, 3, 62, 1)
    if executable:
        struct.pack_into('<Q', raw, 32, 64)
        struct.pack_into('<HH', raw, 54, 56, 1)
        struct.pack_into('<I', raw, 64, 3)
        struct.pack_into('<Q', raw, 72, 128)
        loader = runtime.INTERPRETER.encode() + b'\0'
        struct.pack_into('<Q', raw, 96, len(loader))
        raw.extend(loader)
    return bytes(raw)


def listing(expected):
    rows = ['linux-vdso.so.1 (0x1000)']
    for path in sorted(expected):
        rows.append((Path(path).name + ' => ' if path != runtime.INTERPRETER else '') + path + ' (0x2000)')
    return ('\n'.join(rows) + '\n').encode()


@pytest.fixture
def fake_runtime(monkeypatch):
    """Use real compiled selections; double only installed bytes and ldd."""
    calls = []
    aliases = {p: runtime.LIBRARY_ROOT + 'ld-linux-x86-64.so.2' if p == runtime.INTERPRETER else p
               for p in runtime.DEPENDENCIES}
    raw = {source: elf() for source in aliases.values()}
    raw.update({source: elf(executable=True) for source in runtime._native_files().values()})
    monkeypatch.setattr(runtime.sys, 'platform', 'linux')
    monkeypatch.setattr(runtime.Path, 'resolve', lambda path, **kwargs: Path(aliases.get(str(path), str(path))))
    monkeypatch.setattr(runtime, '_read_file', lambda path, selected_control: raw[path])
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    by_source = {source: runtime._elf_dependencies()[destination]
                 for destination, source in runtime._native_files().items()}
    def probe(argv, timeout, maximum, selected_control):
        calls.append((argv, timeout, maximum, selected_control))
        return listing(by_source[argv[-1]])
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    return calls, raw, aliases


@pytest.mark.parametrize('configuration,case', runtime.spec.TRIALS)
def test_three_fixed_metadata_probes_pin_daemon_helpers_and_selection(fake_runtime, configuration, case):
    calls, _, _ = fake_runtime
    selected_control = control()
    manifest = runtime.inspect_runtime(configuration, case, selected_control)
    assert [call[0] for call in calls] == [['/usr/bin/ldd', source]
        for _, source in sorted(runtime._native_files().items())]
    assert len(calls) == 3 and all(call[1:] == (3, 32768, selected_control) for call in calls)
    assert manifest['runtime_closure_verified'] is manifest['daemon_execution_performed'] is False
    assert manifest['dependency_kind'] == 'fixed_daemon_helpers_and_elf_linked_dependencies_only'
    assert manifest['executables'] == {destination: source for _, source, destination in runtime.spec.SSHD_EXECUTABLES}
    dependencies = manifest['elf_dependencies']
    assert [len(dependencies[path]) for path in (runtime.DESTINATION,
        '/usr/lib/openssh/sshd-session', '/usr/lib/openssh/sshd-auth')] == [7, 22, 21]
    assert set(dependencies['/usr/lib/openssh/sshd-session']) - set(dependencies['/usr/lib/openssh/sshd-auth']) == {
        runtime.LIBRARY_ROOT + 'libwrap.so.0'}
    rows = {row['destination']: row for row in manifest['files']}
    for source, destination, compiled in runtime.spec.compiled_files(configuration, case):
        assert rows[destination] == {'source': source, 'destination': destination,
            'size': len(compiled), 'sha256': hashlib.sha256(compiled).hexdigest()}
    detached = runtime.verify_current(manifest, selected_control)
    assert len(calls) == 3 and detached == manifest and detached is not manifest
    assert len(runtime.manifest_digest(manifest)) == 64
    detached['files'][0]['sha256'] = 'f' * 64
    assert detached != manifest


@pytest.mark.parametrize('configuration,case', [('external', 'O1'), ('A', '/etc/shadow'),
    ('A; sshd', 'O1'), (True, 'O1'), ('B', None)])
def test_invalid_selector_precedes_any_file_or_metadata_process(monkeypatch, configuration, case):
    monkeypatch.setattr(runtime, '_read_file', lambda *args: pytest.fail('invalid selector read a file'))
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('invalid selector spawned a process'))
    with pytest.raises(ValueError): runtime.inspect_runtime(configuration, case, control())


def test_cancelled_inspection_does_not_read_files(monkeypatch):
    cancelled = threading.Event(); cancelled.set()
    monkeypatch.setattr(runtime, '_read_file', lambda *args: pytest.fail('cancelled inspection read a file'))
    with pytest.raises(ExecutionStopped, match='session_cancelled'):
        runtime.inspect_runtime('A', 'O1', ExecutionControl(time.monotonic() + 30, cancelled))


def test_expired_inspection_does_not_read_files(monkeypatch):
    monkeypatch.setattr(runtime, '_read_file', lambda *args: pytest.fail('expired inspection read a file'))
    with pytest.raises(ExecutionStopped, match='session_timeout'):
        runtime.inspect_runtime('A', 'O1', ExecutionControl(time.monotonic() - 1))


def test_metadata_timeout_never_exceeds_remaining_control(fake_runtime):
    calls, _, _ = fake_runtime
    selected_control = ExecutionControl(time.monotonic() + 1)
    runtime.inspect_runtime('A', 'O1', selected_control)
    assert len(calls) == 3 and all(0 < row[1] <= 1 for row in calls)


@pytest.mark.parametrize('fault', ['unsupported_platform', 'untrusted_inspector', 'helper_alias', 'missing_helper'])
def test_unreviewed_platform_paths_or_inspector_fail_without_metadata_process(fake_runtime, monkeypatch, fault):
    _, _, aliases = fake_runtime
    if fault == 'unsupported_platform': monkeypatch.setattr(runtime.sys, 'platform', 'darwin')
    elif fault == 'untrusted_inspector': monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/tmp/ldd')
    elif fault == 'helper_alias': aliases['/usr/lib/openssh/sshd-auth'] = '/tmp/sshd-auth'
    else:
        previous = runtime.Path.resolve
        def missing(path, **kwargs):
            if str(path) == '/usr/lib/openssh/sshd-auth': raise FileNotFoundError('missing helper')
            return previous(path, **kwargs)
        monkeypatch.setattr(runtime.Path, 'resolve', missing)
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('unreviewed runtime reached probe'))
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


def test_probe_cancellation_prevents_following_metadata_process(fake_runtime, monkeypatch):
    cancelled, calls = threading.Event(), []
    def probe(argv, *args):
        calls.append(argv); cancelled.set()
        destination = next(destination for destination, source in runtime._native_files().items() if source == argv[-1])
        return listing(runtime._elf_dependencies()[destination])
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    with pytest.raises(ExecutionStopped, match='session_cancelled'):
        runtime.inspect_runtime('A', 'O1', ExecutionControl(time.monotonic() + 30, cancelled))
    assert calls == [['/usr/bin/ldd', runtime.EXECUTABLE]]


@pytest.mark.parametrize('fault', ['path', 'traversal', 'duplicate', 'extra', 'missing', 'bool_size',
    'too_large', 'digest', 'reordered', 'compiled', 'selection', 'ready', 'executed',
    'helper_source', 'extra_helper', 'helper_dependency', 'aggregate', 'unknown_field'])
def test_recommitted_manifest_cannot_expand_runtime_or_claim_readiness(fake_runtime, fault):
    value = runtime.inspect_runtime('A', 'O1', control())
    row = next(row for row in value['files'] if row['destination'] == runtime.DESTINATION)
    if fault == 'path': row['source'] = '/tmp/sshd'
    elif fault == 'traversal': row['source'] = '/usr/sbin/../sbin/sshd'
    elif fault == 'duplicate': value['files'][-1] = deepcopy(value['files'][0])
    elif fault == 'extra': value['files'].append(deepcopy(row))
    elif fault == 'missing': value['files'].pop()
    elif fault == 'bool_size': row['size'] = True
    elif fault == 'too_large': row['size'] = runtime.MAX_FILE_BYTES + 1
    elif fault == 'digest': row['sha256'] = 'G' * 64
    elif fault == 'reordered': value['files'].reverse()
    elif fault == 'compiled': next(item for item in value['files'] if item['source'].startswith('compiled:'))['sha256'] = 'f' * 64
    elif fault == 'selection': value['configuration'] = 'B'
    elif fault == 'ready': value['runtime_closure_verified'] = True
    elif fault == 'executed': value['daemon_execution_performed'] = True
    elif fault == 'helper_source': value['executables']['/usr/lib/openssh/sshd-auth'] = '/tmp/sshd-auth'
    elif fault == 'extra_helper': value['executables']['/usr/bin/ssh-keygen'] = '/usr/bin/ssh-keygen'
    elif fault == 'helper_dependency': value['elf_dependencies']['/usr/lib/openssh/sshd-auth'] = sorted(runtime.DEPENDENCIES)
    elif fault == 'aggregate':
        for item in value['files']:
            if not item['source'].startswith('compiled:'): item['size'] = runtime.MAX_FILE_BYTES
    else: value['execute'] = True
    with pytest.raises(ValueError): runtime.manifest_digest(value)


@pytest.mark.parametrize('target', ['/usr/sbin/sshd', '/usr/lib/openssh/sshd-session', '/usr/lib/openssh/sshd-auth'])
@pytest.mark.parametrize('fault', ['extra', 'missing', 'duplicate', 'wrapper', 'nonascii', 'missing_library',
    'wrong_soname', 'duplicate_vdso', 'oversized', 'host_config'])
def test_each_executable_requires_its_own_exact_dependency_set(fake_runtime, monkeypatch, target, fault):
    def probe(argv, *args):
        destination = next(destination for destination, source in runtime._native_files().items() if source == argv[-1])
        raw = listing(runtime._elf_dependencies()[destination])
        if argv[-1] != target: return raw
        if fault == 'extra': raw += b'liboutside.so.1 => /tmp/liboutside.so.1 (0x1234)\n'
        elif fault == 'missing': raw = b'\n'.join(raw.splitlines()[:-1])
        elif fault == 'duplicate': raw += raw.splitlines()[1] + b'\n'
        elif fault == 'wrapper': raw += b'not a dynamic executable\n'
        elif fault == 'nonascii': raw += b'\xff\n'
        elif fault == 'missing_library': raw += b'liboutside.so.1 => not found\n'
        elif fault == 'wrong_soname': raw = raw.replace(b'libc.so.6 =>', b'libfake.so.6 =>')
        elif fault == 'duplicate_vdso': raw += b'linux-vdso.so.1 (0x1000)\n'
        elif fault == 'oversized': raw = b' ' * (runtime.MAX_PROBE_BYTES + 1)
        else: raw += b'/etc/pam.d/sshd (0x1234)\n'
        return raw
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


@pytest.mark.parametrize('path', ['/usr/sbin/sshd', '/usr/lib/openssh/sshd-session',
    '/usr/lib/openssh/sshd-auth', runtime.LIBRARY_ROOT + 'libcrypto.so.3'])
def test_changed_file_fails_recheck_without_metadata_process(fake_runtime, monkeypatch, path):
    _, raw, _ = fake_runtime
    value = runtime.inspect_runtime('A', 'O1', control())
    raw[path] += b'changed'
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('verification executed a process'))
    with pytest.raises(IsolationUnavailable, match='pinned manifest'): runtime.verify_current(value, control())


@pytest.mark.parametrize('fault', ['daemon_change', 'helper_change', 'library_change', 'alias_change'])
def test_mid_inspection_changes_cannot_produce_mixed_time_manifest(fake_runtime, monkeypatch, fault):
    _, raw, aliases = fake_runtime
    def probe(argv, *args):
        if fault == 'alias_change': aliases[runtime.LIBRARY_ROOT + 'libcrypto.so.3'] = '/tmp/libcrypto.so.3'
        else:
            path = {'daemon_change': runtime.EXECUTABLE, 'helper_change': '/usr/lib/openssh/sshd-auth',
                    'library_change': runtime.LIBRARY_ROOT + 'libcrypto.so.3'}[fault]
            raw[path] += b'changed'
        destination = next(destination for destination, source in runtime._native_files().items() if source == argv[-1])
        return listing(runtime._elf_dependencies()[destination])
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


@pytest.mark.parametrize('target', ['/usr/sbin/sshd', '/usr/lib/openssh/sshd-session', '/usr/lib/openssh/sshd-auth'])
@pytest.mark.parametrize('fault', ['script', 'architecture', 'loader', 'program_headers'])
def test_all_three_executables_require_supported_elf_before_any_probe(fake_runtime, monkeypatch, target, fault):
    _, raw, _ = fake_runtime
    candidate = bytearray(raw[target])
    if fault == 'script': candidate = bytearray(b'#!/bin/sh\nexec something\n')
    elif fault == 'architecture': struct.pack_into('<H', candidate, 18, 183)
    elif fault == 'loader': candidate[-2] = ord('9')
    else: struct.pack_into('<Q', candidate, 32, 999999)
    raw[target] = bytes(candidate)
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('unsupported ELF reached probe'))
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


def test_regular_reader_refuses_links_fifos_unsafe_permissions_and_size(tmp_path, monkeypatch):
    path = tmp_path / 'runtime'; path.write_bytes(elf()); path.chmod(0o600)
    assert runtime._read_file(str(path), control()) == elf()
    link = tmp_path / 'link'; link.symlink_to(path)
    with pytest.raises(OSError): runtime._read_file(str(link), control())
    fifo = tmp_path / 'fifo'; os.mkfifo(fifo, 0o600)
    with pytest.raises(IsolationUnavailable): runtime._read_file(str(fifo), control())
    path.chmod(0o622)
    with pytest.raises(IsolationUnavailable): runtime._read_file(str(path), control())
    path.chmod(0o600)
    monkeypatch.setattr(runtime.shared, 'MAX_FILE_BYTES', len(elf()) - 1)
    with pytest.raises(IsolationUnavailable): runtime._read_file(str(path), control())


def test_regular_reader_rejects_permission_change_during_read(tmp_path, monkeypatch):
    path = tmp_path / 'runtime'; path.write_bytes(elf()); path.chmod(0o600)
    real_read = runtime.shared.os.read
    def changed(descriptor, count):
        result = real_read(descriptor, count)
        if result: path.chmod(0o644)
        return result
    monkeypatch.setattr(runtime.shared.os, 'read', changed)
    with pytest.raises(IsolationUnavailable, match='changed'): runtime._read_file(str(path), control())


@pytest.mark.parametrize('source,destination', [
    ('/etc/ssh/sshd_config', '/tool/data/sshd_config'),
    ('/usr/lib/openssh/../openssh/sshd-auth', '/usr/lib/openssh/sshd-auth'),
    ('/usr/bin/ssh-keygen', '/tool/sshd'),
    ('/usr/lib/x86_64-linux-gnu/libcrypto.so.3.other', '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'),
    ('/usr/lib/x86_64-linux-gnu/libcrypto.so.3/../../shadow', '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'),
])
def test_host_configuration_and_unreviewed_source_aliases_refuse(source, destination):
    assert not runtime._source_allowed(source, destination)


def test_numeric_library_alias_is_pinned_and_retargeting_detected(fake_runtime):
    _, raw, aliases = fake_runtime
    path = runtime.LIBRARY_ROOT + 'libz.so.1'
    aliases[path] = path + '.3.1'
    raw[aliases[path]] = raw.pop(path)
    value = runtime.inspect_runtime('A', 'O1', control())
    assert next(row for row in value['files'] if row['destination'] == path)['source'] == aliases[path]
    aliases[path] = path + '.4.0'
    with pytest.raises(IsolationUnavailable, match='path changed'): runtime.verify_current(value, control())


def test_manifest_size_bound_is_enforced(fake_runtime, monkeypatch):
    manifest = runtime.inspect_runtime('A', 'O1', control())
    monkeypatch.setattr(runtime, 'MAX_MANIFEST_BYTES', len(runtime.shared._encode(manifest)) - 1)
    with pytest.raises(ValueError, match='closure'): runtime.validate_manifest(manifest)
