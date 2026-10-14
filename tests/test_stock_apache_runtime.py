"""Apache preparation pins a finite module closure without daemon execution."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import struct
import threading
import time

import pytest

from recon_cockpit.secure_agent import stock_apache_runtime as runtime
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
    """Double only native bytes/metadata; compile the real finite selection."""
    calls = []
    aliases = {p: runtime.LIBRARY_ROOT + 'ld-linux-x86-64.so.2' if p == runtime.INTERPRETER else p
               for p in runtime.DEPENDENCIES}
    raw = {source: elf() for source in aliases.values()}
    raw.update({source: elf(executable=destination == runtime.DESTINATION)
                for destination, source in runtime._native_files().items()})
    monkeypatch.setattr(runtime.sys, 'platform', 'linux')
    monkeypatch.setattr(runtime.Path, 'resolve', lambda path, **kwargs: Path(aliases.get(str(path), str(path))))
    monkeypatch.setattr(runtime, '_read_file', lambda path, selected_control: raw[path])
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    def probe(argv, timeout, maximum, selected_control):
        calls.append((argv, timeout, maximum, selected_control))
        return listing(runtime.DEPENDENCIES if argv[-1] == runtime.EXECUTABLE else runtime.MODULE_DEPENDENCIES)
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    return calls, raw, aliases


@pytest.mark.parametrize('configuration,case', [(configuration, case)
    for configuration in ('A', 'B') for case in ('O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'R1', 'R2', 'N1', 'N2', 'N3', 'N4', 'N5')])
def test_inspection_pins_exact_modules_and_compiled_selection_without_launch(fake_runtime, configuration, case):
    calls, _, _ = fake_runtime
    selected = control()
    manifest = runtime.inspect_runtime(configuration, case, selected)
    assert [call[0] for call in calls] == [['/usr/bin/ldd', source]
        for _, source in sorted(runtime._native_files().items())]
    assert len(calls) == 5
    assert all(call[1:] == (3, 32768, selected) for call in calls)
    assert manifest['runtime_closure_verified'] is manifest['daemon_execution_performed'] is False
    assert manifest['dependency_kind'] == 'fixed_modules_and_elf_linked_dependencies_only'
    assert [row['name'] for row in manifest['modules']] == [row[0] for row in runtime.spec.APACHE_MODULES]
    assert len(manifest['elf_dependencies']) == 5
    rows = {row['destination']: row for row in manifest['files']}
    assert rows[runtime.DESTINATION]['source'] == '/usr/sbin/apache2'
    for _, source, destination in runtime.spec.APACHE_MODULES:
        assert rows[destination]['source'] == source
        assert manifest['elf_dependencies'][destination] == sorted(runtime.MODULE_DEPENDENCIES)
    for source, destination, compiled in runtime.spec.compiled_files(configuration, case):
        assert rows[destination] == {'source': source, 'destination': destination,
            'size': len(compiled), 'sha256': hashlib.sha256(compiled).hexdigest()}
    detached = runtime.verify_current(manifest, selected)
    assert len(calls) == 5 and detached == manifest and detached is not manifest
    assert len(runtime.manifest_digest(manifest)) == 64
    detached['files'][0]['sha256'] = 'f' * 64
    assert detached != manifest


@pytest.mark.parametrize('configuration,case', [('external', 'O1'), ('A', '/etc/shadow'),
    ('A; apache2', 'O1'), (True, 'O1'), ('B', None)])
def test_invalid_selector_is_rejected_before_files_or_processes(monkeypatch, configuration, case):
    monkeypatch.setattr(runtime, '_read_file', lambda *args: pytest.fail('invalid selector read a file'))
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('invalid selector spawned a process'))
    with pytest.raises(ValueError):
        runtime.inspect_runtime(configuration, case, control())


def test_cancelled_control_blocks_inspection_before_access(monkeypatch):
    cancelled = threading.Event(); cancelled.set()
    monkeypatch.setattr(runtime, '_read_file', lambda *args: pytest.fail('cancelled inspection read a file'))
    with pytest.raises(ExecutionStopped, match='session_cancelled'):
        runtime.inspect_runtime('A', 'O1', ExecutionControl(time.monotonic() + 30, cancelled))


def test_cancellation_after_metadata_probe_prevents_following_probe(fake_runtime, monkeypatch):
    cancelled = threading.Event()
    calls = []
    def probe(*args):
        calls.append(args[0]); cancelled.set()
        return listing(runtime.DEPENDENCIES)
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    with pytest.raises(ExecutionStopped, match='session_cancelled'):
        runtime.inspect_runtime('A', 'O1', ExecutionControl(time.monotonic() + 30, cancelled))
    assert calls == [['/usr/bin/ldd', runtime.EXECUTABLE]]


@pytest.mark.parametrize('fault', ['path', 'traversal', 'duplicate', 'extra', 'missing', 'bool_size',
    'too_large', 'digest', 'reordered', 'compiled', 'selection', 'ready', 'executed', 'module_source',
    'module_order', 'extra_module', 'module_dependency', 'aggregate', 'unknown_field'])
def test_recommitted_manifest_cannot_expand_files_modules_or_claim_readiness(fake_runtime, fault):
    value = runtime.inspect_runtime('A', 'O1', control())
    row = next(row for row in value['files'] if row['destination'] == runtime.DESTINATION)
    if fault == 'path': row['source'] = '/tmp/apache2'
    elif fault == 'traversal': row['source'] = '/usr/sbin/../sbin/apache2'
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
    elif fault == 'module_source': value['modules'][0]['source'] = '/tmp/mod_mpm_prefork.so'
    elif fault == 'module_order': value['modules'].reverse()
    elif fault == 'extra_module': value['modules'].append({'name': 'proxy_module', 'source': '/usr/lib/apache2/modules/mod_proxy.so', 'destination': '/tool/modules/mod_proxy.so'})
    elif fault == 'module_dependency': value['elf_dependencies']['/tool/modules/mod_alias.so'] = sorted(runtime.DEPENDENCIES)
    elif fault == 'aggregate':
        for item in value['files']:
            if not item['source'].startswith('compiled:'): item['size'] = runtime.MAX_FILE_BYTES
    elif fault == 'unknown_field': value['execute'] = True
    with pytest.raises(ValueError): runtime.manifest_digest(value)


def test_fresh_selection_digest_cannot_relabel_another_compiled_case(fake_runtime):
    value = runtime.inspect_runtime('A', 'O1', control())
    value['case'] = 'R1'
    value['selection_sha256'] = runtime.spec.selection_digest('A', 'R1')
    with pytest.raises(ValueError): runtime.validate_manifest(value)


@pytest.mark.parametrize('target', ['executable', 'module'])
@pytest.mark.parametrize('fault', ['extra', 'missing', 'duplicate', 'wrapper', 'nonascii', 'missing_library',
    'wrong_soname', 'duplicate_vdso', 'oversized', 'host_config'])
def test_each_metadata_probe_must_match_its_own_exact_dependency_set(fake_runtime, monkeypatch, target, fault):
    def probe(argv, *args):
        is_executable = argv[-1] == runtime.EXECUTABLE
        raw = listing(runtime.DEPENDENCIES if is_executable else runtime.MODULE_DEPENDENCIES)
        if is_executable != (target == 'executable'): return raw
        if fault == 'extra': raw += b'liboutside.so.1 => /tmp/liboutside.so.1 (0x1234)\n'
        elif fault == 'missing': raw = b'\n'.join(raw.splitlines()[:-1])
        elif fault == 'duplicate': raw += raw.splitlines()[1] + b'\n'
        elif fault == 'wrapper': raw += b'not a dynamic executable\n'
        elif fault == 'nonascii': raw += b'\xff\n'
        elif fault == 'missing_library': raw += b'liboutside.so.1 => not found\n'
        elif fault == 'wrong_soname': raw = raw.replace(b'libc.so.6 =>', b'libfake.so.6 =>')
        elif fault == 'duplicate_vdso': raw += b'linux-vdso.so.1 (0x1000)\n'
        elif fault == 'oversized': raw = b' ' * (runtime.MAX_PROBE_BYTES + 1)
        elif fault == 'host_config': raw += b'/etc/apache2/mods-enabled/mod_alias.so (0x1234)\n'
        return raw
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


@pytest.mark.parametrize('fault', ['executable_change', 'library_change', 'module_change', 'alias_change'])
def test_changes_across_metadata_probes_fail_before_manifest_returns(fake_runtime, monkeypatch, fault):
    _, raw, aliases = fake_runtime
    def changed(argv, *args):
        if fault == 'executable_change': raw[runtime.EXECUTABLE] += b'changed'
        elif fault == 'library_change': raw[runtime.LIBRARY_ROOT + 'libapr-1.so.0'] += b'changed'
        elif fault == 'module_change': raw['/usr/lib/apache2/modules/mod_alias.so'] += b'changed'
        else: aliases[runtime.LIBRARY_ROOT + 'libapr-1.so.0'] = '/tmp/substitute.so.0'
        return listing(runtime.DEPENDENCIES if argv[-1] == runtime.EXECUTABLE else runtime.MODULE_DEPENDENCIES)
    monkeypatch.setattr(runtime, '_runtime_probe', changed)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


def test_changed_saved_module_fails_readonly_recheck_without_process(fake_runtime, monkeypatch):
    _, raw, _ = fake_runtime
    value = runtime.inspect_runtime('A', 'O1', control())
    raw['/usr/lib/apache2/modules/mod_alias.so'] += b'changed'
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('verification executed a process'))
    with pytest.raises(IsolationUnavailable, match='pinned manifest'):
        runtime.verify_current(value, control())


@pytest.mark.parametrize('fault', ['script', 'architecture', 'loader', 'program_headers', 'module_not_shared'])
def test_unsupported_native_elf_is_rejected_before_any_probe(fake_runtime, monkeypatch, fault):
    _, raw, _ = fake_runtime
    path = '/usr/lib/apache2/modules/mod_alias.so' if fault == 'module_not_shared' else runtime.EXECUTABLE
    candidate = bytearray(raw[path])
    if fault == 'script': candidate = bytearray(b'#!/bin/sh\nexec something\n')
    elif fault == 'architecture': struct.pack_into('<H', candidate, 18, 183)
    elif fault == 'loader': candidate[-2] = ord('9')
    elif fault == 'program_headers': struct.pack_into('<Q', candidate, 32, 999999)
    else: struct.pack_into('<H', candidate, 16, 2)
    raw[path] = bytes(candidate)
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('unsupported ELF reached metadata probe'))
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


def test_reader_reuses_no_follow_regular_stable_permission_and_size_guards(tmp_path, monkeypatch):
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


def test_reader_rejects_permission_changes_during_read(tmp_path, monkeypatch):
    path = tmp_path / 'runtime'; path.write_bytes(elf()); path.chmod(0o600)
    real_read = runtime.shared.os.read
    def changed(descriptor, count):
        result = real_read(descriptor, count)
        if result: path.chmod(0o644)
        return result
    monkeypatch.setattr(runtime.shared.os, 'read', changed)
    with pytest.raises(IsolationUnavailable, match='changed'):
        runtime._read_file(str(path), control())


@pytest.mark.parametrize('source,destination', [
    ('/etc/apache2/mods-enabled/mod_alias.so', '/tool/modules/mod_alias.so'),
    ('/usr/lib/apache2/modules/../modules/mod_alias.so', '/tool/modules/mod_alias.so'),
    ('/usr/lib/apache2/modules/mod_proxy.so', '/tool/modules/mod_proxy.so'),
    ('/usr/lib/x86_64-linux-gnu/libapr-1.so.0.other', '/usr/lib/x86_64-linux-gnu/libapr-1.so.0'),
    ('/usr/lib/x86_64-linux-gnu/libapr-1.so.0/../../shadow', '/usr/lib/x86_64-linux-gnu/libapr-1.so.0'),
])
def test_unreviewed_source_aliases_are_not_manifest_paths(source, destination):
    assert not runtime._source_allowed(source, destination)


def test_canonical_numeric_library_alias_is_pinned(fake_runtime):
    _, raw, aliases = fake_runtime
    path = runtime.LIBRARY_ROOT + 'libapr-1.so.0'
    aliases[path] = path + '.7.6'
    raw[aliases[path]] = raw.pop(path)
    manifest = runtime.inspect_runtime('A', 'O1', control())
    assert next(row for row in manifest['files'] if row['destination'] == path)['source'] == path + '.7.6'


def test_manifest_bound_is_enforced(fake_runtime, monkeypatch):
    manifest = runtime.inspect_runtime('A', 'O1', control())
    monkeypatch.setattr(runtime, 'MAX_MANIFEST_BYTES', len(runtime.shared._encode(manifest)) - 1)
    with pytest.raises(ValueError, match='closure'): runtime.validate_manifest(manifest)
