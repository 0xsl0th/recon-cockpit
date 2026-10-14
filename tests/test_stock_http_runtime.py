"""Read-only nginx pins cannot become host execution or unchecked authority."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import struct
import threading
import time

import pytest

from recon_cockpit.secure_agent import stock_http_runtime as runtime
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


def listing():
    rows = ['linux-vdso.so.1 (0x1000)']
    for path in sorted(runtime.DEPENDENCIES):
        rows.append((Path(path).name + ' => ' if path != runtime.INTERPRETER else '') + path + ' (0x2000)')
    return ('\n'.join(rows) + '\n').encode()


@pytest.fixture
def fake_runtime(monkeypatch):
    """Only the native files/probe are doubled; compiled selection is real."""
    calls = []
    sources = {p: runtime.LIBRARY_ROOT + 'ld-linux-x86-64.so.2' if p == runtime.INTERPRETER else p
               for p in runtime.DEPENDENCIES}
    raw = {source: elf() for source in sources.values()}
    raw[runtime.EXECUTABLE] = elf(executable=True)
    monkeypatch.setattr(runtime.sys, 'platform', 'linux')
    monkeypatch.setattr(runtime.Path, 'resolve', lambda path, **kwargs: Path(sources.get(str(path), str(path))))
    monkeypatch.setattr(runtime, '_read_file', lambda path, selected_control: raw[path])
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    def probe(argv, timeout, maximum, selected_control):
        calls.append((argv, timeout, maximum, selected_control))
        return listing()
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    return calls, raw, sources


def test_inspection_pins_selected_files_and_never_launches_nginx(fake_runtime):
    calls, raw, sources = fake_runtime
    selected_control = control()
    manifest = runtime.inspect_runtime('A', 'O1', selected_control)
    assert calls == [(['/usr/bin/ldd', '/usr/sbin/nginx'], 3, 32768, selected_control)]
    assert manifest['runtime_closure_verified'] is manifest['daemon_execution_performed'] is False
    assert manifest['dependency_kind'] == 'elf_linked_dependencies_only'
    assert manifest['configuration'] == 'A' and manifest['case'] == 'O1'
    assert manifest['selection_sha256'] == runtime.spec.selection_digest('A', 'O1')
    rows = {row['destination']: row for row in manifest['files']}
    assert rows[runtime.DESTINATION]['source'] == runtime.EXECUTABLE
    for source, destination, compiled in runtime.spec.compiled_files('A', 'O1'):
        assert rows[destination] == {'source': source, 'destination': destination,
            'size': len(compiled), 'sha256': hashlib.sha256(compiled).hexdigest()}
    # A pure validation/recheck detaches data and performs no metadata probe.
    detached = runtime.verify_current(manifest, selected_control)
    assert len(calls) == 1 and detached == manifest and detached is not manifest
    detached['files'][0]['sha256'] = 'f' * 64
    assert detached != manifest


@pytest.mark.parametrize('configuration,case', [('external', 'O1'), ('A', '/etc/shadow'),
    ('A; nginx', 'O1'), (True, 'O1'), ('B', None)])
def test_invalid_selector_is_rejected_before_files_or_processes(monkeypatch, configuration, case):
    monkeypatch.setattr(runtime, '_read_file', lambda *args: pytest.fail('invalid selector read a file'))
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('invalid selector spawned a process'))
    with pytest.raises(ValueError):
        runtime.inspect_runtime(configuration, case, control())


def test_cancelled_control_blocks_inspection_before_access(monkeypatch):
    cancelled = threading.Event();cancelled.set()
    monkeypatch.setattr(runtime, '_read_file', lambda *args: pytest.fail('cancelled inspection read a file'))
    with pytest.raises(ExecutionStopped, match='session_cancelled'):
        runtime.inspect_runtime('A', 'O1', ExecutionControl(time.monotonic() + 30, cancelled))


@pytest.mark.parametrize('fault', ['path', 'traversal', 'duplicate', 'extra', 'missing', 'bool_size',
    'too_large', 'digest', 'reordered', 'compiled', 'selection', 'ready'])
def test_recommitted_manifest_cannot_expand_files_or_claim_readiness(fake_runtime, fault):
    value = runtime.inspect_runtime('A', 'O1', control())
    row = next(row for row in value['files'] if row['destination'] == runtime.DESTINATION)
    if fault == 'path': row['source'] = '/tmp/nginx'
    elif fault == 'traversal': row['source'] = '/usr/sbin/../sbin/nginx'
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
    with pytest.raises(ValueError): runtime.manifest_digest(value)


def test_fresh_selection_digest_cannot_relabel_other_compiled_configuration(fake_runtime):
    value = runtime.inspect_runtime('A', 'O1', control())
    value['case'] = 'R1'
    value['selection_sha256'] = runtime.spec.selection_digest('A', 'R1')
    with pytest.raises(ValueError): runtime.validate_manifest(value)


@pytest.mark.parametrize('fault', ['extra', 'missing', 'duplicate', 'wrapper', 'nonascii', 'missing_library'])
def test_ldd_results_must_equal_the_reviewed_finite_dependency_set(fake_runtime, monkeypatch, fault):
    raw = listing()
    if fault == 'extra': raw += b'liboutside.so.1 => /tmp/liboutside.so.1 (0x1234)\n'
    elif fault == 'missing': raw = b'\n'.join(raw.splitlines()[:-1])
    elif fault == 'duplicate': raw += raw.splitlines()[1] + b'\n'
    elif fault == 'wrapper': raw += b'not a dynamic executable\n'
    elif fault == 'nonascii': raw += b'\xff\n'
    elif fault == 'missing_library': raw += b'liboutside.so.1 => not found\n'
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: raw)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


@pytest.mark.parametrize('fault', ['executable_change', 'library_change', 'alias_change'])
def test_changes_across_dependency_probe_fail_before_manifest_returns(fake_runtime, monkeypatch, fault):
    _, raw, aliases = fake_runtime
    def changed(*args):
        if fault == 'executable_change': raw[runtime.EXECUTABLE] += b'changed'
        elif fault == 'library_change': raw[runtime.LIBRARY_ROOT + 'libssl.so.3'] += b'changed'
        else: aliases[runtime.LIBRARY_ROOT + 'libssl.so.3'] = '/tmp/substitute.so.3'
        return listing()
    monkeypatch.setattr(runtime, '_runtime_probe', changed)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


def test_changed_saved_pin_fails_readonly_recheck_without_executing_probe(fake_runtime, monkeypatch):
    _, raw, _ = fake_runtime
    value = runtime.inspect_runtime('A', 'O1', control())
    raw[runtime.EXECUTABLE] += b'changed'
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('verification executed a process'))
    with pytest.raises(IsolationUnavailable, match='pinned manifest'):
        runtime.verify_current(value, control())


@pytest.mark.parametrize('fault', ['script', 'architecture', 'loader', 'program_headers'])
def test_unsupported_elf_is_rejected_before_ldd(fake_runtime, monkeypatch, fault):
    _, raw, _ = fake_runtime
    candidate = bytearray(raw[runtime.EXECUTABLE])
    if fault == 'script': candidate = bytearray(b'#!/bin/sh\nexec something\n')
    elif fault == 'architecture': struct.pack_into('<H', candidate, 18, 183)
    elif fault == 'loader': candidate[-2] = ord('9')
    else: struct.pack_into('<Q', candidate, 32, 999999)
    raw[runtime.EXECUTABLE] = bytes(candidate)
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('unsupported ELF reached ldd'))
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime('A', 'O1', control())


def test_regular_reader_refuses_symlink_fifo_and_writable_files(tmp_path):
    path = tmp_path / 'runtime';path.write_bytes(elf());path.chmod(0o600)
    assert runtime._read_file(str(path), control()) == elf()
    link = tmp_path / 'link';link.symlink_to(path)
    with pytest.raises(OSError): runtime._read_file(str(link), control())
    fifo = tmp_path / 'fifo';os.mkfifo(fifo, 0o600)
    with pytest.raises(IsolationUnavailable): runtime._read_file(str(fifo), control())
    path.chmod(0o622)
    with pytest.raises(IsolationUnavailable): runtime._read_file(str(path), control())


def test_regular_reader_detects_same_size_changes_during_read(tmp_path, monkeypatch):
    path = tmp_path / 'runtime';path.write_bytes(elf());path.chmod(0o600)
    real_read = runtime.os.read
    def changed(descriptor, count):
        result = real_read(descriptor, count)
        if result:
            path.write_bytes(b'X' * len(elf()))
        return result
    monkeypatch.setattr(runtime.os, 'read', changed)
    with pytest.raises(IsolationUnavailable, match='changed during inspection'):
        runtime._read_file(str(path), control())


def test_file_bound_precedes_read_and_total_manifest_bound_is_enforced(tmp_path, monkeypatch, fake_runtime):
    value = runtime.inspect_runtime('A', 'O1', control())
    for row in value['files']:
        if not row['source'].startswith('compiled:'):
            row['size'] = runtime.MAX_FILE_BYTES
    with pytest.raises(ValueError, match='closure'): runtime.validate_manifest(value)
    # The real reader's bound is separate from manifest validation.
    monkeypatch.undo()
    path = tmp_path / 'large';path.write_bytes(b'12345');path.chmod(0o600)
    monkeypatch.setattr(runtime, 'MAX_FILE_BYTES', 4)
    with pytest.raises(IsolationUnavailable): runtime._read_file(str(path), control())
