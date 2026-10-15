"""Stock SSH probe identity is separate; execution and path authority stay fixed."""

from copy import deepcopy
import hashlib
import os
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as native
from recon_cockpit.secure_agent import stock_ssh_nmap_runtime as runtime
from recon_cockpit.secure_agent import stock_ssh_nmap_spec as spec
from test_secure_network_tools_runtime import manifest as native_manifest


def manifest():
    return runtime.from_native_manifest(native_manifest(native.NMAP_SERVICE))


def probe(value):
    return next(row for row in value['files'] if row['destination'] == spec.PROBE_DESTINATION)


def mounted_fixture():
    value = manifest()
    raw = {destination: payload for _, destination, payload in spec.compiled_files()}
    for row in value['files']:
        if not row['source'].startswith('compiled:'):
            payload = b'\x7fELFsynthetic'
            raw[row['destination']] = payload
            row.update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    return value, raw


def test_conversion_changes_only_profile_and_exact_probe_row_without_mutating_input():
    old = native_manifest(native.NMAP_SERVICE)
    saved = deepcopy(old)
    value = runtime.from_native_manifest(old)
    assert old == saved and value is not old
    assert value['profile'] == spec.PROFILE
    assert value['tool_id'] == native.NMAP_SERVICE
    assert probe(value) == {'source': spec.PROBE_SOURCE, 'destination': spec.PROBE_DESTINATION,
        'size': len(spec.PROBES), 'sha256': hashlib.sha256(spec.PROBES).hexdigest()}
    assert {key: item for key, item in old.items() if key not in {'profile', 'files'}} == {
        key: item for key, item in value.items() if key not in {'profile', 'files'}}
    assert [row for row in old['files'] if row['destination'] != spec.PROBE_DESTINATION] == [
        row for row in value['files'] if row['destination'] != spec.PROBE_DESTINATION]
    assert runtime.manifest_digest(value) == hashlib.sha256(native.encode(value)).hexdigest()
    assert runtime.manifest_digest(value) != native.manifest_digest(old)
    assert native.validate_manifest(old) == saved
    assert native.manifest_digest(old) == hashlib.sha256(native.encode(saved)).hexdigest()
    with pytest.raises(ValueError): native.validate_manifest(value)
    with pytest.raises(ValueError): runtime.validate_manifest(old)
    with pytest.raises(ValueError): runtime.from_native_manifest(value)
    assert runtime.runtime_source_mounts(value) == native.runtime_source_mounts(old)
    detached = runtime.validate_manifest(value)
    detached['files'][0]['size'] += 1
    assert detached != value


@pytest.mark.parametrize('fault', ('profile', 'tool_id', 'version', 'field', 'source', 'legacy_payload',
    'sha256', 'size', 'size_float', 'size_bool', 'duplicate', 'missing', 'extra_compiled', 'extra_field',
    'executable', 'library_source', 'library_destination', 'unordered', 'extra_probe_destination'))
def test_production_runtime_rejects_profile_payload_and_closure_substitutions(fault):
    value = manifest()
    row = probe(value)
    if fault == 'profile': value['profile'] = native.PROFILE
    elif fault == 'tool_id': value['tool_id'] = native.DIG
    elif fault == 'version': value['version'] = '2'
    elif fault == 'field': value['extra'] = True
    elif fault == 'source': row['source'] = 'compiled:nmap-service-probes'
    elif fault == 'legacy_payload': row.update(size=len(native.NMAP_SERVICE_PROBES), sha256=hashlib.sha256(native.NMAP_SERVICE_PROBES).hexdigest())
    elif fault == 'sha256': row['sha256'] = 'b' * 64
    elif fault == 'size': row['size'] += 1
    elif fault == 'size_float': row['size'] = float(row['size'])
    elif fault == 'size_bool': row['size'] = True
    elif fault == 'duplicate': value['files'].append(deepcopy(row))
    elif fault == 'missing': value['files'].remove(row)
    elif fault == 'extra_compiled':
        value['files'].append({**row, 'source': 'compiled:extra', 'destination': '/tool/data/extra'})
        value['files'].sort(key=lambda item: item['destination'])
    elif fault == 'extra_field': row['allow'] = True
    elif fault == 'executable': value['executable'] = '/usr/bin/nmap'
    elif fault == 'library_source': value['files'][0]['source'] = '/tmp/evil.so.1'
    elif fault == 'library_destination': value['files'][0]['destination'] = '/etc/ld.so.preload'
    elif fault == 'unordered': value['files'].reverse()
    else:
        value['files'].append({**row, 'destination': '/tool/data/probes'})
        value['files'].sort(key=lambda item: item['destination'])
    with pytest.raises(ValueError): runtime.validate_manifest(value)


def test_runtime_enforces_real_manifest_and_byte_size_not_smaller_validation_view(monkeypatch):
    value = manifest()
    with monkeypatch.context() as patched:
        patched.setattr(native, 'MAX_MANIFEST_BYTES', len(native.encode(value)) - 1)
        with pytest.raises(ValueError): runtime.validate_manifest(value)
    monkeypatch.setattr(native, 'MAX_RUNTIME_BYTES', sum(row['size'] for row in value['files']) - 1)
    with pytest.raises(ValueError): runtime.validate_manifest(value)


def test_inspection_uses_existing_fixed_native_closure(monkeypatch):
    old = native_manifest(native.NMAP_SERVICE)
    control = object()
    seen = []
    monkeypatch.setattr(native, 'inspect_tool_runtime', lambda tool, guard: seen.append((tool, guard)) or old)
    assert runtime.inspect_runtime(control) == runtime.from_native_manifest(old)
    assert seen == [(native.NMAP_SERVICE, control)]
    with pytest.raises(ValueError): runtime.validate_manifest(manifest(), tool_id=native.DIG)


def test_snapshot_stages_actual_production_bytes_and_requests_all_seals(tmp_path, monkeypatch):
    import fcntl
    from recon_cockpit.secure_agent import tool_runtime_common
    # Portable tests exercise this seam on every OS. Real kernel sealing remains
    # Linux-native evidence; this checks exact staging bytes and sealing calls.
    created, seal_calls = [], []
    for name, number in (('MFD_CLOEXEC', 1), ('MFD_ALLOW_SEALING', 2)):
        monkeypatch.setattr(os, name, number, raising=False)
    for name, number in (('F_ADD_SEALS', 1033), ('F_SEAL_WRITE', 8), ('F_SEAL_GROW', 4),
                         ('F_SEAL_SHRINK', 2), ('F_SEAL_SEAL', 1)):
        monkeypatch.setattr(fcntl, name, number, raising=False)

    def temporary_memfd(name, flags):
        assert name == 'recon-web-tool-runtime'
        assert flags == os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        path = tmp_path / ('snapshot-' + str(len(created)))
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        os.unlink(path)
        created.append(descriptor)
        return descriptor

    def record_seals(descriptor, command, flags):
        assert descriptor in created and command == fcntl.F_ADD_SEALS
        seal_calls.append((descriptor, command, flags))
        return 0

    monkeypatch.setattr(os, 'memfd_create', temporary_memfd, raising=False)
    monkeypatch.setattr(fcntl, 'fcntl', record_seals)
    value, payloads = mounted_fixture()
    by_source = {row['source']: payloads[row['destination']] for row in value['files']}
    monkeypatch.setattr(tool_runtime_common, '_read_regular', lambda source: by_source[source])
    descriptors = runtime.snapshot(value, SimpleNamespace(check=lambda: None))
    try:
        assert descriptors == created
        assert seal_calls == [(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            for descriptor in descriptors]
        for row, descriptor in zip(value['files'], descriptors, strict=True):
            assert os.read(descriptor, native.MAX_FILE_BYTES) == payloads[row['destination']]
        assert payloads[spec.PROBE_DESTINATION] == spec.PROBES
        assert payloads[spec.PROBE_DESTINATION] != native.NMAP_SERVICE_PROBES
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@pytest.mark.parametrize('fault', ('none', 'legacy_probe', 'non_elf', 'capability'))
def test_mounted_file_verification_uses_production_pins_and_elf_capability_checks(monkeypatch, fault):
    value, payloads = mounted_fixture()
    if fault == 'legacy_probe': payloads[spec.PROBE_DESTINATION] = native.NMAP_SERVICE_PROBES
    elif fault == 'non_elf':
        payloads[value['executable']] = b'not-elf'
        row = next(row for row in value['files'] if row['destination'] == value['executable'])
        row.update(size=7, sha256=hashlib.sha256(b'not-elf').hexdigest())
    monkeypatch.setattr(native, 'read_runtime_file', lambda destination, tool: payloads[destination])
    monkeypatch.setattr(os, 'listxattr', lambda path: ['security.capability'] if fault == 'capability' else [], raising=False)
    if fault == 'none': runtime.verify_files(value)
    else:
        expected = {'legacy_probe': 'mounted_runtime_mismatch', 'non_elf': 'requires_elf',
                    'capability': 'runtime_file_capabilities'}
        with pytest.raises(ValueError, match=expected[fault]): runtime.verify_files(value)


def test_landlock_uses_same_exact_destination_and_execute_allowlist(monkeypatch):
    from recon_cockpit.secure_agent import network_tools_worker as worker
    seen = []
    monkeypatch.setattr(worker.common, 'apply_landlock', seen.append)
    runtime.landlock(manifest())
    assert seen == [worker._landlock_permissions(native_manifest(native.NMAP_SERVICE))]
