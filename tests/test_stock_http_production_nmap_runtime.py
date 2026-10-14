"""Production probe identity is separate; execution and path authority stay fixed."""

from copy import deepcopy
import hashlib
import os
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as native
from recon_cockpit.secure_agent import stock_http_production_nmap_runtime as runtime
from recon_cockpit.secure_agent import stock_http_production_nmap_spec as spec
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
    value['files'].extend({'source': f'/usr/lib/x86_64-linux-gnu/libsynthetic{i}.so.1',
                          'destination': f'/usr/lib/x86_64-linux-gnu/libsynthetic{i}.so.1',
                          'size': native.MAX_FILE_BYTES, 'sha256': 'a' * 64} for i in range(4))
    total = sum(row['size'] for row in value['files'])
    value['files'][-1]['size'] -= total - native.MAX_RUNTIME_BYTES
    value['files'].sort(key=lambda row: row['destination'])
    assert runtime.validate_manifest(value) == value
    value['files'][-1]['size'] += 1
    with pytest.raises(ValueError, match='runtime_size'): runtime.validate_manifest(value)


def test_inspection_uses_existing_fixed_native_closure(monkeypatch):
    old = native_manifest(native.NMAP_SERVICE)
    control = object()
    seen = []
    monkeypatch.setattr(native, 'inspect_tool_runtime', lambda tool, guard: seen.append((tool, guard)) or old)
    assert runtime.inspect_runtime(control) == runtime.from_native_manifest(old)
    assert seen == [(native.NMAP_SERVICE, control)]
    with pytest.raises(ValueError): runtime.validate_manifest(manifest(), tool_id=native.DIG)


def test_snapshot_seals_actual_production_payload_and_preserves_all_other_bytes(monkeypatch):
    import fcntl
    from recon_cockpit.secure_agent import tool_runtime_common
    value, payloads = mounted_fixture()
    by_source = {row['source']: payloads[row['destination']] for row in value['files']}
    monkeypatch.setattr(tool_runtime_common, '_read_regular', lambda source: by_source[source])
    descriptors = runtime.snapshot(value, SimpleNamespace(check=lambda: None))
    try:
        for row, descriptor in zip(value['files'], descriptors, strict=True):
            assert os.read(descriptor, native.MAX_FILE_BYTES) == payloads[row['destination']]
            assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE
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
    monkeypatch.setattr(os, 'listxattr', lambda path: ['security.capability'] if fault == 'capability' else [])
    if fault == 'none': runtime.verify_files(value)
    else:
        with pytest.raises(ValueError): runtime.verify_files(value)


def test_landlock_uses_same_exact_destination_and_execute_allowlist(monkeypatch):
    from recon_cockpit.secure_agent import network_tools_worker as worker
    seen = []
    monkeypatch.setattr(worker.common, 'apply_landlock', seen.append)
    runtime.landlock(manifest())
    assert seen == [worker._landlock_permissions(native_manifest(native.NMAP_SERVICE))]


def test_selection_commitment_invalidates_previous_unmerged_recognition_policy():
    from recon_cockpit.secure_agent import stock_http_production_contract as contract
    from recon_cockpit.secure_agent import stock_apache_spec, stock_http_spec
    selected = contract.selection('apache', 'A', 'O5')
    previous_commitment = {'profile': contract.PROFILE, 'implementation': 'apache',
        'boundary_revision': contract.BOUNDARY_REVISION,
        'owner_group_policy': {'maximum': contract.MAX_INHERITED_GROUPS, 'overflow_gid': contract.OVERFLOW_GID,
                               'setgroups': 'deny', 'mutation_denied': True},
        'launcher_mapping': 'single-id-to-positive-launcher-uid-gid-before-daemon-input',
        'preparation_selection_sha256': stock_apache_spec.selection_digest('A', 'O5')}
    old = {**selected, 'selection_sha256': hashlib.sha256(stock_http_spec.encode(previous_commitment)).hexdigest()}
    assert old != selected
    with pytest.raises(ValueError): contract.validate_selection(old)
    new_commitment = {**previous_commitment, 'client_recognition': {
        'profile': spec.PROFILE, 'probes_sha256': hashlib.sha256(spec.PROBES).hexdigest()}}
    assert selected['selection_sha256'] == hashlib.sha256(stock_http_spec.encode(new_commitment)).hexdigest()
