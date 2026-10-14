"""AAAA/PTR share dig but cannot share action or query authority."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import network_tools_dns_address_spec as spec
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_policy
from test_secure_network_tools_runtime import envelope as shared_envelope, manifest, recommit, verify


def envelope(case):
    value = shared_envelope(case)
    if case in spec.CASES:
        policy = value['launch']['policy']
        policy['allowed_tools'] = [spec.tool_for_case(case)]
        value['launch']['policy'] = parse_policy(policy).to_dict()
        recommit(value)
    return value


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
def test_address_argv_changes_only_fixed_question_name_and_type(tool):
    assert runtime.EXECUTABLES[tool] == '/usr/bin/dig'
    old, new = runtime.FIXED_ARGV[runtime.DIG_MX], runtime.FIXED_ARGV[tool]
    assert new == old[:6] + (spec.QUERY_NAMES[tool], spec.QUERY_TYPES[tool]) + old[8:]
    assert new[:6] == ('/tool/dig', '-r', '-4', '@127.0.0.1', '-p', '8080')
    assert not {'-x', '-f', '+trace', '+recurse', '+search', 'ANY', 'AXFR', 'IXFR'} & set(new)
    assert '+tcp' in new and '+tries=1' in new and '+time=2' in new


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
def test_resolver_inputs_environment_and_file_authority_match_accepted_dig(tool, monkeypatch):
    for key in ('HOME', 'LOCALDOMAIN', 'RES_OPTIONS', 'DIGRC', 'LD_PRELOAD', 'LD_LIBRARY_PATH'):
        monkeypatch.setenv(key, '/private/untrusted')
    assert runtime.execution_environment(tool) == runtime.execution_environment(runtime.DIG_MX)
    assert runtime.compiled_files(tool) == runtime.compiled_files(runtime.DIG_MX) == (
        ('compiled:resolver', '/etc/resolv.conf', b'# fixed TCP nameserver supplied by reviewed argv\n'),)
    permissions = worker._landlock_permissions(manifest(tool))
    assert permissions == worker._landlock_permissions(manifest(runtime.DIG_MX))
    assert permissions['/etc/resolv.conf'] == 4 and permissions['/tool/dig'] == 5
    assert not {'/usr/bin/python3', '/etc/hosts', '/etc', '/root', '/home'} & permissions.keys()


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('path', ['/etc/hosts', '/root/.digrc', '/etc/bind/rndc.key',
    '/etc/nsswitch.conf', '/tool/data/query.txt', '/tool/data/tsig.key', '/tmp/credential', '/bin/sh'])
def test_host_configuration_keys_and_query_files_cannot_enter_closure(tool, path):
    value = manifest(tool)
    value['files'].append({'source': path, 'destination': path, 'size': 4, 'sha256': 'a' * 64})
    value['files'].sort(key=lambda row: row['destination'])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('fault', ['missing', 'source', 'hash', 'size', 'interpreter', 'executable', 'tool'])
def test_recommitting_resolver_or_runtime_identity_cannot_bypass_pins(tool, fault):
    value = manifest(tool)
    row = next(item for item in value['files'] if item['source'] == 'compiled:resolver')
    if fault == 'missing': value['files'].remove(row)
    elif fault == 'source': row['source'] = '/etc/resolv.conf'
    elif fault == 'hash': row['sha256'] = 'b' * 64
    elif fault == 'size': row['size'] += 1
    elif fault == 'interpreter': value['interpreter'] = '/usr/bin/python3'
    elif fault == 'executable': value['executable'] = '/usr/bin/dig'
    else: value['tool_id'] = runtime.DIG
    with pytest.raises(ValueError): runtime.validate_manifest(value, tool_id=tool)


@pytest.mark.parametrize('case', ['dig-aaaa-ok', 'dig-ptr-ok'])
@pytest.mark.parametrize('other', ['dig-ok', 'dig-mx-ok', 'dig-srv-ok', 'dig-nsid-ok', 'dig-axfr-ok', 'dig-aaaa-ok', 'dig-ptr-ok'])
def test_shared_binary_never_allows_cross_profile_commitments(case, other):
    if case == other:
        return
    value, other_value = envelope(case), envelope(other)
    verify(value)
    verify(other_value)
    assert value['runtime']['files'] == other_value['runtime']['files']
    value['runtime'] = deepcopy(other_value['runtime'])
    with pytest.raises(ValueError): verify(value)
    value['launch']['action'] = other_value['launch']['action']
    recommit(value)
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize('case', ['dig-aaaa-ok', 'dig-ptr-ok'])
@pytest.mark.parametrize('fault', ['mode', 'inner_mode', 'identity', 'manifest', 'namespace',
    'deadline', 'sequence', 'reservation', 'policy', 'action', 'limit'])
def test_fresh_launch_commitments_cannot_expand_question_authority(case, fault):
    value = envelope(case)
    launch = value['launch']
    if fault == 'mode': value['mode'] = 'owned_http_headers_lab'
    elif fault == 'inner_mode': launch['mode'] = 'http_headers_owned'
    elif fault == 'identity': value['identity']['spec_sha256'] = 'b' * 64
    elif fault == 'manifest': value['runtime'] = manifest(runtime.DIG_MX)
    elif fault == 'namespace': value['namespaces'] = dict(launch['host_namespaces'])
    elif fault == 'deadline': launch['deadline'] = 161
    elif fault == 'sequence': launch['sequence'] = 2
    elif fault == 'reservation': launch['output_reserved_before'] = 1
    elif fault == 'policy': launch['policy']['allowed_tools'] = []
    elif fault == 'action':
        launch['action']['target'] = '127.0.0.2'
        launch['policy']['allowed_targets'] = ['127.0.0.0/8']
    else: launch['limits']['max_steps'] = 2
    recommit(value)
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
def test_dig_task_resources_and_no_new_clone_authority(tool, monkeypatch):
    calls, limits = [], {}
    monkeypatch.setattr(worker.common, 'syscall_filter', lambda **kw: calls.append(kw))
    worker.syscall_filter(tool)
    assert calls == [{'allow_threads': True}]
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, 'setrlimit', lambda kind, value: limits.update({kind: value}))
    worker._limits(tool)
    assert limits == {worker.resource.RLIMIT_AS: (256 * 1024 * 1024,) * 2,
        worker.resource.RLIMIT_CPU: (5, 5), worker.resource.RLIMIT_NOFILE: (64, 64),
        worker.resource.RLIMIT_NPROC: (16, 16), worker.resource.RLIMIT_CORE: (0, 0),
        worker.resource.RLIMIT_FSIZE: (0, 0)}
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda kind: (2, 2))
    worker._limits(tool)
    assert set(limits.values()) == {(0, 0), (2, 2)}


@pytest.mark.parametrize('case', ['dig-aaaa-ok', 'dig-ptr-ok'])
@pytest.mark.parametrize('code,reason,expected', [(0, None, 'succeeded'), (1, None, 'failed'),
    (-15, 'timeout', 'timeout'), (-15, 'output_limit', 'output_limit')])
def test_capture_keeps_bounded_channels_and_never_promotes_failed_execution(case, monkeypatch, code, reason, expected):
    monkeypatch.setattr(runtime, 'sys', SimpleNamespace(platform='linux'))
    launch = envelope(case)
    selected = launch.pop('runtime')
    monkeypatch.setattr(runtime, '_snapshot', lambda *_: [])
    monkeypatch.setattr(runtime, '_command', lambda *_: ['fixed-worker'])
    stdout, stderr = b'untrusted DNS data', b'untrusted diagnostic'
    def capture(argv, raw, timeout, maximum, **kwargs):
        assert argv == ['fixed-worker'] and 0 < timeout <= 5
        prefix = runtime.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b'\n'
        assert maximum == 8192 + len(prefix)
        return code, stdout, prefix + stderr, reason
    monkeypatch.setattr(runtime, '_capture_bounded', capture)
    lab = SimpleNamespace(_namespace_fds=(10, 11), _check=lambda *_: None, _verify_pins=lambda: None)
    result = runtime.run_network_tool_owned(lab=lab, launch=launch,
        control=ExecutionControl(time.monotonic() + 20), manifest=selected,
        closure={'stdlib': '/usr/lib/python3.13', 'files': [], 'network_tools_runtime': selected})
    assert result['status'] == expected and result['tool_observation'] is None
    assert result['truncated'] is (reason == 'output_limit')
    assert base64.b64decode(result['raw_output_base64']) == stdout
    assert base64.b64decode(result['raw_stderr_base64']) == stderr
    assert result['provenance']['parser_version'] == spec.PARSER_VERSIONS[spec.tool_for_case(case)]
    assert result['provenance']['exit_code'] == code and result['provenance']['stop_reason'] == reason


def test_all_address_launches_validate_in_exact_client_without_owner_fixture(tmp_path):
    package = tmp_path / 'recon_cockpit' / 'secure_agent'
    package.mkdir(parents=True)
    (package.parent / '__init__.py').write_text('')
    (package / '__init__.py').write_text('')
    source = Path(runtime.__file__).parent
    assert 'network_tools_dns_address_identity' in runtime.MODULES
    assert 'network_tools_dns_address_fixture' not in runtime.MODULES
    for name in runtime.MODULES:
        (package / (name + '.py')).write_bytes((source / (name + '.py')).read_bytes())
    code = '''
import hashlib, json, sys
sys.path.insert(0, sys.argv[1])
from recon_cockpit.secure_agent.network_tools_execution import consume_launch
for value in json.loads(sys.stdin.buffer.read()):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    request, deadline, namespaces, runtime_digest = consume_launch(
        raw, 'a' * 64, hashlib.sha256(raw).hexdigest(), now=100)
    assert request['tool_id'] in ('dig_dns_aaaa_v1', 'dig_dns_ptr_v1')
assert not any(name.endswith('network_tools_dns_address_fixture') for name in sys.modules)
'''
    completed = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(tmp_path)],
        input=json.dumps([envelope(case) for case in spec.CASES]).encode(), capture_output=True, timeout=10)
    assert completed.returncode == 0, completed.stderr.decode('utf-8', 'backslashreplace')
