"""One four-binding GETBULK page cannot acquire continuation or credential authority."""

import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import tool_adapters as adapters
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import SNMPInterfacePageParameters, ValidationError, parse_action, parse_policy
from test_secure_network_tools_runtime import envelope as original_envelope, manifest, recommit, verify


def policy():
    import json
    return parse_policy(json.loads(Path('examples/secure-agent-snmp-page-policy.json').read_text()))


def envelope(case='snmp-page-ok'):
    value = original_envelope(case)
    if case.startswith('snmp-page-'):
        value['launch']['policy'] = policy().to_dict()
        recommit(value)
    return value


def test_fixed_bulkget_has_one_seed_four_repetitions_no_retry_continuation_or_udp():
    assert runtime.EXECUTABLES[runtime.SNMP_PAGE] == "/usr/bin/snmpbulkget"
    assert runtime.FIXED_ARGV[runtime.SNMP_PAGE] == (
        "/tool/snmpbulkget", "-v", "2c", "-c", "recon-fixture-public", "-r", "0", "-t", "2",
        "-Cn0", "-Cr4", "-On", "-Ot", "-Ox", "-m", "", "-M", "", "--dontLoadHostConfig=true",
        "--noPersistentLoad=true", "--noPersistentSave=true", "tcp:127.0.0.1:8080",
        ".1.3.6.1.2.1.2.2.1.2")
    assert "-Cf" not in runtime.FIXED_ARGV[runtime.SNMP_PAGE]
    assert "-Cr4" in runtime.FIXED_ARGV[runtime.SNMP_PAGE] and "-Cn0" in runtime.FIXED_ARGV[runtime.SNMP_PAGE]
    assert [arg for arg in runtime.FIXED_ARGV[runtime.SNMP_PAGE] if arg.startswith('.')] == [
        '.1.3.6.1.2.1.2.2.1.2']
    assert runtime.EXECUTABLES[runtime.SNMP_PAGE] not in {
        exe for tool, exe in runtime.EXECUTABLES.items() if tool != runtime.SNMP_PAGE}


def test_bulkget_is_typed_immutable_and_independent_from_get_policy():
    action = parse_action(contract.action('snmp-page-ok'))
    assert type(action.parameters) is SNMPInterfacePageParameters
    with pytest.raises(FrozenInstanceError):
        action.parameters.port = 161
    descriptor = adapters.get_adapter(runtime.SNMP_PAGE).to_dict()
    assert descriptor['parameters']['required'] == ['port', 'timeout_seconds', 'max_output_bytes']
    assert descriptor['parameters']['additionalProperties'] is False
    assert descriptor['parser_version'] == 'snmp-interface-page-text-v1'
    configured = policy().to_dict()
    configured.update(allowed_tools=[runtime.SNMP_PAGE], allowed_methods=[])
    assert parse_policy(configured).evaluate(action).decision == 'approval_required'
    for case in ('snmp-ok', 'snmp-next-ok'):
        assert parse_policy(configured).evaluate(parse_action(contract.action(case))).reasons == ('tool_not_allowed',)
    configured['allowed_tools'] = [runtime.SNMP]
    assert parse_policy(configured).evaluate(action).reasons == ('tool_not_allowed',)


@pytest.mark.parametrize('field', ['oid', 'oids', 'seed', 'community', 'version', 'username',
    'password', 'credentials', 'authentication', 'privacy', 'walk', 'bulk', 'set', 'followup',
    'protocol', 'transport', 'retry', 'retries', 'correction', 'argv', 'executable', 'command',
    'environment', 'config', 'mibs', 'output_path'])
def test_caller_cannot_add_operation_credentials_or_configuration(field):
    action = contract.action('snmp-page-ok')
    action['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError, match='unknown_parameters_fields'):
        parse_action(action)


@pytest.mark.parametrize('field,value', [('port', True), ('timeout_seconds', 0),
    ('max_output_bytes', False), ('port', 65536), ('timeout_seconds', 31), ('max_output_bytes', 65537)])
def test_parameter_types_and_bounds_are_closed(field, value):
    action = contract.action('snmp-page-ok')
    action['parameters'][field] = value
    with pytest.raises(ValidationError):
        parse_action(action)


def test_bulkget_cannot_inherit_host_secrets_mibs_or_persistent_state(monkeypatch):
    for name in ('HOME', 'SNMPCONFPATH', 'MIBS', 'MIBDIRS', 'MIBFILES', 'SNMP_PERSISTENT_DIR',
                 'SNMP_PERSISTENT_FILE', 'SNMP_COMMUNITY', 'LD_PRELOAD', 'SSLKEYLOGFILE'):
        monkeypatch.setenv(name, '/private/canary')
    assert runtime.execution_environment(runtime.SNMP_PAGE) == {
        'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null', 'MALLOC_ARENA_MAX': '1',
        'MIBS': '', 'MIBDIRS': '', 'MIBFILES': '', 'SNMPCONFPATH': '/tool/no-snmp-config',
        'SNMP_PERSISTENT_DIR': '/tool/no-snmp-state'}
    assert runtime.execution_environment(runtime.SNMP_PAGE) == runtime.execution_environment(runtime.SNMP)
    assert runtime.compiled_files(runtime.SNMP_PAGE) == ()
    permissions = worker._landlock_permissions(manifest(runtime.SNMP_PAGE))
    assert permissions['/tool/snmpbulkget'] == 5 and '/tool/snmpget' not in permissions
    assert not any(p.startswith(('/etc', '/home', '/root', '/var', '/tool/data', '/tool/no-snmp')) for p in permissions)
    assert '/usr/bin/python3' not in permissions


@pytest.mark.parametrize('path', ['/etc/snmp/snmp.conf', '/etc/hosts', '/etc/resolv.conf',
    '/root/.snmp/snmp.conf', '/usr/share/snmp/mibs/IF-MIB.txt', '/var/lib/snmp/snmpbulkget.conf',
    '/tool/data/community', '/tmp/credentials', '/usr/bin/snmpwalk', '/usr/bin/snmpget', '/bin/sh'])
def test_runtime_closure_rejects_configuration_credentials_or_other_programs(path):
    value = manifest(runtime.SNMP_PAGE)
    value['files'].append({'source': path, 'destination': path, 'size': 4, 'sha256': 'a' * 64})
    value['files'].sort(key=lambda row: row['destination'])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('old_case', ['snmp-ok', 'snmp-next-ok'])
@pytest.mark.parametrize('reverse', [False, True])
def test_prior_get_and_getnext_cannot_swap_runtime_or_recommitted_page_action(reverse, old_case):
    cases = (old_case, 'snmp-page-ok') if reverse else ('snmp-page-ok', old_case)
    value, other = (envelope(case) for case in cases)
    verify(value)
    verify(other)
    value['runtime'] = deepcopy(other['runtime'])
    with pytest.raises(ValueError):
        verify(value)
    value['launch']['action'] = other['launch']['action']
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize('fault', ['mode', 'inner_mode', 'identity', 'manifest', 'namespace',
    'deadline', 'sequence', 'reservation', 'policy', 'action', 'limit'])
def test_fresh_commitments_cannot_expand_bulkget_authority(fault):
    value = envelope()
    launch = value['launch']
    if fault == 'mode': value['mode'] = 'owned_http_headers_lab'
    elif fault == 'inner_mode': launch['mode'] = 'http_headers_owned'
    elif fault == 'identity': value['identity']['spec_sha256'] = 'b' * 64
    elif fault == 'manifest': value['runtime'] = manifest(runtime.SNMP_NEXT)
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


@pytest.mark.parametrize('code,reason,expected', [(0, None, 'succeeded'), (2, None, 'failed'),
    (-15, 'timeout', 'timeout'), (-15, 'output_limit', 'output_limit')])
def test_capture_preserves_bounded_channels_without_promoting_failures(monkeypatch, code, reason, expected):
    monkeypatch.setattr(runtime, 'sys', SimpleNamespace(platform='linux'))
    launch = envelope('snmp-page-ok')
    selected = launch.pop('runtime')
    monkeypatch.setattr(runtime, '_snapshot', lambda *_: [])
    monkeypatch.setattr(runtime, '_command', lambda *_: ['fixed-worker'])
    stdout, stderr = b'.1.3.6.1.2.1.2.2.1.2.1 = Hex-STRING: 65 74 68 30\n', b'diagnostic'
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
    assert result['provenance']['runtime_manifest']['tool_id'] == runtime.SNMP_PAGE
    assert result['provenance']['parser_version'] == 'snmp-interface-page-text-v1'
    assert result['provenance']['exit_code'] == code and result['provenance']['stop_reason'] == reason


def test_bulkget_keeps_single_task_filter_and_strict_inherited_resource_caps(monkeypatch):
    calls, limits = [], {}
    monkeypatch.setattr(worker.common, 'syscall_filter', lambda **kw: calls.append(kw))
    worker.syscall_filter(runtime.SNMP_PAGE)
    assert calls == [{'allow_threads': False}]
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, 'setrlimit', lambda kind, value: limits.update({kind: value}))
    worker._limits(runtime.SNMP_PAGE)
    assert limits == {worker.resource.RLIMIT_AS: (256 * 1024 * 1024,) * 2,
        worker.resource.RLIMIT_CPU: (5, 5), worker.resource.RLIMIT_NOFILE: (64, 64),
        worker.resource.RLIMIT_NPROC: (1, 1), worker.resource.RLIMIT_CORE: (0, 0),
        worker.resource.RLIMIT_FSIZE: (0, 0)}
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda kind: (2, 2))
    worker._limits(runtime.SNMP_PAGE)
    assert set(limits.values()) == {(0, 0), (1, 1), (2, 2)}


def test_parser_bootstrap_does_not_mount_bulkget_native_program(monkeypatch):
    from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
    monkeypatch.setattr(parser_runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(parser_runtime, '_namespaces', lambda: {key: key for key in ('user', 'net', 'mnt', 'pid')})
    argv = parser_runtime._command(runtime.SNMP_PAGE, ('/stdlib', [
        ('/usr/bin/python3', '/usr/bin/python3'), ('/usr/bin/snmpbulkget', '/tool/snmpbulkget')]))
    assert '--unshare-net' in argv and '/app/network_tools_snmp_page_parser.py' in argv
    assert '/tool/snmpbulkget' not in argv and '/usr/bin/snmpbulkget' not in argv


def test_every_page_authority_validates_in_exact_client_closure_without_owner_fixture(tmp_path):
    package = tmp_path / 'recon_cockpit' / 'secure_agent'
    package.mkdir(parents=True)
    (package.parent / '__init__.py').write_text('')
    (package / '__init__.py').write_text('')
    source = Path(runtime.__file__).parent
    assert 'network_tools_snmp_page_identity' in runtime.MODULES
    assert 'network_tools_snmp_page_fixture' not in runtime.MODULES
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
    assert request['tool_id'] == 'snmp_interface_page_v1'
assert not any(name.endswith('network_tools_snmp_page_fixture') for name in sys.modules)
'''
    values = [envelope(case) for case in contract.T05_CASES]
    completed = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(tmp_path)],
        input=json.dumps(values).encode(), capture_output=True, timeout=10)
    assert completed.returncode == 0, completed.stderr.decode('utf-8', 'backslashreplace')


def test_pinned_runtime_inspection_only_probes_installed_bulkget_elf(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, '_read_regular', lambda path: b'\x7fELFsnmpbulkget')
    monkeypatch.setattr(runtime, 'read_runtime_file', lambda path, tool_id: b'\x7fELFbytes')
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(Path, 'resolve', lambda self, strict: self)
    def probe(argv, *args):
        calls.append(argv)
        return b'libc.so.6 => /usr/lib/libc.so.6 (0x1)\n/usr/lib/ld-linux.so.2 (0x2)\n'
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    value = runtime.inspect_tool_runtime(runtime.SNMP_PAGE, SimpleNamespace(check=lambda: None))
    assert calls == [['/usr/bin/ldd', '/usr/bin/snmpbulkget']]
    assert {row['source'] for row in value['files']} == {
        '/usr/bin/snmpbulkget', '/usr/lib/libc.so.6', '/usr/lib/ld-linux.so.2'}


def test_shell_wrapper_is_rejected_before_any_probe(monkeypatch):
    monkeypatch.setattr(runtime, '_read_regular', lambda path: b'#!/bin/sh\nexec other')
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('wrapper probed'))
    with pytest.raises(IsolationUnavailable, match='ELF'):
        runtime.inspect_tool_runtime(runtime.SNMP_PAGE, SimpleNamespace(check=lambda: None))
