"""One GETNEXT seed cannot acquire walk, configuration or legacy GET authority."""

import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import tool_adapters as adapters
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import SNMPInterfaceNextParameters, ValidationError, parse_action, parse_policy
from test_secure_network_tools_runtime import envelope, manifest, recommit, verify, policy


def test_all_28_accepted_runtime_invocations_remain_byte_identical():
    selected = {tool: [exe, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, exe in runtime.EXECUTABLES.items() if tool not in (runtime.SNMP_NEXT, runtime.SSH_ALGORITHMS)}
    assert len(selected) == 28
    # Captured from accepted PR66 main before C13 changes.
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == (
        "c6495ce4b50307c17b42e42f4a29efff3719c7cfa1148a9426ec5488898418cf")


def test_all_37_accepted_adapters_remain_byte_identical():
    selected = {tool: adapter.to_dict() for tool, adapter in adapters.ADAPTERS.items()
                if tool not in (adapters.SNMP_NEXT_TOOL_ID, adapters.SSH_ALGORITHMS_TOOL_ID)}
    assert len(selected) == 37
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == (
        "8de073be292540c83863c885ec1696fa8d6dec6429d88551ed0d10dddd5365ff")


def test_fixed_getnext_has_one_seed_no_retry_correction_walk_or_udp():
    assert runtime.EXECUTABLES[runtime.SNMP_NEXT] == "/usr/bin/snmpgetnext"
    assert runtime.FIXED_ARGV[runtime.SNMP_NEXT] == (
        "/tool/snmpgetnext", "-v", "2c", "-c", "recon-fixture-public", "-r", "0", "-t", "2",
        "-Cf", "-On", "-Ot", "-Ox", "-m", "", "-M", "", "--dontLoadHostConfig=true",
        "--noPersistentLoad=true", "--noPersistentSave=true", "tcp:127.0.0.1:8080",
        ".1.3.6.1.2.1.2.2.1.2")
    assert runtime.FIXED_ARGV[runtime.SNMP_NEXT][1:-1] == runtime.FIXED_ARGV[runtime.SNMP][1:-3]
    assert [arg for arg in runtime.FIXED_ARGV[runtime.SNMP_NEXT] if arg.startswith('.')] == [
        '.1.3.6.1.2.1.2.2.1.2']
    assert runtime.EXECUTABLES[runtime.SNMP_NEXT] not in {
        exe for tool, exe in runtime.EXECUTABLES.items() if tool != runtime.SNMP_NEXT}


def test_getnext_is_typed_immutable_and_independent_from_get_policy():
    action = parse_action(contract.action('snmp-next-ok'))
    assert type(action.parameters) is SNMPInterfaceNextParameters
    with pytest.raises(FrozenInstanceError):
        action.parameters.port = 161
    descriptor = adapters.get_adapter(runtime.SNMP_NEXT).to_dict()
    assert descriptor['parameters']['required'] == ['port', 'timeout_seconds', 'max_output_bytes']
    assert descriptor['parameters']['additionalProperties'] is False
    assert descriptor['parser_version'] == 'snmp-interface-next-text-v1'
    configured = policy().to_dict()
    configured.update(allowed_tools=[runtime.SNMP_NEXT], allowed_methods=[])
    assert parse_policy(configured).evaluate(action).decision == 'approval_required'
    assert parse_policy(configured).evaluate(parse_action(contract.action('snmp-ok'))).reasons == ('tool_not_allowed',)
    configured['allowed_tools'] = [runtime.SNMP]
    assert parse_policy(configured).evaluate(action).reasons == ('tool_not_allowed',)


@pytest.mark.parametrize('field', ['oid', 'oids', 'seed', 'community', 'version', 'username',
    'password', 'credentials', 'authentication', 'privacy', 'walk', 'bulk', 'set', 'followup',
    'protocol', 'transport', 'retry', 'retries', 'correction', 'argv', 'executable', 'command',
    'environment', 'config', 'mibs', 'output_path'])
def test_caller_cannot_add_operation_credentials_or_configuration(field):
    action = contract.action('snmp-next-ok')
    action['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError, match='unknown_parameters_fields'):
        parse_action(action)


@pytest.mark.parametrize('field,value', [('port', True), ('timeout_seconds', 0),
    ('max_output_bytes', False), ('port', 65536), ('timeout_seconds', 31), ('max_output_bytes', 65537)])
def test_parameter_types_and_bounds_are_closed(field, value):
    action = contract.action('snmp-next-ok')
    action['parameters'][field] = value
    with pytest.raises(ValidationError):
        parse_action(action)


def test_getnext_cannot_inherit_host_secrets_mibs_or_persistent_state(monkeypatch):
    for name in ('HOME', 'SNMPCONFPATH', 'MIBS', 'MIBDIRS', 'MIBFILES', 'SNMP_PERSISTENT_DIR',
                 'SNMP_PERSISTENT_FILE', 'SNMP_COMMUNITY', 'LD_PRELOAD', 'SSLKEYLOGFILE'):
        monkeypatch.setenv(name, '/private/canary')
    assert runtime.execution_environment(runtime.SNMP_NEXT) == {
        'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null', 'MALLOC_ARENA_MAX': '1',
        'MIBS': '', 'MIBDIRS': '', 'MIBFILES': '', 'SNMPCONFPATH': '/tool/no-snmp-config',
        'SNMP_PERSISTENT_DIR': '/tool/no-snmp-state'}
    assert runtime.execution_environment(runtime.SNMP_NEXT) == runtime.execution_environment(runtime.SNMP)
    assert runtime.compiled_files(runtime.SNMP_NEXT) == ()
    permissions = worker._landlock_permissions(manifest(runtime.SNMP_NEXT))
    assert permissions['/tool/snmpgetnext'] == 5 and '/tool/snmpget' not in permissions
    assert not any(p.startswith(('/etc', '/home', '/root', '/var', '/tool/data', '/tool/no-snmp')) for p in permissions)
    assert '/usr/bin/python3' not in permissions


@pytest.mark.parametrize('path', ['/etc/snmp/snmp.conf', '/etc/hosts', '/etc/resolv.conf',
    '/root/.snmp/snmp.conf', '/usr/share/snmp/mibs/IF-MIB.txt', '/var/lib/snmp/snmpgetnext.conf',
    '/tool/data/community', '/tmp/credentials', '/usr/bin/snmpwalk', '/usr/bin/snmpget', '/bin/sh'])
def test_runtime_closure_rejects_configuration_credentials_or_other_programs(path):
    value = manifest(runtime.SNMP_NEXT)
    value['files'].append({'source': path, 'destination': path, 'size': 4, 'sha256': 'a' * 64})
    value['files'].sort(key=lambda row: row['destination'])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('reverse', [False, True])
def test_get_and_getnext_cannot_swap_runtime_or_recommitted_action(reverse):
    cases = ('snmp-ok', 'snmp-next-ok') if reverse else ('snmp-next-ok', 'snmp-ok')
    value, other = (envelope(case) for case in cases)
    value['runtime'] = deepcopy(other['runtime'])
    with pytest.raises(ValueError):
        verify(value)
    value['launch']['action'] = other['launch']['action']
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize('fault', ['mode', 'inner_mode', 'identity', 'manifest', 'namespace',
    'deadline', 'sequence', 'reservation', 'policy', 'action', 'limit'])
def test_fresh_commitments_cannot_expand_getnext_authority(fault):
    from test_secure_network_tools_runtime import test_fresh_commitments_do_not_bypass_fixed_authority
    test_fresh_commitments_do_not_bypass_fixed_authority('snmp-next-ok', fault)


@pytest.mark.parametrize('code,reason,expected', [(0, None, 'succeeded'), (2, None, 'failed'),
    (-15, 'timeout', 'timeout'), (-15, 'output_limit', 'output_limit')])
def test_capture_preserves_bounded_channels_without_promoting_failures(monkeypatch, code, reason, expected):
    monkeypatch.setattr(runtime, 'sys', SimpleNamespace(platform='linux'))
    launch = envelope('snmp-next-ok')
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
    assert result['provenance']['runtime_manifest']['tool_id'] == runtime.SNMP_NEXT
    assert result['provenance']['parser_version'] == 'snmp-interface-next-text-v1'
    assert result['provenance']['exit_code'] == code and result['provenance']['stop_reason'] == reason


def test_getnext_keeps_single_task_filter_and_strict_inherited_resource_caps(monkeypatch):
    calls, limits = [], {}
    monkeypatch.setattr(worker.common, 'syscall_filter', lambda **kw: calls.append(kw))
    worker.syscall_filter(runtime.SNMP_NEXT)
    assert calls == [{'allow_threads': False}]
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, 'setrlimit', lambda kind, value: limits.update({kind: value}))
    worker._limits(runtime.SNMP_NEXT)
    assert limits == {worker.resource.RLIMIT_AS: (256 * 1024 * 1024,) * 2,
        worker.resource.RLIMIT_CPU: (5, 5), worker.resource.RLIMIT_NOFILE: (64, 64),
        worker.resource.RLIMIT_NPROC: (1, 1), worker.resource.RLIMIT_CORE: (0, 0),
        worker.resource.RLIMIT_FSIZE: (0, 0)}
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda kind: (2, 2))
    worker._limits(runtime.SNMP_NEXT)
    assert set(limits.values()) == {(0, 0), (1, 1), (2, 2)}


def test_parser_bootstrap_does_not_mount_getnext_native_program(monkeypatch):
    from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
    monkeypatch.setattr(parser_runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(parser_runtime, '_namespaces', lambda: {key: key for key in ('user', 'net', 'mnt', 'pid')})
    argv = parser_runtime._command(runtime.SNMP_NEXT, ('/stdlib', [
        ('/usr/bin/python3', '/usr/bin/python3'), ('/usr/bin/snmpgetnext', '/tool/snmpgetnext')]))
    assert '--unshare-net' in argv and '/app/network_tools_snmp_next_parser.py' in argv
    assert '/tool/snmpgetnext' not in argv and '/usr/bin/snmpgetnext' not in argv


def test_pinned_runtime_inspection_only_probes_installed_getnext_elf(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, '_read_regular', lambda path: b'\x7fELFsnmpgetnext')
    monkeypatch.setattr(runtime, 'read_runtime_file', lambda path, tool_id: b'\x7fELFbytes')
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(Path, 'resolve', lambda self, strict: self)
    def probe(argv, *args):
        calls.append(argv)
        return b'libc.so.6 => /usr/lib/libc.so.6 (0x1)\n/usr/lib/ld-linux.so.2 (0x2)\n'
    monkeypatch.setattr(runtime, '_runtime_probe', probe)
    value = runtime.inspect_tool_runtime(runtime.SNMP_NEXT, SimpleNamespace(check=lambda: None))
    assert calls == [['/usr/bin/ldd', '/usr/bin/snmpgetnext']]
    assert {row['source'] for row in value['files']} == {
        '/usr/bin/snmpgetnext', '/usr/lib/libc.so.6', '/usr/lib/ld-linux.so.2'}


def test_shell_wrapper_is_rejected_before_any_probe(monkeypatch):
    monkeypatch.setattr(runtime, '_read_regular', lambda path: b'#!/bin/sh\nexec other')
    monkeypatch.setattr(runtime, '_runtime_probe', lambda *args: pytest.fail('wrapper probed'))
    with pytest.raises(IsolationUnavailable, match='ELF'):
        runtime.inspect_tool_runtime(runtime.SNMP_NEXT, SimpleNamespace(check=lambda: None))
