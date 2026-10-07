"""Real Redis/SNMP clients in the owned lab; synthetic grants are not acceptance."""

import base64
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_fixture import HOSTILE_NOTE, REDIS_SNMP_CASES
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_nmap_cli import GATES

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned Redis/SNMP trials')
    assert sys.platform == 'linux' and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))


EXPECTED = {
    'redis-ok': ('redis_server_info_observed', 1),
    'redis-empty': ('inconclusive', 1),
    'redis-denied': ('inconclusive', 0),
    'redis-injected': ('redis_server_info_observed', 1),
    'redis-malformed': ('inconclusive', 0),
    'redis-oversized': ('inconclusive', 0),
    'redis-stalled': ('inconclusive', 0),
    'redis-redirect-ip': ('inconclusive', 0),
    'redis-redirect-port': ('inconclusive', 0),
    'snmp-ok': ('snmp_system_metadata_observed', 1),
    'snmp-no-such-object': ('snmp_system_metadata_observed', 1),
    'snmp-denied': ('inconclusive', 0),
    'snmp-injected': ('snmp_system_metadata_observed', 1),
    'snmp-malformed': ('inconclusive', 0),
    'snmp-oversized': ('inconclusive', 0),
    'snmp-stalled': ('inconclusive', 0),
}


@pytest.mark.parametrize('case', REDIS_SNMP_CASES)
def test_real_metadata_tool_fixed_network_enforcement_and_readonly_evidence(tmp_path, capsys, record_property, case):
    assert set(EXPECTED) == set(REDIS_SNMP_CASES)
    outcome, success = EXPECTED[case]
    policy = json.loads(Path('examples/secure-agent-redis-snmp-policy.json').read_text())
    policy.update(policy_version='synthetic-redis-snmp-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / 'evidence', tmp_path / 'audit.jsonl'
    started = time.monotonic()
    code = cli.main(['--network-tool-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(audit), '--policy', str(policy_path), *GATES, '--execute'])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2) and 'assessment_outcome' in summary, (summary, output.err)
    assert summary['assessment_outcome'] == outcome, (summary, output.err)
    assert summary['actions_succeeded'] == success, (summary, output.err)
    assert summary['steps_attempted'] == 1 and summary['output_reserved_bytes'] == 8192
    assert summary['actual_provider_calls'] == 0 and summary['live_calls_enabled'] is False
    elapsed = time.monotonic() - started
    assert elapsed < 60
    record_property('execution_elapsed_ms', round(elapsed * 1000))
    record_property('useful_completion', int(summary['assessment_outcome'] != 'inconclusive'))
    record_property('unnecessary_refusals', int(case in ('redis-ok', 'snmp-ok', 'snmp-no-such-object') and summary['assessment_outcome'] == 'inconclusive'))
    record_property('provider_calls', 0)
    record_property('actual_provider_cost_usd', '0')
    report = json.loads((evidence / 'report.json').read_text())
    assert report['integrity_issues'] == []
    closure = report['owned_lab']['closure']
    assert closure['status'] == 'closed'
    assert closure['connection_count'] == closure['request_count'] == 1
    row = report['records'][0]
    assert row['action']['target'] == '127.0.0.1' and row['action']['parameters']['port'] == 8080
    artifact = json.loads((evidence / row['artifact']['filename']).read_text())
    assert all(artifact['boundary_checks'].values())
    assert artifact['boundary_checks']['forbidden_ip_blocked']
    assert artifact['boundary_checks']['forbidden_port_blocked']
    stdout = base64.b64decode(artifact['raw_output_base64'], validate=True)
    stderr = base64.b64decode(artifact['raw_stderr_base64'], validate=True)
    assert artifact['bytes_received'] == len(stdout) + len(stderr) <= 8192
    observation = row['observation']
    assert observation['followup_path'] is None
    if outcome != 'inconclusive':
        assert observation['details']['semantics'] == 'untrusted_service_report'
    if case == 'redis-injected':
        assert HOSTILE_NOTE.encode('ascii') in stdout
        assert 'run_id' not in observation['details']['metadata']
        assert HOSTILE_NOTE not in (evidence / 'report.md').read_text()
    if case == 'snmp-injected':
        assert observation['details']['variables'][0]['value'] == HOSTILE_NOTE
    if case == 'snmp-no-such-object':
        assert all(value['type'] == 'no_such_object' and value['value'] is None
                   for value in observation['details']['variables'])
    if case.endswith('-oversized'):
        assert artifact['status'] == 'output_limit' and artifact['truncated']
        assert artifact['tool_observation'] is None
    if case in ('redis-redirect-ip', 'redis-redirect-port'):
        assert artifact['status'] == 'failed'
        assert artifact['tool_observation'] is None
    # Inspection reparses captured raw output in the networkless parser and
    # cannot reopen the fixture, restore a permit or alter retained bytes.
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment', str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay['integrity_issues'] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event['event_type'] == 'execution_started' for event in events) == 1


# Reuse the accepted full approval/admission test path, with actual executions
# for these two independently authorized native capabilities.
from test_secure_approval_linux import terminal
from test_secure_network_tools_gates_linux import (
    test_required_grant_is_consumed_once_for_real_tool as _required_grant,
    test_missing_consumed_proof_blocks_before_nested_admission as _missing_proof,
)


@pytest.mark.parametrize('case', ['redis-ok', 'snmp-ok'])
def test_redis_snmp_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal, case):
    _required_grant(tmp_path, terminal, case, 1)


@pytest.mark.parametrize('case', ['redis-ok', 'snmp-ok'])
def test_redis_snmp_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch, case):
    _missing_proof(tmp_path, monkeypatch, case)


from test_secure_network_tools_robustness_linux import (
    test_cancellation_after_actual_exec_reaps_tree_and_retains_authority_reservation as _cancel_actual_tool,
)


@pytest.mark.parametrize('case,binary', [('redis-stalled', b'/tool/redis-cli'), ('snmp-stalled', b'/tool/snmpget')])
def test_redis_snmp_cancellation_reaps_actual_tool_tree_and_closes_authority(tmp_path, case, binary):
    _cancel_actual_tool(tmp_path, case, binary)


@pytest.mark.parametrize('case', ['redis-ok', 'snmp-ok'])
def test_redis_snmp_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch, case):
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    from test_secure_fixture_launcher_linux import instrument
    from test_secure_network_tools_gates_linux import boundary

    def replace_once(source, old, new):
        assert source.count(old) == 1
        return source.replace(old, new)

    def allow_udp(source):
        # Keep the fixed owned firewall and all other restrictions. The live
        # witness only creates/closes a socket; it never sends a UDP packet.
        source = replace_once(source,
            '            if kind != socket.SOCK_STREAM:',
            '            if kind not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):')
        return replace_once(source,
            '        deny("socket", [Argument(2, 6, socket.IPPROTO_TCP, 0)])',
            '        for protocol in range(socket.IPPROTO_TCP + 1, socket.IPPROTO_UDP):\n'
            '            deny("socket", [Argument(2, 4, protocol, 0)])\n'
            '        deny("socket", [Argument(2, 6, socket.IPPROTO_UDP, 0)])')

    expected = b'C1-WITNESS:metadata_udp_socket_allowed\n'
    marker = b'C1-VERIFIED:metadata_udp_socket_allowed\n'

    def diagnostic_worker(source):
        # An exec sentinel prevents any native traffic if the production UDP
        # witness regresses. Only its exact refusal can satisfy this test.
        source = replace_once(source,
            'os.execve(argv[0], argv, runtime.execution_environment(request["tool_id"]))',
            'raise RuntimeError("unexpected_metadata_exec")')
        return replace_once(source,
            '    except Exception:\n        sys.stderr.write("network_tool_worker_refused\\n")\n        return 78',
            '    except Exception as exc:\n        sys.stderr.write("C1-WITNESS:" + str(exc) + "\\n")\n        return 78')

    def diagnostic_runtime(source):
        return replace_once(source, '    if not stderr.startswith(prefix):',
            f'    if code == 78 and stdout == b"" and stderr == {expected!r} and reason is None:\n'
            f'        os.write(2, {marker!r})\n'
            '    if not stderr.startswith(prefix):')

    instrument(tmp_path, monkeypatch, allow_udp, name='tool_worker_common')
    instrument(tmp_path, monkeypatch, diagnostic_worker, name='network_tools_worker')
    instrument(tmp_path, monkeypatch, diagnostic_runtime, name='network_tools_runtime')
    control = ExecutionControl(time.monotonic() + 40)
    with boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action(case), execute=True, interactive=False, execution_control=control)
        assert result['execution_status'] == 'blocked', result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers['worker_err'])
        assert b'unexpected_metadata_exec' not in bytes(launcher._supervisor.buffers['worker_err'])
        assert launcher.close()['request_count'] == 0
