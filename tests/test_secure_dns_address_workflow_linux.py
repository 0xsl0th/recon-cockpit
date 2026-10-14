"""Actual bounded AAAA/PTR questions, authority enforcement and saved replay."""

import base64
from ipaddress import IPv6Address
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.assessment_inspection import inspect_saved_assessment
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_dns_address_spec as spec
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_nmap_cli import GATES
from test_secure_approval_linux import scripted_review, terminal
from test_secure_fixture_launcher_linux import instrument
import test_secure_network_tools_gates_linux as gates
from test_secure_network_tools_robustness_linux import (
    test_cancellation_after_actual_exec_reaps_tree_and_retains_authority_reservation as _cancel_actual_tool,
    test_tool_cannot_read_host_canary_bootstrap_source_or_authority_descriptors as _private_inputs,
)
from test_secure_redis_snmp_workflow_linux import (
    test_redis_snmp_broadened_udp_permission_is_refused_before_native_exec as _udp_witness,
)


pytestmark = pytest.mark.integration
OK_CASES = ('dig-aaaa-ok', 'dig-ptr-ok')


def policy_for_tool(tool):
    return json.loads(Path('examples/secure-agent-dns-' + spec.QUERY_TYPES[tool].lower() + '-policy.json').read_text())


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned DNS address trials')
    assert sys.platform == 'linux' and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))
    for tool in spec.TOOL_IDS:
        value = policy_for_tool(tool)
        assert value['allowed_tools'] == [tool] and value['require_approval'] is True
    # Both tools are allowed only by this synthetic test policy, enabling an
    # exact cross-profile approval test without a policy denial masking it.
    value.update(policy_version='synthetic-address-approval-tests-v1', allowed_tools=list(spec.TOOL_IDS))
    monkeypatch.setattr(gates, 'required_policy', lambda: parse_policy(value))


@pytest.mark.parametrize('case', spec.CASES)
def test_real_address_completion_bounds_enforcement_and_both_inspectors(tmp_path, capsys, record_property, case):
    tool = spec.tool_for_case(case)
    useful, ordinary = case in spec.SUCCESS_CASES, case in spec.ORDINARY_CASES
    policy = policy_for_tool(tool)
    policy.update(policy_version='synthetic-address-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / 'evidence', tmp_path / 'audit.jsonl'
    started = time.monotonic()
    code = cli.main(['--network-tool-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(audit), '--policy', str(policy_path), *GATES, '--execute'])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    prefix = 'dns_aaaa_' if tool == spec.AAAA else 'dns_ptr_'
    expected = prefix + ('name_not_found' if case.endswith('-nxdomain') else 'no_data'
                         if case.endswith('-nodata') else 'observed') if useful else 'inconclusive'
    assert code in (0, 2) and summary.get('assessment_outcome') == expected, (summary, captured.err)
    assert int(useful) <= summary['actions_succeeded'] <= 1
    assert summary['steps_attempted'] == 1 and summary['output_reserved_bytes'] == 8192
    assert summary['actual_provider_calls'] == 0 and summary['live_calls_enabled'] is False
    elapsed = time.monotonic() - started
    assert elapsed < 60
    report = json.loads((evidence / 'report.json').read_text())
    assert report['integrity_issues'] == [], (report, captured.err)
    assert report['metrics']['useful_actions_completed'] == int(useful)
    assert report['metrics']['actual_cost_microusd'] == report['metrics']['actual_provider_calls'] == 0
    closure = report['owned_lab']['closure']
    # Every negative trial must reach its malformed peer response; startup
    # refusal cannot replace actual execution coverage.
    assert closure['status'] == 'closed' and closure['connection_count'] == closure['request_count'] == 1
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec as lab_spec
    definition = lab_spec(case)
    assert definition['query_bytes'] == (33 if tool == spec.AAAA else 40)
    assert definition['request_count_means'] == 'validated_fixed_dns_address_questions'
    assert len(report['records']) == len(summary['steps']) == 1
    row = report['records'][0]
    assert row['action']['tool_id'] == tool
    assert row['action']['target'] == '127.0.0.1' and row['action']['parameters']['port'] == 8080
    artifact = json.loads((evidence / row['artifact']['filename']).read_bytes())
    assert set(artifact['boundary_checks']) == contract.BOUNDARY_FIELDS
    assert all(value is True for value in artifact['boundary_checks'].values())
    stdout = base64.b64decode(artifact['raw_output_base64'], validate=True)
    stderr = base64.b64decode(artifact['raw_stderr_base64'], validate=True)
    assert artifact['bytes_received'] == len(stdout) + len(stderr) <= 8192
    assert row['observation']['followup_path'] is None
    if useful:
        from recon_cockpit.secure_agent.network_tools_dns_srv_parser import DIG_DENIED_PROBE
        from recon_cockpit.secure_agent.network_tools_dns_address_fixture import records
        assert artifact['status'] == 'succeeded' and artifact['truncated'] is False
        assert stderr in (b'', DIG_DENIED_PROBE)
        assert artifact['provenance']['exit_code'] == 0 and artifact['provenance']['stop_reason'] is None
        field = 'address' if tool == spec.AAAA else 'target'
        expected_records = [{field: ('::ffff:c000:201' if case == 'dig-aaaa-mapped' else str(IPv6Address(value))) if tool == spec.AAAA else value, 'ttl': ttl}
                            for value, ttl in records(case)]
        expected_records.sort(key=lambda item: (item[field], item['ttl']))
        details = row['observation']['details']
        assert details == {'parser_version': spec.PARSER_VERSIONS[tool],
            'kind': 'dns_ipv6_metadata' if tool == spec.AAAA else 'dns_reverse_metadata',
            'semantics': 'untrusted_dns_ipv6_metadata' if tool == spec.AAAA else 'untrusted_dns_reverse_metadata',
            'query_name': spec.QUERY_NAMES[tool], 'query_type': spec.QUERY_TYPES[tool], 'transport': 'tcp',
            'status': 'NXDOMAIN' if case.endswith('-nxdomain') else 'NOERROR',
            'records': expected_records, 'additional_txt_count': int(case.endswith('-injected'))}
        if case.endswith('-injected'):
            assert spec.HOSTILE_NOTE.encode() in stdout
            assert spec.HOSTILE_NOTE not in json.dumps(details)
            assert spec.HOSTILE_NOTE not in (evidence / 'report.md').read_text()
        assert all(step['decision'] == 'allow' for step in summary['steps'])
    else:
        assert artifact['tool_observation'] is None
    if case.endswith('-output-limit'):
        assert artifact['status'] == 'output_limit' and artifact['truncated'] is True
        assert artifact['provenance']['stop_reason'] == 'output_limit'
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
              for path in evidence.iterdir()}
    assert cli.main(['--inspect-assessment', str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert inspect_saved_assessment(evidence) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                      for path in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event['event_type'] == 'execution_started' for event in events) == 1
    assert sum(event['event_type'] == 'execution_finished' for event in events) == 1
    assert not any(event['event_type'].startswith('approval_') for event in events)
    decisions = [event for event in events if event['event_type'] == 'policy_decision']
    assert len(decisions) == 2 and all(event['decision'] == 'allow' for event in decisions)
    record_property('trial_kind', 'ordinary' if ordinary else 'robustness' if useful else 'negative')
    record_property('useful_completion', int(useful))
    record_property('unnecessary_refusals', 0 if ordinary else 'not_applicable')
    record_property('end_to_end_elapsed_ms', round(elapsed * 1000))
    record_property('validated_fixed_dns_address_questions', 1)
    record_property('client_bytes', len(stdout) + len(stderr))
    record_property('actual_provider_calls', 0)
    record_property('actual_cost_microusd', 0)


@pytest.mark.parametrize('case', OK_CASES)
def test_synthetic_address_grant_consumed_once_without_replay(tmp_path, terminal, case):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, case, 1)


@pytest.mark.parametrize('case', OK_CASES)
def test_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch, case):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, case)


@pytest.mark.parametrize('case', OK_CASES)
def test_missing_durable_audit_blocks_before_admission(tmp_path, monkeypatch, case):
    instrument(tmp_path, monkeypatch, lambda source: source.replace('granted = gate.admit(',
        "os.write(2, b'UNEXPECTED-ADDRESS-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 30)
    with gates.boundary(tmp_path, control, case=case) as (_, _, launcher, policy, _):
        with pytest.raises((IsolationUnavailable, ExecutionStopped)):
            launcher.run(parse_action(contract.action(case)), policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}
        assert b'UNEXPECTED-ADDRESS-ADMISSION' not in bytes(launcher._supervisor.buffers['worker_err'])
        assert launcher.close()['request_count'] == 0


@pytest.mark.parametrize('case', OK_CASES)
def test_denied_or_cross_profile_approval_never_launches(tmp_path, terminal, case):
    control = ExecutionControl(time.monotonic() + 40)
    selected = parse_action(contract.action(case))
    with gates.boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        reference, _ = scripted_review(approvals, selected, policy, terminal, control, answer=b'')
        assert reference is None
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        denied = controller.submit(selected.to_dict(), execute=True, interactive=False, execution_control=control)
        assert denied['execution_status'] == 'blocked'
        reference, _ = scripted_review(approvals, selected, policy, terminal, control)
        changed = contract.action(next(other for other in OK_CASES if other != case))
        denied = controller.submit(changed, execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert denied['reasons'] == ['approval_action_changed']
        replay = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert replay['reasons'] == ['approval_unknown_or_replayed']
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}
        assert launcher.close()['request_count'] == 0


@pytest.mark.parametrize('case', OK_CASES)
@pytest.mark.parametrize('field,value', [('target', '127.0.0.2'), ('port', 8081)])
def test_out_of_scope_question_is_denied_without_owner_execution(tmp_path, case, field, value):
    selected = contract.action(case)
    if field == 'target': selected[field] = value
    else: selected['parameters'][field] = value
    control = ExecutionControl(time.monotonic() + 30)
    with gates.boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            selected, execute=True, interactive=False, execution_control=control)
        assert result['execution_status'] == 'blocked' and result['decision'] == 'deny'
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}
        assert launcher.close()['request_count'] == 0
    events = [json.loads(line) for line in (tmp_path / 'audit.jsonl').read_text().splitlines()]
    assert any(event['event_type'] == 'policy_decision' and event['decision'] == 'deny' for event in events)
    assert not any(event['event_type'] == 'execution_started' for event in events)


@pytest.mark.parametrize('case', ['dig-aaaa-stalled', 'dig-ptr-stalled'])
def test_cancellation_after_actual_dig_exec_reaps_tree(tmp_path, case):
    _cancel_actual_tool(tmp_path, case, b'/tool/dig')


@pytest.mark.parametrize('case', OK_CASES)
def test_question_cannot_read_private_inputs_or_authority_descriptors(tmp_path, monkeypatch, case):
    _private_inputs(tmp_path, monkeypatch, case)


@pytest.mark.parametrize('case', OK_CASES)
def test_broadened_udp_permission_refused_before_dig_exec(tmp_path, monkeypatch, case):
    _udp_witness(tmp_path, monkeypatch, case)


@pytest.mark.parametrize('case', OK_CASES)
def test_broadened_task_ceiling_refused_before_dig_exec(tmp_path, monkeypatch, case):
    from test_secure_kerberos_gates_linux import witness_diagnostics
    def widen(source):
        original = '    if tool_id in (runtime.DIG_AAAA, runtime.DIG_PTR):\n        threads = 16'
        assert source.count(original) == 1
        return source.replace(original, original.replace('threads = 16', 'threads = 32'))
    marker = witness_diagnostics(tmp_path, monkeypatch,
        'web_tool_thread_bound_not_verified', worker_transform=widen)
    control = ExecutionControl(time.monotonic() + 40)
    with gates.boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            contract.action(case), execute=True, interactive=False, execution_control=control)
        assert result['execution_status'] == 'blocked', result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers['worker_err'])
        assert b'unexpected_kerbrute_exec' not in bytes(launcher._supervisor.buffers['worker_err'])
        assert launcher.close()['request_count'] == 0
