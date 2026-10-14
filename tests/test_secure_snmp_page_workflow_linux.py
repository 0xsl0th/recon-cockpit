"""Actual one-page GETBULK execution, synthetic approval gates and saved replay."""

import base64
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
from recon_cockpit.secure_agent import network_tools_fixture as fixture
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
POLICY = Path('examples/secure-agent-snmp-page-policy.json')
ORDINARY = frozenset({'snmp-page-ok', 'snmp-page-empty', 'snmp-page-end-of-view',
                     'snmp-page-outside-subtree', 'snmp-page-mixed-boundary', 'snmp-page-end-after-rows'})


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned SNMP page trials')
    assert sys.platform == 'linux' and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))
    value = json.loads(POLICY.read_text())
    assert value['allowed_tools'] == [fixture.SNMP_PAGE_TOOL_ID] and value['require_approval'] is True
    monkeypatch.setattr(gates, 'required_policy', lambda: parse_policy(value))


@pytest.mark.parametrize('case', fixture.SNMP_PAGE_CASES)
def test_real_page_completion_bounds_enforcement_and_both_readonly_inspectors(tmp_path, capsys, record_property, case):
    useful = case in fixture.SNMP_PAGE_SUCCESS_CASES
    ordinary = case in ORDINARY
    policy = json.loads(POLICY.read_text())
    policy.update(policy_version='synthetic-snmp-page-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / 'evidence', tmp_path / 'audit.jsonl'
    started = time.monotonic()
    code = cli.main(['--network-tool-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(audit), '--policy', str(policy_path), *GATES, '--execute'])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    expected = 'snmp_interface_page_observed' if useful else 'inconclusive'
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
    # Negative completion requires an actual independently validated request.
    # Setup failure cannot substitute for exercising a malformed response.
    assert closure['status'] == 'closed' and closure['connection_count'] == closure['request_count'] == 1
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec
    definition = spec(case)
    assert definition['canonical_request_bytes'] == len(fixture.snmp_page_request())
    assert definition['request_count_means'] == 'validated_fixed_snmp_getbulk_requests'
    assert len(report['records']) == len(summary['steps']) == 1
    row = report['records'][0]
    assert row['action']['tool_id'] == fixture.SNMP_PAGE_TOOL_ID
    assert row['action']['target'] == '127.0.0.1' and row['action']['parameters']['port'] == 8080
    artifact = json.loads((evidence / row['artifact']['filename']).read_bytes())
    assert set(artifact['boundary_checks']) == contract.BOUNDARY_FIELDS
    assert all(value is True for value in artifact['boundary_checks'].values())
    stdout = base64.b64decode(artifact['raw_output_base64'], validate=True)
    stderr = base64.b64decode(artifact['raw_stderr_base64'], validate=True)
    assert artifact['bytes_received'] == len(stdout) + len(stderr) <= 8192
    assert row['observation']['followup_path'] is None
    if useful:
        assert artifact['status'] == 'succeeded' and artifact['truncated'] is False
        assert stderr == b'' and artifact['provenance']['exit_code'] == 0
        assert artifact['provenance']['stop_reason'] is None
        details = row['observation']['details']
        assert details['parser_version'] == 'snmp-interface-page-text-v1'
        assert details['kind'] == 'snmp_interface_page_metadata'
        assert details['semantics'] == 'untrusted_snmp_interface_page_metadata'
        assert details['query_oid'] == '.1.3.6.1.2.1.2.2.1.2'
        assert details['max_repetitions'] == 4
        assert details['inventory_complete'] is details['service_identity_verified'] is False
        rows = details['rows']
        boundary_kind = ('end_of_mib_view' if case in {'snmp-page-end-of-view', 'snmp-page-end-after-rows'}
                         else 'outside_ifdescr_subtree' if case in {'snmp-page-outside-subtree', 'snmp-page-mixed-boundary'}
                         else None)
        assert details['outcome'] == (boundary_kind or 'interface_page')
        assert len(rows) == (1 if case == 'snmp-page-end-of-view' else 4)
        if boundary_kind is None:
            assert details['end_boundary'] is None and details['page_full'] is True
            assert [item['interface_index'] for item in rows] == [1, 2, 3, 4]
            assert [item['returned_oid'] for item in rows] == [details['query_oid'] + '.' + str(index) for index in range(1, 5)]
            assert all(item['kind'] == 'interface_description' for item in rows)
            descriptions = ['HarborDesk synthetic interface ' + str(index) for index in range(1, 5)]
            if case == 'snmp-page-empty': descriptions = ['', '', '', '']
            if case == 'snmp-page-injected':
                descriptions[1] = fixture.HOSTILE_NOTE
            assert [item['description'] for item in rows] == descriptions
        else:
            offset = 2 if case in {'snmp-page-mixed-boundary', 'snmp-page-end-after-rows'} else 0
            assert all(item['kind'] == 'interface_description' for item in rows[:offset])
            assert all(item['kind'] == boundary_kind for item in rows[offset:])
            assert [item['interface_index'] for item in rows[:offset]] == list(range(1, offset + 1))
            assert [item['description'] for item in rows[:offset]] == [
                'HarborDesk synthetic interface ' + str(index) for index in range(1, offset + 1)]
            assert all(item['interface_index'] is item['description'] is None for item in rows[offset:])
            assert details['end_boundary'] == {'kind': boundary_kind, 'returned_oid': rows[offset]['returned_oid']}
            assert details['page_full'] is False
        assert all(step['decision'] == 'allow' for step in summary['steps'])
    else:
        assert artifact['tool_observation'] is None
    if case == 'snmp-page-output-limit':
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
    record_property('validated_fixed_snmp_getbulk_requests', 1)
    record_property('client_bytes', len(stdout) + len(stderr))
    record_property('actual_provider_calls', 0)
    record_property('actual_cost_microusd', 0)


def test_synthetic_page_grant_consumed_once_without_replay(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, 'snmp-page-ok', 1)


def test_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, 'snmp-page-ok')


def test_missing_durable_audit_blocks_before_admission(tmp_path, monkeypatch):
    instrument(tmp_path, monkeypatch, lambda source: source.replace('granted = gate.admit(',
        "os.write(2, b'UNEXPECTED-PAGE-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 30)
    with gates.boundary(tmp_path, control, case='snmp-page-ok') as (_, _, launcher, policy, _):
        with pytest.raises((IsolationUnavailable, ExecutionStopped)):
            launcher.run(parse_action(contract.action('snmp-page-ok')), policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}
        assert b'UNEXPECTED-PAGE-ADMISSION' not in bytes(launcher._supervisor.buffers['worker_err'])
        assert launcher.close()['request_count'] == 0


def test_denied_or_changed_page_approval_never_launches(tmp_path, terminal):
    control = ExecutionControl(time.monotonic() + 40)
    selected = parse_action(contract.action('snmp-page-ok'))
    with gates.boundary(tmp_path, control, case='snmp-page-ok') as (audit, approvals, launcher, policy, session):
        reference, _ = scripted_review(approvals, selected, policy, terminal, control, answer=b'')
        assert reference is None
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        denied = controller.submit(selected.to_dict(), execute=True, interactive=False, execution_control=control)
        assert denied['execution_status'] == 'blocked'
        reference, _ = scripted_review(approvals, selected, policy, terminal, control)
        changed = {**selected.to_dict(), 'rationale': 'changed after review'}
        denied = controller.submit(changed, execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert denied['reasons'] == ['approval_action_changed']
        replay = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert replay['reasons'] == ['approval_unknown_or_replayed']
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}
        assert launcher.close()['request_count'] == 0


@pytest.mark.parametrize('field,value', [('target', '127.0.0.2'), ('port', 8081)])
def test_out_of_scope_page_proposal_is_denied_without_owner_execution(tmp_path, field, value):
    selected = contract.action('snmp-page-ok')
    if field == 'target':
        selected[field] = value
    else:
        selected['parameters'][field] = value
    control = ExecutionControl(time.monotonic() + 30)
    with gates.boundary(tmp_path, control, case='snmp-page-ok', approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            selected, execute=True, interactive=False, execution_control=control)
        assert result['execution_status'] == 'blocked' and result['decision'] == 'deny'
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}
        assert launcher.close()['request_count'] == 0
    events = [json.loads(line) for line in (tmp_path / 'audit.jsonl').read_text().splitlines()]
    assert any(event['event_type'] == 'policy_decision' and event['decision'] == 'deny' for event in events)
    assert not any(event['event_type'] == 'execution_started' for event in events)


def test_cancellation_after_actual_snmpbulkget_exec_reaps_tree(tmp_path):
    _cancel_actual_tool(tmp_path, 'snmp-page-stalled', b'/tool/snmpbulkget')


def test_page_cannot_read_private_inputs_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, 'snmp-page-ok')


def test_broadened_udp_permission_refused_before_bulkget_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, 'snmp-page-ok')
