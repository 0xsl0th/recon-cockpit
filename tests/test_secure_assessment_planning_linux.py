"""Owned mock planning through real Linux boundaries; PTYs verify mechanics only."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
import sys
import threading

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.evidence import inspect_assessment
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.openai_broker import OfflineTransport
from test_secure_approval_linux import terminal
from test_secure_launch_admission_linux import run_workflow


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for bounded assessment planning')
    assert sys.platform == 'linux' and os.geteuid() != 0


def planning_options(tmp_path, scenario='success'):
    return ['--isolated-launcher', '--require-launch-audit', '--require-launch-approval',
            '--assessment-planning-offline', scenario, '--planning-ledger', str(tmp_path/'cost')]


def arguments(tmp_path, scenario='success', *, execute=True):
    return ['--workflow-assessment', 'a', '--owned-lab', '--isolated-audit',
            '--isolated-approvals', '--isolated-launch-admission',
            '--policy', 'examples/secure-agent-discovery-policy.json',
            '--assessment-dir', str(tmp_path/'evidence'), '--audit', str(tmp_path/'events.jsonl'),
            '--execute' if execute else '--dry-run', *planning_options(tmp_path, scenario)]


def stored_accounting(tmp_path):
    # Never open another SQLite handle while the writable authority owns it.
    # Closing one can release the process's POSIX locks held through the other.
    with CostLedger(tmp_path/'cost', read_only=True) as ledger:
        return ledger.report(), ledger.attempts(), ledger.events(limit=1000)


def forbid_launches(monkeypatch):
    monkeypatch.setattr(LinuxFixtureLauncher, '_start', lambda *_: pytest.fail('launcher started'))
    monkeypatch.setattr(LinuxApprovalService, '_start', lambda *_: pytest.fail('approval started'))


@pytest.mark.parametrize('backend', ['--fixture', '--owned-lab'])
@pytest.mark.parametrize('case,outcome,exchanges', [
    ('a', 'validated', 3), ('b', 'not_demonstrated', 3), ('c', 'inconclusive', 3),
    ('d', 'inconclusive', 3), ('e', 'inconclusive', 3), ('f', 'inconclusive', 2),
])
def test_owned_planning_all_outcomes_settle_before_both_direct_gates(
        tmp_path, monkeypatch, capsys, terminal, backend, case, outcome, exchanges):
    original_main, original_print = cli.main, cli._print
    original_settle, original_run = CostLedger.settle_usage, LinuxFixtureLauncher.run
    settled, launched, summaries = [], [], []

    def settle(ledger, *args, **kwargs):
        result = original_settle(ledger, *args, **kwargs)
        settled.append(ledger)
        return result

    def run(launcher, *args, **kwargs):
        assert launcher._witness_source is not None and launcher._approval_source is not None
        assert len(settled) == len(launched) + 1
        accounting = settled[-1].report()['summary']
        assert accounting['mode'] == 'simulation' and accounting['reserved_microusd'] == 0
        assert accounting['actual_microusd'] == len(settled) * 778
        assert accounting['unresolved_attempts'] == 0
        assert all(row['state'] == 'settled' for row in settled[-1].attempts())
        rows = [json.loads(line) for line in (tmp_path/'events.jsonl').read_text().splitlines()]
        assert rows[-1]['event_type'] == 'execution_started'
        assert rows[-2]['event_type'] == 'approval_consumed'
        assert sum(row['event_type'] == 'assessment_planning_proposal_released' for row in rows) == len(settled)
        launched.append(True)
        return original_run(launcher, *args, **kwargs)

    def capture(value):
        summaries.append(value)
        original_print(value)

    monkeypatch.setattr(CostLedger, 'settle_usage', settle)
    monkeypatch.setattr(LinuxFixtureLauncher, 'run', run)
    monkeypatch.setattr(cli, '_print', capture)
    monkeypatch.setattr(cli, 'main', lambda argv: original_main([*argv, *planning_options(tmp_path)]))
    run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, backend)
    summary = summaries[-1]
    assert summary['live_calls_enabled'] is False
    assert summary['planning']['actual_provider_calls'] == 0
    assert summary['broker']['calls_reserved'] == len(settled) == len(launched) == exchanges
    assert summary['coordinator_boundary_checks'] == summary['parser_boundary_checks'] == dict.fromkeys(BOUNDARY_NAMES, True)
    report = json.loads((tmp_path/'evidence'/'report.json').read_text())
    assert len(report['records']) == exchanges and report['integrity_issues'] == []
    files = {path: (path.read_bytes(), path.stat().st_mtime_ns)
             for directory in (tmp_path/'cost', tmp_path/'evidence')
             for path in directory.rglob('*') if path.is_file()}
    accounting, attempts, events = stored_accounting(tmp_path)
    assert accounting['summary']['actual_microusd'] == exchanges * 778
    assert len(attempts) == exchanges and all(row['state'] == 'settled' for row in attempts)
    assert sum(row['kind'] == 'cost_settled' for row in events) == exchanges
    assert inspect_assessment(tmp_path/'evidence') == report
    assert files == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in files}


@pytest.mark.parametrize('scenario,state', [
    ('refusal', 'settled'), ('substituted_action', 'settled'),
    ('missing_usage', 'uncertain'), ('unknown_usage', 'uncertain'),
    ('usage_overrun', 'settled'), ('malformed', 'uncertain'), ('http_error', 'uncertain'),
])
def test_untrusted_planning_failure_never_requests_approval_or_execution(
        tmp_path, monkeypatch, capsys, scenario, state):
    forbid_launches(monkeypatch)
    assert cli.main(arguments(tmp_path, scenario)) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary['stop_reason'] == 'provider_failed'
    assert summary['broker']['calls_reserved'] == 1 and summary['actions_succeeded'] == 0
    assert summary['owned_lab']['closure']['connection_count'] == 0
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == state
    if state == 'uncertain':
        assert accounting['summary']['reserved_microusd'] > 0
        assert accounting['summary']['actual_microusd'] == 0
        assert accounting['summary']['unresolved_attempts'] == 1
    else:
        assert accounting['summary']['reserved_microusd'] == 0
        assert accounting['summary']['actual_microusd'] > 0
        assert accounting['summary']['unresolved_attempts'] == 0
    if scenario == 'usage_overrun':
        assert attempts[0]['reservation_overrun_microusd'] > 0
    assert inspect_assessment(tmp_path/'evidence')['records'] == []
    rows = [json.loads(line) for line in (tmp_path/'events.jsonl').read_text().splitlines()]
    assert not any(row['event_type'] in {'execution_started', 'assessment_planning_proposal_released'} for row in rows)


def test_planning_budget_refusal_prevents_transport_and_execution(tmp_path, monkeypatch, capsys):
    forbid_launches(monkeypatch)
    monkeypatch.setattr(OfflineTransport, 'exchange', lambda *_a, **_k: pytest.fail('transport entered'))
    assert cli.main([*arguments(tmp_path), '--planning-budget-microusd', '0']) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary['stop_reason'] == 'provider_failed' and summary['broker']['calls_reserved'] == 0
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert accounting['summary']['committed_microusd'] == 0
    assert len(attempts) == 1 and attempts[0]['state'] == 'cancelled'
    assert inspect_assessment(tmp_path/'evidence')['records'] == []


@pytest.mark.parametrize('execute', [False, True])
def test_dry_or_noninteractive_planning_cannot_start_approval_or_lab(tmp_path, monkeypatch, capsys, execute):
    forbid_launches(monkeypatch)
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    assert cli.main(arguments(tmp_path, execute=execute)) == (2 if execute else 0)
    summary = json.loads(capsys.readouterr().out)
    assert summary['actions_succeeded'] == 0
    assert summary['owned_lab']['closure']['connection_count'] == 0
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == 'settled'
    assert accounting['summary']['actual_microusd'] == 778
    assert inspect_assessment(tmp_path/'evidence')['records'] == []


def test_cancellation_during_dispatched_planning_retains_hold(tmp_path, monkeypatch, capsys):
    forbid_launches(monkeypatch)
    original = OfflineTransport.exchange
    entered, controls = threading.Event(), []

    def exchange(transport, request, **kwargs):
        controls.append(kwargs['control'])
        entered.set()
        return original(transport, request, **kwargs)

    def cancel():
        assert entered.wait(10), 'planning never reached transport'
        controls[0].cancelled.set()

    monkeypatch.setattr(OfflineTransport, 'exchange', exchange)
    with ThreadPoolExecutor(max_workers=1) as pool:
        cancelling = pool.submit(cancel)
        status = cli.main(arguments(tmp_path, 'slow'))
        cancelling.result(timeout=5)
    assert status == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary['stop_reason'] == 'session_cancelled' and summary['actions_succeeded'] == 0
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == 'uncertain'
    assert accounting['summary']['reserved_microusd'] > 0
    assert accounting['summary']['actual_microusd'] == 0
    assert inspect_assessment(tmp_path/'evidence')['records'] == []


def test_lost_settlement_audit_ack_preserves_charge_without_releasing_proposal(tmp_path, monkeypatch, capsys):
    forbid_launches(monkeypatch)
    original = LinuxAuditSink.emit

    def emit(audit, event):
        original(audit, event)
        if event['event_type'] == 'assessment_planning_settled':
            raise AuditUnavailable('OWNED-LOST-PLANNING-SETTLEMENT-ACK')

    monkeypatch.setattr(LinuxAuditSink, 'emit', emit)
    assert cli.main(arguments(tmp_path)) == 3
    assert json.loads(capsys.readouterr().out)['execution_status'] == 'audit_error'
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == 'settled'
    assert accounting['summary']['actual_microusd'] == 778
    assert accounting['summary']['reserved_microusd'] == 0
    rows = [json.loads(line) for line in (tmp_path/'events.jsonl').read_text().splitlines()]
    assert not any(row['event_type'] in {'execution_started', 'assessment_planning_proposal_released'} for row in rows)
    assert not (tmp_path/'evidence'/'report.json').exists()
    assert inspect_assessment(tmp_path/'evidence')['records'] == []
