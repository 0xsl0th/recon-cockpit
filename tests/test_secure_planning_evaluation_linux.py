"""Actual disconnected planning evaluations; saved evidence is independently graded."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import provider_lab
from recon_cockpit.secure_agent.assessment_planning_transport import LinuxOwnedPlanningTransport
from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.evaluation import EvaluationLimits
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.planning_evaluation import PlanningEvaluationRunner, inspect_planning_evaluation
from test_secure_evaluation_linux import EXPECTED, files_snapshot, policy
from test_secure_provider_linux import descendants, assert_no_survivors, assert_reaped


pytestmark = pytest.mark.integration


@pytest.fixture(scope='module', autouse=True)
def require_real_linux():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned planning evaluations')
    assert sys.platform == 'linux' and os.geteuid() != 0
    LinuxOfflineCoordinator().check_available()


@contextmanager
def observe_runtime(*, on_tls_send=None):
    """Observe the real isolated launcher and TLS trees without doubling them."""
    runtime = SimpleNamespace(processes=[], descendants={}, launches=[], settlements=[])
    original_popen, original_close = subprocess.Popen, provider_lab._Supervisor.close
    original_send, original_run = provider_lab._send, LinuxFixtureLauncher.run
    original_settle = CostLedger.settle_usage

    def popen(argv, *args, **kwargs):
        process = original_popen(argv, *args, **kwargs)
        runtime.processes.append((process, list(argv), dict(kwargs.get('env', {}))))
        return process

    def close(supervisor):
        for child in supervisor.processes.values():
            runtime.descendants.update(descendants(child.pid))
        return original_close(supervisor)

    def send(supervisor, process, raw, *, close=False):
        original_send(supervisor, process, raw, close=close)
        if close and process is supervisor.processes.get('worker') and on_tls_send is not None:
            on_tls_send()

    def settle(ledger, *args, **kwargs):
        result = original_settle(ledger, *args, **kwargs)
        runtime.settlements.append(result['attempt_id'])
        return result

    def run(launcher, *args, **kwargs):
        assert launcher._witness_source is not None and launcher._approval_source is not None
        assert launcher._config['policy']['require_approval'] is False
        assert not hasattr(launcher._approval_service, '_process')
        assert len(runtime.settlements) == len(runtime.launches) + 1
        runtime.launches.append(launcher.identity['instance_id'])
        return original_run(launcher, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(subprocess, 'Popen', popen)
        patch.setattr(provider_lab._Supervisor, 'close', close)
        patch.setattr(provider_lab, '_send', send)
        patch.setattr(CostLedger, 'settle_usage', settle)
        patch.setattr(LinuxFixtureLauncher, 'run', run)
        yield runtime


def assert_destroyed(runtime):
    assert_reaped(runtime.processes)
    assert_no_survivors(runtime.descendants)


def tls_process_count(runtime, role):
    return sum('/app/assessment_planning_tls_' + role + '.py' in argv
               for _, argv, _ in runtime.processes)


@pytest.fixture(scope='module')
def baseline(tmp_path_factory):
    path = tmp_path_factory.mktemp('planning-evaluation')/'baseline'
    with observe_runtime() as runtime:
        report = PlanningEvaluationRunner(path, policy(), EvaluationLimits(repeats=1)).run(execute=True)
    assert report['status'] == 'passed', report
    return SimpleNamespace(path=path, report=report, runtime=runtime)


def test_real_six_case_planning_batch_preserves_expected_outcomes_and_accounting(baseline):
    report = baseline.report
    assert report['planned_trials'] == report['started_trials'] == report['completed_trials'] == report['passed_trials'] == 6
    assert report['failed_trials'] == report['not_run_trials'] == 0
    assert report['cleanup_verified_trials'] == report['isolation_verified_trials'] == 6
    assert report['integrity_issues'] == [] and report['resource_accounting_complete'] is True
    assert report['outcomes'] == {'validated': 1, 'not_demonstrated': 1, 'inconclusive': 4}
    assert report['correct_abstentions'] == 4
    assert report['reservations']['trials'] == 6 and report['reservations']['tool_output_bytes'] == 18432
    assert report['reservations']['simulation_microusd'] == 6 * 55326
    assert report['actual_provider_calls'] == 0 and report['human_acceptance'] is False
    assert report['approval_mode'] == 'unattended_owned_policy'
    metrics = report['aggregate_metrics']
    assert metrics['executions'] == metrics['broker_calls_reserved'] == 17
    assert metrics['actions_succeeded'] == 15 and metrics['unnecessary_actions'] == 0
    assert metrics['output_bytes_reserved'] == metrics['broker_output_tokens_reserved'] == 17408
    assert 0 < metrics['broker_request_bytes_reserved'] <= report['reservations']['broker_request_bytes']
    assert 0 < metrics['retained_response_bytes'] <= metrics['output_bytes_reserved']
    assert metrics['owned_tls_exchanges'] == 17 and metrics['actual_provider_calls'] == 0
    assert metrics['planning_actual_microusd'] == 17 * 778
    assert metrics['planning_reserved_microusd'] == metrics['planning_unresolved_attempts'] == 0
    assert metrics['planning_input_tokens'] == 17 * 512
    assert metrics['planning_output_tokens'] == 17 * 128
    assert metrics['planning_cached_input_tokens'] == 0
    assert all(row['semantic_agreement'] for row in report['per_case'])
    for row in report['trials']:
        grade = row['grade']
        outcome, classification, executions, succeeded = EXPECTED[row['case']]
        assert (grade['outcome'], grade['classification']) == (outcome, classification)
        assert (grade['metrics']['executions'], grade['metrics']['actions_succeeded']) == (executions, succeeded)
        assert grade['observed_terminal_reason'] == grade['expected_terminal_reason']
        assert all(grade['checks'].values())


def test_real_batch_shared_ledger_preserves_distinct_trial_scopes_and_caps(baseline):
    before = files_snapshot(baseline.path)
    with CostLedger(baseline.path/'planning-ledger', read_only=True) as ledger:
        cost = ledger.report()
        assert cost == baseline.report['planning_cost']
        assert cost['summary']['mode'] == 'simulation'
        assert cost['summary']['limit_microusd'] == 6 * 55326
        assert cost['summary']['actual_microusd'] == 17 * 778
        assert cost['summary']['reserved_microusd'] == cost['summary']['unresolved_attempts'] == 0
        attempts = ledger.attempts()
        assert len(attempts) == 17 and all(row['state'] == 'settled' for row in attempts)
        assert all(row['actual_microusd'] == 778 for row in attempts)
        assert len({row['scope_id'] for row in attempts}) == 6
        session_scopes, agent_scopes = set(), set()
        for scope_id in {row['scope_id'] for row in attempts}:
            report = ledger.report(scope_id)
            chain = report['budget_chain']
            assert [row['kind'] for row in chain] == ['account', 'engagement', 'session', 'agent', 'action']
            assert chain[0]['scope_id'] == ledger.account_id
            assert chain[2]['limit_microusd'] == 55326
            session_scopes.add(chain[2]['scope_id'])
            agent_scopes.add(chain[3]['scope_id'])
            assert report['summary']['attempt_count'] in (2, 3)
        assert len(session_scopes) == len(agent_scopes) == 6
        for trial in baseline.report['trials']:
            runtime = json.loads((baseline.path/trial['trial_id']/'runtime.json').read_text())
            planning = runtime['planning']
            assert planning['ledger_id'] == ledger.ledger_id
            assert planning['account_scope_id'] == ledger.account_id
            for kind in ('session', 'agent', 'action'):
                assert planning[kind + '_scope_id'] == 'planning-' + kind + '-' + runtime['session_id']
            assert ledger.report(planning['action_scope_id'])['summary']['attempt_count'] == EXPECTED[trial['case']][2]
            assert runtime['services']['approval_mode'] == 'unattended_owned_policy'
            assert runtime['services']['approval_worker_started'] is False
            assert all(runtime['cleanup'].values())
            receipts = planning['transport_receipts']
            assert len(receipts) == EXPECTED[trial['case']][2]
            assert all(row['receipt']['cleanup'] == {'worker_reaped': True, 'owner_reaped': True} for row in receipts)
    assert files_snapshot(baseline.path) == before


def test_real_batch_isolation_freshness_and_every_process_tree_destroyed(baseline):
    report, runtime = baseline.report, baseline.runtime
    for key in ('session_id', 'assessment_id', 'lab_instance_id', 'broker_id'):
        assert len({row['grade'][key] for row in report['trials']}) == 6
    assert len(set(runtime.launches)) == 6
    assert len(runtime.launches) == len(runtime.settlements) == 17
    assert len(set(runtime.settlements)) == 17
    assert tls_process_count(runtime, 'owner') == tls_process_count(runtime, 'worker') == 17
    for row in report['trials']:
        events = [json.loads(line) for line in (baseline.path/row['trial_id']/'audit.jsonl').read_text().splitlines()]
        assert not any(event['event_type'].startswith('approval_') for event in events)
        assert all(event['approval_reference'] is None for event in events if 'approval_reference' in event)
    assert_destroyed(runtime)


def test_real_planning_batch_read_only_regrade_matches_saved_reports(baseline, monkeypatch):
    before = files_snapshot(baseline.path)
    monkeypatch.setattr(PlanningEvaluationRunner, 'run', lambda *_a, **_k: pytest.fail('inspection started a run'))
    monkeypatch.setattr(LinuxOwnedPlanningTransport, 'exchange', lambda *_a, **_k: pytest.fail('inspection started TLS'))
    monkeypatch.setattr(LinuxFixtureLauncher, 'run', lambda *_a, **_k: pytest.fail('inspection launched assessment'))
    assert inspect_planning_evaluation(baseline.path) == baseline.report
    assert files_snapshot(baseline.path) == before
    assert baseline.path.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in baseline.path.rglob('*') if path.is_file())


@pytest.mark.parametrize('fault', ['tls_cleanup', 'settlement_charge', 'missing_tls_event', 'reused_trial_scope'])
def test_tampered_real_planning_evidence_never_receives_abstention_credit(baseline, tmp_path, fault):
    directory = tmp_path/'changed'
    shutil.copytree(baseline.path, directory)
    trial = directory/'trial-003-c'
    path = trial/'audit.jsonl'
    events = [json.loads(line) for line in path.read_text().splitlines()]
    if fault == 'tls_cleanup':
        event = next(row for row in events if row['event_type'] == 'assessment_planning_tls_finished')
        event['receipt']['cleanup']['owner_reaped'] = False
    elif fault == 'settlement_charge':
        event = next(row for row in events if row['event_type'] == 'assessment_planning_settled')
        event['actual_microusd'] += 1
    elif fault == 'missing_tls_event':
        events.remove(next(row for row in events if row['event_type'] == 'assessment_planning_tls_finished'))
    else:
        runtime_path = trial/'runtime.json'
        runtime = json.loads(runtime_path.read_text())
        other = json.loads((directory/'trial-001-a'/'runtime.json').read_text())
        runtime['planning']['action_scope_id'] = other['planning']['action_scope_id']
        runtime_path.write_text(json.dumps(runtime))
    path.write_text('\n'.join(json.dumps(row) for row in events) + '\n')
    before = files_snapshot(directory)
    report = inspect_planning_evaluation(directory)
    assert report['status'] == 'failed' and report['resource_accounting_complete'] is False
    assert report['correct_abstentions'] == 3 and report['failed_trials'] == 1
    grade = next(row['grade'] for row in report['trials'] if row['case'] == 'c')
    assert grade['verdict'] == grade['classification'] == 'failed'
    assert grade['metrics']['planning_actual_microusd'] is None
    assert files_snapshot(directory) == before


def test_real_between_trial_cancel_preserves_grade_and_prevents_next_dispatch(tmp_path):
    runner = PlanningEvaluationRunner(tmp_path/'cancelled', policy(), EvaluationLimits(repeats=1))
    with observe_runtime() as runtime:
        report = runner.run(execute=True, on_trial=lambda _: runner.cancel())
    assert report['status'] == 'incomplete' and report['stop_reason'] == 'cancelled'
    assert report['passed_trials'] == report['started_trials'] == 1
    assert report['not_run_trials'] == 5 and len(set(runtime.launches)) == 1
    assert tls_process_count(runtime, 'owner') == tls_process_count(runtime, 'worker') == 3
    assert inspect_planning_evaluation(runner.directory) == report
    assert_destroyed(runtime)


def test_real_active_tls_cancel_never_scores_partial_trial_as_abstention(tmp_path):
    runner = PlanningEvaluationRunner(tmp_path/'cancelled', policy(), EvaluationLimits(repeats=1))
    with observe_runtime(on_tls_send=runner.cancel) as runtime:
        report = runner.run(execute=True)
    assert report['status'] == 'incomplete' and report['stop_reason'] == 'cancelled'
    assert report['started_trials'] == report['failed_trials'] == 1
    assert report['passed_trials'] == report['correct_abstentions'] == 0
    assert report['not_run_trials'] == 5
    assert report['resource_accounting_complete'] is False
    assert report['aggregate_metrics']['output_bytes_reserved'] is None
    assert runtime.launches == runtime.settlements == []
    assert tls_process_count(runtime, 'owner') == tls_process_count(runtime, 'worker') == 1
    with CostLedger(runner.directory/'planning-ledger', read_only=True) as ledger:
        attempts = ledger.attempts()
        assert len(attempts) == 1 and attempts[0]['state'] == 'uncertain'
        assert ledger.report()['summary']['reserved_microusd'] > 0
        assert ledger.report()['summary']['actual_microusd'] == 0
    assert inspect_planning_evaluation(runner.directory) == report
    assert_destroyed(runtime)


def test_real_batch_deadline_stops_authority_and_prevents_next_trial(tmp_path):
    runner = PlanningEvaluationRunner(tmp_path/'expired', policy(),
                                     EvaluationLimits(repeats=1, max_runtime_seconds=1))
    with observe_runtime() as runtime:
        report = runner.run(execute=True)
    assert report['status'] == 'incomplete' and report['stop_reason'] == 'deadline'
    assert report['started_trials'] == 1 and report['not_run_trials'] == 5
    assert report['passed_trials'] == report['correct_abstentions'] == 0
    assert inspect_planning_evaluation(runner.directory) == report
    assert_destroyed(runtime)
