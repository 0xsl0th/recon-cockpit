"""Batch lifecycle and aggregate replay with explicitly synthetic trial doubles."""
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import web_comparison as batch
from recon_cockpit.secure_agent import web_comparison_grading as grading
from recon_cockpit.secure_agent.evaluation import EvaluationLimits, EvaluationUnavailable, _Directory
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.web_comparison_contract import oracle


def policy():
    return parse_policy(Path('examples/secure-agent-web-comparison-policy.json').read_bytes())


def snapshot(path):
    return {str(p.relative_to(path)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in path.rglob('*') if p.is_file()}


@pytest.fixture
def synthetic_trials(monkeypatch):
    """Exercise scheduling/cache reconciliation; real trial grading is separate."""
    calls = []

    def trial(self, path, case, arm):
        calls.append((case, arm))
        expected = oracle(case, arm)
        grade = {'verdict': 'passed', 'issues': [], 'session_id': str(uuid4()),
            'assessment_id': str(uuid4()), 'lab_instance_id': str(uuid4()),
            'semantic_fingerprint': hashlib.sha256((case + arm).encode()).hexdigest(),
            'outcome': expected['outcome'], 'task_completed': expected['legitimate_completion'],
            'legitimate_actions_completed': expected['actions_succeeded'],
            'unauthorized_proposals': expected['unauthorized_proposals'],
            'unauthorized_blocked': expected['unauthorized_proposals'], 'unauthorized_executed': 0,
            'metrics': {'steps_attempted': 3, 'executions': expected['actions_succeeded'],
                'output_bytes_reserved': expected['output_reserved_bytes'], 'elapsed_ms': 100,
                'prefix_elapsed_ms': 70, 'approval_wait_ms': 0, 'actual_provider_calls': 0,
                'decision_latency_ns': 2000 if arm == 'scripted' else 1000}}
        with _Directory(path) as directory:
            directory.write('synthetic-grade.json', grade, 16384)

    def grade(path, **_):
        try:
            return json.loads((Path(path) / 'synthetic-grade.json').read_bytes())
        except OSError:
            return {'verdict': 'failed', 'issues': ['missing_synthetic_trial'], 'metrics': {}}

    monkeypatch.setattr(batch.WebComparisonRunner, '_run_trial', trial)
    monkeypatch.setattr(grading, 'grade_trial', grade)
    return calls


@pytest.mark.parametrize('repeats', [1, 3, 10])
def test_complete_pairs_replay_without_mutation_and_report_completion_penalty(tmp_path, synthetic_trials, repeats):
    directory = tmp_path / 'batch'
    report = batch.WebComparisonRunner(directory, policy(), EvaluationLimits(repeats=repeats)).run(execute=True)
    assert report['status'] == 'passed' and report['integrity_issues'] == []
    assert report['planned_trials'] == report['passed_trials'] == repeats * 6
    assert report['tasks_completed'] == repeats * 5
    assert report['unauthorized_proposals'] == report['unauthorized_blocked'] == repeats
    assert report['unauthorized_executed'] == report['actual_provider_calls'] == report['approval_wait_ms'] == 0
    assert all(row['semantic_agreement'] for row in report['per_arm_case'])
    assert all(row['scripted_minus_baseline']['decision_latency_ns'] == 1000 for row in report['pairs'])
    injection = next(row for row in report['pairs'] if row['case'] == 'injected')
    assert injection['scripted_minus_baseline']['executions'] == -1
    assert injection['scripted_minus_baseline']['output_bytes_reserved'] == -1024
    assert report['reservations'] == report['batch_allowances'] == batch._totals(repeats * 6)
    before = snapshot(directory)
    assert batch.inspect_comparison(directory) == report
    assert snapshot(directory) == before
    if repeats == 10:
        assert (directory / 'report.json').stat().st_size > 32768
    assert len(synthetic_trials) == repeats * 6


def test_dry_run_never_starts_trials_and_cannot_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(batch.WebComparisonRunner, '_run_trial', lambda *_: pytest.fail('dry run executed'))
    directory = tmp_path / 'batch'
    runner = batch.WebComparisonRunner(directory, policy())
    report = runner.run()
    assert report['status'] == 'dry_run' and report['started_trials'] == 0
    assert report['reservations'] == batch._totals(0)
    assert batch.inspect_comparison(directory) == report
    with pytest.raises(RuntimeError, match='already_used'):
        runner.run(execute=True)
    with pytest.raises(EvaluationUnavailable):
        batch.WebComparisonRunner(directory, policy()).run(execute=True)


def test_cancel_before_start_and_between_trials_preserves_reservations(tmp_path, synthetic_trials):
    runner = batch.WebComparisonRunner(tmp_path / 'before', policy())
    runner.cancel()
    assert runner._cancelled.is_set()
    report = runner.run(execute=True)
    assert report['status'] == 'incomplete' and report['stop_reason'] == 'cancelled'
    assert report['started_trials'] == 0 and synthetic_trials == []
    runner = batch.WebComparisonRunner(tmp_path / 'during', policy())
    report = runner.run(execute=True, on_trial=lambda _: runner.cancel())
    assert report['stop_reason'] == 'cancelled' and report['completed_trials'] == 1
    assert report['reservations'] == batch._totals(1)
    assert batch.inspect_comparison(tmp_path / 'during') == report


@pytest.mark.parametrize('mutation', ['json_claim', 'noncanonical_json', 'markdown', 'trial', 'extra_file', 'torn_journal'])
def test_replay_detects_tampering_without_trusting_cached_claims(tmp_path, synthetic_trials, mutation):
    directory = tmp_path / 'batch'
    original = batch.WebComparisonRunner(directory, policy(), EvaluationLimits(repeats=1)).run(execute=True)
    if mutation in ('json_claim', 'noncanonical_json'):
        path = directory / 'report.json'
        if mutation == 'json_claim':
            value = json.loads(path.read_bytes()); value['tasks_completed'] = 6
            path.write_text(json.dumps(value))
        else:
            path.write_bytes(path.read_bytes() + b'\n')
    elif mutation == 'markdown':
        (directory / 'report.md').write_text('invented result')
    elif mutation == 'trial':
        path = directory / original['trials'][0]['trial_id'] / 'synthetic-grade.json'
        value = json.loads(path.read_bytes()); value['metrics']['elapsed_ms'] += 1
        path.write_text(json.dumps(value))
    elif mutation == 'extra_file':
        (directory / 'unexpected').write_text('not in the manifest')
    else:
        path = directory / 'evaluation.jsonl'; path.write_bytes(path.read_bytes()[:-1])
    before = snapshot(directory)
    actual = batch.inspect_comparison(directory)
    assert actual['status'] in ('failed', 'incomplete') and actual['integrity_issues']
    assert actual['tasks_completed'] == 5
    assert snapshot(directory) == before


@pytest.mark.parametrize('field,value', [('trial_limits', {'max_steps': 4}), ('live_calls_enabled', True),
    ('plan', []), ('batch_allowances', {}), ('mode', []), ('evaluation', {'id': 'unreviewed'})])
def test_manifest_widening_or_substitution_refuses(tmp_path, field, value):
    directory = tmp_path / 'batch'
    batch.WebComparisonRunner(directory, policy()).run()
    path = directory / 'manifest.json'
    manifest = json.loads(path.read_bytes()); manifest[field] = value
    path.write_text(json.dumps(manifest))
    before = snapshot(directory)
    with pytest.raises(EvaluationUnavailable):
        batch.inspect_comparison(directory)
    assert snapshot(directory) == before


def test_repeated_trial_identity_fails_aggregate(tmp_path, synthetic_trials):
    directory = tmp_path / 'batch'
    report = batch.WebComparisonRunner(directory, policy(), EvaluationLimits(repeats=1)).run(execute=True)
    first, second = [directory / t['trial_id'] / 'synthetic-grade.json' for t in report['trials'][:2]]
    value = json.loads(second.read_bytes()); value['session_id'] = json.loads(first.read_bytes())['session_id']
    second.write_text(json.dumps(value))
    actual = batch.inspect_comparison(directory)
    assert actual['status'] == 'failed' and 'reused_session_id' in actual['integrity_issues']


@pytest.mark.parametrize('extra', [b'{}\n', b'[]\n', b'null\n', b'"text"\n'])
def test_appended_journal_corruption_cannot_discard_verified_reservations(tmp_path, synthetic_trials, extra):
    directory = tmp_path / 'batch'
    original = batch.WebComparisonRunner(directory, policy(), EvaluationLimits(repeats=1)).run(execute=True)
    path = directory / 'evaluation.jsonl'
    path.write_bytes(path.read_bytes() + extra)
    before = snapshot(directory)
    report = batch.inspect_comparison(directory)
    assert report['status'] == 'failed' and 'evaluation_journal_limit' in report['integrity_issues']
    assert report['started_trials'] == report['completed_trials'] == 6
    assert report['reservations'] == original['reservations'] == batch._totals(6)
    assert report['tasks_completed'] == 5 and before == snapshot(directory)


@pytest.mark.parametrize('bad', [b'[]\n', b'null\n', b'"text"\n'])
def test_nonobject_journal_returns_structured_incomplete_report(tmp_path, bad):
    directory = tmp_path / 'batch'
    batch.WebComparisonRunner(directory, policy()).run()
    (directory / 'evaluation.jsonl').write_bytes(bad)
    report = batch.inspect_comparison(directory)
    assert report['status'] == 'incomplete' and 'evaluation_journal_invalid' in report['integrity_issues']
