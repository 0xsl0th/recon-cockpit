"""Portable batch admission, storage, and read-only replay checks."""

import json
from pathlib import Path
import sqlite3

import pytest

from recon_cockpit.secure_agent import planning_evaluation as evaluation
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.evaluation import EvaluationLimits, EvaluationUnavailable, inspect_evaluation
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.planning_evaluation_contract import (
    TRIAL_BUDGET, descriptor, evaluation_identity, totals)


def policy():
    path = Path(__file__).resolve().parents[1] / "examples/secure-agent-evaluation-policy.json"
    return parse_policy(path.read_bytes())


def files(path):
    return {str(item.relative_to(path)): (item.read_bytes(), item.stat().st_mtime_ns)
            for item in path.rglob("*") if item.is_file()}


def test_separate_profile_preserves_original_baseline():
    from recon_cockpit.secure_agent.evaluation_contract import descriptor as baseline
    original = baseline()
    assert original["id"] == "owned-workflow-evaluation"
    assert original["grading"] == "saved-evidence-and-audit-replay-v1"
    assert descriptor()["cases"] == original["cases"]
    assert descriptor()["id"] != original["id"]
    assert descriptor()["services"]["human_acceptance"] is False
    assert evaluation_identity()["sha256"] != original.get("sha256")
    assert TRIAL_BUDGET == 55326
    assert totals(18)["simulation_microusd"] == 995868


def test_dry_run_creates_only_plan_and_reports(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("dry run constructed authority or ledger")

    monkeypatch.setattr(evaluation.PlanningEvaluationRunner, "_run_trial", forbidden)
    monkeypatch.setattr(CostLedger, "create", forbidden)
    path = tmp_path / "dry"
    report = evaluation.PlanningEvaluationRunner(path, policy()).run()
    assert report["status"] == "dry_run"
    assert report["started_trials"] == 0 and report["planned_trials"] == 18
    assert set(path.iterdir()) == {path / name for name in (
        "manifest.json", "evaluation.jsonl", "report.json", "report.md")}
    assert report["planning_cost"] is None
    assert report["actual_provider_calls"] == 0 and report["human_acceptance"] is False
    assert all(value == 0 for value in report["reservations"].values())
    before = files(path)
    assert evaluation.inspect_planning_evaluation(path) == report
    assert files(path) == before
    with pytest.raises(EvaluationUnavailable):
        inspect_evaluation(path)


def test_precancelled_run_creates_no_trial_and_preserves_batch_cap(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("cancelled batch started a trial")

    monkeypatch.setattr(evaluation.PlanningEvaluationRunner, "_run_trial", forbidden)
    path = tmp_path / "cancelled"
    runner = evaluation.PlanningEvaluationRunner(path, policy(), EvaluationLimits(repeats=1))
    runner.cancel()
    report = runner.run(execute=True)
    assert report["status"] == "incomplete" and report["stop_reason"] == "cancelled"
    assert report["started_trials"] == 0
    assert report["planning_cost"]["summary"]["limit_microusd"] == 6 * TRIAL_BUDGET
    assert report["planning_cost"]["summary"]["attempt_count"] == 0
    before = files(path)
    assert evaluation.inspect_planning_evaluation(path) == report
    assert files(path) == before


def test_durable_reservation_precedes_trial_and_failure_stops_batch(tmp_path, monkeypatch):
    path = tmp_path / "failure"
    calls = []

    def fail_trial(self, trial_path, case):
        events = [json.loads(line) for line in (path / "evaluation.jsonl").read_bytes().splitlines()]
        assert events[-1]["event_type"] == "evaluation_trial_started"
        assert events[-1]["reserved_totals"] == totals(1)
        assert self._ledger.report()["summary"]["limit_microusd"] == 18 * TRIAL_BUDGET
        calls.append(case)
        raise RuntimeError("private error must not leak")

    monkeypatch.setattr(evaluation.PlanningEvaluationRunner, "_run_trial", fail_trial)
    report = evaluation.PlanningEvaluationRunner(path, policy()).run(execute=True)
    assert calls == ["a"]
    assert report["status"] == "failed" and report["stop_reason"] == "component_failed"
    assert report["reservations"] == totals(1)
    assert report["correct_abstentions"] == report["passed_trials"] == 0
    assert report["not_run_trials"] == 17
    assert "private error" not in json.dumps(report)
    assert evaluation.inspect_planning_evaluation(path) == report


def test_single_use_and_existing_directory_are_refused(tmp_path):
    runner = evaluation.PlanningEvaluationRunner(tmp_path / "batch", policy())
    runner.run()
    with pytest.raises(RuntimeError, match="evaluation_already_used"):
        runner.run()
    with pytest.raises(EvaluationUnavailable):
        evaluation.PlanningEvaluationRunner(tmp_path / "batch", policy()).run()


@pytest.mark.parametrize("field,value", [
    ("mode", "provider"), ("limit_microusd", 10**9), ("period", "new-period"),
    ("account_scope_id", "another-account"), ("engagement_scope_id", "another-engagement"),
    ("ledger_id", "not-a-uuid"), ("directory", "elsewhere"),
])
def test_manifest_cannot_change_money_profile(tmp_path, field, value):
    path = tmp_path / "batch"
    evaluation.PlanningEvaluationRunner(path, policy()).run()
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["planning_ledger"][field] = value
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(EvaluationUnavailable):
        evaluation.inspect_planning_evaluation(path)


@pytest.mark.parametrize("fault", ["missing", "public", "symlink", "extra_scope", "changed_limit", "root_journal"])
def test_corrupt_or_changed_ledger_cannot_pass_inspection(tmp_path, fault):
    path = tmp_path / "batch"
    runner = evaluation.PlanningEvaluationRunner(path, policy())
    runner.cancel()
    runner.run(execute=True)
    db = path / "planning-ledger" / "ledger.sqlite3"
    if fault == "missing":
        db.unlink()
    elif fault == "public":
        db.chmod(0o644)
    elif fault == "symlink":
        moved = tmp_path / "moved.sqlite3"
        db.rename(moved)
        db.symlink_to(moved)
    elif fault == "root_journal":
        with sqlite3.connect(db) as connection:
            # Model damaged persisted bytes, beyond the API's immutable journal.
            connection.execute("DROP TRIGGER immutable_events_update")
            payload = json.loads(connection.execute("SELECT payload FROM events WHERE sequence=1").fetchone()[0])
            payload["limit_microusd"] += 1
            connection.execute("UPDATE events SET payload=? WHERE sequence=1", (json.dumps(payload),))
    else:
        with CostLedger(db.parent) as ledger:
            if fault == "extra_scope":
                ledger.add_scope("unplanned", parent_id=ledger.account_id, kind="engagement")
            else:
                ledger.set_limit(ledger.account_id, 10**9, event_id="changed-limit")
    before = files(path)
    report = evaluation.inspect_planning_evaluation(path)
    assert report["status"] == "failed"
    assert any(issue.startswith("planning_ledger_") for issue in report["integrity_issues"])
    assert report["correct_abstentions"] == 0
    assert files(path) == before


def test_approval_required_policy_cannot_be_rewritten(tmp_path):
    value = policy().to_dict()
    value["require_approval"] = True
    with pytest.raises(ValueError, match="unattended_owned_policy"):
        evaluation.PlanningEvaluationRunner(tmp_path / "batch", parse_policy(value))
    assert not (tmp_path / "batch").exists()


@pytest.mark.parametrize("target", ["manifest", "journal"])
@pytest.mark.parametrize("timestamp", [None, "", "2026-09-30T00:00:00", "2026-09-30T01:00:00+01:00"])
def test_invalid_batch_timestamps_fail_inspection(tmp_path, target, timestamp):
    path = tmp_path / "batch"
    evaluation.PlanningEvaluationRunner(path, policy()).run()
    if target == "manifest":
        location = path / "manifest.json"
        value = json.loads(location.read_bytes())
        value["created_at"] = timestamp
        location.write_text(json.dumps(value))
        with pytest.raises(EvaluationUnavailable):
            evaluation.inspect_planning_evaluation(path)
    else:
        location = path / "evaluation.jsonl"
        event = json.loads(location.read_bytes())
        event["timestamp"] = timestamp
        location.write_text(json.dumps(event) + "\n")
        report = evaluation.inspect_planning_evaluation(path)
        assert report["status"] == "incomplete"
        assert "evaluation_journal_invalid" in report["integrity_issues"]


@pytest.mark.parametrize("value", [0, 11, True, 1.5])
def test_repeat_limit_is_closed(value):
    with pytest.raises(ValueError):
        EvaluationLimits(repeats=value)
