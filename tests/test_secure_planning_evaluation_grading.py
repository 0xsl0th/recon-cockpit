"""Saved planning grades use real evidence, audit and simulation accounting.

Namespace/process observations are explicit portable doubles. Linux tests own
the corresponding boundary and cleanup evidence; these tests exercise replay.
"""

from copy import deepcopy
import json
import os
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import assessment_planning, openai_provider, owned_lab
from recon_cockpit.secure_agent import planning_evaluation_grading as grading
from recon_cockpit.secure_agent import planning_evaluation_runtime as runtime
from recon_cockpit.secure_agent.assessment_planning_tls_contract import response_body
from recon_cockpit.secure_agent.assessment_planning_transport import LinuxOwnedPlanningTransport
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.audit_protocol import CHECKS as AUDIT_CHECKS
from recon_cockpit.secure_agent.cost_contract import TokenUsage
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.evaluation_contract import FIXED_LIMITS, oracle
from recon_cockpit.secure_agent.launcher_protocol import CHECKS as LAUNCHER_CHECKS
from recon_cockpit.secure_agent.planning_evaluation_contract import TRIAL_BUDGET, scope_ids
from recon_cockpit.secure_agent.provider_contract import BOUNDARY_NAMES as TLS_CHECKS
from test_secure_evaluation import boundaries, policy, snapshot


@pytest.fixture
def planning_boundaries(boundaries, monkeypatch):
    """Keep actual provider/evidence/cost behavior while replacing OS isolation."""
    class Audit:
        def __init__(self, path, *, launch_witness):
            assert launch_witness is True
            self.sink = AuditSink(path)
            self._supervisor = None
            self.boundary_checks = dict.fromkeys(AUDIT_CHECKS, True)

        def __enter__(self):
            self.sink.__enter__()
            return self

        def __exit__(self, *args):
            self.sink.__exit__(*args)

        def emit(self, event):
            return self.sink.emit(event)

    class Approval:
        def __init__(self, policy, session_id, *, launch_witness):
            assert policy.require_approval is False and launch_witness is True
            self._supervisor = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    class Launcher:
        def __init__(self, backend, *, audit, approvals):
            self.backend, self.name = backend, backend.name
            self._witness_source = self._approval_source = {"portable_test": True}
            self._supervisor = None
            self._closed = self._cleanup_verified = False
            self.boundary_checks = dict.fromkeys(LAUNCHER_CHECKS, True)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

        @property
        def snapshot(self):
            return self.backend.snapshot

        def check_available(self, action=None):
            return self.backend.check_available(action)

        def run(self, action, policy, *, control):
            return self.backend.run(action, policy, control=control)

        def close(self):
            self._closed = self._cleanup_verified = True
            return self.backend.lab.close()

    def exchange(transport, request, *, control, context_digest):
        control.check()
        receipt = {"schema_version": "1", "context_digest": context_digest, "status": "ok",
            "http_status": 200, "boundary_checks": dict.fromkeys(TLS_CHECKS, True),
            "cleanup": {"worker_reaped": True, "owner_reaped": True}, "connection_count": 1, "request_count": 1}
        transport._portable_receipt = receipt
        return {"body": response_body(request, {"case": transport.case, "scenario": transport.scenario,
                                                "run_id": transport.run_id}), "receipt": receipt}

    monkeypatch.setattr(runtime, "OwnedLab", owned_lab.OwnedLab)
    monkeypatch.setattr(runtime, "AuthorizedOwnedLabBackend", owned_lab.AuthorizedOwnedLabBackend)
    monkeypatch.setattr(runtime, "LinuxAuditSink", Audit)
    monkeypatch.setattr(runtime, "LinuxApprovalService", Approval)
    monkeypatch.setattr(runtime, "LinuxFixtureLauncher", Launcher)
    monkeypatch.setattr(assessment_planning, "LinuxOpenAIPlanner", openai_provider.LinuxOpenAIPlanner)
    monkeypatch.setattr(LinuxOwnedPlanningTransport, "exchange", exchange)
    monkeypatch.setattr(LinuxOwnedPlanningTransport, "last_receipt",
                        property(lambda self: getattr(self, "_portable_receipt", None)))
    return boundaries


@pytest.fixture
def trial(tmp_path, planning_boundaries, request):
    evaluation_id = str(uuid4())
    scopes = scope_ids(evaluation_id)
    runner = SimpleNamespace(policy=policy(), _deadline=time.monotonic() + 60,
                             _lock=threading.RLock(), _active=None, _stopped=lambda: None)
    runner._install = lambda authority: setattr(runner, "_active", authority)
    with CostLedger.create(tmp_path / "cost", account_id=scopes["account_scope_id"],
                           mode="simulation", limit_microusd=6 * TRIAL_BUDGET) as ledger:
        ledger.add_scope(scopes["engagement_scope_id"], parent_id=scopes["account_scope_id"],
                         kind="engagement", limit_microusd=6 * TRIAL_BUDGET)
        case = getattr(request, "param", "c")
        path = tmp_path / "trial"
        runtime.run_trial(runner, path, case, ledger=ledger, **scopes)
        args = dict(case=case, policy_digest=runner.policy.digest, limits=FIXED_LIMITS,
                    ledger=ledger, evaluation_id=evaluation_id, **scopes)
        grade = grading.grade_trial(path, **args)
        assert grade["verdict"] == "passed", (grade, json.loads((path / "runtime.json").read_bytes()))
        yield SimpleNamespace(path=path, root=tmp_path, ledger=ledger, runner=runner, scopes=scopes,
                              grade=grade, args=args, case=case)


def rewrite(path, value):
    path.write_text(json.dumps(value))


def rewrite_audit(path, events):
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n")


def failed(trial, *, stage=None):
    before = snapshot(trial.root)
    grade = grading.grade_trial(trial.path, **trial.args)
    assert grade["verdict"] == grade["classification"] == "failed"
    assert all(value is None for value in grade["metrics"].values())
    assert grade["cost"] is grade["semantic_fingerprint"] is None
    if stage is not None:
        assert grade["issues"] == [stage]
    assert snapshot(trial.root) == before
    return grade


@pytest.mark.parametrize("trial", list("abcdef"), indirect=True)
def test_all_six_outcomes_replay_with_settled_owned_tls_costs(trial):
    grade = trial.grade
    count = 2 if trial.case == "f" else 3
    assert grade["outcome"] == oracle(trial.case)["outcome"]
    assert grade["classification"] == oracle(trial.case)["classification"]
    assert all(grade["checks"].values())
    assert grade["metrics"]["owned_tls_exchanges"] == grade["metrics"]["executions"] == count
    assert grade["metrics"]["planning_actual_microusd"] == 778 * count
    assert grade["metrics"]["planning_input_tokens"] == 512 * count
    assert grade["metrics"]["planning_output_tokens"] == 128 * count
    assert grade["metrics"]["planning_cached_input_tokens"] == grade["metrics"]["actual_provider_calls"] == 0
    assert grade["metrics"]["planning_reserved_microusd"] == grade["metrics"]["planning_unresolved_attempts"] == 0
    assert len(grade["cost"]["attempts"]) == count
    assert all(row["state"] == "settled" for row in grade["cost"]["attempts"])
    before = snapshot(trial.root)
    assert grading.grade_trial(trial.path, **trial.args) == grade
    assert snapshot(trial.root) == before


def test_later_trial_spend_does_not_change_prior_grade(trial):
    before = trial.grade
    runtime.run_trial(trial.runner, trial.root / "sibling", "b", ledger=trial.ledger, **trial.scopes)
    assert trial.ledger.report()["summary"]["actual_microusd"] == 6 * 778
    assert grading.grade_trial(trial.path, **trial.args) == before
    assert "effective_available_microusd" not in before["cost"]["summary"]
    assert "limiting_scope_id" not in before["cost"]["summary"]
    assert "last_event_sequence" not in before["cost"]


def test_baseline_grader_does_not_accept_new_planning_profile(trial):
    from recon_cockpit.secure_agent.evaluation_grading import grade_trial

    result = grade_trial(trial.path, case=trial.case, policy_digest=policy().digest, limits=FIXED_LIMITS)
    assert result["verdict"] == "failed"


def test_every_runtime_object_uses_a_closed_required_schema(trial):
    path = trial.path / "runtime.json"
    original = json.loads(path.read_bytes())
    for location in ((), ("planning",), ("services",), ("cleanup",)):
        current = original
        for key in location:
            current = current[key]
        for field in (*current, "unrecognized"):
            changed = deepcopy(original)
            target = changed
            for key in location:
                target = target[key]
            if field == "unrecognized":
                target[field] = "PRIVATE"
            else:
                del target[field]
            rewrite(path, changed)
            result = failed(trial)
            assert "PRIVATE" not in json.dumps(result)
    rewrite(path, original)
    assert grading.grade_trial(trial.path, **trial.args) == trial.grade


@pytest.mark.parametrize("location,value", [
    (("error",), "component_failed"), (("profile",), "owned-workflow-evaluation"),
    (("case",), "a"), (("session_id",), str(uuid4())), (("broker_id",), str(uuid4())),
    (("elapsed_ms",), True), (("elapsed_ms",), -1),
    (("cleanup", "audit_reaped"), False), (("cleanup", "launcher_reaped"), 1),
    (("cleanup", "approval_unstarted"), False), (("cleanup", "launcher_closed"), False),
    (("services", "audit_gate"), False), (("services", "approval_gate"), True + 0),
    (("services", "approval_worker_started"), True), (("services", "approval_mode"), "interactive"),
    (("services", "audit_boundary_checks"), {}), (("services", "launcher_boundary_checks"), {}),
    (("planning", "actual_provider_calls"), True), (("planning", "actual_provider_calls"), 1),
    (("planning", "mode"), "provider"), (("planning", "provider"), "live-provider"),
    (("planning", "broker_config_digest"), "0" * 64), (("planning", "control_deadline"), 1),
    (("planning", "transport_receipts"), []), (("planning", "ledger_id"), str(uuid4())),
    (("planning", "action_scope_id"), "another-action"),
    (("planning", "cost", "summary", "actual_microusd"), 0),
    (("planning", "cost", "summary", "actual_complete"), 1),
    (("planning", "cost", "by_model"), []), (("planning", "cost", "attempts"), []),
    (("backend", "executions_reserved"), True), (("broker", "calls_reserved"), True),
    (("coordinator_boundary_checks",), {}), (("parser_boundary_checks",), {}),
])
def test_runtime_claims_cannot_override_evidence_audit_or_ledger(trial, location, value):
    path = trial.path / "runtime.json"
    changed = json.loads(path.read_bytes())
    target = changed
    for key in location[:-1]:
        target = target[key]
    target[location[-1]] = value
    rewrite(path, changed)
    failed(trial)


def test_missing_extra_or_contradictory_audit_context_is_rejected(trial):
    path = trial.path / "audit.jsonl"
    original = [json.loads(line) for line in path.read_text().splitlines()]
    first = {}
    for index, event in enumerate(original):
        first.setdefault(event["event_type"], index)
    for index in first.values():
        for field in (*original[index], "unrecognized"):
            changed = deepcopy(original)
            if field == "unrecognized":
                changed[index][field] = "PRIVATE"
            else:
                del changed[index][field]
            rewrite_audit(path, changed)
            result = failed(trial, stage="audit_accounting_failed")
            assert "PRIVATE" not in json.dumps(result)
    rewrite_audit(path, original)
    assert grading.grade_trial(trial.path, **trial.args) == trial.grade


@pytest.mark.parametrize("fault", ["order", "duplicate", "missing_settlement", "early_proposal", "retry", "grant",
    "settled_charge", "settled_bool", "request_digest", "workflow_digest", "context_digest", "tls_status",
    "tls_cleanup", "tls_boundary", "tls_requests", "tls_connections", "tls_extra", "step_bool", "timestamp",
    "deadline_per_call", "approval_reference", "execution_id", "action_target", "audit_incomplete"])
def test_planning_audit_requires_one_settled_exchange_before_each_launch(trial, fault):
    path = trial.path / "audit.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    find = lambda kind: next(event for event in events if event["event_type"] == kind)
    if fault in {"order", "early_proposal"}:
        a, b = (4, 5) if fault == "order" else (7, 8)
        events[a], events[b] = events[b], events[a]
    elif fault in {"duplicate", "retry", "grant"}:
        event = deepcopy(find("assessment_planning_tls_reserved"))
        if fault == "grant":
            event["event_type"] = "approval_consumed"
        events.insert(5, event)
    elif fault == "missing_settlement":
        events.remove(find("assessment_planning_settled"))
    elif fault == "settled_charge":
        find("assessment_planning_settled")["actual_microusd"] = 0
    elif fault == "settled_bool":
        find("assessment_planning_settled")["within_token_limits"] = 1
    elif fault in {"request_digest", "workflow_digest", "context_digest"}:
        kind = {"request_digest": "assessment_planning_reserved", "workflow_digest": "assessment_planning_proposal_released",
                "context_digest": "assessment_planning_tls_reserved"}[fault]
        find(kind)[fault] = "0" * 64
    elif fault.startswith("tls_"):
        receipt = find("assessment_planning_tls_finished")["receipt"]
        if fault == "tls_status":
            receipt["status"] = "transport_error"
        elif fault == "tls_cleanup":
            receipt["cleanup"]["owner_reaped"] = False
        elif fault == "tls_boundary":
            receipt["boundary_checks"]["forbidden_ip_blocked"] = False
        elif fault == "tls_requests":
            receipt["request_count"] = 0
        elif fault == "tls_connections":
            receipt["connection_count"] = 2
        else:
            receipt["unrecognized"] = "PRIVATE"
    elif fault == "step_bool":
        find("assessment_planning_settled")["step"] = True
    elif fault == "timestamp":
        events[0]["timestamp"] = "2026-09-30T00:00:00"
    elif fault == "deadline_per_call":
        find("assessment_planning_tls_finished")["context_digest"] = "0" * 64
    elif fault == "approval_reference":
        find("execution_started")["approval_reference"] = "invented-grant"
    elif fault == "execution_id":
        find("execution_started")["execution_id"] = str(uuid4())
    elif fault == "action_target":
        find("execution_started")["target"] = "203.0.113.99"
    rewrite_audit(path, events)
    if fault == "audit_incomplete":
        path.write_bytes(path.read_bytes()[:-1])
    failed(trial, stage="audit_accounting_failed")


@pytest.mark.parametrize("fault", ["attempt_state", "attempt_request", "attempt_usage", "attempt_charge", "attempt_reference",
    "attempt_scope", "scope_parent", "scope_cap", "extra_attempt", "unavailable", "missing"])
def test_durable_ledger_must_match_exact_trial_scope_and_usage(trial, fault):
    first = trial.ledger.attempts()[0]
    db = trial.ledger._db
    if fault == "attempt_state":
        db.execute("UPDATE attempts SET state='uncertain' WHERE attempt_id=?", (first["attempt_id"],))
    elif fault == "attempt_request":
        db.execute("UPDATE attempts SET request_digest=? WHERE attempt_id=?", ("0" * 64, first["attempt_id"]))
    elif fault == "attempt_usage":
        db.execute("UPDATE attempts SET usage=? WHERE attempt_id=?",
                   (json.dumps({"input_tokens": 512, "output_tokens": 1, "cached_input_tokens": 0}), first["attempt_id"]))
    elif fault == "attempt_charge":
        db.execute("UPDATE attempts SET actual_microusd=0 WHERE attempt_id=?", (first["attempt_id"],))
    elif fault == "attempt_reference":
        db.execute("UPDATE attempts SET receipt_reference='another-receipt' WHERE attempt_id=?", (first["attempt_id"],))
    elif fault == "attempt_scope":
        db.execute("UPDATE attempts SET scope_id=? WHERE attempt_id=?",
                   (trial.grade["agent_scope_id"], first["attempt_id"]))
    elif fault == "scope_parent":
        db.execute("UPDATE scopes SET parent_id=? WHERE scope_id=?",
                   (trial.scopes["engagement_scope_id"], trial.grade["action_scope_id"]))
    elif fault == "scope_cap":
        db.execute("UPDATE scopes SET limit_microusd=0 WHERE scope_id=?", (trial.grade["action_scope_id"],))
    elif fault == "extra_attempt":
        trial.ledger.estimate("unreviewed-attempt", scope_id=trial.grade["action_scope_id"], request_digest="0" * 64,
            price=assessment_planning.contract.PRICE, usage=TokenUsage(1, 1), input_token_limit=1, output_token_limit=1)
    elif fault == "unavailable":
        trial.ledger.close()
    else:
        trial.args["ledger"] = None
    failed(trial, stage="planning_accounting_failed")


def test_tampered_ledger_events_cannot_be_hidden_by_matching_final_totals(trial):
    db = trial.ledger._db
    db.execute("DROP TRIGGER immutable_events_update")
    row = db.execute("SELECT sequence,payload FROM events WHERE kind='dispatch_started' LIMIT 1").fetchone()
    db.execute("UPDATE events SET payload=? WHERE sequence=?", (json.dumps({"request_digest": "0" * 64}), row[0]))
    failed(trial, stage="planning_accounting_failed")


def test_failed_trace_retains_bound_scope_ids_without_claiming_cost_credit(trial):
    path = trial.path / "evidence" / "report.json"
    report = json.loads(path.read_bytes())
    report["outcome"] = "validated"
    rewrite(path, report)
    result = failed(trial)
    for key in ("session_id", "ledger_id", "session_scope_id", "agent_scope_id", "action_scope_id"):
        assert result[key] == trial.grade[key]


@pytest.mark.parametrize("missing", ["audit.jsonl", "evidence"])
def test_partial_trial_preserves_verified_cost_binding_without_passing(trial, missing):
    (trial.path / missing).rename(trial.root / ("saved-" + missing))
    result = failed(trial, stage="trial_evidence_unavailable")
    for key in ("session_id", "ledger_id", "session_scope_id", "agent_scope_id", "action_scope_id"):
        assert result[key] == trial.grade[key]


@pytest.mark.parametrize("fault", ["runtime_public", "runtime_symlink", "runtime_hardlink", "extra_file", "artifact", "report"])
def test_private_saved_files_and_artifact_replay_are_required(trial, fault):
    path = trial.path / "runtime.json"
    if fault == "runtime_public":
        path.chmod(0o644)
    elif fault == "runtime_symlink":
        target = trial.root / "runtime-copy"
        path.rename(target)
        path.symlink_to(target)
    elif fault == "runtime_hardlink":
        os.link(path, trial.root / "runtime-link")
    elif fault == "extra_file":
        (trial.path / "unreviewed").write_text("PRIVATE")
    elif fault == "artifact":
        next((trial.path / "evidence").glob("result-*.json")).write_text("{}")
    else:
        (trial.path / "evidence" / "report.json").write_text("{}")
    result = failed(trial)
    assert "PRIVATE" not in json.dumps(result)
