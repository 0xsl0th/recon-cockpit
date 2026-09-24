"""Portable scheduler/grader tests. Namespace components are explicit doubles."""

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli, evaluation, evaluation_grading as grading
from recon_cockpit.secure_agent.evaluation import EvaluationLimits, EvaluationRunner, EvaluationUnavailable, inspect_evaluation
from recon_cockpit.secure_agent.evaluation_contract import FIXED_LIMITS, descriptor, oracle
from recon_cockpit.secure_agent.models import parse_policy


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-evaluation-policy.json"


def policy():
    return parse_policy(POLICY.read_bytes())


def snapshot(path):
    return {str(item.relative_to(path)): (item.read_bytes(), item.stat().st_mtime_ns)
            for item in path.rglob("*") if item.is_file()}


@pytest.fixture
def boundaries(monkeypatch):
    from recon_cockpit.secure_agent import owned_lab, coordinator_isolation, openai_provider
    from recon_cockpit.secure_agent.owned_lab_contract import BACKEND, identity
    from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
    from recon_cockpit.secure_agent.worker import _response

    labs = []

    class Lab:
        def __init__(self, case, session_id, limits, *, execute):
            self.identity = identity(case, str(uuid4()))
            self.session_id = session_id
            self._namespace_fds = ()
            self._supervisor = None
            self.connections = self.requests = 0
            self.closed = False
            labs.append(self)

        def close(self):
            self.closed = True
            return {"identity": self.identity, "status": "closed",
                    "connection_count": self.connections, "request_count": self.requests}

    class Backend:
        name = BACKEND

        def __init__(self, policy, session_id, limits, lab, *, execute):
            self.lab = lab

        @property
        def snapshot(self):
            return {"executions_reserved": self.lab.connections, "output_bytes_reserved": self.lab.connections * 1024}

        def check_available(self, action=None):
            pass

        def run(self, action, policy, *, control):
            control.check()
            assert not self.lab.closed
            self.lab.connections += 1
            if action.tool_id == "tcp_connect":
                raw = {"status": "succeeded", "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}],
                       "bytes_received": 0, "truncated": False}
            else:
                self.lab.requests += 1
                if self.lab.requests == 2 and self.lab.identity["scenario"] in "de":
                    raw = {"status": "timeout" if self.lab.identity["scenario"] == "d" else "output_limit",
                           "results": [], "bytes_received": 0, "truncated": False}
                else:
                    status, body, _ = _response(action.parameters.path)
                    count = len(body) + 64
                    raw = {"status": "succeeded", "bytes_received": count, "truncated": False,
                           "results": [{"target": "127.0.0.1", "port": 8080, "http_status": status,
                                        "body": body.decode(), "bytes_received": count, "truncated": False,
                                        "response_sha256": hashlib.sha256(body).hexdigest()}]}
            return {**raw, "backend": BACKEND, "boundary_checks": dict.fromkeys(grading._EXECUTOR, True),
                    "owned_lab": {"identity": self.lab.identity, "connection_count": self.lab.connections,
                                  "request_count": self.lab.requests}}

    class Parser:
        boundary_checks = dict.fromkeys(grading._ISOLATION, True)

        def plan(self, config, observation, exchange, *, control):
            return decode_response(exchange(build_request(config, observation), control=control))

    def coordinate(self, init, exchange, *, control):
        self._boundary_checks = dict.fromkeys(grading._ISOLATION, True)
        initial = json.loads(init)
        for step in range(1, 5):
            request = {**initial, "sequence": step, "operation": "plan"}
            for _ in range(2):
                control.check()
                response = json.loads(exchange(json.dumps(request).encode(), control=control))
                if response["stop"]:
                    return json.dumps({**initial, "status": "closed"}).encode()
                request.update(operation="propose", plan=response["plan"])
        pytest.fail("authority did not stop")

    monkeypatch.setattr(owned_lab, "OwnedLab", Lab)
    monkeypatch.setattr(owned_lab, "AuthorizedOwnedLabBackend", Backend)
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", Parser)
    monkeypatch.setattr(coordinator_isolation.LinuxOfflineCoordinator, "run", coordinate)
    return labs


@pytest.fixture
def batch(tmp_path, boundaries):
    directory = tmp_path / "batch"
    report = EvaluationRunner(directory, policy(), EvaluationLimits(repeats=1)).run(execute=True)
    assert report["status"] == "passed", report
    return SimpleNamespace(directory=directory, report=report, labs=boundaries)


def test_default_eighteen_trials_use_fresh_authority_and_saved_evidence(tmp_path, boundaries):
    directory = tmp_path / "baseline"
    report = EvaluationRunner(directory, policy()).run(execute=True)
    assert report["status"] == "passed" and report["passed_trials"] == report["planned_trials"] == 18
    assert report["correct_abstentions"] == 12
    assert report["aggregate_metrics"]["executions"] == 51
    assert report["aggregate_metrics"]["actions_succeeded"] == 45
    assert report["aggregate_metrics"]["output_bytes_reserved"] == 51 * 1024
    assert report["reservations"]["tool_output_bytes"] == 54 * 1024
    assert report["cleanup_verified_trials"] == report["isolation_verified_trials"] == 18
    assert all(row["semantic_agreement"] for row in report["per_case"])
    assert all(lab.closed for lab in boundaries) and len(boundaries) == 18
    for key in ("session_id", "assessment_id", "lab_instance_id", "broker_id"):
        assert len({row["grade"][key] for row in report["trials"]}) == 18
    before = snapshot(directory)
    assert inspect_evaluation(directory) == report
    assert snapshot(directory) == before


@pytest.mark.parametrize("case", list("abcdef"))
def test_case_specific_evidence_and_stop_reasons_are_graded(batch, case):
    row = next(row for row in batch.report["trials"] if row["case"] == case)
    grade = row["grade"]
    assert grade["outcome"] == grade["expected_outcome"] == oracle(case)["outcome"]
    assert grade["observed_terminal_reason"] == grade["expected_terminal_reason"]
    assert grade["classification"] == oracle(case)["classification"]
    assert all(grade["checks"].values())
    assert grade["metrics"]["executions"] == (2 if case == "f" else 3)


@pytest.mark.parametrize("fault", ["missing_runtime", "runtime_error", "cleanup_false", "cleanup_bool", "parser_false",
    "coordinator_missing", "backend_bytes", "broker_bytes", "broker_bool", "case", "identity", "elapsed",
    "audit_reservation", "audit_order", "audit_incomplete", "audit_session", "audit_duplicate",
    "artifact", "report", "closure", "public_runtime", "runtime_symlink", "runtime_hardlink", "extra_file"])
def test_tampering_cannot_receive_credit_for_an_inconclusive_case(batch, fault):
    trial = batch.directory / "trial-003-c"
    runtime_path = trial / "runtime.json"
    runtime = json.loads(runtime_path.read_bytes())
    audit_path = trial / "audit.jsonl"
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    if fault == "missing_runtime":
        runtime_path.unlink()
    elif fault == "runtime_error":
        runtime["error"] = "trial_component_failed"
    elif fault == "cleanup_false":
        runtime["cleanup"]["owner_reaped"] = False
    elif fault == "cleanup_bool":
        runtime["cleanup"]["namespace_fds_closed"] = 1
    elif fault == "parser_false":
        runtime["parser_boundary_checks"]["root_read_only"] = False
    elif fault == "coordinator_missing":
        runtime["coordinator_boundary_checks"] = {}
    elif fault == "backend_bytes":
        runtime["backend"]["output_bytes_reserved"] = 1
    elif fault == "broker_bytes":
        runtime["broker"]["request_bytes_reserved"] -= 1
    elif fault == "broker_bool":
        runtime["broker"]["calls_reserved"] = True
    elif fault == "case":
        runtime["case"] = "a"
    elif fault == "identity":
        runtime["lab_identity"]["instance_id"] = str(uuid4())
    elif fault == "elapsed":
        runtime["elapsed_ms"] = -1
    elif fault == "audit_reservation":
        next(row for row in events if row["event_type"] == "session_output_reserved")["output_reserved_bytes"] = 0
    elif fault == "audit_order":
        events[7], events[9] = events[9], events[7]
    elif fault == "audit_incomplete":
        events.pop()
    elif fault == "audit_session":
        events[0]["session_id"] = str(uuid4())
    elif fault == "audit_duplicate":
        events[1]["event_id"] = events[0]["event_id"]
    elif fault == "artifact":
        target = next((trial / "evidence").glob("result-*.json"))
        target.write_text("{}")
    elif fault == "report":
        (trial / "evidence" / "report.json").write_text('{"outcome":"inconclusive"}')
    elif fault == "closure":
        journal = trial / "evidence" / "evidence.jsonl"
        journal.write_text("\n".join(line for line in journal.read_text().splitlines()
                                    if json.loads(line)["event_type"] != "assessment_owned_lab_closed") + "\n")
    elif fault == "public_runtime":
        runtime_path.chmod(0o644)
    elif fault == "runtime_symlink":
        target = trial / "moved.json"
        runtime_path.rename(target)
        runtime_path.symlink_to(target)
    elif fault == "runtime_hardlink":
        os.link(runtime_path, trial / "linked.json")
    elif fault == "extra_file":
        (trial / "surprise").write_text("unexpected")
    if fault not in {"missing_runtime", "runtime_symlink"}:
        runtime_path.write_text(json.dumps(runtime))
    audit_path.write_text("\n".join(json.dumps(row) for row in events) + "\n")
    before = snapshot(batch.directory)
    grade = grading.grade_trial(trial, case="c", policy_digest=policy().digest, limits=FIXED_LIMITS)
    assert grade["verdict"] == "failed" and grade["classification"] == "failed"
    assert grade["metrics"]["broker_calls_reserved"] is None
    aggregate = inspect_evaluation(batch.directory)
    assert aggregate["status"] == "failed" and not aggregate["resource_accounting_complete"]
    assert aggregate["aggregate_metrics"]["broker_calls_reserved"] is None
    assert snapshot(batch.directory) == before


def test_cached_aggregate_and_trial_grades_do_not_override_replay(batch):
    path = batch.directory / "report.json"
    saved = json.loads(path.read_bytes())
    saved["trials"][0]["grade"]["outcome"] = "not_demonstrated"
    path.write_text(json.dumps(saved))
    actual = inspect_evaluation(batch.directory)
    assert actual["trials"][0]["grade"]["outcome"] == "validated"
    assert actual["status"] == "failed" and "aggregate_report_mismatch" in actual["integrity_issues"]


def test_incomplete_or_contradictory_audit_context_cannot_receive_abstention_credit(batch):
    # Reuse one valid six-case batch. Each mutation starts from the original
    # bytes, so corruption checks do not multiply namespace-double executions.
    trial = batch.directory / "trial-003-c"
    audit_path = trial / "audit.jsonl"
    original = audit_path.read_bytes()
    events = [json.loads(line) for line in original.splitlines()]
    first_by_kind = {}
    for index, event in enumerate(events):
        first_by_kind.setdefault(event["event_type"], index)
    mutations = []
    for kind, index in first_by_kind.items():
        event = events[index]
        for field in ("session_id", "policy_digest", "limits_digest", "control_plane", "broker_id", "config_digest"):
            if field in event:
                mutations.append((kind + " missing " + field, index, field, "delete", None))
        for field in ("step", "session_step"):
            if field in event:
                assert event[field] == 1
                mutations.append((kind + " boolean " + field, index, field, "replace", True))
        for field, value in (("action_id", str(uuid4())), ("tool_id", "unexpected_tool"), ("target", "203.0.113.99")):
            if field in event:
                mutations.append((kind + " changed " + field, index, field, "replace", value))
        mutations.append((kind + " extra field", index, "unrecognized_context", "replace", {"approval": True}))
    # The schema must cover the actual submission as well as its preview.
    actual_policy = [index for index, event in enumerate(events) if event["event_type"] == "policy_decision"][1]
    mutations.extend([
        ("actual policy missing session", actual_policy, "session_id", "delete", None),
        ("actual policy boolean step", actual_policy, "session_step", "replace", True),
        ("actual policy changed action", actual_policy, "action_id", "replace", str(uuid4())),
        ("missing timestamp", 0, "timestamp", "delete", None),
        ("null timestamp", 0, "timestamp", "replace", None),
        ("boolean timestamp", 0, "timestamp", "replace", True),
        ("malformed timestamp", 0, "timestamp", "replace", "not-a-timestamp"),
        ("timezone-free timestamp", 0, "timestamp", "replace", "2026-09-24T12:00:00"),
    ])
    policy_digest = policy().digest
    try:
        for label, index, field, operation, replacement in mutations:
            changed = copy.deepcopy(events)
            if operation == "delete":
                del changed[index][field]
            else:
                changed[index][field] = replacement
            audit_path.write_text("\n".join(json.dumps(event) for event in changed) + "\n")
            before = snapshot(batch.directory)
            grade = grading.grade_trial(trial, case="c", policy_digest=policy_digest, limits=FIXED_LIMITS)
            assert grade["verdict"] == "failed" and grade["classification"] == "failed", label
            assert grade["issues"] == ["audit_accounting_failed"], label
            assert grade["checks"]["resource_accounting"] is False, label
            assert all(value is None for value in grade["metrics"].values()), label
            aggregate = inspect_evaluation(batch.directory)
            assert aggregate["status"] == "failed" and not aggregate["resource_accounting_complete"], label
            assert aggregate["correct_abstentions"] == 3, label
            assert "saved_trial_grade_mismatch" in aggregate["integrity_issues"], label
            assert all(value is None for value in aggregate["aggregate_metrics"].values()), label
            assert snapshot(batch.directory) == before, label
    finally:
        audit_path.write_bytes(original)
    assert inspect_evaluation(batch.directory) == batch.report


def test_interrupted_journal_retains_reservation_and_never_resumes(batch):
    journal = batch.directory / "evaluation.jsonl"
    lines = journal.read_text().splitlines()
    journal.write_text(lines[0] + '\n{"torn":')
    before = snapshot(batch.directory)
    result = inspect_evaluation(batch.directory)
    assert result["status"] == "incomplete" and result["started_trials"] == 1
    assert result["completed_trials"] == 0 and result["reservations"]["tool_output_bytes"] == 3072
    assert not result["resource_accounting_complete"] and result["not_run_trials"] == 5
    assert "evaluation_journal_torn" in result["integrity_issues"]
    assert snapshot(batch.directory) == before


def test_cancellation_between_trials_retains_reservations_and_stops_schedule(tmp_path, boundaries):
    runner = EvaluationRunner(tmp_path / "batch", policy())
    result = runner.run(execute=True, on_trial=lambda _: runner.cancel())
    assert result["status"] == "incomplete" and result["stop_reason"] == "cancelled"
    assert result["passed_trials"] == result["started_trials"] == len(boundaries) == 1
    assert result["not_run_trials"] == 17 and result["reservations"]["trials"] == 1
    assert boundaries[0].closed and inspect_evaluation(runner.directory) == result


@pytest.mark.parametrize("mode", ["dry_run", "pre_cancel", "expired"])
def test_no_runtime_for_unadmitted_trials(tmp_path, monkeypatch, mode):
    runner = EvaluationRunner(tmp_path / "batch", policy())
    monkeypatch.setattr(runner, "_run_trial", lambda *_: pytest.fail("must not start authority"))
    if mode == "pre_cancel":
        runner.cancel()
    if mode == "expired":
        original = evaluation._Directory.write

        def expire(directory, *args):
            original(directory, *args)
            runner._deadline = 0
        monkeypatch.setattr(evaluation._Directory, "write", expire)
    result = runner.run(execute=mode != "dry_run")
    assert result["started_trials"] == 0 and result["reservations"]["trials"] == 0
    assert result["status"] == ("dry_run" if mode == "dry_run" else "incomplete")
    with pytest.raises(RuntimeError, match="already_used"):
        runner.run(execute=True)


def test_durable_start_failure_prevents_runtime(tmp_path, monkeypatch):
    runner = EvaluationRunner(tmp_path / "batch", policy())
    original = evaluation.AuditSink.emit

    def fail(audit, event):
        if event["event_type"] == "evaluation_trial_started":
            raise EvaluationUnavailable("injected durability failure")
        original(audit, event)
    monkeypatch.setattr(evaluation.AuditSink, "emit", fail)
    monkeypatch.setattr(runner, "_run_trial", lambda *_: pytest.fail("must not execute"))
    with pytest.raises(EvaluationUnavailable):
        runner.run(execute=True)
    assert inspect_evaluation(runner.directory)["status"] == "incomplete"


@pytest.mark.parametrize("field,value", [("repeats", 0), ("repeats", 11), ("repeats", True),
                                         ("max_runtime_seconds", 0), ("max_runtime_seconds", 3601), ("max_runtime_seconds", 1.5)])
def test_evaluation_limits_are_strict(field, value):
    with pytest.raises(ValueError):
        EvaluationLimits(**{field: value})


def test_approval_required_policy_is_not_rewritten(tmp_path):
    value = policy().to_dict()
    value["require_approval"] = True
    with pytest.raises(ValueError, match="explicit_unattended"):
        EvaluationRunner(tmp_path / "batch", parse_policy(value))
    assert not (tmp_path / "batch").exists() and value["require_approval"] is True


@pytest.mark.parametrize("options", [["--evaluation-repeats", "3"], ["--evaluate-owned-lab"],
    ["--evaluate-owned-lab", "--evaluation-dir", "unused", "--fixture"],
    ["--evaluate-owned-lab", "--evaluation-dir", "unused", "--session-max-steps", "3"],
    ["--inspect-evaluation", "unused", "--execute"], ["--inspect-evaluation", "unused", "--owned-lab"]])
def test_invalid_cli_combinations_fail_before_policy_read(monkeypatch, options):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("must not read policy"))
    with pytest.raises(SystemExit) as caught:
        cli.main(options)
    assert caught.value.code == 2


def test_cli_execution_and_inspection_restore_handlers(tmp_path, boundaries, capsys, monkeypatch):
    output = tmp_path / "batch"
    before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    assert cli.main(["--evaluate-owned-lab", "--evaluation-dir", str(output), "--evaluation-repeats", "1",
                     "--policy", str(POLICY), "--execute"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert all(signal.getsignal(number) == handler for number, handler in before.items())
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("inspection must not read policy"))
    monkeypatch.setattr(EvaluationRunner, "run", lambda *_: pytest.fail("inspection must not execute"))
    assert cli.main(["--inspect-evaluation", str(output)]) == 0
    assert json.loads(capsys.readouterr().out) == report


def test_oracle_is_separate_and_returns_copies(monkeypatch):
    from recon_cockpit.secure_agent import workflow
    monkeypatch.setattr(workflow, "decide", lambda *_: pytest.fail("oracle must not invoke workflow"))
    changed = oracle("a")
    changed["statuses"].clear()
    assert len(oracle("a")["statuses"]) == 3
    assert descriptor()["baseline_trials"] == 18


@pytest.mark.parametrize("fault", ["path", "repeat_bool", "policy", "oracle", "live", "reservation"])
def test_manifest_tampering_cannot_select_work_or_change_accounting(batch, fault):
    path = batch.directory / "manifest.json"
    value = json.loads(path.read_bytes())
    if fault == "path":
        value["plan"][0]["trial_id"] = "../../elsewhere"
    elif fault == "repeat_bool":
        value["limits"]["repeats"] = True
    elif fault == "policy":
        value["policy_digest"] = "0" * 64
    elif fault == "oracle":
        value["evaluation"]["sha256"] = "0" * 64
    elif fault == "live":
        value["live_calls_enabled"] = True
    else:
        value["batch_allowances"]["tool_output_bytes"] = 0
    path.write_text(json.dumps(value))
    before = snapshot(batch.directory)
    with pytest.raises(EvaluationUnavailable):
        inspect_evaluation(batch.directory)
    assert snapshot(batch.directory) == before


@pytest.mark.parametrize("kind", ["existing", "symlink"])
def test_runner_refuses_to_overwrite_or_resume_existing_output(tmp_path, kind):
    target = tmp_path / "existing"
    target.mkdir(mode=0o700)
    (target / "keep").write_text("existing work")
    output = target
    if kind == "symlink":
        output = tmp_path / "link"
        output.symlink_to(target, target_is_directory=True)
    with pytest.raises(EvaluationUnavailable):
        EvaluationRunner(output, policy()).run()
    assert (target / "keep").read_text() == "existing work"
    assert set(target.iterdir()) == {target / "keep"}


def test_duplicate_session_identity_is_rejected_even_when_cached_grades_agree(batch):
    manifest = json.loads((batch.directory / "manifest.json").read_bytes())
    trials = copy.deepcopy(batch.report["trials"])
    trials[1]["grade"]["session_id"] = trials[0]["grade"]["session_id"]
    report = evaluation._aggregate(manifest, trials, manifest["plan"], dict.fromkeys(row["trial_id"] for row in trials),
                                   {"stop_reason": "completed", "elapsed_ms": 1}, [])
    assert report["status"] == "failed" and "reused_session_id" in report["integrity_issues"]


def test_runtime_failure_stops_future_trials_and_keeps_full_allowance(tmp_path, monkeypatch):
    runner = EvaluationRunner(tmp_path / "batch", policy())
    launches = []

    def fail(path, case):
        launches.append(case)
        raise OSError("private injected failure")
    monkeypatch.setattr(runner, "_run_trial", fail)
    report = runner.run(execute=True)
    assert launches == ["a"] and report["status"] == "failed"
    assert report["started_trials"] == 1 and report["not_run_trials"] == 17
    assert report["reservations"]["tool_output_bytes"] == 3072
    assert report["aggregate_metrics"]["output_bytes_reserved"] is None
    assert "private injected failure" not in json.dumps(report)
