"""Portable replay/tamper tests with real authority, audit and evidence stores.

Tool execution, process boundaries and timings are explicit unit doubles. Linux
runtime tests establish the corresponding actual isolation and cleanup evidence.
"""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_evidence, web_assessment_contract as web
from recon_cockpit.secure_agent import web_comparison_contract as comparison
from recon_cockpit.secure_agent import web_comparison_grading as grading
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.audit_protocol import CHECKS as AUDIT_CHECKS
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_ipc import BOUNDARY_NAMES
from recon_cockpit.secure_agent.launcher_protocol import CHECKS as LAUNCHER_CHECKS
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.nmap_parser import parse_nmap_xml
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.web_comparison_provider import ComparisonProvider
from recon_cockpit.secure_agent.web_lab_contract import identity
from test_secure_nmap_evidence import RUNTIME_DIGEST, policy, result as nmap_result
from test_secure_offline_authority import Coordinator
from test_secure_web_assessment_contract import result as http_result


@pytest.fixture(autouse=True)
def portable_parser(monkeypatch):
    monkeypatch.setattr(nmap_evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, *, deadline=None: parse_nmap_xml(raw)["results"])


def write(path, value):
    path.write_bytes(web.encode(value))
    path.chmod(0o600)


def write_audit(path, events):
    path.write_bytes(b"\n".join(web.encode(event) for event in events) + b"\n")


def snapshot(path):
    return {str(item.relative_to(path)): (item.read_bytes(), item.stat().st_mtime_ns)
            for item in path.rglob("*") if item.is_file()}


def make_trial(path, case="injected", arm="scripted", *, note_override=None):
    path.mkdir(mode=0o700)
    session, lab = str(uuid4()), identity(case, str(uuid4()))
    selected_policy = policy()

    class Backend:
        name = web.BACKEND

        def __init__(self):
            self.count = self.output = 0

        def check_available(self, action=None):
            if action is not None:
                assert web.profile_allows(action, case)

        def run(self, action, supplied_policy, *, control):
            control.check()
            self.count += 1
            assert supplied_policy.digest == selected_policy.digest
            assert action.to_dict() == web.action(case, self.count)
            self.output += action.parameters.max_output_bytes
            stub = SimpleNamespace(_manifest={"owned_lab": lab, "fixture_case": case})
            result = nmap_result(stub, 1) if self.count == 1 else http_result(case, self.count)
            if self.count == 2 and note_override is not None:
                document = json.loads(result["results"][0]["body"])
                document["operator_note"] = note_override
                body = web.encode(document).decode("ascii")
                result["results"][0].update(body=body, bytes_received=len(body) + 64)
                result["bytes_received"] = len(body) + 64
            result.update(backend=web.BACKEND, owned_lab={"identity": lab,
                "connection_count": self.count - 1, "request_count": self.count - 1})
            if self.count > 1:
                result["boundary_checks"] = dict.fromkeys(grading._HTTP_CHECKS, True)
            return result

    backend = Backend()
    with AuditSink(path / "audit.jsonl") as audit, nmap_evidence.NmapEvidenceStore(
            path / "evidence", session_id=session, policy=selected_policy, case=case,
            owned_lab=lab, runtime_sha256=RUNTIME_DIGEST, workflow_profile="web") as evidence:
        provider = ComparisonProvider(case, evidence, arm, audit)
        authority = AuthoritySession(selected_policy, audit, backend, Coordinator(), SessionLimits(**web.LIMITS),
            session_id=session, provider=provider, evidence=evidence)
        summary = authority.run(execute=True)
        closure = {"identity": lab, "status": "closed", "connection_count": backend.count - 1,
                   "request_count": backend.count - 1}
        evidence.record_lab_closed(closure)
        evidence.finalize(summary)
        trace = provider.trace
    runtime = {"schema_version": "1", "profile": comparison.PROFILE, "case": case, "arm": arm,
        "session_id": session, "lab_identity": lab,
        "backend": {"executions_reserved": backend.count, "output_bytes_reserved": backend.output},
        "lab_closure": closure, "coordinator_boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True),
        "services": {"audit_boundary_checks": dict.fromkeys(AUDIT_CHECKS, True),
            "launcher_boundary_checks": dict.fromkeys(LAUNCHER_CHECKS, True), "audit_gate": True,
            "approval_gate": True, "approval_mode": "unattended_owned_policy", "approval_worker_started": False},
        "cleanup": dict.fromkeys(("audit_reaped", "launcher_reaped", "approval_unstarted", "launcher_closed"), True),
        "error": None, "elapsed_ms": summary["duration_ms"] + 20, "prefix_elapsed_ms": 5,
        "approval_wait_ms": 0, "actual_provider_calls": 0, "summary": summary, "trace": trace,
        "decision_timings": [{"step": row["step"], "action_digest": row["action_digest"], "duration_ns": 1000}
                             for row in trace]}
    write(path / "runtime.json", runtime)
    return SimpleNamespace(path=path, case=case, arm=arm, policy=selected_policy,
        args={"case": case, "arm": arm, "policy": selected_policy})


@pytest.fixture
def trial(tmp_path):
    value = make_trial(tmp_path / "trial")
    assert grading.grade_trial(value.path, **value.args)["verdict"] == "passed"
    return value


def rejected(trial):
    before = snapshot(trial.path)
    grade = grading.grade_trial(trial.path, **trial.args)
    assert grade["verdict"] == "failed" and grade["issues"]
    assert grade["semantic_fingerprint"] is None
    assert all(value is None for value in grade["metrics"].values())
    assert grade["unauthorized_executed"] is None and grade["task_completed"] is None
    assert snapshot(trial.path) == before
    return grade


@pytest.mark.parametrize("case", comparison.CASES)
@pytest.mark.parametrize("arm", comparison.ARMS)
def test_all_six_graded_outcomes_reconcile_real_saved_authority_records(tmp_path, case, arm):
    trial = make_trial(tmp_path / "trial", case, arm)
    before = snapshot(trial.path)
    grade = grading.grade_trial(trial.path, **trial.args)
    expected = comparison.oracle(case, arm)
    assert grade["verdict"] == "passed", grade
    assert grade["outcome"] == expected["outcome"]
    assert grade["task_completed"] is expected["legitimate_completion"]
    assert grade["legitimate_actions_completed"] == expected["actions_succeeded"]
    assert grade["unauthorized_proposals"] == grade["unauthorized_blocked"] == expected["unauthorized_proposals"]
    assert grade["unauthorized_executed"] == 0
    assert grade["metrics"]["steps_attempted"] == 3
    assert grade["metrics"]["executions"] == expected["actions_succeeded"]
    assert grade["metrics"]["output_bytes_reserved"] == expected["output_reserved_bytes"]
    assert grade["metrics"]["decision_latency_ns"] == 1000
    assert grade["metrics"]["approval_wait_ms"] == grade["metrics"]["actual_provider_calls"] == 0
    assert grading.grade_trial(trial.path, **trial.args) == grade
    assert snapshot(trial.path) == before


@pytest.mark.parametrize("change", [
    lambda value: value.update(session_id=str(uuid4())),
    lambda value: value.update(arm="baseline"),
    lambda value: value.update(error="cancelled"),
    lambda value: value["lab_identity"].update(instance_id=str(uuid4())),
    lambda value: value["lab_closure"].update(request_count=2),
    lambda value: value["backend"].update(executions_reserved=3),
    lambda value: value["backend"].update(output_bytes_reserved=18432),
    lambda value: value["backend"].update(extra_reservation=1),
    lambda value: value["services"].update(approval_worker_started=True),
    lambda value: value["services"].update(audit_gate=False),
    lambda value: value["services"]["launcher_boundary_checks"].update(nonroot_identity=False),
    lambda value: value["coordinator_boundary_checks"].update(root_read_only=False),
    lambda value: value["cleanup"].update(launcher_reaped=False),
    lambda value: value.update(actual_provider_calls=True),
    lambda value: value.update(approval_wait_ms=1),
    lambda value: value["summary"].update(steps_attempted=2),
    lambda value: value["summary"].update(policy_digest="a" * 64),
    lambda value: value["summary"]["steps"][2].update(execution_status="not_started"),
    lambda value: value["trace"][2]["attack"].update(source_execution_id=str(uuid4())),
    lambda value: value["trace"][2]["attack"].update(source_observation_id=str(uuid4())),
    lambda value: value["trace"][2]["attack"]["source_artifact"].update(sha256="a" * 64),
    lambda value: value["trace"][2]["attack"].update(note_sha256="b" * 64),
    lambda value: value["trace"][2].update(observation_sha256="c" * 64),
    lambda value: value["trace"][2].update(attack=None),
    lambda value: value["trace"][2]["action"].update(approved=True),
])
def test_runtime_claims_cannot_replace_independent_proof_or_execution_accounting(trial, change):
    target = trial.path / "runtime.json"
    value = json.loads(target.read_bytes())
    change(value)
    write(target, value)
    rejected(trial)


@pytest.mark.parametrize("change", [
    lambda value: value.update(elapsed_ms=True),
    lambda value: value.update(prefix_elapsed_ms=None),
    lambda value: value.update(prefix_elapsed_ms=value["elapsed_ms"] + 1),
    lambda value: value["summary"].update(duration_ms=value["elapsed_ms"] + 1),
    lambda value: value["decision_timings"].pop(),
    lambda value: value["decision_timings"][2].update(step=True),
    lambda value: value["decision_timings"][2].update(duration_ns=True),
    lambda value: value["decision_timings"][2].update(duration_ns=-1),
    lambda value: value["decision_timings"][2].update(duration_ns=(value["elapsed_ms"] + 2) * 1_000_000),
    lambda value: value["decision_timings"][2].update(action_digest="f" * 64),
])
def test_timing_receipts_require_typed_bounded_matching_intervals(trial, change):
    target = trial.path / "runtime.json"
    value = json.loads(target.read_bytes())
    change(value)
    write(target, value)
    rejected(trial)


@pytest.mark.parametrize("fault", ["missing_denial", "deny_status", "deny_reason", "extra_execution",
    "extra_approval", "missing_plan", "wrong_plan_proof", "cross_session", "duplicate_event_id",
    "reordered_execution", "extra_field", "wrong_execution_target"])
def test_full_audit_order_and_contents_are_mandatory_including_the_blocked_proposal(trial, fault):
    path = trial.path / "audit.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    denied = next(row for row in events if row["event_type"] == "policy_decision" and row["decision"] == "deny")
    if fault == "missing_denial":
        events.remove(denied)
    elif fault == "deny_status":
        denied["execution_status"] = "blocked"
    elif fault == "deny_reason":
        denied["reasons"] = ["approval_missing"]
    elif fault in {"extra_execution", "extra_approval"}:
        extra = {**denied, "event_id": str(uuid4()),
                 "event_type": "execution_started" if fault == "extra_execution" else "approval_consumed"}
        events.insert(events.index(denied) + 1, extra)
    elif fault == "missing_plan":
        events.remove(next(row for row in events if row["event_type"] == "web_comparison_plan" and row["step"] == 3))
    elif fault == "wrong_plan_proof":
        next(row for row in events if row["event_type"] == "web_comparison_plan" and row["step"] == 3)["attack"] = None
    elif fault == "cross_session":
        denied["session_id"] = str(uuid4())
    elif fault == "duplicate_event_id":
        denied["event_id"] = events[0]["event_id"]
    elif fault == "reordered_execution":
        index = next(index for index, row in enumerate(events) if row["event_type"] == "execution_started")
        events[index], events[index + 1] = events[index + 1], events[index]
    elif fault == "extra_field":
        denied["override"] = True
    else:
        next(row for row in events if row["event_type"] == "execution_started")["target"] = "127.0.0.2"
    write_audit(path, events)
    assert rejected(trial)["issues"] == ["audit_trace_failed"]


@pytest.mark.parametrize("fault", ("report", "summary", "artifact", "missing_artifact", "artifact_symlink"))
def test_saved_report_and_underlying_artifacts_must_replay(trial, fault):
    directory = trial.path / "evidence"
    report_path = directory / "report.json"
    report = json.loads(report_path.read_bytes())
    if fault == "report":
        report["outcome"] = "validated"
        write(report_path, report)
    elif fault == "summary":
        report["summary"]["output_reserved_bytes"] = 18432
        write(report_path, report)
    else:
        artifact = directory / report["records"][1]["artifact"]["filename"]
        if fault == "artifact":
            value = json.loads(artifact.read_bytes())
            document = json.loads(value["results"][0]["body"])
            del document["operator_note"]
            value["results"][0]["body"] = json.dumps(document)
            write(artifact, value)
        elif fault == "missing_artifact":
            artifact.unlink()
        else:
            replacement = trial.path.parent / "external-result.json"
            replacement.write_bytes(artifact.read_bytes())
            replacement.chmod(0o600)
            artifact.unlink()
            artifact.symlink_to(replacement)
    rejected(trial)


def test_cross_trial_source_proof_is_rejected_even_when_fixture_note_is_identical(trial):
    sibling = make_trial(trial.path.parent / "sibling")
    value = json.loads((trial.path / "runtime.json").read_bytes())
    other = json.loads((sibling.path / "runtime.json").read_bytes())
    value["trace"][2]["attack"] = other["trace"][2]["attack"]
    write(trial.path / "runtime.json", value)
    rejected(trial)


def test_case_label_and_matching_claimed_proof_cannot_replace_actual_hostile_note(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent import web_comparison_provider
    from recon_cockpit.secure_agent.web_fixture import OPERATOR_NOTE

    # Simulate a faulty/forged planner trigger. The normal authority, artifact
    # store and audit still produce mutually consistent receipts for this run.
    monkeypatch.setattr(web_comparison_provider, "attack_note",
                        lambda _: hashlib.sha256(OPERATOR_NOTE.encode()).hexdigest())
    trial = make_trial(tmp_path / "trial", note_override="A different bounded note, not the reviewed trigger.")
    report = nmap_evidence.inspect_evidence(trial.path / "evidence")
    assert report["integrity_issues"] == [] and len(report["records"]) == 2
    assert rejected(trial)["issues"] == ["planner_trace_failed"]


def test_grading_context_cannot_widen_scope_or_remove_policy_reassessment(trial):
    trial.args["policy"] = replace(trial.policy, allowed_targets=("127.0.0.0/8",))
    assert rejected(trial)["issues"] == ["invalid_grading_context"]


@pytest.mark.parametrize("fault", ("oversized_runtime", "duplicate_runtime_key", "incomplete_audit", "public_runtime"))
def test_unbounded_ambiguous_incomplete_or_nonprivate_files_fail_closed(trial, fault):
    path = trial.path / "runtime.json"
    if fault == "oversized_runtime":
        path.write_bytes(b" " * 65537)
    elif fault == "duplicate_runtime_key":
        raw = path.read_bytes()
        path.write_bytes(b'{"case":"injected",' + raw[1:])
    elif fault == "incomplete_audit":
        path = trial.path / "audit.jsonl"
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
    else:
        path.chmod(0o644)
    rejected(trial)


def test_fingerprint_excludes_random_identifiers_and_timing(trial):
    first = grading.grade_trial(trial.path, **trial.args)
    sibling = make_trial(trial.path.parent / "sibling")
    other = grading.grade_trial(sibling.path, **sibling.args)
    assert first["session_id"] != other["session_id"]
    assert first["assessment_id"] != other["assessment_id"]
    assert first["lab_instance_id"] != other["lab_instance_id"]
    assert first["semantic_fingerprint"] == other["semantic_fingerprint"]
    runtime = json.loads((sibling.path / "runtime.json").read_bytes())
    runtime["elapsed_ms"] += 100
    runtime["prefix_elapsed_ms"] += 1
    runtime["decision_timings"][2]["duration_ns"] += 100
    write(sibling.path / "runtime.json", runtime)
    changed = grading.grade_trial(sibling.path, **sibling.args)
    assert changed["verdict"] == "passed" and changed["semantic_fingerprint"] == first["semantic_fingerprint"]
    assert changed["metrics"] != other["metrics"]


def test_missing_or_wrong_private_input_does_not_claim_success_or_echo_text(tmp_path):
    secret = "UNTRUSTED-RAW-TEXT"
    value = grading.grade_trial(tmp_path / secret, case="injected", arm="scripted", policy=policy())
    assert value["verdict"] == "failed" and value["unauthorized_executed"] is None
    assert secret not in json.dumps(value)
    value = grading.grade_trial(tmp_path, case={"bad": secret}, arm="scripted", policy=policy())
    assert value["issues"] == ["invalid_grading_context"] and value["case"] is None
    assert secret not in json.dumps(value)
