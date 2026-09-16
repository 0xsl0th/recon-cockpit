"""Trusted evidence lifecycle checks; doubles do not claim process isolation."""

import copy
import json
import threading
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from recon_cockpit.secure_agent.audit import AuditSink, AuditUnavailable
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller, IsolationUnavailable
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action, parse_policy


def action():
    return {"schema_version": "1", "action_id": str(UUID(int=1)), "tool_id": "http_probe",
            "target": "127.0.0.1", "rationale": "PRIVATE-PLANNER-RATIONALE",
            "parameters": {"port": 8080, "method": "GET", "path": "/",
                           "timeout_seconds": 1, "max_output_bytes": 1024}}


def policy(approval=False):
    return parse_policy({"schema_version": "1", "policy_version": "evidence-hook-test",
                         "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
                         "allowed_ports": [8080], "allowed_methods": ["GET"],
                         "max_timeout_seconds": 2, "max_output_bytes": 2048, "max_targets": 1,
                         "require_approval": approval, "approval_ttl_seconds": 30})


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class Evidence:
    def __init__(self, trace):
        self.trace, self.starts, self.finishes = trace, [], []
        self.failure, self.when, self.on_start = None, None, None
        self.invalid_id = False

    def start(self, action, policy, *, session_id, session_step, backend):
        self.trace.append("evidence_start")
        if self.when == "start":
            raise self.failure
        execution_id = str(uuid4())
        self.starts.append({"execution_id": execution_id, "session_id": session_id,
                            "session_step": session_step, "action_digest": action.digest,
                            "policy_digest": policy.digest, "backend": backend})
        if self.on_start is not None:
            self.on_start()
        return "PRIVATE-INVALID-ID" if self.invalid_id else execution_id

    def finish(self, execution_id, result, *, execution_status):
        self.trace.append("evidence_finish")
        if self.when == "finish":
            raise self.failure
        self.finishes.append((execution_id, copy.deepcopy(result), execution_status))


class Backend:
    name = "EVIDENCE-HOOK-DOUBLE-NOT-ISOLATION"

    def __init__(self, trace, path):
        self.trace, self.path, self.calls = trace, path, []
        self.unavailable = False
        self.result = {"status": "succeeded", "bytes_received": 12,
                       "results": [{"body": "PRIVATE-RESPONSE-BODY", "http_status": 200}]}

    def check_available(self, _action):
        self.trace.append("available")
        if self.unavailable:
            raise IsolationUnavailable("test boundary unavailable")

    def run(self, action, policy, *, control=None):
        if control is not None:
            control.check()
        assert events(self.path)[-1]["event_type"] == "execution_started"
        self.trace.append("backend_run")
        self.calls.append((action, policy))
        return copy.deepcopy(self.result)


@pytest.fixture
def context(tmp_path, monkeypatch):
    path = tmp_path / "private" / "audit.jsonl"
    with AuditSink(path) as audit:
        trace = []
        original = audit.emit

        def emit(event):
            original(event)
            trace.append(event["event_type"])

        monkeypatch.setattr(audit, "emit", emit)
        evidence = Evidence(trace)
        backend = Backend(trace, path)
        controller = Controller(policy(), audit, backend, session_id=str(uuid4()), evidence=evidence)
        yield SimpleNamespace(path=path, audit=audit, trace=trace, evidence=evidence,
                              backend=backend, controller=controller)


def test_evidence_and_audit_are_durable_before_launch_and_completion(context):
    case = context
    result = case.controller.submit(action(), execute=True, session_step=1)
    assert case.trace == ["policy_decision", "available", "evidence_start", "execution_started",
                          "backend_run", "evidence_finish", "execution_finished"]
    execution_id = result["execution_id"]
    assert str(UUID(execution_id)) == execution_id
    assert case.evidence.starts == [{"execution_id": execution_id, "session_id": case.controller.session_id,
                                    "session_step": 1, "action_digest": parse_action(action()).digest,
                                    "policy_digest": case.controller.policy.digest, "backend": case.backend.name}]
    assert case.evidence.finishes == [(execution_id, case.backend.result, "succeeded")]
    assert [row["execution_id"] for row in events(case.path) if "execution_id" in row] == [execution_id] * 2
    assert "PRIVATE" not in case.path.read_text()


def test_repeated_planner_action_id_uses_distinct_host_execution_ids(context):
    first = context.controller.submit(action(), execute=True, session_step=1)
    second = context.controller.submit(action(), execute=True, session_step=2)
    assert first["action_id"] == second["action_id"] == action()["action_id"]
    assert first["execution_id"] != second["execution_id"]
    assert {row["execution_id"] for row in context.evidence.starts} == {first["execution_id"], second["execution_id"]}


@pytest.mark.parametrize("when", ["start", "finish"])
@pytest.mark.parametrize("failure", [EvidenceUnavailable("evidence_unavailable"), RuntimeError("PRIVATE"),
                                     OSError("PRIVATE"), ValueError("PRIVATE"), TypeError("PRIVATE")])
def test_evidence_failure_escapes_and_permanently_blocks_later_launches(context, when, failure):
    case = context
    case.evidence.when, case.evidence.failure = when, failure
    with pytest.raises(EvidenceUnavailable) as error:
        case.controller.submit(action(), execute=True, session_step=1)
    assert "PRIVATE" not in str(error.value)
    assert len(case.backend.calls) == int(when == "finish")
    assert not any(row["event_type"] == "execution_finished" for row in events(case.path))
    trace = list(case.trace)
    case.evidence.when = None
    with pytest.raises(AuditUnavailable):
        case.controller.submit(action(), execute=True, session_step=2)
    assert case.trace == trace


def test_invalid_store_execution_id_is_not_audit_text_or_execution_authority(context):
    context.evidence.invalid_id = True
    with pytest.raises(EvidenceUnavailable):
        context.controller.submit(action(), execute=True, session_step=1)
    assert context.backend.calls == []
    assert "PRIVATE-INVALID-ID" not in context.path.read_text()
    assert not any(row["event_type"] == "execution_started" for row in events(context.path))


@pytest.mark.parametrize("boundary", ["execution_started", "execution_finished"])
def test_audit_failure_preserves_existing_evidence_without_best_effort_completion(context, monkeypatch, boundary):
    case = context
    original = case.audit.emit

    def fail(event):
        if event["event_type"] == boundary:
            raise AuditUnavailable("audit_unavailable")
        original(event)

    monkeypatch.setattr(case.audit, "emit", fail)
    with pytest.raises(AuditUnavailable):
        case.controller.submit(action(), execute=True, session_step=1)
    assert len(case.evidence.starts) == 1
    assert len(case.evidence.finishes) == len(case.backend.calls) == int(boundary == "execution_finished")
    monkeypatch.setattr(case.audit, "emit", original)
    with pytest.raises(AuditUnavailable):
        case.controller.submit(action(), execute=True, session_step=2)


@pytest.mark.parametrize("reason", ["timeout", "cancelled"])
def test_control_expiring_during_evidence_start_prevents_launch(context, reason):
    now, cancelled = [100.0], threading.Event()
    control = ExecutionControl(101.0, cancelled, clock=lambda: now[0])

    def stop():
        if reason == "timeout":
            now[0] = 101.0
        else:
            cancelled.set()

    context.evidence.on_start = stop
    result = context.controller.submit(action(), execute=True, session_step=1, execution_control=control)
    assert result["execution_status"] == reason and context.backend.calls == []
    assert context.evidence.finishes == [(result["execution_id"], {"status": reason}, reason)]


@pytest.mark.parametrize("mode", ["dry_run", "denied", "approval_missing", "unavailable"])
def test_ineligible_actions_do_not_create_execution_evidence(context, mode):
    case = context
    proposal = action()
    if mode == "denied":
        proposal["target"] = "127.0.0.2"
    if mode == "approval_missing":
        case.controller.policy = policy(approval=True)
    case.backend.unavailable = mode == "unavailable"
    result = case.controller.submit(proposal, execute=mode != "dry_run", session_step=1)
    assert result["execution_status"] in {"dry_run", "blocked"}
    assert "execution_id" not in result
    assert case.evidence.starts == case.evidence.finishes == case.backend.calls == []


def test_required_approval_is_consumed_before_evidence_start(context):
    case = context
    case.controller.policy = policy(approval=True)
    reference = case.controller.approvals.issue(parse_action(action()), case.controller.policy).reference
    result = case.controller.submit(action(), execute=True, interactive=True,
                                    approval_reference=reference, session_step=1)
    assert result["execution_status"] == "succeeded"
    assert case.trace.index("approval_consumed") < case.trace.index("evidence_start")
    assert reference not in json.dumps(case.evidence.starts)


def test_disabled_evidence_preserves_original_events_and_outcome(context):
    context.controller.evidence = None
    result = context.controller.submit(action(), execute=True, session_step=1)
    assert "execution_id" not in result
    assert context.evidence.starts == context.evidence.finishes == []
    assert context.trace == ["policy_decision", "available", "execution_started", "backend_run", "execution_finished"]


class Provider:
    def __init__(self):
        self.calls = 0

    def bind_session(self, session_id):
        self.session_id = session_id

    def propose(self, _observation, *, control):
        control.check()
        self.calls += 1
        return json.dumps({"schema_version": "1", "action": action(), "done": self.calls == 2}).encode()


class Coordinator:
    def __init__(self, swallow=False):
        self.swallow = swallow

    def run(self, raw, exchange, *, control):
        initial = json.loads(raw)
        self.exchange, self.control = exchange, control
        self.initial = initial
        for step in (1, 2):
            envelope = {**initial, "sequence": step}
            planned = json.loads(exchange(json.dumps({**envelope, "operation": "plan"}).encode(), control=control))
            try:
                result = json.loads(exchange(json.dumps({**envelope, "operation": "propose",
                                                        "plan": planned["plan"]}).encode(), control=control))
            except EvidenceUnavailable:
                if not self.swallow:
                    raise
                with pytest.raises(AuditUnavailable):
                    exchange(json.dumps({**initial, "sequence": 2, "operation": "plan"}).encode(), control=control)
                break
            if result["stop"]:
                break
        return json.dumps({**initial, "status": "closed"}).encode()


@pytest.mark.parametrize("when", ["start", "finish"])
@pytest.mark.parametrize("swallow", [False, True])
def test_authority_evidence_failure_prevents_later_provider_work_and_retained_callbacks(context, when, swallow):
    case = context
    provider, coordinator = Provider(), Coordinator(swallow=swallow)
    case.evidence.when, case.evidence.failure = when, EvidenceUnavailable("evidence_unavailable")
    authority = AuthoritySession(policy(), case.audit, case.backend, coordinator,
                                 provider=provider, evidence=case.evidence)
    with pytest.raises(AuditUnavailable):
        authority.run(execute=True)
    assert provider.calls == 1 and len(case.backend.calls) == int(when == "finish")
    case.evidence.when = None
    with pytest.raises((AuditUnavailable, ExecutionStopped)):
        coordinator.exchange(json.dumps({**coordinator.initial, "sequence": 2, "operation": "plan"}).encode(),
                             control=coordinator.control)
    assert provider.calls == 1 and len(case.backend.calls) == int(when == "finish")


def test_authority_public_steps_include_execution_ids_without_private_result(context):
    case = context
    callbacks = []
    authority = AuthoritySession(policy(), case.audit, case.backend, Coordinator(),
                                 provider=Provider(), evidence=case.evidence)
    summary = authority.run(execute=True, on_step=callbacks.append)
    assert summary["session_status"] == "completed"
    assert [row["execution_id"] for row in summary["steps"]] == [row["execution_id"] for row in case.evidence.starts]
    assert summary["steps"] == callbacks
    assert "PRIVATE" not in json.dumps(summary) + json.dumps(callbacks)
