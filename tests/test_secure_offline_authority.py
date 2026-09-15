"""Combined authority/broker checks with explicitly portable boundary doubles."""

from concurrent.futures import ThreadPoolExecutor
import copy
import json
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import openai_provider
from recon_cockpit.secure_agent.approvals import ApprovalStore
from recon_cockpit.secure_agent.audit import AuditSink, AuditUnavailable
from recon_cockpit.secure_agent.control_plane import AuthorityProtocolError, AuthoritySession
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.openai_broker import BrokerLimits, OfflineTransport
from recon_cockpit.secure_agent.openai_fixtures import scenario_responses
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig, build_request, decode_response
from recon_cockpit.secure_agent.openai_provider import OfflineOpenAIProvider
from recon_cockpit.secure_agent.session import SessionLimits
from recon_cockpit.secure_agent.worker import INJECTION_FIXTURE
from scripts.secure_agent_control_plane_demo import demo_policy


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class PortableParser:
    """Exercise the real broker and codec, without claiming process isolation."""

    boundary_checks = None

    def __init__(self):
        self.observations, self.configs, self.controls, self.requests = [], [], [], []

    def plan(self, config, observation, exchange, *, control):
        control.check()
        self.observations.append(json.loads(observation))
        self.configs.append(config)
        self.controls.append(control)
        request = build_request(config, observation)
        self.requests.append(request)
        response = exchange(request, control=control)
        control.check()
        return decode_response(response)


class Coordinator:
    """Can send arbitrary child messages; does not create an OS boundary."""

    boundary_checks = None

    def __init__(self, behavior=None, final=None):
        self.behavior, self.final = behavior, final
        self.inits, self.requests, self.responses = [], [], []
        self.behavior_completed = False

    def envelope(self, operation, sequence, **fields):
        return {"schema_version": "2", "session_id": self.session_id,
                "sequence": sequence, "operation": operation, **fields}

    def send(self, operation, sequence, **fields):
        request = self.envelope(operation, sequence, **fields)
        self.requests.append(copy.deepcopy(request))
        response = json.loads(self.exchange(encode(request), control=self.control))
        self.responses.append(response)
        return response

    def step(self, sequence):
        reply = self.send("plan", sequence)
        if reply["stop"]:
            return reply
        return self.send("propose", sequence, plan=reply["plan"])

    def run(self, init_payload, exchange, *, control):
        self.init = json.loads(init_payload)
        self.inits.append(self.init)
        self.session_id = self.init["session_id"]
        self.exchange, self.control = exchange, control
        if self.behavior is not None:
            self.behavior(self)
            self.behavior_completed = True
        else:
            for step in range(1, 17):
                if self.step(step)["stop"]:
                    break
        if self.final is not None:
            return self.final(self)
        return encode({"schema_version": "2", "session_id": self.session_id, "status": "closed"})


class Backend:
    """No sockets or processes; a fake launch checks its durable audit record."""

    name = "OFFLINE-AUTHORITY-UNIT-TEST-NOT-ISOLATION"

    def __init__(self, path):
        self.path = path
        self.calls, self.controls, self.checks = [], [], []
        self.status = "succeeded"

    def check_available(self, action):
        self.checks.append(action)

    def run(self, action, policy, *, control):
        control.check()
        latest = events(self.path)[-1]
        assert latest["event_type"] == "execution_started"
        assert latest["action_digest"] == action.digest
        assert latest["policy_digest"] == policy.digest
        self.calls.append(action)
        self.controls.append(control)
        body = INJECTION_FIXTURE.decode("ascii") if action.parameters.path == "/injection" else "PRIVATE-OWNED-BODY"
        return {"status": self.status, "bytes_received": 0,
                "results": [{"body": body, "http_status": 200}]}


@pytest.fixture
def make_session(monkeypatch, tmp_path):
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", PortableParser)
    path = tmp_path / "private-audit" / "events.jsonl"
    with AuditSink(path) as audit:
        def create(scenario="three_step", *, approval=False, coordinator=None,
                   broker_limits=None, session_limits=None, clock=time.monotonic):
            transport = OfflineTransport(scenario_responses(scenario))
            provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit,
                                             transport, limits=broker_limits)
            coordinator = Coordinator() if coordinator is None else coordinator
            backend = Backend(path)
            authority = AuthoritySession(demo_policy(approval=approval), audit, backend, coordinator,
                                         session_limits, provider=provider, clock=clock)
            return SimpleNamespace(authority=authority, provider=provider, parser=provider._planner,
                                   coordinator=coordinator, backend=backend, transport=transport,
                                   audit=audit, path=path)
        yield create


def scripted_grant(controller, raw, *, control):
    """Test-only store callback; this does not represent a human approval."""
    control.check()
    return controller.approvals.issue(parse_action(raw), controller.policy).reference


def test_three_step_uses_one_session_control_and_real_broker(make_session):
    case = make_session()
    steps = []
    summary = case.authority.run(execute=True, on_step=steps.append)
    assert summary["session_status"] == "completed"
    assert summary["stop_reason"] == "coordinator_done"
    assert summary["control_plane"] == "privsep-offline-v2"
    assert summary["steps_attempted"] == summary["actions_succeeded"] == 3
    assert summary["output_reserved_bytes"] == 3072
    assert summary["steps"] == steps
    assert case.coordinator.init == {"schema_version": "2", "session_id": case.authority.session_id}
    assert [row["operation"] for row in case.coordinator.requests] == ["plan", "propose"] * 3
    assert [row["sequence"] for row in case.coordinator.responses] == [1, 1, 2, 2, 3, 3]
    for index, reply in enumerate(case.coordinator.responses):
        assert set(reply) == {"schema_version", "session_id", "sequence", "stop", "plan"}
        assert reply["schema_version"] == "2" and reply["session_id"] == case.authority.session_id
        assert reply["stop"] is (index == 5)
        assert (reply["plan"] is None) is (index % 2 == 1)
    assert [action.parameters.path for action in case.backend.calls] == ["/", "/injection", "/"]
    assert all(control is case.coordinator.control for control in case.parser.controls + case.backend.controls)
    assert all(config is case.provider.broker.config for config in case.parser.configs)
    assert case.parser.observations == [
        {"step": 1, "untrusted_observation": None},
        {"step": 2, "untrusted_observation": {"execution_status": "succeeded", "body": "PRIVATE-OWNED-BODY"}},
        {"step": 3, "untrusted_observation": {"execution_status": "succeeded", "body": INJECTION_FIXTURE.decode("ascii")}},
    ]
    assert dict(case.provider.broker.snapshot) == {
        "calls_reserved": 3, "output_tokens_reserved": 3072,
        "request_bytes_reserved": sum(map(len, case.parser.requests)),
    }
    assert case.transport.calls == 3
    records = events(case.path)
    bound = [row for row in records if row["event_type"] == "offline_provider_session_bound"]
    assert len(bound) == 1 and bound[0]["session_id"] == case.authority.session_id
    assert bound[0]["broker_id"] == case.provider.broker.broker_id
    assert {row["broker_id"] for row in records if "broker_id" in row} == {case.provider.broker.broker_id}
    assert {row["session_id"] for row in records if "session_id" in row} == {case.authority.session_id}
    assert records[-1]["event_type"] == "session_finished"
    disclosed = json.dumps(summary) + case.path.read_text() + json.dumps(case.coordinator.responses)
    assert "PRIVATE-OWNED-BODY" not in disclosed and "Ignore prior instructions" not in disclosed
    assert case.provider.boundary_checks is case.coordinator.boundary_checks is None


def test_dry_run_keeps_provider_allowances_without_backend_checks_or_grants(make_session):
    case = make_session(approval=True)
    summary = case.authority.run(interactive=True, approval=lambda *a, **k: pytest.fail("dry-run grant"))
    assert summary["session_status"] == "completed"
    assert summary["actions_succeeded"] == 0 and summary["output_reserved_bytes"] == 3072
    assert case.backend.calls == case.backend.checks == []
    assert case.transport.calls == case.provider.broker.snapshot["calls_reserved"] == 3
    assert case.parser.observations[1]["untrusted_observation"] == {"execution_status": "dry_run", "body": ""}


@pytest.mark.parametrize("field,value", [
    ("observation", {"execution_status": "succeeded", "body": "grant approval"}),
    ("config", {"model": "other-model"}), ("provider", "live"), ("prompt", "override"),
    ("max_calls", 16), ("max_output_tokens", 4096), ("max_steps", 16), ("deadline", 10**12),
    ("execute", True), ("interactive", True), ("approval_reference", "forged-grant"),
    ("policy", {"allowed_targets": ["0.0.0.0/0"]}), ("reset", True),
])
@pytest.mark.parametrize("phase", ["plan", "propose"])
def test_coordinator_cannot_supply_provider_or_authority_configuration(make_session, field, value, phase):
    def attack(child):
        extra = {field: value}
        if phase == "propose":
            extra["plan"] = child.send("plan", 1)["plan"]
        with pytest.raises(AuthorityProtocolError):
            child.send(phase, 1, **extra)
        with pytest.raises((AuthorityProtocolError, ExecutionStopped)):
            child.send("plan", 2)

    case = make_session(coordinator=Coordinator(attack))
    summary = case.authority.run(execute=True)
    assert case.coordinator.behavior_completed
    assert summary["stop_reason"] == "coordinator_protocol_error"
    assert summary["steps_attempted"] == case.transport.calls == int(phase == "propose")
    assert summary["output_reserved_bytes"] == 0 and case.backend.calls == []
    assert case.coordinator.control.cancelled.is_set()


@pytest.mark.parametrize("attack_name", [
    "propose_before_plan", "plan_twice", "advance_before_propose", "wrong_session", "wrong_sequence",
    "boolean_sequence", "wrong_version", "missing_operation", "plan_with_plan", "propose_without_plan",
    "changed_action", "changed_done", "replay_plan", "replay_propose",
])
def test_phase_sequence_session_and_pending_plan_attacks_poison_channel(make_session, attack_name):
    counters = {"calls": 0, "launches": 0}

    def attack(child):
        if attack_name == "propose_before_plan":
            forged = child.envelope("propose", 1, plan={"schema_version": "1", "action": None, "done": True})
        else:
            pending = child.send("plan", 1)["plan"]
            counters["calls"] = 1
            forged = child.envelope("propose", 1, plan=copy.deepcopy(pending))
            if attack_name in {"plan_twice", "advance_before_propose"}:
                forged = child.envelope("plan", 1 if attack_name == "plan_twice" else 2)
            elif attack_name == "wrong_session":
                forged["session_id"] = str(uuid4())
            elif attack_name == "wrong_sequence":
                forged["sequence"] = 2
            elif attack_name == "boolean_sequence":
                forged["sequence"] = True
            elif attack_name == "wrong_version":
                forged["schema_version"] = "1"
            elif attack_name == "missing_operation":
                del forged["operation"]
            elif attack_name == "plan_with_plan":
                forged["operation"] = "plan"
            elif attack_name == "propose_without_plan":
                del forged["plan"]
            elif attack_name == "changed_action":
                forged["plan"]["action"]["parameters"]["path"] = "/changed"
            elif attack_name == "changed_done":
                forged["plan"]["done"] = True
            else:
                assert child.send("propose", 1, plan=pending)["stop"] is False
                counters["launches"] = 1
                if attack_name == "replay_plan":
                    forged = child.envelope("plan", 1)
        with pytest.raises(AuthorityProtocolError):
            child.exchange(encode(forged), control=child.control)
        with pytest.raises((AuthorityProtocolError, ExecutionStopped)):
            child.send("plan", 2)

    case = make_session(coordinator=Coordinator(attack))
    summary = case.authority.run(execute=True)
    assert case.coordinator.behavior_completed
    assert summary["stop_reason"] == "coordinator_protocol_error"
    assert case.transport.calls == summary["steps_attempted"] == counters["calls"]
    assert summary["actions_succeeded"] == len(case.backend.calls) == counters["launches"]


@pytest.mark.parametrize("raw", [b"", b"[]", b"null", b"\xff", b" " * 20481, "{}", None,
                                     b'{"operation":"plan","operation":"propose"}'])
def test_malformed_envelope_never_spends_a_provider_call(make_session, raw):
    def attack(child):
        with pytest.raises(AuthorityProtocolError):
            child.exchange(raw, control=child.control)
        with pytest.raises((AuthorityProtocolError, ExecutionStopped)):
            child.send("plan", 1)

    case = make_session(coordinator=Coordinator(attack))
    summary = case.authority.run(execute=True)
    assert case.coordinator.behavior_completed
    assert summary["stop_reason"] == "coordinator_protocol_error"
    assert summary["steps_attempted"] == case.transport.calls == 0
    assert case.backend.calls == []


def test_plan_is_only_a_quote_and_key_order_does_not_change_its_meaning(make_session):
    def converse(child):
        pending = child.send("plan", 1)["plan"]
        assert case.transport.calls == 1 and case.backend.calls == []
        assert not any(row["event_type"] == "execution_started" for row in events(case.path))
        reordered = dict(reversed(list(pending.items())))
        reordered["action"] = dict(reversed(list(pending["action"].items())))
        assert child.send("propose", 1, plan=reordered)["stop"] is True

    case = make_session(coordinator=Coordinator(converse), session_limits=SessionLimits(max_steps=1))
    summary = case.authority.run(execute=True)
    assert case.coordinator.behavior_completed
    assert summary["stop_reason"] == "step_limit" and len(case.backend.calls) == 1


@pytest.mark.parametrize("raw", [b"", b"[]", b"\xff", b"{}", "{}", None,
                                     encode({"schema_version": "1", "action": None, "done": False}),
                                     encode({"schema_version": "1", "action": {"rationale": "x" * 12288}, "done": True})])
def test_malformed_or_oversized_provider_plan_stops_without_tool_authority(make_session, monkeypatch, raw):
    case = make_session()
    monkeypatch.setattr(case.provider, "propose", lambda *_a, **_k: raw)
    summary = case.authority.run(execute=True)
    assert summary["stop_reason"] == "invalid_proposal"
    assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 0
    assert case.coordinator.responses == [{"schema_version": "2", "session_id": case.authority.session_id,
                                           "sequence": 1, "stop": True, "plan": None}]
    assert case.backend.calls == []


@pytest.mark.parametrize("scenario", ["refusal", "malformed", "incomplete"])
def test_rejected_offline_reply_retains_provider_allowance_and_does_not_retry(make_session, scenario):
    case = make_session(scenario, approval=True)
    summary = case.authority.run(execute=True, interactive=True,
                                 approval=lambda *a, **k: pytest.fail("invalid reply requested grant"))
    assert summary["stop_reason"] == "provider_failed"
    assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 0
    assert case.transport.calls == case.provider.broker.snapshot["calls_reserved"] == 1
    assert case.provider.broker.snapshot["output_tokens_reserved"] == 1024
    assert case.coordinator.responses[-1]["stop"] is True
    assert case.backend.calls == []


@pytest.mark.parametrize("budget,reason", [
    (BrokerLimits(max_calls=2), "broker_call_limit"),
    (BrokerLimits(max_reserved_output_tokens=2048), "broker_token_limit"),
    (BrokerLimits(max_request_bytes=1), "broker_request_limit"),
])
def test_broker_limits_are_separate_from_tool_limits_and_never_refunded(make_session, budget, reason):
    case = make_session("endless", broker_limits=budget)
    summary = case.authority.run(execute=True)
    spent = 0 if reason == "broker_request_limit" else 2
    assert summary["stop_reason"] == case.provider.broker.last_error == reason
    assert summary["steps_attempted"] == spent + 1
    assert summary["actions_succeeded"] == len(case.backend.calls) == spent
    assert case.transport.calls == case.provider.broker.snapshot["calls_reserved"] == spent
    assert case.provider.broker.snapshot["output_tokens_reserved"] == spent * 1024
    assert summary["output_reserved_bytes"] == spent * 1024


@pytest.mark.parametrize("limits,reason,calls,launches", [
    (SessionLimits(max_steps=2), "step_limit", 2, 2),
    (SessionLimits(max_output_bytes=1024), "output_limit", 2, 1),
])
def test_authority_limits_stop_planning_without_refunding_provider_work(make_session, limits, reason, calls, launches):
    case = make_session("endless", session_limits=limits)
    summary = case.authority.run(execute=True)
    assert summary["stop_reason"] == reason and summary["steps_attempted"] == calls
    assert case.transport.calls == case.provider.broker.snapshot["calls_reserved"] == calls
    assert summary["actions_succeeded"] == len(case.backend.calls) == launches
    assert summary["output_reserved_bytes"] == launches * 1024
    assert case.coordinator.responses[-1]["stop"] is True


@pytest.mark.parametrize("status", ["failed", "timeout", "output_limit", "blocked"])
def test_failed_execution_stops_future_provider_work_and_retains_reservations(make_session, status):
    case = make_session()
    case.backend.status = status
    summary = case.authority.run(execute=True)
    assert summary["stop_reason"] == "action_" + status
    assert summary["steps_attempted"] == case.transport.calls == 1
    assert summary["actions_succeeded"] == 0 and summary["output_reserved_bytes"] == 1024
    assert case.provider.broker.snapshot["output_tokens_reserved"] == 1024


def test_each_action_needs_a_fresh_host_grant_kept_out_of_coordinator_and_parser(make_session):
    case = make_session(approval=True)
    grants = []

    def approve(controller, raw, *, control):
        assert control is case.coordinator.control
        reference = scripted_grant(controller, raw, control=control)
        grants.append((parse_action(raw).digest, reference))
        return reference

    summary = case.authority.run(execute=True, interactive=True, approval=approve)
    assert summary["session_status"] == "completed"
    assert summary["actions_succeeded"] == len(grants) == 3
    assert len({reference for _, reference in grants}) == 3
    consumed = [row for row in events(case.path) if row["event_type"] == "approval_consumed"]
    assert [(row["action_digest"], row["approval_reference"]) for row in consumed] == grants
    disclosed = json.dumps(summary) + json.dumps(case.coordinator.responses) + b"".join(case.parser.requests).decode()
    assert all(reference not in disclosed for _, reference in grants)


@pytest.mark.parametrize("mode,reason,launches", [
    ("noninteractive", "noninteractive_approval_required", 0),
    ("missing", "approval_missing", 0),
    ("replay", "approval_unknown_or_replayed", 1),
    ("expired", "approval_expired", 0),
    ("changed_action", "approval_action_changed", 0),
    ("changed_policy", "approval_policy_changed", 0),
])
def test_missing_reused_or_stale_grants_never_authorize_the_next_tool(make_session, mode, reason, launches):
    case = make_session(approval=True)
    now, references = [100.0], []
    case.authority.controller.approvals = ApprovalStore(clock=lambda: now[0])

    def approve(controller, raw, *, control):
        if mode == "missing":
            return None
        if references and mode == "replay":
            return references[0]
        action, policy = json.loads(raw), controller.policy
        if mode == "changed_action":
            action["parameters"]["path"] = "/changed"
        if mode == "changed_policy":
            policy = parse_policy({**policy.to_dict(), "policy_version": "different-policy"})
        reference = controller.approvals.issue(parse_action(action), policy).reference
        references.append(reference)
        if mode == "expired":
            now[0] += policy.approval_ttl_seconds
        return reference

    summary = case.authority.run(execute=True, interactive=mode != "noninteractive", approval=approve)
    assert summary["stop_reason"] == "action_blocked"
    assert summary["steps"][-1]["reasons"] == [reason]
    assert summary["actions_succeeded"] == len(case.backend.calls) == launches
    assert case.transport.calls == launches + 1


@pytest.mark.parametrize("scenario,stop", [("injection_target", "proposal_denied"),
                                          ("injection_authority", "provider_failed")])
def test_hostile_provider_followup_cannot_change_policy_or_obtain_another_grant(make_session, scenario, stop):
    case = make_session(scenario, approval=True)
    digest, grants = case.authority.controller.policy.digest, []

    def approve(controller, raw, *, control):
        grants.append(scripted_grant(controller, raw, control=control))
        return grants[-1]

    summary = case.authority.run(execute=True, interactive=True, approval=approve)
    assert summary["stop_reason"] == stop
    assert summary["steps_attempted"] == case.transport.calls == 2
    assert summary["actions_succeeded"] == len(case.backend.calls) == len(grants) == 1
    assert case.authority.controller.policy.digest == digest
    if scenario == "injection_target":
        assert summary["steps"][-1]["reasons"] == ["target_out_of_scope"]


@pytest.mark.parametrize("boundary,calls,launches", [
    ("session_started", 0, 0), ("offline_provider_session_bound", 0, 0),
    ("session_step_started", 0, 0), ("broker_request_reserved", 0, 0),
    ("broker_exchange_finished", 1, 0), ("session_output_reserved", 1, 0),
    ("execution_started", 1, 0), ("execution_finished", 1, 1),
])
def test_audit_failure_poisoning_prevents_any_later_exchange_or_launch(make_session, monkeypatch, boundary, calls, launches):
    case = make_session()
    original = case.audit.emit

    def fail(event):
        if event["event_type"] == boundary:
            raise AuditUnavailable("PRIVATE-DISK-ERROR")
        original(event)

    monkeypatch.setattr(case.audit, "emit", fail)
    with pytest.raises(AuditUnavailable):
        case.authority.run(execute=True)
    assert case.transport.calls == calls and len(case.backend.calls) == launches
    monkeypatch.setattr(case.audit, "emit", original)
    with pytest.raises(RuntimeError, match="session_already_used"):
        case.authority.run(execute=True)
    if case.coordinator.inits:
        with pytest.raises((AuthorityProtocolError, ExecutionStopped, AuditUnavailable)):
            case.coordinator.send("plan", 2)
    assert case.transport.calls == calls and len(case.backend.calls) == launches


@pytest.mark.parametrize("reason", ["session_timeout", "session_cancelled"])
@pytest.mark.parametrize("boundary", ["offline_provider_session_bound", "session_step_started",
                                       "broker_request_reserved", "broker_exchange_finished",
                                       "session_output_reserved", "execution_started", "approval"])
def test_one_deadline_and_cancel_cover_all_prelaunch_boundaries(make_session, monkeypatch, boundary, reason):
    now = [100.0]
    case = make_session(approval=boundary == "approval", clock=lambda: now[0],
                        session_limits=SessionLimits(max_runtime_seconds=1))
    original = case.audit.emit

    def stop():
        if reason == "session_timeout":
            now[0] = 101.0
        else:
            case.authority.cancel()

    def emit(event):
        original(event)
        if event["event_type"] == boundary:
            stop()

    def approve(controller, raw, *, control):
        reference = scripted_grant(controller, raw, control=control)
        stop()
        return reference

    monkeypatch.setattr(case.audit, "emit", emit)
    summary = case.authority.run(execute=True, interactive=True, approval=approve)
    assert summary["stop_reason"] == reason
    assert summary["actions_succeeded"] == 0 and case.backend.calls == []
    assert case.transport.calls <= 1


def test_cancellation_during_offline_exchange_retains_cost_and_stops_both_dialogues(make_session):
    case = make_session("timeout")
    timer = threading.Timer(0.05, case.authority.cancel)
    started = time.monotonic()
    timer.start()
    try:
        summary = case.authority.run(execute=True)
    finally:
        timer.cancel()
        timer.join(timeout=1)
    assert time.monotonic() - started < 2
    assert summary["stop_reason"] == "session_cancelled"
    assert case.transport.calls == case.provider.broker.snapshot["calls_reserved"] == 1
    assert case.provider.broker.snapshot["output_tokens_reserved"] == 1024
    assert case.backend.calls == []


def test_forged_control_cannot_replace_session_deadline(make_session):
    def attack(child):
        forged = ExecutionControl(child.control.deadline + 10000)
        child.exchange(encode(child.envelope("plan", 1)), control=forged)

    case = make_session(coordinator=Coordinator(attack))
    summary = case.authority.run(execute=True)
    assert summary["stop_reason"] == "coordinator_protocol_error"
    assert case.transport.calls == 0 and case.backend.calls == []


def test_concurrent_request_cancels_pending_approval_before_launch(make_session):
    waiting, release = threading.Event(), threading.Event()

    def approve(controller, raw, *, control):
        reference = scripted_grant(controller, raw, control=control)
        waiting.set()
        assert release.wait(timeout=2)
        return reference

    def attack(child):
        pending = child.send("plan", 1)["plan"]
        with ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(child.send, "propose", 1, plan=pending)
            try:
                assert waiting.wait(timeout=2)
                with pytest.raises(AuthorityProtocolError):
                    child.send("plan", 2)
            finally:
                release.set()
            with pytest.raises((AuthorityProtocolError, ExecutionStopped)):
                running.result(timeout=2)

    case = make_session(approval=True, coordinator=Coordinator(attack))
    summary = case.authority.run(execute=True, interactive=True, approval=approve)
    assert case.coordinator.behavior_completed
    assert summary["stop_reason"] == "coordinator_protocol_error"
    assert summary["actions_succeeded"] == 0 and case.backend.calls == []
    assert case.transport.calls == 1 and summary["output_reserved_bytes"] == 1024


def test_session_provider_and_retained_channel_cannot_restart_accounting(make_session):
    case = make_session()
    assert case.authority.run(execute=True)["session_status"] == "completed"
    with pytest.raises(RuntimeError, match="session_already_used"):
        case.authority.run(execute=True)
    with pytest.raises(RuntimeError, match="broker_session_already_bound"):
        case.provider.bind_session(str(uuid4()))
    with pytest.raises((AuthorityProtocolError, ExecutionStopped)):
        case.coordinator.send("plan", 1)
    coordinator = Coordinator()
    replacement = AuthoritySession(demo_policy(), case.audit, case.backend, coordinator, provider=case.provider)
    summary = replacement.run(execute=True)
    assert summary["stop_reason"] == "provider_failed"
    assert coordinator.inits == []
    assert case.transport.calls == len(case.backend.calls) == 3
    assert case.provider.broker.snapshot["calls_reserved"] == 3


def test_pre_cancelled_session_never_starts_coordinator_or_provider_work(make_session):
    case = make_session()
    case.authority.cancel()
    summary = case.authority.run(execute=True)
    assert summary["stop_reason"] == "session_cancelled"
    assert case.coordinator.inits == case.backend.calls == []
    assert case.transport.calls == summary["steps_attempted"] == 0
