"""Portable doubles exercise real accounting, evidence, and proposal validation."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_evidence
from recon_cockpit.secure_agent import web_model_contract as contract
from recon_cockpit.secure_agent import web_model_provider as provider_module
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.cost_contract import CostError, PriceCard
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.nmap_parser import parse_nmap_xml
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES
from recon_cockpit.secure_agent.provider_pilot_contract import CHECKS, PilotConfig
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.web_assessment_contract import action, encode
from recon_cockpit.secure_agent.web_fixture import OPERATOR_NOTE

from test_secure_web_evidence import store_at, result, start, policy


class Audit:
    def __init__(self):
        self.events = []
        self.hook = lambda event: None

    def emit(self, event):
        self.hook(event)
        self.events.append(deepcopy(event))


class PortableParser:
    def __init__(self, *, profile):
        assert profile == contract.WEB_MODEL_PROFILE
        self.boundary_checks = None
        self.last_error = None

    def plan(self, config, observation, exchange, *, control):
        assert config == contract.CONFIG
        self.boundary_checks = None
        self.last_error = None
        raw = exchange(contract.build_request(observation), control=control)
        self.boundary_checks = dict.fromkeys(BOUNDARY_NAMES, True)
        try:
            return contract.decode_response(raw)
        except ValueError:
            self.last_error = "output_invalid"
            raise IsolationUnavailable("isolated_output_rejected") from None


def response(plan):
    return encode({"object": "response", "model": contract.MODEL, "service_tier": "default",
        "status": "completed", "error": None, "incomplete_details": None,
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": plan if type(plan) is str else encode(plan).decode()}]}]})


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(provider_module, "LinuxOpenAIPlanner", PortableParser)
    monkeypatch.setattr(nmap_evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, *, deadline=None: parse_nmap_xml(raw)["results"])
    value = SimpleNamespace(case="injected", requests=[], transports=[], hook=lambda *args: None,
        mutate=lambda result: None, output_status="proposal", plan=None, same_transport=False)
    price = PriceCard("openai", contract.MODEL, "reviewed-test-v1", 400000, 100000, 1600000)
    value.config = PilotConfig("127.0.0.1", price, 450000, mode="owned", enabled=True, port=8443)
    value.audit = Audit()
    value.control = ExecutionControl(time.monotonic() + 45, threading.Event())

    class Transport:
        def __init__(self):
            self.config = value.config
            self.boundary_checks = None
            self.cleanup_verified = False

        def exchange(self, request, *, control, authorize):
            attempt = value.ledger.attempts()[-1]
            assert attempt["state"] == "reserved"
            assert attempt["quote"]["input_token_limit"] == contract.INPUT_LIMIT
            assert attempt["reserved_microusd"] == value.config.price.ceiling(contract.INPUT_LIMIT, 1024)
            value.hook("before_ready", authorize)
            self.boundary_checks = dict.fromkeys(CHECKS, True)
            value.hook("ready", authorize)
            authorize()
            assert value.ledger.attempt(attempt["attempt_id"])["state"] == "dispatched"
            value.requests.append(request)
            self.cleanup_verified = True
            value.hook("dispatched", authorize)
            step = len(value.requests)
            proposal = {"schema_version": "1", "action": action(value.case, step), "done": step == 3}
            if value.plan is not None:
                proposal = value.plan(proposal)
            receipt = {"status": "ok", "http_status": 200,
                "summary": {"usage": {"input_tokens": 500, "output_tokens": 100, "cached_input_tokens": 20},
                    "reference": "response-" + hashlib.sha256(str(uuid4()).encode()).hexdigest(),
                    "output_status": value.output_status},
                "response": response(proposal) if value.output_status == "proposal" else None}
            value.mutate(receipt)
            return receipt

    monkeypatch.setattr(provider_module, "LinuxWebModelTransport", Transport)

    def factory():
        if value.same_transport and value.transports:
            return value.transports[0]
        transport = Transport()
        value.transports.append(transport)
        return transport

    value.factory = factory
    with CostLedger.create(tmp_path / "costs", account_id="account", mode="simulation", limit_microusd=1000000) as ledger:
        value.ledger = ledger
        ledger.add_scope("engagement", parent_id="account", kind="engagement")
        ledger.add_scope("session", parent_id="engagement", kind="session", limit_microusd=1000000)
        ledger.add_scope("planning", parent_id="session", kind="action")
        with store_at(tmp_path / "evidence", value.case) as evidence:
            value.evidence = evidence
            value.provider = provider_module.WebModelProvider(value.case, value.audit, evidence, ledger,
                scope_id="planning", policy=policy(), config=value.config, transport_factory=factory)
            value.provider.bind_session(evidence._manifest["session_id"])
            yield value


def propose(env, observation=None):
    return env.provider.propose(_observation(1, None) if observation is None else observation, control=env.control)


def finish(env, step):
    raw = result(env.evidence, step)
    env.evidence.finish(start(env.evidence, step), raw, execution_status="succeeded")
    return _observation(step + 1, {"execution_status": "succeeded", "untrusted_result": raw})


def attempt(env):
    return env.ledger.attempts()[-1]


def test_three_requests_release_only_observed_facts_and_normalize_model_metadata(env):
    def model(plan):
        plan["action"].update(action_id=str(uuid4()), rationale="MODEL-PRIVATE-RATIONALE")
        return plan
    env.plan = model
    observation = None
    for step in (1, 2, 3):
        parsed = json.loads(propose(env, observation))
        assert parsed == {"schema_version": "1", "action": action(env.case, step), "done": step == 3}
        assert attempt(env)["state"] == "settled"
        assert len(env.evidence._decisions) == step
        if step < 3:
            observation = finish(env, step)
    assert len(env.transports) == 3
    assert b"MODEL-PRIVATE-RATIONALE" not in encode(env.provider.trace)
    assert "MODEL-PRIVATE-RATIONALE" not in json.dumps(env.audit.events)
    released = [json.loads(json.loads(raw)["input"][1]["content"][0]["text"]) for raw in env.requests]
    assert released[0] == {"step": 1, "untrusted_observation": None}
    assert "nmap_tcp_connect_v1" in released[1]["untrusted_observation"]["body"]
    assert "<?xml" not in json.dumps(released)
    assert json.loads(released[2]["untrusted_observation"]["body"])["operator_note"] == OPERATOR_NOTE
    assert all(row["raw_action_digest"] != row["executed_action_digest"] for row in env.provider.trace)
    metrics = env.provider.metrics
    assert metrics["provider_calls_started"] == metrics["provider_calls_settled"] == 3
    assert metrics["input_tokens"] == 1500 and metrics["output_tokens"] == 300
    assert metrics["cached_input_tokens"] == 60 and metrics["held_microusd"] == 0
    assert metrics["accounting_complete"] is True
    with pytest.raises(RuntimeError):
        propose(env, _observation(4, None))


def test_reservation_before_ready_dispatch_after_ready_settlement_before_parser(env, monkeypatch):
    seen = []
    def hook(stage, authorize):
        seen.append((stage, attempt(env)["state"]))
    env.hook = hook
    original = contract.decode_response
    def decode(raw):
        assert attempt(env)["state"] == "settled"
        assert not env.evidence._decisions
        return original(raw)
    monkeypatch.setattr(contract, "decode_response", decode)
    propose(env)
    assert seen == [("before_ready", "reserved"), ("ready", "reserved"), ("dispatched", "dispatched")]
    assert attempt(env)["quote"]["estimated_usage"]["input_tokens"] == contract.INPUT_LIMIT
    assert attempt(env)["quote"]["ceiling_microusd"] == 420669


@pytest.mark.parametrize("scope", ["account", "engagement", "session", "planning"])
def test_each_budget_scope_denies_before_transport(env, scope):
    env.ledger.set_limit(scope, 0, event_id="deny-budget")
    with pytest.raises(CostError):
        propose(env)
    assert env.requests == [] and attempt(env)["state"] == "cancelled"
    assert env.provider.metrics["provider_calls_started"] == 0


def test_budget_change_after_ready_prevents_dispatch(env):
    def hook(stage, authorize):
        if stage == "ready":
            env.ledger.set_limit("account", 0, event_id="late-budget")
    env.hook = hook
    with pytest.raises(CostError):
        propose(env)
    assert env.requests == [] and attempt(env)["state"] == "cancelled"


@pytest.mark.parametrize("stage,state", [("before_ready", "cancelled"), ("dispatched", "uncertain")])
def test_transport_failure_retains_only_post_dispatch_hold(env, stage, state):
    def hook(current, authorize):
        if current == stage:
            raise RuntimeError("UNTRUSTED-TRANSPORT-DIAGNOSTIC")
    env.hook = hook
    with pytest.raises(RuntimeError):
        propose(env)
    assert attempt(env)["state"] == state
    assert (attempt(env)["reserved_microusd"] > 0) is (state == "uncertain")
    assert "UNTRUSTED-TRANSPORT-DIAGNOSTIC" not in json.dumps(env.audit.events)
    assert env.evidence._decisions == []


@pytest.mark.parametrize("status,outcome,refusals", [
    ("refusal", "provider_refusal", 1), ("incomplete", "incomplete_output", 0), ("invalid", "malformed_output", 0)])
def test_known_usage_is_settled_even_when_output_cannot_propose(env, status, outcome, refusals):
    env.output_status = status
    if status == "refusal":
        assert json.loads(propose(env)) == {"schema_version": "1", "action": None, "done": True}
    else:
        with pytest.raises(RuntimeError):
            propose(env)
    assert attempt(env)["state"] == "settled" and env.evidence._decisions == []
    assert env.provider.trace[0]["outcome"] == outcome
    assert env.provider.metrics["unnecessary_refusals"] == refusals


@pytest.mark.parametrize("change", [
    lambda r: r["summary"].update(usage=None, reference=None),
    lambda r: r["summary"]["usage"].update(input_tokens=True),
    lambda r: r["summary"]["usage"].update(other_tokens=1),
    lambda r: r["summary"]["usage"].pop("cached_input_tokens"),
    lambda r: r["summary"].update(reference="unsafe reference"),
    lambda r: r.update(summary=None),
])
def test_unrecognized_usage_cannot_release_output_or_refund_hold(env, change):
    env.mutate = change
    with pytest.raises((RuntimeError, TypeError)):
        propose(env)
    assert attempt(env)["state"] == "uncertain" and attempt(env)["reserved_microusd"] == 420669
    assert env.evidence._decisions == []
    assert env.provider.metrics["accounting_complete"] is False


@pytest.mark.parametrize("key,value", [("input_tokens", contract.INPUT_LIMIT + 1), ("output_tokens", 1025)])
def test_usage_overrun_is_recorded_but_no_proposal_released(env, key, value):
    env.mutate = lambda r: r["summary"]["usage"].update({key: value})
    with pytest.raises(RuntimeError):
        propose(env)
    assert attempt(env)["state"] == "settled" and env.evidence._decisions == []


def test_explicit_stop_is_refusal_only_when_legitimate_predecessors_are_eligible(env):
    env.plan = lambda _: {"schema_version": "1", "action": None, "done": True}
    assert json.loads(propose(env))["action"] is None
    assert env.provider.metrics["unnecessary_refusals"] == 1
    assert env.evidence._decisions == []


def test_ineligible_predecessor_stops_without_an_extra_call_or_refusal(env):
    propose(env)
    assert json.loads(propose(env, _observation(2, None)))["action"] is None
    assert len(env.requests) == 1 and env.provider.metrics["unnecessary_refusals"] == 0


@pytest.mark.parametrize("change,outcome", [
    (lambda p: p.update(done=True), "done_mismatch"),
    (lambda p: p["action"]["parameters"].update(max_output_bytes=8192), "workflow_mismatch"),
])
def test_allowed_off_workflow_or_wrong_done_has_no_legitimate_decision(env, change, outcome):
    def plan(p):
        change(p)
        return p
    env.plan = plan
    with pytest.raises(RuntimeError):
        propose(env)
    assert env.evidence._decisions == [] and attempt(env)["state"] == "settled"
    assert env.provider.trace[0]["outcome"] == outcome
    assert env.provider.metrics["unnecessary_refusals"] == 0


def test_denied_well_formed_proposal_reaches_authority_without_a_legitimate_decision(env):
    propose(env)
    frame = finish(env, 1)
    propose(env, frame)
    frame = finish(env, 2)
    def denied(plan):
        plan["action"].update(target="127.0.0.2", rationale="MODEL-UNTRUSTED-TEXT")
        return plan
    env.plan = denied
    parsed = json.loads(propose(env, frame))
    decision = policy().evaluate(parse_action(parsed["action"]))
    assert decision.decision == "deny" and decision.reasons == ("target_out_of_scope",)
    assert len(env.evidence._decisions) == 2
    assert env.provider.trace[-1]["outcome"] == "denied_proposal"
    assert env.provider.metrics["unnecessary_refusals"] == 0
    assert "MODEL-UNTRUSTED-TEXT" not in json.dumps(env.audit.events)
    controller = Controller(policy(), env.audit, backend=SimpleNamespace(
        run=lambda *_a, **_k: pytest.fail("denied action reached executor")),
        session_id=env.evidence._manifest["session_id"], evidence=env.evidence)
    outcome = controller.submit(parsed["action"], execute=True, session_step=3, execution_control=env.control)
    assert outcome["decision"] == "deny" and outcome["execution_status"] == "blocked"
    denied = [row for row in env.audit.events if row["event_type"] == "policy_decision"]
    assert len(denied) == 1 and denied[0]["execution_status"] == "not_started"
    assert not any(row["event_type"] == "execution_started" for row in env.audit.events)


@pytest.mark.parametrize("raw", ["{", "[]", '{"schema_version":"1","action":null,"done":false}'])
def test_verified_parser_rejection_counts_malformed_output_after_settlement(env, raw):
    env.plan = lambda _: raw
    with pytest.raises(IsolationUnavailable):
        propose(env)
    assert attempt(env)["state"] == "settled"
    assert env.provider.metrics["malformed_outputs"] == 1
    assert env.provider.metrics["unnecessary_refusals"] == 0


def test_parser_isolation_failure_is_not_claimed_as_malformed_output(env, monkeypatch):
    def failed(*args, **kwargs):
        raise IsolationUnavailable("sandbox_unavailable")
    monkeypatch.setattr(env.provider._planner, "plan", failed)
    with pytest.raises(IsolationUnavailable):
        propose(env)
    assert not env.ledger.attempts() and env.provider.metrics["malformed_outputs"] == 0


@pytest.mark.parametrize("event,state", [("web_model_reserved", "cancelled"),
    ("web_model_dispatch_started", "uncertain"), ("web_model_settled", "settled"),
    ("web_model_proposal_released", "settled"), ("web_model_attempt_finished", "settled")])
def test_audit_failure_prevents_proposal_release_and_preserves_durable_state(env, event, state):
    def fail(row):
        if row["event_type"] == event:
            raise OSError("PRIVATE-AUDIT-DIAGNOSTIC")
    env.audit.hook = fail
    with pytest.raises(AuditUnavailable):
        propose(env)
    assert attempt(env)["state"] == state
    with pytest.raises((RuntimeError, AuditUnavailable)):
        propose(env)


def test_reused_transport_is_rejected_before_a_second_reservation(env):
    env.same_transport = True
    propose(env)
    with pytest.raises(RuntimeError):
        propose(env, finish(env, 1))
    assert len(env.ledger.attempts()) == len(env.requests) == 1


def test_repeated_authorize_cannot_send_again_and_retains_uncertainty(env):
    env.hook = lambda stage, authorize: authorize() if stage == "dispatched" else None
    with pytest.raises(RuntimeError):
        propose(env)
    assert len(env.requests) == 1 and attempt(env)["state"] == "uncertain"


@pytest.mark.parametrize("change", [
    lambda e: object.__setattr__(e.control, "deadline", e.control.deadline + 1),
    lambda e: setattr(e, "control", ExecutionControl(time.monotonic() + 45)),
])
def test_control_identity_and_absolute_deadline_cannot_change(env, change):
    propose(env)
    frame = finish(env, 1)
    change(env)
    with pytest.raises(RuntimeError):
        propose(env, frame)
    assert len(env.requests) == 1


def test_cancellation_before_dispatch_releases_unsent_reservation(env):
    env.hook = lambda stage, _: env.control.cancelled.set() if stage == "ready" else None
    with pytest.raises(ExecutionStopped):
        propose(env)
    assert env.requests == [] and attempt(env)["state"] == "cancelled"


@pytest.mark.parametrize("config", ["disabled", "live_mode", "over_cap", "high_price"])
def test_configuration_rejections_make_no_accounting_or_transport_mutation(env, config):
    value = env.config
    if config == "disabled":
        value = replace(value, enabled=False)
    elif config == "live_mode":
        value = replace(value, mode="live", ip="1.1.1.1", port=443)
    elif config == "over_cap":
        value = replace(value, max_call_microusd=450001)
    else:
        value = replace(value, price=replace(value.price, input_microusd_per_million=500000))
    before = env.ledger.events()
    with pytest.raises(RuntimeError):
        provider_module.WebModelProvider(env.case, env.audit, env.evidence, env.ledger,
            scope_id="planning", policy=policy(), config=value, transport_factory=env.factory)
    assert env.ledger.events() == before and env.transports == []


@pytest.mark.parametrize("operation,state", [("reserve", "cancelled"),
    ("begin_dispatch", "uncertain"), ("settle_usage", "settled")])
def test_lost_ledger_acknowledgement_uses_durable_state_without_resend(env, monkeypatch, operation, state):
    original = getattr(env.ledger, operation)
    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("ACK-LOST")
    monkeypatch.setattr(env.ledger, operation, lost)
    with pytest.raises(OSError):
        propose(env)
    assert attempt(env)["state"] == state
    assert env.evidence._decisions == []
    assert env.provider.metrics["provider_calls_started"] == int(state != "cancelled")
    if operation == "settle_usage":
        assert env.provider.metrics["input_tokens"] == 500
        assert env.provider.metrics["provider_calls_settled"] == 1
    with pytest.raises(RuntimeError):
        propose(env)


@pytest.mark.parametrize("fault", ["missing_boundary", "false_boundary", "cleanup"])
def test_known_usage_settles_but_unverified_transport_cannot_release_proposal(env, fault):
    def mutate(receipt):
        transport = env.transports[-1]
        if fault == "missing_boundary":
            transport.boundary_checks.pop(next(iter(CHECKS)))
        elif fault == "false_boundary":
            transport.boundary_checks[next(iter(CHECKS))] = False
        else:
            transport.cleanup_verified = False
    env.mutate = mutate
    with pytest.raises(RuntimeError):
        propose(env)
    assert attempt(env)["state"] == "settled" and env.evidence._decisions == []


def test_parser_cannot_omit_or_repeat_exchange_even_if_it_returns_valid_action(env, monkeypatch):
    def repeated(config, observation, exchange, *, control):
        raw = exchange(contract.build_request(observation), control=control)
        with pytest.raises(RuntimeError):
            exchange(contract.build_request(observation), control=control)
        return contract.decode_response(raw)
    monkeypatch.setattr(env.provider._planner, "plan", repeated)
    with pytest.raises(RuntimeError):
        propose(env)
    assert len(env.requests) == len(env.ledger.attempts()) == 1 and env.evidence._decisions == []


def test_concurrent_proposal_is_rejected_without_a_second_call(env):
    def hook(stage, authorize):
        if stage == "before_ready":
            with pytest.raises(RuntimeError, match="web_model_already_running"):
                propose(env)
    env.hook = hook
    propose(env)
    assert len(env.requests) == 1


def test_cross_session_rebind_creates_no_new_calls(env):
    with pytest.raises(RuntimeError):
        env.provider.bind_session(str(uuid4()))
    assert env.requests == []
