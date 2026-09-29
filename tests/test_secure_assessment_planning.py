"""Portable planning doubles exercise actual ledger and durable evidence gates."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import assessment_planning as planning
from recon_cockpit.secure_agent import assessment_planning_contract as contract
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.cost_contract import CostError
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.openai_broker import OfflineTransport
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
from recon_cockpit.secure_agent.session import _observation


class Audit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class PortableParser:
    boundary_checks = None

    def plan(self, config, observation, exchange, *, control):
        return decode_response(exchange(build_request(config, observation), control=control))


@pytest.fixture
def case(tmp_path, monkeypatch, request):
    monkeypatch.setattr(planning, "LinuxOpenAIPlanner", PortableParser)
    path = Path(__file__).resolve().parents[1] / "examples/secure-agent-discovery-policy.json"
    policy = parse_policy(json.loads(path.read_text()))
    session_id, audit = str(uuid4()), Audit()
    with CostLedger.create(tmp_path / "costs", account_id="account", mode="simulation",
                           limit_microusd=contract.DEFAULT_BUDGET_MICROUSD) as ledger:
        for scope, parent, kind in (("engagement", "account", "engagement"),
                                   ("session", "engagement", "session"),
                                   ("agent", "session", "agent"), ("planning", "agent", "action")):
            ledger.add_scope(scope, parent_id=parent, kind=kind)
        with EvidenceStore(tmp_path / "evidence", session_id=session_id, policy=policy,
                           case="a", discovery=True, workflow=True) as evidence:
            provider = planning.OwnedAssessmentPlanningProvider(
                "a", audit, evidence, ledger, scope_id="planning", scenario=getattr(request, "param", "success"))
            provider.bind_session(session_id)
            yield SimpleNamespace(provider=provider, ledger=ledger, audit=audit, evidence=evidence,
                session_id=session_id, policy=policy, directory=tmp_path / "evidence",
                control=ExecutionControl(time.monotonic() + 30, threading.Event()))


def propose(case, observation=None):
    return case.provider.propose(_observation(1, None) if observation is None else observation,
                                 control=case.control)


def first_attempt(case):
    attempts = case.ledger.attempts()
    assert len(attempts) == 1
    return attempts[0]


def finish_first(case):
    action = parse_action(json.loads(propose(case))["action"])
    execution = case.evidence.start(action, case.policy, session_id=case.session_id,
        session_step=1, backend="linux-authorized-discovery-fixture-executor-v1")
    result = {"status": "succeeded", "bytes_received": 0, "truncated": False,
              "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}]}
    case.evidence.finish(execution, result, execution_status="succeeded")
    return _observation(2, {"execution_status": "succeeded", "untrusted_result": result})


def test_decision_and_reservation_precede_dispatch_and_settlement_precedes_parser(case, monkeypatch):
    original = OfflineTransport.exchange
    released = []

    def exchange(self, request, **kwargs):
        rows = [json.loads(line) for line in (case.directory / "evidence.jsonl").read_text().splitlines()]
        assert rows[-1]["event_type"] == "assessment_workflow_decision"
        assert first_attempt(case)["state"] == "dispatched"
        assert first_attempt(case)["request_digest"] == hashlib.sha256(request).hexdigest()
        released.append(request)
        return original(self, request, **kwargs)

    def parse(config, observation, exchange, *, control):
        raw = exchange(build_request(config, observation), control=control)
        assert first_attempt(case)["state"] == "settled"
        assert first_attempt(case)["actual_microusd"] == 778
        return decode_response(raw)

    monkeypatch.setattr(OfflineTransport, "exchange", exchange)
    monkeypatch.setattr(case.provider._planner, "plan", parse)
    plan = json.loads(propose(case))
    assert plan["action"] == discovery_action("a", 1) and not plan["done"]
    assert len(released) == case.provider.broker.snapshot["calls_reserved"] == 1
    assert case.provider.accounting["summary"]["mode"] == "simulation"
    assert case.evidence.records == []  # A charged proposal supplies no execution evidence.
    assert case.audit.events[-1]["event_type"] == "assessment_planning_proposal_released"
    serialized = json.dumps(case.audit.events)
    assert "rationale" not in serialized and "response-" not in serialized


def test_second_step_requires_saved_evidence_and_uses_same_control(case):
    observation = finish_first(case)
    plan = json.loads(propose(case, observation))
    assert plan["action"] == discovery_action("a", 2)
    assert len(case.ledger.attempts()) == 2
    assert case.provider.accounting["summary"]["actual_microusd"] == 1556


def test_workflow_stop_creates_no_second_attempt(case):
    propose(case)
    stopped = json.loads(propose(case, _observation(2, None)))
    assert stopped == {"schema_version": "1", "action": None, "done": True}
    assert len(case.ledger.attempts()) == case.provider.broker.snapshot["calls_reserved"] == 1
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case, _observation(3, None))


@pytest.mark.parametrize("scope", ["account", "engagement", "session", "agent", "planning"])
def test_all_budget_ancestors_deny_before_exchange(case, monkeypatch, scope):
    case.ledger.set_limit(scope, 0, event_id="deny")
    monkeypatch.setattr(OfflineTransport, "exchange", lambda *_a, **_k: pytest.fail("transport"))
    with pytest.raises(CostError, match="cost_budget_exceeded"):
        propose(case)
    assert first_attempt(case)["state"] == "cancelled"
    assert first_attempt(case)["actual_source"] == "not_sent"
    assert case.provider.broker.snapshot["calls_reserved"] == 0


def test_budget_lowered_after_reservation_blocks_dispatch(case, monkeypatch):
    original = case.audit.emit

    def emit(event):
        original(event)
        if event["event_type"] == "assessment_planning_reserved":
            case.ledger.set_limit("account", 0, event_id="lower")

    monkeypatch.setattr(case.audit, "emit", emit)
    with pytest.raises(CostError, match="cost_budget_exceeded"):
        propose(case)
    assert first_attempt(case)["state"] == "cancelled"
    assert any(row["kind"] == "dispatch_denied" for row in case.ledger.events())


@pytest.mark.parametrize("case,state", [("refusal", "settled"), ("substituted_action", "settled"),
    ("usage_overrun", "settled"), ("missing_usage", "uncertain"), ("unknown_usage", "uncertain"),
    ("malformed", "uncertain"), ("http_error", "uncertain")], indirect=["case"])
def test_adversarial_transcripts_never_release_or_retry(case, state):
    with pytest.raises((ValueError, RuntimeError)):
        propose(case)
    attempt = first_attempt(case)
    assert attempt["state"] == state
    assert attempt["reserved_microusd"] == (18442 if state == "uncertain" else 0)
    assert case.evidence.records == []
    assert not any(row["event_type"] == "assessment_planning_proposal_released" for row in case.audit.events)
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)
    assert case.provider.broker.snapshot["calls_reserved"] == 1


@pytest.mark.parametrize("event,state", [
    ("assessment_planning_reserved", "cancelled"), ("assessment_planning_dispatch_started", "uncertain"),
    ("broker_request_reserved", "uncertain"), ("broker_exchange_finished", "uncertain"),
    ("assessment_planning_settled", "settled"), ("assessment_planning_proposal_released", "settled"),
])
def test_audit_failure_blocks_release_and_keeps_correct_cost(case, monkeypatch, event, state):
    original = case.audit.emit

    def emit(value):
        if value["event_type"] == event:
            raise OSError("PRIVATE FAILURE CANARY")
        original(value)

    monkeypatch.setattr(case.audit, "emit", emit)
    with pytest.raises(AuditUnavailable):
        propose(case)
    assert first_attempt(case)["state"] == state
    assert "PRIVATE" not in json.dumps(case.audit.events)
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)


@pytest.mark.parametrize("stage", ["decision", "reserve", "dispatch", "transport", "settled"])
@pytest.mark.parametrize("cancel", [False, True])
def test_cancellation_and_deadline_stops_are_terminal(case, monkeypatch, stage, cancel):
    def stop():
        raise ExecutionStopped("session_cancelled" if cancel else "session_timeout")

    if stage == "decision":
        monkeypatch.setattr(case.evidence, "record_decision", lambda *_: stop())
    elif stage == "transport":
        monkeypatch.setattr(OfflineTransport, "exchange", lambda *_a, **_k: stop())
    else:
        original = case.audit.emit
        event = {"reserve": "assessment_planning_reserved", "dispatch": "assessment_planning_dispatch_started",
                 "settled": "assessment_planning_settled"}[stage]

        def emit(value):
            original(value)
            if value["event_type"] == event:
                case.control.cancelled.set() if cancel else object.__setattr__(case.control, "deadline", 0)

        monkeypatch.setattr(case.audit, "emit", emit)
    with pytest.raises((ExecutionStopped, ValueError)):
        propose(case)
    expected = {"decision": None, "reserve": "cancelled", "dispatch": "uncertain",
                "transport": "uncertain", "settled": "settled"}[stage]
    assert (first_attempt(case)["state"] if expected else case.ledger.attempts()) == (expected or [])
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_base_exception_after_dispatch_retains_hold(case, monkeypatch, error):
    def stop(*_a, **_k):
        raise error()

    monkeypatch.setattr(OfflineTransport, "exchange", stop)
    with pytest.raises(error):
        propose(case)
    assert first_attempt(case)["state"] == "uncertain"
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)


def test_duplicate_receipt_cannot_release_second_proposal(case, monkeypatch):
    original_usage = contract.usage
    first_reference = []

    def usage(raw):
        parsed, reference = original_usage(raw)
        if not first_reference:
            first_reference.append(reference)
        return parsed, first_reference[0]

    monkeypatch.setattr(contract, "usage", usage)
    observation = finish_first(case)
    with pytest.raises(CostError, match="cost_receipt_already_used"):
        propose(case, observation)
    assert [row["state"] for row in case.ledger.attempts()] == ["settled", "uncertain"]


@pytest.mark.parametrize("mode", ["no_exchange", "wrong_request", "swallow_failure", "duplicate_exchange", "substitute"])
def test_compromised_parser_cannot_bypass_dispatch_settlement_or_candidate(case, monkeypatch, mode):
    expected = {"schema_version": "1", "action": discovery_action("a", 1), "done": False}

    def parse(config, observation, exchange, *, control):
        request = build_request(config, observation)
        if mode == "wrong_request":
            exchange(request + b" ", control=control)
        elif mode == "swallow_failure":
            try:
                exchange(b"substitution", control=control)
            except ValueError:
                pass
        elif mode == "duplicate_exchange":
            exchange(request, control=control)
            try:
                exchange(request, control=control)
            except RuntimeError:
                pass
        elif mode == "substitute":
            exchange(request, control=control)
            expected["action"]["target"] = "127.0.0.2"
        return contract.encode(expected)

    monkeypatch.setattr(case.provider._planner, "plan", parse)
    with pytest.raises((ValueError, RuntimeError)):
        propose(case)
    assert len(case.ledger.attempts()) == (1 if mode in {"duplicate_exchange", "substitute"} else 0)
    assert case.evidence.records == []


def test_failed_decision_prevents_money_and_parser(case, monkeypatch):
    def fail(*_):
        raise EvidenceUnavailable("evidence_unavailable")

    monkeypatch.setattr(case.evidence, "record_decision", fail)
    monkeypatch.setattr(case.provider._planner, "plan", lambda *_a, **_k: pytest.fail("parser"))
    with pytest.raises(EvidenceUnavailable):
        propose(case)
    assert case.ledger.attempts() == []


@pytest.mark.parametrize("change", ["new_control", "deadline", "cancel_reference", "clock"])
def test_control_cannot_change_between_proposals(case, change):
    observation = finish_first(case)
    if change == "new_control":
        case.control = replace(case.control)
    else:
        field, value = {"deadline": ("deadline", time.monotonic() + 25),
                        "cancel_reference": ("cancelled", threading.Event()),
                        "clock": ("clock", lambda: time.monotonic())}[change]
        object.__setattr__(case.control, field, value)
    with pytest.raises(ValueError):
        propose(case, observation)
    assert len(case.ledger.attempts()) == 1


def test_reconstruction_and_rebinding_do_not_restore_authority(case):
    propose(case)
    with pytest.raises(ValueError, match="invalid_owned_planning_configuration"):
        planning.OwnedAssessmentPlanningProvider("a", case.audit, case.evidence, case.ledger, scope_id="planning")
    with pytest.raises(ValueError, match="planning_session_binding_failed"):
        case.provider.bind_session(str(uuid4()))
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)
    assert first_attempt(case)["state"] == "settled"


@pytest.mark.parametrize("stage", ["construction", "bound", "reserved"])
def test_provider_mode_never_uses_provider_accounting(case, monkeypatch, stage):
    if stage == "reserved":
        original = case.audit.emit

        def emit(event):
            original(event)
            if event["event_type"] == "assessment_planning_reserved":
                case.ledger.mode = "provider"

        monkeypatch.setattr(case.audit, "emit", emit)
    else:
        case.ledger.mode = "provider"
    with pytest.raises(ValueError, match="invalid_owned_planning_configuration"):
        if stage == "construction":
            planning.OwnedAssessmentPlanningProvider("a", case.audit, case.evidence, case.ledger, scope_id="planning")
        else:
            propose(case)
    assert (first_attempt(case)["state"] if stage == "reserved" else case.ledger.attempts()) == (
        "cancelled" if stage == "reserved" else [])


def test_construction_performs_no_dispatch_or_audit_and_requires_binding(case, monkeypatch):
    before_events, before_costs = list(case.audit.events), case.ledger.events()
    monkeypatch.setattr(OfflineTransport, "exchange", lambda *_a, **_k: pytest.fail("transport"))
    provider = planning.OwnedAssessmentPlanningProvider("a", case.audit, case.evidence,
                                                       case.ledger, scope_id="planning")
    assert case.audit.events == before_events and case.ledger.events() == before_costs
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        provider.propose(_observation(1, None), control=case.control)
    assert case.ledger.attempts() == []


def test_concurrent_proposal_cannot_claim_another_exchange(case, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    results, failures = [], []
    original = OfflineTransport.exchange

    def exchange(self, *args, **kwargs):
        entered.set()
        assert release.wait(3)
        return original(self, *args, **kwargs)

    def run():
        try:
            results.append(propose(case))
        except BaseException as exc:
            failures.append(exc)

    monkeypatch.setattr(OfflineTransport, "exchange", exchange)
    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert entered.wait(3)
        with pytest.raises(RuntimeError, match="planning_already_running"):
            propose(case)
        assert first_attempt(case)["state"] == "dispatched"
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and len(results) == 1 and failures == []
    assert first_attempt(case)["state"] == "settled"
    assert case.provider.broker.snapshot["calls_reserved"] == 1


def test_closed_ledger_after_dispatch_never_releases_a_proposal(case, monkeypatch):
    original = OfflineTransport.exchange

    def exchange(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        case.ledger.close()
        return response

    monkeypatch.setattr(OfflineTransport, "exchange", exchange)
    with pytest.raises(CostError, match="cost_ledger_unavailable"):
        propose(case)
    with CostLedger(case.ledger.directory, read_only=True) as reopened:
        attempt = reopened.attempts()[0]
        assert attempt["state"] == "dispatched" and attempt["reserved_microusd"] == 18442
    assert not any(row["event_type"] == "assessment_planning_proposal_released" for row in case.audit.events)
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)


@pytest.mark.parametrize("method,state", [("estimate", "cancelled"), ("reserve", "cancelled"),
                                         ("begin_dispatch", "uncertain"), ("settle_usage", "settled")])
@pytest.mark.parametrize("interrupted", [False, True])
def test_lost_ledger_acknowledgement_uses_durable_phase_and_preserves_error(
        case, monkeypatch, method, state, interrupted):
    original = getattr(case.ledger, method)
    error = KeyboardInterrupt() if interrupted else CostError("test_lost_acknowledgement")

    def lose_reply(*args, **kwargs):
        original(*args, **kwargs)
        raise error

    monkeypatch.setattr(case.ledger, method, lose_reply)
    with pytest.raises(type(error)) as raised:
        propose(case)
    assert raised.value is error
    assert first_attempt(case)["state"] == state
    assert not any(row["event_type"] == "assessment_planning_proposal_released" for row in case.audit.events)
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)
