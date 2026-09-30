"""Portable checks of the owned TLS planning broker and real monetary gate.

Only the exact transport's exchange and networkless parser are doubled here.
These tests establish host-side admission and receipt handling, not isolation.
"""

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
from recon_cockpit.secure_agent import assessment_planning_tls as tls
from recon_cockpit.secure_agent import assessment_planning_tls_contract as tls_contract
from recon_cockpit.secure_agent.assessment_planning_transport import LinuxOwnedPlanningTransport
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.cost_contract import CostError
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.evidence import EvidenceStore
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.openai_protocol import MAX_RESPONSE_BYTES, build_request, decode_response
from recon_cockpit.secure_agent.provider_broker import OwnedProviderBroker
from recon_cockpit.secure_agent.provider_contract import BOUNDARY_NAMES, ProviderError
from recon_cockpit.secure_agent.provider_lab import LinuxOwnedProviderTransport
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


def receipt(expected_digest, **changes):
    value = {"schema_version": "1", "context_digest": expected_digest, "status": "ok",
             "http_status": 200, "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True),
             "cleanup": {"worker_reaped": True, "owner_reaped": True},
             "connection_count": 1, "request_count": 1}
    value.update(changes)
    return value


@pytest.fixture
def transport_stub(monkeypatch):
    state = SimpleNamespace(calls=[], receipt=None, handler=None)

    def exchange(self, request, *, control, context_digest):
        state.calls.append((request, control, context_digest))
        state.receipt = receipt(context_digest)
        if state.handler is not None:
            return state.handler(self, request, control, context_digest)
        return {"body": tls_contract.response_body(request, {
            "case": self.case, "scenario": self.scenario, "run_id": self.run_id}),
            "receipt": state.receipt}

    monkeypatch.setattr(LinuxOwnedPlanningTransport, "exchange", exchange)
    monkeypatch.setattr(LinuxOwnedPlanningTransport, "last_receipt", property(lambda self: state.receipt))
    return state


@pytest.fixture
def case(tmp_path, monkeypatch, request, transport_stub):
    monkeypatch.setattr(planning, "LinuxOpenAIPlanner", PortableParser)
    policy_path = Path(__file__).resolve().parents[1] / "examples/secure-agent-discovery-policy.json"
    policy = parse_policy(json.loads(policy_path.read_text()))
    session_id, audit = str(uuid4()), Audit()
    with CostLedger.create(tmp_path / "costs", account_id="account", mode="simulation",
                           limit_microusd=contract.DEFAULT_BUDGET_MICROUSD) as ledger:
        for scope, parent, kind in (("engagement", "account", "engagement"),
                                   ("session", "engagement", "session"),
                                   ("agent", "session", "agent"), ("planning", "agent", "action")):
            ledger.add_scope(scope, parent_id=parent, kind=kind)
        with EvidenceStore(tmp_path / "evidence", session_id=session_id, policy=policy,
                           case="a", discovery=True, workflow=True) as evidence:
            provider = tls.OwnedTLSAssessmentPlanningProvider("a", audit, evidence, ledger,
                scope_id="planning", scenario=getattr(request, "param", "success"))
            provider.bind_session(session_id)
            yield SimpleNamespace(provider=provider, ledger=ledger, audit=audit, evidence=evidence,
                session_id=session_id, policy=policy, directory=tmp_path / "evidence",
                transport=transport_stub, control=ExecutionControl(time.monotonic() + 30, threading.Event()))


@pytest.fixture
def broker_case(transport_stub):
    audit = Audit()
    transport = LinuxOwnedPlanningTransport("a", scenario="success", run_id="a" * 32)
    request = tls_contract.canonical_request("a", 1)
    observation = json.loads(request)["input"][1]["content"][0]["text"].encode("ascii")
    return SimpleNamespace(broker=tls.OwnedPlanningTLSBroker(audit, transport), transport=transport,
        state=transport_stub, audit=audit, request=request, observation=observation,
        control=ExecutionControl(time.monotonic() + 30, threading.Event()))


def propose(case, observation=None):
    return case.provider.propose(_observation(1, None) if observation is None else observation,
                                 control=case.control)


def call(case, *, request=None):
    return case.broker.exchange(case.observation, case.request if request is None else request,
                               control=case.control)


def first_attempt(case):
    attempts = case.ledger.attempts()
    assert len(attempts) == 1
    return attempts[0]


def assert_terminal_without_proposal(case):
    assert case.evidence.records == []
    assert not any(event["event_type"] == "assessment_planning_proposal_released" for event in case.audit.events)
    calls = len(case.transport.calls)
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)
    assert len(case.transport.calls) == calls


def finish_first(case):
    action = parse_action(json.loads(propose(case))["action"])
    execution = case.evidence.start(action, case.policy, session_id=case.session_id,
        session_step=1, backend="linux-authorized-discovery-fixture-executor-v1")
    result = {"status": "succeeded", "bytes_received": 0, "truncated": False,
              "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}]}
    case.evidence.finish(execution, result, execution_status="succeeded")
    return _observation(2, {"execution_status": "succeeded", "untrusted_result": result})


def test_evidence_and_dispatch_precede_tls_and_settlement_precedes_parser(case, monkeypatch):
    def exchange(transport, request, control, context_digest):
        decisions = [json.loads(row) for row in (case.directory / "evidence.jsonl").read_text().splitlines()]
        assert decisions[-1]["event_type"] == "assessment_workflow_decision"
        attempt = first_attempt(case)
        assert attempt["state"] == "dispatched"
        assert attempt["request_digest"] == hashlib.sha256(request).hexdigest()
        assert case.audit.events[-1]["event_type"] == "assessment_planning_tls_reserved"
        assert case.audit.events[-1]["context_digest"] == context_digest
        assert control is case.control
        return {"body": tls_contract.response_body(request, {
            "case": transport.case, "scenario": transport.scenario, "run_id": transport.run_id}),
            "receipt": receipt(context_digest)}

    def parse(config, observation, exchange, *, control):
        raw = exchange(build_request(config, observation), control=control)
        assert first_attempt(case)["state"] == "settled"
        assert first_attempt(case)["actual_microusd"] == 778
        return decode_response(raw)

    case.transport.handler = exchange
    monkeypatch.setattr(case.provider._planner, "plan", parse)
    result = json.loads(propose(case))
    assert result == {"schema_version": "1", "action": discovery_action("a", 1), "done": False}
    assert case.provider.accounting["summary"]["mode"] == "simulation"
    assert case.evidence.records == []
    assert len(case.transport.calls) == case.provider.broker.snapshot["calls_reserved"] == 1
    assert case.provider.broker.last_receipt["cleanup"] == {"worker_reaped": True, "owner_reaped": True}
    serialized = json.dumps(case.audit.events)
    assert "rationale" not in serialized and "resp_owned_" not in serialized


def test_second_plan_requires_durable_evidence_and_has_distinct_usage_receipt(case):
    observation = finish_first(case)
    result = json.loads(propose(case, observation))
    assert result["action"] == discovery_action("a", 2)
    assert [row["state"] for row in case.ledger.attempts()] == ["settled", "settled"]
    assert case.provider.accounting["summary"]["actual_microusd"] == 1556
    assert len(case.transport.calls) == 2
    assert case.transport.calls[0][2] != case.transport.calls[1][2]


@pytest.mark.parametrize("case,state", [("refusal", "settled"), ("substituted_action", "settled"),
    ("usage_overrun", "settled"), ("missing_usage", "uncertain"), ("unknown_usage", "uncertain")], indirect=["case"])
def test_hostile_planning_responses_never_release_or_retry(case, state):
    with pytest.raises((ValueError, RuntimeError)):
        propose(case)
    attempt = first_attempt(case)
    assert attempt["state"] == state
    assert attempt["reserved_microusd"] == (18442 if state == "uncertain" else 0)
    if state == "settled":
        assert attempt["actual_microusd"] >= 778
    assert len(case.transport.calls) == 1
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("field,value", [
    ("schema_version", 1), ("schema_version", "2"), ("context_digest", "0" * 64),
    ("status", "PRIVATE-STATUS"), ("http_status", True), ("http_status", 199),
    ("http_status", None), ("connection_count", 0), ("connection_count", 2),
    ("connection_count", True), ("connection_count", None), ("request_count", 0),
    ("request_count", 2), ("request_count", True), ("request_count", None),
    ("cleanup", {}), ("cleanup", {"worker_reaped": 1, "owner_reaped": True}),
    ("cleanup", {"worker_reaped": True, "owner_reaped": True, "extra": "PRIVATE"}),
    ("boundary_checks", {}), ("boundary_checks", dict.fromkeys(BOUNDARY_NAMES, 1)),
])
def test_invalid_receipts_keep_dispatch_hold_and_never_release(case, field, value):
    case.transport.handler = lambda _t, _r, _c, digest: {
        "body": b"PRIVATE RESPONSE", "receipt": receipt(digest, **{field: value})}
    with pytest.raises(ProviderError, match="provider_receipt_invalid"):
        propose(case)
    assert first_attempt(case)["state"] == "uncertain"
    assert first_attempt(case)["reserved_microusd"] == 18442
    assert "PRIVATE" not in json.dumps(case.audit.events)
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("mutation", ["receipt_extra", "receipt_missing", "receipt_list",
    "result_extra", "result_missing", "result_list", "body_empty", "body_text", "body_bytearray", "body_oversized"])
def test_closed_exchange_envelope_and_bounded_bytes(case, mutation):
    def exchange(_transport, _request, _control, digest):
        result = {"body": b"PRIVATE", "receipt": receipt(digest)}
        if mutation == "receipt_extra":
            result["receipt"]["secret"] = "PRIVATE"
        elif mutation == "receipt_missing":
            result["receipt"].pop("cleanup")
        elif mutation == "receipt_list":
            result["receipt"] = []
        elif mutation == "result_extra":
            result["secret"] = "PRIVATE"
        elif mutation == "result_missing":
            result.pop("body")
        elif mutation == "result_list":
            return []
        else:
            result["body"] = {"body_empty": b"", "body_text": "PRIVATE", "body_bytearray": bytearray(b"PRIVATE"),
                              "body_oversized": b"x" * (MAX_RESPONSE_BYTES + 1)}[mutation]
        return result

    case.transport.handler = exchange
    with pytest.raises(ProviderError, match="provider_receipt_invalid"):
        propose(case)
    assert first_attempt(case)["state"] == "uncertain"
    assert "PRIVATE" not in json.dumps(case.audit.events)
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("failed", ["worker_reaped", "owner_reaped", *sorted(BOUNDARY_NAMES), "missing_checks"])
def test_failed_cleanup_or_isolation_withholds_response_and_cost_refund(case, failed):
    def exchange(_transport, _request, _control, digest):
        value = receipt(digest)
        if failed == "missing_checks":
            value["boundary_checks"] = None
        else:
            value["cleanup" if failed.endswith("reaped") else "boundary_checks"][failed] = False
        return {"body": b"PRIVATE", "receipt": value}

    case.transport.handler = exchange
    code = "provider_cleanup_failed" if failed.endswith("reaped") else "provider_isolation_failed"
    with pytest.raises(ProviderError, match=code):
        propose(case)
    assert first_attempt(case)["state"] == "uncertain"
    assert case.provider.broker.last_receipt is not None
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("body,code", [(None, "provider_http_error"), (b"PRIVATE", "provider_receipt_invalid")])
def test_failed_status_cannot_carry_a_response(case, body, code):
    case.transport.handler = lambda _t, _r, _c, digest: {
        "body": body, "receipt": receipt(digest, status="http_error", http_status=429)}
    with pytest.raises(ProviderError, match=code):
        propose(case)
    assert first_attempt(case)["state"] == "uncertain"
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("saved", ["valid", "wrong_context", "failed_cleanup", "missing"])
def test_exception_receipt_is_validated_and_exception_text_is_not_released(case, saved):
    def exchange(_transport, _request, _control, digest):
        value = receipt(digest, status="transport_error", http_status=None)
        if saved == "wrong_context":
            value["context_digest"] = "0" * 64
        if saved == "failed_cleanup":
            value["cleanup"]["owner_reaped"] = False
        case.transport.receipt = None if saved == "missing" else value
        raise OSError("PRIVATE NETWORK DETAIL")

    case.transport.handler = exchange
    expected = {"valid": "provider_transport_failed", "missing": "provider_transport_failed",
                "wrong_context": "provider_receipt_invalid", "failed_cleanup": "provider_cleanup_failed"}[saved]
    with pytest.raises(ProviderError, match=expected):
        propose(case)
    assert first_attempt(case)["state"] == "uncertain"
    finished = [event for event in case.audit.events
                if event["event_type"] == "assessment_planning_tls_finished"]
    assert len(finished) == 1
    assert finished[0]["exchange_status"] == "failed" and finished[0]["reason"] == expected
    assert "PRIVATE" not in json.dumps(case.audit.events)
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("event,state,calls", [
    ("assessment_planning_reserved", "cancelled", 0),
    ("assessment_planning_dispatch_started", "uncertain", 0),
    ("assessment_planning_tls_reserved", "uncertain", 0),
    ("assessment_planning_tls_finished", "uncertain", 1),
    ("assessment_planning_settled", "settled", 1),
    ("assessment_planning_proposal_released", "settled", 1),
])
def test_audit_loss_is_terminal_at_each_money_and_tls_boundary(case, monkeypatch, event, state, calls):
    original = case.audit.emit

    def emit(value):
        if value["event_type"] == event:
            raise OSError("PRIVATE AUDIT DETAIL")
        original(value)

    monkeypatch.setattr(case.audit, "emit", emit)
    with pytest.raises(AuditUnavailable):
        propose(case)
    assert first_attempt(case)["state"] == state
    assert len(case.transport.calls) == calls
    assert "PRIVATE" not in json.dumps(case.audit.events)
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("scope", ["account", "engagement", "session", "agent", "planning"])
def test_budget_denial_never_enters_tls(case, scope):
    case.ledger.set_limit(scope, 0, event_id="deny")
    with pytest.raises(CostError, match="cost_budget_exceeded"):
        propose(case)
    assert first_attempt(case)["state"] == "cancelled"
    assert case.provider.broker.snapshot["calls_reserved"] == 0
    assert case.transport.calls == []
    assert_terminal_without_proposal(case)


def test_forged_parser_request_is_rejected_before_money_or_transport(case, monkeypatch):
    def parse(config, observation, exchange, *, control):
        return exchange(build_request(config, observation) + b" ", control=control)

    monkeypatch.setattr(case.provider._planner, "plan", parse)
    with pytest.raises(ValueError, match="planning_request_mismatch"):
        propose(case)
    assert case.ledger.attempts() == [] and case.transport.calls == []
    assert_terminal_without_proposal(case)


@pytest.mark.parametrize("field,value", [("model", "external-model"), ("max_output_tokens", 4096),
    ("stream", True), ("store", True), ("background", True), ("tools", [{"type": "web_search"}]),
    ("url", "https://external.invalid"), ("headers", {"Authorization": "PRIVATE"}),
    ("verify_tls", False), ("retries", 1)])
def test_broker_rejects_substituted_fixed_request_before_transport(broker_case, field, value):
    request = json.loads(broker_case.request)
    request[field] = value
    with pytest.raises(ProviderError, match="provider_request_mismatch"):
        call(broker_case, request=contract.encode(request))
    assert broker_case.state.calls == [] and broker_case.broker.snapshot["calls_reserved"] == 0
    assert "PRIVATE" not in json.dumps(broker_case.audit.events)
    with pytest.raises(ProviderError, match="provider_closed"):
        call(broker_case)


def test_broker_three_call_ceiling_and_read_only_snapshots(broker_case):
    for _ in range(3):
        call(broker_case)
    assert dict(broker_case.broker.snapshot) == {"calls_reserved": 3,
        "output_tokens_reserved": 3 * contract.OUTPUT_LIMIT,
        "request_bytes_reserved": 3 * len(broker_case.request)}
    with pytest.raises(TypeError):
        broker_case.broker.snapshot["calls_reserved"] = 0
    copied = broker_case.broker.last_receipt
    copied["cleanup"]["worker_reaped"] = False
    assert broker_case.broker.last_receipt["cleanup"]["worker_reaped"] is True
    with pytest.raises(ProviderError, match="provider_call_limit"):
        call(broker_case)
    with pytest.raises(ProviderError, match="provider_closed"):
        call(broker_case)
    assert len(broker_case.state.calls) == 3


@pytest.mark.parametrize("change", ["new_control", "deadline", "cancel_reference", "clock"])
def test_control_identity_and_fields_cannot_change_between_calls(broker_case, change):
    call(broker_case)
    if change == "new_control":
        broker_case.control = replace(broker_case.control)
    else:
        field, value = {"deadline": ("deadline", time.monotonic() + 20),
                        "cancel_reference": ("cancelled", threading.Event()),
                        "clock": ("clock", lambda: time.monotonic())}[change]
        object.__setattr__(broker_case.control, field, value)
    with pytest.raises(ProviderError, match="provider_(control_changed|invalid_control)"):
        call(broker_case)
    assert len(broker_case.state.calls) == 1


@pytest.mark.parametrize("invalid", ["too_long", "nan", "infinite", "boolean", "clock", "cancel_type", "wrong_type"])
def test_invalid_control_never_reserves_or_enters_transport(broker_case, invalid):
    if invalid == "wrong_type":
        broker_case.control = SimpleNamespace(deadline=time.monotonic() + 30)
    else:
        field, value = {"too_long": ("deadline", time.monotonic() + 130), "nan": ("deadline", float("nan")),
            "infinite": ("deadline", float("inf")), "boolean": ("deadline", True),
            "clock": ("clock", lambda: time.monotonic()), "cancel_type": ("cancelled", object())}[invalid]
        object.__setattr__(broker_case.control, field, value)
    with pytest.raises(ProviderError, match="provider_invalid_control"):
        call(broker_case)
    assert broker_case.state.calls == [] and broker_case.broker.snapshot["calls_reserved"] == 0


@pytest.mark.parametrize("stage", ["reserved", "finished"])
def test_cancellation_after_tls_audit_prevents_body_release(case, monkeypatch, stage):
    original = case.audit.emit

    def emit(value):
        original(value)
        if value["event_type"] == "assessment_planning_tls_" + stage:
            case.control.cancelled.set()

    monkeypatch.setattr(case.audit, "emit", emit)
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        propose(case)
    assert first_attempt(case)["state"] == "uncertain"
    assert len(case.transport.calls) == (stage == "finished")
    finished = [event for event in case.audit.events
                if event["event_type"] == "assessment_planning_tls_finished"]
    assert len(finished) == 1
    assert finished[0]["exchange_status"] == ("succeeded" if stage == "finished" else "failed")
    if stage == "finished":
        assert finished[0]["receipt"]["status"] == "ok" and "reason" not in finished[0]
    else:
        assert finished[0]["reason"] == "session_cancelled" and finished[0]["receipt"] is None
    assert_terminal_without_proposal(case)


def test_reconstruction_and_rebinding_do_not_reopen_settled_session(case):
    propose(case)
    with pytest.raises(ValueError, match="invalid_owned_planning_configuration"):
        tls.OwnedTLSAssessmentPlanningProvider("a", case.audit, case.evidence, case.ledger, scope_id="planning")
    with pytest.raises(ValueError, match="planning_session_binding_failed"):
        case.provider.bind_session(str(uuid4()))
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        propose(case)
    assert first_attempt(case)["state"] == "settled" and len(case.transport.calls) == 1


def test_simultaneous_proposals_cannot_claim_another_exchange(case):
    entered, release = threading.Event(), threading.Event()
    results, failures = [], []

    def exchange(transport, request, control, digest):
        entered.set()
        assert release.wait(3)
        return {"body": tls_contract.response_body(request, {
            "case": transport.case, "scenario": transport.scenario, "run_id": transport.run_id}),
            "receipt": receipt(digest)}

    def run():
        try:
            results.append(propose(case))
        except BaseException as exc:
            failures.append(exc)

    case.transport.handler = exchange
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
    assert first_attempt(case)["state"] == "settled" and len(case.transport.calls) == 1


def test_simultaneous_broker_calls_never_make_a_second_reservation(broker_case):
    entered, release = threading.Event(), threading.Event()
    results = []

    def exchange(_transport, _request, _control, digest):
        entered.set()
        assert release.wait(3)
        return {"body": b"response", "receipt": receipt(digest)}

    broker_case.state.handler = exchange
    thread = threading.Thread(target=lambda: results.append(call(broker_case)))
    thread.start()
    try:
        assert entered.wait(3)
        with pytest.raises(ProviderError, match="provider_already_running"):
            call(broker_case)
        assert broker_case.broker.snapshot["calls_reserved"] == 1
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and results == [b"response"] and len(broker_case.state.calls) == 1


def test_old_status_broker_rejects_new_planning_transport_and_reverse(broker_case):
    with pytest.raises(ProviderError, match="provider_invalid_transport"):
        OwnedProviderBroker(broker_case.audit, broker_case.transport)
    with pytest.raises(ProviderError, match="provider_invalid_transport"):
        tls.OwnedPlanningTLSBroker(broker_case.audit, LinuxOwnedProviderTransport("success"))
    assert broker_case.state.calls == []


def test_transport_subclasses_and_duck_types_are_rejected(broker_case):
    class Substitute(LinuxOwnedPlanningTransport):
        pass

    for transport in (Substitute("a", scenario="success", run_id="a" * 32),
                      SimpleNamespace(case="a", scenario="success", run_id="a" * 32)):
        with pytest.raises(ProviderError, match="provider_invalid_transport"):
            tls.OwnedPlanningTLSBroker(broker_case.audit, transport)
    broker_case.broker._transport = SimpleNamespace(case="a", scenario="success", run_id="a" * 32)
    with pytest.raises(ProviderError, match="provider_invalid_transport"):
        call(broker_case)
    assert broker_case.state.calls == []


@pytest.mark.parametrize("field,value", [("_case", "b"), ("_scenario", "refusal"), ("_run_id", "b" * 32)])
def test_transport_identity_cannot_change_after_binding(broker_case, field, value):
    call(broker_case)
    setattr(broker_case.transport, field, value)
    with pytest.raises(ProviderError, match="provider_invalid_transport"):
        call(broker_case)
    assert len(broker_case.state.calls) == broker_case.broker.snapshot["calls_reserved"] == 1
    with pytest.raises(ProviderError, match="provider_closed"):
        call(broker_case)


def test_construction_performs_no_exchange_and_requires_session_binding(case):
    before_events, before_costs = list(case.audit.events), case.ledger.events()
    provider = tls.OwnedTLSAssessmentPlanningProvider("a", case.audit, case.evidence,
                                                    case.ledger, scope_id="planning")
    assert case.audit.events == before_events and case.ledger.events() == before_costs
    assert case.transport.calls == []
    with pytest.raises(RuntimeError, match="planning_provider_closed"):
        provider.propose(_observation(1, None), control=case.control)
    assert case.ledger.attempts() == [] and case.transport.calls == []


@pytest.mark.parametrize("scenario", [None, 1, "external", "https://api.openai.com", "success "])
def test_no_unreviewed_live_scenario_configuration(case, scenario):
    with pytest.raises(ValueError, match="invalid_owned_planning_configuration"):
        tls.OwnedTLSAssessmentPlanningProvider("a", case.audit, case.evidence, case.ledger,
                                             scope_id="planning", scenario=scenario)
    assert case.ledger.attempts() == [] and case.transport.calls == []
