"""Only bound reachability evidence permits the final fixed HTTP action."""

import copy
import hashlib
import json
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import http_headers_contract as contract
from recon_cockpit.secure_agent import http_headers_workflow as workflow
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.http_headers_fixture import OPERATOR_NOTE
from recon_cockpit.secure_agent.models import parse_action


NMAP_OBSERVATION = {
    "parser_version": "nmap-tcp-connect-xml-v1", "kind": "nmap_discovery",
    "classification": "reachable", "reason": "nmap_tcp_port_reachable", "followup_path": None,
}


def frame(step, value=None):
    return contract.encode({"step": step, "untrusted_observation": value})


def record(case="vulnerable", step=1, authority=None):
    action = contract.action(case, step)
    if step == 1:
        observation = copy.deepcopy(NMAP_OBSERVATION)
    else:
        observation = contract.classify_headers({
            "parser_version": "http-headers-v1", "status_code": 200, "content_type": "text/html",
            "csp": "present" if case == "corrected" else "absent",
            "x_frame_options": "deny" if case == "corrected" else "absent",
            "x_content_type_options": "nosniff" if case == "corrected" else "absent",
        })
    return {"execution_id": str(uuid4()), "observation_id": str(uuid4()), "session_step": step,
            "action": {key: value for key, value in action.items() if key != "rationale"},
            "action_digest": parse_action(action).digest, "execution_status": "succeeded",
            "observation": observation,
            "authority_observation_sha256": hashlib.sha256(authority or frame(step + 1)).hexdigest()}


@pytest.mark.parametrize("case", contract.CASES)
def test_two_action_workflow_finishes_without_a_third_proposal(case):
    initial = workflow.decide(case, 1, [], frame(1))
    assert initial.action == contract.action(case, 1) and initial.done is False
    source = frame(2, {"status": "succeeded", "result": {"untrusted": OPERATOR_NOTE}})
    predecessor = record(case, authority=source)
    final = workflow.decide(case, 2, [predecessor], source)
    assert final.action == contract.action(case, 2) and final.done is True
    assert final.to_dict()["predecessors"] == [{
        "execution_id": predecessor["execution_id"], "observation_id": predecessor["observation_id"]}]
    assert "127.0.0.2" not in json.dumps(final.to_dict())
    with pytest.raises(ValueError):
        workflow.decide(case, 3, [predecessor], source)


@pytest.mark.parametrize("mutation,reason", [
    (lambda row: row.update(action_digest="0" * 64), "predecessor_evidence_invalid"),
    (lambda row: row.update(session_step=True), "predecessor_evidence_invalid"),
    (lambda row: row.update(execution_id="invalid"), "predecessor_evidence_invalid"),
    (lambda row: row.update(observation_id=None), "predecessor_evidence_invalid"),
    (lambda row: row["action"].update(target="127.0.0.2"), "predecessor_evidence_invalid"),
    (lambda row: row.update(execution_status="failed"), "predecessor_execution_not_succeeded"),
    (lambda row: row["observation"].update(classification="inconclusive"), "nmap_reachability_not_established"),
    (lambda row: row["observation"].update(approved=True), "nmap_reachability_not_established"),
    (lambda row: row.update(authority_observation_sha256="0" * 64), "authority_observation_mismatch"),
])
def test_forged_or_unsuccessful_predecessor_stops_before_http(mutation, reason):
    source = frame(2)
    predecessor = record(authority=source)
    mutation(predecessor)
    decision = workflow.decide("vulnerable", 2, [predecessor], source)
    assert decision.done is True and decision.action is None
    assert decision.reason == reason


def test_missing_extra_cross_case_or_unbound_predecessors_fail_closed():
    predecessor = record("vulnerable")
    assert workflow.decide("vulnerable", 2, [], frame(2)).reason == "predecessor_evidence_missing"
    assert workflow.decide("vulnerable", 2, [predecessor] * 2, frame(2)).action is None
    assert workflow.decide("injected", 2, [predecessor], frame(2)).action is None
    assert workflow.decide("vulnerable", 2, [predecessor], frame(2, "different")).action is None


@pytest.mark.parametrize("case,reason", [
    ("vulnerable", "http_hardening_gaps_observed"),
    ("corrected", "http_hardening_headers_present"),
    ("injected", "http_hardening_gaps_observed"),
])
def test_terminal_decision_reports_observed_headers_not_exploitation(case, reason):
    records = [record(case, 1), record(case, 2)]
    decision = workflow.terminal_decision(case, records, {
        "steps_attempted": 2, "mode": "execute", "session_status": "completed"})
    assert decision.step == 3 and decision.action is None and decision.done is True
    assert decision.reason == reason
    assert len(decision.to_dict()["predecessors"]) == 2


@pytest.mark.parametrize("mutation", [
    lambda records: records[1].update(observation={"classification": "no_gaps_observed"}),
    lambda records: records[1]["observation"].update(reason="exploitable"),
    lambda records: records[1]["observation"]["headers"].update(csp="absent"),
    lambda records: records[1].update(execution_status="timeout"),
    lambda records: records[1].update(execution_id=records[0]["execution_id"]),
    lambda records: records[1].update(observation_id=records[0]["observation_id"]),
])
def test_terminal_cannot_upgrade_missing_ambiguous_or_replayed_evidence(mutation):
    records = [record("corrected", 1), record("corrected", 2)]
    mutation(records)
    decision = workflow.terminal_decision("corrected", records, {
        "steps_attempted": 2, "mode": "execute", "session_status": "completed"})
    assert decision.reason in {"http_header_evidence_invalid", "discovery_or_execution_evidence_missing"}


def test_dry_run_has_one_proposal_then_stop_and_no_findings():
    decision = workflow.decide("corrected", 2, [], frame(2))
    assert decision.action is None
    terminal = workflow.terminal_decision("corrected", [], {
        "steps_attempted": 2, "mode": "dry_run", "session_status": "completed"})
    assert terminal.reason == "dry_run_has_no_execution_evidence"


class Evidence:
    def __init__(self, case="vulnerable"):
        self.case, self.records, self.calls = case, [], []

    def record_decision(self, step, observation):
        self.calls.append(step)
        return workflow.decide(self.case, step, self.records, observation)


def provider(case="vulnerable"):
    evidence = Evidence(case)
    instance = workflow.HTTPHeadersProvider(case, evidence)
    instance.bind_session(str(uuid4()))
    return instance, evidence


def control():
    return ExecutionControl(time.monotonic() + 5)


def test_provider_is_single_use_and_requires_fresh_matching_frames():
    instance, evidence = provider("injected")
    first = json.loads(instance.propose(frame(1), control=control()))
    assert first["action"] == contract.action("injected", 1) and first["done"] is False
    source = frame(2)
    evidence.records = [record("injected", authority=source)]
    second = json.loads(instance.propose(source, control=control()))
    assert second["action"] == contract.action("injected", 2) and second["done"] is True
    with pytest.raises(RuntimeError):
        instance.propose(frame(3), control=control())
    with pytest.raises(ValueError):
        instance.bind_session(str(uuid4()))
    assert evidence.calls == [1, 2]


@pytest.mark.parametrize("bad_frame", [
    b'{"step":1,"step":1,"untrusted_observation":null}', b'[]',
    frame(True), frame(2), frame(1, {"approve": True}), b"x" * 8193,
])
def test_provider_rejects_malformed_or_replayed_input_without_recording(bad_frame):
    instance, evidence = provider()
    with pytest.raises(ValueError):
        instance.propose(bad_frame, control=control())
    assert evidence.calls == []
    with pytest.raises(RuntimeError):
        instance.propose(frame(1), control=control())


def test_expired_control_stops_before_any_decision_and_closes_provider():
    instance, evidence = provider()
    with pytest.raises(ExecutionStopped):
        instance.propose(frame(1), control=ExecutionControl(time.monotonic() - 1))
    assert evidence.calls == []
    with pytest.raises(RuntimeError):
        instance.propose(frame(1), control=control())


def test_workflow_card_and_returned_action_do_not_expose_mutable_internal_state():
    card = workflow.card()
    original = workflow.card_identity()
    card["steps"].append({"step": 3, "tool_id": "arbitrary"})
    assert workflow.card_identity() == original
    decision = workflow.decide("vulnerable", 1, [], frame(1))
    action = decision.action
    action["target"] = "127.0.0.2"
    assert decision.action["target"] == "127.0.0.1"
