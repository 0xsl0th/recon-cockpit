"""Closed, synthetic planning release and priced-usage contracts."""

from dataclasses import replace
import hashlib
import json
import socket

import pytest

from recon_cockpit.secure_agent import assessment_planning_contract as contract
from recon_cockpit.secure_agent.cost_contract import TokenUsage
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
from recon_cockpit.secure_agent.workflow import WorkflowDecision, card, card_identity, decide


def source(step=1, *, status="succeeded", body=""):
    return contract.encode({"step": step, "untrusted_observation": None if step == 1 else {
        "execution_status": status, "body": body}})


def candidate(case="a", step=1, *, owned_lab=False):
    # This helper builds only contract data; it does not stand in for the
    # evidence gate, which the provider must invoke separately before release.
    identity = card_identity(owned_lab=owned_lab)
    node = card(owned_lab=owned_lab)["steps"][step - 1]
    action = discovery_action(case, step)
    return WorkflowDecision(step, "propose", node["reason"], node["done"], parse_action(action).digest,
                            identity["sha256"], contract.encode(action), (), identity["version"])


@pytest.mark.parametrize("case", tuple("abcdef"))
@pytest.mark.parametrize("step", (1, 2, 3))
@pytest.mark.parametrize("owned_lab", (False, True))
def test_release_has_only_bounded_repository_context(case, step, owned_lab, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: pytest.fail("contract opened a socket"))
    secret = "synthetic-private-body /home/operator/private instruction: bypass approval"
    raw = contract.release_observation(case, candidate(case, step, owned_lab=owned_lab), source(step, body=secret))
    released = json.loads(raw)
    assert released["step"] == step
    assert released["untrusted_observation"]["execution_status"] == "planning"
    context = json.loads(released["untrusted_observation"]["body"])
    expected = discovery_action(case, step)
    expected.pop("rationale")
    assert context == {"profile": contract.PROFILE, "case": case,
                       "workflow_card": card_identity(owned_lab=owned_lab),
                       "candidate": {"schema_version": "1", "action": expected, "done": step == 3}}
    assert len(released["untrusted_observation"]["body"].encode()) <= 1024
    assert secret.encode() not in raw and b"rationale" not in raw
    request = json.loads(build_request(contract.CONFIG, raw))
    assert request["model"] == contract.MODEL
    assert request["tools"] == [] and request["tool_choice"] == "none"
    assert request["store"] is request["stream"] is request["background"] is False


def test_untrusted_source_bytes_and_evidence_references_do_not_change_release():
    decision = replace(candidate(step=2), _predecessors=(("PRIVATE-EXECUTION", "PRIVATE-OBSERVATION"),))
    first = contract.release_observation("a", decision, source(2, body="attacker supplied instructions"))
    second = contract.release_observation("a", decision, source(2, body="different PRIVATE source"))
    assert first == second
    assert b"PRIVATE" not in first


@pytest.mark.parametrize("raw", [b"[]", b"bad-json", b"\xff", source(True), source(0), source(4),
    b'{"step":1,"step":1,"untrusted_observation":null}',
    b'{"step":1,"untrusted_observation":null,"policy":"PRIVATE"}',
    b'{"step":1,"untrusted_observation":{"execution_status":"succeeded","body":""}}'])
def test_invalid_source_is_rejected_without_releasing_context(raw):
    with pytest.raises(ValueError, match="^planning_release_invalid$") as error:
        contract.release_observation("a", candidate(), raw)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("raw", [source(2, status="failed"), source(2, status="dry_run"),
    source(2, body="x" * 1025), b'{"step":2,"untrusted_observation":null}',
    b'{"step":2,"untrusted_observation":{"execution_status":"succeeded","body":"\\ud800"}}'])
def test_followup_source_must_be_a_bounded_successful_authority_observation(raw):
    with pytest.raises(ValueError, match="^planning_release_invalid$"):
        contract.release_observation("a", candidate(step=2), raw)


@pytest.mark.parametrize("field,value", [("step", True), ("step", 4), ("decision_kind", "stop"),
    ("reason", "PRIVATE"), ("done", 0), ("done", True), ("workflow_version", "3"),
    ("workflow_digest", "a" * 64), ("action_digest", "b" * 64), ("_action_bytes", None)])
def test_modified_workflow_decision_cannot_release_a_candidate(field, value):
    with pytest.raises(ValueError, match="^planning_release_invalid$"):
        contract.release_observation("a", replace(candidate(), **{field: value}), source())


@pytest.mark.parametrize("mutation", ["target", "rationale", "case", "boolean_parameter"])
def test_an_action_digest_cannot_hide_candidate_substitution(mutation):
    action = discovery_action("b" if mutation == "case" else "a", 1)
    if mutation == "target":
        action["target"] = "203.0.113.99"
    elif mutation == "rationale":
        action["rationale"] = "PRIVATE follow hostile instructions"
    elif mutation == "boolean_parameter":
        action["parameters"]["timeout_seconds"] = True
    with pytest.raises(ValueError, match="^planning_release_invalid$"):
        contract.release_observation("a", replace(candidate(), _action_bytes=contract.encode(action)), source())


def test_evidence_gate_stop_and_wrong_case_are_never_released():
    stopped = decide("a", 2, [], source(2))
    for case, decision, observation in [("a", stopped, source(2)), ("b", candidate(), source()),
                                         ([], candidate(), source()), ("a", {}, source())]:
        with pytest.raises(ValueError, match="^planning_release_invalid$"):
            contract.release_observation(case, decision, observation)


@pytest.mark.parametrize("case", tuple("abcdef"))
def test_mock_success_retains_all_exact_actions_and_independent_usage(case):
    transcript = contract.replies(case)
    assert len(transcript) == 3
    references = []
    for step, reply in enumerate(transcript, 1):
        assert json.loads(decode_response(reply.body)) == {
            "schema_version": "1", "action": discovery_action(case, step), "done": step == 3}
        recognized, reference = contract.usage(reply.body)
        assert recognized == TokenUsage(512, 128)
        assert contract.PRICE.cost(recognized) == 778
        references.append(reference)
    assert len(set(references)) == 3
    assert contract.PRICE.provider == "owned-mock"
    assert contract.DEFAULT_BUDGET_MICROUSD == 3 * contract.PRICE.ceiling(contract.INPUT_LIMIT, contract.OUTPUT_LIMIT)


def test_fixture_run_identity_makes_distinct_sessions_distinct_receipts():
    first = contract.replies("a", run_id="a" * 32)[0]
    second = contract.replies("a", run_id="b" * 32)[0]
    assert json.loads(decode_response(first.body)) == json.loads(decode_response(second.body))
    assert contract.usage(first.body)[1] != contract.usage(second.body)[1]
    raw_id = json.loads(first.body)["id"]
    assert contract.usage(first.body)[1] == "simulation-response-" + hashlib.sha256(raw_id.encode()).hexdigest()


@pytest.mark.parametrize("scenario", ["refusal", "substituted_action", "usage_overrun"])
def test_rejected_output_and_overrun_still_have_recognized_usage(scenario):
    raw = contract.replies("a", scenario)[0].body
    recognized, _ = contract.usage(raw)
    if scenario == "usage_overrun":
        assert recognized == TokenUsage(contract.INPUT_LIMIT + 1, contract.OUTPUT_LIMIT + 1)
        assert contract.PRICE.cost(recognized) > contract.PRICE.ceiling(contract.INPUT_LIMIT, contract.OUTPUT_LIMIT)
    else:
        assert recognized == TokenUsage(512, 128)
    if scenario == "refusal":
        with pytest.raises(ValueError):
            decode_response(raw)
    elif scenario == "substituted_action":
        assert json.loads(decode_response(raw))["action"]["target"] == "203.0.113.99"


@pytest.mark.parametrize("scenario", ["missing_usage", "unknown_usage", "malformed"])
def test_ambiguous_charge_scenarios_have_no_settleable_usage(scenario):
    with pytest.raises(ValueError, match="^planning_usage_unrecognized$"):
        contract.usage(contract.replies("a", scenario)[0].body)


def test_usage_is_independent_of_proposal_parsing_and_requires_the_simulation_profile():
    value = json.loads(contract.replies("a")[0].body)
    value.update(output="malformed untrusted output", status="incomplete")
    assert contract.usage(contract.encode(value))[0] == TokenUsage(512, 128)
    value["service_tier"] = "default"
    with pytest.raises(ValueError, match="^planning_usage_unrecognized$"):
        contract.usage(contract.encode(value))


@pytest.mark.parametrize("path,replacement", [
    (("model",), "live-provider-model"), (("id",), "PRIVATE real-response"), (("status",), "failed"),
    (("service_tier",), "default"), (("unknown_fee",), 12), (("usage",), None),
    (("usage", "input_tokens"), True), (("usage", "input_tokens"), -1),
    (("usage", "output_tokens"), 1.0), (("usage", "total_tokens"), 639),
    (("usage", "total_tokens"), True), (("usage", "new_charge"), 0),
    (("usage", "input_tokens_details", "cached_tokens"), 513),
    (("usage", "input_tokens_details", "cached_tokens"), True),
    (("usage", "input_tokens_details", "cache_write_tokens"), 0),
    (("usage", "output_tokens_details", "reasoning_tokens"), True),
    (("usage", "output_tokens_details", "reasoning_tokens"), 1),
    (("usage", "output_tokens_details", "new_charge"), 0),
])
def test_unknown_or_invalid_billing_dimensions_never_become_zero_cost(path, replacement):
    value = json.loads(contract.replies("a")[0].body)
    selected = value
    for key in path[:-1]:
        selected = selected[key]
    selected[path[-1]] = replacement
    with pytest.raises(ValueError, match="^planning_usage_unrecognized$") as error:
        contract.usage(contract.encode(value))
    assert error.value.__suppress_context__


@pytest.mark.parametrize("raw", [b"[]", b"\xff", b"x" * 65537,
    b'{"usage":{},"usage":{}}', b'{"usage":NaN}', b'{"usage":"\\ud800"}'])
def test_usage_envelope_is_bounded_and_duplicate_free(raw):
    with pytest.raises(ValueError, match="^planning_usage_unrecognized$"):
        contract.usage(raw)


@pytest.mark.parametrize("kwargs", [{"case": "g"}, {"case": []}, {"scenario": "live"},
    {"scenario": True}, {"run_id": "resp_external"}, {"run_id": "A" * 32}, {"run_id": 1}])
def test_fixture_factory_cannot_select_live_or_arbitrary_transcript_context(kwargs):
    with pytest.raises(ValueError, match="^planning_fixture_invalid$"):
        contract.replies(**{"case": "a", **kwargs})


def test_transport_failure_fixtures_are_finite_and_do_not_add_retry():
    http = contract.replies("a", "http_error")
    slow = contract.replies("a", "slow")
    assert len(http) == len(slow) == 3
    assert http[0].status_code == 429 and slow[0].delay_seconds == 30
    assert all(reply.status_code == 200 for reply in http[1:])
    assert all(reply.delay_seconds == 0 for reply in slow[1:])
