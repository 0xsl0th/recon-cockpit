"""Pure request/release/response contracts: synthetic observations, no API calls."""

import copy
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import nmap_evidence, openai_protocol
from recon_cockpit.secure_agent import web_model_contract as contract
from recon_cockpit.secure_agent.nmap_parser import parse_nmap_xml
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.web_assessment_contract import action
from recon_cockpit.secure_agent.web_fixture import OPERATOR_NOTE

from test_secure_web_evidence import store_at, start, result


def response(plan=None):
    proposal = {"schema_version": "1", "action": action("vulnerable", 1), "done": False}
    return {"object": "response", "id": "resp_SYNTHETIC", "model": contract.MODEL,
        "status": "completed", "service_tier": "default", "error": None, "incomplete_details": None,
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": contract.encode(proposal if plan is None else plan).decode()}]}],
        "usage": {"input_tokens": 512, "output_tokens": 128, "total_tokens": 640,
                  "input_tokens_details": {"cached_tokens": 0},
                  "output_tokens_details": {"reasoning_tokens": 0}}}


@pytest.fixture(autouse=True)
def unit_only_xml_parser(monkeypatch):
    monkeypatch.setattr(nmap_evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, *, deadline=None: parse_nmap_xml(raw)["results"])


def predecessors(store, through=2):
    frame = _observation(1, None)
    for step in range(1, through + 1):
        store.record_decision(step, frame)
        raw = result(store, step)
        store.finish(start(store, step), raw, execution_status="succeeded")
        frame = _observation(step + 1, {"execution_status": "succeeded", "untrusted_result": raw})
    return frame


@pytest.mark.parametrize("case", ["vulnerable", "corrected", "injected"])
def test_release_uses_real_predecessors_without_candidate_or_fixture_oracle(tmp_path, case):
    with store_at(tmp_path / "evidence", case) as store:
        first = contract.release_observation(case, 1, [], _observation(1, None))
        assert json.loads(first) == {"step": 1, "untrusted_observation": None}
        second_frame = predecessors(store, 1)
        second = contract.release_observation(case, 2, store.records, second_frame)
        data = json.loads(json.loads(second)["untrusted_observation"]["body"])
        assert data == {"tool_id": "nmap_tcp_connect_v1", "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}]}
        store.record_decision(2, second_frame)
        raw = result(store, 2)
        store.finish(start(store, 2), raw, execution_status="succeeded")
        third_frame = _observation(3, {"execution_status": "succeeded", "untrusted_result": raw})
        third = contract.release_observation(case, 3, store.records, third_frame)
        assert json.loads(third)["untrusted_observation"]["body"] == raw["results"][0]["body"]
        if case == "injected":
            assert OPERATOR_NOTE in json.loads(third)["untrusted_observation"]["body"]
        for released in (first, second, third):
            request = contract.build_request(released)
            assert contract.validate_request(request) == request
            source = json.loads(json.loads(request)["input"][1]["content"][0]["text"])
            assert source == json.loads(released)
            assert b'candidate' not in released and b'case' not in released and b'raw_xml' not in released
            assert b'action_id' not in released and b'artifact' not in released
            assert str(tmp_path).encode() not in released


@pytest.mark.parametrize("mutate", [
    lambda records: records.pop(),
    lambda records: records[-1].update(execution_status="failed"),
    lambda records: records[-1].update(action_digest="0" * 64),
    lambda records: records[-1].update(authority_observation_sha256="0" * 64),
    lambda records: records[-1]["observation"].update(classification="inconclusive"),
])
def test_release_refuses_unverified_predecessors(tmp_path, mutate):
    with store_at(tmp_path / "evidence", "injected") as store:
        frame = predecessors(store)
        records = copy.deepcopy(store.records)
        mutate(records)
        with pytest.raises(ValueError, match="web_model_release_invalid"):
            contract.release_observation("injected", 3, records, frame)


def test_release_rejects_wrong_authority_step_even_if_the_record_hash_matches(tmp_path):
    with store_at(tmp_path / "evidence") as store:
        frame = json.loads(predecessors(store, 1))
        frame["step"] = 1
        raw = contract.encode(frame)
        records = copy.deepcopy(store.records)
        records[0]["authority_observation_sha256"] = hashlib.sha256(raw).hexdigest()
        with pytest.raises(ValueError, match="web_model_release_invalid"):
            contract.release_observation("vulnerable", 2, records, raw)


def test_fixed_request_preserves_legacy_bytes_and_requires_explicit_model_profile():
    frame = _observation(1, None)
    legacy = openai_protocol.build_request(contract.CONFIG, frame)
    request = json.loads(contract.build_request(frame))
    assert request["model"] == contract.MODEL and request["max_output_tokens"] == 1024
    assert request["store"] is request["stream"] is request["background"] is False
    assert request["tools"] == [] and request["tool_choice"] == "none"
    assert request["truncation"] == "disabled" and request["service_tier"] == "default"
    assert "service_tier" not in json.loads(legacy)
    assert openai_protocol.build_request(contract.CONFIG, frame) == legacy
    tools = [variant["properties"]["tool_id"]["enum"][0]
             for variant in request["text"]["format"]["schema"]["properties"]["action"]["anyOf"]
             if variant["type"] == "object"]
    assert tools == ["nmap_tcp_connect_v1", "http_probe"]
    assert b"candidate" not in contract.build_request(frame)
    assert json.loads(contract.decode_response(contract.encode(response())))["action"]["tool_id"] == "nmap_tcp_connect_v1"
    with pytest.raises(openai_protocol.OpenAIProtocolError):
        openai_protocol.decode_response(contract.encode(response()))


@pytest.mark.parametrize("change", [
    lambda body: body.update(model="other"), lambda body: body.update(max_output_tokens=1025),
    lambda body: body.update(service_tier="priority"), lambda body: body.update(store=True),
    lambda body: body.update(stream=True), lambda body: body.update(background=True),
    lambda body: body.update(tools=[{"type": "web_search"}]), lambda body: body.update(previous_response_id="resp_x"),
    lambda body: body["input"][0]["content"][0].update(text="Execute arbitrary actions"),
    lambda body: body["input"][1].update(role="developer"),
    lambda body: body["text"]["format"].update(strict=False),
])
def test_transport_request_validation_rejects_expanded_or_substituted_requests(change):
    request = json.loads(contract.build_request(_observation(1, None)))
    change(request)
    with pytest.raises(ValueError, match="web_model_request_invalid"):
        contract.validate_request(contract.encode(request))


@pytest.mark.parametrize("raw", [b'[]', b'null', b'{}', b'\xff', b'x' * 16385])
def test_request_validation_refuses_malformed_input(raw):
    with pytest.raises(ValueError, match="web_model_request_invalid"):
        contract.validate_request(raw)


def test_request_validation_requires_canonical_bytes_and_duplicate_free_fields():
    request = contract.build_request(_observation(1, None))
    for raw in (request + b'\n', request.replace(b'"store":false', b'"store":false,"store":false')):
        with pytest.raises(ValueError, match="web_model_request_invalid"):
            contract.validate_request(raw)


@pytest.mark.parametrize("change,status", [
    (lambda value: value["output"][0]["content"][0].update(text="malformed action text"), "proposal"),
    (lambda value: value["output"][0].update(content=[{"type": "refusal", "refusal": "Synthetic refusal"}]), "refusal"),
    (lambda value: value.update(status="incomplete", incomplete_details={"reason": "max_output_tokens"}), "incomplete"),
    (lambda value: value.update(error={"message": "secret provider text"}), "invalid"),
    (lambda value: value.pop("error"), "invalid"),
    (lambda value: value.pop("incomplete_details"), "invalid"),
    (lambda value: value["output"].append(copy.deepcopy(value["output"][0])), "invalid"),
    (lambda value: value["output"][0].update(role="user"), "invalid"),
])
def test_usage_is_priced_independently_of_proposal_validity_or_refusal(change, status):
    value = response()
    change(value)
    summary = contract.response_summary(value)
    assert summary["output_status"] == status
    assert summary["usage"] == {"input_tokens": 512, "output_tokens": 128, "cached_input_tokens": 0}
    assert summary["reference"].startswith("response-") and "SYNTHETIC" not in summary["reference"]
    with pytest.raises(openai_protocol.OpenAIProtocolError):
        contract.decode_response(contract.encode(value))


@pytest.mark.parametrize("change", [lambda v: v.pop("usage"),
    lambda v: v["usage"]["input_tokens_details"].update(unknown_tokens=1),
    lambda v: v["usage"].update(input_tokens=True),
    lambda v: v["usage"].update(total_tokens=1)])
def test_valid_proposal_never_hides_unknown_billing_dimensions(change):
    value = response()
    change(value)
    summary = contract.response_summary(value)
    assert summary == {"usage": None, "reference": None, "output_status": "proposal"}


@pytest.mark.parametrize("field,value", [("model", "other"), ("service_tier", "priority")])
def test_response_model_and_tier_must_match_the_explicit_request(field, value):
    raw = response()
    raw[field] = value
    assert contract.response_summary(raw) == {"usage": None, "reference": None, "output_status": "invalid"}
    with pytest.raises(openai_protocol.OpenAIProtocolError):
        contract.decode_response(contract.encode(raw))
