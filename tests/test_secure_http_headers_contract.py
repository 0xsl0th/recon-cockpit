"""The new HTTP receipt and scope are strict; legacy capabilities stay fixed."""

import base64
import copy
import hashlib
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import http_headers_contract as contract
from recon_cockpit.secure_agent import http_headers_lab_contract as lab
from recon_cockpit.secure_agent import web_lab_contract
from recon_cockpit.secure_agent.assessment_contract import _BOUNDARY_FIELDS
from recon_cockpit.secure_agent.http_headers_fixture import (
    CORRECTED_HEADERS, INJECTED_PORTAL_BODY, OPERATOR_NOTE, PORTAL_BODY, response,
)
from recon_cockpit.secure_agent.models import (
    HTTPHeadersParameters, HTTPParameters, ValidationError, parse_action, parse_policy,
)
from recon_cockpit.secure_agent.tool_adapters import (
    ADAPTERS, LEGACY_PROPOSAL_PROFILE, NMAP_PROPOSAL_PROFILE, proposal_tools,
)


def normalized(*, hardened=False):
    return {"parser_version": "http-headers-v1", "status_code": 200, "content_type": "text/html",
            "csp": "present" if hardened else "absent",
            "x_frame_options": "deny" if hardened else "absent",
            "x_content_type_options": "nosniff" if hardened else "absent"}


def receipt(raw=b"retained bytes", *, status="succeeded", headers=None):
    truncated = status == "output_limit"
    row = {"target": "127.0.0.1", "port": 8080, "bytes_received": len(raw),
           "truncated": truncated, "raw_response": base64.b64encode(raw).decode(),
           "response_sha256": hashlib.sha256(raw).hexdigest()}
    return {"status": status, "results": [row], "bytes_received": len(raw),
            "truncated": truncated, "http_headers": headers,
            "boundary_checks": {key: True for key in _BOUNDARY_FIELDS}}


def policy(**changes):
    return parse_policy({
        "schema_version": "1", "policy_version": "http-headers-test-v1",
        "allowed_targets": ["127.0.0.1/32"],
        "allowed_tools": [contract.TOOL_ID, contract.HTTP_TOOL_ID],
        "allowed_ports": [8080], "allowed_methods": ["GET"],
        "max_timeout_seconds": 5, "max_output_bytes": 16384, "max_targets": 1,
        "require_approval": True, "approval_ttl_seconds": 60, **changes,
    })


@pytest.mark.parametrize("case", contract.CASES)
def test_fixed_new_profile_uses_typed_action_and_existing_session_ceiling(case):
    actions = [parse_action(contract.action(case, step)) for step in (1, 2)]
    assert [row.tool_id for row in actions] == [contract.TOOL_ID, "http_headers_v1"]
    assert type(actions[1].parameters) is HTTPHeadersParameters
    assert type(actions[1].parameters) is not HTTPParameters
    assert actions[1].parameters.to_dict() == {
        "port": 8080, "method": "GET", "path": "/harbordesk/portal.html",
        "timeout_seconds": 1, "max_output_bytes": 2048,
    }
    assert all(contract.profile_allows(row, case) for row in actions)
    assert sum(row.parameters.max_output_bytes for row in actions) == 18432
    assert contract.LIMITS == {"max_steps": 3, "max_runtime_seconds": 60, "max_output_bytes": 18432}
    assert all(policy().evaluate(row).decision == "approval_required" for row in actions)
    assert contract.capability_descriptor()["live_calls_enabled"] is False


def test_new_tool_does_not_enter_any_accepted_model_proposal_profile():
    assert proposal_tools(LEGACY_PROPOSAL_PROFILE) == ("http_probe", "tcp_connect")
    assert proposal_tools(NMAP_PROPOSAL_PROFILE) == (contract.TOOL_ID, "http_probe")
    assert ADAPTERS[contract.HTTP_TOOL_ID].parameter_schema()["properties"]["method"] == {
        "type": "string", "enum": ["GET", "HEAD"]}


@pytest.mark.parametrize("field,value", [
    ("port", True), ("port", "8080"), ("timeout_seconds", False),
    ("timeout_seconds", 1.0), ("max_output_bytes", "2048"),
    ("method", "get"), ("path", "/../secret"), ("path", "/portal\r\nX-Header: x"),
])
def test_new_parameter_type_rejects_ambiguous_types_and_request_injection(field, value):
    action = contract.action("vulnerable", 2)
    action["parameters"][field] = value
    with pytest.raises(ValidationError):
        parse_action(action)


@pytest.mark.parametrize("field,value", [
    ("port", 8081), ("method", "HEAD"), ("path", "/admin"),
    ("timeout_seconds", 2), ("max_output_bytes", 2049),
])
def test_syntactically_valid_parameters_cannot_expand_reviewed_profile(field, value):
    action = contract.action("vulnerable", 2)
    action["parameters"][field] = value
    assert not contract.profile_allows(parse_action(action), "vulnerable")


@pytest.mark.parametrize("target", ["127.0.0.2", "127.0.0.1/32", "::1"])
def test_profile_requires_literal_owned_ipv4_target(target):
    action = contract.action("vulnerable", 2)
    action["target"] = target
    assert not contract.profile_allows(parse_action(action), "vulnerable")


@pytest.mark.parametrize("changes,reason", [
    ({"allowed_targets": ["127.0.0.2/32"]}, "target_out_of_scope"),
    ({"allowed_tools": [contract.TOOL_ID]}, "tool_not_allowed"),
    ({"allowed_ports": [8081]}, "port_not_allowed"),
    ({"allowed_methods": ["HEAD"]}, "method_not_allowed"),
    ({"max_output_bytes": 1024}, "output_limit_exceeds_policy"),
])
def test_policy_applies_every_relevant_old_gate_to_new_tool(changes, reason):
    decision = policy(**changes).evaluate(parse_action(contract.action("vulnerable", 2)))
    assert decision.decision == "deny"
    assert reason in decision.reasons


@pytest.mark.parametrize("case,step", [("a", 1), ([], 2), ("injected", True), ("corrected", 3)])
def test_unknown_case_and_extra_action_are_rejected(case, step):
    with pytest.raises(ValueError):
        contract.action(case, step)


@pytest.mark.parametrize("case", contract.CASES)
def test_fixture_is_small_static_html_with_separate_identity(case):
    status, body, headers = response(case, contract.PORTAL_PATH)
    assert status == 200 and len(body) <= 1024
    assert contract.FIXTURE_MARKER.encode() in body
    assert body == (INJECTED_PORTAL_BODY if case == "injected" else PORTAL_BODY)
    assert (OPERATOR_NOTE.encode() in body) is (case == "injected")
    assert (headers == CORRECTED_HEADERS) is (case == "corrected")
    instance = str(uuid4())
    identity = lab.identity(case, instance)
    assert lab.validate_identity(identity, case=case) == identity
    assert identity != web_lab_contract.identity(case, instance)
    assert lab.spec(case)["routes"][0]["headers_sha256"] == hashlib.sha256(headers).hexdigest()
    assert lab.spec(case)["routes"][0]["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert response(case, "/forbidden")[0] == 404


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(id="harbordesk-owned-web-lab"),
    lambda value: value.update(scenario="unknown"),
    lambda value: value.update(spec_sha256="0" * 64),
    lambda value: value.update(instance_id="not-a-uuid"),
    lambda value: value.update(approved=True),
])
def test_lab_identity_rejects_wrong_profile_or_forgery(mutation):
    identity = lab.identity("vulnerable", str(uuid4()))
    mutation(identity)
    with pytest.raises(ValueError):
        lab.validate_identity(identity)


def test_request_continuity_and_closure_are_exact_while_connections_are_lower_bounds():
    identity = lab.identity("vulnerable", str(uuid4()))
    initial = {"identity": identity, "connection_count": 0, "request_count": 0}
    nmap = {"backend": contract.BACKEND, "owned_lab": initial}
    assert contract.validate_result_context(nmap, identity, tool_id=contract.TOOL_ID,
                                           execution_status="succeeded") == initial
    after = {"identity": identity, "connection_count": 1, "request_count": 1}
    http = {"backend": contract.BACKEND, "owned_lab": after}
    assert contract.validate_result_context(http, identity, previous=initial,
        tool_id=contract.HTTP_TOOL_ID, execution_status="succeeded") == after
    assert lab.validate_closure({**after, "status": "closed"}, identity, previous=after)
    with pytest.raises(ValueError):
        contract.validate_result_context(nmap, identity, previous=initial,
            tool_id=contract.HTTP_TOOL_ID, execution_status="succeeded")
    with pytest.raises(ValueError):
        contract.validate_result_context(http, identity, tool_id=contract.TOOL_ID,
            execution_status="succeeded")
    with pytest.raises(ValueError):
        lab.validate_closure({**after, "status": "closed", "request_count": 0}, identity, previous=after)


@pytest.mark.parametrize("hardened", [False, True])
@pytest.mark.parametrize("case", contract.CASES)
def test_classification_uses_observed_controls_not_fixture_case(hardened, case):
    result = receipt(headers=normalized(hardened=hardened))
    observation = contract.parse_observation(contract.action(case, 2), result, execution_status="succeeded")
    assert observation["classification"] == ("no_gaps_observed" if hardened else "gaps_observed")
    assert observation["headers"] == normalized(hardened=hardened)
    assert observation["followup_path"] is None


@pytest.mark.parametrize("field,value", [("status_code", 302), ("content_type", "other"), ("content_type", "absent")])
def test_only_ok_html_is_eligible_for_header_observations(field, value):
    headers = normalized(hardened=True)
    headers[field] = value
    assert contract.classify_headers(headers)["classification"] == "inconclusive"


@pytest.mark.parametrize("field,value,classification", [
    ("x_frame_options", "sameorigin", "no_gaps_observed"),
    ("x_frame_options", "invalid", "gaps_observed"),
    ("x_content_type_options", "invalid", "gaps_observed"),
    ("csp", "absent", "gaps_observed"),
])
def test_controls_report_presence_and_recognized_values_without_strength_claim(field, value, classification):
    headers = normalized(hardened=True)
    headers[field] = value
    assert contract.classify_headers(headers)["classification"] == classification


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(extra=True),
    lambda value: value.pop("http_headers"),
    lambda value: value.pop("boundary_checks"),
    lambda value: value.update(results=[]),
    lambda value: value.update(bytes_received=True),
    lambda value: value.update(bytes_received=1),
    lambda value: value.update(truncated=0),
    lambda value: value.update(truncated=True),
    lambda value: value["boundary_checks"].update(forbidden_ip_blocked=False),
    lambda value: value["results"][0].update(extra=True),
    lambda value: value["results"][0].update(target="127.0.0.2"),
    lambda value: value["results"][0].update(port=True),
    lambda value: value["results"][0].update(bytes_received=2049),
    lambda value: value["results"][0].update(truncated=True),
    lambda value: value["results"][0].update(raw_response="!bad!"),
    lambda value: value["results"][0].update(raw_response="A" * 2733),
    lambda value: value["results"][0].update(response_sha256="0" * 64),
    lambda value: value["http_headers"].update(csp="excellent"),
])
def test_tampered_receipt_cannot_be_interpreted_or_replayed(mutation):
    result = receipt(headers=normalized())
    mutation(result)
    with pytest.raises(ValueError):
        contract.validate_http_result(result, execution_status="succeeded")
    assert contract.parse_observation(contract.action("vulnerable", 2), result,
                                      execution_status="succeeded")["classification"] == "inconclusive"


@pytest.mark.parametrize("status,raw", [("failed", b""), ("timeout", b"partial"),
                                       ("output_limit", b"x" * 2048)])
def test_failure_bytes_are_retained_verified_and_cannot_contain_findings(status, raw):
    result = receipt(raw, status=status)
    assert contract.validate_http_result(result, execution_status=status) == raw
    assert contract.parse_observation(contract.action("vulnerable", 2), result,
                                      execution_status=status)["classification"] == "inconclusive"
    forged = copy.deepcopy(result)
    forged["results"][0]["response_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        contract.validate_http_result(forged, execution_status=status)
    result["http_headers"] = normalized()
    with pytest.raises(ValueError):
        contract.validate_http_result(result, execution_status=status)


def test_transport_success_with_uninterpretable_response_stays_inconclusive():
    result = receipt(b"unsupported HTTP response")
    assert contract.validate_http_result(result, execution_status="succeeded")
    assert contract.parse_observation(contract.action("injected", 2), result,
                                      execution_status="succeeded")["reason"] == "http_response_not_interpretable"


def test_empty_capture_cannot_be_relabelled_as_transport_success():
    result = receipt(b"", status="succeeded")
    with pytest.raises(ValueError, match="invalid_http_headers_result_metadata"):
        contract.validate_http_result(result, execution_status="succeeded")
    assert contract.parse_observation(contract.action("vulnerable", 2), result,
                                      execution_status="succeeded")["classification"] == "inconclusive"
