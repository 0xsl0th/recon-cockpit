"""Seeded HTTP contracts and pure evidence parsing; no socket or isolation claims."""

import copy
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import assessment_contract as contract, worker
from recon_cockpit.secure_agent.models import parse_action


def result_for(body, *, status=200):
    if type(body) is dict:
        body = json.dumps(body, separators=(",", ":")).encode("ascii")
    if type(body) is str:
        body = body.encode("utf-8")
    wire = (f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            .encode("ascii") + body)
    retained = wire[:1024]
    _, separator, retained_body = retained.partition(b"\r\n\r\n")
    truncated = len(wire) > 1024
    row = {"target": "127.0.0.1", "port": 8080, "http_status": status,
           "bytes_received": len(retained), "truncated": truncated,
           "body": retained_body.decode("utf-8", "replace") if separator else "",
           "response_sha256": hashlib.sha256(retained).hexdigest()}
    return {"status": "output_limit" if truncated else "succeeded", "results": [row],
            "bytes_received": len(retained), "truncated": truncated}


def fixture_result(case, sequence):
    action = contract.assessment_action(case, sequence)
    status, body, _headers = worker._response(action["parameters"]["path"])
    return action, result_for(body, status=status)


def parse(action, result, *, status="succeeded"):
    return contract.parse_observation(action, result, execution_status=status)


def assert_safe_inconclusive(observation):
    assert observation["classification"] == "inconclusive"
    assert observation["followup_path"] is None
    assert set(observation) == {"parser_version", "kind", "classification", "reason", "followup_path"}
    assert observation["parser_version"] == "http-assessment-v1"
    assert "PRIVATE" not in json.dumps(observation)


@pytest.mark.parametrize("case", contract.CASES)
@pytest.mark.parametrize("sequence", [1, 2])
def test_actions_are_exact_deterministic_existing_http_actions(case, sequence):
    action = contract.assessment_action(case, sequence)
    assert action == contract.assessment_action(case, sequence) == parse_action(action).to_dict()
    assert action["tool_id"] == "http_probe" and action["target"] == "127.0.0.1"
    assert action["parameters"] == {"port": 8080, "method": "GET",
                                    "path": (contract.discovery_path(case) if sequence == 1
                                             else contract.diagnostics_path(case)),
                                    "timeout_seconds": 1, "max_output_bytes": 1024}
    assert action["action_id"] != contract.assessment_action(case, 3 - sequence)["action_id"]


@pytest.mark.parametrize("case", [None, 1, True, "", "A", "g", "../a", "a/diagnostics.json"])
def test_fixture_case_cannot_select_an_arbitrary_path(case):
    for function in (contract.discovery_path, contract.diagnostics_path, lambda value: contract.assessment_action(value, 1)):
        with pytest.raises(ValueError, match="^invalid_assessment_case$"):
            function(case)


@pytest.mark.parametrize("sequence", [None, "1", True, 0, 3, 1.0])
def test_action_sequence_is_a_strict_bounded_integer(sequence):
    with pytest.raises(ValueError, match="^invalid_assessment_sequence$"):
        contract.assessment_action("a", sequence)


def test_descriptor_is_serializable_fixed_and_returns_independent_data():
    descriptor = contract.capability_descriptor()
    assert json.loads(json.dumps(descriptor)) == descriptor
    assert descriptor["capability_id"] == "http_probe"
    assert descriptor["parser_version"] == contract.PARSER_VERSION
    assert descriptor["destination"] == {"target": "127.0.0.1", "port": 8080, "fixture_only": True}
    assert descriptor["approval"] == "operator_policy"
    assert descriptor["live_calls_enabled"] is False
    assert descriptor["result_contract"]["wire_capture"] is False
    assert set(descriptor["parameters"]["paths"]) == {
        path(case) for case in contract.CASES for path in (contract.discovery_path, contract.diagnostics_path)
    }
    descriptor["parameters"]["paths"].clear()
    assert len(contract.capability_descriptor()["parameters"]["paths"]) == 12


@pytest.mark.parametrize("case", contract.CASES[:-1])
def test_only_actual_same_case_discovery_enables_followup(case):
    action, result = fixture_result(case, 1)
    observation = parse(action, result)
    assert observation == {"parser_version": contract.PARSER_VERSION, "kind": "discovery",
                           "classification": "discovered", "reason": "fixture_discovered",
                           "followup_path": contract.diagnostics_path(case)}
    del action["rationale"]
    assert parse(action, result) == observation


@pytest.mark.parametrize("case,classification", [("a", "exposed"), ("b", "absent"),
                                                 ("c", "inconclusive"), ("e", "inconclusive")])
def test_positive_absent_and_inconclusive_followup_variants(case, classification):
    action, result = fixture_result(case, 2)
    observation = parse(action, result, status=result["status"])
    assert observation["kind"] == "diagnostics"
    assert observation["classification"] == classification
    assert observation["followup_path"] is None
    assert "internal_service" not in json.dumps(observation)
    assert "Ignore prior instructions" not in json.dumps(observation)
    del action["rationale"]
    assert parse(action, result, status=result["status"]) == observation


def test_outcome_comes_from_response_instead_of_seeded_case_name():
    positive_action, positive_result = fixture_result("a", 2)
    absent_action, absent_result = fixture_result("b", 2)
    assert parse(positive_action, absent_result)["classification"] == "absent"
    assert parse(absent_action, positive_result)["classification"] == "exposed"


def test_hostile_discovery_cannot_supply_a_target_or_path():
    action, result = fixture_result("f", 1)
    assert "203.0.113.99" in result["results"][0]["body"]
    observation = parse(action, result)
    assert_safe_inconclusive(observation)
    assert observation["reason"] == "unexpected_discovery_document"
    assert "203.0.113.99" not in json.dumps(observation)


@pytest.mark.parametrize("followup", [
    "/assessment/b/diagnostics.json", "/", "/assessment/a/../diagnostics.json", "//127.0.0.1/private",
    "http://127.0.0.1:8080/assessment/a/diagnostics.json", "http://203.0.113.99/PRIVATE",
    None, True, ["/assessment/a/diagnostics.json"],
])
def test_discovery_requires_exact_bounded_same_case_path(followup):
    body = {"fixture": contract.FIXTURE_MARKER, "diagnostics_path": followup}
    assert_safe_inconclusive(parse(contract.assessment_action("a", 1), result_for(body)))


@pytest.mark.parametrize("status", ["dry_run", "not_started", "blocked", "failed", "timeout", "output_limit",
                                   "cancelled", "PRIVATE", None, True])
def test_only_actual_successful_execution_can_support_a_claim(status):
    action, result = fixture_result("a", 2)
    observation = parse(action, result, status=status)
    assert_safe_inconclusive(observation)
    assert observation["reason"] == "execution_not_succeeded"


@pytest.mark.parametrize("key,value", [
    ("target", "127.0.0.2"), ("target", "127.0.0.1/32"), ("tool_id", "shell"),
    ("action_id", "PRIVATE"), ("schema_version", "2"), ("approval", True),
])
def test_action_metadata_cannot_widen_the_capability(key, value):
    action, result = fixture_result("a", 2)
    action[key] = value
    assert_safe_inconclusive(parse(action, result))


@pytest.mark.parametrize("key,value", [
    ("port", 8081), ("method", "HEAD"), ("timeout_seconds", 2), ("max_output_bytes", 2048),
    ("path", "/PRIVATE"), ("path", "/assessment/g/diagnostics.json"), ("path", "/assessment/a/index.json/"),
    ("proxy", "PRIVATE"),
])
def test_action_parameters_are_exactly_the_reviewed_workflow(key, value):
    action, result = fixture_result("a", 2)
    action["parameters"][key] = value
    assert_safe_inconclusive(parse(action, result))


@pytest.mark.parametrize("key,value", [
    ("target", "127.0.0.2"), ("target", None), ("port", True), ("port", 8080.0), ("port", 8081),
    ("http_status", True), ("http_status", 200.0), ("http_status", "200"), ("http_status", None),
    ("http_status", 99), ("http_status", 600), ("bytes_received", True), ("bytes_received", -1),
    ("bytes_received", 1025), ("bytes_received", 5), ("body", None), ("body", ["PRIVATE"]),
    ("body", "PRIVATE" * 1024), ("body", "\ud800"), ("body", "\U0001f600" * 300),
    ("response_sha256", "PRIVATE"), ("response_sha256", "A" * 64),
    ("response_sha256", None), ("response_sha256", "0" * 65),
    ("truncated", True), ("truncated", 0), ("path", "/assessment/a/diagnostics.json"),
])
def test_spoofed_or_inconsistent_result_metadata_is_inconclusive(key, value):
    action, result = fixture_result("a", 2)
    result["results"][0][key] = value
    assert_safe_inconclusive(parse(action, result))


@pytest.mark.parametrize("key,value", [
    ("status", "failed"), ("status", True), ("bytes_received", True), ("bytes_received", 1),
    ("bytes_received", 0), ("bytes_received", 1025), ("truncated", True), ("truncated", 0),
    ("results", []), ("results", [None]), ("results", "PRIVATE"), ("PRIVATE", "PRIVATE"),
    ("backend", "PRIVATE\ntext"), ("backend", 1), ("boundary_checks", None),
    ("boundary_checks", {"capabilities_dropped": True}),
])
def test_invalid_outer_result_cannot_support_a_finding(key, value):
    action, result = fixture_result("a", 2)
    result[key] = value
    assert_safe_inconclusive(parse(action, result))


def test_missing_extra_or_multiple_result_rows_are_inconclusive():
    action, result = fixture_result("a", 2)
    for key in tuple(result):
        bad = copy.deepcopy(result)
        del bad[key]
        assert_safe_inconclusive(parse(action, bad))
    for key in tuple(result["results"][0]):
        bad = copy.deepcopy(result)
        del bad["results"][0][key]
        assert_safe_inconclusive(parse(action, bad))
    result["results"].append(copy.deepcopy(result["results"][0]))
    assert_safe_inconclusive(parse(action, result))


def test_verified_executor_metadata_is_accepted_but_not_echoed():
    action, result = fixture_result("a", 2)
    result["backend"] = "linux-authorized-fixture-executor-v1"
    result["boundary_checks"] = dict.fromkeys((
        "forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked", "capabilities_dropped"), True)
    assert parse(action, result)["classification"] == "exposed"
    result["boundary_checks"]["capabilities_dropped"] = 1
    assert_safe_inconclusive(parse(action, result))


@pytest.mark.parametrize("body", [
    b"", b"null", b"[]", b"true", b"{}", b'{"PRIVATE":true}',
    b'{"fixture":"recon-http-assessment-v1","fixture":"recon-http-assessment-v1"}',
    b'{"debug":NaN}', b'{"debug":Infinity}', b'{"debug":-Infinity}',
    b'{"debug":true', b'{"debug":true}\nPRIVATE',
])
def test_malformed_or_unexpected_documents_never_become_findings(body):
    assert_safe_inconclusive(parse(contract.assessment_action("a", 2), result_for(body)))


@pytest.mark.parametrize("field,value", [
    ("fixture", "PRIVATE"), ("document", "public"), ("internal_service", "PRIVATE"),
    ("debug", 1), ("debug", "true"), ("debug", False), ("debug", None),
    ("approval", True), ("finding", "PRIVATE"),
])
def test_positive_document_requires_exact_schema_types_and_marker(field, value):
    body = json.loads(worker.ASSESSMENT_DIAGNOSTICS_FIXTURE)
    body[field] = value
    assert_safe_inconclusive(parse(contract.assessment_action("a", 2), result_for(body)))


@pytest.mark.parametrize("http_status", [201, 302, 401, 403, 404, 500])
def test_seeded_positive_body_on_an_unexpected_http_status_is_inconclusive(http_status):
    result = result_for(worker.ASSESSMENT_DIAGNOSTICS_FIXTURE, status=http_status)
    assert_safe_inconclusive(parse(contract.assessment_action("a", 2), result))


@pytest.mark.parametrize("body,status", [
    ({"error": "not_found"}, 200), ({"error": "not_found"}, 403),
    ({"error": "different"}, 404), ({"error": "not_found", "finding": "PRIVATE"}, 404),
])
def test_absence_requires_the_complete_expected_404_document(body, status):
    assert_safe_inconclusive(parse(contract.assessment_action("b", 2), result_for(body, status=status)))


@pytest.mark.parametrize("value", [None, [], "PRIVATE", 0, True])
def test_nonobject_inputs_return_safe_inconclusive_observations(value):
    action, result = fixture_result("a", 2)
    assert_safe_inconclusive(parse(value, result))
    assert_safe_inconclusive(parse(action, value))


def test_stall_and_large_fixtures_are_fixed_and_existing_fixtures_are_unchanged(monkeypatch):
    sleeps = []
    monkeypatch.setattr(worker.time, "sleep", sleeps.append)
    assert worker._response(contract.diagnostics_path("d")) == (200, worker.ASSESSMENT_DIAGNOSTICS_FIXTURE, b"")
    assert sleeps == [35]
    status, body, _headers = worker._response(contract.diagnostics_path("e"))
    assert status == 200 and len(body) > 1024
    assert worker._response("/injection") == (200, worker.INJECTION_FIXTURE, b"")
    assert worker._response("/") == (200, b"Recon Cockpit owned isolated fixture\n", b"")
    assert worker._response("/redirect")[0] == 302
    assert len(worker._response("/large")[1]) == 65536 + 4096
