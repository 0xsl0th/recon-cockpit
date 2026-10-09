"""Fixed tool authority, request continuity, and independently replayable bytes."""

import base64
import copy
import hashlib
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import web_tools_contract as contract
from recon_cockpit.secure_agent import web_tools_parser as parser
from recon_cockpit.secure_agent import web_tools_runtime as runtime
from recon_cockpit.secure_agent.models import CurlHTTPSParameters, FFufParameters, ValidationError, parse_action, parse_policy
from recon_cockpit.secure_agent.tool_adapters import LEGACY_PROPOSAL_PROFILE, NMAP_PROPOSAL_PROFILE, proposal_tools
from recon_cockpit.secure_agent.web_tools_fixture import CA_PEM, WORDS, PATH_WORDLIST_BYTES, PORTAL_PATH, wire_response
from recon_cockpit.secure_agent.web_tools_lab_contract import identity
from test_secure_web_tools_parser import ffuf_output, ffuf_rows


def manifest(tool_id):
    source, destination, compiled = runtime._compiled(tool_id)
    interpreter = "/lib64/ld-linux-x86-64.so.2"
    files = [{"source": source, "destination": destination, "size": len(compiled),
              "sha256": hashlib.sha256(compiled).hexdigest()},
             {"source": runtime.EXECUTABLES[tool_id], "destination": runtime.FIXED_ARGV[tool_id][0],
              "size": 1, "sha256": "a" * 64},
             {"source": interpreter, "destination": interpreter, "size": 1, "sha256": "b" * 64}]
    return runtime.validate_manifest({"version": "1", "profile": runtime.PROFILE, "tool_id": tool_id,
        "executable": runtime.FIXED_ARGV[tool_id][0], "interpreter": interpreter,
        "files": sorted(files, key=lambda item: item["destination"])})


def receipt(tool_id=contract.CURL_TOOL_ID, *, status="succeeded", raw=None, stderr=b""):
    if raw is None:
        raw = wire_response("curl-ok", PORTAL_PATH) if tool_id == contract.CURL_TOOL_ID else ffuf_output()
    normalized = parser.parse_tool_output(tool_id, raw) if status == "succeeded" and raw else None
    pinned = manifest(tool_id)
    return {"status": status, "results": [], "tool_observation": normalized,
        "raw_output_base64": base64.b64encode(raw).decode(), "raw_stderr_base64": base64.b64encode(stderr).decode(),
        "bytes_received": len(raw) + len(stderr), "truncated": status == "output_limit",
        "boundary_checks": dict.fromkeys(contract.BOUNDARY_FIELDS, True),
        "provenance": {"runtime_sha256": runtime.manifest_digest(pinned), "runtime_manifest": pinned,
            "output_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "parser_version": contract.parser_version(tool_id), "exit_code": 0 if status == "succeeded" else -9,
            "stop_reason": status if status in {"timeout", "output_limit"} else None}}


def policy(**changes):
    return parse_policy({"schema_version": "1", "policy_version": "web-tools-test-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": [contract.CURL_TOOL_ID, contract.FFUF_TOOL_ID],
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 10,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": True,
        "approval_ttl_seconds": 60, **changes})


@pytest.mark.parametrize("case", contract.CASES)
def test_case_selects_exact_typed_single_action_and_existing_policy_gates(case):
    action = parse_action(contract.action(case))
    expected = contract.CURL_TOOL_ID if case.startswith("curl-") else contract.FFUF_TOOL_ID
    assert action.tool_id == expected and action.target == "127.0.0.1"
    assert type(action.parameters) is (CurlHTTPSParameters if expected == contract.CURL_TOOL_ID else FFufParameters)
    assert contract.profile_allows(action, case)
    assert policy().evaluate(action).decision == "approval_required"
    assert policy(allowed_methods=[]).evaluate(action).reasons == ("method_not_allowed",)
    assert contract.LIMITS == {"max_steps": 1, "max_runtime_seconds": 60, "max_output_bytes": 8192}
    with pytest.raises(ValueError):
        contract.action(case, 2)


def test_shared_static_contracts_agree_and_model_profiles_stay_unchanged():
    assert contract.PARSER_VERSIONS == parser.PARSER_VERSIONS
    assert WORDS == parser.WORDS
    assert PATH_WORDLIST_BYTES == ("\n".join(WORDS) + "\n").encode()
    assert proposal_tools(LEGACY_PROPOSAL_PROFILE) == ("http_probe", "tcp_connect")
    assert proposal_tools(NMAP_PROPOSAL_PROFILE) == ("nmap_tcp_connect_v1", "http_probe")
    assert contract.capability_descriptor()["live_calls_enabled"] is False


@pytest.mark.parametrize("case", ["curl-ok", "ffuf-normal"])
@pytest.mark.parametrize("key,value", [("port", 8081), ("timeout_seconds", 2), ("max_output_bytes", 2048)])
def test_syntactic_parameters_do_not_expand_reviewed_profile(case, key, value):
    action = contract.action(case)
    action["parameters"][key] = value
    assert not contract.profile_allows(parse_action(action), case)


@pytest.mark.parametrize("case", ["curl-ok", "ffuf-normal"])
@pytest.mark.parametrize("field", ["argv", "executable", "wordlist", "url", "headers", "credentials", "environment"])
def test_no_arbitrary_tool_input_fields(case, field):
    action = contract.action(case)
    action["parameters"][field] = "untrusted"
    with pytest.raises(ValidationError):
        parse_action(action)


@pytest.mark.parametrize("tool", [contract.CURL_TOOL_ID, contract.FFUF_TOOL_ID])
def test_valid_receipt_binds_raw_bytes_runtime_and_parser(tool):
    value = receipt(tool)
    output, stderr = contract.validate_tool_result(value, tool_id=tool, execution_status="succeeded",
        runtime_sha256=value["provenance"]["runtime_sha256"])
    assert stderr == b"" and parser.parse_tool_output(tool, output) == value["tool_observation"]
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=tool, execution_status="succeeded", runtime_sha256="0" * 64)


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(extra=True), lambda r: r.update(results=[{}]),
    lambda r: r.update(bytes_received=True), lambda r: r.update(bytes_received=8193),
    lambda r: r.update(truncated=0), lambda r: r.update(truncated=True),
    lambda r: r.update(raw_output_base64="!bad!"), lambda r: r.update(raw_stderr_base64="A" * 10925),
    lambda r: r["boundary_checks"].update(forbidden_ip_blocked=1),
    lambda r: r["provenance"].update(output_sha256="0" * 64),
    lambda r: r["provenance"].update(stderr_sha256="0" * 64),
    lambda r: r["provenance"].update(runtime_sha256="0" * 64),
    lambda r: r["provenance"].update(exit_code=True),
    lambda r: r["provenance"].update(exit_code=1),
    lambda r: r["provenance"].update(stop_reason="timeout"),
    lambda r: r["provenance"].update(parser_version="old"),
    lambda r: r["provenance"].update(runtime_manifest=manifest(contract.FFUF_TOOL_ID)),
    lambda r: r["tool_observation"]["headers"].update(status_code=True),
])
def test_receipt_tampering_never_produces_observations(mutation):
    value = receipt()
    mutation(value)
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=contract.CURL_TOOL_ID, execution_status="succeeded")
    assert contract.parse_observation(contract.action("curl-ok"), value,
        execution_status="succeeded")["classification"] == "inconclusive"


@pytest.mark.parametrize("status,raw", [("failed", b""), ("timeout", b"partial"), ("output_limit", b"x" * 8192)])
def test_native_failure_bytes_are_validated_but_never_interpreted(status, raw):
    value = receipt(status=status, raw=raw)
    assert contract.validate_tool_result(value, tool_id=contract.CURL_TOOL_ID, execution_status=status)[0] == raw
    assert contract.parse_observation(contract.action("curl-ok"), value,
        execution_status=status)["reason"] == "execution_not_succeeded"
    value["tool_observation"] = receipt()["tool_observation"]
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=contract.CURL_TOOL_ID, execution_status=status)


def test_successful_ffuf_exit_with_no_rows_cannot_claim_completed_discovery():
    value = receipt(contract.FFUF_TOOL_ID, raw=b"")
    assert contract.validate_tool_result(value, tool_id=contract.FFUF_TOOL_ID, execution_status="succeeded") == (b"", b"")
    assert contract.parse_observation(contract.action("ffuf-stalled"), value,
        execution_status="succeeded")["reason"] == "tool_output_not_interpretable"


@pytest.mark.parametrize("case,raw,classification,reason", [
    ("curl-ok", wire_response("curl-ok", PORTAL_PATH), "response_observed", "https_response_observed"),
    ("curl-redirect", wire_response("curl-redirect", PORTAL_PATH), "inconclusive", "unexpected_https_response"),
    ("ffuf-normal", ffuf_output(), "paths_observed", "content_paths_observed"),
    ("ffuf-wildcard", ffuf_output(ffuf_rows(wildcard=True)), "inconclusive", "wildcard_or_unexpected_baseline"),
])
def test_classification_follows_observed_bytes_and_control_response(case, raw, classification, reason):
    tool = contract.action(case)["tool_id"]
    observation = contract.classify_tool(tool, parser.parse_tool_output(tool, raw))
    assert observation["classification"] == classification and observation["reason"] == reason
    assert observation["followup_path"] is None


def test_only_authentication_or_access_denial_never_claims_paths_do_not_exist():
    rows = ffuf_rows()
    for index, row in enumerate(rows[:-1]):
        row["status"] = 401 if index % 2 else 403
    normalized = parser.parse_tool_output(contract.FFUF_TOOL_ID, ffuf_output(rows))
    observation = contract.classify_tool(contract.FFUF_TOOL_ID, normalized)
    assert observation["classification"] == "no_successful_paths_observed"
    assert observation["reason"] == "no_successful_content_paths_observed"
    assert {row["status_code"] for row in observation["details"]["responses"][:-1]} == {401, 403}


@pytest.mark.parametrize("case,requests,normalized", [("curl-ok", 1, True), ("curl-untrusted", 0, False),
    ("ffuf-normal", 8, True), ("ffuf-stalled", 3, False)])
def test_request_continuity_matches_tool_and_successful_coverage(case, requests, normalized):
    owned = identity(case, str(uuid4()))
    tool = contract.action(case)["tool_id"]
    result = {"backend": contract.BACKEND, "owned_lab": {"identity": owned,
        "connection_count": max(requests, 1), "request_count": requests}, "tool_observation": {} if normalized else None}
    status = "failed" if case == "curl-untrusted" else "succeeded"
    assert contract.validate_result_context(result, owned, tool_id=tool, execution_status=status)
    if normalized:
        result["owned_lab"]["request_count"] -= 1
        with pytest.raises(ValueError):
            contract.validate_result_context(result, owned, tool_id=tool, execution_status=status)


def test_untrusted_tls_receipt_cannot_claim_an_application_request():
    owned = identity("curl-untrusted", str(uuid4()))
    result = {"backend": contract.BACKEND, "owned_lab": {"identity": owned, "connection_count": 1, "request_count": 1}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, owned, tool_id=contract.CURL_TOOL_ID, execution_status="failed")
