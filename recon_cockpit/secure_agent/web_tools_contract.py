"""Fixed single-action curl/ffuf contracts; observations confer no authority."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from uuid import NAMESPACE_URL, uuid5

from .assessment_contract import _ACTION_FIELDS
from .models import Action, parse_action
from .tool_adapters import (CURL_TOOL_ID, FFUF_TOOL_ID, CURL_PARAMETERS, FFUF_PARAMETERS,
                            WEB_TOOLS_LIMITS, get_adapter)
from .web_tools_lab_contract import (BACKEND, CASES, validate_closure, validate_context,
                                     validate_identity)
from .web_tools_fixture import PORTAL_PATH, TLS_NAME, WORDS, PATH_WORDLIST_BYTES, tool_for_case


TOOL_ID = CURL_TOOL_ID
PROFILE = "owned_web_tools_lab"
WORKFLOW = "owned-web-tool-assessment-v1"
LIMITS = dict(WEB_TOOLS_LIMITS)
PARAMETERS = {CURL_TOOL_ID: dict(CURL_PARAMETERS), FFUF_TOOL_ID: dict(FFUF_PARAMETERS)}
PARSER_VERSIONS = {CURL_TOOL_ID: "curl-https-http-v1", FFUF_TOOL_ID: "ffuf-content-json-v1"}
BOUNDARY_FIELDS = frozenset({"forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked",
    "capabilities_dropped", "no_new_privs", "root_read_only", "process_creation_blocked",
    "raw_sockets_blocked", "landlock_applied", "python_unreadable"})


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def parser_version(tool_id):
    if type(tool_id) is not str or tool_id not in PARSER_VERSIONS:
        raise ValueError("unsupported_web_tool")
    return PARSER_VERSIONS[tool_id]


def action(case, step=1):
    if type(step) is not int or step != 1:
        raise ValueError("invalid_web_tools_step")
    tool_id = tool_for_case(case)
    return parse_action({"schema_version": "1", "action_id": str(uuid5(NAMESPACE_URL, WORKFLOW + ":" + case)),
        "tool_id": tool_id, "target": "127.0.0.1", "parameters": dict(PARAMETERS[tool_id]),
        "rationale": "DETERMINISTIC OWNED WEB TOOL: execute one fixed scoped tool profile."}).to_dict()


def profile_allows(value, case):
    return (type(value) is Action and type(case) is str and case in CASES
            and value.target == "127.0.0.1" and value.tool_id == tool_for_case(case)
            and value.parameters.to_dict() == PARAMETERS[value.tool_id])


def capability_descriptor():
    return {"schema_version": "1", "workflow_id": WORKFLOW,
        "capabilities": [get_adapter(tool).to_dict() for tool in (CURL_TOOL_ID, FFUF_TOOL_ID)],
        "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
        "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
        "tls_name": TLS_NAME, "curl_path": PORTAL_PATH, "ffuf_paths": ["/harbordesk/" + word for word in WORDS],
        "wordlist_sha256": hashlib.sha256(PATH_WORDLIST_BYTES).hexdigest(), "parser_versions": dict(PARSER_VERSIONS)}


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    expected = validate_identity(expected)
    if (type(result) is not dict or result.get("backend") != BACKEND
            or tool_id != tool_for_case(expected["scenario"])):
        raise ValueError("invalid_web_tools_lab_result")
    context = validate_context(result.get("owned_lab"), expected)
    before = {"connection_count": 0, "request_count": 0} if previous is None else validate_context(previous, expected)
    connections = context["connection_count"] - before["connection_count"]
    requests = context["request_count"] - before["request_count"]
    maximum = 1 if tool_id == CURL_TOOL_ID else len(WORDS)
    if (connections < 0 or not 0 <= requests <= maximum
            or (execution_status == "succeeded" and tool_id == CURL_TOOL_ID and requests != 1)
            or (expected["scenario"] == "curl-untrusted" and requests != 0)
            or (execution_status == "succeeded" and result.get("tool_observation") is not None and requests != maximum)):
        raise ValueError("web_tools_request_continuity_mismatch")
    return context


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_tool_result(result, *, tool_id, execution_status, runtime_sha256=None):
    """Check bounded capture/provenance; replay parsing is a separate boundary."""
    version = parser_version(tool_id)
    core = {k: v for k, v in result.items() if k not in {"backend", "owned_lab"}} if type(result) is dict else result
    if (type(core) is not dict or set(core) != {"status", "results", "raw_output_base64", "raw_stderr_base64",
            "bytes_received", "truncated", "provenance", "boundary_checks", "tool_observation"}
            or type(execution_status) is not str or execution_status not in {"succeeded", "failed", "timeout", "output_limit"}
            or core["status"] != execution_status or core["results"] != []
            or type(core["results"]) is not list or type(core["bytes_received"]) is not int
            or not 0 <= core["bytes_received"] <= PARAMETERS[tool_id]["max_output_bytes"]
            or type(core["truncated"]) is not bool or core["truncated"] != (execution_status == "output_limit")
            or (core["truncated"] and core["bytes_received"] != PARAMETERS[tool_id]["max_output_bytes"])):
        raise ValueError("invalid_web_tool_result")
    checks = core["boundary_checks"]
    if type(checks) is not dict or set(checks) != BOUNDARY_FIELDS or any(v is not True for v in checks.values()):
        raise ValueError("invalid_web_tool_boundary_checks")
    decoded = []
    try:
        for field in ("raw_output_base64", "raw_stderr_base64"):
            encoded = core[field]
            if type(encoded) is not str or len(encoded) > 10924:
                raise ValueError("invalid_web_tool_capture")
            raw = base64.b64decode(encoded, validate=True)
            if base64.b64encode(raw).decode("ascii") != encoded:
                raise ValueError("invalid_web_tool_capture")
            decoded.append(raw)
    except (ValueError, TypeError):
        raise ValueError("invalid_web_tool_capture") from None
    output, stderr = decoded
    if len(output) + len(stderr) != core["bytes_received"]:
        raise ValueError("invalid_web_tool_capture_size")
    provenance = core["provenance"]
    if (type(provenance) is not dict or set(provenance) != {"runtime_sha256", "runtime_manifest", "output_sha256",
            "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
            or not _digest(provenance["runtime_sha256"])
            or (runtime_sha256 is not None and provenance["runtime_sha256"] != runtime_sha256)
            or provenance["output_sha256"] != hashlib.sha256(output).hexdigest()
            or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
            or provenance["parser_version"] != version or type(provenance["exit_code"]) is not int
            or not -255 <= provenance["exit_code"] <= 255
            or provenance["stop_reason"] not in (None, "timeout", "output_limit")
            or (execution_status == "succeeded" and (provenance["exit_code"] != 0 or provenance["stop_reason"] is not None))
            or (execution_status == "failed" and (provenance["exit_code"] == 0 or provenance["stop_reason"] is not None))
            or (execution_status in {"timeout", "output_limit"} and provenance["stop_reason"] != execution_status)):
        raise ValueError("invalid_web_tool_provenance")
    from .web_tools_runtime import manifest_digest
    manifest = provenance["runtime_manifest"]
    if manifest_digest(manifest) != provenance["runtime_sha256"] or manifest.get("tool_id") != tool_id:
        raise ValueError("invalid_web_tool_runtime")
    if core["tool_observation"] is not None:
        if execution_status != "succeeded" or core["truncated"] or not output:
            raise ValueError("failed_web_tool_has_observation")
        from .web_tools_parser import validate_result
        validate_result(tool_id, core["tool_observation"])
    return output, stderr


def _observation(tool_id, classification, reason, details=None):
    return {"parser_version": parser_version(tool_id), "kind": "web_tool", "tool_id": tool_id,
            "classification": classification, "reason": reason, "followup_path": None, "details": details}


def classify_tool(tool_id, normalized):
    from .web_tools_parser import validate_result
    normalized = validate_result(tool_id, normalized)
    if tool_id == CURL_TOOL_ID:
        headers = normalized["headers"]
        valid = headers["status_code"] == 200 and headers["content_type"] == "text/html"
        return _observation(tool_id, "response_observed" if valid else "inconclusive",
            "https_response_observed" if valid else "unexpected_https_response", normalized)
    if normalized["baseline"] != "not_found":
        return _observation(tool_id, "inconclusive", "wildcard_or_unexpected_baseline", normalized)
    found = any(200 <= row["status_code"] <= 299 for row in normalized["responses"][:-1])
    return _observation(tool_id, "paths_observed" if found else "no_successful_paths_observed",
        "content_paths_observed" if found else "no_successful_content_paths_observed", normalized)


def parse_observation(value, result, *, execution_status):
    tool_id = value.get("tool_id") if type(value) is dict else None
    if type(tool_id) is not str or tool_id not in PARSER_VERSIONS:
        raise ValueError("invalid_web_tool_action")
    try:
        if set(value) not in (_ACTION_FIELDS, _ACTION_FIELDS | {"rationale"}):
            raise ValueError("invalid_action")
        parsed = parse_action({**value, "rationale": value.get("rationale", "")})
        if parsed.target != "127.0.0.1" or parsed.parameters.to_dict() != PARAMETERS[tool_id]:
            raise ValueError("invalid_action")
    except (ValueError, TypeError, KeyError, RecursionError):
        return _observation(tool_id, "inconclusive", "invalid_action")
    try:
        validate_tool_result(result, tool_id=tool_id, execution_status=execution_status)
    except (ValueError, TypeError, KeyError, RecursionError):
        return _observation(tool_id, "inconclusive", "invalid_result_metadata")
    if execution_status != "succeeded":
        return _observation(tool_id, "inconclusive", "execution_not_succeeded")
    if result["tool_observation"] is None:
        return _observation(tool_id, "inconclusive", "tool_output_not_interpretable")
    return classify_tool(tool_id, result["tool_observation"])
