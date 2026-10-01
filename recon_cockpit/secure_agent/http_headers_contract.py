"""Reviewed Nmap-to-HTTP headers profile for a separate owned HTML fixture.

Observed header gaps are hardening observations, not proof of exploitability.
Neither HTML nor header values grant authority or become workflow instructions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from uuid import NAMESPACE_URL, uuid5

from . import nmap_contract
from .assessment_contract import _ACTION_FIELDS, _BOUNDARY_FIELDS
from .models import parse_action
from .tool_adapters import (
    HTTP_HEADERS_TOOL_ID, HTTP_HEADERS_PARAMETERS, NMAP_SESSION_LIMITS, get_adapter,
)
from .http_headers_lab_contract import (
    BACKEND, CASES, FIXTURE_MARKER, PORTAL_PATH,
    validate_closure, validate_context, validate_identity,
)


TOOL_ID = nmap_contract.TOOL_ID
HTTP_TOOL_ID = HTTP_HEADERS_TOOL_ID
PROFILE = "owned_http_headers_lab"
WORKFLOW = "owned-http-headers-assessment-v1"
PARSER_VERSION = nmap_contract.PARSER_VERSION
HTTP_PARSER_VERSION = "http-headers-v1"
PARAMETERS = dict(nmap_contract.PARAMETERS)
HTTP_PARAMETERS = dict(HTTP_HEADERS_PARAMETERS)
LIMITS = dict(NMAP_SESSION_LIMITS)
encode = nmap_contract.encode


def action(case, step):
    if type(case) is not str or case not in CASES or type(step) is not int or step not in (1, 2):
        raise ValueError("invalid_http_headers_workflow_step")
    return parse_action({
        "schema_version": "1", "action_id": str(uuid5(NAMESPACE_URL, WORKFLOW + ":" + case + ":" + str(step))),
        "tool_id": TOOL_ID if step == 1 else HTTP_TOOL_ID, "target": "127.0.0.1",
        "parameters": dict(PARAMETERS if step == 1 else HTTP_PARAMETERS),
        "rationale": "DETERMINISTIC OWNED HTTP HEADERS LAB: observe the scoped synthetic HTML response.",
    }).to_dict()


def profile_allows(value, case):
    if type(case) is not str or case not in CASES or value.target != "127.0.0.1":
        return False
    if value.tool_id == TOOL_ID:
        return value.parameters.to_dict() == PARAMETERS
    return value.tool_id == HTTP_TOOL_ID and value.parameters.to_dict() == HTTP_PARAMETERS


def capability_descriptor():
    return {
        "schema_version": "1", "workflow_id": WORKFLOW,
        "capabilities": [get_adapter(tool).to_dict() for tool in (TOOL_ID, HTTP_TOOL_ID)],
        "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
        "limits": dict(LIMITS), "live_calls_enabled": False,
        "http_parser_version": HTTP_PARSER_VERSION, "http_paths": [PORTAL_PATH],
        "scenario": "synthetic_http_header_hardening_observations",
    }


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    """Connections remain lower bounds; one HTTP execution makes one request."""
    expected = validate_identity(expected)
    if type(result) is not dict or result.get("backend") != BACKEND:
        raise ValueError("invalid_http_headers_lab_result")
    context = validate_context(result.get("owned_lab"), expected)
    before = {"connection_count": 0, "request_count": 0} if previous is None else validate_context(previous, expected)
    connections = context["connection_count"] - before["connection_count"]
    requests = context["request_count"] - before["request_count"]
    if connections < 0 or requests < 0 or tool_id not in {TOOL_ID, HTTP_TOOL_ID}:
        raise ValueError("http_headers_lab_continuity_mismatch")
    if tool_id == TOOL_ID and requests != 0:
        raise ValueError("nmap_sent_application_request")
    if tool_id == HTTP_TOOL_ID and (requests > 1 or (execution_status == "succeeded" and requests != 1)):
        raise ValueError("http_headers_request_continuity_mismatch")
    return context


def _observation(classification, reason, headers=None):
    return {"parser_version": HTTP_PARSER_VERSION, "kind": "http_headers",
            "classification": classification, "reason": reason,
            "followup_path": None, "headers": headers}


def classify_headers(headers):
    """Interpret only reviewed normalized enums, never policy strength or HTML."""
    from .http_headers_parser import validate_result

    headers = validate_result(headers)
    if headers["status_code"] != 200 or headers["content_type"] != "text/html":
        return _observation("inconclusive", "unexpected_http_response", headers)
    gaps = (headers["csp"] != "present"
            or headers["x_frame_options"] not in ("deny", "sameorigin")
            or headers["x_content_type_options"] != "nosniff")
    return _observation("gaps_observed" if gaps else "no_gaps_observed",
                        "http_hardening_gaps_observed" if gaps else "http_hardening_headers_present",
                        headers)


def validate_http_result(result, *, execution_status):
    """Return bounded retained bytes after strict receipt metadata validation.

    Every native outcome retains one row, including an empty capture on an
    early failure. Raw HTTP parsing remains a separate confined operation.
    """
    from .http_headers_parser import validate_result

    if type(result) is dict:
        result = {key: item for key, item in result.items() if key not in {"owned_lab", "backend"}}
    fields = {"status", "results", "bytes_received", "truncated", "http_headers", "boundary_checks"}
    statuses = ("succeeded", "failed", "timeout", "output_limit")
    if (type(result) is not dict or set(result) != fields
            or type(execution_status) is not str or execution_status not in statuses
            or result["status"] != execution_status
            or type(result["results"]) is not list or len(result["results"]) != 1
            or type(result["results"][0]) is not dict):
        raise ValueError("invalid_http_headers_result")
    row = result["results"][0]
    if set(row) != {"target", "port", "bytes_received", "truncated", "raw_response", "response_sha256"}:
        raise ValueError("invalid_http_headers_result_metadata")
    if (row["target"] != "127.0.0.1" or type(row["port"]) is not int or row["port"] != 8080
            or type(result["bytes_received"]) is not int or type(row["bytes_received"]) is not int
            or not 0 <= row["bytes_received"] <= HTTP_PARAMETERS["max_output_bytes"]
            or (execution_status == "succeeded" and row["bytes_received"] == 0)
            or result["bytes_received"] != row["bytes_received"]
            or type(result["truncated"]) is not bool or type(row["truncated"]) is not bool
            or result["truncated"] != row["truncated"]
            or result["truncated"] != (execution_status == "output_limit")
            or (result["truncated"] and row["bytes_received"] != HTTP_PARAMETERS["max_output_bytes"])
            or type(row["raw_response"]) is not str or len(row["raw_response"]) > 2732
            or type(row["response_sha256"]) is not str):
        raise ValueError("invalid_http_headers_result_metadata")
    checks = result["boundary_checks"]
    if (type(checks) is not dict or set(checks) != _BOUNDARY_FIELDS
            or any(item is not True for item in checks.values())):
        raise ValueError("invalid_http_headers_boundary_checks")
    try:
        raw = base64.b64decode(row["raw_response"], validate=True)
        if (base64.b64encode(raw).decode("ascii") != row["raw_response"]
                or len(raw) != row["bytes_received"]
                or hashlib.sha256(raw).hexdigest() != row["response_sha256"]):
            raise ValueError("invalid_raw_response")
    except (ValueError, TypeError, binascii.Error):
        raise ValueError("invalid_http_headers_raw_response") from None
    if result["http_headers"] is not None:
        if execution_status != "succeeded" or result["truncated"] or not raw:
            raise ValueError("failed_http_headers_have_findings")
        validate_result(result["http_headers"])
    return raw


def parse_observation(value, result, *, execution_status):
    """Interpret already isolated normalized fields, never raw HTTP or HTML.

    The evidence store separately replays retained bytes in a confined parser.
    """
    if type(value) is dict and value.get("tool_id") == TOOL_ID:
        return nmap_contract.parse_observation(value, result, execution_status=execution_status)
    try:
        if type(value) is not dict or set(value) not in (_ACTION_FIELDS, _ACTION_FIELDS | {"rationale"}):
            raise ValueError("invalid_action")
        parsed = parse_action({**value, "rationale": value.get("rationale", "")})
        if (parsed.tool_id != HTTP_TOOL_ID or parsed.target != "127.0.0.1"
                or parsed.parameters.to_dict() != HTTP_PARAMETERS):
            raise ValueError("invalid_action")
    except (ValueError, TypeError, RecursionError, KeyError):
        return _observation("inconclusive", "invalid_action")
    try:
        validate_http_result(result, execution_status=execution_status)
    except (ValueError, TypeError, RecursionError):
        return _observation("inconclusive", "invalid_result_metadata")
    if execution_status != "succeeded":
        return _observation("inconclusive", "execution_not_succeeded")
    if result["http_headers"] is None:
        return _observation("inconclusive", "http_response_not_interpretable")
    return classify_headers(result["http_headers"])
