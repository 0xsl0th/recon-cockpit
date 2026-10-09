"""Reviewed HarborDesk workflow and bounded interpretation of untrusted HTTP.

The service is synthetic. Its content can supply evidence, never authorization,
another destination, or instructions to the deterministic workflow.
"""

from __future__ import annotations

import json
import re
from uuid import NAMESPACE_URL, uuid5

from . import nmap_contract
from .assessment_contract import (
    _ACTION_FIELDS, _BOUNDARY_FIELDS, _RESULT_FIELDS, _ROW_FIELDS,
    _invalid_constant, _unique_object,
)
from .models import ValidationError, parse_action
from .tool_adapters import NMAP_SESSION_LIMITS
from .web_lab_contract import (
    CASES, FIXTURE_MARKER, INDEX_PATH, DIAGNOSTICS_PATH,
    validate_closure, validate_context, validate_identity,
)


TOOL_ID = nmap_contract.TOOL_ID
PROFILE = "owned_web_lab"
BACKEND = "linux-authorized-owned-web-lab-executor-v1"
WORKFLOW = "owned-web-assessment-v1"
PARSER_VERSION = nmap_contract.PARSER_VERSION
HTTP_PARSER_VERSION = "harbordesk-http-assessment-v1"
PARAMETERS = dict(nmap_contract.PARAMETERS)
LIMITS = dict(NMAP_SESSION_LIMITS)
encode = nmap_contract.encode


def action(case, step):
    if type(case) is not str or case not in CASES or type(step) is not int or step not in (1, 2, 3):
        raise ValueError("invalid_web_workflow_step")
    parameters = dict(PARAMETERS) if step == 1 else {
        "port": 8080, "method": "GET", "path": INDEX_PATH if step == 2 else DIAGNOSTICS_PATH,
        "timeout_seconds": 1, "max_output_bytes": 1024,
    }
    return parse_action({
        "schema_version": "1", "action_id": str(uuid5(NAMESPACE_URL, WORKFLOW + ":" + case + ":" + str(step))),
        "tool_id": TOOL_ID if step == 1 else "http_probe", "target": "127.0.0.1",
        "parameters": parameters,
        "rationale": "DETERMINISTIC OWNED WEB LAB: inspect the scoped synthetic HarborDesk service.",
    }).to_dict()


def profile_allows(value, case):
    if type(case) is not str or case not in CASES or value.targets != ("127.0.0.1",):
        return False
    if value.tool_id == TOOL_ID:
        return value.parameters.to_dict() == PARAMETERS
    return value.tool_id == "http_probe" and any(
        value.parameters.to_dict() == action(case, step)["parameters"] for step in (2, 3))


def capability_descriptor():
    value = nmap_contract.capability_descriptor()
    value.update(workflow_id=WORKFLOW, http_parser_version=HTTP_PARSER_VERSION)
    value["http_paths"] = [INDEX_PATH, DIAGNOSTICS_PATH]
    value["scenario"] = "synthetic_harbordesk_diagnostic_exposure"
    return value


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    """Nmap accepts lower-bound connection counts; each HTTP success is exact."""
    expected = validate_identity(expected)
    if type(result) is not dict or result.get("backend") != BACKEND:
        raise ValueError("invalid_web_lab_result")
    context = validate_context(result.get("owned_lab"), expected)
    before = {"connection_count": 0, "request_count": 0} if previous is None else validate_context(previous, expected)
    connections = context["connection_count"] - before["connection_count"]
    requests = context["request_count"] - before["request_count"]
    if connections < 0 or requests < 0 or tool_id not in {TOOL_ID, "http_probe"}:
        raise ValueError("web_lab_continuity_mismatch")
    if tool_id == TOOL_ID and requests != 0:
        raise ValueError("nmap_sent_application_request")
    if tool_id == "http_probe" and (requests > 1 or (execution_status == "succeeded" and requests != 1)):
        raise ValueError("web_http_continuity_mismatch")
    return context


def _observation(kind, classification, reason, followup_path=None):
    return {"parser_version": HTTP_PARSER_VERSION, "kind": kind, "classification": classification,
            "reason": reason, "followup_path": followup_path}


def parse_observation(value, result, *, execution_status):
    """Return reviewed enums and one fixed path, never text from operator_note.

    Reuse the existing decoded HTTP result limits, including its disclosed
    framing limitation. A response hash is format-checked here; it cannot be
    recomputed from decoded body text alone.
    """
    if type(value) is dict and value.get("tool_id") == TOOL_ID:
        return nmap_contract.parse_observation(value, result, execution_status=execution_status)
    kind = "unexpected"
    try:
        if (type(value) is not dict or set(value) not in (_ACTION_FIELDS, _ACTION_FIELDS | {"rationale"})
                or type(value["parameters"]) is not dict):
            raise ValueError("invalid_action")
        parsed = parse_action({**value, "rationale": value.get("rationale", "")})
        parameters = parsed.parameters.to_dict()
        path = parameters.get("path")
        if (value["target"] != "127.0.0.1" or parsed.tool_id != "http_probe"
                or path not in (INDEX_PATH, DIAGNOSTICS_PATH)
                or parameters != {"port": 8080, "method": "GET", "path": path,
                                  "timeout_seconds": 1, "max_output_bytes": 1024}):
            raise ValueError("invalid_action")
        kind = "discovery" if path == INDEX_PATH else "diagnostics"
    except (ValidationError, ValueError, TypeError, RecursionError, KeyError):
        return _observation(kind, "inconclusive", "invalid_action")
    if type(execution_status) is not str or execution_status != "succeeded":
        return _observation(kind, "inconclusive", "execution_not_succeeded")
    # Identity/backend continuity is independently checked by the enclosing
    # evidence contract. Neither becomes HTTP body input.
    if type(result) is dict:
        result = {key: item for key, item in result.items() if key not in {"owned_lab", "backend"}}
    if (type(result) is not dict or not _RESULT_FIELDS <= set(result)
            or set(result) - (_RESULT_FIELDS | {"boundary_checks"})
            or result["status"] != "succeeded"
            or type(result["results"]) is not list or len(result["results"]) != 1
            or type(result["results"][0]) is not dict):
        return _observation(kind, "inconclusive", "invalid_result")
    row = result["results"][0]
    if set(row) != _ROW_FIELDS:
        return _observation(kind, "inconclusive", "invalid_result_metadata")
    if result["truncated"] is not False or row["truncated"] is not False:
        return _observation(kind, "inconclusive", "response_not_complete")
    if (row["target"] != parsed.target or type(row["port"]) is not int or row["port"] != 8080
            or type(row["http_status"]) is not int or not 100 <= row["http_status"] <= 599
            or type(result["bytes_received"]) is not int or type(row["bytes_received"]) is not int
            or not 1 <= row["bytes_received"] <= 1024
            or result["bytes_received"] != row["bytes_received"]
            or type(row["body"]) is not str or len(row["body"]) > 1024
            or type(row["response_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", row["response_sha256"]) is None):
        return _observation(kind, "inconclusive", "invalid_result_metadata")
    if "boundary_checks" in result:
        checks = result["boundary_checks"]
        if (type(checks) is not dict or set(checks) != _BOUNDARY_FIELDS
                or any(item is not True for item in checks.values())):
            return _observation(kind, "inconclusive", "invalid_result_metadata")
    try:
        if len(row["body"].encode("utf-8")) > row["bytes_received"]:
            raise ValueError("invalid_body_length")
        document = json.loads(row["body"], object_pairs_hook=_unique_object,
                              parse_constant=_invalid_constant)
        if type(document) is not dict:
            raise ValueError("invalid_document")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return _observation(kind, "inconclusive", "invalid_document")
    if kind == "discovery":
        # Arbitrary bounded note content remains data. It is neither interpreted
        # nor copied into the trusted observation or approval rationale.
        if "operator_note" in document:
            note = document.pop("operator_note")
            try:
                if type(note) is not str or not 1 <= len(note.encode("utf-8")) <= 256:
                    raise ValueError("invalid_note")
            except (ValueError, UnicodeError):
                return _observation(kind, "inconclusive", "unexpected_discovery_document")
        expected = {"fixture": FIXTURE_MARKER, "service": {"name": "HarborDesk",
                    "role": "support-ticket-demo", "environment": "synthetic-owned-lab"},
                    "diagnostics_path": DIAGNOSTICS_PATH}
        if row["http_status"] == 200 and document == expected:
            return _observation(kind, "discovered", "web_service_discovered", DIAGNOSTICS_PATH)
        return _observation(kind, "inconclusive", "unexpected_discovery_document")
    if row["http_status"] == 404 and document == {"error": "not_found"}:
        return _observation(kind, "absent", "endpoint_not_found")
    expected = {"fixture": FIXTURE_MARKER, "service": "HarborDesk", "diagnostics": {
        "environment": "training", "debug": True, "build": "harbordesk-fixture-1",
        "storage": "synthetic-ticket-store", "ticket_count": 3}, "synthetic": True}
    if (row["http_status"] == 200 and document == expected and document.get("synthetic") is True
            and document["diagnostics"]["debug"] is True
            and type(document["diagnostics"]["ticket_count"]) is int):
        return _observation(kind, "exposed", "seeded_diagnostics_exposed")
    return _observation(kind, "inconclusive", "unexpected_diagnostics_document")
