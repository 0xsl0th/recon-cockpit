"""Fixed HTTP fixture workflow and bounded, data-only observation parser.

This descriptor is not execution permission. Observations describe the seeded
fixture only; they do not establish a general vulnerability or authenticate
server content. The caller binds the original action to its execution record.
"""

from __future__ import annotations

import json
import re
from uuid import NAMESPACE_URL, uuid5

from .models import ValidationError, parse_action


CASES = ("a", "b", "c", "d", "e", "f")
FIXTURE_MARKER = "recon-http-assessment-v1"
PARSER_VERSION = "http-assessment-v1"
_ACTION_FIELDS = {"schema_version", "action_id", "tool_id", "target", "parameters"}
_RESULT_FIELDS = {"status", "results", "bytes_received", "truncated"}
_ROW_FIELDS = {"target", "port", "http_status", "bytes_received", "truncated", "body", "response_sha256"}
_BOUNDARY_FIELDS = {"forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked",
                    "capabilities_dropped"}


def _case(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_assessment_case")
    return case


def discovery_path(case):
    return "/assessment/" + _case(case) + "/index.json"


def diagnostics_path(case):
    return "/assessment/" + _case(case) + "/diagnostics.json"


def assessment_action(case, sequence):
    case = _case(case)
    if type(sequence) is not int or sequence not in (1, 2):
        raise ValueError("invalid_assessment_sequence")
    return parse_action({
        "schema_version": "1",
        "action_id": str(uuid5(NAMESPACE_URL, f"recon-http-assessment-v1:{case}:{sequence}")),
        "tool_id": "http_probe", "target": "127.0.0.1",
        "parameters": {"port": 8080, "method": "GET",
                       "path": discovery_path(case) if sequence == 1 else diagnostics_path(case),
                       "timeout_seconds": 1, "max_output_bytes": 1024},
        "rationale": "DETERMINISTIC OWNED FIXTURE ASSESSMENT: inspect the scoped HTTP document.",
    }).to_dict()


def capability_descriptor():
    """Return a fresh JSON descriptor; operator policy remains authoritative."""
    return {
        "schema_version": "1", "capability_id": "http_probe", "capability_version": "1",
        "workflow_id": "owned-http-assessment-v1", "parser_version": PARSER_VERSION,
        "effect": "read_owned_fixture_http", "approval": "operator_policy",
        "destination": {"target": "127.0.0.1", "port": 8080, "fixture_only": True},
        "parameters": {"method": "GET", "timeout_seconds": 1, "max_output_bytes": 1024,
                       "paths": [path(case) for case in CASES for path in (discovery_path, diagnostics_path)]},
        "limits": {"max_actions": 2, "max_steps": 2, "max_output_bytes": 2048,
                   "max_observation_body_bytes": 1024},
        "isolation": {"coordinator": "linux-private-namespaces",
                      "planner": "linux-private-namespaces",
                      "executor": "linux-authorized-fixture-executor-v1"},
        "result_contract": {"format": "decoded-http-probe-result-v1", "wire_capture": False,
                            "worker_digest": "sha256-retained-http-response",
                            "artifact_digest": "sha256-canonical-decoded-result"},
        "live_calls_enabled": False,
    }


def _observation(kind, classification, reason, followup_path=None):
    return {"parser_version": PARSER_VERSION, "kind": kind, "classification": classification,
            "reason": reason, "followup_path": followup_path}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_document_key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("invalid_document_constant")


def parse_observation(action, result, *, execution_status):
    """Parse only exact fixture evidence; never return untrusted body strings.

    The action may omit rationale, as evidence deliberately does not retain it.
    HTTP status alone is insufficient: body/schema and result metadata must
    agree. Probe success and no reported truncation do not establish general
    HTTP framing integrity. The worker response digest is format-checked, not
    recomputed: decoded result JSON is not the original HTTP byte stream.
    """
    kind = "unexpected"
    try:
        if (type(action) is not dict or set(action) not in (_ACTION_FIELDS, _ACTION_FIELDS | {"rationale"})
                or type(action["parameters"]) is not dict):
            raise ValueError("invalid_action")
        parsed = parse_action({**action, "rationale": action.get("rationale", "")})
        parameters = parsed.parameters.to_dict()
        match = re.fullmatch(r"/assessment/([a-f])/(index|diagnostics)\.json", parameters["path"])
        if (action["target"] != "127.0.0.1" or parsed.tool_id != "http_probe" or match is None
                or parameters != {"port": 8080, "method": "GET", "path": parameters["path"],
                                  "timeout_seconds": 1, "max_output_bytes": 1024}):
            raise ValueError("invalid_action")
        case = match[1]
        kind = "discovery" if match[2] == "index" else "diagnostics"
    except (ValidationError, ValueError, TypeError, RecursionError, KeyError):
        return _observation(kind, "inconclusive", "invalid_action")
    if type(execution_status) is not str or execution_status != "succeeded":
        return _observation(kind, "inconclusive", "execution_not_succeeded")
    if (type(result) is not dict or not _RESULT_FIELDS <= set(result)
            or set(result) - (_RESULT_FIELDS | {"backend", "boundary_checks"})
            or type(result["status"]) is not str or result["status"] != "succeeded"
            or type(result["results"]) is not list or len(result["results"]) != 1
            or type(result["results"][0]) is not dict):
        return _observation(kind, "inconclusive", "invalid_result")
    row = result["results"][0]
    if set(row) != _ROW_FIELDS:
        return _observation(kind, "inconclusive", "invalid_result_metadata")
    if result["truncated"] is not False or row["truncated"] is not False:
        return _observation(kind, "inconclusive", "response_not_complete")
    if (type(row["target"]) is not str or row["target"] != parsed.target
            or type(row["port"]) is not int or row["port"] != parameters["port"]
            or type(row["http_status"]) is not int or not 100 <= row["http_status"] <= 599
            or type(result["bytes_received"]) is not int or type(row["bytes_received"]) is not int
            or not 1 <= row["bytes_received"] <= parameters["max_output_bytes"]
            or result["bytes_received"] != row["bytes_received"]
            or type(row["body"]) is not str or len(row["body"]) > 1024
            or type(row["response_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", row["response_sha256"]) is None):
        return _observation(kind, "inconclusive", "invalid_result_metadata")
    if "backend" in result and (type(result["backend"]) is not str
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", result["backend"]) is None):
        return _observation(kind, "inconclusive", "invalid_result_metadata")
    if "boundary_checks" in result:
        checks = result["boundary_checks"]
        if (type(checks) is not dict or set(checks) != _BOUNDARY_FIELDS
                or any(value is not True for value in checks.values())):
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
        expected = {"fixture": FIXTURE_MARKER, "diagnostics_path": diagnostics_path(case)}
        if row["http_status"] == 200 and document == expected:
            return _observation(kind, "discovered", "fixture_discovered", diagnostics_path(case))
        return _observation(kind, "inconclusive", "unexpected_discovery_document")
    if row["http_status"] == 404 and document == {"error": "not_found"}:
        return _observation(kind, "absent", "endpoint_not_found")
    expected = {"fixture": FIXTURE_MARKER, "document": "internal-diagnostics",
                "internal_service": "billing-db.fixture.invalid", "debug": True}
    if (row["http_status"] == 200 and document == expected
            and type(document.get("debug")) is bool):
        return _observation(kind, "exposed", "seeded_diagnostics_exposed")
    return _observation(kind, "inconclusive", "unexpected_diagnostics_document")
