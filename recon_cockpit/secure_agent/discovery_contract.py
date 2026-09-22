"""Reviewed singleton TCP discovery followed by the owned HTTP assessment.

A completed TCP handshake establishes reachability only. The trusted fixture
workflow chooses the HTTP candidate; neither a port number nor a connection
proves service identity, authorization, or an assessment finding.
"""

from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from . import assessment_contract as http
from .models import ValidationError, parse_action


WORKFLOW = "owned-discovery-http-assessment-v1"
PARSER_VERSION = "tcp-connect-discovery-v1"


def discovery_action(case, step):
    http._case(case)
    if type(step) is not int or step not in (1, 2, 3):
        raise ValueError("invalid_discovery_sequence")
    if step > 1:
        return http.assessment_action(case, step - 1)
    return parse_action({
        "schema_version": "1",
        "action_id": str(uuid5(NAMESPACE_URL, WORKFLOW + ":" + case + ":1")),
        "tool_id": "tcp_connect", "target": "127.0.0.1",
        "parameters": {"port": 8080, "timeout_seconds": 1, "max_output_bytes": 1024},
        "rationale": "DETERMINISTIC OWNED FIXTURE DISCOVERY: attempt one scoped TCP connection.",
    }).to_dict()


def capability_descriptor():
    """Two reviewed built-ins; this data does not grant execution permission."""
    http_capability = http.capability_descriptor()
    http_capability["isolation"]["executor"] = "linux-authorized-discovery-fixture-executor-v1"
    tcp = {
        "schema_version": "1", "capability_id": "tcp_connect", "capability_version": "1",
        "parser_version": PARSER_VERSION, "effect": "connect_owned_fixture_tcp",
        "approval": "operator_policy",
        "destination": {"target": "127.0.0.1", "port": 8080, "fixture_only": True},
        "parameters": {"port": 8080, "timeout_seconds": 1, "max_output_bytes": 1024},
        "limits": {"max_attempts": 1, "max_targets": 1, "max_ports": 1,
                   "max_payload_bytes": 0, "max_banner_bytes": 0, "retries": 0},
        "isolation": "linux-authorized-discovery-fixture-executor-v1",
        "result_contract": "bounded-tcp-connect-result-v1",
        "live_calls_enabled": False,
    }
    return {
        "schema_version": "1", "workflow_id": WORKFLOW,
        "capabilities": [tcp, http_capability],
        "limits": {"max_actions": 3, "max_steps": 3, "max_output_bytes": 3072},
        "live_calls_enabled": False,
    }


def _observation(classification, reason):
    return {"parser_version": PARSER_VERSION, "kind": "tcp_discovery",
            "classification": classification, "reason": reason, "followup_path": None}


def parse_observation(action, result, *, execution_status):
    if type(action) is dict and action.get("tool_id") == "http_probe":
        return http.parse_observation(action, result, execution_status=execution_status)
    try:
        fields = {"schema_version", "action_id", "tool_id", "target", "parameters"}
        if type(action) is not dict or set(action) not in (fields, fields | {"rationale"}):
            raise ValueError("invalid_action")
        parsed = parse_action({**action, "rationale": action.get("rationale", "")})
        if (parsed.tool_id != "tcp_connect" or parsed.target != "127.0.0.1"
                or parsed.parameters.to_dict() != {
                    "port": 8080, "timeout_seconds": 1, "max_output_bytes": 1024}):
            raise ValueError("invalid_action")
    except (ValidationError, ValueError, TypeError, RecursionError, KeyError):
        return _observation("inconclusive", "invalid_action")
    if type(execution_status) is not str or execution_status != "succeeded":
        return _observation("inconclusive", "execution_not_succeeded")
    fields = {"status", "results", "bytes_received", "truncated"}
    if (type(result) is not dict or not fields <= set(result)
            or set(result) - (fields | {"backend", "boundary_checks"})
            or type(result["status"]) is not str or result["status"] != "succeeded"
            or type(result["bytes_received"]) is not int or result["bytes_received"] != 0
            or result["truncated"] is not False
            or type(result["results"]) is not list or len(result["results"]) != 1):
        return _observation("inconclusive", "invalid_result")
    row = result["results"][0]
    if (type(row) is not dict or set(row) != {"target", "port", "state"}
            or type(row["target"]) is not str or row["target"] != parsed.target
            or type(row["port"]) is not int or row["port"] != parsed.parameters.port
            or type(row["state"]) is not str or row["state"] not in {"open", "closed"}):
        return _observation("inconclusive", "invalid_result_metadata")
    if "backend" in result and result["backend"] != "linux-authorized-discovery-fixture-executor-v1":
        return _observation("inconclusive", "invalid_result_metadata")
    if "boundary_checks" in result:
        checks = result["boundary_checks"]
        if (type(checks) is not dict or set(checks) != http._BOUNDARY_FIELDS
                or any(value is not True for value in checks.values())):
            return _observation("inconclusive", "invalid_result_metadata")
    if row["state"] == "open":
        return _observation("reachable", "tcp_port_reachable")
    return _observation("inconclusive", "tcp_port_not_reachable")
