"""Finite operator-scoped HTTP/SSH proposals; scope is not network authority."""

import hashlib
import json
from uuid import NAMESPACE_URL, uuid5

from .models import Action, parse_action, parse_policy
from .configurable_scope import validate_scope, scope_digest, endpoint
from .tool_adapters import (CONFIGURABLE_NMAP_TOOL_ID as NMAP, CONFIGURABLE_HEADERS_TOOL_ID as HEADERS,
                            CONFIGURABLE_SSH_TOOL_ID as SSH, get_adapter)

PROFILE = "configurable_owned_lab"
BACKEND = "linux-authorized-configurable-owned-executor-v1"
WORKFLOW = "configurable-owned-http-ssh-v1"
LIMITS = {"max_steps": 4, "max_runtime_seconds": 60, "max_output_bytes": 26624}
TOOL_IDS = (NMAP, HEADERS, NMAP, SSH)
ENDPOINTS = ("http", "http", "ssh", "ssh")
OUTPUT_RESERVATIONS = (0, 8192, 10240, 18432, 26624)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def action(scope, step):
    scope = validate_scope(scope)
    if type(step) is not int or not 1 <= step <= 4:
        raise ValueError("invalid_configurable_step")
    selected = endpoint(scope, ENDPOINTS[step - 1])
    parameters = {"port": selected["port"], "timeout_seconds": 1 if step == 2 else 5,
                  "max_output_bytes": 2048 if step == 2 else 8192}
    if step == 2:
        parameters.update(method="GET", path=selected["path"])
    binding = scope_digest(scope)
    return parse_action({"schema_version": "1", "action_id": str(uuid5(NAMESPACE_URL,
        WORKFLOW + ":" + binding + ":" + str(step))), "tool_id": TOOL_IDS[step - 1],
        "target": selected["target"], "parameters": parameters,
        "rationale": "Deterministic owned endpoint assessment; operator scope " + binding + "."}).to_dict()


def step_for_action(scope, value):
    if type(value) is not Action:
        raise ValueError("invalid_configurable_action")
    for step in range(1, 5):
        if value.to_dict() == action(scope, step):
            return step
    raise ValueError("configurable_action_outside_scope")


def profile_allows(value, scope):
    try:
        step_for_action(scope, value)
        return True
    except (ValueError, TypeError, KeyError):
        return False


def policy_for_scope(scope, *, require_approval=True):
    scope = validate_scope(scope)
    return parse_policy({"schema_version": "1", "policy_version": "configurable-owned-v1",
        "allowed_targets": list(dict.fromkeys(scope[name]["target"] for name in ("http", "ssh"))),
        "allowed_tools": list(dict.fromkeys(TOOL_IDS)),
        "allowed_ports": list(dict.fromkeys(scope[name]["port"] for name in ("http", "ssh"))),
        "allowed_methods": ["GET"], "max_timeout_seconds": 5, "max_output_bytes": 8192,
        "max_targets": 1, "require_approval": require_approval, "approval_ttl_seconds": 60})


def capability_descriptor(scope):
    scope = validate_scope(scope)
    return {"schema_version": "1", "workflow_id": WORKFLOW, "scope": scope,
        "scope_sha256": scope_digest(scope), "limits": dict(LIMITS),
        "capabilities": [get_adapter(tool).to_dict() for tool in dict.fromkeys(TOOL_IDS)],
        "steps": [action(scope, step) for step in range(1, 5)],
        "network_model": "two_disconnected_owned_endpoint_fixtures",
        "live_calls_enabled": False, "planning": "deterministic_offline"}


def observation(scope, step, result):
    from .configurable_parser import validate_result

    scope = validate_scope(scope)
    if type(step) is not int or not 1 <= step <= 4 or type(result) is not dict:
        raise ValueError("invalid_configurable_observation_context")
    details = result.get("tool_observation")
    if result.get("status") != "succeeded" or result.get("truncated") is not False or details is None:
        return {"tool_id": TOOL_IDS[step - 1], "classification": "inconclusive",
                "reason": "complete_validated_evidence_missing", "details": None}
    details = validate_result(TOOL_IDS[step - 1], details, scope=scope, endpoint_id=ENDPOINTS[step - 1])
    return {"tool_id": TOOL_IDS[step - 1], "classification": "observed",
            "reason": "bounded_metadata_observed", "details": details}


def predecessor_gate(scope, step, value):
    """Only complete identification of the declared protocol allows its follow-up."""
    if type(step) is not int or step not in (1, 3) or type(value) is not dict or value.get("classification") != "observed":
        return False
    try:
        from .configurable_parser import validate_result
        details = validate_result(NMAP, value["details"], scope=scope, endpoint_id=ENDPOINTS[step - 1])
        return (value["tool_id"] == NMAP and details["identification"] == "identified"
                and details["service"]["name"] == ENDPOINTS[step - 1])
    except (ValueError, TypeError, KeyError):
        return False


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    from .configurable_lab_contract import validate_assessment_identity, validate_context

    expected = validate_assessment_identity(expected)
    step = result.get("scope_step") if type(result) is dict else None
    if (type(step) is not int or not 1 <= step <= 4 or tool_id != TOOL_IDS[step - 1]
            or result.get("backend") != BACKEND or result.get("status") != execution_status
            or execution_status not in ("succeeded", "failed", "timeout", "output_limit")
            or result.get("scope_sha256") != expected["scope_sha256"]):
        raise ValueError("invalid_configurable_result_context")
    context = result.get("owned_lab")
    if (type(context) is not dict or set(context) != {"identity", "step", "endpoints"}
            or context["identity"] != expected or type(context["step"]) is not int or context["step"] != step
            or type(context["endpoints"]) is not dict or set(context["endpoints"]) != {"http", "ssh"}):
        raise ValueError("invalid_configurable_aggregate_context")
    if previous is None:
        if step != 1:
            raise ValueError("configurable_context_predecessor_missing")
        before = {name: {"connection_count": 0, "request_count": 0} for name in ("http", "ssh")}
    else:
        if (type(previous) is not dict or set(previous) != {"identity", "step", "endpoints"}
                or previous["identity"] != expected or type(previous["step"]) is not int
                or previous["step"] != step - 1 or type(previous["endpoints"]) is not dict
                or set(previous["endpoints"]) != {"http", "ssh"}):
            raise ValueError("configurable_context_predecessor_changed")
        before = {name: validate_context(previous["endpoints"][name], expected["endpoints"][name])
                  for name in ("http", "ssh")}
    selected = ENDPOINTS[step - 1]
    for name in ("http", "ssh"):
        row = validate_context(context["endpoints"][name], expected["endpoints"][name])
        delta = {key: row[key] - before[name][key] for key in ("connection_count", "request_count")}
        if name != selected:
            if any(delta.values()):
                raise ValueError("configurable_other_endpoint_changed")
        elif (not 0 <= delta["request_count"] <= 1
                or not delta["request_count"] <= delta["connection_count"] <= (3 if step in (1, 3) else 1)):
            raise ValueError("configurable_endpoint_count_mismatch")
        elif execution_status == "succeeded" and result.get("tool_observation") is not None:
            if delta["request_count"] != 1 or delta["connection_count"] < (2 if step in (1, 3) else 1):
                raise ValueError("configurable_endpoint_incomplete")
    return json.loads(encode(context))
