"""Independent inner verification of a single-use configurable endpoint launch."""

import hashlib
import hmac
import math
import re
import time
from uuid import UUID

from .executor_worker import LAUNCH_FIELDS, digest
from .models import load_json, parse_action, parse_policy
from .configurable_contract import LIMITS, PROFILE, ENDPOINTS, HEADERS, OUTPUT_RESERVATIONS, step_for_action
from .configurable_scope import validate_scope
from .configurable_lab_contract import validate_identity


def consume_launch(raw, nonce, context_digest, *, now=None):
    if (type(raw) is not bytes or len(raw) > 32768 or type(nonce) is not str
            or re.fullmatch(r"[a-f0-9]{64}", nonce) is None or type(context_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", context_digest) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError("configurable_launch_commitment_mismatch")
    value = load_json(raw)
    fields = {"mode", "launch", "identity", "namespaces", "scope", "endpoint_id"}
    if type(value) is not dict or set(value) not in (fields, fields | {"runtime"}) or value["mode"] != PROFILE:
        raise ValueError("invalid_configurable_launch")
    scope = validate_scope(value["scope"])
    identity = validate_identity(value["identity"], scope=scope, endpoint_name=value["endpoint_id"])
    launch = value["launch"]
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS or launch["schema_version"] != "1"
            or launch["mode"] != PROFILE or launch["execute"] is not True or launch["nonce"] != nonce
            or type(launch["session_id"]) is not str or str(UUID(launch["session_id"])) != launch["session_id"]):
        raise ValueError("invalid_configurable_authority")
    limits = launch["limits"]
    if (type(limits) is not dict or set(limits) != set(LIMITS)
            or any(type(limits[key]) is not int or not 1 <= limits[key] <= cap for key, cap in LIMITS.items())
            or digest(limits) != launch["limits_digest"]):
        raise ValueError("invalid_configurable_limits")
    now = time.monotonic() if now is None else now
    deadline = launch["deadline"]
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits["max_runtime_seconds"]):
        raise ValueError("configurable_expired")
    action, policy = parse_action(launch["action"]), parse_policy(launch["policy"])
    step = step_for_action(scope, action)
    if (action.to_dict() != launch["action"] or policy.to_dict() != launch["policy"]
            or action.digest != launch["action_digest"] or policy.digest != launch["policy_digest"]
            or policy.evaluate(action).decision == "deny" or ENDPOINTS[step - 1] != value["endpoint_id"]
            or type(launch["sequence"]) is not int or launch["sequence"] != step or step > limits["max_steps"]):
        raise ValueError("configurable_authority_denied")
    if (type(launch["output_reserved_before"]) is not int
            or launch["output_reserved_before"] != OUTPUT_RESERVATIONS[step - 1]
            or type(launch["output_reserved_after"]) is not int
            or launch["output_reserved_after"] != OUTPUT_RESERVATIONS[step]
            or launch["output_reserved_after"] > limits["max_output_bytes"]):
        raise ValueError("configurable_reservation_mismatch")
    host, lab = launch["host_namespaces"], value["namespaces"]
    for namespaces in (host, lab):
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None
                       for key, item in namespaces.items())):
            raise ValueError("invalid_configurable_namespaces")
    if any(host[key] == lab[key] for key in host):
        raise ValueError("configurable_namespaces_not_private")
    runtime_digest = None
    if action.tool_id == HEADERS:
        if "runtime" in value:
            raise ValueError("unexpected_configurable_header_runtime")
    else:
        from .configurable_runtime import underlying_tool
        from .network_tools_runtime import validate_manifest, manifest_digest
        runtime_digest = manifest_digest(validate_manifest(value.get("runtime"), tool_id=underlying_tool(action.tool_id)))
    return {"target": action.target, "parameters": action.parameters.to_dict(), "tool_id": action.tool_id,
            "endpoint_id": value["endpoint_id"], "scope": scope, "host_namespaces": host,
            "verify_boundary": True}, deadline, lab, runtime_digest
