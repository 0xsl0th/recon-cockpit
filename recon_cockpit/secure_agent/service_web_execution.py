"""Independent fixed-order authority verification for the new owned workflow."""

import hashlib
import hmac
import math
import re
import time
from uuid import UUID

from .executor_worker import LAUNCH_FIELDS, digest
from .models import load_json, parse_action, parse_policy
from .service_web_contract import (LIMITS, OUTPUT_RESERVATIONS, TOOL_IDS, action_step,
                                    profile_allows)
from .service_web_lab_contract import validate_identity


MAX_LAUNCH_BYTES = 32768


def consume_launch(raw, nonce, context_digest, *, now=None, expected_tool=None):
    if (type(raw) is not bytes or len(raw) > MAX_LAUNCH_BYTES
            or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{64}", nonce) is None
            or type(context_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", context_digest) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError("service_web_launch_commitment_mismatch")
    value = load_json(raw)
    if (type(value) is not dict or set(value) not in (
            {"mode", "launch", "identity", "namespaces"},
            {"mode", "launch", "identity", "namespaces", "runtime"})
            or value["mode"] != "owned_service_web_lab"):
        raise ValueError("invalid_service_web_launch")
    identity = validate_identity(value["identity"])
    launch = value["launch"]
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS
            or launch["schema_version"] != "1" or launch["mode"] != "service_web_owned"
            or launch["execute"] is not True or launch["nonce"] != nonce
            or type(launch["session_id"]) is not str or str(UUID(launch["session_id"])) != launch["session_id"]):
        raise ValueError("invalid_service_web_authority")
    limits = launch["limits"]
    if (type(limits) is not dict or set(limits) != set(LIMITS)
            or any(type(limits[key]) is not int or not 1 <= limits[key] <= cap for key, cap in LIMITS.items())
            or digest(limits) != launch["limits_digest"]):
        raise ValueError("invalid_service_web_limits")
    now = time.monotonic() if now is None else now
    deadline = launch["deadline"]
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits["max_runtime_seconds"]):
        raise ValueError("service_web_expired")
    action, policy = parse_action(launch["action"]), parse_policy(launch["policy"])
    if (not profile_allows(action, identity["scenario"])
            or (expected_tool is not None and action.tool_id != expected_tool)
            or action.to_dict() != launch["action"] or policy.to_dict() != launch["policy"]
            or action.digest != launch["action_digest"] or policy.digest != launch["policy_digest"]
            or policy.evaluate(action).decision == "deny"):
        raise ValueError("service_web_action_or_policy_denied")
    step = action_step(action.tool_id)
    if (type(launch["sequence"]) is not int or launch["sequence"] != step
            or step > limits["max_steps"]):
        raise ValueError("service_web_step_mismatch")
    if (type(launch["output_reserved_before"]) is not int
            or launch["output_reserved_before"] != OUTPUT_RESERVATIONS[step - 1]
            or type(launch["output_reserved_after"]) is not int
            or launch["output_reserved_after"] != OUTPUT_RESERVATIONS[step]
            or launch["output_reserved_after"] > limits["max_output_bytes"]):
        raise ValueError("service_web_output_reservation_mismatch")
    host, lab = launch["host_namespaces"], value["namespaces"]
    for namespaces in (host, lab):
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None
                       for key, item in namespaces.items())):
            raise ValueError("invalid_service_web_namespaces")
    if any(host[key] == lab[key] for key in host):
        raise ValueError("service_web_namespaces_not_private")
    runtime_digest = None
    if action.tool_id == TOOL_IDS[2]:
        if "runtime" in value:
            raise ValueError("unexpected_service_web_native_runtime")
    else:
        if "runtime" not in value:
            raise ValueError("missing_service_web_runtime")
        if action.tool_id == TOOL_IDS[0]:
            from .network_tools_runtime import validate_manifest, manifest_digest
        else:
            from .web_tools_runtime import validate_manifest, manifest_digest
        runtime_digest = manifest_digest(validate_manifest(value["runtime"], tool_id=action.tool_id))
    return {"target": action.target, "parameters": action.parameters.to_dict(), "tool_id": action.tool_id,
            "host_namespaces": host, "verify_boundary": True}, deadline, lab, runtime_digest
