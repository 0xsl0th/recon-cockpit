"""Independent complete authority verification before a network-tool process starts."""

import hashlib
import hmac
import math
import re
import time
from uuid import UUID

from .executor_worker import LAUNCH_FIELDS, digest
from .models import load_json, parse_action, parse_policy
from .network_tools_contract import LIMITS, profile_allows
from .network_tools_lab_contract import validate_identity
from .network_tools_runtime import manifest_digest, validate_manifest


MAX_LAUNCH_BYTES = 32768


def consume_launch(raw, nonce, context_digest, *, now=None):
    if (type(raw) is not bytes or len(raw) > MAX_LAUNCH_BYTES
            or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{64}", nonce) is None
            or type(context_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", context_digest) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError("network_tool_launch_commitment_mismatch")
    value = load_json(raw)
    # T02 verifies its complete launch without importing any fixture or owner
    # into the dedicated client. Keep the same checks for callers of this API.
    candidate_launch = value.get("launch")
    candidate_action = candidate_launch.get("action") if type(candidate_launch) is dict else None
    selected = candidate_action.get("tool_id") if type(candidate_action) is dict else None
    if selected in ("openssl_tls10_posture_v1", "openssl_tls11_posture_v1",
                    "openssl_tls12_posture_v1", "openssl_tls13_posture_v1"):
        from .network_tools_tls_posture_runtime import consume_launch as consume_tls_posture
        request = consume_tls_posture(raw, nonce, context_digest, now=now)
        return {"target": "127.0.0.1", "parameters": value["launch"]["action"]["parameters"],
                "tool_id": request["tool_id"], "host_namespaces": request["host_namespaces"],
                "verify_boundary": True}, request["deadline"], request["lab_namespaces"], manifest_digest(request["manifest"])
    if type(value) is dict and value.get("mode") == "owned_service_web_lab":
        from .service_web_execution import consume_launch as consume_service_web
        return consume_service_web(raw, nonce, context_digest, now=now, expected_tool="nmap_service_identify_v1")
    if (set(value) != {"mode", "launch", "identity", "namespaces", "runtime"}
            or value["mode"] != "owned_network_tools_lab"):
        raise ValueError("invalid_network_tool_launch")
    identity = validate_identity(value["identity"])
    launch = value["launch"]
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS
            or launch["schema_version"] != "1" or launch["mode"] != "network_tools_owned"
            or launch["execute"] is not True or launch["nonce"] != nonce
            or type(launch["session_id"]) is not str or str(UUID(launch["session_id"])) != launch["session_id"]):
        raise ValueError("invalid_network_tool_authority")
    limits = launch["limits"]
    if (type(limits) is not dict or set(limits) != set(LIMITS)
            or any(type(limits[key]) is not int or not 1 <= limits[key] <= cap for key, cap in LIMITS.items())
            or digest(limits) != launch["limits_digest"]):
        raise ValueError("invalid_network_tool_limits")
    now = time.monotonic() if now is None else now
    deadline = launch["deadline"]
    if (type(launch["sequence"]) is not int or launch["sequence"] != 1
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits["max_runtime_seconds"]):
        raise ValueError("network_tool_expired_or_exhausted")
    action, policy = parse_action(launch["action"]), parse_policy(launch["policy"])
    if (not profile_allows(action, identity["scenario"])
            or action.to_dict() != launch["action"] or policy.to_dict() != launch["policy"]
            or action.digest != launch["action_digest"] or policy.digest != launch["policy_digest"]
            or policy.evaluate(action).decision == "deny"):
        raise ValueError("network_tool_action_or_policy_denied")
    if (type(launch["output_reserved_before"]) is not int or launch["output_reserved_before"] != 0
            or type(launch["output_reserved_after"]) is not int
            or launch["output_reserved_after"] != action.parameters.max_output_bytes
            or launch["output_reserved_after"] > limits["max_output_bytes"]):
        raise ValueError("network_tool_output_reservation_mismatch")
    host, lab = launch["host_namespaces"], value["namespaces"]
    for namespaces in (host, lab):
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None
                       for key, item in namespaces.items())):
            raise ValueError("invalid_network_tool_namespaces")
    if any(host[key] == lab[key] for key in host):
        raise ValueError("network_tool_namespaces_not_private")
    manifest = validate_manifest(value["runtime"], tool_id=action.tool_id)
    return {"target": action.target, "parameters": action.parameters.to_dict(), "tool_id": action.tool_id,
            "host_namespaces": host, "verify_boundary": True}, deadline, lab, manifest_digest(manifest)
