"""Verify a fixed routed action in the fresh client; grants no new authority."""

import hashlib
import hmac
import math
import re
import time
from uuid import UUID

from . import routing_contract as contract
from .executor_worker import LAUNCH_FIELDS, digest
from .models import load_json, parse_action


def consume_launch(raw, nonce, context_digest, *, now=None):
    if (type(raw) is not bytes or not raw or len(raw) > 32768
            or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{64}", nonce) is None
            or type(context_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", context_digest) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError("routing_client_commitment_changed")
    value = load_json(raw)
    if (type(value) is not dict or set(value) != {"mode", "launch", "identity", "namespaces", "selection", "selector", "runtime"}
            or value["mode"] != contract.PROFILE):
        raise ValueError("invalid_routing_client_launch")
    selected = contract.validate_selection(value["selection"])
    selector = contract.validate_selector(value["selector"])
    underlying = contract.underlying_contract(selector)
    chosen = contract.underlying_selection(selector, selected)
    runtime = underlying.validate_runtime(value["runtime"], chosen)
    launch = value["launch"]
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS or launch["schema_version"] != "1"
            or launch["mode"] != contract.PROFILE or launch["execute"] is not True
            or launch["nonce"] != nonce or type(launch["session_id"]) is not str
            or str(UUID(launch["session_id"])) != launch["session_id"]):
        raise ValueError("invalid_routing_client_authority")
    identity = contract.validate_identity(value["identity"], selection=selected, session_id=launch["session_id"])
    if identity["runtimes"][selector] != underlying.runtime_digests(runtime, chosen):
        raise ValueError("routing_client_runtime_changed")
    limits = contract.validate_limits(launch["limits"], selected)
    if digest(limits) != launch["limits_digest"]:
        raise ValueError("routing_client_limits_changed")
    now = time.monotonic() if now is None else now
    deadline = launch["deadline"]
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits["max_runtime_seconds"]):
        raise ValueError("routing_client_expired")
    action = parse_action(launch["action"])
    policy = contract.validate_policy(launch["policy"], selected)
    if (action.to_dict() != launch["action"] or policy.to_dict() != launch["policy"]
            or action.digest != launch["action_digest"] or policy.digest != launch["policy_digest"]
            or policy.evaluate(action).decision == "deny" or contract.action_selector(action, selected) != selector
            or type(launch["sequence"]) is not int or not 1 <= launch["sequence"] <= 4):
        raise ValueError("routing_client_authority_denied")
    before, after = launch["output_reserved_before"], launch["output_reserved_after"]
    if (type(before) is not int or type(after) is not int or before < 0
            or after - before != action.parameters.max_output_bytes or after > limits["max_output_bytes"]):
        raise ValueError("routing_client_reservation_changed")
    host, routed = launch["host_namespaces"], value["namespaces"]
    for names in (host, routed):
        if (type(names) is not dict or set(names) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None
                       for key, item in names.items())):
            raise ValueError("invalid_routing_client_namespaces")
    if any(host[key] == routed[key] for key in host):
        raise ValueError("routing_client_namespace_not_private")
    return {"target": action.target, "parameters": action.parameters.to_dict(), "tool_id": action.tool_id,
            "scope": underlying.scope(chosen), "endpoint_id": "http" if selector.startswith("http_") else "ssh",
            "host_namespaces": host, "configuration": selected["configuration"], "case": chosen["case"],
            "selection": selected, "selector": selector, "verify_boundary": True}, deadline, routed, identity["runtimes"][selector]["client_runtime_sha256"]
