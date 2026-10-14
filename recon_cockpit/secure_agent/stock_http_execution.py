"""Inner verification of the exact single-use stock-nginx diagnostic launch."""

import hashlib
import hmac
import math
import re
import time
from uuid import UUID

from .executor_worker import LAUNCH_FIELDS, digest
from .models import load_json, parse_action, parse_policy
from . import stock_http_contract as contract


def consume_launch(raw, nonce, context_digest, *, now=None):
    if (type(raw) is not bytes or len(raw) > 32768 or type(nonce) is not str
            or re.fullmatch(r"[a-f0-9]{64}", nonce) is None or type(context_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", context_digest) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError("stock_http_launch_commitment_mismatch")
    value = load_json(raw)
    if (type(value) is not dict or set(value) != {"mode", "launch", "identity", "namespaces", "selection", "runtime"}
            or value["mode"] != contract.PROFILE):
        raise ValueError("invalid_stock_http_launch")
    selected = contract.validate_selection(value["selection"])
    runtime = contract.validate_runtime(value["runtime"], selected)
    launch = value["launch"]
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS or launch["schema_version"] != "1"
            or launch["mode"] != contract.PROFILE or launch["execute"] is not True
            or launch["nonce"] != nonce or type(launch["session_id"]) is not str
            or str(UUID(launch["session_id"])) != launch["session_id"]):
        raise ValueError("invalid_stock_http_authority")
    identity = contract.validate_identity(value["identity"], selection=selected,
                                         session_id=launch["session_id"], runtime=runtime)
    limits = contract.validate_limits(launch["limits"], selected)
    if digest(limits) != launch["limits_digest"]:
        raise ValueError("stock_http_limits_changed")
    now = time.monotonic() if now is None else now
    deadline = launch["deadline"]
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits["max_runtime_seconds"]):
        raise ValueError("stock_http_expired")
    action, policy = parse_action(launch["action"]), parse_policy(launch["policy"])
    contract.validate_policy(launch["policy"], selected)
    if (action.to_dict() != launch["action"] or policy.to_dict() != launch["policy"]
            or action.digest != launch["action_digest"] or policy.digest != launch["policy_digest"]
            or policy.evaluate(action).decision == "deny" or not contract.profile_allows(action, selected)
            or type(launch["sequence"]) is not int or launch["sequence"] != 1):
        raise ValueError("stock_http_authority_denied")
    if (type(launch["output_reserved_before"]) is not int or launch["output_reserved_before"] != 0
            or type(launch["output_reserved_after"]) is not int
            or launch["output_reserved_after"] != limits["max_output_bytes"]):
        raise ValueError("stock_http_reservation_mismatch")
    host, lab = launch["host_namespaces"], value["namespaces"]
    for namespaces in (host, lab):
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None
                       for key, item in namespaces.items())):
            raise ValueError("invalid_stock_http_namespaces")
    if any(host[key] == lab[key] for key in host):
        raise ValueError("stock_http_namespaces_not_private")
    return {"target": action.target, "parameters": action.parameters.to_dict(), "tool_id": action.tool_id,
            "scope": contract.scope(selected), "endpoint_id": "http", "host_namespaces": host,
            "configuration": selected["configuration"], "case": selected["case"], "selection": selected,
            "verify_boundary": True}, deadline, lab, identity["client_runtime_sha256"]
