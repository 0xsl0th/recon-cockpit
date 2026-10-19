"""Validate one immutable client launch; live permission stays in the owner."""

import hashlib
import math
import re
import time

from . import name_tls_contract as contract, name_tls_public as public
from . import name_tls_role_spec as roles
from .models import parse_action, parse_policy
from .session_limits import SessionLimits


def consume_launch(raw, nonce, commitment):
    if (type(raw) is not bytes or len(raw) > 32768
            or not re.fullmatch(r"[a-f0-9]{64}", nonce)
            or hashlib.sha256(raw).hexdigest() != commitment):
        raise ValueError("name_tls_launch_commitment")
    value = public.decode(raw)
    fields = {"mode", "selection", "identity", "binding", "namespaces", "runtime", "launch"}
    if type(value) is not dict or set(value) != fields or value["mode"] != contract.PROFILE:
        raise ValueError("name_tls_launch_shape")
    selected = contract.validate_selection(value["selection"])
    identity = contract.validate_identity(value["identity"], selection=selected)
    launch = value["launch"]
    expected = {"schema_version", "mode", "execute", "session_id", "nonce", "sequence",
        "action", "action_digest", "policy", "policy_digest", "limits", "limits_digest",
        "deadline", "output_reserved_before", "output_reserved_after", "host_namespaces"}
    if (type(launch) is not dict or set(launch) != expected or launch["schema_version"] != "1"
            or launch["mode"] != contract.PROFILE or launch["execute"] is not True
            or launch["nonce"] != nonce or launch["session_id"] != identity["session_id"]
            or type(launch["sequence"]) is not int or not 1 <= launch["sequence"] <= 3):
        raise ValueError("name_tls_launch_authority")
    action, policy = parse_action(launch["action"]), parse_policy(launch["policy"])
    contract.validate_action(action, selected, identity, value["binding"])
    contract.validate_policy(policy, selected)
    contract.validate_limits(launch["limits"], selected)
    slot = contract.action_selector(action, selected)
    if (launch["action_digest"] != action.digest or launch["policy_digest"] != policy.digest
            or launch["limits_digest"] != SessionLimits(**launch["limits"]).digest
            or policy.evaluate(action).decision == "deny"
            or type(launch["deadline"]) not in (int, float) or not math.isfinite(launch["deadline"])
            or not 0 < launch["deadline"] - time.monotonic() <= 60
            or any(type(launch[key]) is not int for key in ("output_reserved_before", "output_reserved_after"))
            or not 0 <= launch["output_reserved_before"] < launch["output_reserved_after"] <= 18432
            or launch["output_reserved_after"] - launch["output_reserved_before"] != action.parameters.max_output_bytes):
        raise ValueError("name_tls_launch_limits")
    for ns in (launch["host_namespaces"], value["namespaces"]):
        if (type(ns) is not dict or set(ns) != {"user", "net", "mnt", "pid"}
                or any(type(v) is not str or re.fullmatch(k + r":\[\d+\]", v) is None for k, v in ns.items())):
            raise ValueError("name_tls_launch_namespaces")
    if value["namespaces"]["net"] == launch["host_namespaces"]["net"]:
        raise ValueError("name_tls_launch_host_network")
    op = contract.operation(slot)
    if op == "http":
        if value["runtime"] is not None:
            raise ValueError("name_tls_http_native_runtime")
    else:
        manifest = roles.validate_manifest(value["runtime"], role=op + "_client")
        if any(manifest[k] != selected[k] for k in ("configuration", "case")):
            raise ValueError("name_tls_client_runtime_selection")
    return value, action
