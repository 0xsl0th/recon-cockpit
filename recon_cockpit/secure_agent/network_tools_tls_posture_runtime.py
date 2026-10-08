"""Four fixed TLS client closures, independently bound to production authority.

The reviewed diagnostic supplies only finite OpenSSL bytes and arguments. No
diagnostic request, receipt or observation can stand in for the launch permit.
This module's worker-facing imports contain no owner, fixture or private key.
"""

import hashlib
import hmac
import math
from pathlib import Path
import re
import time
from types import MappingProxyType
from uuid import UUID

from . import tls_posture_diagnostic_worker as fixed
from .network_tools_tls_posture_spec import TOOL_VERSIONS, PARAMETERS, LIMITS, BOUNDARY_FIELDS

PROFILE = "network-tools-tls-posture-runtime-v1"
READY_PREFIX = b"RECON_NETWORK_TLS_POSTURE_READY_V1 "
MAX_LAUNCH_BYTES = 32768
FIXED_ARGV = MappingProxyType({tool: fixed.FIXED_ARGV[version] for tool, version in TOOL_VERSIONS.items()})
ENVIRONMENT = fixed.ENVIRONMENT
CLIENT_MODULES = ("network_tools_tls_posture_worker", "network_tools_tls_posture_runtime",
    "network_tools_tls_posture_spec", "network_tools_tls_posture_identity", "tls_posture_diagnostic_worker",
    "models", "tool_parameters", "tool_adapters", "executor_worker", "worker", "tool_worker_common")


def diagnostic_manifest(value):
    """Project only a validated production closure onto unchanged byte checks."""
    if (type(value) is not dict
            or set(value) != {"version", "profile", "tool_id", "executable", "interpreter", "files"}
            or value["profile"] != PROFILE or type(value["tool_id"]) is not str
            or value["tool_id"] not in TOOL_VERSIONS or len(fixed.encode(value)) > 12288):
        raise ValueError("invalid_tls_posture_runtime")
    return fixed.validate_manifest({key: (fixed.PROFILE if key == "profile" else item)
        for key, item in value.items() if key != "tool_id"})


def validate_manifest(value, *, tool_id=None):
    diagnostic_manifest(value)
    if tool_id is not None and value["tool_id"] != tool_id:
        raise ValueError("tls_posture_runtime_tool_mismatch")
    return value


def manifest_digest(value):
    return hashlib.sha256(fixed.encode(validate_manifest(value))).hexdigest()


def consume_launch(raw, nonce, commitment, *, now=None):
    """Check the complete production launch in a fresh, single-exec worker."""
    from .executor_worker import LAUNCH_FIELDS, digest
    from .models import load_json, parse_action, parse_policy
    from .network_tools_tls_posture_identity import validate_identity
    from .network_tools_tls_posture_spec import tool_for_case
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_LAUNCH_BYTES
            or type(nonce) is not str or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
            or type(commitment) is not str or re.fullmatch(r"[0-9a-f]{64}", commitment) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), commitment)):
        raise ValueError("tls_posture_launch_commitment_mismatch")
    value = load_json(raw)
    if (set(value) != {"mode", "launch", "identity", "namespaces", "runtime"}
            or value["mode"] != "owned_network_tools_lab"):
        raise ValueError("invalid_tls_posture_launch")
    identity = validate_identity(value["identity"])
    launch = value["launch"]
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS
            or launch["schema_version"] != "1" or launch["mode"] != "network_tools_owned"
            or launch["execute"] is not True or launch["nonce"] != nonce
            or type(launch["session_id"]) is not str or str(UUID(launch["session_id"])) != launch["session_id"]):
        raise ValueError("invalid_tls_posture_authority")
    limits = launch["limits"]
    if (type(limits) is not dict or set(limits) != set(LIMITS)
            or any(type(limits[key]) is not int or not 1 <= limits[key] <= cap for key, cap in LIMITS.items())
            or digest(limits) != launch["limits_digest"]):
        raise ValueError("invalid_tls_posture_limits")
    now = time.monotonic() if now is None else now
    deadline = launch["deadline"]
    if (type(launch["sequence"]) is not int or launch["sequence"] != 1
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits["max_runtime_seconds"]):
        raise ValueError("tls_posture_expired_or_exhausted")
    action, policy = parse_action(launch["action"]), parse_policy(launch["policy"])
    if (action.tool_id != tool_for_case(identity["scenario"]) or action.target != "127.0.0.1"
            or action.parameters.to_dict() != dict(PARAMETERS)
            or action.to_dict() != launch["action"] or policy.to_dict() != launch["policy"]
            or action.digest != launch["action_digest"] or policy.digest != launch["policy_digest"]
            or policy.evaluate(action).decision == "deny"):
        raise ValueError("tls_posture_action_or_policy_denied")
    if (type(launch["output_reserved_before"]) is not int or launch["output_reserved_before"] != 0
            or type(launch["output_reserved_after"]) is not int
            or launch["output_reserved_after"] != PARAMETERS["max_output_bytes"]
            or launch["output_reserved_after"] > limits["max_output_bytes"]):
        raise ValueError("tls_posture_output_reservation_mismatch")
    host, lab = launch["host_namespaces"], value["namespaces"]
    for namespaces in (host, lab):
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None
                       for key, item in namespaces.items())):
            raise ValueError("invalid_tls_posture_namespaces")
    if any(host[key] == lab[key] for key in host):
        raise ValueError("tls_posture_namespaces_not_private")
    manifest = validate_manifest(value["runtime"], tool_id=action.tool_id)
    return {"version": TOOL_VERSIONS[action.tool_id], "tool_id": action.tool_id, "deadline": deadline,
            "host_namespaces": host, "lab_namespaces": lab, "manifest": manifest}


def command(lab, bootstrap, manifest, descriptors, nonce, commitment):
    """Expose the unchanged client bytes and only pure authority helpers."""
    from .isolation import _trusted_program
    from .tool_runtime_common import _CLOSE_EXCEPT
    validate_manifest(manifest)
    stdlib, files = bootstrap
    destinations = {item["destination"] for item in manifest["files"]}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
        "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1",
        "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if destination not in destinations and Path(destination).name not in {"nft", "bwrap", "nsenter"}:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in CLIENT_MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    for item, descriptor in zip(manifest["files"], descriptors, strict=True):
        mode = "0555" if item["destination"] in {manifest["executable"], manifest["interpreter"]} else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), item["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/network_tools_tls_posture_worker.py", nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)), *argv]
