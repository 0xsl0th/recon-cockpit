"""A production-authorized, closed ffuf runtime for the twelve-path corpus.

The reviewed native diagnostic is evidence for the chosen bytes, not an input
protocol or execution authority. No diagnostic modules enter the client mount.
"""

import hashlib
import hmac
import math
from pathlib import Path
import re
import time
from types import MappingProxyType
from uuid import UUID

from .network_tools_web_hierarchy_spec import TOOL_ID, PARAMETERS, LIMITS, WORDLIST, BOUNDARY_FIELDS


PROFILE = "network-tools-web-hierarchy-runtime-v1"
READY_PREFIX = b"RECON_NETWORK_WEB_HIERARCHY_READY_V1 "
MAX_LAUNCH_BYTES = 32768
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 12288
EXECUTABLE = "/usr/bin/ffuf"
COMPILED = (("compiled:web-hierarchy-paths", "/tool/data/hierarchy-paths.txt", WORDLIST),)
CONFIG_DIRECTORY = "/tool/config"
SCRAPER_DIRECTORY = CONFIG_DIRECTORY + "/ffuf/scraper"
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
INTERPRETER = re.compile(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?ld-linux[^/]*\.so\.[0-9]+\Z")
ENVIRONMENT = MappingProxyType({"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1",
    "GOMAXPROCS": "1", "GOMEMLIMIT": "64MiB", "XDG_CONFIG_HOME": CONFIG_DIRECTORY})
FIXED_ARGV = ("/tool/ffuf", "-u", "http://127.0.0.1:8080/harbordesk/FUZZ",
    "-w", COMPILED[0][1], "-t", "1", "-rate", "4", "-timeout", "1",
    "-maxtime", "10", "-noninteractive", "-ignore-body", "-mc", "all", "-json",
    "-s", "-scrapers", "")
CLIENT_MODULES = ("network_tools_web_hierarchy_runtime", "network_tools_web_hierarchy_worker",
    "network_tools_web_hierarchy_spec", "network_tools_web_hierarchy_identity", "web_hierarchy_spec",
    "models", "tool_parameters", "tool_adapters", "executor_worker", "worker", "tool_worker_common")


def encode(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def validate_manifest(value, *, tool_id=None):
    if (type(value) is not dict
            or set(value) != {"version", "profile", "tool_id", "executable", "interpreter", "files"}
            or value["version"] != "1" or value["profile"] != PROFILE or value["tool_id"] != TOOL_ID
            or (tool_id is not None and tool_id != TOOL_ID) or value["executable"] != FIXED_ARGV[0]
            or type(value["interpreter"]) is not str or not INTERPRETER.fullmatch(value["interpreter"])
            or type(value["files"]) is not list or not 3 <= len(value["files"]) <= 48
            or len(encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_web_hierarchy_runtime")
    destinations, total = set(), 0
    for item in value["files"]:
        if (type(item) is not dict or set(item) != {"source", "destination", "size", "sha256"}
                or type(item["source"]) is not str or type(item["destination"]) is not str
                or any(".." in item[key] or "//" in item[key] for key in ("source", "destination"))
                or type(item["size"]) is not int or not 0 < item["size"] <= MAX_FILE_BYTES
                or type(item["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("invalid_web_hierarchy_runtime_file")
        source, destination = item["source"], item["destination"]
        if destination == FIXED_ARGV[0]:
            valid = source == EXECUTABLE
        elif destination == COMPILED[0][1]:
            valid = (source == COMPILED[0][0] and item["size"] == len(WORDLIST)
                     and item["sha256"] == hashlib.sha256(WORDLIST).hexdigest())
        else:
            valid = bool(LIBRARY.fullmatch(source) and LIBRARY.fullmatch(destination))
        if not valid or destination in destinations:
            raise ValueError("unreviewed_web_hierarchy_runtime_path")
        destinations.add(destination)
        total += item["size"]
    if (not {FIXED_ARGV[0], COMPILED[0][1], value["interpreter"]} <= destinations
            or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])):
        raise ValueError("invalid_web_hierarchy_runtime_closure")
    return value


def manifest_digest(value):
    return hashlib.sha256(encode(validate_manifest(value))).hexdigest()


def inspect_runtime(control):
    """Reuse accepted distribution-ELF inspection; keep its profile unchanged."""
    from . import web_tools_runtime as accepted
    original = accepted.inspect_tool_runtime(accepted.FFUF, control)
    entries = [dict(item) for item in original["files"] if not item["source"].startswith("compiled:")]
    entries.append({"source": COMPILED[0][0], "destination": COMPILED[0][1],
        "size": len(WORDLIST), "sha256": hashlib.sha256(WORDLIST).hexdigest()})
    return validate_manifest({"version": "1", "profile": PROFILE, "tool_id": TOOL_ID,
        "executable": original["executable"], "interpreter": original["interpreter"],
        "files": sorted(entries, key=lambda row: row["destination"])})


def consume_launch(raw, nonce, commitment, *, now=None):
    """Independently bind a production launch to its exact case and closure."""
    from .executor_worker import LAUNCH_FIELDS, digest
    from .models import load_json, parse_action, parse_policy
    from .network_tools_web_hierarchy_identity import validate_identity
    from .network_tools_web_hierarchy_spec import tool_for_case
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_LAUNCH_BYTES
            or type(nonce) is not str or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
            or type(commitment) is not str or re.fullmatch(r"[0-9a-f]{64}", commitment) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), commitment)):
        raise ValueError("web_hierarchy_launch_commitment_mismatch")
    value = load_json(raw)
    if (set(value) != {"mode", "launch", "identity", "namespaces", "runtime"}
            or value["mode"] != "owned_network_tools_lab"):
        raise ValueError("invalid_web_hierarchy_launch")
    identity = validate_identity(value["identity"])
    launch = value["launch"]
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS
            or launch["schema_version"] != "1" or launch["mode"] != "network_tools_owned"
            or launch["execute"] is not True or launch["nonce"] != nonce
            or type(launch["session_id"]) is not str or str(UUID(launch["session_id"])) != launch["session_id"]):
        raise ValueError("invalid_web_hierarchy_authority")
    limits = launch["limits"]
    if (type(limits) is not dict or set(limits) != set(LIMITS)
            or any(type(limits[key]) is not int or not 1 <= limits[key] <= cap for key, cap in LIMITS.items())
            or digest(limits) != launch["limits_digest"]):
        raise ValueError("invalid_web_hierarchy_limits")
    now = time.monotonic() if now is None else now
    deadline = launch["deadline"]
    if (type(launch["sequence"]) is not int or launch["sequence"] != 1
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits["max_runtime_seconds"]):
        raise ValueError("web_hierarchy_expired_or_exhausted")
    action, policy = parse_action(launch["action"]), parse_policy(launch["policy"])
    if (action.tool_id != tool_for_case(identity["scenario"]) or action.target != "127.0.0.1"
            or action.parameters.to_dict() != dict(PARAMETERS)
            or action.to_dict() != launch["action"] or policy.to_dict() != launch["policy"]
            or action.digest != launch["action_digest"] or policy.digest != launch["policy_digest"]
            or policy.evaluate(action).decision == "deny"):
        raise ValueError("web_hierarchy_action_or_policy_denied")
    if (type(launch["output_reserved_before"]) is not int or launch["output_reserved_before"] != 0
            or type(launch["output_reserved_after"]) is not int
            or launch["output_reserved_after"] != PARAMETERS["max_output_bytes"]
            or launch["output_reserved_after"] > limits["max_output_bytes"]):
        raise ValueError("web_hierarchy_output_reservation_mismatch")
    host, lab = launch["host_namespaces"], value["namespaces"]
    for namespaces in (host, lab):
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None
                       for key, item in namespaces.items())):
            raise ValueError("invalid_web_hierarchy_namespaces")
    if any(host[key] == lab[key] for key in host):
        raise ValueError("web_hierarchy_namespaces_not_private")
    manifest = validate_manifest(value["runtime"], tool_id=action.tool_id)
    return {"tool_id": action.tool_id, "deadline": deadline,
            "host_namespaces": host, "lab_namespaces": lab, "manifest": manifest}


def command(lab, bootstrap, manifest, descriptors, nonce, commitment):
    """Mount only the exact client closure and pure authority helpers."""
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
    argv += ["--perms", "0555", "--dir", SCRAPER_DIRECTORY,
        "--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/network_tools_web_hierarchy_worker.py",
        nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)), *argv]
