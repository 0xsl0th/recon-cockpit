"""Pinned native bytes and reviewed argv for scoped owned endpoint execution."""

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

from . import network_tools_runtime as native
from .configurable_parser import NMAP, HEADERS, SSH, parser_version
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _trusted_program
from .tool_runtime_common import _CLOSE_EXCEPT

NATIVE_TOOL_IDS = (NMAP, SSH)
UNDERLYING = {NMAP: native.NMAP_SERVICE, SSH: native.SSH}
READY_PREFIX = b"RECON_CONFIGURABLE_TOOL_READY_V1 "
BOUNDARY_NAMES = ("cross_service_blocked", "forbidden_ip_blocked", "forbidden_port_blocked",
    "namespace_creation_blocked", "capabilities_dropped", "no_new_privs", "root_read_only",
    "process_creation_blocked", "raw_sockets_blocked", "landlock_applied", "python_unreadable")
MODULES = tuple(dict.fromkeys((*native.MODULES, "configurable_runtime", "configurable_worker",
    "configurable_scope", "configurable_parser", "configurable_execution", "configurable_contract",
    "configurable_lab_contract", "http_headers_parser", "http_headers_fixture", "network_tools_nmap_parser",
    "nmap_contract", "network_tools_parser")))


def underlying_tool(tool_id):
    if type(tool_id) is not str or tool_id not in UNDERLYING:
        raise ValueError("invalid_configurable_native_tool")
    return UNDERLYING[tool_id]


def validate_manifests(value):
    if type(value) is not dict or set(value) != set(NATIVE_TOOL_IDS):
        raise ValueError("invalid_configurable_runtime_map")
    for tool_id in NATIVE_TOOL_IDS:
        native.validate_manifest(value[tool_id], tool_id=UNDERLYING[tool_id])
    return deepcopy(value)


def inspect_configurable_runtime(control):
    return validate_manifests({tool_id: native.inspect_tool_runtime(underlying, control)
                              for tool_id, underlying in UNDERLYING.items()})


def runtime_source_mounts(value):
    manifests = validate_manifests(value)
    return sorted({pair for manifest in manifests.values() for pair in native.runtime_source_mounts(manifest)})


def project_closure(closure, tool_id):
    if tool_id not in (*NATIVE_TOOL_IDS, HEADERS):
        raise ValueError("invalid_configurable_runtime_tool")
    manifests = validate_manifests(closure["configurable_runtime"])
    return {"stdlib": closure["stdlib"], "files": list(closure["files"]),
            "configurable_runtime": None if tool_id == HEADERS else manifests[tool_id]}


def _command(lab, bootstrap, manifest, descriptors, nonce, commitment):
    stdlib, files = bootstrap
    tool_files = [] if manifest is None else native.runtime_files(manifest)
    tool_paths = {item["destination"] for item in tool_files}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    # Only the selected sealed tool enters this child, even if the launcher has
    # pinned both manifests. Never expose an alternate executable or transport.
    forbidden = {"nft", "bwrap", "nsenter", "ip", "nmap", "ssh-keyscan"}
    for source, destination in files:
        if destination not in tool_paths and Path(destination).name not in forbidden:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    for item, fd in zip(tool_files, descriptors):
        mode = "0555" if item["destination"] in {manifest["executable"], manifest["interpreter"]} else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(fd), item["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/configurable_worker.py", nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
            "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
            ",".join(map(str, descriptors)) if descriptors else "0,1,2", *argv]


def run_configurable_tool_owned(*, lab, launch, control, closure=None, manifest=None):
    if sys.platform != "linux" or type(control) is not ExecutionControl:
        raise IsolationUnavailable("Configurable tools require Linux authority control")
    control.check()
    lab._check(control)
    lab._verify_pins()
    tool_id = launch["launch"]["action"]["tool_id"]
    parser_version(tool_id)
    if tool_id == HEADERS:
        if manifest is not None or (closure is not None and closure["configurable_runtime"] is not None):
            raise IsolationUnavailable("Header action has an unexpected native runtime")
    else:
        pinned = None if manifest is None else native.validate_manifest(manifest, tool_id=UNDERLYING[tool_id])
        manifest = ((native.inspect_tool_runtime(UNDERLYING[tool_id], control) if pinned is None else pinned)
                    if closure is None else native.validate_manifest(closure["configurable_runtime"], tool_id=UNDERLYING[tool_id]))
        if pinned is not None and native.manifest_digest(pinned) != native.manifest_digest(manifest):
            raise IsolationUnavailable("Configurable authority runtime changed")
    bootstrap = lab._runtime(control) if closure is None else (closure["stdlib"], [(p, p) for p in closure["files"]])
    envelope = dict(launch) if manifest is None else {**launch, "runtime": manifest}
    raw = native.encode(envelope)
    if len(raw) > 32768:
        raise IsolationUnavailable("Configurable launch envelope exceeds bound")
    commitment = hashlib.sha256(raw).hexdigest()
    prefix = READY_PREFIX + commitment.encode("ascii") + b"\n"
    descriptors = [] if manifest is None else native._snapshot(manifest, control)
    try:
        code, stdout, stderr, reason = _capture_bounded(
            _command(lab, bootstrap, manifest, descriptors, launch["launch"]["nonce"], commitment), raw,
            min(launch["launch"]["action"]["parameters"]["timeout_seconds"], control.remaining()),
            8192 + len(prefix), control=control, pass_fds=(*lab._namespace_fds, *descriptors))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    control.check()
    if not stderr.startswith(prefix):
        raise IsolationUnavailable("Configurable confinement not verified; no fallback")
    stderr = stderr[len(prefix):]
    if tool_id == HEADERS:
        if code != 0 or reason is not None or stderr:
            raise IsolationUnavailable("Configurable header worker failed")
        try:
            from .models import load_json
            result = load_json(stdout)
            if (type(result) is not dict or set(result) != {"status", "results", "bytes_received", "truncated", "boundary_checks"}
                    or result["status"] not in {"succeeded", "failed", "timeout", "output_limit"}
                    or type(result["boundary_checks"]) is not dict
                    or set(result["boundary_checks"]) != set(BOUNDARY_NAMES)
                    or any(flag is not True for flag in result["boundary_checks"].values())):
                raise ValueError("invalid_configurable_header_result")
        except (ValueError, TypeError, RecursionError):
            raise IsolationUnavailable("Invalid configurable header reply") from None
        return result
    if len(stdout) + len(stderr) > 8192:
        reason = "output_limit"
        stdout, stderr = stdout[:8192], stderr[:max(0, 8192 - len(stdout))]
    return {"status": reason or ("succeeded" if code == 0 else "failed"), "results": [], "tool_observation": None,
        "bytes_received": len(stdout) + len(stderr), "truncated": reason == "output_limit",
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True),
        "raw_output_base64": base64.b64encode(stdout).decode("ascii"),
        "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "provenance": {"runtime_sha256": native.manifest_digest(manifest), "runtime_manifest": manifest,
            "output_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "parser_version": parser_version(tool_id), "exit_code": code, "stop_reason": reason}}
