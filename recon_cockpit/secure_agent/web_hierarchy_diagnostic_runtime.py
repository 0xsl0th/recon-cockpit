"""Pinned ffuf development capture in an already-owned diagnostic namespace."""

import base64
import hashlib
import os
from pathlib import Path
import sys
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _trusted_program
from .tool_runtime_common import _CLOSE_EXCEPT, sealed_snapshots
from .web_hierarchy_spec import WORDLIST
from . import web_hierarchy_diagnostic_worker as fixed


def inspect_runtime(control):
    """Reuse accepted ELF inspection; replace only the new diagnostic data pin."""
    from . import web_tools_runtime as accepted
    original = accepted.inspect_tool_runtime(accepted.FFUF, control)
    entries = [dict(item) for item in original["files"] if not item["source"].startswith("compiled:")]
    entries.append({"source": fixed.COMPILED_SOURCE, "destination": fixed.COMPILED_DESTINATION,
        "size": len(WORDLIST), "sha256": hashlib.sha256(WORDLIST).hexdigest()})
    return fixed.validate_manifest({"version": "1", "profile": fixed.PROFILE,
        "executable": original["executable"], "interpreter": original["interpreter"],
        "files": sorted(entries, key=lambda row: row["destination"])})


def client_command(lab, manifest, descriptors, commitment):
    fixed.validate_manifest(manifest)
    stdlib, files = lab._bootstrap
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
    for name in ("worker.py", "tool_worker_common.py", "web_hierarchy_diagnostic_worker.py",
                 "web_hierarchy_spec.py", "__init__.py"):
        argv += ["--ro-bind", str(directory / name), "/app/recon_cockpit/secure_agent/" + name]
    argv += ["--ro-bind", str(directory / "__init__.py"), "/app/recon_cockpit/__init__.py"]
    for item, descriptor in zip(manifest["files"], descriptors, strict=True):
        mode = "0555" if item["destination"] in {manifest["executable"], manifest["interpreter"]} else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), item["destination"]]
    # Reuse ffuf's accepted empty configuration/scraper directory behavior.
    argv += ["--perms", "0555", "--dir", fixed.SCRAPER_DIRECTORY,
        "--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S",
        "/app/recon_cockpit/secure_agent/web_hierarchy_diagnostic_worker.py", commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)), *argv]


def capture_client(lab, control):
    """Return bounded raw observations; cancellation propagates after cleanup."""
    if (sys.platform != "linux" or type(control) is not ExecutionControl
            or control.clock is not time.monotonic):
        raise IsolationUnavailable("Web hierarchy diagnostic requires fixed Linux control")
    control.check()
    lab._check(control)
    lab._verify_pins()
    manifest = inspect_runtime(control)
    descriptors = sealed_snapshots(manifest, fixed.COMPILED_SOURCE, WORDLIST, control)
    try:
        request = {"deadline": min(time.monotonic() + fixed.CLIENT_SECONDS, control.deadline),
            "host_namespaces": _namespaces(), "lab_namespaces": lab._lab_namespaces, "manifest": manifest}
        raw = fixed.encode(request)
        commitment = hashlib.sha256(raw).hexdigest()
        fixed.validate_request(raw, commitment)
        prefix = fixed.READY_PREFIX + commitment.encode("ascii") + b"\n"
        started = time.monotonic()
        code, stdout, stderr, reason = _capture_bounded(
            client_command(lab, manifest, descriptors, commitment), raw,
            max(0, request["deadline"] - time.monotonic()), fixed.MAX_OUTPUT_BYTES + len(prefix),
            control=control, pass_fds=(*lab._namespace_fds, *descriptors))
        elapsed = round((time.monotonic() - started) * 1000)
        ready = stderr.startswith(prefix)
        if ready:
            stderr = stderr[len(prefix):]
        if len(stdout) + len(stderr) > fixed.MAX_OUTPUT_BYTES:
            reason = "output_limit"
            stdout = stdout[:fixed.MAX_OUTPUT_BYTES]
            stderr = stderr[:fixed.MAX_OUTPUT_BYTES - len(stdout)]
        control.check()
        return {"runtime_manifest": manifest,
            "runtime_sha256": hashlib.sha256(fixed.encode(manifest)).hexdigest(),
            "argv": list(fixed.FIXED_ARGV),
            "execution": {"exit_code": code, "stop_reason": reason, "elapsed_ms": elapsed,
                "raw_stdout_base64": base64.b64encode(stdout).decode("ascii"),
                "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
                "truncated": reason == "output_limit"},
            "confinement": {"worker_ready": ready, "private_namespaces_and_firewall": ready,
                "read_only_pinned_runtime": ready, "landlock_and_seccomp": ready,
                "no_inherited_descriptors": ready, "thread_task_limit": ready,
                "udp_blocked": ready}}
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
