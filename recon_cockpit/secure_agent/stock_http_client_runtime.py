"""Selected stock HTTP diagnostic client, gated after confined readiness."""

import base64
import hashlib
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

from . import configurable_runtime as existing
from . import network_tools_runtime as native
from . import stock_http_spec as spec
from .configurable_parser import HEADERS, NMAP, parser_version
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _trusted_program
from .models import load_json
from .tool_runtime_common import _CLOSE_EXCEPT


READY_PREFIX = b"RECON_STOCK_HTTP_CLIENT_READY_V1 "
BOUNDARY_NAMES = ("other_configuration_blocked", "forbidden_ip_blocked", "forbidden_port_blocked",
    "excluded_destination_blocked", "namespace_creation_blocked", "capabilities_dropped", "no_new_privs",
    "root_read_only", "process_creation_blocked", "raw_sockets_blocked", "private_socket_blocked",
    "private_socket_mount_absent", "landlock_applied", "python_unreadable")
MODULES = tuple(dict.fromkeys((*existing.MODULES, "stock_http_spec", "stock_http_runtime",
    "stock_http_contract", "stock_http_execution", "stock_http_client_worker", "stock_http_client_runtime")))
STARTUP_SECONDS = 10
MARSHALLING_SECONDS = 0.25


def _write_control(proc, raw, supervisor, *, deadline=None):
    """Bound pipe backpressure by the same supervisor/session deadlines."""
    from .routed import _BudgetExceeded
    if type(raw) is not bytes or not raw or len(raw) > 32769:
        raise IsolationUnavailable("Stock diagnostic control packet invalid")
    descriptor = proc.stdin.fileno()
    os.set_blocking(descriptor, False)
    offset = 0
    def writable():
        if deadline is not None and time.monotonic() >= deadline:
            raise _BudgetExceeded("timeout")
        if proc.poll() is not None:
            raise IsolationUnavailable("Stock diagnostic client exited before release")
        return bool(select.select([], [descriptor], [], 0)[1])
    while offset < len(raw):
        supervisor.check()
        supervisor.wait_for(writable, worker_may_exit=True)
        try:
            count = os.write(descriptor, raw[offset:])
        except BlockingIOError:
            continue
        except BrokenPipeError:
            raise IsolationUnavailable("Stock diagnostic control pipe closed") from None
        if count <= 0:
            raise IsolationUnavailable("Stock diagnostic control write incomplete")
        offset += count
    supervisor.check()


def _native_stop_reason(code, reason, action_deadline, *, now=None):
    now = time.monotonic() if now is None else now
    if (reason is None and code in (-signal.SIGALRM, 128 + signal.SIGALRM)
            and now >= action_deadline):
        return "timeout"
    return reason


def _header_reply(stdout, selected):
    result = load_json(stdout)
    action = spec.action(selected["configuration"], selected["case"])
    if (type(result) is not dict or set(result) != {"status", "results", "bytes_received", "truncated", "boundary_checks"}
            or type(result["status"]) is not str or result["status"] not in {"succeeded", "failed", "timeout", "output_limit"}
            or type(result["bytes_received"]) is not int or not 0 <= result["bytes_received"] <= 2048
            or type(result["truncated"]) is not bool or result["truncated"] != (result["status"] == "output_limit")
            or type(result["boundary_checks"]) is not dict or set(result["boundary_checks"]) != set(BOUNDARY_NAMES)
            or any(value is not True for value in result["boundary_checks"].values())
            or type(result["results"]) is not list or len(result["results"]) != 1):
        raise ValueError("invalid_stock_header_result")
    row = result["results"][0]
    if (type(row) is not dict or set(row) != {"target", "port", "bytes_received", "truncated", "raw_response", "response_sha256"}
            or row["target"] != action["target"] or type(row["port"]) is not int or row["port"] != action["parameters"]["port"]
            or type(row["bytes_received"]) is not int or row["bytes_received"] != result["bytes_received"]
            or row["truncated"] is not result["truncated"] or type(row["raw_response"]) is not str):
        raise ValueError("invalid_stock_header_result")
    raw = base64.b64decode(row["raw_response"], validate=True)
    if len(raw) != result["bytes_received"] or row["response_sha256"] != hashlib.sha256(raw).hexdigest():
        raise ValueError("invalid_stock_header_result")
    return result


def validate_client_runtime(value, selection):
    from .stock_http_contract import validate_selection
    selected = validate_selection(selection)
    if spec.action_kind(selected["case"]) == "headers":
        if value is not None:
            raise ValueError("stock_header_runtime_must_be_null")
        return None
    return native.validate_manifest(value, tool_id=native.NMAP_SERVICE)


def inspect_client_runtime(selection, control):
    from .stock_http_contract import validate_selection
    selected = validate_selection(selection)
    return (None if spec.action_kind(selected["case"]) == "headers"
            else native.inspect_tool_runtime(native.NMAP_SERVICE, control))


def runtime_source_mounts(value, selection):
    manifest = validate_client_runtime(value, selection)
    return [] if manifest is None else native.runtime_source_mounts(manifest)


def _command(lab, bootstrap, manifest, descriptors, nonce, commitment):
    stdlib, files = bootstrap
    selected_files = [] if manifest is None else native.runtime_files(manifest)
    selected_paths = {row["destination"] for row in selected_files}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
        "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1", "--chdir", "/",
        "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    forbidden = {"nft", "bwrap", "nsenter", "ip", "nmap", "ssh-keyscan", "nginx"}
    for source, destination in files:
        if destination not in selected_paths and Path(destination).name not in forbidden:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    for row, descriptor in zip(selected_files, descriptors, strict=True):
        mode = "0555" if row["destination"] in {manifest["executable"], manifest["interpreter"]} else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), row["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_http_client_worker.py", nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)) if descriptors else "0,1,2", *argv]


def run_stock_http_tool_owned(*, lab, launch, control, closure=None, manifest=None):
    from .routed import _Supervisor, _BudgetExceeded
    from .stock_http_contract import validate_selection
    if sys.platform != "linux" or type(control) is not ExecutionControl or control.clock is not time.monotonic:
        raise IsolationUnavailable("Stock diagnostic requires fixed Linux control")
    control.check()
    lab._check(control)
    lab._verify_pins()
    selected = validate_selection(launch["selection"])
    manifest = validate_client_runtime(manifest, selected)
    if closure is not None:
        pinned = validate_client_runtime(closure["stock_http_runtime"]["client"], selected)
        if pinned != manifest:
            raise IsolationUnavailable("Stock diagnostic client runtime changed")
    tool_id = launch["launch"]["action"]["tool_id"]
    if tool_id != spec.action(selected["configuration"], selected["case"])["tool_id"]:
        raise IsolationUnavailable("Stock diagnostic client tool changed")
    bootstrap = lab._runtime(control) if closure is None else (closure["stdlib"], [(p, p) for p in closure["files"]])
    if launch["runtime"]["client"] != manifest:
        raise IsolationUnavailable("Stock diagnostic launch runtime changed")
    raw = native.encode(launch)
    if len(raw) > 32768:
        raise IsolationUnavailable("Stock diagnostic launch packet exceeded limit")
    commitment = hashlib.sha256(raw).hexdigest()
    prefix = READY_PREFIX + commitment.encode("ascii") + b"\n"
    descriptors = [] if manifest is None else native._snapshot(manifest, control)
    supervisor = _Supervisor(min(STARTUP_SECONDS, control.remaining()), 8192 + len(prefix), control=control)
    started = time.monotonic()
    action_started = None
    reason = None
    try:
        proc = supervisor.launch("worker", _command(lab, bootstrap, manifest, descriptors,
            launch["launch"]["nonce"], commitment), pass_fds=(*lab._namespace_fds, *descriptors), stdin=subprocess.PIPE)
        _write_control(proc, raw + b"\n", supervisor)
        supervisor.wait_for(lambda: b"\n" in supervisor.buffers["worker_err"], worker_may_exit=True)
        if bytes(supervisor.buffers["worker_err"]) != prefix or supervisor.buffers["worker_out"]:
            raise IsolationUnavailable("Stock diagnostic confinement not verified")
        action_started = time.monotonic()
        action_deadline = min(control.deadline, action_started + spec.budgets(selected["case"])["tool_timeout_seconds"])
        lab.arm(control, action_deadline)
        supervisor.deadline = min(control.deadline, action_deadline + MARSHALLING_SECONDS)
        go = native.encode({"nonce": launch["launch"]["nonce"], "deadline": action_deadline}) + b"\n"
        _write_control(proc, go, supervisor, deadline=action_deadline)
        proc.stdin.close()
        supervisor.wait_for(lambda: proc.poll() is not None and {"worker_out", "worker_err"} <= supervisor.eof,
                            worker_may_exit=True)
    except _BudgetExceeded as error:
        if action_started is None:
            raise IsolationUnavailable("Stock diagnostic client startup exceeded bound") from error
        reason = error.status
    finally:
        try:
            supervisor.close()
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
    control.check()
    stdout, stderr = bytes(supervisor.buffers["worker_out"]), bytes(supervisor.buffers["worker_err"])
    if not stderr.startswith(prefix):
        raise IsolationUnavailable("Stock diagnostic confinement marker missing")
    stderr = stderr[len(prefix):]
    code = proc.returncode
    timing = {"client_startup_ms": round((action_started - started) * 1000),
              "action_elapsed_ms": round((time.monotonic() - action_started) * 1000)}
    if tool_id == HEADERS:
        if code != 0 or reason is not None or stderr:
            raise IsolationUnavailable("Stock diagnostic header worker failed")
        try:
            result = _header_reply(stdout, selected)
        except (ValueError, TypeError, RecursionError):
            raise IsolationUnavailable("Stock diagnostic header reply invalid") from None
        return {**result, "timing": timing}
    reason = _native_stop_reason(code, reason, action_deadline)
    if len(stdout) + len(stderr) > 8192:
        reason = "output_limit"
        stdout, stderr = stdout[:8192], stderr[:max(0, 8192 - len(stdout))]
    return {"status": reason or ("succeeded" if code == 0 else "failed"), "results": [], "tool_observation": None,
        "bytes_received": len(stdout) + len(stderr), "truncated": reason == "output_limit",
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), "timing": timing,
        "raw_output_base64": base64.b64encode(stdout).decode("ascii"),
        "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "provenance": {"runtime_sha256": native.manifest_digest(manifest), "runtime_manifest": manifest,
            "output_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "parser_version": parser_version(tool_id), "exit_code": code, "stop_reason": reason}}
