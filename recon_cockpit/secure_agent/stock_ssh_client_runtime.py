"""One stock SSH native client, released only after confined READY and owner GO."""

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
from . import stock_ssh_spec as spec, stock_ssh_contract as contract
from .stock_ssh_parser import NMAP, SSH, parser_version
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _trusted_program
from .models import load_json
from .tool_runtime_common import _CLOSE_EXCEPT


READY_PREFIX = b"RECON_STOCK_SSH_CLIENT_READY_V1 "
BOUNDARY_NAMES = ("cross_service_blocked", "other_configuration_blocked", "forbidden_ip_blocked",
    "forbidden_port_blocked", "excluded_destination_blocked", "namespace_creation_blocked",
    "capabilities_dropped", "no_new_privs", "root_read_only", "process_creation_blocked",
    "raw_sockets_blocked", "private_socket_blocked", "private_socket_mount_absent",
    "landlock_applied", "python_unreadable")
MODULES = tuple(dict.fromkeys((*existing.MODULES, "stock_http_spec", "stock_http_runtime",
    "stock_http_contract", "stock_http_execution", "network_tools_ssh_fixture",
    "stock_ssh_spec", "stock_ssh_runtime", "stock_ssh_process", "stock_ssh_contract",
    "stock_ssh_execution", "stock_ssh_nmap_spec", "stock_ssh_nmap_runtime", "stock_ssh_parser",
    "stock_ssh_client_worker", "stock_ssh_client_runtime")))


def boundary_names(selection):
    contract.validate_selection(selection)
    return BOUNDARY_NAMES


def underlying_tool(selection):
    selected = contract.validate_selection(selection)
    return native.NMAP_SERVICE if spec.action_kind(selected["case"]) == "nmap" else native.SSH


def client_runtime_module(selection):
    if underlying_tool(selection) == native.NMAP_SERVICE:
        from . import stock_ssh_nmap_runtime
        return stock_ssh_nmap_runtime
    return native


STARTUP_SECONDS = 10
MARSHALLING_SECONDS = 0.25


def _write_control(proc, raw, supervisor, *, deadline=None):
    """Bound pipe backpressure by the same supervisor/session deadlines."""
    from .routed import _BudgetExceeded
    if type(raw) is not bytes or not raw or len(raw) > 32769:
        raise IsolationUnavailable("Stock SSH control packet invalid")
    descriptor = proc.stdin.fileno()
    os.set_blocking(descriptor, False)
    offset = 0
    def writable():
        if deadline is not None and time.monotonic() >= deadline:
            raise _BudgetExceeded("timeout")
        if proc.poll() is not None:
            raise IsolationUnavailable("Stock SSH client exited before release")
        return bool(select.select([], [descriptor], [], 0)[1])
    while offset < len(raw):
        supervisor.check()
        supervisor.wait_for(writable, worker_may_exit=True)
        try:
            count = os.write(descriptor, raw[offset:])
        except BlockingIOError:
            continue
        except BrokenPipeError:
            raise IsolationUnavailable("Stock SSH control pipe closed") from None
        if count <= 0:
            raise IsolationUnavailable("Stock SSH control write incomplete")
        offset += count
    supervisor.check()


def _native_stop_reason(code, reason, action_deadline, *, now=None):
    now = time.monotonic() if now is None else now
    if (reason is None and code in (-signal.SIGALRM, 128 + signal.SIGALRM)
            and now >= action_deadline):
        return "timeout"
    return reason


def validate_client_runtime(value, selection):
    selected = contract.validate_selection(selection)
    return client_runtime_module(selected).validate_manifest(value, tool_id=underlying_tool(selected))


def inspect_client_runtime(selection, control):
    selected = contract.validate_selection(selection)
    runtime = client_runtime_module(selected)
    return (native.inspect_tool_runtime(native.SSH, control) if runtime is native
            else runtime.inspect_runtime(control))


def runtime_source_mounts(value, selection):
    manifest = validate_client_runtime(value, selection)
    return client_runtime_module(selection).runtime_source_mounts(manifest)


def _command(lab, bootstrap, manifest, descriptors, nonce, commitment):
    stdlib, files = bootstrap
    selected = contract.validate_selection(lab.selection)
    manifest = validate_client_runtime(manifest, selected)
    runtime = client_runtime_module(selected)
    selected_files = runtime.runtime_files(manifest)
    selected_paths = {row["destination"] for row in selected_files}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
        "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1", "--chdir", "/",
        "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    forbidden = {"nft", "bwrap", "nsenter", "ip", "nmap", "ssh-keyscan", "sshd", "sshd-session", "sshd-auth", "nginx", "apache2"}
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
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_ssh_client_worker.py", nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)) if descriptors else "0,1,2", *argv]


def run_stock_ssh_tool_owned(*, lab, launch, control, closure=None, manifest=None):
    from .routed import _Supervisor, _BudgetExceeded
    if sys.platform != "linux" or type(control) is not ExecutionControl or control.clock is not time.monotonic:
        raise IsolationUnavailable("Stock SSH requires fixed Linux control")
    control.check()
    lab._check(control)
    lab._verify_pins()
    if launch["mode"] != contract.PROFILE or launch["launch"]["mode"] != contract.PROFILE:
        raise IsolationUnavailable("Stock SSH client launch profile changed")
    selected = contract.validate_selection(launch["selection"])
    if (selected != lab.selection or launch["identity"] != lab.identity
            or launch["namespaces"] != lab._lab_namespaces):
        raise IsolationUnavailable("Stock SSH client owner binding changed")
    runtime = client_runtime_module(selected)
    manifest = validate_client_runtime(manifest, selected)
    if closure is not None:
        pinned = validate_client_runtime(closure["stock_ssh_runtime"]["client"], selected)
        if pinned != manifest:
            raise IsolationUnavailable("Stock SSH client runtime changed")
    tool_id = launch["launch"]["action"]["tool_id"]
    if tool_id != spec.action(selected["configuration"], selected["case"])["tool_id"]:
        raise IsolationUnavailable("Stock SSH client tool changed")
    bootstrap = lab._runtime(control) if closure is None else (closure["stdlib"], [(p, p) for p in closure["files"]])
    if launch["runtime"]["client"] != manifest:
        raise IsolationUnavailable("Stock SSH launch runtime changed")
    raw = native.encode(launch)
    if len(raw) > 32768:
        raise IsolationUnavailable("Stock SSH launch packet exceeded limit")
    commitment = hashlib.sha256(raw).hexdigest()
    prefix = READY_PREFIX + commitment.encode("ascii") + b"\n"
    descriptors = (native._snapshot(manifest, control) if runtime is native
                   else runtime.snapshot(manifest, control))
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
            raise IsolationUnavailable("Stock SSH confinement not verified")
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
            raise IsolationUnavailable("Stock SSH client startup exceeded bound") from error
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
        raise IsolationUnavailable("Stock SSH confinement marker missing")
    stderr = stderr[len(prefix):]
    code = proc.returncode
    timing = {"client_startup_ms": round((action_started - started) * 1000),
              "action_elapsed_ms": round((time.monotonic() - action_started) * 1000)}
    reason = _native_stop_reason(code, reason, action_deadline)
    if len(stdout) + len(stderr) > 8192:
        reason = "output_limit"
        stdout, stderr = stdout[:8192], stderr[:max(0, 8192 - len(stdout))]
    return {"status": reason or ("succeeded" if code == 0 else "failed"), "results": [], "tool_observation": None,
        "bytes_received": len(stdout) + len(stderr), "truncated": reason == "output_limit",
        "boundary_checks": dict.fromkeys(boundary_names(selected), True), "timing": timing,
        "raw_output_base64": base64.b64encode(stdout).decode("ascii"),
        "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "provenance": {"runtime_sha256": runtime.manifest_digest(manifest), "runtime_manifest": manifest,
            "output_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "parser_version": parser_version(tool_id), "exit_code": code, "stop_reason": reason}}
