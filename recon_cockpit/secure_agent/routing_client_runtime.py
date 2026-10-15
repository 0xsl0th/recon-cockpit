"""Fresh fixed-action clients in their exact routed client namespace."""

import base64
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

from . import routing_contract as contract, network_tools_runtime as native
from . import stock_http_client_runtime as http, stock_ssh_client_runtime as ssh
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _trusted_program
from .models import load_json
from .tool_runtime_common import _CLOSE_EXCEPT

READY_PREFIX = b"RECON_ROUTING_CLIENT_READY_V1 "
BOUNDARY_NAMES = ("other_service_blocked", "excluded_destination_blocked", "wrong_port_blocked",
    "namespace_creation_blocked", "capabilities_dropped", "no_new_privs", "root_read_only",
    "process_creation_blocked", "raw_sockets_blocked", "private_socket_blocked",
    "private_socket_mount_absent", "routed_namespace_verified", "landlock_applied", "python_unreadable")
MODULES = tuple(dict.fromkeys((*http.MODULES, *http.PRODUCTION_MODULES, *ssh.MODULES,
    "routing_contract", "routing_topology_spec", "routing_execution", "routing_client_runtime", "routing_client_worker")))
STARTUP_SECONDS = 10
MARSHALLING_SECONDS = .25


def client_adapter(selector):
    return http if contract.selector_role(selector) == "http_frontend" else ssh


def client_runtime_module(selector):
    return client_adapter(selector).client_runtime_module(contract.underlying_selection(selector))


def validate_client_runtime(value, selector):
    return client_adapter(selector).validate_client_runtime(value, contract.underlying_selection(selector))


def parser_version(selector):
    from .configurable_parser import parser_version as http_version
    from .stock_ssh_parser import parser_version as ssh_version
    action = contract.underlying_contract(selector).action(contract.underlying_selection(selector))
    return (http_version if selector.startswith("http_") else ssh_version)(action["tool_id"])


def boundary_names(selector):
    contract.validate_selector(selector)
    return BOUNDARY_NAMES


def command(service, bootstrap, manifest, descriptors, nonce, commitment):
    selector = contract.validate_selector(service.selector)
    manifest = validate_client_runtime(manifest, selector)
    selected_files = [] if manifest is None else client_runtime_module(selector).runtime_files(manifest)
    if len(descriptors) != len(selected_files):
        raise ValueError("routing_client_snapshot_count_changed")
    paths = {row["destination"] for row in selected_files}
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
        "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1", "--chdir", "/",
        "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    forbidden = {"nft", "bwrap", "nsenter", "ip", "nmap", "ssh-keyscan", "sshd", "sshd-session", "sshd-auth", "nginx", "apache2"}
    for source, destination in files:
        if destination not in paths and Path(destination).name not in forbidden:
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
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/routing_client_worker.py", nonce, commitment]
    user_fd, net_fd = service.namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)) if descriptors else "0,1,2", *argv]


def header_reply(raw, selector):
    if selector != "http_headers":
        raise ValueError("routing_not_headers")
    value = load_json(raw)
    if (type(value) is not dict or type(value.get("boundary_checks")) is not dict
            or set(value["boundary_checks"]) != set(BOUNDARY_NAMES)
            or any(flag is not True for flag in value["boundary_checks"].values())):
        raise ValueError("routing_header_boundary_changed")
    # Preserve the accepted header shape/limits; only its topology witnesses differ.
    selected = contract.underlying_selection(selector)
    original = value["boundary_checks"]
    value["boundary_checks"] = dict.fromkeys(http.boundary_names(selected), True)
    checked = http._header_reply(native.encode(value), selected)
    checked["boundary_checks"] = original
    return checked


def run_routed_tool_owned(*, service, launch, control, closure, manifest):
    from .routed import _Supervisor, _BudgetExceeded
    if sys.platform != "linux" or type(control) is not ExecutionControl or control.clock is not time.monotonic:
        raise IsolationUnavailable("Routing requires fixed Linux control")
    control.check()
    service.check(control)
    selector = contract.validate_selector(service.selector)
    if (launch["mode"] != contract.PROFILE or launch["launch"]["mode"] != contract.PROFILE
            or launch["selector"] != selector or launch["selection"] != service.selection
            or launch["identity"] != service.identity or launch["namespaces"] != service.namespaces):
        raise IsolationUnavailable("Routed client owner binding changed")
    manifest = validate_client_runtime(manifest, selector)
    if launch["runtime"]["client"] != manifest or closure["routing_runtime"][selector]["client"] != manifest:
        raise IsolationUnavailable("Routed client runtime changed")
    raw = native.encode(launch)
    if len(raw) > 32768:
        raise IsolationUnavailable("Routed client launch packet limit")
    commitment = hashlib.sha256(raw).hexdigest()
    prefix = READY_PREFIX + commitment.encode("ascii") + b"\n"
    runtime = client_runtime_module(selector)
    descriptors = [] if manifest is None else (native._snapshot(manifest, control) if runtime is native else runtime.snapshot(manifest, control))
    maximum = contract.action_bounds(selector)["output_bytes"]
    # Header JSON carries base64 for 2048 raw bytes plus bounded metadata.
    capture_limit = 8192 if selector == "http_headers" else maximum
    supervisor = _Supervisor(min(STARTUP_SECONDS, control.remaining()), capture_limit + len(prefix), control=control)
    started, action_started, reason = time.monotonic(), None, None
    try:
        bootstrap = (closure["stdlib"], [(path, path) for path in closure["files"]])
        proc = supervisor.launch("worker", command(service, bootstrap, manifest, descriptors,
            launch["launch"]["nonce"], commitment), pass_fds=(*service.namespace_fds, *descriptors), stdin=subprocess.PIPE)
        ssh._write_control(proc, raw + b"\n", supervisor)
        supervisor.wait_for(lambda: b"\n" in supervisor.buffers["worker_err"], worker_may_exit=True)
        if bytes(supervisor.buffers["worker_err"]) != prefix or supervisor.buffers["worker_out"]:
            raise IsolationUnavailable("Routed client confinement not verified")
        action_started = time.monotonic()
        action_deadline = min(control.deadline, action_started + contract.action_bounds(selector)["timeout_seconds"])
        service.arm(control, action_deadline)
        supervisor.deadline = min(control.deadline, action_deadline + MARSHALLING_SECONDS)
        ssh._write_control(proc, native.encode({"nonce": launch["launch"]["nonce"], "deadline": action_deadline}) + b"\n",
                           supervisor, deadline=action_deadline)
        proc.stdin.close()
        supervisor.wait_for(lambda: proc.poll() is not None and {"worker_out", "worker_err"} <= supervisor.eof, worker_may_exit=True)
    except _BudgetExceeded as error:
        if action_started is None:
            raise IsolationUnavailable("Routed client startup exceeded bound") from error
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
        raise IsolationUnavailable("Routed client confinement marker missing")
    stderr = stderr[len(prefix):]
    code = proc.returncode
    timing = {"client_startup_ms": round((action_started - started) * 1000),
              "action_elapsed_ms": round((time.monotonic() - action_started) * 1000)}
    if selector == "http_headers":
        if code != 0 or reason is not None or stderr:
            raise IsolationUnavailable("Routed header worker failed")
        return {**header_reply(stdout, selector), "timing": timing}
    reason = ssh._native_stop_reason(code, reason, action_deadline)
    if len(stdout) + len(stderr) > maximum:
        reason = "output_limit"
        stdout, stderr = stdout[:maximum], stderr[:max(0, maximum - len(stdout))]
    return {"status": reason or ("succeeded" if code == 0 else "failed"), "results": [], "tool_observation": None,
        "bytes_received": len(stdout) + len(stderr), "truncated": reason == "output_limit",
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), "timing": timing,
        "raw_output_base64": base64.b64encode(stdout).decode("ascii"), "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "provenance": {"runtime_sha256": runtime.manifest_digest(manifest), "runtime_manifest": manifest,
            "output_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "parser_version": parser_version(selector), "exit_code": code, "stop_reason": reason}}
