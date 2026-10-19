"""One witnessed fixed client, with no daemon secrets in its mounted closure."""

import base64
import hashlib
import os
from pathlib import Path
import subprocess
import time

from . import name_tls_contract as contract, name_tls_public as public
from . import name_tls_role_spec as roles, name_tls_native_runtime as native
from . import name_tls_python_runtime as sources
from .name_tls_client_worker import READY_PREFIX, BOUNDARY_NAMES
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _trusted_program
from .tool_runtime_common import sealed_snapshots, _CLOSE_EXCEPT

MODULES = ("worker", "tool_worker_common", "models", "tool_parameters", "tool_adapters", "session_limits",
           "name_tls_public", "name_tls_contract", "name_tls_role_spec", "name_tls_execution", "name_tls_client_worker",
           "name_tls_worker_common", "name_tls_topology_spec", *sources.PACKAGE_FILES)
FORBIDDEN_PROGRAMS = {"bwrap", "nsenter", "nft", "ip", "dnsmasq", "nginx", "apache2", "dig", "openssl",
                      "nmap", "ssh", "ssh-keyscan", "sshd", "sshd-session", "sshd-auth"}


def command(service, bootstrap, manifest, descriptors, nonce, commitment, *, source_descriptors, info_fd):
    operation = contract.operation(service.slot)
    selected = contract.validate_selection(service.selection)
    if operation == "http":
        if manifest is not None or descriptors:
            raise ValueError("name_tls_http_client_runtime")
        rows = []
    else:
        manifest = roles.validate_manifest(manifest, role=operation + "_client")
        if any(manifest[k] != selected[k] for k in ("configuration", "case")):
            raise ValueError("name_tls_client_runtime_selection")
        rows = manifest["files"]
    if len(descriptors) != len(rows) or len(set(descriptors)) != len(descriptors):
        raise ValueError("name_tls_client_snapshot_count")
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--as-pid-1",
        "--info-fd", str(info_fd), "--clearenv",
        "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1", "--chdir", "/",
        "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    destinations = {row["destination"] for row in rows}
    for source, destination in files:
        if destination not in destinations and Path(destination).name not in FORBIDDEN_PROGRAMS:
            argv += ["--ro-bind", source, destination]
    sources.mount_sources(argv, MODULES, source_descriptors)
    for row, descriptor in zip(rows, descriptors, strict=True):
        mode = "0555" if row["destination"] in (manifest["executable"], manifest["interpreter"]) else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), row["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/name_tls_client_worker.py", nonce, commitment]
    user_fd, net_fd = service.namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, (info_fd, *descriptors, *source_descriptors.values()))), *argv]


def run(*, service, launch, control, closure, manifest):
    from .routed import _Supervisor, _BudgetExceeded
    from .stock_ssh_client_runtime import _write_control, _native_stop_reason
    if type(control) is not ExecutionControl or control.clock is not time.monotonic:
        raise IsolationUnavailable("Name/TLS requires monotonic owned control")
    service.check(control)
    if (launch["mode"] != contract.PROFILE or launch["selection"] != service.selection
            or launch["identity"] != service.identity or launch["namespaces"] != service.namespaces
            or launch["runtime"] != manifest or closure["name_tls_runtime"] != service.runtime):
        raise IsolationUnavailable("Name/TLS client owner binding changed")
    operation = contract.operation(service.slot)
    expected = None if operation == "http" else service.runtime["roles"][operation + "_client"]
    if manifest != expected:
        raise IsolationUnavailable("Name/TLS client runtime changed")
    raw = public.encode(launch)
    if len(raw) > 32768:
        raise IsolationUnavailable("Name/TLS launch packet limit")
    commitment = hashlib.sha256(raw).hexdigest()
    prefix = READY_PREFIX + commitment.encode("ascii") + b"\n"
    descriptors, source_descriptors = [], {}
    maximum = contract.action_bounds(service.slot)["output_bytes"]
    supervisor = _Supervisor(max(.001, service.deadline - time.monotonic()), maximum + len(prefix), control=control)
    started, action_started, reason, proc = time.monotonic(), None, None, None
    try:
        descriptors = [] if manifest is None else sealed_snapshots(manifest, None, None, control,
            additional_compiled=native.compiled_snapshots(manifest))
        source_descriptors = sources.snapshot_sources(service.runtime, MODULES, control)
        bootstrap = (closure["stdlib"], [(path, path) for path in closure["files"]])
        read_fd, info_fd = supervisor.pipe()
        supervisor.watch(read_fd, "info")
        proc = supervisor.launch("worker", command(service, bootstrap, manifest, descriptors,
            launch["launch"]["nonce"], commitment, source_descriptors=source_descriptors, info_fd=info_fd),
            pass_fds=(*service.namespace_fds, *descriptors, *source_descriptors.values(), info_fd), stdin=subprocess.PIPE)
        supervisor.close_fd(info_fd)
        _write_control(proc, raw + b"\n", supervisor)
        supervisor.wait_for(lambda: b"\n" in supervisor.buffers["worker_err"], worker_may_exit=True)
        if bytes(supervisor.buffers["worker_err"]) != prefix or supervisor.buffers["worker_out"]:
            raise IsolationUnavailable("Name/TLS client confinement not verified")
        from .routing_services import _owner_info
        from .name_tls_daemon import launcher_mapping, client_ready
        from .isolation import _namespaces
        pins, directory, observed = _owner_info(supervisor, "info", _namespaces())
        if observed["net"] != service.namespaces["net"]:
            raise IsolationUnavailable("Name/TLS client network observation changed")
        mapping = launcher_mapping(directory, observed, pins)
        waiting_image = os.stat("exe", dir_fd=directory)
        waiting_image = (waiting_image.st_dev, waiting_image.st_ino)
        action_started = time.monotonic()
        action_deadline = min(service.deadline, control.deadline,
            action_started + contract.action_bounds(service.slot)["timeout_seconds"])
        supervisor.deadline = action_deadline
        _write_control(proc, public.encode({"nonce": launch["launch"]["nonce"], "deadline": action_deadline}) + b"\n",
                       supervisor, deadline=action_deadline)
        proc.stdin.close()
        native_observation = None
        if manifest is not None:
            observations = []
            def native_ready():
                found = client_ready(directory, observed, pins, manifest, operation, waiting_image=waiting_image)
                if found:
                    observations.append(found)
                return bool(found)
            supervisor.wait_for(native_ready)
            native_observation = observations[0]
        service.release(control, action_deadline)
        supervisor.wait_for(lambda: proc.poll() is not None and {"worker_out", "worker_err"} <= supervisor.eof,
                            worker_may_exit=True)
    except _BudgetExceeded as error:
        if action_started is None:
            raise IsolationUnavailable("Name/TLS client startup exceeded action bound") from error
        reason = error.status
    finally:
        try:
            supervisor.close()
        finally:
            for descriptor in (*descriptors, *source_descriptors.values()):
                os.close(descriptor)
    control.check()
    stdout, stderr = bytes(supervisor.buffers["worker_out"]), bytes(supervisor.buffers["worker_err"])
    if not stderr.startswith(prefix):
        raise IsolationUnavailable("Name/TLS client confinement marker missing")
    stderr = stderr[len(prefix):]
    code = proc.returncode
    reason = _native_stop_reason(code, reason, action_deadline)
    if len(stdout) + len(stderr) > maximum:
        reason = "output_limit"
        stdout, stderr = stdout[:maximum], stderr[:max(0, maximum - len(stdout))]
    return {"status": reason or ("succeeded" if code == 0 else "failed"), "results": [], "tool_observation": None,
        "bytes_received": len(stdout) + len(stderr), "truncated": reason == "output_limit",
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True),
        "client_observation": {"namespaces": observed, "mapping": mapping, "native_ready": native_observation},
        "timing": {"client_startup_ms": round((action_started - started) * 1000),
                   "action_elapsed_ms": round((time.monotonic() - action_started) * 1000)},
        "raw_output_base64": base64.b64encode(stdout).decode("ascii"),
        "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "provenance": {"runtime_sha256": None if manifest is None else roles.manifest_digest(manifest),
            "runtime_manifest": manifest, "output_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "parser_version": "owned-name-tls-parser-v1",
            "exit_code": code, "stop_reason": reason}}
