"""Bounded, owned-only TLS development diagnostic, outside the product catalog.

This is a feasibility instrument, not a policy/approval executor. It never
accepts targets, arguments, credentials or attachment to an existing lab. Each
call creates and destroys one disconnected owned namespace, then returns raw
client and owner observations without converting them into production evidence.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import uuid4

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _trusted_program
from .owned_lab import OwnedLab
from .routed import _Supervisor, _pin_namespaces
from .session_limits import SessionLimits
from .tool_runtime_common import sealed_snapshots, _CLOSE_EXCEPT
from . import tls_posture_diagnostic_worker as fixed


CASES = ("modern", "legacy", "reject", "hrr")
MAX_OWNER_MESSAGE = 262144
MAX_OWNER_OUTPUT = MAX_OWNER_MESSAGE + 8192
SESSION_SECONDS = 30


def validate_selection(case, version):
    if (type(case) is not str or case not in CASES
            or type(version) is not str or version not in fixed.VERSIONS
            or (case == "hrr" and version != "tls1_3")):
        raise ValueError("invalid_tls_diagnostic_selection")


def inspect_runtime(control):
    from . import network_tools_runtime as accepted
    manifest = accepted.inspect_tool_runtime(accepted.TLS_CERTIFICATE, control)
    return fixed.validate_manifest({"version": "1", "profile": fixed.PROFILE,
        "executable": manifest["executable"], "interpreter": manifest["interpreter"],
        "files": accepted.runtime_files(manifest)})


class DiagnosticLab(OwnedLab):
    """Existing namespace lifecycle with a separate bounded owner transcript."""

    def __init__(self, case, version):
        validate_selection(case, version)
        self.version = version
        super().__init__(case, str(uuid4()), SessionLimits(1, SESSION_SECONDS, fixed.MAX_OUTPUT_BYTES))

    def _make_identity(self, case, instance_id):
        return {"scenario": case, "instance_id": instance_id, "diagnostic_only": True}

    def _owner_request(self, host, control):
        return {"case": self.identity["scenario"], "version": self.version,
                "deadline": control.deadline, "host_namespaces": host}

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).parent
        mounts = []
        for name in ("tls_posture_diagnostic_fixture.py", "network_tools_tls_certificate_material.py",
                     "network_tools_fixture.py", "network_tools_dns_mx_fixture.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        # OPENSSL_CONF is process-local for the synthetic legacy owner only.
        argv[1:1] = ["--setenv", "OPENSSL_CONF", "/dev/null"]
        argv[argv.index("--remount-ro"):argv.index("--remount-ro")] = mounts
        argv[-1] = "/app/tls_posture_diagnostic_fixture.py"
        return argv

    def _read_message(self):
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b"\n" in supervisor.buffers["lab_out"][self._offset:])
        buffered = supervisor.buffers["lab_out"]
        end = buffered.index(b"\n", self._offset) + 1
        raw = bytes(buffered[self._offset:end])
        if len(raw) > MAX_OWNER_MESSAGE:
            raise IsolationUnavailable("TLS diagnostic owner transcript exceeded its bound")
        self._offset = end
        return json.loads(raw, object_pairs_hook=fixed._unique)

    def start(self, control):
        # Kept separate from OwnedLab.start so a larger, finite owner transcript
        # allowance never changes the accepted management or client limits.
        with self._lock:
            try:
                self._check(control)
                if self._started:
                    raise IsolationUnavailable("TLS diagnostic lab cannot be restarted")
                if control.remaining() > SESSION_SECONDS:
                    raise IsolationUnavailable("TLS diagnostic session exceeds its bound")
                self._control = control
                self._check_available()
                host = _namespaces()
                stdlib, files = self._runtime(control)
                self._bootstrap = stdlib, files
                self._supervisor = _Supervisor(control.remaining(), MAX_OWNER_OUTPUT, control=control)
                info_r, info_w = self._supervisor.pipe()
                self._supervisor.watch(info_r, "info")
                proc = self._supervisor.launch("lab", self._owner_command(stdlib, files, info_w),
                    pass_fds=(info_w,), stdin=subprocess.PIPE)
                self._supervisor.close_fd(info_w)
                proc.stdin.write(fixed.encode(self._owner_request(host, control)) + b"\n")
                ready = self._read_message()
                self._supervisor.wait_for(lambda: "info" in self._supervisor.eof)
                if (type(ready) is not dict
                        or set(ready) != {"ready", "namespaces", "witness_baselines", "connection_count", "request_count"}
                        or ready["ready"] is not True or ready["witness_baselines"] is not True
                        or type(ready["connection_count"]) is not int or ready["connection_count"] != 0
                        or type(ready["request_count"]) is not int or ready["request_count"] != 0):
                    raise IsolationUnavailable("TLS diagnostic owner readiness failed")
                self._namespace_fds = _pin_namespaces(bytes(self._supervisor.buffers["info"]), host)
                self._supervisor.fds.update(self._namespace_fds)
                metadata = json.loads(bytes(self._supervisor.buffers["info"]))
                observed = {name: os.readlink(f"/proc/{metadata['child-pid']}/ns/{name}") for name in host}
                if ready["namespaces"] != observed or any(observed[name] == host[name] for name in host):
                    raise IsolationUnavailable("TLS diagnostic owner namespace identity failed")
                self._lab_namespaces, self._started = observed, True
                self._verify_pins()
            except BaseException:
                self.close()
                raise

    def snapshot(self, control):
        self._check(control)
        self._verify_pins()
        if self._sequence:
            raise IsolationUnavailable("TLS diagnostic snapshot is single-use")
        self._sequence = 1
        self._supervisor.processes["lab"].stdin.write(fixed.encode({"sequence": 1,
            "minimum_connections": 0, "minimum_requests": 0}) + b"\n")
        value = self._read_message()
        if (type(value) is not dict
                or set(value) != {"sequence", "connection_count", "request_count", "diagnostic"}
                or type(value["sequence"]) is not int or value["sequence"] != 1
                or any(type(value[key]) is not int or not 0 <= value[key] <= 2
                       for key in ("connection_count", "request_count"))
                or type(value["diagnostic"]) is not dict):
            raise IsolationUnavailable("TLS diagnostic owner receipt invalid")
        self._counts = {key: value[key] for key in self._counts}
        return {key: item for key, item in value.items() if key != "sequence"}


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
    for name in ("worker.py", "tool_worker_common.py", "tls_posture_diagnostic_worker.py", "__init__.py"):
        argv += ["--ro-bind", str(directory / name), "/app/recon_cockpit/secure_agent/" + name]
    argv += ["--ro-bind", str(directory / "__init__.py"), "/app/recon_cockpit/__init__.py"]
    for item, descriptor in zip(manifest["files"], descriptors, strict=True):
        mode = "0555" if item["destination"] in {manifest["executable"], manifest["interpreter"]} else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), item["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/tls_posture_diagnostic_worker.py", commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)), *argv]


def run_trial(case, version):
    """Run one fixed development trial; return raw observations after cleanup."""
    validate_selection(case, version)
    control = ExecutionControl(time.monotonic() + SESSION_SECONDS)
    manifest = inspect_runtime(control)
    from .network_tools_fixture import TLS_CERTIFICATE_CA_PEM
    descriptors = sealed_snapshots(manifest, "compiled:fixture-ca", TLS_CERTIFICATE_CA_PEM, control)
    lab = DiagnosticLab(case, version)
    result = None
    try:
        lab.start(control)
        request = {"version": version, "deadline": min(time.monotonic() + 5, control.deadline),
            "host_namespaces": _namespaces(), "lab_namespaces": lab._lab_namespaces, "manifest": manifest}
        raw = fixed.encode(request)
        commitment = hashlib.sha256(raw).hexdigest()
        fixed.validate_request(raw, commitment)
        prefix = fixed.READY_PREFIX + commitment.encode("ascii") + b"\n"
        started = time.monotonic()
        code, stdout, stderr, reason = _capture_bounded(client_command(lab, manifest, descriptors, commitment),
            raw, max(0, request["deadline"] - time.monotonic()), fixed.MAX_OUTPUT_BYTES + len(prefix),
            control=control, pass_fds=(*lab._namespace_fds, *descriptors))
        elapsed = round((time.monotonic() - started) * 1000)
        ready = stderr.startswith(prefix)
        if ready:
            stderr = stderr[len(prefix):]
        if len(stdout) + len(stderr) > fixed.MAX_OUTPUT_BYTES:
            reason = "output_limit"
            stdout = stdout[:fixed.MAX_OUTPUT_BYTES]
            stderr = stderr[:fixed.MAX_OUTPUT_BYTES - len(stdout)]
        owner = lab.snapshot(control)
        result = {"schema_version": "1", "diagnostic_only": True, "case": case, "version": version,
            "argv": list(fixed.FIXED_ARGV[version]), "runtime_manifest": manifest,
            "runtime_sha256": hashlib.sha256(fixed.encode(manifest)).hexdigest(),
            "execution": {"exit_code": code, "stop_reason": reason, "elapsed_ms": elapsed,
                "raw_stdout_base64": base64.b64encode(stdout).decode("ascii"),
                "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
                "truncated": reason == "output_limit"},
            "owner": owner, "confinement": {"worker_ready": ready,
                "private_namespaces_and_firewall": ready, "read_only_pinned_runtime": ready,
                "landlock_and_seccomp": ready, "no_inherited_descriptors": ready},
            "actual_provider_calls": 0, "actual_cost_microusd": 0,
            "cleanup": {"closed": False}}
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        closure = lab.close()
        if result is not None:
            result["cleanup"] = {"closed": closure["status"] == "closed"}
    return result
