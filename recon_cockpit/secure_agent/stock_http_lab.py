"""Separately supervised recorder and pinned stock nginx in disposable owners."""

import array
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import threading
import time
from uuid import uuid4

from . import stock_http_contract as contract, stock_http_spec as spec, stock_http_runtime as runtime
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces, _runtime_files, _trusted_program
from .routed import _Supervisor, _pin_namespaces
from .session_limits import SessionLimits
from .tool_runtime_common import sealed_snapshots
from .stock_http_owner_worker import BOUNDS, DAEMON_READY, MAX_PACKET, SCRATCH_BYTES, decode, encode

MODULES = ("worker", "tool_worker_common", "stock_http_spec", "stock_http_runtime",
           "stock_http_owner_worker", "stock_http_recorder", "configurable_contract",
           "configurable_scope", "models", "tool_parameters", "tool_adapters", "isolation", "execution")


def _mount_modules(argv):
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]


def _base_command(bootstrap, *, recorder, info_fd=None):
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0",
        "--cap-drop", "ALL", "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--as-pid-1",
        "--clearenv", "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1",
        "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    if recorder:
        argv += ["--cap-add", "CAP_NET_ADMIN", "--info-fd", str(info_fd),
                 "--perms", "0700", "--size", str(SCRATCH_BYTES), "--tmpfs", "/scratch",
                 "--perms", "0700", "--size", str(SCRATCH_BYTES), "--tmpfs", "/peer"]
    for source, destination in files:
        if Path(destination).name not in {"bwrap", "nsenter", "ip", "nginx"} and (recorder or Path(destination).name != "nft"):
            argv += ["--ro-bind", source, destination]
    _mount_modules(argv)
    return argv


def recorder_command(bootstrap, info_fd):
    argv = _base_command(bootstrap, recorder=True, info_fd=info_fd)
    return argv + ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_http_owner_worker.py", "recorder"]


def daemon_command(bootstrap, manifest, descriptors, peer_fd):
    runtime.validate_manifest(manifest)
    if len(descriptors) != len(manifest["files"]):
        raise ValueError("stock_daemon_snapshot_count_changed")
    argv = _base_command(bootstrap, recorder=False)
    for item, descriptor in zip(manifest["files"], descriptors, strict=True):
        mode = "0555" if item["destination"] in (manifest["executable"], manifest["interpreter"]) else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), item["destination"]]
    argv += ["--bind-fd", str(peer_fd), "/scratch"]
    for name, value in spec.NGINX_ENVIRONMENT.items():
        argv += ["--setenv", name, value]
    return argv + ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_http_owner_worker.py", "daemon"]


class StockHttpLab:
    """One-use metadata until the independently authorized backend calls start."""

    def __init__(self, selection, session_id, limits, *, execute=True, runtime=None, identity=None, closure=None):
        self.selection = contract.validate_selection(selection)
        if type(limits) is not SessionLimits or type(execute) is not bool:
            raise ValueError("invalid_stock_http_lab")
        contract.validate_limits(asdict(limits), self.selection)
        self.session_id, self.limits, self.execute = session_id, limits, execute
        self._stock_http_runtime = contract.validate_runtime(runtime, self.selection)
        self._identity = contract.validate_identity(identity or {
            "version": "1", "profile": contract.PROFILE, "instance_id": str(uuid4()), "session_id": session_id,
            **self.selection, **contract.runtime_digests(self._stock_http_runtime, self.selection)},
            selection=self.selection, session_id=session_id, runtime=self._stock_http_runtime)
        self._closure = closure
        self._control = self._supervisor = self._channel = None
        self._namespace_fds, self._lab_namespaces = (), {}
        self._peer_fd = None
        self._started = self._closed = False
        self._sequence = 0
        self._owner = self._last_snapshot = self._receipt = None
        self._lock = threading.RLock()

    @property
    def identity(self):
        return deepcopy(self._identity)

    @property
    def runtime(self):
        return contract.validate_runtime(self._stock_http_runtime, self.selection)

    @property
    def started(self):
        return self._started

    def __enter__(self):
        if self._closed:
            raise IsolationUnavailable("Stock HTTP owner permanently closed")
        return self

    def __exit__(self, *_):
        self.close()

    def _check_available(self):
        if self._closure is None:
            LinuxFixtureBackend().check_available()
        for name in ("bwrap", "nft", "nsenter"):
            _trusted_program(name)
        if Path(_trusted_program("bwrap")).stat().st_mode & stat.S_ISUID:
            raise IsolationUnavailable("Stock HTTP requires non-setuid Bubblewrap")

    def _runtime(self, control):
        control.check()
        if self._closure is None:
            return _runtime_files("/usr/bin/python3", _trusted_program("nft"), control=control)
        from .owned_launcher_runtime import runtime as bootstrap
        return bootstrap(self._closure, owner=True)

    def _check(self, control):
        if (self._closed or not self.execute or type(control) is not ExecutionControl
                or control.clock is not time.monotonic or (self._control is not None and control is not self._control)):
            raise IsolationUnavailable("Stock HTTP owner control changed")
        control.check()
        contract.validate_identity(self._identity, selection=self.selection, session_id=self.session_id,
                                   runtime=self.runtime)
        if self._supervisor is not None:
            self._supervisor.check()
            if any(process.poll() is not None for process in self._supervisor.processes.values()):
                raise IsolationUnavailable("Stock HTTP owner process exited")

    def _verify_pins(self):
        if len(self._namespace_fds) != 2:
            raise IsolationUnavailable("Stock HTTP namespace descriptors missing")
        for name, descriptor in zip(("user", "net"), self._namespace_fds, strict=True):
            if os.readlink("/proc/self/fd/" + str(descriptor)) != self._lab_namespaces[name]:
                raise IsolationUnavailable("Stock HTTP namespace descriptor changed")

    def _send(self, value):
        raw = encode(value)
        while True:
            self._control.check()
            if select.select([], [self._channel], [], min(0.05, self._control.remaining()))[1]:
                if self._channel.send(raw) != len(raw):
                    raise IsolationUnavailable("Stock HTTP control send truncated")
                return

    def _receive(self, *, directory=False):
        self._supervisor.wait_for(lambda: bool(select.select([self._channel], [], [], 0)[0]))
        raw, ancillary, flags, _ = self._channel.recvmsg(MAX_PACKET + 1, socket.CMSG_SPACE(8 * 4), socket.MSG_CMSG_CLOEXEC)
        descriptors = []
        try:
            invalid_ancillary = False
            for level, kind, data in ancillary:
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                    invalid_ancillary = True
                    continue
                items = array.array("i")
                if len(data) % items.itemsize:
                    invalid_ancillary = True
                items.frombytes(data[:len(data) - len(data) % items.itemsize])
                descriptors += items.tolist()
            if (invalid_ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    or len(descriptors) != int(directory)):
                raise ValueError("stock_owner_invalid_descriptor_count")
            value = decode(raw)
            if directory:
                descriptor = descriptors[0]
                info, usage = os.fstat(descriptor), os.fstatvfs(descriptor)
                if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                        or usage.f_blocks * usage.f_frsize != SCRATCH_BYTES):
                    raise ValueError("stock_owner_invalid_shared_scratch")
                self._peer_fd = descriptor
                self._supervisor.fds.add(descriptor)
                descriptors.pop()
            return value
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def _command(self, operation, **fields):
        self._sequence += 1
        self._send({"sequence": self._sequence, "operation": operation, **fields})
        reply = self._receive()
        if (set(reply) != {"sequence", "operation", "recorder"} or reply["sequence"] != self._sequence
                or reply["operation"] != operation or type(reply["recorder"]) is not dict):
            raise IsolationUnavailable("Stock HTTP owner reply changed")
        return reply["recorder"]

    def start(self, control):
        with self._lock:
            try:
                self._check(control)
                if self._started:
                    self._verify_pins()
                    return
                if control.remaining() > 60:
                    raise IsolationUnavailable("Stock HTTP lifetime exceeds contract")
                self._control = control
                self._check_available()
                bootstrap = self._runtime(control)
                # 768 KiB private files + 256 KiB retained evidence per owner.
                # This shared capture is at most64 KiB; control/replay snapshots
                # each have a separate64 KiB bound and only the latest is kept.
                self._supervisor = _Supervisor(control.remaining(), 65536, control=control)
                info_read, info_write = self._supervisor.pipe()
                self._supervisor.watch(info_read, "info")
                self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                self._channel.setblocking(False)
                try:
                    self._supervisor.launch("lab", recorder_command(bootstrap, info_write), stdin=child, pass_fds=(info_write,))
                finally:
                    child.close()
                    self._supervisor.close_fd(info_write)
                host = _namespaces()
                initial = {"configuration": self.selection["configuration"], "case": self.selection["case"],
                    "deadline": control.deadline, "host_namespaces": host,
                    "runtime_digest": self._identity["daemon_runtime_sha256"]}
                self._send(initial)
                ready = self._receive(directory=True)
                if (set(ready) != {"ready", "namespaces", "witness_baselines", "bounds", "runtime_digest"}
                        or ready["ready"] is not True or ready["witness_baselines"] is not True
                        or ready["bounds"] != BOUNDS or ready["runtime_digest"] != initial["runtime_digest"]):
                    raise IsolationUnavailable("Stock HTTP recorder readiness invalid")
                self._supervisor.wait_for(lambda: "info" in self._supervisor.eof)
                info = bytes(self._supervisor.buffers["info"])
                self._namespace_fds = _pin_namespaces(info, host)
                self._supervisor.fds.update(self._namespace_fds)
                pid = json.loads(info)["child-pid"]
                self._lab_namespaces = {name: os.readlink(f"/proc/{pid}/ns/{name}") for name in host}
                if ready["namespaces"] != self._lab_namespaces or any(self._lab_namespaces[name] == host[name] for name in host):
                    raise IsolationUnavailable("Stock HTTP recorder namespace changed")
                manifest = self.runtime["daemon"]
                compiled = tuple((source, raw) for source, _destination, raw in
                                 spec.compiled_files(self.selection["configuration"], self.selection["case"]))
                descriptors = sealed_snapshots(manifest, None, None, control, additional_compiled=compiled)
                try:
                    daemon = self._supervisor.launch("daemon", daemon_command(bootstrap, manifest, descriptors, self._peer_fd),
                        pass_fds=(*descriptors, self._peer_fd), stdin=subprocess.PIPE)
                    daemon.stdin.write(encode({**initial, "manifest": manifest}))
                    daemon.stdin.close()
                finally:
                    for descriptor in descriptors:
                        os.close(descriptor)
                self._supervisor.close_fd(self._peer_fd)
                self._peer_fd = None
                self._supervisor.wait_for(lambda: b"\n" in self._supervisor.buffers["daemon_out"])
                line = bytes(self._supervisor.buffers["daemon_out"]).split(b"\n", 1)[0]
                if not line.startswith(DAEMON_READY):
                    raise IsolationUnavailable("Stock HTTP daemon confinement missing")
                daemon_ready = decode(line[len(DAEMON_READY):])
                if (set(daemon_ready) != {"namespaces", "bounds", "runtime_digest"}
                        or daemon_ready["bounds"] != BOUNDS or daemon_ready["runtime_digest"] != initial["runtime_digest"]
                        or set(daemon_ready["namespaces"]) != set(host)
                        or any(daemon_ready["namespaces"][name] in (host[name], self._lab_namespaces[name]) for name in host)):
                    raise IsolationUnavailable("Stock HTTP daemon namespace or resource binding changed")
                # Socket creation follows the bootstrap marker. Poll a bounded
                # owner-side stat, never connect or send an extra nginx request.
                self._owner = {"recorder_namespaces": self._lab_namespaces,
                    "daemon_namespaces": daemon_ready["namespaces"], "witness_baselines": True,
                    "recorder_bounds": dict(BOUNDS), "daemon_bounds": dict(BOUNDS),
                    "private_socket_unmounted_from_client": True, "daemon_ready": True}
                self._started = True
                self._verify_pins()
                self._last_snapshot = self._snapshot(self._command("ready"))
            except BaseException:
                self.close()
                raise

    def _snapshot(self, recorder):
        return {"connection_count": recorder["connections_admitted"],
                "request_count": recorder["requests_delivered"], "recorder": recorder, "owner": deepcopy(self._owner)}

    def arm(self, control, action_deadline):
        with self._lock:
            self._check(control)
            self._verify_pins()
            self._last_snapshot = self._snapshot(self._command("arm", deadline=action_deadline))
            return deepcopy(self._last_snapshot)

    def snapshot(self, control, **minimum_counts):
        """Finalize forwarding after the sole client action, then retain counts."""
        with self._lock:
            self._check(control)
            self._verify_pins()
            if not set(minimum_counts) <= {"minimum_connections", "minimum_requests"}:
                raise ValueError("invalid_stock_owner_counter_barrier")
            self._last_snapshot = self._snapshot(self._command("finish"))
            for argument, field in (("minimum_connections", "connection_count"), ("minimum_requests", "request_count")):
                minimum = minimum_counts.get(argument, 0)
                if type(minimum) is not int or minimum < 0 or self._last_snapshot[field] < minimum:
                    raise IsolationUnavailable("Stock HTTP counters did not settle")
            return deepcopy(self._last_snapshot)

    def close(self):
        with self._lock:
            if self._receipt is not None:
                return deepcopy(self._receipt)
            self._closed = True
            if self._channel is not None:
                self._channel.close()
                self._channel = None
            if self._supervisor is not None:
                self._supervisor.close()
                if any(process.poll() is None for process in self._supervisor.processes.values()):
                    raise IsolationUnavailable("Stock HTTP owner cleanup incomplete")
            self._namespace_fds = ()
            self._peer_fd = None
            snapshot = self._last_snapshot or {"connection_count": 0, "request_count": 0, "recorder": None}
            self._receipt = {"identity": self.identity, "status": "closed", "started": self._started,
                "connection_count": snapshot["connection_count"], "request_count": snapshot["request_count"],
                "recorder": snapshot["recorder"], "processes_reaped": True, "namespace_descriptors_closed": True}
            return deepcopy(self._receipt)


class ConfinedStockHttpLab(StockHttpLab):
    def __init__(self, config, closure):
        super().__init__(config["case"], config["session_id"], SessionLimits(**config["limits"]),
            execute=config["execute"], runtime=closure["stock_http_runtime"], identity=config["owned_lab"], closure=closure)
