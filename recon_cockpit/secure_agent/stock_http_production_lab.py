"""Production HTTP owners, with one-use Apache namespace socket custody."""

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

from . import stock_http_production_contract as contract, stock_http_spec as spec
from . import stock_http_runtime as runtime, stock_apache_spec as apache, stock_apache_runtime
from .stock_http_production_transport import receive_packet, send_packet, socket_identity, owned_socket
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces, _runtime_files, _trusted_program
from .routed import _Supervisor, _pin_namespaces
from .session_limits import SessionLimits
from .tool_runtime_common import sealed_snapshots
from .stock_http_production_owner_worker import BOUNDS, DAEMON_READY, MAX_PACKET, SCRATCH_BYTES, decode, encode

MODULES = ("worker", "tool_worker_common", "stock_http_spec", "stock_http_runtime",
           "stock_http_owner_worker", "stock_http_recorder", "configurable_contract",
           "configurable_scope", "models", "tool_parameters", "tool_adapters", "isolation", "execution",
           "stock_http_contract", "stock_http_production_contract", "stock_apache_spec", "stock_apache_runtime",
           "stock_http_production_transport", "stock_http_production_owner_worker")


def _mount_modules(argv):
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]


def _base_command(bootstrap, *, recorder, implementation, info_fd):
    if implementation not in ("nginx", "apache"):
        raise ValueError("stock_production_unknown_implementation")
    stdlib, files = bootstrap
    uid = 0 if recorder or implementation == "nginx" else apache.NAMESPACE_UID
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--uid", str(uid), "--gid", str(uid),
        "--cap-drop", "ALL", "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--as-pid-1",
        "--info-fd", str(info_fd), "--clearenv", "--setenv", "LC_ALL", "C",
        "--setenv", "MALLOC_ARENA_MAX", "1", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
        "--ro-bind", stdlib, stdlib]
    if recorder:
        argv += ["--cap-add", "CAP_NET_ADMIN", "--perms", "0700", "--size", str(SCRATCH_BYTES), "--tmpfs", "/scratch"]
        if implementation == "nginx":
            argv += ["--ro-bind", "/stock-peer", "/peer"]
    for source, destination in files:
        if Path(destination).name not in {"bwrap", "nsenter", "ip", "nginx", "apache2"} and (recorder or Path(destination).name != "nft"):
            argv += ["--ro-bind", source, destination]
    _mount_modules(argv)
    return argv


def recorder_command(bootstrap, info_fd, selection):
    selected = contract.validate_selection(selection)
    argv = _base_command(bootstrap, recorder=True, implementation=selected["implementation"], info_fd=info_fd)
    return argv + ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_http_production_owner_worker.py", "recorder"]


def daemon_command(bootstrap, manifest, descriptors, selection, info_fd):
    selected = contract.validate_selection(selection)
    selected_runtime = stock_apache_runtime if selected["implementation"] == "apache" else runtime
    manifest = selected_runtime.validate_manifest(manifest)
    if (len(descriptors) != len(manifest["files"])
            or any(manifest[key] != item for key, item in contract.preparation_selection(selected).items())):
        raise ValueError("stock_production_daemon_snapshot_changed")
    argv = _base_command(bootstrap, recorder=False, implementation=selected["implementation"], info_fd=info_fd)
    for item, descriptor in zip(manifest["files"], descriptors, strict=True):
        mode = "0555" if item["destination"] in (manifest["executable"], manifest["interpreter"]) else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), item["destination"]]
    argv += ["--bind", "/stock-peer", "/scratch"]
    environment = apache.APACHE_ENVIRONMENT if selected["implementation"] == "apache" else spec.NGINX_ENVIRONMENT
    for name, value in environment.items():
        argv += ["--setenv", name, value]
    return argv + ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_http_production_owner_worker.py", "daemon"]


def listener_ready(process_directory, expected_namespaces, namespace_fds):
    """Read only a pinned process's bounded TCP table; never connect to probe."""
    if len(namespace_fds) != 2:
        raise ValueError("stock_production_daemon_namespace_pins_missing")
    for name, descriptor in zip(("user", "net"), namespace_fds, strict=True):
        if (os.readlink("/proc/self/fd/" + str(descriptor)) != expected_namespaces[name]
                or os.readlink("ns/" + name, dir_fd=process_directory) != expected_namespaces[name]):
            raise ValueError("stock_production_daemon_namespace_changed")
    descriptor = os.open("net/tcp", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=process_directory)
    try:
        raw = os.read(descriptor, 8193)
    finally:
        os.close(descriptor)
    if len(raw) > 8192:
        raise ValueError("stock_production_listener_table_limit")
    lines = raw.decode("ascii").splitlines()
    if not lines or lines[0].split()[:4] != ["sl", "local_address", "rem_address", "st"]:
        raise ValueError("stock_production_listener_table_invalid")
    rows = [line.split() for line in lines[1:] if line.strip()]
    if not rows:
        return False
    expected = "0100007F:" + format(apache.PRIVATE_ENDPOINT[1], "04X")
    if (len(rows) != 1 or len(rows[0]) < 10 or rows[0][1:4] != [expected, "00000000:0000", "0A"]
            or not rows[0][9].isdigit() or int(rows[0][9]) <= 0):
        raise ValueError("stock_production_unexpected_daemon_listener")
    return True


class StockHttpProductionLab:
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

    def _receive(self):
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
                    or descriptors):
                raise ValueError("stock_owner_invalid_descriptor_count")
            return decode(raw)
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

    def _owner_info(self, channel_name, host):
        self._supervisor.wait_for(lambda: channel_name in self._supervisor.eof)
        raw = bytes(self._supervisor.buffers[channel_name])
        if len(raw) > 4096:
            raise IsolationUnavailable("Stock HTTP production owner metadata exceeded bound")
        namespace_fds = _pin_namespaces(raw, host)
        self._supervisor.fds.update(namespace_fds)
        pid = json.loads(raw)["child-pid"]
        directory = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self._supervisor.fds.add(directory)
        observed = {name: os.readlink("ns/" + name, dir_fd=directory) for name in host}
        if any(observed[name] == host[name] for name in host):
            raise IsolationUnavailable("Stock HTTP production owner namespace not private")
        return namespace_fds, directory, observed

    def start(self, control):
        with self._lock:
            daemon_channel = private_socket = None
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
                self._supervisor = _Supervisor(control.remaining(), 65536, control=control)
                host = _namespaces()
                initial = {"selection": self.selection, "deadline": control.deadline,
                    "host_namespaces": host, "runtime_digest": self._identity["daemon_runtime_sha256"]}
                manifest = self.runtime["daemon"]
                chosen_spec = apache if self.selection["implementation"] == "apache" else spec
                compiled = tuple((source, raw) for source, _destination, raw in
                    chosen_spec.compiled_files(self.selection["configuration"], self.selection["case"]))
                descriptors = sealed_snapshots(manifest, None, None, control, additional_compiled=compiled)
                daemon_info_read, daemon_info_write = self._supervisor.pipe()
                self._supervisor.watch(daemon_info_read, "daemon_info")
                daemon_channel, daemon_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                daemon_channel.setblocking(False)
                try:
                    self._supervisor.launch("daemon", daemon_command(bootstrap, manifest, descriptors,
                        self.selection, daemon_info_write), pass_fds=(*descriptors, daemon_info_write), stdin=daemon_child)
                finally:
                    daemon_child.close()
                    self._supervisor.close_fd(daemon_info_write)
                    for descriptor in descriptors:
                        os.close(descriptor)
                self._supervisor.wait_for(lambda: bool(select.select([], [daemon_channel], [], 0)[1]))
                send_packet(daemon_channel, {**initial, "manifest": manifest})
                self._supervisor.wait_for(lambda: bool(select.select([daemon_channel], [], [], 0)[0]))
                daemon_ready, transferred = receive_packet(daemon_channel,
                    descriptor_required=self.selection["implementation"] == "apache")
                if transferred is not None:
                    private_socket = owned_socket(transferred)
                expected_uid = 65534 if private_socket is not None else 0
                if (set(daemon_ready) != {"namespaces", "bounds", "runtime_digest", "namespace_identity", "descriptor"}
                        or daemon_ready["bounds"] != BOUNDS or daemon_ready["runtime_digest"] != initial["runtime_digest"]
                        or daemon_ready["namespace_identity"] != {"uid": expected_uid, "gid": expected_uid, "supplementary_groups": []}
                        or (daemon_ready["descriptor"] != (None if private_socket is None else socket_identity(private_socket)))):
                    raise IsolationUnavailable("Stock HTTP production daemon boundary invalid")
                self._supervisor.wait_for(lambda: b"\n" in self._supervisor.buffers["daemon_out"])
                line = bytes(self._supervisor.buffers["daemon_out"]).split(b"\n", 1)[0]
                if line != DAEMON_READY + encode(daemon_ready):
                    raise IsolationUnavailable("Stock HTTP production daemon descriptor cleanup unverified")
                daemon_channel.close()
                daemon_channel = None
                daemon_pins, daemon_directory, daemon_namespaces = self._owner_info("daemon_info", host)
                if daemon_ready["namespaces"] != daemon_namespaces:
                    raise IsolationUnavailable("Stock HTTP production daemon namespaces changed")
                if private_socket is not None:
                    ready_deadline = min(control.deadline, time.monotonic() + 2)
                    def native_ready():
                        if time.monotonic() >= ready_deadline:
                            raise IsolationUnavailable("Stock HTTP production daemon startup exceeded bound")
                        return listener_ready(daemon_directory, daemon_namespaces, daemon_pins)
                    self._supervisor.wait_for(native_ready)
                info_read, info_write = self._supervisor.pipe()
                self._supervisor.watch(info_read, "info")
                self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                self._channel.setblocking(False)
                try:
                    self._supervisor.launch("lab", recorder_command(bootstrap, info_write, self.selection), stdin=child, pass_fds=(info_write,))
                finally:
                    child.close()
                    self._supervisor.close_fd(info_write)
                self._send({**initial, "descriptor": daemon_ready["descriptor"]})
                if private_socket is not None:
                    # Only this already-validated socket crosses into recorder;
                    # no namespace descriptor or daemon control socket is sent.
                    self._supervisor.wait_for(lambda: bool(select.select([], [self._channel], [], 0)[1]))
                    send_packet(self._channel, {"descriptor": daemon_ready["descriptor"]}, private_socket.fileno())
                    private_socket.close()
                    private_socket = None
                ready = self._receive()
                if (set(ready) != {"ready", "namespaces", "witness_baselines", "bounds", "runtime_digest", "descriptor"}
                        or ready["ready"] is not True or ready["witness_baselines"] is not True
                        or ready["bounds"] != BOUNDS or ready["runtime_digest"] != initial["runtime_digest"]):
                    raise IsolationUnavailable("Stock HTTP recorder readiness invalid")
                self._namespace_fds, _recorder_directory, self._lab_namespaces = self._owner_info("info", host)
                if (ready["namespaces"] != self._lab_namespaces
                        or any(daemon_namespaces[name] == self._lab_namespaces[name] for name in host)):
                    raise IsolationUnavailable("Stock HTTP production owners not separate")
                transport = {"kind": "unix_socket", "listener_verified": True, "descriptor": None}
                if self.selection["implementation"] == "apache":
                    descriptor = ready["descriptor"]
                    if (type(descriptor) is not dict or set(descriptor) != {"daemon_netns_cookie", "recorder_netns_cookie", "inode",
                            "unconnected_at_transfer", "transferred_once", "daemon_duplicate_closed", "connect_denied_in_daemon"}
                            or any(descriptor[key] != item for key, item in daemon_ready["descriptor"].items())
                            or type(descriptor["recorder_netns_cookie"]) is not int or not 0 < descriptor["recorder_netns_cookie"] < 2**64
                            or descriptor["recorder_netns_cookie"] == descriptor["daemon_netns_cookie"]
                            or any(descriptor[key] is not True for key in ("unconnected_at_transfer", "transferred_once",
                                "daemon_duplicate_closed", "connect_denied_in_daemon"))):
                        raise IsolationUnavailable("Stock HTTP production descriptor custody invalid")
                    transport = {"kind": "namespace_tcp_descriptor", "listener_verified": True, "descriptor": descriptor}
                elif ready["descriptor"] is not None:
                    raise IsolationUnavailable("Stock HTTP production unexpected descriptor custody")
                self._owner = {"recorder_namespaces": self._lab_namespaces, "daemon_namespaces": daemon_namespaces,
                    "witness_baselines": True, "recorder_bounds": dict(BOUNDS), "daemon_bounds": dict(BOUNDS),
                    "private_socket_unmounted_from_client": True, "daemon_ready": True,
                    "implementation": self.selection["implementation"], "private_transport": transport,
                    "daemon_namespace_identity": daemon_ready["namespace_identity"]}
                self._started = True
                self._verify_pins()
                self._last_snapshot = self._snapshot(self._command("ready"))
            except BaseException:
                self.close()
                raise
            finally:
                if daemon_channel is not None:
                    daemon_channel.close()
                if private_socket is not None:
                    private_socket.close()

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
            snapshot = self._last_snapshot or {"connection_count": 0, "request_count": 0, "recorder": None}
            self._receipt = {"identity": self.identity, "status": "closed", "started": self._started,
                "connection_count": snapshot["connection_count"], "request_count": snapshot["request_count"],
                "recorder": snapshot["recorder"], "processes_reaped": True, "namespace_descriptors_closed": True}
            return deepcopy(self._receipt)


class ConfinedStockHttpProductionLab(StockHttpProductionLab):
    def __init__(self, config, closure):
        super().__init__(config["case"], config["session_id"], SessionLimits(**config["limits"]),
            execute=config["execute"], runtime=closure["stock_http_runtime"], identity=config["owned_lab"], closure=closure)
