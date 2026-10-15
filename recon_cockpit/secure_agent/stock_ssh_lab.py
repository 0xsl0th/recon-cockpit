"""Two disconnected stock SSH owners, created only after launcher admission."""

from copy import deepcopy
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import socket
import stat
import threading
import time
from uuid import uuid4

from . import stock_ssh_contract as contract, stock_ssh_spec as spec, stock_ssh_runtime as runtime
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces, _runtime_files, _trusted_program
from .routed import _Supervisor, _pin_namespaces
from .session_limits import SessionLimits
from .tool_runtime_common import sealed_snapshots
from .stock_ssh_owner_worker import send_packet, receive_packet
from .stock_http_production_lab import MODULES as HTTP_MODULES, launcher_mapping

MODULES = (*HTTP_MODULES, "stock_ssh_spec", "stock_ssh_runtime", "stock_ssh_process", "stock_ssh_custodian",
           "stock_ssh_contract", "stock_ssh_nmap_spec", "stock_ssh_owner_worker", "stock_ssh_recorder",
           "stock_ssh_packets", "network_tools_ssh_fixture")


def owner_command(bootstrap, info_fd, *, mode, manifest=None, descriptors=()):
    if mode not in ("recorder", "custodian"):
        raise ValueError("stock_ssh_unknown_owner")
    stdlib, files = bootstrap
    uid = 0 if mode == "recorder" else spec.NAMESPACE_UID
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--uid", str(uid), "--gid", str(uid),
        "--cap-drop", "ALL", "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--as-pid-1",
        "--info-fd", str(info_fd), "--clearenv", "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1",
        "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    if mode == "recorder":
        argv += ["--cap-add", "CAP_NET_ADMIN", "--perms", "0700", "--size", "786432", "--tmpfs", "/scratch"]
        if manifest is not None or descriptors:
            raise ValueError("stock_ssh_recorder_cannot_mount_daemon")
    for source, destination in files:
        if Path(destination).name not in {"bwrap", "nsenter", "ip"} and (mode == "recorder" or Path(destination).name != "nft"):
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    if mode == "custodian":
        manifest = runtime.validate_manifest(manifest)
        if len(descriptors) != len(manifest["files"]):
            raise ValueError("stock_ssh_snapshot_count_changed")
        executables = {row[2] for row in spec.SSHD_EXECUTABLES} | {manifest["interpreter"]}
        for row, descriptor in zip(manifest["files"], descriptors, strict=True):
            mode_bits = "0400" if row["destination"] == spec.HOST_KEY_PATH else "0555" if row["destination"] in executables else "0444"
            argv += ["--perms", mode_bits, "--ro-bind-data", str(descriptor), row["destination"]]
    return argv + ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_ssh_owner_worker.py", mode]


class StockSshLab:
    """Construction and inspection are metadata; start requires confined authority."""

    def __init__(self, selection, session_id, limits, *, execute=True, runtime=None, identity=None, closure=None):
        self.selection = contract.validate_selection(selection)
        if type(limits) is not SessionLimits or type(execute) is not bool:
            raise ValueError("invalid_stock_ssh_lab")
        contract.validate_limits(asdict(limits), self.selection)
        self.session_id, self.limits, self.execute = session_id, limits, execute
        self._stock_ssh_runtime = contract.validate_runtime(runtime, self.selection)
        self._identity = contract.validate_identity(identity or {"version": "1", "profile": contract.PROFILE,
            "instance_id": str(uuid4()), "session_id": session_id, **self.selection,
            **contract.runtime_digests(self._stock_ssh_runtime, self.selection)},
            selection=self.selection, session_id=session_id, runtime=self._stock_ssh_runtime)
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
        return contract.validate_runtime(self._stock_ssh_runtime, self.selection)

    @property
    def started(self):
        return self._started

    def __enter__(self):
        if self._closed:
            raise IsolationUnavailable("Stock SSH owner permanently closed")
        return self

    def __exit__(self, *_):
        self.close()

    def _check_available(self):
        if self._closure is None:
            LinuxFixtureBackend().check_available()
        for name in ("bwrap", "nft", "nsenter"):
            _trusted_program(name)
        if Path(_trusted_program("bwrap")).stat().st_mode & stat.S_ISUID:
            raise IsolationUnavailable("Stock SSH requires non-setuid Bubblewrap")

    def _runtime(self, control):
        control.check()
        if self._closure is None:
            return _runtime_files("/usr/bin/python3", _trusted_program("nft"), control=control)
        from .owned_launcher_runtime import runtime as bootstrap
        return bootstrap(self._closure, owner=True)

    def _check(self, control):
        if (self._closed or not self.execute or type(control) is not ExecutionControl
                or control.clock is not time.monotonic or self._control is not None and control is not self._control):
            raise IsolationUnavailable("Stock SSH owner control changed")
        control.check()
        contract.validate_identity(self._identity, selection=self.selection, session_id=self.session_id, runtime=self.runtime)
        if self._supervisor is not None:
            self._supervisor.check()
            if any(process.poll() is not None for process in self._supervisor.processes.values()):
                raise IsolationUnavailable("Stock SSH owner process exited")

    def _verify_pins(self):
        self._check(self._control)
        for name, descriptor in zip(("user", "net"), self._namespace_fds, strict=True):
            if os.readlink("/proc/self/fd/" + str(descriptor)) != self._lab_namespaces[name]:
                raise IsolationUnavailable("Stock SSH namespace descriptor changed")

    def _send_to(self, channel, value, descriptor=None):
        self._supervisor.wait_for(lambda: bool(select.select([], [channel], [], 0)[1]))
        send_packet(channel, value, descriptor)

    def _receive_from(self, channel):
        self._supervisor.wait_for(lambda: bool(select.select([channel], [], [], 0)[0]))
        value, _ = receive_packet(channel, descriptor_required=False)
        return value

    def _command(self, operation, **fields):
        self._sequence += 1
        self._send_to(self._channel, {"sequence": self._sequence, "operation": operation, **fields})
        reply = self._receive_from(self._channel)
        if (type(reply) is not dict or set(reply) != {"sequence", "operation", "recorder", "instances"}
                or reply["sequence"] != self._sequence or reply["operation"] != operation):
            raise IsolationUnavailable("Stock SSH owner reply changed")
        return reply

    def _owner_info(self, channel_name, host):
        self._supervisor.wait_for(lambda: channel_name in self._supervisor.eof)
        raw = bytes(self._supervisor.buffers[channel_name])
        if len(raw) > 4096:
            raise IsolationUnavailable("Stock SSH owner metadata exceeded bound")
        pins = _pin_namespaces(raw, host)
        self._supervisor.fds.update(pins)
        pid = json.loads(raw)["child-pid"]
        directory = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self._supervisor.fds.add(directory)
        observed = {name: os.readlink("ns/" + name, dir_fd=directory) for name in host}
        if any(observed[name] == host[name] for name in host):
            raise IsolationUnavailable("Stock SSH owner namespace not private")
        return pins, directory, observed

    def start(self, control):
        with self._lock:
            custodian_channel = None
            try:
                if (type(self) is not ConfinedStockSshLab or type(self._closure) is not dict
                        or contract.validate_runtime(self._closure.get("stock_ssh_runtime"), self.selection) != self.runtime):
                    raise IsolationUnavailable("Stock SSH owners require the witnessed isolated launcher")
                self._check(control)
                if self._started:
                    self._verify_pins()
                    return
                if control.remaining() > 60:
                    raise IsolationUnavailable("Stock SSH owner lifetime exceeds contract")
                self._control = control
                self._check_available()
                bootstrap = self._runtime(control)
                self._supervisor = _Supervisor(control.remaining(), 65536, control=control)
                host = _namespaces()
                initial = {"selection": self.selection, "deadline": control.deadline, "host_namespaces": host,
                           "runtime_digest": self._identity["daemon_runtime_sha256"]}
                manifest = self.runtime["daemon"]
                compiled = tuple((source, raw) for source, _, raw in spec.compiled_files(self.selection["configuration"], self.selection["case"]))
                descriptors = sealed_snapshots(manifest, None, None, control, additional_compiled=compiled)
                info_read, info_write = self._supervisor.pipe()
                self._supervisor.watch(info_read, "custodian_info")
                custodian_channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                custodian_channel.setblocking(False)
                try:
                    self._supervisor.launch("custodian", owner_command(bootstrap, info_write, mode="custodian",
                        manifest=manifest, descriptors=descriptors), pass_fds=(*descriptors, info_write), stdin=child)
                finally:
                    child.close()
                    self._supervisor.close_fd(info_write)
                    for descriptor in descriptors:
                        os.close(descriptor)
                waiting = self._receive_from(custodian_channel)
                if type(waiting) is not dict or set(waiting) != {"bootstrap_waiting", "namespaces"} or waiting["bootstrap_waiting"] is not True:
                    raise IsolationUnavailable("Stock SSH custodian bootstrap gate invalid")
                pins, directory, custodian_namespaces = self._owner_info("custodian_info", host)
                if waiting["namespaces"] != custodian_namespaces:
                    raise IsolationUnavailable("Stock SSH custodian namespace changed")
                mapping = launcher_mapping(directory, custodian_namespaces, pins, "apache")
                self._send_to(custodian_channel, {**initial, "manifest": manifest})
                custodian_ready = self._receive_from(custodian_channel)
                contract.validate_custodian_ready(custodian_ready, runtime_digest=initial["runtime_digest"], namespaces=custodian_namespaces)
                info_read, info_write = self._supervisor.pipe()
                self._supervisor.watch(info_read, "info")
                self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                self._channel.setblocking(False)
                try:
                    self._supervisor.launch("lab", owner_command(bootstrap, info_write, mode="recorder"), stdin=child, pass_fds=(info_write,))
                finally:
                    child.close()
                    self._supervisor.close_fd(info_write)
                self._send_to(self._channel, initial)
                self._send_to(self._channel, {"operation": "custodian_channel"}, custodian_channel.fileno())
                custodian_channel.close()
                custodian_channel = None
                ready = self._receive_from(self._channel)
                self._namespace_fds, _, self._lab_namespaces = self._owner_info("info", host)
                contract.validate_recorder_ready(ready, runtime_digest=initial["runtime_digest"], namespaces=self._lab_namespaces,
                                                 custodian_namespaces=custodian_namespaces, selected=self.selection)
                self._owner = {"recorder": ready, "custodian": custodian_ready, "launcher_mapping": mapping}
                self._started = True
                self._verify_pins()
                self._last_snapshot = self._snapshot(self._command("ready"))
            except BaseException:
                self.close()
                raise
            finally:
                if custodian_channel is not None:
                    custodian_channel.close()

    def _snapshot(self, reply):
        return {"connection_count": reply["recorder"]["connections_admitted"],
                "request_count": reply["recorder"]["server_key_replies_forwarded"],
                "recorder": reply["recorder"], "instances": reply["instances"], "owner": deepcopy(self._owner)}

    def arm(self, control, action_deadline):
        with self._lock:
            self._check(control)
            self._verify_pins()
            self._last_snapshot = self._snapshot(self._command("arm", deadline=action_deadline))
            return deepcopy(self._last_snapshot)

    def snapshot(self, control, **minimum_counts):
        with self._lock:
            self._check(control)
            self._verify_pins()
            self._last_snapshot = self._snapshot(self._command("finish"))
            if not set(minimum_counts) <= {"minimum_connections", "minimum_requests"}:
                raise ValueError("invalid_stock_ssh_counter_barrier")
            for argument, field in (("minimum_connections", "connection_count"), ("minimum_requests", "request_count")):
                minimum = minimum_counts.get(argument, 0)
                if type(minimum) is not int or minimum < 0 or self._last_snapshot[field] < minimum:
                    raise IsolationUnavailable("Stock SSH owner counters did not settle")
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
                    raise IsolationUnavailable("Stock SSH owner cleanup incomplete")
            self._namespace_fds = ()
            snapshot = self._last_snapshot or {"connection_count": 0, "request_count": 0, "recorder": None, "instances": []}
            self._receipt = {"identity": self.identity, "status": "closed", "started": self._started,
                "connection_count": snapshot["connection_count"], "request_count": snapshot["request_count"],
                "recorder": snapshot["recorder"], "instances": snapshot["instances"],
                "processes_reaped": True, "namespace_descriptors_closed": True}
            return deepcopy(self._receipt)


class ConfinedStockSshLab(StockSshLab):
    def __init__(self, config, closure):
        super().__init__(config["case"], config["session_id"], SessionLimits(**config["limits"]),
            execute=config["execute"], runtime=closure["stock_ssh_runtime"], identity=config["owned_lab"], closure=closure)
