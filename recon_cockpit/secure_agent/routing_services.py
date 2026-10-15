"""Bounded routed frontends and independently confined accepted service daemons."""

import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import select
import socket
import stat
import threading
import time

from . import routing_contract as contract, routing_client_runtime as client
from . import stock_http_production_lab as http_lab, stock_http_production_owner_worker as http_owner
from . import stock_http_owner_worker as http_common, stock_http_spec as http_spec
from . import stock_ssh_lab as ssh_lab, stock_ssh_owner_worker as ssh_owner, stock_ssh_spec as ssh_spec
from . import stock_ssh_contract as ssh_contract
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _namespaces, _trusted_program
from .routed import _Supervisor, _pin_namespaces
from .tool_runtime_common import sealed_snapshots, _CLOSE_EXCEPT

MODULES = tuple(dict.fromkeys((*http_lab.MODULES, *ssh_lab.MODULES, *client.MODULES,
    "routing_services", "routing_service_contract", "routing_frontend_worker", "routing_ledger", "stock_ssh_client_runtime",
    "stock_ssh_parser", "stock_ssh_parser_runtime", "stock_ssh_parser_worker")))


def frontend_command(bootstrap, role, namespace_fds, info_fd):
    if role not in ("http_frontend", "ssh_frontend") or len(namespace_fds) != 2:
        raise ValueError("routing_frontend_command_changed")
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--as-pid-1",
        "--info-fd", str(info_fd), "--clearenv", "--setenv", "LC_ALL", "C",
        "--setenv", "MALLOC_ARENA_MAX", "1", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
        "--ro-bind", stdlib, stdlib, "--perms", "0700", "--size", str(http_common.SCRATCH_BYTES), "--tmpfs", "/scratch"]
    if role == "http_frontend":
        argv += ["--ro-bind", "/stock-peer", "/peer"]
    forbidden = {"bwrap", "nsenter", "nft", "ip", "nginx", "apache2", "sshd", "sshd-session", "sshd-auth", "nmap", "ssh-keyscan"}
    for source, destination in files:
        if Path(destination).name not in forbidden:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/routing_frontend_worker.py"]
    user_fd, net_fd = namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT, str(info_fd), *argv]


def daemon_command(bootstrap, manifest, descriptors, selector, info_fd):
    selector = contract.validate_selector(selector)
    chosen = contract.underlying_selection(selector)
    if selector.startswith("ssh_"):
        return ssh_lab.owner_command(bootstrap, info_fd, mode="custodian", manifest=manifest, descriptors=descriptors)
    argv = http_lab.daemon_command(bootstrap, manifest, descriptors, chosen, info_fd)
    indices = [i for i, part in enumerate(argv) if part == "--bind" and argv[i + 1:i + 3] == ["/stock-peer", "/scratch"]]
    if len(indices) != 1:
        raise ValueError("routing_nginx_scratch_command_changed")
    argv[indices[0] + 1] = "/stock-peer/" + selector
    return argv


def _send(supervisor, channel, value, descriptor=None):
    supervisor.wait_for(lambda: bool(select.select([], [channel], [], 0)[1]))
    ssh_owner.send_packet(channel, value, descriptor)


def _receive(supervisor, channel):
    supervisor.wait_for(lambda: bool(select.select([channel], [], [], 0)[0]))
    value, _ = ssh_owner.receive_packet(channel, descriptor_required=False)
    return value


def _owner_info(supervisor, name, host):
    supervisor.wait_for(lambda: name in supervisor.eof)
    raw = bytes(supervisor.buffers[name])
    if len(raw) > 4096:
        raise ValueError("routing_owner_metadata_limit")
    pins = _pin_namespaces(raw, host)
    supervisor.fds.update(pins)
    pid = json.loads(raw)["child-pid"]
    directory = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    supervisor.fds.add(directory)
    names = {name: os.readlink("ns/" + name, dir_fd=directory) for name in host}
    if any(names[name] == host[name] for name in host):
        raise ValueError("routing_owner_namespace_not_private")
    return pins, directory, names


class Services:
    """Persistent frontends, finite per-action daemons; constructor is metadata."""

    def __init__(self, topology, *, selection, identity, runtime, closure, control, arm_action):
        self.selection = contract.validate_selection(selection)
        self.runtime = contract.validate_runtime(runtime, self.selection)
        self.identity = contract.validate_identity(identity, selection=self.selection, runtime=self.runtime)
        if (type(control) is not ExecutionControl or control.clock is not time.monotonic or not callable(arm_action)
                or type(closure) is not dict or closure.get("routing_runtime") != self.runtime):
            raise ValueError("routing_service_authority_changed")
        self.topology, self.closure, self.control, self.arm_action = topology, closure, control, arm_action
        self.frontends, self.completed = {}, []
        self.current_daemon = None
        self._closed, self._receipt = False, None
        self._lock = threading.Lock()

    def _bootstrap(self):
        from .owned_launcher_runtime import runtime
        return runtime(self.closure, owner=True)

    def _check(self):
        if self._closed:
            raise IsolationUnavailable("Routing services permanently closed")
        self.control.check()
        if self.topology._closed or self.topology._process.poll() is not None:
            raise IsolationUnavailable("Routing topology continuity lost")
        self.topology._supervisor.check()
        for row in self.frontends.values():
            row["supervisor"].check()
            if any(process.poll() is not None for process in row["supervisor"].processes.values()):
                raise IsolationUnavailable("Routing frontend continuity lost")

    def _frontend(self, selector):
        self._check()
        role = contract.selector_role(selector)
        if role in self.frontends:
            return self.frontends[role]
        service_name = "http" if role == "http_frontend" else "ssh"
        namespace_fds = self.topology.namespace_fds(role)
        expected = self.topology.namespaces(role)
        host = _namespaces()
        supervisor = _Supervisor(self.control.remaining(), 65536, control=self.control)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        parent.setblocking(False)
        exported = ()
        row = {"supervisor": supervisor, "channel": parent, "sequence": 0}
        self.frontends[role] = row
        try:
            read_fd, info_fd = supervisor.pipe()
            supervisor.watch(read_fd, "info")
            supervisor.launch("frontend", frontend_command(self._bootstrap(), role, namespace_fds, info_fd),
                              pass_fds=(*namespace_fds, info_fd), stdin=child)
            child.close(); supervisor.close_fd(info_fd)
            pairs = [] if service_name == "http" else [pair["daemon"] for pair in self.topology.identity["private_ssh_pairs"]]
            initial = {"selection": self.selection, "role": role, "identity": self.identity,
                "deadline": self.control.deadline, "namespaces": expected, "host_namespaces": host, "private_pairs": pairs}
            _send(supervisor, parent, initial)
            exported = self.topology.frontend_descriptors(service_name)
            operations = ["listener", "ledger"]
            if service_name == "ssh":
                operations += ["private_" + side + "_" + str(index) for index in range(4) for side in ("client", "server")]
            if len(exported) != len(operations):
                raise ValueError("routing_frontend_export_count_changed")
            for operation, descriptor in zip(operations, exported, strict=True):
                _send(supervisor, parent, {"operation": operation}, descriptor)
            ready = _receive(supervisor, parent)
            pins, directory, observed = _owner_info(supervisor, "info", host)
            if (type(ready) is not dict or set(ready) != {"ready", "role", "namespaces", "listener", "bounds", "private_pairs"}
                    or ready["ready"] is not True or ready["role"] != role or ready["namespaces"] != observed
                    or observed["net"] != expected["net"] or any(observed[name] == expected[name] for name in ("user", "mnt", "pid"))
                    or ready["listener"] != (["10.77.0.10", 8080] if service_name == "http" else ["10.77.0.20", 2222])
                    or ready["bounds"] != http_common.BOUNDS or ready["private_pairs"] != pairs):
                raise ValueError("routing_frontend_ready_changed")
            mapping = http_lab.launcher_mapping(directory, observed, pins, "nginx")
            row.update(ready=ready, mapping=mapping)
            return row
        except BaseException:
            parent.close(); supervisor.close()
            raise
        finally:
            child.close()
            for descriptor in exported:
                os.close(descriptor)

    def _command(self, frontend, operation, *, custody=None, **fields):
        self._check()
        frontend["sequence"] += 1
        sequence = frontend["sequence"]
        supervisor, channel = frontend["supervisor"], frontend["channel"]
        _send(supervisor, channel, {"sequence": sequence, "operation": operation, **fields})
        if custody is not None:
            _send(supervisor, channel, {"operation": "custodian"}, custody.fileno())
        reply = _receive(supervisor, channel)
        if (type(reply) is not dict or set(reply) != {"sequence", "operation", "recorder", "instances", "reservations", "budget_denied", "last_budget_reply"}
                or type(reply["sequence"]) is not int or reply["sequence"] != sequence or reply["operation"] != operation
                or type(reply["budget_denied"]) is not bool):
            raise ValueError("routing_frontend_reply_changed")
        return reply

    def _daemon(self, selector):
        self._check()
        chosen = contract.underlying_selection(selector)
        underlying = contract.underlying_contract(selector)
        manifest = self.runtime[selector]["daemon"]
        spec = http_spec if selector.startswith("http_") else ssh_spec
        if selector.startswith("http_"):
            http_common.scratch_bound("/stock-peer")
            os.mkdir("/stock-peer/" + selector, 0o700)
        supervisor = _Supervisor(self.control.remaining(), 65536, control=self.control)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        parent.setblocking(False)
        self.current_daemon = {"supervisor": supervisor, "channel": parent}
        descriptors = ()
        try:
            compiled = tuple((source, raw) for source, _, raw in spec.compiled_files("A", chosen["case"]))
            descriptors = sealed_snapshots(manifest, None, None, self.control, additional_compiled=compiled)
            read_fd, info_fd = supervisor.pipe()
            supervisor.watch(read_fd, "info")
            supervisor.launch("daemon", daemon_command(self._bootstrap(), manifest, descriptors, selector, info_fd),
                              pass_fds=(*descriptors, info_fd), stdin=child)
            child.close(); supervisor.close_fd(info_fd)
            host = _namespaces()
            waiting = _receive(supervisor, parent)
            pins, directory, observed = _owner_info(supervisor, "info", host)
            if waiting != {"bootstrap_waiting": True, "namespaces": observed}:
                raise ValueError("routing_daemon_bootstrap_changed")
            mapping = http_lab.launcher_mapping(directory, observed, pins, "nginx" if selector.startswith("http_") else "apache")
            runtime_digest = underlying.runtime_digests(self.runtime[selector], chosen)["daemon_runtime_sha256"]
            _send(supervisor, parent, {"selection": chosen, "deadline": self.control.deadline,
                "host_namespaces": host, "runtime_digest": runtime_digest, "manifest": manifest})
            ready = _receive(supervisor, parent)
            if selector.startswith("ssh_"):
                ssh_contract.validate_custodian_ready(ready, runtime_digest=runtime_digest, namespaces=observed)
            else:
                http_owner.contract.validate_daemon_identity(ready.get("namespace_identity"), "nginx")
                if (set(ready) != {"namespaces", "bounds", "runtime_digest", "namespace_identity", "descriptor"}
                        or ready["namespaces"] != observed or ready["runtime_digest"] != runtime_digest
                        or ready["bounds"] != http_common.BOUNDS or ready["descriptor"] is not None):
                    raise ValueError("routing_nginx_ready_changed")
                supervisor.wait_for(lambda: b"\n" in supervisor.buffers["daemon_out"])
                if bytes(supervisor.buffers["daemon_out"]).split(b"\n", 1)[0] != http_owner.DAEMON_READY + http_owner.encode(ready):
                    raise ValueError("routing_nginx_descriptor_cleanup_unverified")
                until = min(self.control.deadline, time.monotonic() + 2)
                def ready_socket():
                    if time.monotonic() >= until:
                        raise ValueError("routing_nginx_socket_deadline")
                    try:
                        return stat.S_ISSOCK(os.stat("/stock-peer/" + selector + "/nginx.sock", follow_symlinks=False).st_mode)
                    except FileNotFoundError:
                        return False
                supervisor.wait_for(ready_socket)
                parent.close()
                self.current_daemon["channel"] = None
            self.current_daemon.update(ready=ready, mapping=mapping)
            return self.current_daemon
        except BaseException:
            self._close_daemon()
            raise
        finally:
            child.close()
            for descriptor in descriptors:
                os.close(descriptor)

    def _close_daemon(self):
        if self.current_daemon is None:
            return
        row, self.current_daemon = self.current_daemon, None
        if row["channel"] is not None:
            row["channel"].close()
        row["supervisor"].close()
        if any(process.poll() is None for process in row["supervisor"].processes.values()):
            raise IsolationUnavailable("Routed daemon cleanup incomplete")

    def run_action(self, selector, launch):
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Routing service action already running")
        frontend = None
        try:
            self._check()
            selector = contract.validate_selector(selector)
            if selector in [row["selector"] for row in self.completed]:
                raise ValueError("routing_service_action_replayed")
            sequence = launch["sequence"]
            action_digest = contract.digest(contract.action(self.selection, selector))
            if launch["action_digest"] != action_digest:
                raise ValueError("routing_service_action_changed")
            owner_started = time.monotonic()
            frontend = self._frontend(selector)
            daemon = self._daemon(selector)
            custody = daemon["channel"] if selector.startswith("ssh_") else None
            self._command(frontend, "start", custody=custody, selector=selector,
                          action_sequence=sequence, action_digest=action_digest)
            if custody is not None:
                custody.close(); daemon["channel"] = None
            owner_startup_ms = round((time.monotonic() - owner_started) * 1000)
            view = _ActionView(self, frontend, selector, sequence, action_digest)
            bound = {"mode": contract.PROFILE, "launch": launch, "identity": self.identity,
                "namespaces": view.namespaces, "selection": self.selection, "selector": selector,
                "runtime": self.runtime[selector]}
            result = client.run_routed_tool_owned(service=view, launch=bound, control=self.control,
                closure=self.closure, manifest=self.runtime[selector]["client"])
            reply = self._command(frontend, "finish")
            if selector.startswith("http_"):
                from .stock_http_recorder import validate_snapshot
            else:
                from .stock_ssh_recorder import validate_snapshot
            snapshot = validate_snapshot(reply["recorder"], configuration="A", case=contract.underlying_selection(selector)["case"])
            stopping = time.monotonic()
            self._close_daemon()
            result["timing"].update(owner_startup_ms=owner_startup_ms,
                owner_teardown_ms=round((time.monotonic() - stopping) * 1000))
            result["tool_observation"] = None
            if result["status"] == "succeeded" and result["truncated"] is False and not reply["budget_denied"]:
                try:
                    if selector.startswith("http_"):
                        from .configurable_parser_runtime import parse_isolated_tool_output
                        raw = result["results"][0]["raw_response"] if selector == "http_headers" else result["raw_output_base64"]
                        result["tool_observation"] = parse_isolated_tool_output(contract.action(self.selection, selector)["tool_id"],
                            base64.b64decode(raw, validate=True), base64.b64decode(result.get("raw_stderr_base64", ""), validate=True),
                            scope=contract.scope(self.selection), endpoint_id="http", control=self.control, closure=self.closure)
                    else:
                        from .stock_ssh_parser_runtime import parse_isolated_tool_output
                        result["tool_observation"] = parse_isolated_tool_output(contract.action(self.selection, selector)["tool_id"],
                            base64.b64decode(result["raw_output_base64"], validate=True), base64.b64decode(result["raw_stderr_base64"], validate=True),
                            configuration="A", control=self.control, closure=self.closure)
                except ValueError:
                    pass
            receipt = {"selector": selector, "action_sequence": sequence, "action_digest": action_digest,
                "underlying_selection": contract.underlying_selection(selector), "daemon_ready": deepcopy(daemon["ready"]),
                "daemon_mapping": deepcopy(daemon["mapping"]), "frontend_ready": deepcopy(frontend["ready"]),
                "frontend_mapping": deepcopy(frontend["mapping"]), "recorder": snapshot,
                "instances": reply["instances"], "reservations": reply["reservations"],
                "budget_denied": reply["budget_denied"], "last_budget_reply": reply["last_budget_reply"],
                "closure": {"daemon_processes_reaped": True, "action_connections_closed": True,
                            "frontend_persists": True, "topology_persists": True}}
            self.completed.append(deepcopy(receipt))
            return {**result, "routing_service": receipt}
        except BaseException:
            self._close_daemon()
            self.close()
            raise
        finally:
            self._lock.release()

    def close(self):
        if self._receipt is not None:
            return deepcopy(self._receipt)
        self._closed = True
        self._close_daemon()
        roles = []
        for role, row in self.frontends.items():
            row["channel"].close()
            row["supervisor"].close()
            if any(process.poll() is None for process in row["supervisor"].processes.values()):
                raise IsolationUnavailable("Routed frontend cleanup incomplete")
            roles.append(role)
        self._receipt = {"closed": True, "frontends_reaped": roles, "all_processes_reaped": True,
            "all_control_descriptors_closed": True, "actions_completed": len(self.completed)}
        return deepcopy(self._receipt)


class _ActionView:
    def __init__(self, services, frontend, selector, sequence, action_digest):
        self.services, self.frontend, self.selector = services, frontend, selector
        self.sequence, self.action_digest = sequence, action_digest
        self.selection, self.identity = services.selection, services.identity
        role = "http_client" if selector.startswith("http_") else "ssh_client"
        self.namespace_fds = services.topology.namespace_fds(role)
        self.namespaces = services.topology.namespaces(role)

    def check(self, control):
        if control is not self.services.control:
            raise ValueError("routing_client_control_changed")
        self.services._check()
        for name, descriptor in zip(("user", "net"), self.namespace_fds, strict=True):
            if os.readlink("/proc/self/fd/" + str(descriptor)) != self.namespaces[name]:
                raise ValueError("routing_client_namespace_pin_changed")

    def arm(self, control, deadline):
        self.check(control)
        self.services.arm_action(self.selector, self.sequence, self.action_digest, deadline)
        self.services._command(self.frontend, "arm", deadline=deadline)
