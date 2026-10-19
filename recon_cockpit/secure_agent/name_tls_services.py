"""Persistent protocol recorders and one confined native daemon per action."""

import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import select
import socket
import threading
import time

from . import name_tls_contract as contract, name_tls_public as public
from . import name_tls_client as client, name_tls_native_runtime as native
from . import name_tls_daemon as daemon, name_tls_transport as transport
from . import name_tls_topology_spec as topology_spec
from . import name_tls_python_runtime as sources
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _namespaces, _trusted_program
from .routed import _Supervisor
from .routing_services import _owner_info
from .tool_runtime_common import sealed_snapshots, _CLOSE_EXCEPT

MODULES = ("name_tls_frontend_worker", "name_tls_recorder", "name_tls_contract", "name_tls_public",
    "name_tls_ledger", "name_tls_wire", "name_tls_transport", "name_tls_topology_spec",
    "models", "tool_parameters", "tool_adapters", "worker", "tool_worker_common",
    "tls_posture_hello", "http_headers_parser", "name_tls_worker_common", *sources.PACKAGE_FILES)


def frontend_command(bootstrap, namespace_fds, info_fd, *, source_descriptors):
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--as-pid-1",
        "--info-fd", str(info_fd), "--clearenv", "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1",
        "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if Path(destination).name not in client.FORBIDDEN_PROGRAMS:
            argv += ["--ro-bind", source, destination]
    sources.mount_sources(argv, MODULES, source_descriptors)
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/name_tls_frontend_worker.py"]
    user_fd, net_fd = namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, (info_fd, *source_descriptors.values()))), *argv]


def _send(supervisor, channel, value, descriptor=None):
    supervisor.wait_for(lambda: bool(select.select([], [channel], [], 0)[1]))
    transport.send_packet(channel, value, descriptor)


def _receive(supervisor, channel, *, descriptor_required=False):
    supervisor.wait_for(lambda: bool(select.select([channel], [], [], 0)[0]))
    return transport.receive_packet(channel, descriptor_required=descriptor_required)


class Services:
    def __init__(self, topology, *, selection, identity, runtime, closure, control):
        self.selection = contract.validate_selection(selection)
        self.runtime = native.validate_runtime(runtime)
        self.identity = contract.validate_identity(identity, selection=self.selection, runtime=self.runtime)
        if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                or type(closure) is not dict or closure.get("name_tls_runtime") != self.runtime):
            raise ValueError("name_tls_service_authority")
        self.topology, self.control, self.closure = topology, control, closure
        self.frontends, self.completed = {}, []
        self.current_daemon = self.active = self._receipt = None
        self._closed, self._started = False, False
        self._lock = threading.Lock()

    def _bootstrap(self):
        from .owned_launcher_runtime import runtime
        return runtime(self.closure, owner=True)

    def _check(self):
        if self._closed:
            raise IsolationUnavailable("Name/TLS services permanently closed")
        self.control.check()
        if self.topology._closed or self.topology._process.poll() is not None:
            raise IsolationUnavailable("Name/TLS topology continuity lost")
        self.topology._supervisor.check()
        for row in self.frontends.values():
            row["supervisor"].check()
            if any(process.poll() is not None for process in row["supervisor"].processes.values()):
                raise IsolationUnavailable("Name/TLS recorder continuity lost")

    def start(self, deadline):
        if self._started or deadline > self.control.deadline:
            raise ValueError("name_tls_service_start")
        for operation in topology_spec.OPERATIONS:
            self._frontend(operation, deadline)
        self._started = True

    def _frontend(self, operation, deadline):
        self._check()
        role = operation + "_frontend"
        namespace_role = topology_spec.frontend_role(operation)
        namespace_fds = self.topology.namespace_fds(namespace_role)
        expected, host = self.topology.namespaces(namespace_role), _namespaces()
        supervisor = _Supervisor(max(.001, deadline - time.monotonic()), 16384, control=self.control)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        parent.setblocking(False)
        row = {"supervisor": supervisor, "channel": parent, "sequence": 0}
        self.frontends[operation] = row
        exported, source_descriptors = (), {}
        try:
            source_descriptors = sources.snapshot_sources(self.runtime, MODULES, self.control)
            read_fd, info_fd = supervisor.pipe()
            supervisor.watch(read_fd, "info")
            supervisor.launch("frontend", frontend_command(self._bootstrap(), namespace_fds, info_fd,
                source_descriptors=source_descriptors),
                pass_fds=(*namespace_fds, info_fd, *source_descriptors.values()), stdin=child)
            child.close()
            supervisor.close_fd(info_fd)
            _send(supervisor, parent, {"selection": self.selection, "identity": self.identity,
                "role": role, "host_namespaces": host, "routed_namespaces": expected, "deadline": self.control.deadline})
            exported = self.topology.frontend_descriptors(operation)
            for name, descriptor in zip(("listener", "ledger"), exported, strict=True):
                _send(supervisor, parent, {"operation": name}, descriptor)
            ready, _ = _receive(supervisor, parent)
            pins, directory, observed = _owner_info(supervisor, "info", host)
            from .name_tls_frontend_worker import validate_ready
            ready = validate_ready(ready, role=role, selected=self.selection, namespaces=observed)
            inherited = self.topology.identity["listeners"][operation]
            if ready["listener_identity"] != {"inode": inherited["inode"],
                    "netns_cookie": inherited["netns_cookie"], "endpoint": inherited["local"]}:
                raise ValueError("name_tls_frontend_listener_custody_changed")
            if (observed["net"] != expected["net"]
                    or any(observed[name] == expected[name] for name in ("user", "mnt", "pid"))):
                raise ValueError("name_tls_frontend_namespace_changed")
            mapping = daemon.launcher_mapping(directory, observed, pins)
            row.update(ready=ready, mapping=mapping)
            supervisor.deadline = self.control.deadline
            return row
        except BaseException as error:
            diagnostic = bytes(supervisor.buffers.get("frontend_err", b"")).decode("utf-8", "replace")[-2048:]
            parent.close()
            supervisor.close()
            raise IsolationUnavailable("Name/TLS frontend: " + str(error)[:256] + ": " + diagnostic) from error
        finally:
            child.close()
            for descriptor in (*exported, *source_descriptors.values()):
                os.close(descriptor)

    def _command(self, frontend, operation, *, private_socket=None, **fields):
        self._check()
        frontend["sequence"] += 1
        sequence = frontend["sequence"]
        supervisor, channel = frontend["supervisor"], frontend["channel"]
        old_deadline = supervisor.deadline
        if self.active is not None:
            supervisor.deadline = min(old_deadline, self.active["deadline"])
        try:
            _send(supervisor, channel, {"sequence": sequence, "operation": operation, **fields})
            if private_socket is not None:
                descriptor_identity = fields["daemon_descriptor"]
                try:
                    _send(supervisor, channel, {"operation": "daemon_descriptor", "descriptor": descriptor_identity},
                          private_socket.fileno())
                finally:
                    private_socket.close()
                transport.assert_descriptor_copies(descriptor_identity, [], maximum=128)
            reply, _ = _receive(supervisor, channel)
            expected = {"sequence", "operation", "recorder", "raw_streams", "reservations", "budget_denied",
                        "last_budget_reply", "descriptor_custody"}
            if (type(reply) is not dict or set(reply) != expected or reply["sequence"] != sequence
                    or reply["operation"] != operation or type(reply["budget_denied"]) is not bool):
                raise ValueError("name_tls_frontend_reply_changed")
            return reply
        finally:
            supervisor.deadline = old_deadline

    def arm_action(self, action, sequence):
        self._check()
        if not self._started or self.active is not None:
            raise ValueError("name_tls_service_action_overlap")
        slot = contract.action_selector(action, self.selection)
        started = time.monotonic()
        reply = self.topology.ledger_request({"operation": "ARM", "action_sequence": sequence,
            "action_digest": action.digest, "owner_identity_sha256": self.identity["owner_identity_sha256"],
            "slot": slot, "action": action.to_dict()})
        if reply["status"] != "ok":
            return reply
        self.active = {"slot": slot, "sequence": sequence, "action_digest": action.digest,
            "started": started, "deadline": min(self.control.deadline,
                started + contract.action_bounds(slot)["hard_action_seconds"])}
        return reply

    def _daemon(self, operation):
        self._check()
        manifest = self.runtime["roles"][daemon.selected_role(operation)]
        supervisor = _Supervisor(min(2, self.active["deadline"] - time.monotonic()), 16384, control=self.control)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        parent.setblocking(False)
        row = {"supervisor": supervisor, "channel": parent, "private_socket": None}
        self.current_daemon = row
        descriptors, source_descriptors = (), {}
        try:
            descriptors = sealed_snapshots(manifest, None, None, self.control,
                additional_compiled=native.compiled_snapshots(manifest))
            source_descriptors = sources.snapshot_sources(self.runtime, (*daemon.MODULES, *sources.PACKAGE_FILES), self.control)
            read_fd, info_fd = supervisor.pipe()
            supervisor.watch(read_fd, "info")
            supervisor.launch("daemon", daemon.daemon_command(self._bootstrap(), manifest, descriptors,
                self.selection, operation, info_fd, source_descriptors=source_descriptors),
                pass_fds=(*descriptors, info_fd, *source_descriptors.values()), stdin=child)
            child.close()
            supervisor.close_fd(info_fd)
            host = _namespaces()
            waiting, _ = _receive(supervisor, parent)
            pins, directory, observed = _owner_info(supervisor, "info", host)
            if waiting != {"bootstrap_waiting": True, "namespaces": observed}:
                raise ValueError("name_tls_daemon_bootstrap_changed")
            mapping = daemon.launcher_mapping(directory, observed, pins)
            role_digest = native.manifest_digest(manifest)
            _send(supervisor, parent, {"selection": self.selection, "manifest": manifest,
                "runtime_digest": role_digest, "operation": operation,
                "deadline": self.active["deadline"], "host_namespaces": host})
            ready, descriptor = _receive(supervisor, parent, descriptor_required=True)
            row["private_socket"] = transport.owned_socket(descriptor)
            from .name_tls_daemon_worker import validate_namespace_identity
            validate_namespace_identity(ready.get("namespace_identity"))
            if (set(ready) != {"namespaces", "namespace_identity", "bounds", "runtime_digest", "descriptor", "operation"}
                    or ready["namespaces"] != observed or ready["bounds"] != daemon.BOUNDS
                    or ready["runtime_digest"] != role_digest or ready["operation"] != operation
                    or ready["descriptor"] != transport.socket_identity(row["private_socket"])):
                raise ValueError("name_tls_daemon_ready_changed")
            supervisor.wait_for(lambda: b"\n" in supervisor.buffers["daemon_out"])
            if bytes(supervisor.buffers["daemon_out"]).split(b"\n", 1)[0] != daemon.DAEMON_READY + public.encode(ready):
                raise ValueError("name_tls_daemon_descriptor_cleanup_unverified")
            observation = []
            def ready_socket():
                found = daemon.listener_ready(directory, observed, pins, manifest, operation)
                if found:
                    observation.append(found)
                return bool(found)
            supervisor.wait_for(ready_socket)
            parent.close()
            row.update(channel=None, ready=ready, mapping=mapping, native_ready=observation[0])
            supervisor.deadline = self.active["deadline"]
            return row
        except BaseException as error:
            diagnostic = bytes(supervisor.buffers.get("daemon_err", b"")).decode("utf-8", "replace")[-2048:]
            self._close_daemon()
            raise IsolationUnavailable("Name/TLS daemon: " + str(error)[:256] + ": " + diagnostic) from error
        finally:
            child.close()
            for descriptor in (*descriptors, *source_descriptors.values()):
                os.close(descriptor)

    def _close_daemon(self):
        if self.current_daemon is None:
            return
        row, self.current_daemon = self.current_daemon, None
        if row["private_socket"] is not None:
            row["private_socket"].close()
        if row["channel"] is not None:
            row["channel"].close()
        row["supervisor"].close()
        if any(process.poll() is None for process in row["supervisor"].processes.values()):
            raise IsolationUnavailable("Name/TLS daemon cleanup incomplete")

    def run_action(self, action, launch):
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Name/TLS action already active")
        try:
            self._check()
            active = self.active
            if (active is None or active["sequence"] != launch["sequence"]
                    or active["action_digest"] != action.digest or launch["action_digest"] != action.digest):
                raise ValueError("name_tls_service_action_changed")
            slot, operation = active["slot"], contract.operation(active["slot"])
            frontend = self.frontends[operation]
            owned = self._daemon(operation)
            private_socket, owned["private_socket"] = owned["private_socket"], None
            self._command(frontend, "prepare", slot=slot, action_sequence=active["sequence"],
                action=action.to_dict(), daemon_descriptor=owned["ready"]["descriptor"], private_socket=private_socket)
            view = _ActionView(self, frontend)
            binding = self.topology.ledger_snapshot()["binding"]
            manifest = None if operation == "http" else self.runtime["roles"][operation + "_client"]
            envelope = {"mode": contract.PROFILE, "selection": self.selection, "identity": self.identity,
                "binding": binding, "namespaces": view.namespaces, "runtime": manifest, "launch": launch}
            result = client.run(service=view, launch=envelope, control=self.control, closure=self.closure, manifest=manifest)
            finished = self._command(frontend, "finish")
            self._close_daemon()
            from .name_tls_parser import encode_input
            from .name_tls_parser_runtime import parse_isolated_operation
            streams = {key: base64.b64decode(raw, validate=True) for key, raw in finished["raw_streams"].items()}
            raw = encode_input(operation, configuration=self.selection["configuration"], case=self.selection["case"],
                **streams, stdout=base64.b64decode(result["raw_output_base64"], validate=True),
                stderr=base64.b64decode(result["raw_stderr_base64"], validate=True),
                exit_code=result["provenance"]["exit_code"], stop_reason=result["provenance"]["stop_reason"],
                truncated=result["truncated"])
            parsed, parser_receipt, parser_error = None, None, None
            try:
                parsed, parser_receipt = parse_isolated_operation(raw, deadline=active["deadline"],
                    control=self.control, closure=self.closure, bundle=self.runtime, return_receipt=True)
            except IsolationUnavailable:
                parser_error = "parser_isolation_unavailable"
            except ValueError:
                parser_error = "invalid_native_observation"
            if time.monotonic() >= active["deadline"]:
                raise IsolationUnavailable("Name/TLS whole action deadline exceeded")
            if parser_error is not None and result["status"] == "succeeded":
                result["status"] = "failed"
            native_success = parsed is not None and (parsed["useful_task_completed"] or parsed["expected_negative"])
            finish = self.topology.ledger_request({"operation": "FINISH_ACTION", "action_sequence": active["sequence"],
                "action_digest": action.digest, "owner_identity_sha256": self.identity["owner_identity_sha256"],
                "output_bytes": result["bytes_received"], "native_success": native_success,
                "observation": parsed["observation"] if parsed is not None and operation == "dns" and self.selection["case"] != "N8" else None,
                "parsed_result_sha256": public.digest(parsed), "native_result_sha256": public.digest(result)})
            if finish["status"] != "ok":
                raise IsolationUnavailable("Name/TLS owner refused native result: " + finish["reason"])
            receipt = {"slot": slot, "action_sequence": active["sequence"], "action_digest": action.digest,
                "action": action.to_dict(), "daemon_ready": owned["ready"], "daemon_mapping": owned["mapping"],
                "native_ready": owned["native_ready"], "frontend_ready": frontend["ready"],
                "frontend_mapping": frontend["mapping"], "recorder": finished["recorder"],
                "reservations": finished["reservations"], "descriptor_custody": finished["descriptor_custody"],
                "budget_denied": finished["budget_denied"], "last_budget_reply": finished["last_budget_reply"],
                "parser_input_base64": base64.b64encode(raw).decode("ascii"), "parsed": parsed,
                "parser_receipt": parser_receipt, "parser_error": parser_error,
                "binding": self.topology.ledger_snapshot()["binding"],
                "closure": {"daemon_processes_reaped": True, "action_connections_closed": True,
                            "frontend_persists": True, "topology_persists": True}}
            self.completed.append(deepcopy(receipt))
            self.active = None
            result["tool_observation"] = parsed
            result["name_tls_service"] = receipt
            return result
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
                raise IsolationUnavailable("Name/TLS recorder cleanup incomplete")
            roles.append(role)
        self._receipt = {"closed": True, "frontends_reaped": roles, "all_processes_reaped": True,
                         "all_control_descriptors_closed": True, "actions_completed": len(self.completed)}
        return deepcopy(self._receipt)


class _ActionView:
    def __init__(self, services, frontend):
        self.services, self.frontend = services, frontend
        self.slot, self.deadline = services.active["slot"], services.active["deadline"]
        self.selection, self.identity, self.runtime = services.selection, services.identity, services.runtime
        role = contract.operation(self.slot) + "_client"
        self.namespace_fds = services.topology.namespace_fds(role)
        self.namespaces = services.topology.namespaces(role)

    def check(self, control):
        if control is not self.services.control or time.monotonic() >= self.deadline:
            raise ValueError("name_tls_client_control_changed")
        self.services._check()
        for name, descriptor in zip(("user", "net"), self.namespace_fds, strict=True):
            if os.readlink("/proc/self/fd/" + str(descriptor)) != self.namespaces[name]:
                raise ValueError("name_tls_client_namespace_pin_changed")

    def release(self, control, deadline):
        self.check(control)
        self.services._command(self.frontend, "arm", deadline=deadline)
