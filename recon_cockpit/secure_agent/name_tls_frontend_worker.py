"""Persistent key-free recorder with one inherited owner role channel."""

import errno
import os
import sys

ENTRY_DESCRIPTORS_VERIFIED = False
if __name__ == "__main__":
    for _entry in os.listdir("/proc/self/fd"):
        if int(_entry) > 2:
            try:
                os.fstat(int(_entry))
            except OSError as _error:
                if _error.errno == errno.EBADF:
                    continue
                raise
            raise SystemExit(78)
    ENTRY_DESCRIPTORS_VERIFIED = True
    sys.path.insert(0, "/app")

import base64
from copy import deepcopy
import ctypes
import math
import resource
import re
import select
import signal
import socket
import stat
import time

from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent import name_tls_ledger as ledger
from recon_cockpit.secure_agent import name_tls_recorder as recorder
from recon_cockpit.secure_agent import name_tls_transport as transport
from recon_cockpit.secure_agent import name_tls_worker_common as bootstrap
from recon_cockpit.secure_agent import worker, tool_worker_common as common
from recon_cockpit.secure_agent.name_tls_topology_spec import endpoints, validate_namespace_identity

BOUNDS = {"address_space_bytes": 268435456, "file_descriptors": 64, "processes": 1,
          "cpu_seconds": 5, "file_bytes": 0, "core_bytes": 0}
CHECKS = frozenset({"capabilities_dropped", "no_new_privs", "private_namespaces", "immutable_mapping",
    "root_read_only", "socket_creation_blocked", "process_creation_blocked", "namespace_creation_blocked",
    "exec_blocked", "server_material_absent"})
MAX_RESERVATION_BYTES = 131072
RESERVATION_CLEANUP_RESERVE = 8192
MAX_COMMANDS = 12
SOURCE_MODULES = ("name_tls_frontend_worker", "name_tls_recorder", "name_tls_contract", "name_tls_public",
    "name_tls_ledger", "name_tls_wire", "name_tls_transport", "name_tls_topology_spec", "name_tls_worker_common",
    "models", "tool_parameters", "tool_adapters", "worker", "tool_worker_common", "tls_posture_hello", "http_headers_parser")


def validate_ready(value, *, role, selected, namespaces):
    selected = contract.validate_selection(selected)
    fields = {"ready", "role", "namespaces", "payload_identity", "listener", "listener_identity", "bounds", "checks"}
    if (type(value) is not dict or set(value) != fields or value["ready"] is not True
            or role not in ledger.ROLES[1:] or value["role"] != role or value["namespaces"] != namespaces
            or type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
            or any(type(v) is not str or re.fullmatch(k + r":\[[0-9]+\]", v) is None for k, v in namespaces.items())
            or value["bounds"] != BOUNDS or contract.public.encode(value["bounds"]) != contract.public.encode(BOUNDS)
            or type(value["checks"]) is not dict or set(value["checks"]) != CHECKS
            or any(v is not True for v in value["checks"].values())):
        raise ValueError("name_tls_frontend_ready_changed")
    validate_namespace_identity(value["payload_identity"])
    expected = list(endpoints(selected["configuration"])[role.removesuffix("_frontend")])
    listener = value["listener_identity"]
    if (value["listener"] != expected or type(listener) is not dict
            or set(listener) != {"inode", "netns_cookie", "endpoint"} or listener["endpoint"] != expected
            or any(type(listener[key]) is not int or not 0 < listener[key] < 2**64 for key in ("inode", "netns_cookie"))):
        raise ValueError("name_tls_frontend_listener_identity_changed")
    return deepcopy(value)


class BudgetRefused(OSError):
    """No daemon connect or payload send is permitted after owner refusal."""


class BudgetChannel:
    def __init__(self, channel, role, deadline, owner_identity_sha256):
        if role not in ledger.ROLES[1:] or not contract._hash(owner_identity_sha256):
            raise ValueError("name_tls_frontend_role_changed")
        self.channel, self.role, self.deadline = channel, role, deadline
        self.owner_identity_sha256 = owner_identity_sha256
        self.sequence = self.action_sequence = 0
        self.action_digest = self.lease = self.last_reply = None
        self.failed = self.continuity_lost = False
        self.retry_at = 0.0
        self.reservations = []
        self.delivered = {"request": 0, "response": 0}

    def bind(self, action_sequence, action_digest):
        if (self.failed or self.lease is not None or type(action_sequence) is not int
                or not self.action_sequence < action_sequence <= 3 or not contract._hash(action_digest)):
            raise ValueError("name_tls_frontend_action_binding_changed")
        self.action_sequence, self.action_digest = action_sequence, action_digest
        self.last_reply = None
        self.reservations = []
        self.delivered = {"request": 0, "response": 0}
        self.retry_at = 0.0

    def call(self, operation, **fields):
        cleanup = operation == "FINISH_CONNECTION"
        if (self.continuity_lost or self.failed and not cleanup or self.action_digest is None
                or time.monotonic() >= self.deadline and not cleanup):
            raise BudgetRefused("name_tls_frontend_budget_unavailable")
        # Reserve the maximum complete round-trip before sending an irreversible
        # request. Every acknowledged reply remains retainable after a refusal.
        retained = len(transport.encode({"reservations": self.reservations}))
        remaining = MAX_RESERVATION_BYTES - retained
        needed = ledger.MAX_MESSAGE_BYTES + ledger.MAX_REPLY_BYTES + 256
        if remaining < needed + (0 if cleanup else RESERVATION_CLEANUP_RESERVE):
            self.failed = True
            raise BudgetRefused("name_tls_frontend_transcript_limit")
        self.sequence += 1
        message = {"operation": operation, "sequence": self.sequence,
                   "action_sequence": self.action_sequence, "action_digest": self.action_digest,
                   "owner_identity_sha256": self.owner_identity_sha256, **fields}
        contract.public.encode(message, max_bytes=ledger.MAX_MESSAGE_BYTES)
        try:
            self.channel.settimeout(min(1, max(.001, self.deadline - time.monotonic())))
            transport.send_packet(self.channel, message)
            reply, _ = transport.receive_packet(self.channel, descriptor_required=False)
            reply = ledger.validate_reply(reply, message, role=self.role)
        except BaseException:
            self.failed = self.continuity_lost = True
            raise
        finally:
            self.channel.setblocking(False)
        self.last_reply = reply
        self.reservations.append({"role": self.role, "message": message, "reply": reply})
        if reply["status"] == "denied":
            self.failed = True
            raise BudgetRefused(reply["reason"])
        return reply

    def connection(self, local_id):
        if self.lease is not None:
            raise ValueError("name_tls_frontend_overlapping_lease")
        if time.monotonic() < self.retry_at:
            return False
        reply = self.call("RESERVE_CONNECTION", local_id=local_id)
        if reply["status"] == "wait":
            self.retry_at = time.monotonic() + reply["retry_after_ms"] / 1000
            return False
        self.lease = reply["lease"]
        return True

    def request(self, kind):
        self.call("RESERVE_OPERATION", lease=self.lease, kind=kind)

    def before_write(self, active, direction, amount):
        if type(active) is not dict or direction not in self.delivered or type(amount) is not int or amount <= 0:
            raise ValueError("name_tls_frontend_invalid_write")
        # A prior short/EAGAIN reservation is never refunded or reused as a
        # freshness permit. Every attempt rechecks the surviving owner's TTL.
        self.call("RESERVE_BYTES", lease=self.lease, direction=direction, bytes=amount)
        active.setdefault("owner_offered", {})[direction] = amount

    def after_write(self, active, direction, count):
        offered = active.get("owner_offered", {}).pop(direction, None)
        if type(count) is not int or type(offered) is not int or not 0 <= count <= offered:
            raise ValueError("name_tls_frontend_write_exceeded_reservation")
        self.delivered[direction] += count

    def observe_dns(self, semantic, *, request_sha256, original_sha256, delivered_sha256):
        self.call("OBSERVE_DNS", lease=self.lease, semantic=semantic,
                  request_sha256=request_sha256, original_answer_sha256=original_sha256,
                  delivered_answer_sha256=delivered_sha256, response_bytes=self.delivered["response"])

    def finish(self, *, request_bytes, response_bytes, transcript_sha256, reason):
        if type(request_bytes) is not int or type(response_bytes) is not int or self.delivered != {
                "request": request_bytes, "response": response_bytes}:
            self.failed = True
            raise ValueError("name_tls_frontend_delivery_changed")
        if self.lease is not None:
            lease, self.lease = self.lease, None
            if self.continuity_lost:
                raise BudgetRefused("name_tls_frontend_delivery_unacknowledged")
            self.call("FINISH_CONNECTION", lease=lease, delivered_request_bytes=request_bytes,
                      delivered_response_bytes=response_bytes, transcript_sha256=transcript_sha256)


def settle_service(service, *, clock=time.monotonic, sleep=time.sleep):
    """Drain the already armed exchange within its original native deadline."""
    while not service.done:
        service.tick()
        if not service.done:
            remaining = service.deadline - clock()
            if remaining <= 0:
                service.close("timeout")
                break
            sleep(min(.001, remaining))


def _control_channel(descriptor):
    channel = socket.socket(fileno=descriptor)
    if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
        channel.close()
        raise ValueError("name_tls_frontend_control_socket")
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, transport.MAX_PACKET * 2)
    return channel


def _receive_fd(channel, operation):
    message, descriptor = transport.receive_packet(channel, descriptor_required=True)
    if message != {"operation": operation}:
        os.close(descriptor)
        raise ValueError("name_tls_frontend_descriptor_order")
    return descriptor


def namespaces():
    return {name: os.readlink("/proc/self/ns/" + name) for name in ("user", "net", "mnt", "pid")}


def assert_routed_namespaces(host, routed):
    names = {"user", "net", "mnt", "pid"}
    if type(host) is not dict or set(host) != names or type(routed) is not dict or set(routed) != names:
        raise ValueError("name_tls_frontend_namespace_shape")
    current = namespaces()
    for name in names:
        if type(host[name]) is not str or type(routed[name]) is not str or current[name] == host[name]:
            raise ValueError("name_tls_frontend_host_namespace")
        if (current[name] != routed[name]) if name == "net" else (current[name] == routed[name]):
            raise ValueError("name_tls_frontend_routed_namespace")
    if {name for _, name in socket.if_nameindex()} != {"lo", "eth0"}:
        raise ValueError("name_tls_frontend_interfaces")
    if not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise ValueError("name_tls_frontend_writable_root")
    if int(worker._status()["CapEff"], 16) & ((1 << 12) | (1 << 21)):
        raise ValueError("name_tls_frontend_setup_capabilities")
    return current


def limits(deadline):
    for kind, maximum in ((resource.RLIMIT_AS, BOUNDS["address_space_bytes"]),
        (resource.RLIMIT_NOFILE, BOUNDS["file_descriptors"]), (resource.RLIMIT_NPROC, 1),
        (resource.RLIMIT_CPU, 5), (resource.RLIMIT_FSIZE, 0), (resource.RLIMIT_CORE, 0)):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))
    signal.signal(signal.SIGALRM, worker._deadline)
    signal.setitimer(signal.ITIMER_REAL, max(.001, deadline - time.monotonic()))


def socket_filter():
    worker.install_syscall_filter()
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise ValueError("name_tls_frontend_seccomp_allocation")
    try:
        for name in ("socket", "socketpair", "socketcall", "bind", "listen", "memfd_create", "open_by_handle_at"):
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number == -1 or library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) != 0:
                raise ValueError("name_tls_frontend_seccomp_rule")
        if library.seccomp_load(context) != 0:
            raise ValueError("name_tls_frontend_seccomp_load")
    finally:
        library.seccomp_release(context)


def confinement_witnesses():
    status = worker._status()
    if status["NoNewPrivs"] != "1" or any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise ValueError("name_tls_frontend_privileges")
    if os.getpid() != 1 or common._namespace_task_count() != 1:
        raise ValueError("name_tls_frontend_process_count")
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX, socket.AF_NETLINK):
        try:
            channel = socket.socket(family, socket.SOCK_STREAM)
        except PermissionError:
            pass
        else:
            channel.close()
            raise ValueError("name_tls_frontend_socket_creation")
    try:
        child = os.fork()
    except PermissionError:
        pass
    else:
        if child == 0:
            os._exit(78)
        os.waitpid(child, 0)
        raise ValueError("name_tls_frontend_process_creation")
    try:
        os.execve("/app/name-tls-exec-witness", ["name-tls-exec-witness"], {})
    except PermissionError:
        pass
    else:
        raise ValueError("name_tls_frontend_exec_allowed")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x10000000) == 0 or ctypes.get_errno() != errno.EPERM:
        raise ValueError("name_tls_frontend_namespace_creation")


def require_idle_listener(listener):
    if select.select([listener], [], [], 0)[0]:
        raise ValueError("name_tls_frontend_unbound_connection")


def receive_daemon_socket(channel, expected, seen, frontend_cookie):
    expected = transport.validate_descriptor_identity(expected)
    message, descriptor = transport.receive_packet(channel, descriptor_required=True)
    private = transport.owned_socket(descriptor)
    try:
        key = (expected["daemon_netns_cookie"], expected["inode"])
        if (message != {"operation": "daemon_descriptor", "descriptor": expected}
                or transport.socket_identity(private) != expected or key in seen
                or expected["daemon_netns_cookie"] == frontend_cookie):
            raise ValueError("name_tls_frontend_descriptor_changed")
        transport.assert_descriptor_copies(expected, [private.fileno()])
        seen.add(key)
        return private
    except BaseException:
        private.close()
        raise


def main():
    channel = listener = budget_socket = private = service = budget = None
    try:
        if not ENTRY_DESCRIPTORS_VERIFIED or len(sys.argv) != 1:
            raise ValueError("name_tls_frontend_invalid_entry")
        bootstrap.close_import_descriptor(entry_verified=ENTRY_DESCRIPTORS_VERIFIED)
        channel = _control_channel(0)
        initial, _ = transport.receive_packet(channel, descriptor_required=False)
        if type(initial) is not dict or set(initial) != {
                "selection", "identity", "role", "host_namespaces", "routed_namespaces", "deadline"}:
            raise ValueError("name_tls_frontend_initial_shape")
        selected = contract.validate_selection(initial["selection"])
        identity = contract.validate_identity(initial["identity"], selection=selected)
        role, deadline = initial["role"], initial["deadline"]
        if (role not in ledger.ROLES[1:] or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not 0 < deadline - time.monotonic() <= 60):
            raise ValueError("name_tls_frontend_lifetime")
        operation = role.removesuffix("_frontend")
        current_namespaces = assert_routed_namespaces(initial["host_namespaces"], initial["routed_namespaces"])
        payload_identity = bootstrap.namespace_identity()
        listener = socket.socket(fileno=_receive_fd(channel, "listener"))
        endpoint = endpoints(selected["configuration"])[operation]
        if (listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM
                or listener.getsockname() != endpoint or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ValueError("name_tls_frontend_listener_changed")
        listener_identity = {"inode": os.fstat(listener.fileno()).st_ino,
                             "netns_cookie": transport.netns_cookie(listener), "endpoint": list(endpoint)}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as witness:
            if transport.netns_cookie(witness) != listener_identity["netns_cookie"]:
                raise ValueError("name_tls_frontend_listener_namespace")
        budget_socket = _control_channel(_receive_fd(channel, "ledger"))
        budget = BudgetChannel(budget_socket, role, deadline, identity["owner_identity_sha256"])
        for path in ("/tool/nginx", "/tool/dnsmasq", "/tool/data/name-tls/server.key",
                     "/app/recon_cockpit/secure_agent/name_tls_spec.py",
                     "/app/recon_cockpit/secure_agent/network_tools_tls_certificate_material.py"):
            if os.path.exists(path):
                raise ValueError("name_tls_frontend_server_material")
        limits(deadline)
        worker.drop_privileges()
        bootstrap.seal_group_identity(payload_identity)
        socket_filter()
        confinement_witnesses()
        common.apply_landlock({"/dev/null": 6, "/proc/self/status": 4})
        transport.send_packet(channel, {"ready": True, "role": role, "namespaces": current_namespaces,
            "payload_identity": payload_identity, "listener": list(endpoint), "listener_identity": listener_identity,
            "bounds": BOUNDS, "checks": dict.fromkeys(CHECKS, True)})
        sequence, seen_slots, seen_descriptors = 0, set(), set()
        descriptor_identity = None
        armed = False
        while time.monotonic() < deadline:
            if select.select([channel], [], [], .005)[0]:
                command, _ = transport.receive_packet(channel, descriptor_required=False)
                sequence += 1
                op = command.get("operation")
                extras = {"prepare": {"slot", "action_sequence", "action", "daemon_descriptor"},
                          "arm": {"deadline"}, "finish": set(), "close": set()}
                if (type(command) is not dict or op not in extras or set(command) != {"sequence", "operation"} | extras[op]
                        or type(command["sequence"]) is not int or command["sequence"] != sequence or sequence > MAX_COMMANDS):
                    raise ValueError("name_tls_frontend_command")
                if op == "prepare":
                    require_idle_listener(listener)
                    slot = contract.action_selector(command["action"], selected)
                    if (service is not None or slot in seen_slots or slot != command["slot"]
                            or contract.selector_role(slot) != role
                            or any(command["action"]["parameters"][key] != identity[key] for key in (
                                "owner_id", "owner_identity_sha256", "session_id", "runtime_identity_sha256"))):
                        raise ValueError("name_tls_frontend_action_changed")
                    budget.bind(command["action_sequence"], contract.digest(command["action"]))
                    private = receive_daemon_socket(channel, command["daemon_descriptor"], seen_descriptors,
                                                    listener_identity["netns_cookie"])
                    descriptor_identity = dict(command["daemon_descriptor"])
                    service = recorder.Service(operation, listener, private, configuration=selected["configuration"],
                        case=selected["case"], deadline=deadline, budget=budget, second_observation=slot == "dns_2")
                    seen_slots.add(slot)
                    armed = False
                elif op == "arm":
                    now = time.monotonic()
                    cap = contract.action_bounds(operation)["timeout_seconds"]
                    if (service is None or armed or type(command["deadline"]) not in (float, int)
                            or not math.isfinite(command["deadline"]) or not 0 < command["deadline"] - now <= cap
                            or command["deadline"] > deadline):
                        raise ValueError("name_tls_frontend_arm_deadline")
                    service.deadline = command["deadline"]
                    armed = True
                else:
                    if service is not None:
                        if op == "finish":
                            if not armed:
                                raise ValueError("name_tls_frontend_finish_unarmed")
                            settle_service(service)
                        else:
                            service.close()
                    require_idle_listener(listener)
                closed = private is None or private.fileno() == -1
                if descriptor_identity is not None:
                    transport.assert_descriptor_copies(descriptor_identity, [] if closed else [private.fileno()])
                custody = None if descriptor_identity is None else {"descriptor": descriptor_identity,
                    "frontend_netns_cookie": listener_identity["netns_cookie"], "unconnected_at_transfer": True,
                    "transferred_once": True, "frontend_consumed": bool(service and service.connect_started),
                    "frontend_copy_closed": closed}
                transport.send_packet(channel, {"sequence": sequence, "operation": op,
                    "recorder": None if service is None else service.snapshot(),
                    "raw_streams": {} if service is None else {key: base64.b64encode(raw).decode("ascii") for key, raw in service.raw_streams().items()},
                    "reservations": deepcopy(budget.reservations), "budget_denied": budget.failed,
                    "last_budget_reply": deepcopy(budget.last_reply), "descriptor_custody": custody})
                if op == "close":
                    return 0
                if op == "finish":
                    service = private = descriptor_identity = None
                    armed = False
            if service is not None and armed:
                service.tick()
            elif service is None:
                require_idle_listener(listener)
        raise TimeoutError("name_tls_frontend_owner_deadline")
    except Exception:
        sys.stderr.write("name_tls_frontend_refused\n")
        return 78
    finally:
        if service is not None:
            try:
                service.close()
            except Exception:
                pass
        for owned in (private, listener, budget_socket, channel):
            if owned is not None:
                owned.close()


if __name__ == "__main__":
    raise SystemExit(main())
