"""Fixed disconnected routing topology and trusted-launcher descriptor custody.

This module never attaches an existing network. Construction is metadata;
the containing witnessed launcher supplies the only production authority.
"""

import array
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import re
import select
import socket
import struct
import time

from .routing_topology_spec import (PROFILE, ROLES, EXPORTS, ENDPOINTS, CLIENTS, LINKS, BOUNDS, MAX_PACKET,
    NS_GET_USERNS, NS_GET_NSTYPE, encode, decode, spec, digest, routes, firewall_rules, validate_pair,
    validate_metadata, validate_closure, validate_network_state)

FRAME_BYTES = 32768
FRAME_MAGIC = b"RCT1"
FRAME_HEADER = struct.Struct("!4sII")
TRANSFER_SECONDS = 2


def _wait_channel(channel, *, writing, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("routing_topology_transport_deadline")
    readable, writable, _ = select.select([] if writing else [channel],
        [channel] if writing else [], [], remaining)
    if not (writable if writing else readable):
        raise ValueError("routing_topology_transport_deadline")


def send_packet(channel, value, descriptors=(), *, deadline=None):
    if len(descriptors) > len(EXPORTS):
        raise ValueError("routing_topology_descriptor_limit")
    raw = encode(value)
    deadline = min(time.monotonic() + TRANSFER_SECONDS, deadline or float("inf"))
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))] if descriptors else []
    size = FRAME_BYTES - FRAME_HEADER.size
    frames = ((raw,) if len(raw) <= FRAME_BYTES else
        (FRAME_HEADER.pack(FRAME_MAGIC, len(raw), offset) + raw[offset:offset + size]
         for offset in range(0, len(raw), size)))
    for frame in frames:
        _wait_channel(channel, writing=True, deadline=deadline)
        if channel.sendmsg([frame], ancillary, socket.MSG_DONTWAIT) != len(frame):
            raise ValueError("routing_topology_short_send")
        ancillary = []


def receive_packet(channel, *, expected_descriptors=0, deadline=None):
    if type(expected_descriptors) is not int or not 0 <= expected_descriptors <= len(EXPORTS):
        raise ValueError("routing_topology_descriptor_limit")
    deadline = min(time.monotonic() + TRANSFER_SECONDS, deadline or float("inf"))
    descriptors, invalid = [], False
    try:
        data, total = bytearray(), None
        while True:
            _wait_channel(channel, writing=False, deadline=deadline)
            raw, ancillary, flags, _ = channel.recvmsg(FRAME_BYTES + 1,
                socket.CMSG_SPACE((len(EXPORTS) + 1) * array.array("i").itemsize),
                getattr(socket, "MSG_CMSG_CLOEXEC", 0) | socket.MSG_DONTWAIT)
            for level, kind, payload in ancillary:
                if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    invalid = True
                    continue
                items = array.array("i")
                invalid |= len(payload) % items.itemsize != 0 or bool(data)
                items.frombytes(payload[:len(payload) - len(payload) % items.itemsize])
                descriptors.extend(items)
                for descriptor in items:
                    os.set_inheritable(descriptor, False)
            if (invalid or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) > FRAME_BYTES
                    or len(descriptors) != expected_descriptors):
                raise ValueError("routing_topology_descriptor_transport")
            if total is None and not raw.startswith(FRAME_MAGIC):
                return decode(raw), tuple(descriptors)
            if len(raw) <= FRAME_HEADER.size:
                raise ValueError("routing_topology_frame_shape")
            magic, size, offset = FRAME_HEADER.unpack_from(raw)
            if (magic != FRAME_MAGIC or not FRAME_BYTES < size <= MAX_PACKET or offset != len(data)
                    or total is not None and total != size
                    or len(raw) != FRAME_HEADER.size + min(FRAME_BYTES - FRAME_HEADER.size, size - offset)):
                raise ValueError("routing_topology_frame_order")
            total = size
            data.extend(raw[FRAME_HEADER.size:])
            if len(data) == total:
                return decode(bytes(data)), tuple(descriptors)
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise










def namespace_name(descriptor, namespace):
    value = os.readlink("/proc/self/fd/" + str(descriptor))
    if re.fullmatch(namespace + r":\[\d+\]", value) is None:
        raise ValueError("routing_topology_namespace_descriptor")
    return value


def socket_identity(descriptor, *, listener):
    duplicate = socket.socket(fileno=os.dup(descriptor))
    try:
        if duplicate.family != socket.AF_INET or duplicate.type != socket.SOCK_STREAM:
            raise ValueError("routing_topology_listener_type")
        if bool(duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)) != listener:
            raise ValueError("routing_topology_listener_state")
        result = {"inode": os.fstat(descriptor).st_ino, "local": list(duplicate.getsockname()),
                  "netns_cookie": struct.unpack("=Q", duplicate.getsockopt(socket.SOL_SOCKET, 71, 8))[0]}
        if not listener:
            result["peer"] = list(duplicate.getpeername())
        return result
    finally:
        duplicate.close()




def validate_exports(value, descriptors, *, parent_namespaces):
    value = validate_metadata(value)
    if len(descriptors) != len(EXPORTS) or len(set(descriptors)) != len(EXPORTS):
        raise ValueError("routing_topology_ready_changed")
    if type(value["networks"]) is not dict or set(value["networks"]) != set(ROLES):
        raise ValueError("routing_topology_networks_changed")
    user = namespace_name(descriptors[0], "user")
    if user != value["user"] or user == parent_namespaces["user"] or fcntl.ioctl(descriptors[0], NS_GET_NSTYPE) != 0x10000000:
        raise ValueError("routing_topology_user_changed")
    network_names = []
    for role, descriptor in zip(ROLES, descriptors[1:6], strict=True):
        name = namespace_name(descriptor, "net")
        if (name != value["networks"][role] or name == parent_namespaces["net"]
                or fcntl.ioctl(descriptor, NS_GET_NSTYPE) != 0x40000000):
            raise ValueError("routing_topology_network_changed")
        owner = fcntl.ioctl(descriptor, NS_GET_USERNS)
        try:
            if namespace_name(owner, "user") != user:
                raise ValueError("routing_topology_namespace_owner_changed")
        finally:
            os.close(owner)
        network_names.append(name)
    if len(set(network_names)) != 5:
        raise ValueError("routing_topology_networks_not_distinct")
    if type(value["listeners"]) is not dict or set(value["listeners"]) != set(ENDPOINTS):
        raise ValueError("routing_topology_listeners_changed")
    for index, service in enumerate(("http", "ssh"), 6):
        actual = socket_identity(descriptors[index], listener=True)
        if actual != value["listeners"][service] or actual["local"] != list(ENDPOINTS[service]):
            raise ValueError("routing_topology_listener_changed")
    if len({item["netns_cookie"] for item in value["listeners"].values()}) != 3:
        raise ValueError("routing_topology_listener_networks_changed")
    for descriptor in descriptors[8:10]:
        channel = socket.socket(fileno=os.dup(descriptor))
        try:
            if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
                raise ValueError("routing_topology_ledger_channel_changed")
            channel.getpeername()
        finally:
            channel.close()
    pairs = value["private_ssh_pairs"]
    if type(pairs) is not list or len(pairs) != 4 or value["private_pairs_drained"] is not True:
        raise ValueError("routing_topology_private_pairs_changed")
    seen = set()
    for index, pair in enumerate(pairs):
        validate_pair(pair)
        for offset, side in enumerate(("frontend", "daemon")):
            actual = socket_identity(descriptors[10 + 2 * index + offset], listener=False)
            if actual != pair[side] or actual["inode"] in seen or actual["netns_cookie"] != value["listeners"]["ssh"]["netns_cookie"]:
                raise ValueError("routing_topology_private_pair_changed")
            seen.add(actual["inode"])
    expected = [{"client": client, "endpoint": endpoint, "connected": True}
                for client in ("http", "ssh") for endpoint in ENDPOINTS]
    if value["baselines"] != expected:
        raise ValueError("routing_topology_baseline_changed")
    expected = [{"client": client, "endpoint": endpoint, "connected": endpoint == client}
                for client in ("http", "ssh") for endpoint in ENDPOINTS]
    if value["filtered"] != expected:
        raise ValueError("routing_topology_filtered_changed")
    return deepcopy(value)


def owner_command(bootstrap):
    """Only called from the independently witnessed, disconnected launcher."""
    from .isolation import _trusted_program
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0",
        "--cap-drop", "ALL", "--cap-add", "CAP_SYS_ADMIN", "--cap-add", "CAP_NET_ADMIN",
        "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--as-pid-1",
        "--clearenv", "--setenv", "LC_ALL", "C", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
        "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if Path(destination).name not in {"bwrap", "nsenter", "ip"}:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in ("routing_topology", "routing_topology_spec", "routing_topology_worker", "worker", "tool_worker_common",
                 "models", "tool_parameters", "tool_adapters", "routing_contract", "routing_ledger",
                 "stock_http_production_contract", "stock_http_spec", "stock_apache_spec",
                 "stock_http_production_nmap_spec", "stock_ssh_contract", "stock_ssh_spec",
                 "stock_ssh_process", "stock_ssh_nmap_spec", "configurable_contract", "configurable_scope",
                 "network_tools_ssh_fixture"):
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    # The private proc mount remains writable only for namespace-local setup.
    # The worker removes mount/sysctl authority and filesystem writes before READY.
    return argv + ["--remount-ro", "/dev", "--remount-ro", "/", "/usr/bin/python3", "-I", "-S",
                   "/app/recon_cockpit/secure_agent/routing_topology_worker.py"]


class Topology:
    """Owned by a witnessed launcher; namespace capabilities never reach host.

    The constructor's bootstrap is the launcher's already validated native
    closure. It neither inspects arbitrary binaries nor accepts caller routes.
    """

    def __init__(self, bootstrap, control, *, selection=None, identity=None):
        self.bootstrap, self.control = bootstrap, control
        if (selection is None) != (identity is None):
            raise ValueError("routing_topology_partial_ledger_identity")
        self.selection, self.assessment_identity = deepcopy(selection), deepcopy(identity)
        self._launcher_sequence = 0
        self._last_action_sequence = 0
        self._last_action_digest = None
        self._receipt = None
        self._supervisor = self._channel = self._process = None
        self._descriptors = {}
        self._ready = None
        self._closed = False
        self._cleanup_failed = False

    @staticmethod
    def _assert_launcher():
        # A host process has an initial/full UID map and cannot enter this API.
        uid, gid = os.getuid(), os.getgid()
        if uid <= 0 or gid <= 0 or not os.statvfs("/").f_flag & os.ST_RDONLY:
            raise ValueError("routing_topology_requires_private_launcher")
        for name, identity in (("uid", uid), ("gid", gid)):
            raw = Path("/proc/self/" + name + "_map").read_text(encoding="ascii")
            rows = [list(map(int, line.split())) for line in raw.splitlines()]
            if len(rows) != 1 or rows[0][0] != identity or rows[0][2] != 1:
                raise ValueError("routing_topology_requires_private_launcher_mapping")
        if [name for _, name in socket.if_nameindex()] != ["lo"]:
            raise ValueError("routing_topology_launcher_network_attached")

    @property
    def identity(self):
        if self._ready is None:
            raise ValueError("routing_topology_not_ready")
        return deepcopy(self._ready)

    def start(self):
        from .routed import _Supervisor
        from .isolation import _namespaces
        from .execution import ExecutionControl
        self._assert_launcher()
        if (self._closed or self._ready is not None or type(self.control) is not ExecutionControl
                or self.control.clock is not time.monotonic or self.control.remaining() > 60):
            raise ValueError("routing_topology_start_changed")
        self.control.check()
        parent = _namespaces()
        self._supervisor = _Supervisor(self.control.remaining(), 65536, control=self.control)
        self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._channel.setblocking(False)
        try:
            self._process = self._supervisor.launch("topology", owner_command(self.bootstrap), stdin=child)
            child.close()
            self._supervisor.wait_for(lambda: bool(select.select([], [self._channel], [], 0)[1]))
            initial = {"operation": "setup", "deadline": self.control.deadline,
                "host_namespaces": parent, "topology_sha256": digest()}
            if self.selection is not None:
                initial.update(selection=self.selection, identity=self.assessment_identity)
            send_packet(self._channel, initial)
            self._supervisor.wait_for(lambda: bool(select.select([self._channel], [], [], 0)[0]))
            ready, descriptors = receive_packet(self._channel, expected_descriptors=len(EXPORTS))
            self._descriptors = dict(zip(EXPORTS, descriptors, strict=True))
            self._ready = validate_exports(ready, descriptors, parent_namespaces=parent)
            # Verify the setup user's complete mapping from the positive launcher.
            # Namespace FD ownership is independently tied to this launcher's UID.
            owner_uid = array.array("I", [0])
            fcntl.ioctl(self._descriptors["user"], 0xB704, owner_uid, True)
            if owner_uid[0] != os.getuid():
                raise ValueError("routing_topology_namespace_owner_uid")
            return self.identity
        except BaseException:
            self.close()
            raise
        finally:
            child.close()

    def namespace_fds(self, role):
        if role not in ROLES or self._closed or self._ready is None:
            raise ValueError("routing_topology_namespace_role")
        return self._descriptors["user"], self._descriptors[role + "_net"]

    def namespaces(self, role):
        self.namespace_fds(role)
        return {**self._ready["owner_namespaces"], "net": self._ready["networks"][role]}

    def frontend_descriptors(self, service):
        if service not in ("http", "ssh") or self._closed or self._ready is None:
            raise ValueError("routing_topology_frontend_role")
        names = [service + "_listener", service + "_ledger_channel"]
        if service == "ssh":
            names += [name for name in EXPORTS if name.startswith("ssh_pair_")]
        if any(name not in self._descriptors for name in names):
            raise ValueError("routing_topology_frontend_already_transferred")
        return tuple(self._descriptors.pop(name) for name in names)

    def request(self, message):
        if self._closed or self._ready is None:
            raise ValueError("routing_topology_closed")
        self._supervisor.wait_for(lambda: bool(select.select([], [self._channel], [], 0)[1]))
        send_packet(self._channel, message)
        self._supervisor.wait_for(lambda: bool(select.select([self._channel], [], [], 0)[0]))
        reply, _ = receive_packet(self._channel)
        return reply

    def ledger_request(self, message):
        from .routing_ledger import validate_reply
        if self.selection is None or type(message) is not dict:
            raise ValueError("routing_topology_ledger_unavailable")
        message = deepcopy(message)
        self._launcher_sequence += 1
        if "sequence" in message and message["sequence"] != self._launcher_sequence:
            raise ValueError("routing_topology_launcher_sequence_changed")
        message["sequence"] = self._launcher_sequence
        reply = validate_reply(self.request(message), message, role="launcher")
        if message["operation"] == "ARM" and reply["status"] == "ok":
            self._last_action_sequence = message["action_sequence"]
            self._last_action_digest = message["action_digest"]
        return reply

    def ledger_snapshot(self):
        if self.selection is None:
            raise ValueError("routing_topology_ledger_unavailable")
        return self.request({"operation": "TOPOLOGY_SNAPSHOT"})

    def close(self):
        if self._closed:
            if self._cleanup_failed:
                raise ValueError("routing_topology_cleanup_failed")
            return deepcopy(self._receipt)
        self._closed = True
        failures = []
        for descriptor in self._descriptors.values():
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(error)
        self._descriptors.clear()
        if self._channel is not None:
            try:
                self._channel.close()
            except BaseException as error:
                failures.append(error)
        if self._supervisor is not None:
            try:
                self._supervisor.close()
            except BaseException as error:
                failures.append(error)
        exited = self._process is None or self._process.poll() is not None
        if failures or not exited:
            self._cleanup_failed = True
            raise ValueError("routing_topology_cleanup_failed") from (failures[0] if failures else None)
        self._receipt = {"status": "closed", "owner_exited": exited,
            "descriptors_closed": not self._descriptors,
            "namespaces": None if self._ready is None else deepcopy(self._ready["networks"]),
            "topology_sha256": digest()}
        return deepcopy(self._receipt)
