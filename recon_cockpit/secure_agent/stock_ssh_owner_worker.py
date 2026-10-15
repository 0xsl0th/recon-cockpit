"""Separated stock SSH recorder and finite process custodian namespace owners."""

import errno
import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError as error:
                if error.errno == errno.EBADF:
                    continue
                raise
            raise ValueError("stock_ssh_owner_inherited_descriptor")


ENTRY_DESCRIPTORS_VERIFIED = False
if __name__ == "__main__":
    try:
        private_descriptors()
        ENTRY_DESCRIPTORS_VERIFIED = True
    except Exception:
        sys.stderr.write("stock_ssh_owner_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import array
from copy import deepcopy
import hashlib
import json
import math
import re
import resource
import select
import socket
import stat
import struct
import subprocess
import time

from recon_cockpit.secure_agent import stock_ssh_contract as contract
from recon_cockpit.secure_agent import stock_ssh_spec as spec, stock_ssh_runtime as runtime
from recon_cockpit.secure_agent import stock_ssh_process as process, stock_ssh_custodian as custodian
from recon_cockpit.secure_agent import stock_ssh_recorder as recorder
from recon_cockpit.secure_agent import stock_http_owner_worker as existing
from recon_cockpit.secure_agent.stock_http_production_owner_worker import namespace_identity, seal_group_identity
from recon_cockpit.secure_agent.stock_http_production_transport import owned_socket
from recon_cockpit.secure_agent import worker, tool_worker_common as common

MAX_PACKET = 262144
MAX_INSTANCES = 3
PRIVATE_WITNESS = b"RECON_STOCK_SSH_PRIVATE_WITNESS_V1\n"
RECEIVE_CLOEXEC = getattr(socket, "MSG_CMSG_CLOEXEC", 0x40000000)
BOUNDS = dict(existing.BOUNDS)
namespaces = existing.namespaces


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_PACKET:
        raise ValueError("stock_ssh_owner_packet_limit")
    return raw


def decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_PACKET:
        raise ValueError("stock_ssh_owner_invalid_packet")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("stock_ssh_owner_duplicate_key")
            value[key] = item
        return value
    def invalid_constant(_):
        raise ValueError("stock_ssh_owner_nonfinite_number")
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            invalid_constant(value)
        return number
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=invalid_constant, parse_float=finite_float)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("stock_ssh_owner_invalid_packet") from exc
    if type(value) is not dict:
        raise ValueError("stock_ssh_owner_invalid_packet")
    return value


def send_packet(channel, value, descriptor=None):
    raw = encode(value)
    ancillary = [] if descriptor is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))]
    if channel.sendmsg([raw], ancillary) != len(raw):
        raise ValueError("stock_ssh_owner_packet_truncated")


def receive_packet(channel, *, descriptor_required):
    if type(descriptor_required) is not bool:
        raise ValueError("stock_ssh_owner_invalid_descriptor_mode")
    raw, ancillary, flags, _ = channel.recvmsg(MAX_PACKET + 1, socket.CMSG_SPACE(8 * 4), RECEIVE_CLOEXEC)
    descriptors, keep = [], False
    try:
        malformed = False
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                malformed = True
                continue
            rows = array.array("i")
            malformed |= bool(len(payload) % rows.itemsize)
            rows.frombytes(payload[:len(payload) - len(payload) % rows.itemsize])
            descriptors.extend(rows)
        if (malformed or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(descriptors) != int(descriptor_required)):
            raise ValueError("stock_ssh_owner_unexpected_descriptor")
        if not raw and not descriptors:
            return None, None
        value = decode(raw)
        keep = True
        return value, descriptors[0] if descriptors else None
    finally:
        if not keep:
            for descriptor in descriptors:
                os.close(descriptor)


def send(channel, value):
    send_packet(channel, value)


def receive(channel):
    return receive_packet(channel, descriptor_required=False)[0]


def request(value, *, daemon=False, now=None):
    fields = {"selection", "deadline", "host_namespaces", "runtime_digest"} | ({"manifest"} if daemon else set())
    if type(value) is not dict or set(value) != fields:
        raise ValueError("stock_ssh_owner_invalid_request")
    selected = contract.validate_selection(value["selection"])
    now = time.monotonic() if now is None else now
    if (type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - now <= 60):
        raise ValueError("stock_ssh_owner_expired")
    digest = value["runtime_digest"]
    if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("stock_ssh_owner_invalid_runtime_digest")
    host = value["host_namespaces"]
    if (type(host) is not dict or set(host) != {"user", "net", "mnt", "pid"}
            or any(type(item) is not str or re.fullmatch(key + r":\[\d+\]", item) is None for key, item in host.items())):
        raise ValueError("stock_ssh_owner_invalid_host_namespaces")
    if daemon:
        manifest = runtime.validate_manifest(value["manifest"])
        if (runtime.manifest_digest(manifest) != digest or any(manifest[key] != item
                for key, item in contract.preparation_selection(selected).items())):
            raise ValueError("stock_ssh_owner_runtime_changed")
    return value


def verify_mounted_runtime(manifest):
    """Inspect only manifest-validated, sealed virtual destinations."""
    manifest = runtime.validate_manifest(manifest)
    for item in manifest["files"]:
        descriptor = os.open(item["destination"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_size != item["size"]
                    or before.st_mode & 0o022 or not os.statvfs(item["destination"]).f_flag & os.ST_RDONLY):
                raise ValueError("stock_ssh_owner_unsealed_runtime")
            raw = bytearray()
            while len(raw) <= item["size"]:
                part = os.read(descriptor, min(65536, item["size"] + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            after = os.fstat(descriptor)
            if (len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError("stock_ssh_owner_runtime_changed")
        finally:
            os.close(descriptor)


def validate_connected_identity(value):
    if (type(value) is not dict or set(value) != {"inode", "local", "peer", "netns_cookie"}
            or any(type(value[key]) is not int or not 0 < value[key] < 2**64 for key in ("inode", "netns_cookie"))):
        raise ValueError("stock_ssh_owner_invalid_descriptor_identity")
    for key in ("local", "peer"):
        address = value[key]
        if (type(address) is not list or len(address) != 2 or address[0] != "127.0.0.1"
                or type(address[1]) is not int or not 1 <= address[1] <= 65535):
            raise ValueError("stock_ssh_owner_invalid_descriptor_endpoint")
    if value["local"] == value["peer"]:
        raise ValueError("stock_ssh_owner_same_descriptor_endpoint")
    return dict(value)


def prepare_addresses(configuration):
    selected = spec.action(configuration, "O1")
    addresses = tuple(dict.fromkeys((selected["target"], *(row[0] for row in spec.witness_endpoints(configuration)))))
    interface = socket.if_nametoindex("lo")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("stock_ssh_owner_network_attached")
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(2); channel.bind((0, 0))
        for sequence, address in enumerate(addresses, 1):
            packed = socket.inet_pton(socket.AF_INET, address)
            attribute = struct.pack("=HH", 8, 1) + packed + struct.pack("=HH", 8, 2) + packed
            body = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, interface) + attribute
            message = struct.pack("=IHHII", 16 + len(body), 20, 1 | 4 | 0x400 | 0x200, sequence, 0) + body
            if channel.sendto(message, (0, 0)) != len(message):
                raise ValueError("stock_ssh_owner_address_truncated")
            raw, sender = channel.recvfrom(4097)
            if (sender != (0, 0) or not 36 <= len(raw) <= 4096
                    or struct.unpack_from("=IHH", raw)[:2] != (len(raw), 2)
                    or struct.unpack_from("=I", raw, 8)[0] != sequence
                    or struct.unpack_from("=i", raw, 16)[0] != 0 or raw[20:36] != message[:16]):
                raise ValueError("stock_ssh_owner_address_ack_invalid")


def validate_private_transport(value, selection):
    selected = contract.validate_selection(selection)
    if (type(value) is not dict or set(value) != {"mode", "pairs", "private_listener_closed", "exact_established_routes_only",
                                               "setup_exchange_verified", "setup_witness_bytes_each_direction"}
            or value["mode"] != "preconnected-loopback-tcp-descriptor-no-live-listener"
            or value["private_listener_closed"] is not True or value["exact_established_routes_only"] is not True
            or value["setup_exchange_verified"] is not True
            or type(value["setup_witness_bytes_each_direction"]) is not int
            or value["setup_witness_bytes_each_direction"] != len(PRIVATE_WITNESS)
            or type(value["pairs"]) is not list
            or len(value["pairs"]) != spec.budgets(selected["case"])["max_connections"]):
        raise ValueError("stock_ssh_owner_invalid_private_transport")
    rows = [validate_connected_identity(item) for item in value["pairs"]]
    if (len({row["inode"] for row in rows}) != len(rows)
            or len({tuple(row["peer"]) for row in rows}) != len(rows)
            or len({tuple(row["local"]) for row in rows}) != 1
            or len({row["netns_cookie"] for row in rows}) != 1):
        raise ValueError("stock_ssh_owner_private_transport_mismatch")
    return deepcopy(value)


def private_pairs(count, deadline, *, prepare_transport=None):
    if type(count) is not int or not 1 <= count <= MAX_INSTANCES:
        raise ValueError("stock_ssh_owner_pair_count")
    result, clients = [], []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen(count)
            listener.settimeout(worker._remaining(deadline, 2))
            for _ in range(count):
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clients.append(client)
                client.bind(("127.0.0.1", 0))
            if prepare_transport is not None:
                # Pin both endpoint tuples before allowing their handshake.
                # Installing conntrack hooks after a TCP handshake would make
                # its first data appear NEW and fail the final established gate.
                prepare_transport([{"local": list(listener.getsockname()), "peer": list(client.getsockname())}
                                   for client in clients])
            for client in clients:
                server = None
                try:
                    client.settimeout(worker._remaining(deadline, 2)); client.connect(listener.getsockname())
                    server, _ = listener.accept()
                    client.setblocking(False); server.setblocking(False)
                    identity = validate_connected_identity(custodian.connected_identity(server.fileno()))
                    peer = validate_connected_identity(custodian.connected_identity(client.fileno()))
                    if (identity["local"] != peer["peer"] or identity["peer"] != peer["local"]
                            or identity["netns_cookie"] != peer["netns_cookie"]):
                        raise ValueError("stock_ssh_owner_pair_changed")
                    result.append((client, server, identity))
                except BaseException:
                    client.close()
                    if server is not None: server.close()
                    raise
        return result  # Listening socket is closed before firewall/confinement.
    except BaseException:
        for client, server, _ in result:
            client.close(); server.close()
        for client in clients: client.close()
        raise


def _firewall_rules(configuration, routes, *, setup):
    spec.validate_selection(configuration, "O1")
    if type(routes) is not list or not 1 <= len(routes) <= MAX_INSTANCES:
        raise ValueError("stock_ssh_owner_invalid_private_routes")
    for item in routes:
        if type(item) is not dict or set(item) != {"local", "peer"}:
            raise ValueError("stock_ssh_owner_invalid_private_route")
        validate_connected_identity({"inode": 1, "netns_cookie": 1, **item})
    if len({(tuple(item["local"]), tuple(item["peer"])) for item in routes}) != len(routes):
        raise ValueError("stock_ssh_owner_duplicate_private_route")
    selected = spec.action(configuration, "O1")
    target, port = selected["target"], selected["parameters"]["port"]
    chains = []
    for hook, interface in (("output", "oifname"), ("input", "iifname")):
        rules = [f'  {interface} "lo" ip daddr {target} tcp dport {port} ct direction original accept',
            f'  {interface} "lo" ct direction reply ct state established ct original ip daddr {target} ct original proto-dst {port} accept']
        for item in routes:
            for source, destination in ((item["local"], item["peer"]), (item["peer"], item["local"])):
                state = "{ new, established }" if setup else "established"
                rules.append(f'  {interface} "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {source[1]} tcp dport {destination[1]} ct state {state} accept')
        chains.append(f' chain {hook} {{ type filter hook {hook} priority 0; policy drop;\n' + "\n".join(rules) + "\n }")
    return "table inet recon_stock_ssh {\n" + "\n".join(chains) + "\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n"


def firewall_rules(configuration, identities):
    if type(identities) is not list:
        raise ValueError("stock_ssh_owner_invalid_private_routes")
    identities = [validate_connected_identity(item) for item in identities]
    return _firewall_rules(configuration, [{key: item[key] for key in ("local", "peer")} for item in identities], setup=False)


def verify_private_pairs(pairs, deadline):
    """Consume fixed setup witnesses through the FINAL firewall in both directions."""
    for client, server, identity in pairs:
        if custodian.connected_identity(server.fileno()) != identity:
            raise ValueError("stock_ssh_owner_pair_changed")
        for sender, receiver in ((client, server), (server, client)):
            sender.settimeout(worker._remaining(deadline, 1))
            receiver.settimeout(worker._remaining(deadline, 1))
            try:
                sender.sendall(PRIVATE_WITNESS)
                received = bytearray()
                while len(received) < len(PRIVATE_WITNESS):
                    raw = receiver.recv(len(PRIVATE_WITNESS) - len(received))
                    if not raw:
                        raise ValueError("stock_ssh_owner_private_witness_incomplete")
                    received.extend(raw)
                if bytes(received) != PRIVATE_WITNESS:
                    raise ValueError("stock_ssh_owner_private_witness_changed")
            finally:
                sender.setblocking(False); receiver.setblocking(False)


def _control_channel(descriptor):
    channel = socket.socket(fileno=descriptor)
    if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
        channel.close()
        raise ValueError("stock_ssh_owner_requires_control_socket")
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, MAX_PACKET * 2)
    return channel


def _wait(channel, deadline, *, descriptor=False):
    ready, _, _ = select.select([channel], [], [], max(0, deadline - time.monotonic()))
    if not ready:
        raise TimeoutError("stock_ssh_owner_control_timeout")
    return receive_packet(channel, descriptor_required=descriptor)


def validate_instance_message(message, *, last, count, selected, owner_deadline, now=None):
    now = time.monotonic() if now is None else now
    contract.validate_selection(selected)
    if (type(message) is not dict or set(message) != {"operation", "connection_id", "deadline", "descriptor"}
            or message["operation"] != "instance" or type(message["connection_id"]) is not int
            or not last < message["connection_id"] <= recorder.MAX_CONNECTION_ATTEMPTS
            or count >= spec.budgets(selected["case"])["max_connections"]
            or type(message["deadline"]) not in (int, float) or not math.isfinite(message["deadline"])
            or not 0 < message["deadline"] - now <= 5 or message["deadline"] > owner_deadline):
        raise ValueError("stock_ssh_owner_invalid_instance")
    validate_connected_identity(message["descriptor"])
    return deepcopy(message)


def _is_cancel(value, number):
    return (type(value) is dict and set(value) == {"operation", "connection_id"}
            and value["operation"] == "cancel" and type(value["connection_id"]) is int
            and value["connection_id"] == number)


def custodian_main():
    channel = _control_channel(0)
    try:
        send(channel, {"bootstrap_waiting": True, "namespaces": namespaces()})
        value = request(receive(channel), daemon=True)
        selected, manifest = value["selection"], value["manifest"]
        identity = namespace_identity(value["host_namespaces"], "apache")
        verify_mounted_runtime(manifest)
        worker._set_limits(worker._remaining(value["deadline"], 60))
        worker.drop_privileges(); identity = seal_group_identity(identity)
        custodian.confine_custodian(manifest)
        send(channel, {"ready": True, "namespaces": namespaces(), "namespace_identity": identity,
            "bounds": process.BOUNDS, "runtime_digest": value["runtime_digest"]})
        count, last, last_cancelled, cookie = 0, 0, False, None
        while True:
            ready, _, _ = select.select([channel], [], [], worker._remaining(value["deadline"], 60))
            if not ready:
                raise TimeoutError("stock_ssh_owner_deadline")
            # Exactly one FD is required for an instance; inspect metadata first
            # using MSG_PEEK, then consume it with the fixed ancillary parser.
            raw = channel.recv(MAX_PACKET + 1, socket.MSG_PEEK)
            if not raw:
                return 0
            proposed = decode(raw)
            operation = proposed.get("operation")
            message, descriptor = receive_packet(channel, descriptor_required=operation == "instance")
            if operation == "close" and message == {"operation": "close"}:
                return 0
            if _is_cancel(message, last) and last and not last_cancelled:
                last_cancelled = True  # Exact stale cancellation has no effect on another instance.
                continue
            try:
                message = validate_instance_message(message, last=last, count=count,
                    selected=selected, owner_deadline=value["deadline"])
                actual = validate_connected_identity(custodian.connected_identity(descriptor))
                if actual != validate_connected_identity(message["descriptor"]) or cookie is not None and cookie != actual["netns_cookie"]:
                    raise ValueError("stock_ssh_owner_instance_descriptor_changed")
                cookie, last, last_cancelled = actual["netns_cookie"], message["connection_id"], False
                count += 1  # Reserve before the first process creation.
                send(channel, {"operation": "started", "connection_id": last})
                def cancelled():
                    nonlocal last_cancelled
                    ready, _, _ = select.select([channel], [], [], 0)
                    if not ready:
                        return False
                    cancellation = receive(channel)
                    if not _is_cancel(cancellation, last) or last_cancelled:
                        raise ValueError("stock_ssh_owner_invalid_cancellation")
                    last_cancelled = True
                    return True
                receipt = custodian.run_instance(descriptor, manifest, deadline=message["deadline"], cancelled=cancelled)
                receipt = process.validate_receipt(receipt)
                send(channel, {"operation": "finished", "connection_id": last, "receipt": receipt})
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    finally:
        channel.close()


class InstanceChannels:
    """One-use connected descriptor transfer with synchronous reaping barrier."""

    def __init__(self, channel, pairs, deadline):
        self.channel, self.pairs, self.deadline = channel, list(pairs), deadline
        self.receipts, self.active, self.started = [], None, None

    def connect(self, number, deadline):
        if self.active is not None or not self.pairs:
            raise ValueError("stock_ssh_owner_instance_overlap_or_exhaustion")
        client, server, identity = self.pairs.pop(0)
        self.active = (number, client, identity)
        try:
            if custodian.connected_identity(server.fileno()) != identity:
                raise ValueError("stock_ssh_owner_descriptor_changed")
            send_packet(self.channel, {"operation": "instance", "connection_id": number,
                "deadline": deadline, "descriptor": identity}, server.fileno())
        finally:
            server.close()
        reply, _ = _wait(self.channel, min(deadline, time.monotonic() + 1))
        if (type(reply) is not dict or type(reply.get("connection_id")) is not int
                or reply != {"operation": "started", "connection_id": number}):
            raise ValueError("stock_ssh_owner_instance_not_started")
        return client

    def finalize(self, number):
        if self.active is None:
            return
        active, self.active = self.active, None
        if active[0] != number:
            raise ValueError("stock_ssh_owner_instance_finalizer_mismatch")
        active[1].close()
        ready, _, _ = select.select([self.channel], [], [], .05)
        if not ready:
            send(self.channel, {"operation": "cancel", "connection_id": number})
        reply, _ = _wait(self.channel, time.monotonic() + 1)
        if (type(reply) is not dict or set(reply) != {"operation", "connection_id", "receipt"}
                or reply["operation"] != "finished" or reply["connection_id"] != number
                or type(reply["connection_id"]) is not int
                or type(reply["receipt"]) is not dict
                or reply["receipt"].get("descriptor") != active[2]
                or reply["receipt"].get("all_server_processes_reaped") is not True):
            raise ValueError("stock_ssh_owner_instance_not_reaped")
        receipt = process.validate_receipt(reply["receipt"])
        self.receipts.append({"connection_id": number, "receipt": receipt})
        if (len(self.receipts) > MAX_INSTANCES
                or sum(row["receipt"]["server_identities"] for row in self.receipts) > 3 * MAX_INSTANCES
                or sum(row["receipt"]["fork_attempts"] for row in self.receipts) > 2 * MAX_INSTANCES
                or sum(row["receipt"]["exec_attempts"] for row in self.receipts) > 3 * MAX_INSTANCES):
            raise ValueError("stock_ssh_owner_aggregate_process_limit")

    def close(self):
        if self.active is not None:
            self.finalize(self.active[0])
        for client, server, _ in self.pairs:
            client.close(); server.close()
        self.pairs.clear()


def recorder_main():
    channel = _control_channel(0)
    custody, channels, service, listeners = None, None, None, []
    pairs = []
    try:
        value = request(receive(channel))
        selected = value["selection"]
        transfer, descriptor = receive_packet(channel, descriptor_required=True)
        custody = _control_channel(descriptor)
        if transfer != {"operation": "custodian_channel"}:
            raise ValueError("stock_ssh_owner_invalid_custodian_transfer")
        worker.assert_private_namespaces(value["host_namespaces"])
        worker._set_limits(worker._remaining(value["deadline"], 60))
        existing.scratch_bound("/scratch")
        prepare_addresses(selected["configuration"])
        action = spec.action(selected["configuration"], selected["case"])
        for address in ((action["target"], action["parameters"]["port"]), *spec.witness_endpoints(selected["configuration"])):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(address); listener.listen(8)
        for listener in listeners[1:]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(worker._remaining(value["deadline"], 1)); connection.connect(listener.getsockname())
                accepted, _ = listener.accept(); accepted.close()
        def setup_transport(routes):
            subprocess.run(["/usr/sbin/nft", "-f", "-"], input=_firewall_rules(selected["configuration"], routes, setup=True).encode("ascii"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, check=True,
                timeout=worker._remaining(value["deadline"], 3), env={"LC_ALL": "C"})
        pairs = private_pairs(spec.budgets(selected["case"])["max_connections"], value["deadline"], prepare_transport=setup_transport)
        identities = [identity for _, _, identity in pairs]
        subprocess.run(["/usr/sbin/nft", "-f", "-"], input=("delete table inet recon_stock_ssh\n" + firewall_rules(selected["configuration"], identities)).encode("ascii"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, check=True,
            timeout=worker._remaining(value["deadline"], 3), env={"LC_ALL": "C"})
        verify_private_pairs(pairs, value["deadline"])
        channels = InstanceChannels(custody, pairs, value["deadline"])
        pairs = []
        service = recorder.Service(selected["configuration"], selected["case"], listeners[0], deadline=value["deadline"],
            connection_factory=channels.connect, connection_finalizer=channels.finalize)
        worker.drop_privileges(); existing.limits(value["deadline"])
        existing.socket_filter(daemon=False); existing.confinement_witnesses()
        common.apply_landlock({"/dev/null": 6, "/proc/self/status": 4, "/scratch": (1 << 15) - 2})
        send(channel, {"ready": True, "namespaces": namespaces(), "witness_baselines": True,
            "bounds": BOUNDS, "runtime_digest": value["runtime_digest"], "private_transport": {
                "mode": "preconnected-loopback-tcp-descriptor-no-live-listener", "pairs": identities,
                "private_listener_closed": True, "exact_established_routes_only": True,
                "setup_exchange_verified": True, "setup_witness_bytes_each_direction": len(PRIVATE_WITNESS)}})
        sequence = 0
        while True:
            worker._remaining(value["deadline"], 60)
            ready, _, _ = select.select([channel, *listeners[1:]], [], [], 0)
            if any(listener in ready for listener in listeners[1:]):
                raise RuntimeError("stock_ssh_owner_destination_witness_leak")
            if channel in ready:
                command = receive(channel)
                if command is None:
                    return 0
                sequence += 1
                operation = command.get("operation")
                if (type(command.get("sequence")) is not int or command["sequence"] != sequence or sequence > 64
                        or operation not in ("ready", "arm", "snapshot", "finish", "close")
                        or set(command) != {"sequence", "operation"} | ({"deadline"} if operation == "arm" else set())):
                    raise ValueError("stock_ssh_owner_invalid_command")
                if operation == "arm": service.arm(command["deadline"])
                elif operation in ("finish", "close"): service.close()
                send(channel, {"sequence": sequence, "operation": operation, "recorder": service.snapshot(),
                               "instances": channels.receipts})
                if operation == "close": return 0
            service.tick(.01)
    finally:
        if service is not None: service.close()
        if channels is not None: channels.close()
        for client, server, _ in pairs:
            client.close(); server.close()
        for listener in listeners: listener.close()
        if custody is not None: custody.close()
        channel.close()


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("recorder", "custodian") or not ENTRY_DESCRIPTORS_VERIFIED:
            raise ValueError("stock_ssh_owner_invalid_mode")
        return recorder_main() if sys.argv[1] == "recorder" else custodian_main()
    except Exception:
        sys.stderr.write("stock_ssh_owner_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
