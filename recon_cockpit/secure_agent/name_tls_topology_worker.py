"""Finite private veth setup; no host network descriptors or target input."""

import os
import sys

ENTRY_DESCRIPTORS_VERIFIED = False
if __name__ == "__main__":
    # Validate inherited descriptors before imports that may open runtime files.
    for _name in os.listdir("/proc/self/fd"):
        if int(_name) > 2:
            try:
                os.fstat(int(_name))
            except OSError:
                continue
            raise SystemExit(78)
    ENTRY_DESCRIPTORS_VERIFIED = True
    sys.path.insert(0, "/app")

import ctypes
import errno
import fcntl
import math
import resource
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import time

from recon_cockpit.secure_agent import name_tls_topology as topology
from recon_cockpit.secure_agent import worker, tool_worker_common as common
from recon_cockpit.secure_agent import name_tls_worker_common as bootstrap

LIBC = ctypes.CDLL(None, use_errno=True)
if hasattr(LIBC, "setns"):
    LIBC.setns.argtypes = (ctypes.c_int, ctypes.c_int)
if hasattr(LIBC, "unshare"):
    LIBC.unshare.argtypes = (ctypes.c_int,)
CLONE_NEWNET = 0x40000000


def _close_import_descriptor():
    """Close only libffi's verified read-only descriptor opened after entry.

    The initial inventory predates all ctypes imports. The distribution libffi
    retains a descriptor to its mapped image for optional callback trampolines;
    this worker does not construct callbacks and needs no retained image FD.
    """
    if not ENTRY_DESCRIPTORS_VERIFIED:
        raise ValueError("name_tls_topology_entry_descriptors_unverified")
    extra = []
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor <= 2:
            continue
        try:
            identity = os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
            continue
        extra.append((descriptor, identity))
    if len(extra) > 1:
        raise ValueError("name_tls_topology_import_descriptor_count")
    if not extra:
        return
    descriptor, identity = extra[0]
    path = os.readlink("/proc/self/fd/" + str(descriptor))
    if (not re.fullmatch(r"/(?:usr/)?lib(?:64)?/(?:[a-zA-Z0-9_-]+/)?libffi\.so\.\d+(?:\.\d+)*", path)
            or not stat.S_ISREG(identity.st_mode)
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) != os.O_RDONLY
            or not os.statvfs(path).f_flag & os.ST_RDONLY):
        raise ValueError("name_tls_topology_import_descriptor_identity")
    with open("/proc/self/maps", encoding="ascii") as stream:
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise ValueError("name_tls_topology_import_mapping_limit")
    expected_device = (os.major(identity.st_dev), os.minor(identity.st_dev))
    verified = False
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[1] == "r-xp" and fields[5] == path:
            device = tuple(int(part, 16) for part in fields[3].split(":"))
            if device == expected_device and int(fields[4]) == identity.st_ino:
                verified = True
    if not verified:
        raise ValueError("name_tls_topology_import_mapping_changed")
    os.close(descriptor)


def _enter(descriptor):
    if LIBC.setns(descriptor, CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "name_tls_topology_setns")


def _attribute(kind, raw):
    value = struct.pack("=HH", len(raw) + 4, kind) + raw
    return value + bytes((-len(value)) % 4)


def _attributes(raw):
    values = {}
    while raw:
        if len(raw) < 4:
            raise ValueError("name_tls_topology_netlink_attribute")
        size, kind = struct.unpack_from("=HH", raw)
        kind &= 0x3fff
        padded = (size + 3) & ~3
        if size < 4 or padded > len(raw) or kind in values or any(raw[size:padded]) or len(values) >= 64:
            raise ValueError("name_tls_topology_netlink_attribute")
        values[kind] = raw[4:size]
        raw = raw[padded:]
    return values


def _text_attribute(raw):
    if not raw or raw[-1:] != b"\0" or b"\0" in raw[:-1]:
        raise ValueError("name_tls_topology_netlink_text")
    return raw[:-1].decode("ascii", "strict")


class Netlink:
    def __init__(self):
        self.channel = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        self.channel.settimeout(1)
        self.channel.bind((0, 0))
        self.sequence = 0

    def close(self):
        self.channel.close()

    def send(self, kind, body, *, create=False):
        self.sequence += 1
        flags = 1 | 4 | (0x400 | 0x200 if create else 0)
        header = struct.pack("=IHHII", 16 + len(body), kind, flags, self.sequence, 0)
        if self.channel.sendto(header + body, (0, 0)) != len(header + body):
            raise ValueError("name_tls_topology_netlink_short_send")
        raw, sender = self.channel.recvfrom(4097)
        if (sender != (0, 0) or not 36 <= len(raw) <= 4096
                or struct.unpack_from("=IHHI", raw)[:2] != (len(raw), 2)
                or struct.unpack_from("=I", raw, 8)[0] != self.sequence or raw[20:36] != header):
            raise ValueError("name_tls_topology_netlink_ack")
        error = struct.unpack_from("=i", raw, 16)[0]
        if error:
            raise OSError(-error, "name_tls_topology_netlink_rejected")

    def veth(self, name, peer_namespace):
        info = struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, 0, 0, 0)
        peer = info + _attribute(3, b"eth0\0") + _attribute(28, struct.pack("=i", peer_namespace))
        detail = _attribute(1, b"veth\0") + _attribute(0x8002, _attribute(0x8001, peer))
        self.send(16, info + _attribute(3, name.encode("ascii") + b"\0") + _attribute(0x8012, detail), create=True)

    def up(self, name):
        index = socket.if_nametoindex(name)
        self.send(16, struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, index, 1, 1))

    def address(self, interface, address, prefix):
        packed = socket.inet_pton(socket.AF_INET, address)
        body = struct.pack("=BBBBI", socket.AF_INET, prefix, 0, 0, socket.if_nametoindex(interface))
        self.send(20, body + _attribute(1, packed) + _attribute(2, packed), create=True)

    def route(self, destination, gateway, interface):
        body = struct.pack("=BBBBBBBBI", socket.AF_INET, 32, 0, 0, 254, 4, 0, 1, 0)
        self.send(24, body + _attribute(1, socket.inet_pton(socket.AF_INET, destination))
                  + _attribute(5, socket.inet_pton(socket.AF_INET, gateway))
                  + _attribute(4, struct.pack("=I", socket.if_nametoindex(interface))), create=True)

    def dump(self, kind, body, expected):
        self.sequence += 1
        header = struct.pack("=IHHII", 16 + len(body), kind, 1 | 0x300, self.sequence, 0)
        if self.channel.sendto(header + body, (0, 0)) != len(header + body):
            raise ValueError("name_tls_topology_dump_send")
        records, received = [], 0
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            raw, _, flags, sender = self.channel.recvmsg(65536)
            received += len(raw)
            if sender != (0, 0) or flags or received > 131072:
                raise ValueError("name_tls_topology_dump_bounds")
            while raw:
                if len(raw) < 16:
                    raise ValueError("name_tls_topology_dump_header")
                size, message, flags, sequence, _ = struct.unpack_from("=IHHII", raw)
                padded = (size + 3) & ~3
                if (size < 16 or padded > len(raw) or sequence != self.sequence
                        or flags & 0x10 or any(raw[size:padded])):
                    raise ValueError("name_tls_topology_dump_header")
                payload, raw = raw[16:size], raw[padded:]
                if message == 3:
                    if payload not in (b"", bytes(4)) or raw:
                        raise ValueError("name_tls_topology_dump_done")
                    return records
                if message != expected or len(records) >= 128:
                    raise ValueError("name_tls_topology_dump_record")
                records.append(payload)
        raise ValueError("name_tls_topology_dump_deadline")

    def observe(self):
        links, addresses, routes, names = [], [], [], {}
        for raw in self.dump(18, struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, 0, 0, 0), 16):
            if len(raw) < 16:
                raise ValueError("name_tls_topology_link_record")
            _, _, hardware, index, flags, _ = struct.unpack_from("=BBHiII", raw)
            attrs = _attributes(raw[16:])
            name = _text_attribute(attrs[3])
            loopback = hardware == 772
            kind = "loopback" if loopback else _text_attribute(_attributes(attrs[18])[1])
            peer = None if loopback else struct.unpack("=I", attrs[5])[0]
            links.append({"interface": name, "index": index, "peer_index": peer, "kind": kind, "up": bool(flags & 1)})
            if index in names:
                raise ValueError("name_tls_topology_duplicate_link_index")
            names[index] = name
        for raw in self.dump(22, struct.pack("=BBBBI", socket.AF_INET, 0, 0, 0, 0), 20):
            if len(raw) < 8:
                raise ValueError("name_tls_topology_address_record")
            family, prefix, _, _, index = struct.unpack_from("=BBBBI", raw)
            attrs = _attributes(raw[8:])
            if family != socket.AF_INET or attrs.get(1) != attrs.get(2):
                raise ValueError("name_tls_topology_address_family")
            addresses.append({"interface": names[index], "address": socket.inet_ntop(socket.AF_INET, attrs[2]), "prefix": prefix})
        for raw in self.dump(26, struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0), 24):
            if len(raw) < 12:
                raise ValueError("name_tls_topology_route_record")
            family, prefix, source_prefix, tos, table, protocol, scope, kind, flags = struct.unpack_from("=BBBBBBBBI", raw)
            attrs = _attributes(raw[12:])
            if (family != socket.AF_INET or source_prefix or tos or flags
                    or set(attrs) - {1, 4, 5, 7, 12, 15}):
                raise ValueError("name_tls_topology_route_semantics")
            routes.append({"table": struct.unpack("=I", attrs[15])[0] if 15 in attrs else table,
                "destination": socket.inet_ntop(socket.AF_INET, attrs.get(1, bytes(4))), "prefix": prefix,
                "gateway": socket.inet_ntop(socket.AF_INET, attrs[5]) if 5 in attrs else None,
                "interface": names[struct.unpack("=I", attrs[4])[0]], "protocol": protocol, "scope": scope, "type": kind})
        with open("/proc/sys/net/ipv4/ip_forward", encoding="ascii") as stream:
            forwarding = stream.read(3)
        if forwarding not in ("0\n", "1\n"):
            raise ValueError("name_tls_topology_forwarding_state")
        return {"links": sorted(links, key=lambda item: item["interface"]),
                "addresses": sorted(addresses, key=topology.encode),
                "routes": sorted(routes, key=topology.encode), "ipv4_forwarding": forwarding == "1\n", "ipv6_disabled": _ipv6_disabled()}


def _set_limits(deadline):
    if not 0 < deadline - time.monotonic() <= 60:
        raise ValueError("name_tls_topology_deadline")
    for kind, maximum in ((resource.RLIMIT_AS, topology.BOUNDS["address_space_bytes"]),
                          (resource.RLIMIT_NOFILE, topology.BOUNDS["file_descriptors"]),
                          (resource.RLIMIT_FSIZE, topology.BOUNDS["retained_bytes"]),
                          (resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 62)):
        inherited = resource.getrlimit(kind)[1]
        maximum = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (maximum, maximum))
    signal.signal(signal.SIGALRM, worker._deadline)
    signal.setitimer(signal.ITIMER_REAL, deadline - time.monotonic())


def _nft(rules, deadline):
    """One fixed helper at a time; bounded writes, reads, lifetime and reap."""
    process = subprocess.Popen(["/usr/sbin/nft", "-f", "-"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, env={"LC_ALL": "C"}, start_new_session=True)
    output = bytearray()
    end = min(deadline, time.monotonic() + topology.BOUNDS["setup_helper_seconds"])
    try:
        process.stdin.write(rules.encode("ascii"))
        process.stdin.close()
        os.set_blocking(process.stdout.fileno(), False)
        eof = False
        while not eof or process.poll() is None:
            if time.monotonic() >= end:
                raise ValueError("name_tls_topology_nft_timeout")
            if not eof and select.select([process.stdout], [], [], min(.05, end - time.monotonic()))[0]:
                raw = os.read(process.stdout.fileno(), topology.BOUNDS["setup_helper_output_bytes"] + 1 - len(output))
                if not raw:
                    eof = True
                output.extend(raw)
                if len(output) > topology.BOUNDS["setup_helper_output_bytes"]:
                    raise ValueError("name_tls_topology_nft_output_limit")
            elif eof:
                process.wait(timeout=max(.001, end - time.monotonic()))
        if process.returncode != 0:
            raise ValueError("name_tls_topology_nft_refused:" + output.decode("ascii", "replace"))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2)
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()


def _listener(endpoint):
    channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        channel.bind(endpoint)
        channel.listen(1)
        channel.setblocking(False)
        return channel
    except BaseException:
        channel.close()
        raise


def _assert_descriptors(expected, count):
    if len(expected) != count or any(type(item) is not int or item < 0 for item in expected):
        raise ValueError("name_tls_topology_descriptor_expectation")
    observed = set()
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            observed.add(descriptor)
    if observed != expected:
        raise ValueError("name_tls_topology_descriptor_inventory:expected=" + repr(sorted(expected))
                         + ":observed=" + repr(sorted(observed)))


def _witnesses(networks, listeners, *, filtered, deadline, configuration="A"):
    selected_endpoints = topology.endpoints(configuration)
    result = []
    for client in topology.OPERATIONS:
        _enter(networks[client + "_client"])
        for endpoint in selected_endpoints:
            if time.monotonic() >= deadline:
                raise ValueError("name_tls_topology_witness_deadline")
            connected = False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(min(.15 if filtered else .5, deadline - time.monotonic()))
                try:
                    connection.connect(selected_endpoints[endpoint])
                    connected = True
                except (TimeoutError, ConnectionRefusedError, OSError) as error:
                    if not isinstance(error, TimeoutError) and getattr(error, "errno", None) not in (
                            errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM):
                        raise
                if connected:
                    ready = select.select([listeners[endpoint]], [], [], .5)[0]
                    if not ready:
                        raise ValueError("name_tls_topology_witness_accept_missing")
                    accepted, peer = listeners[endpoint].accept()
                    with accepted:
                        if peer[0] != topology.CLIENTS[client]:
                            raise ValueError("name_tls_topology_witness_source_changed")
                        connection.sendall(b"routing-witness\n")
                        accepted.settimeout(.5)
                        if accepted.recv(64) != b"routing-witness\n":
                            raise ValueError("name_tls_topology_witness_payload_changed")
            if connected != (endpoint == client if filtered else True):
                raise ValueError("name_tls_topology_witness_failed:" + client + ":" + endpoint)
            result.append({"client": client, "endpoint": endpoint, "connected": connected})
    _enter(networks["router"])
    return result


def _seal():
    # Import/preload all filter dependencies before denying filesystem writes.
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    worker.drop_privileges()
    common.apply_landlock({"/proc": 12})
    common.syscall_filter(allow_threads=False)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise ValueError("name_tls_topology_seccomp_init")
    try:
        for name in ("socket", "socketpair", "connect", "bind", "listen", "execve", "execveat",
                     "fork", "vfork", "clone", "clone3", "unshare", "setns", "mount", "umount2",
                     "pivot_root", "chroot", "ptrace", "process_vm_readv", "process_vm_writev",
                     "pidfd_open", "pidfd_getfd", "pidfd_send_signal", "io_uring_setup", "bpf",
                     "keyctl", "add_key", "request_key", "open_by_handle_at", "memfd_create"):
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0 or library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) != 0:
                raise ValueError("name_tls_topology_seccomp_rule")
        if library.seccomp_load(context) != 0:
            raise ValueError("name_tls_topology_seccomp_load")
    finally:
        library.seccomp_release(context)
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    status = worker._status()
    if (status["NoNewPrivs"] != "1" or any(int(status[key], 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or os.getpid() != 1 or common._namespace_task_count() != 1):
        raise ValueError("name_tls_topology_seal_changed")
    for call in (lambda: LIBC.unshare(CLONE_NEWNET), lambda: LIBC.setns(-1, CLONE_NEWNET)):
        if call() != -1 or ctypes.get_errno() != errno.EPERM:
            raise ValueError("name_tls_topology_setup_not_disabled")
    try:
        channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError:
        pass
    else:
        channel.close()
        raise ValueError("name_tls_topology_socket_creation_allowed")


def _ipv6_disabled():
    for name in ("all", "default"):
        with open("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", encoding="ascii") as stream:
            if stream.read(3) != "1\n":
                return False
    with open("/proc/net/if_inet6", encoding="ascii") as stream:
        return not stream.read(1)


def _payload_identity():
    from recon_cockpit.secure_agent.name_tls_topology_spec import validate_namespace_identity
    result = {"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups()}
    for name in ("uid", "gid"):
        with open("/proc/self/" + name + "_map", encoding="ascii") as stream:
            raw = stream.read(1025)
        if len(raw) > 1024:
            raise ValueError("name_tls_topology_mapping_limit")
        result[name + "_map"] = [list(map(int, line.split())) for line in raw.splitlines()]
    return validate_namespace_identity(result)


def setup(initial, *, configuration="A"):
    selected = topology.endpoints(configuration)
    if (type(initial) is not dict or set(initial) != {"operation", "deadline", "host_namespaces", "topology_sha256"}
            or initial["operation"] != "setup" or initial["topology_sha256"] != topology.digest(configuration=configuration)
            or type(initial["deadline"]) not in (int, float) or not math.isfinite(initial["deadline"])):
        raise ValueError("name_tls_topology_initial_changed")
    bootstrap.assert_private_namespaces(initial["host_namespaces"])
    identity = _payload_identity()
    deadline = initial["deadline"]
    _set_limits(deadline)
    setup_deadline = min(deadline, time.monotonic() + topology.BOUNDS["setup_seconds"])
    signal.setitimer(signal.ITIMER_REAL, max(.001, setup_deadline - time.monotonic()))
    networks, listeners, exports, ledger_channels = {}, {}, [], {}
    try:
        networks["router"] = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        user = os.open("/proc/self/ns/user", os.O_RDONLY | os.O_CLOEXEC)
        exports.append(user)
        for role in topology.ROLES:
            if role != "router":
                if LIBC.unshare(CLONE_NEWNET) != 0:
                    raise OSError(ctypes.get_errno(), "name_tls_topology_create_network")
                networks[role] = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            _enter(networks[role])
            for name in ("all", "default"):
                with open("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", "w", encoding="ascii") as stream:
                    stream.write("1\n")
            _enter(networks["router"])
        for role, interface, _, _ in topology.LINKS:
            netlink = Netlink()
            try:
                netlink.veth(interface, networks[role])
            finally:
                netlink.close()
        for role in topology.ROLES:
            _enter(networks[role])
            netlink = Netlink()
            try:
                netlink.up("lo")
                if role == "router":
                    for _, interface, local, _ in topology.LINKS:
                        netlink.up(interface)
                        netlink.address(interface, local, 30)
                    netlink.address("lo", selected["dns_excluded"][0], 32)
                    with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="ascii") as stream:
                        stream.write("1\n")
                else:
                    _, _, _, remote = next(row for row in topology.LINKS if row[0] == role)
                    netlink.up("eth0")
                    netlink.address("eth0", remote, 30)
                    if role.endswith("frontend"):
                        netlink.address("eth0", selected["dns" if role == "dns_frontend" else "http"][0], 32)
                for destination, gateway, interface in topology.routes(role, configuration=configuration):
                    netlink.route(destination, gateway, interface)
            finally:
                netlink.close()
            for key in topology.listener_keys(role):
                listeners[key] = _listener(selected[key])
        observed = {}
        for role in topology.ROLES:
            _enter(networks[role])
            netlink = Netlink()
            try:
                observed[role] = netlink.observe()
            finally:
                netlink.close()
        topology.validate_network_state(observed, configuration=configuration)
        baseline = _witnesses(networks, listeners, filtered=False, deadline=setup_deadline, configuration=configuration)
        for role in topology.ROLES:
            _enter(networks[role])
            _nft(topology.firewall_rules(role, configuration=configuration), setup_deadline)
        filtered = _witnesses(networks, listeners, filtered=True, deadline=setup_deadline, configuration=configuration)
        for operation in topology.OPERATIONS:
            owner, frontend = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            owner.setblocking(False)
            frontend.setblocking(False)
            ledger_channels[operation + "_frontend"] = owner
            exports.append(frontend.detach())
        names = {role: topology.namespace_name(networks[role], "net") for role in topology.ROLES}
        ready = {"ready": True, "profile": topology.PROFILE, "topology_sha256": topology.digest(configuration=configuration),
            "user": topology.namespace_name(user, "user"), "networks": names,
            "listeners": {key: topology.socket_identity(value.fileno(), listener=True) for key, value in listeners.items()},
            "baselines": baseline, "filtered": filtered, "bounds": dict(topology.BOUNDS),
            "setup_helpers": 6, "capabilities_dropped": True, "setup_disabled": True, "exports": list(topology.EXPORTS),
            "owner_namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ("user", "net", "mnt", "pid")},
            "network_state": observed, "descriptor_custody": {"before_export": 25, "steady": 19},
            "namespace_identity": identity}
        descriptors = (user, *(networks[role] for role in topology.ROLES),
                       *(listeners[operation].fileno() for operation in topology.OPERATIONS), *exports[1:])
        _assert_descriptors({0, 1, 2, *networks.values(), *exports,
            *(item.fileno() for item in listeners.values()), *(item.fileno() for item in ledger_channels.values())}, 25)
        _seal()
        if _payload_identity() != identity:
            raise ValueError("name_tls_topology_payload_identity_changed")
        bootstrap.seal_group_identity(identity)
        topology.validate_metadata(ready, configuration=configuration)
        signal.setitimer(signal.ITIMER_REAL, max(.001, deadline - time.monotonic()))
        return ready, descriptors, networks, listeners, exports, ledger_channels
    except BaseException:
        for item in (*listeners.values(), *ledger_channels.values()):
            item.close()
        for descriptor in (*networks.values(), *exports):
            os.close(descriptor)
        raise


def main():
    channel = socket.socket(fileno=0)
    owned = None
    ledger = None
    try:
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError("name_tls_topology_control_type")
        _close_import_descriptor()
        initial, _ = topology.receive_packet(channel)
        base = dict(initial)
        configuration = "A"
        if "selection" in base or "identity" in base:
            from recon_cockpit.secure_agent.name_tls_ledger import Ledger
            from recon_cockpit.secure_agent.name_tls_contract import validate_selection
            selected, identity = base.pop("selection"), base.pop("identity")
            selected = validate_selection(selected)
            configuration = selected["configuration"]
            ledger = Ledger(selected, identity, started_at=base["deadline"] - 60)
        owned = setup(base, configuration=configuration)
        ready, descriptors, networks, listeners, exports, ledger_channels = owned
        topology.send_packet(channel, ready, descriptors)
        # Exported listener copies are exclusively held by the trusted launcher.
        for service in topology.OPERATIONS:
            listeners.pop(service).close()
        for descriptor in exports[1:]:
            os.close(descriptor)
        del exports[1:]
        _assert_descriptors({0, 1, 2, *networks.values(), *exports,
            *(item.fileno() for item in listeners.values()),
            *(item.fileno() for item in ledger_channels.values())}, 19)
        channel.setblocking(False)
        roles = {channel: "launcher", **{item: role for role, item in ledger_channels.items()}}
        snapshots = 0
        stopped = False
        messages = []
        while time.monotonic() < base["deadline"]:
            if ledger is not None:
                ledger.check_deadline()
            readable = select.select([*roles, *listeners.values()], [], [], min(.05, max(0, base["deadline"] - time.monotonic())))[0]
            if not readable:
                continue
            for incoming in readable:
                if incoming not in roles:
                    if ledger is not None:
                        ledger.terminate("continuity_lost")
                    accepted, _ = incoming.accept()
                    accepted.close()
                    raise ValueError("name_tls_topology_denied_listener_received_connection")
                role = roles[incoming]
                try:
                    message, _ = topology.receive_packet(incoming)
                except (ValueError, OSError):
                    if ledger is not None:
                        ledger.terminate("owner_channel_closed" if role == "launcher" else "continuity_lost")
                    if role == "launcher":
                        return 0 if stopped or ledger is None else 78
                    del roles[incoming]
                    continue
                if ledger is None:
                    if role != "launcher" or message != {"operation": "close"}:
                        raise ValueError("name_tls_topology_unknown_operation")
                    topology.send_packet(incoming, {"closed": True,
                        "topology_sha256": topology.digest(configuration=configuration)})
                    return 0
                if role == "launcher" and message == {"operation": "TOPOLOGY_SNAPSHOT"}:
                    snapshots += 1
                    if snapshots > 64:
                        ledger.terminate("owner_protocol_error")
                        raise ValueError("name_tls_topology_snapshot_limit")
                    topology.send_packet(incoming, {"ledger": ledger.snapshot(), "messages": messages})
                else:
                    from recon_cockpit.secure_agent.name_tls_ledger import (
                        MAX_MESSAGE_BYTES, MAX_REPLY_BYTES, MAX_EVENT_BYTES, CLEANUP_OPERATIONS)
                    raw = topology.encode(message)
                    current = len(topology.encode({"ledger": ledger.snapshot(), "messages": messages}))
                    # Reserve the complete future request/reply, its event and
                    # at most one bounded action/binding state expansion before
                    # allowing a message to affect live authority. Retain an
                    # additional 8 KiB for terminal/cleanup evidence.
                    cleanup = message.get("operation") in CLEANUP_OPERATIONS
                    ceiling = topology.MAX_PACKET - (0 if cleanup else 8192)
                    if len(raw) > MAX_MESSAGE_BYTES or current + len(raw) + MAX_REPLY_BYTES + MAX_EVENT_BYTES + 4096 > ceiling:
                        ledger.terminate("owner_protocol_error")
                        raise ValueError("name_tls_topology_transcript_capacity")
                    reply = ledger.apply(message, role=role)
                    retained = topology.decode(topology.encode({"role": role, "message": message, "reply": reply}))
                    messages.append(retained)
                    topology.encode({"ledger": ledger.snapshot(), "messages": messages})
                    topology.send_packet(incoming, reply)
                    stopped |= role == "launcher" and message.get("operation") == "STOP" and reply["status"] == "ok"
        raise ValueError("name_tls_topology_deadline")
    except BaseException as error:
        sys.stderr.write(type(error).__name__ + ":" + str(error)[:2048] + "\n")
        return 78
    finally:
        if owned is not None:
            _, _, networks, listeners, exports, ledger_channels = owned
            for item in (*listeners.values(), *ledger_channels.values()):
                item.close()
            for descriptor in (*networks.values(), *exports):
                os.close(descriptor)
        channel.close()


if __name__ == "__main__":
    raise SystemExit(main())
