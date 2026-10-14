"""Production owner custody and framing tests; no daemon startup occurs here."""

import array
from copy import deepcopy
import errno
import fcntl
import io
import os
import socket
import stat
import struct
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import stock_http_production_contract as contract
from recon_cockpit.secure_agent import stock_http_production_lab as lab
from recon_cockpit.secure_agent import stock_http_production_owner_worker as worker
from recon_cockpit.secure_agent import stock_http_production_transport as transport
from recon_cockpit.secure_agent import stock_apache_runtime as apache_runtime
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_stock_apache_runtime import fake_runtime as fake_apache_runtime, control


HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
PRIVATE = {name: name + ":[200]" for name in HOST}


def selected():
    return contract.selection("apache", "A", "O1")


class SocketDouble:
    def __init__(self):
        self.domain, self.kind, self.protocol = socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP
        self.address, self.blocking, self.cookie, self.peer = ("0.0.0.0", 0), False, 123, None
        self.closed, self.calls = False, []
        self.connect_result = errno.EINPROGRESS

    def fileno(self): return 33
    def getsockname(self): return self.address
    def getblocking(self): return self.blocking
    def setblocking(self, value): self.blocking = value
    def close(self): self.closed = True
    def getsockopt(self, level, option, size=None):
        return {transport.SO_DOMAIN: self.domain, socket.SO_TYPE: self.kind,
                transport.SO_PROTOCOL: self.protocol, transport.SO_NETNS_COOKIE: struct.pack("=Q", self.cookie)}[option]
    def getpeername(self):
        if self.peer is None: raise OSError(errno.ENOTCONN, "unconnected")
        return self.peer
    def connect_ex(self, address):
        self.calls.append(address)
        return self.connect_result


@pytest.fixture
def private_socket(monkeypatch):
    value = SocketDouble()
    monkeypatch.setattr(transport.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_ino=456))
    monkeypatch.setattr(transport.fcntl, "fcntl", lambda *args: os.O_NONBLOCK)
    return value


def test_private_descriptor_identity_has_no_network_side_effect(private_socket):
    assert transport.socket_identity(private_socket) == {"daemon_netns_cookie": 123, "inode": 456}
    assert private_socket.calls == []


@pytest.mark.parametrize("fault", ("domain", "kind", "protocol", "bound", "blocking", "os_blocking", "connected", "cookie", "not_socket"))
def test_descriptor_identity_refuses_wrong_capability(private_socket, monkeypatch, fault):
    if fault == "domain": private_socket.domain = socket.AF_UNIX
    elif fault == "kind": private_socket.kind = socket.SOCK_DGRAM
    elif fault == "protocol": private_socket.protocol = 0
    elif fault == "bound": private_socket.address = ("127.0.0.1", 19080)
    elif fault == "blocking": private_socket.blocking = True
    elif fault == "os_blocking": monkeypatch.setattr(transport.fcntl, "fcntl", lambda *args: 0)
    elif fault == "connected": private_socket.peer = ("127.0.0.1", 19080)
    elif fault == "cookie": private_socket.cookie = 0
    else: monkeypatch.setattr(transport.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_ino=456))
    with pytest.raises(ValueError): transport.socket_identity(private_socket)
    assert private_socket.calls == []


@pytest.mark.parametrize("value", (None, {}, {"daemon_netns_cookie": True, "inode": 1},
    {"daemon_netns_cookie": 0, "inode": 1}, {"daemon_netns_cookie": 1, "inode": -1},
    {"daemon_netns_cookie": 1, "inode": 2**64}, {"daemon_netns_cookie": 1, "inode": 1, "fd": 9}))
def test_descriptor_metadata_is_exact_and_bounded(value):
    with pytest.raises(ValueError): transport.validate_descriptor_identity(value)


class PacketChannel:
    def __init__(self, raw, descriptors=(), flags=0, ancillary=None):
        self.packet = (raw, [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors).tobytes())]
                       if descriptors else [], flags, None)
        if ancillary is not None: self.packet = (raw, ancillary, flags, None)
    def recvmsg(self, *args): return self.packet


@pytest.mark.parametrize("fault", ("missing", "extra", "unexpected", "truncated", "control_truncated", "bad_json", "inheritable", "other_control"))
def test_received_descriptor_custody_closes_every_rejected_fd(monkeypatch, fault):
    closed = []
    descriptors = [] if fault == "missing" else [21, 22] if fault == "extra" else [21]
    channel = PacketChannel(b"bad" if fault == "bad_json" else b'{"ready":true}', descriptors,
        socket.MSG_TRUNC if fault == "truncated" else socket.MSG_CTRUNC if fault == "control_truncated" else 0)
    if fault == "other_control":
        raw, ancillary, flags, address = channel.packet
        channel.packet = (raw, [*ancillary, (0, 0, b"x")], flags, address)
    monkeypatch.setattr(transport.os, "close", closed.append)
    monkeypatch.setattr(transport.os, "get_inheritable", lambda fd: fault == "inheritable")
    with pytest.raises(ValueError): transport.receive_packet(channel, descriptor_required=fault != "unexpected")
    assert closed == descriptors


def test_valid_received_descriptor_transfers_ownership_once(monkeypatch):
    monkeypatch.setattr(transport.os, "get_inheritable", lambda fd: False)
    monkeypatch.setattr(transport.os, "close", lambda fd: pytest.fail("valid transferred descriptor prematurely closed"))
    assert transport.receive_packet(PacketChannel(b'{"ready":true}', [21]), descriptor_required=True) == ({"ready": True}, 21)


@pytest.mark.parametrize("fault", ("constructor", "blocking"))
def test_socket_wrapper_failure_closes_owned_descriptor(monkeypatch, fault):
    closed = []
    if fault == "constructor":
        def constructor(**kwargs): raise OSError(errno.ENOTSOCK, "not a socket")
        monkeypatch.setattr(transport.socket, "socket", constructor)
    else:
        def blocking(value): raise OSError("cannot set blocking")
        channel = SimpleNamespace(setblocking=blocking, close=lambda: closed.append(21))
        monkeypatch.setattr(transport.socket, "socket", lambda **kwargs: channel)
    monkeypatch.setattr(transport.os, "close", closed.append)
    with pytest.raises(OSError): transport.owned_socket(21)
    assert closed == [21]


def test_private_connector_consumes_only_once_and_only_fixed_endpoint(private_socket):
    service = transport.DescriptorService.__new__(transport.DescriptorService)
    service._private_socket = private_socket
    service._private_identity = {"daemon_netns_cookie": 123, "inode": 456}
    assert service._connect_daemon() is private_socket
    assert private_socket.calls == [transport.PRIVATE_ENDPOINT]
    with pytest.raises(ValueError, match="consumed"): service._connect_daemon()
    assert private_socket.calls == [transport.PRIVATE_ENDPOINT]


def test_connect_failure_closes_private_capability(private_socket):
    service = transport.DescriptorService.__new__(transport.DescriptorService)
    service._private_socket = private_socket
    service._private_identity = {"daemon_netns_cookie": 123, "inode": 456}
    private_socket.connect_result = errno.ECONNREFUSED
    with pytest.raises(OSError): service._connect_daemon()
    assert private_socket.closed and service._private_socket is None


def test_finish_closes_unused_private_capability_without_connect(private_socket, monkeypatch):
    service = transport.DescriptorService.__new__(transport.DescriptorService)
    service._private_socket = private_socket
    monkeypatch.setattr(transport.Service, "close", lambda *args: None)
    service.close()
    assert private_socket.closed and private_socket.calls == []
    service.close()


def test_production_owner_constructs_without_starting_anything(fake_apache_runtime, monkeypatch):
    monkeypatch.setattr(lab, "_Supervisor", lambda *args, **kwargs: pytest.fail("owner construction executed"))
    choice = selected()
    value = lab.StockHttpProductionLab(choice, str(uuid4()), SessionLimits(**contract.limits(choice)),
        runtime={"daemon": apache_runtime.inspect_runtime("A", "O1", control()), "client": None})
    assert value.started is False and value.identity["implementation"] == "apache"
    assert value.close()["started"] is False
    with pytest.raises(RuntimeError): value.start(control())


def test_apache_owner_commands_mount_only_pins_and_keep_uid_resources(fake_apache_runtime, monkeypatch):
    monkeypatch.setattr(lab, "_trusted_program", lambda name: "/usr/bin/" + name)
    bootstrap = ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"),
                 ("/usr/sbin/nft", "/usr/sbin/nft"), ("/usr/bin/nsenter", "/usr/bin/nsenter")])
    choice = selected()
    recorder = lab.recorder_command(bootstrap, 20, choice)
    assert recorder[recorder.index("--uid") + 1] == "0"
    assert recorder[recorder.index("--size") + 1] == "786432"
    assert "/peer" not in recorder and "/stock-peer" not in recorder
    assert "--as-pid-1" in recorder and "/usr/bin/nsenter" not in recorder
    manifest = apache_runtime.inspect_runtime("A", "O1", control())
    descriptors = list(range(40, 40 + len(manifest["files"])))
    daemon = lab.daemon_command(bootstrap, manifest, descriptors, choice, 21)
    assert daemon[daemon.index("--uid") + 1] == daemon[daemon.index("--gid") + 1] == "65534"
    assert daemon[daemon.index("--bind") + 1:daemon.index("--bind") + 3] == ["/stock-peer", "/scratch"]
    assert daemon.count("--ro-bind-data") == len(manifest["files"])
    assert "/etc/passwd" in daemon and "/etc/group" in daemon and "/etc/nsswitch.conf" in daemon
    assert "--as-pid-1" in daemon and "--tmpfs" not in daemon and "/usr/sbin/nft" not in daemon
    assert "CAP_NET_ADMIN" not in daemon and "CAP_SETUID" not in daemon and "CAP_SETGID" not in daemon
    with pytest.raises(ValueError): lab.daemon_command(bootstrap, manifest, descriptors[:-1], choice, 21)
    with pytest.raises(ValueError): lab.daemon_command(bootstrap, manifest, descriptors, contract.selection("apache", "B", "O1"), 21)


@pytest.mark.parametrize("fault", ("selection", "implementation", "deadline", "digest", "descriptor", "extra"))
def test_recorder_startup_rejects_changed_binding(fault):
    value = {"selection": selected(), "deadline": 110, "host_namespaces": HOST,
        "runtime_digest": "a" * 64, "descriptor": {"daemon_netns_cookie": 1, "inode": 2}}
    assert worker.request(value, now=100) == value
    if fault == "selection": value["selection"]["case"] = "R1"
    elif fault == "implementation": value["selection"]["implementation"] = "nginx"
    elif fault == "deadline": value["deadline"] = 161
    elif fault == "digest": value["runtime_digest"] = "g" * 64
    elif fault == "descriptor": value["descriptor"]["inode"] = True
    else: value["target"] = "127.0.0.1"
    with pytest.raises(ValueError): worker.request(value, now=100)


def test_daemon_request_pins_exact_apache_manifest(fake_apache_runtime):
    manifest = apache_runtime.inspect_runtime("A", "O1", control())
    value = {"selection": selected(), "deadline": 110, "host_namespaces": HOST,
        "runtime_digest": apache_runtime.manifest_digest(manifest), "manifest": manifest}
    assert worker.request(value, daemon=True, now=100) == value
    for choice in (contract.selection("apache", "B", "O1"), contract.selection("nginx", "A", "O1")):
        with pytest.raises(ValueError): worker.request({**value, "selection": choice}, daemon=True, now=100)


def test_nonzero_daemon_identity_requires_private_namespace_and_single_maps(monkeypatch):
    monkeypatch.setattr(worker, "namespaces", lambda: PRIVATE)
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(worker.os, "getuid", lambda: 65534)
    monkeypatch.setattr(worker.os, "getgid", lambda: 65534)
    monkeypatch.setattr(worker.os, "getgroups", lambda: [])
    monkeypatch.setattr("builtins.open", lambda path, **kwargs: io.StringIO("deny\n" if path.endswith("setgroups") else "65534 1000 1\n"))
    assert worker.namespace_identity(HOST, "apache") == {"uid": 65534, "gid": 65534, "supplementary_groups": [],
        "setgroups_policy": "deny", "group_mutation_denied": False}
    for mapping in ("0 1000 1\n", "65534 -1 1\n", "65534 1000 2\n", "65534 1000 1\n0 2 1\n"):
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: io.StringIO(mapping))
        with pytest.raises(ValueError): worker.namespace_identity(HOST, "apache")


@pytest.mark.parametrize("fault", ("host", "extra_interface", "uid", "gid", "groups"))
def test_nonzero_identity_rejects_wrong_owner(monkeypatch, fault):
    monkeypatch.setattr(worker, "namespaces", lambda: PRIVATE if fault != "host" else HOST)
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo")] + ([(2, "eth0")] if fault == "extra_interface" else []))
    monkeypatch.setattr(worker.os, "getuid", lambda: 0 if fault == "uid" else 65534)
    monkeypatch.setattr(worker.os, "getgid", lambda: 0 if fault == "gid" else 65534)
    monkeypatch.setattr(worker.os, "getgroups", lambda: [7] if fault == "groups" else [])
    monkeypatch.setattr("builtins.open", lambda path, **kwargs: io.StringIO("deny\n" if path.endswith("setgroups") else "65534 1000 1\n"))
    with pytest.raises(ValueError): worker.namespace_identity(HOST, "apache")


TABLE_HEADER = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
TABLE_ROW = b" 0: 0100007F:4A88 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534 0 888 1\n"


@pytest.mark.parametrize("fault", (None, "empty", "extra", "address", "port", "connected", "header", "oversize", "pin", "process_namespace"))
def test_listener_readiness_uses_only_bounded_pinned_proc_table(monkeypatch, fault):
    opened, closed = [], []
    def readlink(path, **kwargs):
        if path == "/proc/self/fd/21": return "user:[200]"
        if path == "/proc/self/fd/22": return "net:[999]" if fault == "pin" else "net:[200]"
        return ("net:[999]" if fault == "process_namespace" and path == "ns/net" else PRIVATE[path[3:]])
    monkeypatch.setattr(lab.os, "readlink", readlink)
    monkeypatch.setattr(lab.os, "open", lambda path, flags, **kwargs: opened.append((path, flags, kwargs)) or 77)
    monkeypatch.setattr(lab.os, "close", closed.append)
    raw = TABLE_HEADER + TABLE_ROW
    if fault == "empty": raw = TABLE_HEADER
    elif fault == "extra": raw += TABLE_ROW
    elif fault == "address": raw = raw.replace(b"0100007F", b"00000000")
    elif fault == "port": raw = raw.replace(b"4A88", b"4A89")
    elif fault == "connected": raw = raw.replace(b" 0A ", b" 01 ")
    elif fault == "header": raw = b"invalid\n" + TABLE_ROW
    elif fault == "oversize": raw = b"x" * 8193
    monkeypatch.setattr(lab.os, "read", lambda fd, maximum: raw)
    if fault in (None, "empty"):
        assert lab.listener_ready(20, PRIVATE, (21, 22)) is (fault is None)
    else:
        with pytest.raises(ValueError): lab.listener_ready(20, PRIVATE, (21, 22))
    if fault not in ("pin", "process_namespace"):
        assert opened == [("net/tcp", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, {"dir_fd": 20})]
        assert closed == [77]
    else:
        assert opened == closed == []


@pytest.mark.parametrize("groups", ([], [65534], [65534] * 17))
def test_unprivileged_inherited_groups_are_observed_and_immutable(monkeypatch, groups):
    monkeypatch.setattr(worker, "namespaces", lambda: PRIVATE)
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(worker.os, "getuid", lambda: 65534)
    monkeypatch.setattr(worker.os, "getgid", lambda: 65534)
    monkeypatch.setattr(worker.os, "getgroups", lambda: list(groups))
    monkeypatch.setattr("builtins.open", lambda path, **kwargs: io.StringIO("deny\n" if path.endswith("setgroups") else "65534 0 1\n"))
    def denied(value):
        assert value == groups
        raise PermissionError(errno.EPERM, "disabled")
    monkeypatch.setattr(worker.os, "setgroups", denied)
    identity = worker.namespace_identity(HOST, "apache")
    assert identity["group_mutation_denied"] is False
    assert worker.seal_group_identity(identity) == {"uid": 65534, "gid": 65534,
        "supplementary_groups": groups, "setgroups_policy": "deny", "group_mutation_denied": True}


@pytest.mark.parametrize("fault", ("policy", "overlong", "other_group", "changed", "mutation", "wrong_error"))
def test_inherited_group_revision_cannot_allow_additional_authority(monkeypatch, fault):
    monkeypatch.setattr(worker, "namespaces", lambda: PRIVATE)
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(worker.os, "getuid", lambda: 65534)
    monkeypatch.setattr(worker.os, "getgid", lambda: 65534)
    groups = [65534] * (65 if fault == "overlong" else 2)
    if fault == "other_group": groups[0] = 7
    monkeypatch.setattr(worker.os, "getgroups", lambda: groups)
    monkeypatch.setattr("builtins.open", lambda path, **kwargs: io.StringIO(
        ("allow\n" if fault == "policy" else "deny\n") if path.endswith("setgroups") else "65534 0 1\n"))
    if fault in ("policy", "overlong", "other_group"):
        with pytest.raises(ValueError): worker.namespace_identity(HOST, "apache")
        return
    identity = worker.namespace_identity(HOST, "apache")
    if fault == "changed": monkeypatch.setattr(worker.os, "getgroups", lambda: [])
    def mutate(value):
        if fault == "wrong_error": raise OSError(errno.EINVAL, "not a denial witness")
    monkeypatch.setattr(worker.os, "setgroups", mutate)
    with pytest.raises((ValueError, OSError)): worker.seal_group_identity(identity)
    assert identity["group_mutation_denied"] is False


@pytest.mark.parametrize("implementation", ("nginx", "apache"))
@pytest.mark.parametrize("fault", (None, "host_root", "wrong_outer_uid", "wrong_outer_gid", "extra_map", "inner_root", "range", "oversize", "pin"))
def test_launcher_independently_proves_unprivileged_mapping_before_bootstrap(monkeypatch, implementation, fault):
    uid = 65534 if implementation == "apache" else 0
    opened, closed = [], []
    monkeypatch.setattr(lab.os, "getuid", lambda: 0 if fault == "host_root" else 1000)
    monkeypatch.setattr(lab.os, "getgid", lambda: 1001)
    def readlink(path, **kwargs):
        if path == "/proc/self/fd/21": return "user:[999]" if fault == "pin" else PRIVATE["user"]
        if path == "/proc/self/fd/22": return PRIVATE["net"]
        return PRIVATE[path[3:]]
    monkeypatch.setattr(lab.os, "readlink", readlink)
    def open_mapping(path, flags, **kwargs):
        opened.append(path)
        assert kwargs == {"dir_fd": 20}
        return 77 if path == "uid_map" else 78
    monkeypatch.setattr(lab.os, "open", open_mapping)
    monkeypatch.setattr(lab.os, "close", closed.append)
    def read_mapping(descriptor, size):
        assert size == 1025
        outer = 1000 if descriptor == 77 else 1001
        if fault == "wrong_outer_uid" and descriptor == 77: outer = 0
        if fault == "wrong_outer_gid" and descriptor == 78: outer = 0
        inner = 1 if fault == "inner_root" and uid == 0 else 0 if fault == "inner_root" else uid
        raw = f"{inner} {outer} {2 if fault == 'range' else 1}\n".encode()
        if fault == "extra_map": raw += b"1 2000 1\n"
        if fault == "oversize": raw = b"x" * 1025
        return raw
    monkeypatch.setattr(lab.os, "read", read_mapping)
    if fault is None:
        assert lab.launcher_mapping(20, PRIVATE, (21, 22), implementation) == {
            "launcher_uid": 1000, "launcher_gid": 1001,
            "uid_map": [[uid, 1000, 1]], "gid_map": [[uid, 1001, 1]]}
        assert opened == ["uid_map", "gid_map"] and closed == [77, 78]
    else:
        with pytest.raises(ValueError): lab.launcher_mapping(20, PRIVATE, (21, 22), implementation)
        assert len(opened) == len(closed)
