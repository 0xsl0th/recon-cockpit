"""Native daemon recipes and seccomp socket selection stay finite."""
from copy import deepcopy
import ctypes
import errno
import os
import socket
import stat
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import name_tls_daemon as daemon, name_tls_daemon_worker as worker
from recon_cockpit.secure_agent import name_tls_topology_spec as topology
from recon_cockpit.secure_agent import name_tls_transport as transport
from recon_cockpit.secure_agent import name_tls_role_spec as roles


@pytest.fixture(autouse=True)
def linux_socket_constants_for_portable_policy_inspection(monkeypatch):
    monkeypatch.setattr(socket, "AF_NETLINK", 16, raising=False)
    monkeypatch.setattr(socket, "NETLINK_ROUTE", 0, raising=False)


def test_fixed_daemon_argv_matches_preparation_without_generating_keys():
    from recon_cockpit.secure_agent import name_tls_spec as preparation
    selected = preparation.selection("A", "O4")
    assert list(daemon.argv_for("dns")) == selected["daemon_proposals"][0]["argv"]
    assert list(daemon.argv_for("http")) == list(daemon.argv_for("tls")) == selected["daemon_proposals"][1]["argv"]
    assert daemon.ENVIRONMENT == dict(preparation.ENVIRONMENT)
    assert daemon.BOUNDS["processes"] == daemon.BOUNDS["threads"] == 1
    assert daemon.BOUNDS["file_descriptors"] == 64


@pytest.mark.parametrize("directory,path", ((None, "/dev/urandom"), (42, "root/dev/urandom")))
def test_entropy_node_verified_without_reading_and_descriptor_closed(monkeypatch, directory, path):
    opened, closed = [], []
    monkeypatch.setattr(os, "O_PATH", 0x200000, raising=False)
    def open_node(name, flags, *, dir_fd):
        opened.append((name, flags, dir_fd))
        return 73
    with monkeypatch.context() as patch:
        patch.setattr(daemon.os, "open", open_node)
        patch.setattr(daemon.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_rdev=os.makedev(1, 9)))
        patch.setattr(daemon.os, "close", closed.append)
        patch.setattr(daemon.os, "read", lambda *_: pytest.fail("entropy must not be read into evidence"))
        actual = daemon.observe_entropy_device("dns", process_directory=directory)
    assert actual == {"path": "/dev/urandom", "type": "character", "major": 1, "minor": 9, "access": "read"}
    assert opened == [(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, directory)]
    assert closed == [73]


@pytest.mark.parametrize("mode,major,minor", ((stat.S_IFREG, 1, 9), (stat.S_IFLNK, 1, 9),
                                            (stat.S_IFCHR, 1, 8), (stat.S_IFCHR, 2, 9)))
def test_entropy_verification_refuses_other_device_and_closes_fd(monkeypatch, mode, major, minor):
    closed = []
    monkeypatch.setattr(os, "O_PATH", 0x200000, raising=False)
    with monkeypatch.context() as patch:
        patch.setattr(daemon.os, "open", lambda *a, **k: 73)
        patch.setattr(daemon.os, "fstat", lambda fd: SimpleNamespace(st_mode=mode, st_rdev=os.makedev(major, minor)))
        patch.setattr(daemon.os, "close", closed.append)
        with pytest.raises(ValueError, match="entropy_device_changed"):
            daemon.observe_entropy_device("dns")
    assert closed == [73]


@pytest.mark.parametrize("operation", ("http", "tls"))
def test_web_role_never_opens_entropy_device(monkeypatch, operation):
    with monkeypatch.context() as patch:
        patch.setattr(daemon.os, "open", lambda *a, **k: pytest.fail("web entropy permission is not declared"))
        assert daemon.observe_entropy_device(operation) is None
    assert daemon.validate_entropy_device(None, operation) is None
    with pytest.raises(ValueError, match="unexpected_entropy"):
        daemon.validate_entropy_device(dict(daemon.ENTROPY_DEVICE), operation)


@pytest.mark.parametrize("replacement", (None, {}, {**daemon.ENTROPY_DEVICE, "major": True},
    {**daemon.ENTROPY_DEVICE, "minor": 8}, {**daemon.ENTROPY_DEVICE, "path": "/dev/random"},
    {**daemon.ENTROPY_DEVICE, "access": "read_write"}))
def test_entropy_receipt_does_not_authorize_other_node_or_access(replacement):
    with pytest.raises(ValueError, match="entropy_device_changed"):
        daemon.validate_entropy_device(replacement, "dns")


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("operation", ("dns", "http", "tls"))
def test_private_network_only_delivers_selected_operation(configuration, operation):
    rules = worker.firewall_rules(configuration, operation)
    endpoint = topology.endpoints(configuration)[operation]
    assert f"ip daddr {endpoint[0]} tcp dport {endpoint[1]} " in rules
    assert f"ip saddr {endpoint[0]} tcp sport {endpoint[1]} " in rules
    assert rules.count("policy drop") == 3 and rules.count(" accept") == 4
    assert "eth0" not in rules and "udp" not in rules and "ip6" not in rules
    assert all(f"tcp dport {topology.endpoints(configuration)[other][1]} " not in rules
               for other in ("dns", "http", "tls") if other != operation)


@pytest.mark.parametrize("operation", (None, True, {}, [], "smtp", "DNS", "dns;sh"))
def test_daemon_operation_is_closed_before_any_launch(operation):
    with pytest.raises(ValueError):
        daemon.argv_for(operation)


class Function:
    def __init__(self, function):
        self.function = function
    def __call__(self, *args):
        return self.function(*args)


@pytest.mark.parametrize("operation", ("dns", "http", "tls"))
def test_socket_policy_does_not_accidentally_allow_other_families_or_processes(monkeypatch, operation):
    names, rules = {}, []
    def resolve(name):
        names.setdefault(name, {b"socketcall": -10060, b"send": -109}.get(name, len(names) + 1))
        return names[name]
    def rule(context, action, number, count, args):
        assert context == 1 and action == 0x00050000 | 1
        row = tuple((args[i].arg, args[i].op, args[i].datum_a, args[i].datum_b) for i in range(count))
        assert len({item[0] for item in row}) == len(row)  # libseccomp forbids duplicate arg tests.
        rules.append((number, row))
        return 0
    library = SimpleNamespace(seccomp_init=Function(lambda *_: 1),
        seccomp_syscall_resolve_name=Function(resolve), seccomp_rule_add_array=Function(rule),
        seccomp_load=Function(lambda _: 0), seccomp_release=Function(lambda _: None))
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **k: library)
    worker.socket_filter(operation)
    def denied(name, arguments):
        def matches(comparison):
            index, op, left, right = comparison
            actual = arguments[index]
            return {1: actual != left, 4: actual == left, 6: actual > left, 7: actual & left == right}[op]
        return any(number == names[name] and all(matches(item) for item in comparisons) for number, comparisons in rules)
    for name in (b"connect", b"fork", b"vfork", b"clone", b"clone3", b"setns", b"unshare", b"execveat"):
        assert denied(name, [0] * 6)
    for name, flag_index in ((b"send", 3), (b"sendto", 3), (b"sendmsg", 2), (b"sendmmsg", 3)):
        for ordinary_flags in (0, 0x40, 0x4000, 0x8000, 0xC040):
            arguments = [0] * 6
            arguments[flag_index] = ordinary_flags
            assert not denied(name, arguments)  # Replies and SCM_RIGHTS remain possible.
            arguments[flag_index] |= 0x20000000
            assert denied(name, arguments)
        for other_index in set(range(6)) - {flag_index}:
            arguments = [0] * 6
            arguments[other_index] = 0x20000000
            assert not denied(name, arguments)
    assert denied(b"socketcall", [0] * 6)
    assert b"execve" not in names
    for family in range(48):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_RAW):
            if family == socket.AF_INET and (kind == socket.SOCK_STREAM or operation == "dns" and kind == socket.SOCK_DGRAM):
                assert not denied(b"socket", [family, kind, 0])
            elif operation == "dns" and family == socket.AF_NETLINK and kind in (socket.SOCK_RAW, socket.SOCK_DGRAM):
                assert not denied(b"socket", [family, kind, socket.NETLINK_ROUTE])
            else:
                assert denied(b"socket", [family, kind, 0])
    assert denied(b"socket", [socket.AF_INET, socket.SOCK_STREAM, 255])
    if operation == "dns":
        assert denied(b"socket", [socket.AF_NETLINK, socket.SOCK_RAW, 12])


@pytest.mark.parametrize("failure", (None, "sendto", "sendmsg", "sendmmsg", "connected"))
@pytest.mark.parametrize("wrong_errno", (errno.EINPROGRESS, errno.ECONNREFUSED, errno.EFAULT, None))
def test_fastopen_witness_requires_each_actual_eperm_and_unconnected_socket(monkeypatch, failure, wrong_errno):
    events = []
    endpoint = ("10.77.0.53", 5353)
    def probe(name):
        events.append(name)
        if failure == name:
            if wrong_errno is None:
                return 1
            raise OSError(wrong_errno, "injected syscall result")
        raise PermissionError(errno.EPERM, "denied")
    class Stream:
        def sendto(self, raw, flags, destination):
            assert raw == b"x" and flags == 0x20000000 and destination == endpoint
            return probe("sendto")
        def sendmsg(self, buffers, ancillary, flags, destination):
            assert buffers == [b"x"] and ancillary == [] and flags == 0x20000000 and destination == endpoint
            return probe("sendmsg")
        def getpeername(self):
            events.append("peer")
            if failure == "connected":
                return endpoint
            raise OSError(errno.ENOTCONN, "unconnected")
    monkeypatch.setattr(worker, "_sendmmsg_fastopen", lambda stream, destination: probe("sendmmsg"))
    if failure is None:
        worker.fastopen_witnesses(Stream(), endpoint)
        assert events == ["sendto", "sendmsg", "sendmmsg", "peer"]
    else:
        with pytest.raises(ValueError, match="fastopen"):
            worker.fastopen_witnesses(Stream(), endpoint)


def test_sendmmsg_witness_has_real_single_payload_and_exact_sockaddr(monkeypatch):
    def call(fd, pointer, count, flags):
        row = pointer._obj
        assert fd == 37 and count == 1 and flags == 0x20000000
        assert row.message.name_length == 16 and row.message.iov_length == 1
        address = ctypes.string_at(row.message.name, row.message.name_length)
        assert address[2:4] == (5353).to_bytes(2, "big") and address[4:8] == socket.inet_aton("10.77.0.53")
        assert ctypes.string_at(row.message.iov[0].base, row.message.iov[0].length) == b"x"
        assert not row.message.control and not row.message.control_length and not row.message.flags
        ctypes.set_errno(errno.EPERM)
        return -1
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(sendmmsg=Function(call)))
    with pytest.raises(PermissionError):
        worker._sendmmsg_fastopen(SimpleNamespace(fileno=lambda: 37), ("10.77.0.53", 5353))


@pytest.mark.parametrize("protocol", ("tcp", "udp"))
def test_actual_listener_table_parser_rejects_unconnected_active_and_wildcard_records(protocol):
    header = b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    state = "0A" if protocol == "tcp" else "07"
    raw = header + f"0: 35004D0A:14E9 00000000:0000 {state} 0:0 0:0 0 65534 0 12345\n".encode()
    assert daemon._socket_rows(raw, protocol=protocol) == [{"endpoint": ["10.77.0.53", 5353], "inode": 12345}]
    for changed in (raw.replace(b"00000000:0000", b"0100007F:00FF"), raw.replace(b"12345", b"0"), raw.replace(state.encode() + b" 0:0", b"01 0:0")):
        with pytest.raises(ValueError):
            daemon._socket_rows(changed, protocol=protocol)


@pytest.mark.parametrize("raw", (b"", b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":"' + b'a'*262144 + b'"}'))
def test_bootstrap_codec_rejects_ambiguous_or_oversized_data(raw):
    with pytest.raises(ValueError):
        transport.decode_bootstrap(raw)


def test_bootstrap_aliases_are_identical_to_daemon_codec():
    value = {"configuration": "A", "nested": [1, True, None]}
    assert transport.decode_bootstrap(transport.encode_bootstrap(value)) == value
    assert len(transport.digest(value)) == 64
    assert transport.BOOTSTRAP_BYTES == 262144
