"""Native daemon recipes and seccomp socket selection stay finite."""
from copy import deepcopy
import socket
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
        names.setdefault(name, len(names) + 1)
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
