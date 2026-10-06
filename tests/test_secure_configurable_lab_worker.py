"""Finite protocol phases, private address setup and exact firewall boundaries."""

import io
import json
import socket
import struct
import threading
import time

import pytest

from recon_cockpit.secure_agent import configurable_lab_worker as worker
from recon_cockpit.secure_agent import configurable_scope as scope_contract
from recon_cockpit.secure_agent import network_tools_fixture as network

SCOPE = {"schema_version": "1", "scope_id": "owned-http-ssh",
         "http": {"target": "10.9.0.10", "port": 8088, "path": "/training/portal"},
         "ssh": {"target": "172.20.0.11", "port": 2222}}
HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}


class Connection:
    def __init__(self, raw=b"", *, reset=False):
        self.input = io.BytesIO(raw)
        self.output = bytearray()
        self.closed = False
        self.timeouts = []
        self.reset = reset

    def recv(self, count):
        part = self.input.read(count)
        if not part and self.reset:
            raise ConnectionResetError("native scan reset")
        return part

    def sendall(self, raw):
        self.output.extend(raw)

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


def serve(inputs, endpoint="http"):
    connections = [value if isinstance(value, Connection) else Connection(value) for value in inputs]
    pending = iter(connections)
    class Listener:
        def accept(self):
            return next(pending), ("10.9.0.10", 1)
    service = object.__new__(worker.ConfigurableService)
    service.case, service.listener = endpoint, Listener()
    service.selected = SCOPE[endpoint]
    service.deadline = time.monotonic() + 10
    service.condition = threading.Condition()
    service.connections = service.requests = 0
    service.failed = False
    service._serve()
    return service, connections


@pytest.mark.parametrize("reset", [False, True])
@pytest.mark.parametrize("separate_null", [False, True])
def test_http_real_probe_shapes_require_scan_then_nmap_then_configured_path(reset, separate_null):
    inputs = [Connection(reset=reset)] + ([b""] if separate_null else [])
    inputs += [network.NMAP_SERVICE_GET, worker.header_request(SCOPE["http"])]
    service, connections = serve(inputs)
    assert service.connections == 3 + separate_null and service.requests == 2
    assert bytes(connections[-2].output) == network.NMAP_SERVICE_HTTP
    assert bytes(connections[-1].output) == worker.header_response()
    assert all(connection.closed for connection in connections)
    assert all(0 < value <= 2 for connection in connections for value in connection.timeouts)


@pytest.mark.parametrize("reset", [False, True])
def test_ssh_scan_then_nmap_banner_then_public_kex_reuses_consistent_banner(monkeypatch, reset):
    calls = []
    def kex(connection, *, banner, deadline):
        calls.append((connection, banner, deadline))
        connection.sendall(b"public synthetic KEX response")
    monkeypatch.setattr(worker.ssh, "serve", kex)
    service, connections = serve([Connection(reset=reset), b"", b"client key exchange"], "ssh")
    assert service.connections == 3 and service.requests == 2
    assert bytes(connections[1].output) == network.NMAP_SERVICE_SSH
    assert calls[0][0] is connections[2] and calls[0][1] == network.NMAP_SERVICE_SSH[:-2]
    assert all(connection.closed for connection in connections)


@pytest.mark.parametrize("prefix,bad", [([], network.NMAP_SERVICE_GET),
    ([b""], worker.header_request(SCOPE["http"])), ([b"", b""], b""),
    ([b""], b"GET / HTTP/1.1\r\n\r\n"),
    ([b""], network.NMAP_SERVICE_GET + b"body"),
    ([b"", network.NMAP_SERVICE_GET], network.NMAP_SERVICE_GET),
    ([b"", network.NMAP_SERVICE_GET], worker.header_request(SCOPE["http"]).replace(b"/training/portal", b"/private")),
    ([b"", network.NMAP_SERVICE_GET], worker.header_request(SCOPE["http"]).replace(b"GET ", b"POST ")),
    ([b"", network.NMAP_SERVICE_GET], worker.header_request(SCOPE["http"]).replace(b"10.9.0.10", b"10.9.0.11")),
    ([b"", network.NMAP_SERVICE_GET], worker.header_request(SCOPE["http"]) + b"body"),
    ([b"", network.NMAP_SERVICE_GET], worker.header_request(SCOPE["http"]) * 2),
    ([b"", network.NMAP_SERVICE_GET], worker.header_request(SCOPE["http"]).replace(b"Connection: close", b"Cookie: secret"))])
def test_wrong_order_or_request_shape_fails_owner_without_responding(prefix, bad):
    service, connections = serve([*prefix, bad])
    assert service.failed and not connections[-1].output
    assert service.requests == (1 if network.NMAP_SERVICE_GET in prefix else 0)
    with pytest.raises(RuntimeError, match="service_failed"):
        service.snapshot(0, 0, time.monotonic() + 1)


@pytest.mark.parametrize("prefix,raw", [([], b"G"), ([b""], b""),
    ([b"", network.NMAP_SERVICE_GET], b""), ([b"", network.NMAP_SERVICE_GET], b"GET /")])
def test_only_first_completely_empty_reset_is_valid(prefix, raw):
    service, connections = serve([*prefix, Connection(raw, reset=True)])
    assert service.failed and not connections[-1].output


def test_no_fourth_ssh_exchange_or_authentication_is_accepted(monkeypatch):
    monkeypatch.setattr(worker.ssh, "serve", lambda *a, **k: True)
    extra = Connection(b"authentication data")
    service, _ = serve([b"", b"", b"", extra], "ssh")
    assert service.failed and service.connections == 3 and service.requests == 2
    assert extra.closed and extra.input.tell() == 0 and not extra.output


def test_no_third_http_request_is_read_after_complete_metadata():
    extra = Connection(worker.header_request(SCOPE["http"]))
    service, _ = serve([b"", network.NMAP_SERVICE_GET, worker.header_request(SCOPE["http"]), extra])
    assert service.failed and service.connections == 3 and service.requests == 2
    assert extra.closed and extra.input.tell() == 0


@pytest.mark.parametrize("change", [{"endpoint": "ldap"}, {"endpoint": True}, {"deadline": True},
    {"deadline": 0}, {"deadline": float("nan")}, {"deadline": float("inf")},
    {"resume": True}, {"scope": {}}, {"target": "8.8.8.8"}])
def test_owner_bootstrap_has_no_runtime_target_or_capability_escape(change):
    value = {"scope": SCOPE, "endpoint": "http", "deadline": time.monotonic() + 30,
             "host_namespaces": HOST, **change}
    with pytest.raises(ValueError):
        worker.read_request(io.BytesIO(json.dumps(value).encode() + b"\n"))


def test_owner_bootstrap_rejects_duplicates_unterminated_and_oversized_frames():
    raw = json.dumps({"scope": SCOPE, "endpoint": "http", "deadline": time.monotonic() + 30,
                      "host_namespaces": HOST}).encode()
    for invalid in (raw, b'{"endpoint":"ssh",' + raw[1:] + b"\n", b" " * 8193 + b"\n"):
        with pytest.raises(ValueError):
            worker.read_request(io.BytesIO(invalid))
    assert worker.read_request(io.BytesIO(raw + b"\n"))["scope"] == SCOPE


@pytest.mark.parametrize("name", ["http", "ssh"])
def test_firewall_only_admits_selected_pair_and_its_connection_tracking_replies(name):
    selected = SCOPE[name]
    rules = worker.firewall_rules(SCOPE, name)
    exact = f'ip daddr {selected["target"]} tcp dport {selected["port"]}'
    reply = f'ct original ip daddr {selected["target"]} ct original proto-dst {selected["port"]}'
    assert rules.count(exact) == 2 and rules.count(reply) == 2
    assert rules.count('ct direction original accept') == 2
    assert rules.count('ct direction reply ct state established') == 2
    assert rules.count('policy drop;') == 3
    assert 'oifname "lo"' in rules and 'iifname "lo"' in rules
    other = SCOPE["ssh" if name == "http" else "http"]
    assert f'ip daddr {other["target"]} tcp dport {other["port"]}' not in rules


def test_address_message_is_one_exact_create_exclusive_ipv4_loopback_alias():
    raw = worker.address_message("10.9.0.10", 1, 1)
    assert raw == (struct.pack("=IHHII", 40, 20, 0x605, 1, 0)
        + struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, 1)
        + struct.pack("=HH", 8, 1) + b"\x0a\x09\x00\x0a"
        + struct.pack("=HH", 8, 2) + b"\x0a\x09\x00\x0a")
    ack = struct.pack("=IHHIIi", 36, 2, 0, 1, 42, 0) + raw[:16]
    worker.validate_address_ack(ack, raw, (0, 0))


@pytest.mark.parametrize("address,index,sequence", [("8.8.8.8", 1, 1), ("localhost", 1, 1),
    ("10.9.0.10", 0, 1), ("10.9.0.10", True, 1), ("10.9.0.10", 1, True), ("10.9.0.10", 1, 5)])
def test_address_request_rejects_nondeclared_address_types_and_unbounded_sequence(address, index, sequence):
    with pytest.raises((ValueError, OSError)):
        worker.address_message(address, index, sequence)


@pytest.mark.parametrize("fault", ["source", "errno", "sequence", "header", "short", "oversize", "length", "type"])
def test_netlink_ack_must_be_success_for_exact_request_from_kernel(fault):
    request = worker.address_message("10.9.0.10", 1, 1)
    ack = bytearray(struct.pack("=IHHIIi", 36, 2, 0, 1, 42, 0) + request[:16])
    source = (0, 0)
    if fault == "source": source = (42, 0)
    if fault == "errno": ack[16:20] = struct.pack("=i", -1)
    if fault == "sequence": ack[8:12] = struct.pack("=I", 2)
    if fault == "header": ack[-1] ^= 1
    if fault == "short": ack = ack[:20]
    if fault == "oversize": ack += b"x" * 4096
    if fault == "length": ack[0:4] = struct.pack("=I", 35)
    if fault == "type": ack[4:6] = struct.pack("=H", 3)
    with pytest.raises(ValueError):
        worker.validate_address_ack(bytes(ack), request, source)


def test_namespace_identity_rejection_precedes_netlink_socket(monkeypatch):
    def reject(_):
        raise RuntimeError("not private")
    monkeypatch.setattr(worker.owner.worker, "assert_private_namespaces", reject)
    monkeypatch.setattr(worker.socket, "socket", lambda *a, **k: pytest.fail("host address operation attempted"))
    with pytest.raises(RuntimeError, match="not private"):
        worker.prepare_addresses({"scope": SCOPE, "endpoint": "http", "deadline": time.monotonic() + 10,
                                  "host_namespaces": HOST})
