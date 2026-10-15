"""Real loopback protocol doubles plus the real aggregate ledger, not stock runs."""

from copy import deepcopy
import socket

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_ledger as ledger
from recon_cockpit.secure_agent import routing_frontend_worker as frontend
from recon_cockpit.secure_agent import stock_http_recorder as http, stock_ssh_recorder as ssh
from test_routing_contract import identity
from test_routing_ledger import Harness as LedgerHarness
from test_stock_http_recorder import Harness as HttpHarness, response
from test_stock_ssh_recorder import Harness as SshHarness, CLIENT_IDENTIFICATION, kex, packets


class Wire:
    """Synchronous transport double; owner applies the production ledger."""
    def __init__(self, owner, role):
        self.owner, self.role, self.reply = owner, role, None
        self.messages = []
        self.modify = lambda value: value
    def settimeout(self, value): pass
    def setblocking(self, value): pass
    def send(self, value):
        self.messages.append(deepcopy(value))
        self.reply = self.owner.apply(value, role=self.role)
    def receive(self):
        if self.reply is None: raise EOFError("lost owner")
        reply, self.reply = self.reply, None
        return self.modify(reply), None


def install_wire(monkeypatch):
    monkeypatch.setattr(frontend, "send_packet", lambda channel, value: channel.send(value))
    monkeypatch.setattr(frontend, "receive_packet", lambda channel, **kwargs: channel.receive())


def budget_for(monkeypatch, harness, selector, case="ordinary"):
    install_wire(monkeypatch)
    owner = LedgerHarness(case)
    owner.ledger._clock = lambda: harness.clock
    assert owner.arm(selector)["status"] == "ok"
    wire = Wire(owner.ledger, contract.selector_role(selector))
    budget = frontend.BudgetChannel(wire, wire.role, 160)
    budget.bind(1, owner.action_digest)
    harness.service.budget = budget
    return owner, wire, budget


@pytest.fixture
def ssh_double(monkeypatch):
    h = SshHarness(monkeypatch)
    # Keep the accepted real loopback constructor/traffic; add only the routed
    # budget subclass after construction. Production endpoint guards are tested
    # independently below and require actual routed endpoints in native tests.
    h.service.__class__ = frontend.SshService
    yield h
    h.close()


def test_key_exchange_reserves_before_payload_and_reaps_before_lease_release(monkeypatch, ssh_double):
    h = ssh_double
    owner, wire, budget = budget_for(monkeypatch, h, "ssh_keys")
    original_finalize = h.service.connection_finalizer
    def finalize(number):
        assert owner.ledger.snapshot()["active_connection"] is not None
        original_finalize(number)
    h.service.connection_finalizer = finalize
    h.exchange_to_reply()
    record = h.service.snapshot()
    snapshot = owner.ledger.snapshot()
    assert snapshot["active_connection"] is None and h.finalized == [1]
    assert record["client_packets_forwarded"] == 2 and record["server_key_replies_forwarded"] == 1
    assert snapshot["counters"]["kex_exchanges"] == 1
    assert snapshot["counters"]["request_bytes"] == record["client_bytes_forwarded"]
    assert snapshot["counters"]["response_bytes"] == record["client_bytes_delivered"]
    operations = [row["operation"] for row in wire.messages]
    assert operations[0] == "RESERVE_CONNECTION" and operations[-1] == "FINISH_CONNECTION"
    assert operations.index("RESERVE_REQUEST") < next(i for i, row in enumerate(wire.messages)
        if row["operation"] == "RESERVE_BYTES" and row["direction"] == "request")
    assert not budget.failed


def test_zero_kex_stops_client_payload_but_records_banner_and_cleanup(monkeypatch, ssh_double):
    h = ssh_double
    owner, wire, budget = budget_for(monkeypatch, h, "ssh_keys", "ssh_zero")
    client = h.initial()
    client.sendall(CLIENT_IDENTIFICATION + kex())
    h.until(lambda: h.service.ledger["finalized"])
    record = h.service.snapshot(); snapshot = owner.ledger.snapshot()
    assert record["client_bytes_forwarded"] == record["client_packets_forwarded"] == 0
    assert record["client_bytes_delivered"] > 0 and h.finalized == [1]
    assert snapshot["terminal_reason"] == "aggregate_kex_exchanges_limit"
    assert snapshot["active_connection"] is None and budget.failed
    assert snapshot["counters"]["request_bytes"] == snapshot["counters"]["kex_exchanges"] == 0
    assert wire.messages[-1]["operation"] == "FINISH_CONNECTION"


@pytest.mark.parametrize("payload", (packets.synthetic_packet(b"\x15"), packets.synthetic_packet(b"\x32"), b"GET / HTTP/1.0\r\n\r\n"))
def test_non_kex_packets_never_reach_private_daemon(monkeypatch, ssh_double, payload):
    h = ssh_double
    owner, wire, budget = budget_for(monkeypatch, h, "ssh_keys")
    client = h.initial(); client.sendall(CLIENT_IDENTIFICATION + payload)
    h.until(lambda: h.service.active is None)
    record = h.service.snapshot()
    assert record["client_packets_forwarded"] == record["server_key_replies_forwarded"] == 0
    assert owner.ledger.snapshot()["active_connection"] is None
    assert h.finalized == [1]


def test_http_exact_request_uses_selected_private_socket_and_real_byte_ledger(monkeypatch):
    h = HttpHarness(monkeypatch, case="O1")
    h.service.__class__ = frontend.HttpService
    h.service.selector = "http_headers"
    owner, wire, budget = budget_for(monkeypatch, h, "http_headers")
    original_socket = socket.socket
    paths = []
    class PrivateSocket(original_socket):
        def connect_ex(self, path):
            paths.append(path)
            assert owner.ledger.snapshot()["counters"]["http_requests"] == 1
            return 0
    def make_socket(family=socket.AF_INET, kind=socket.SOCK_STREAM, *args, **kwargs):
        if family == socket.AF_UNIX and kind == socket.SOCK_STREAM and not args and "fileno" not in kwargs:
            channel, peer = socket.socketpair()
            peer.setblocking(False); h.peers.append(peer)
            return PrivateSocket(fileno=channel.detach())
        return original_socket(family, kind, *args, **kwargs)
    monkeypatch.setattr(socket, "socket", make_socket)
    try:
        h.arm(); client = h.client(h.service.expected)
        h.reply(); h.until(lambda: h.service.active is None and h.service.ledger["requests_delivered"] == 1)
        h.expect_response(client, response())
        record = h.service.snapshot(); snapshot = owner.ledger.snapshot()
        assert paths == ["/peer/http_headers/nginx.sock"]
        assert snapshot["counters"]["request_bytes"] == record["request_bytes_delivered"] == len(h.service.expected)
        assert snapshot["counters"]["response_bytes"] == record["client_response_bytes"] == len(response())
        assert snapshot["active_connection"] is None and not budget.failed
    finally:
        h.close()


def test_partial_or_failed_writes_keep_credit_without_double_charge(monkeypatch):
    install_wire(monkeypatch)
    h = LedgerHarness(); h.arm("http_headers")
    monkeypatch.setattr(frontend.time, "monotonic", lambda: h.now)
    budget = frontend.BudgetChannel(Wire(h.ledger, "http_frontend"), "http_frontend", 160)
    budget.bind(1, h.action_digest); assert budget.connection(1); budget.request("http")
    active = {}
    budget.before_write(active, "request", 100)
    budget.after_write(active, "request", 30)
    budget.before_write(active, "request", 70)  # Retry after a partial write.
    budget.after_write(active, "request", 0)   # EAGAIN keeps the full credit.
    budget.before_write(active, "request", 80)
    assert h.ledger.snapshot()["counters"]["request_bytes"] == 110
    budget.after_write(active, "request", 80); budget.finish()
    assert h.ledger.snapshot()["counters"]["request_bytes"] == 110
    assert h.ledger.snapshot()["active_connection"] is None


def test_cross_action_rate_and_sequence_persist_then_connection_budget_refuses(monkeypatch):
    install_wire(monkeypatch)
    h = LedgerHarness("connection_one"); h.arm("http_nmap")
    monkeypatch.setattr(frontend.time, "monotonic", lambda: h.now)
    budget = frontend.BudgetChannel(Wire(h.ledger, "http_frontend"), "http_frontend", 160)
    budget.bind(1, h.action_digest); assert budget.connection(1); budget.finish()
    assert h.finish_action()["status"] == "ok"
    h.arm("http_headers"); budget.bind(2, h.action_digest)
    # Budget exhaustion is terminal and is not hidden by resetting the frontend.
    h.now += .25
    with pytest.raises(frontend.BudgetRefused): budget.connection(1)
    assert budget.sequence == 3 and budget.failed
    assert h.ledger.snapshot()["counters"]["connections"] == 1


@pytest.mark.parametrize("mutation", ("role", "sequence", "action_digest", "lease", "extra", "eof"))
def test_owner_reply_mutations_close_budget_continuity(monkeypatch, mutation):
    install_wire(monkeypatch)
    h = LedgerHarness(); h.arm("ssh_keys")
    monkeypatch.setattr(frontend.time, "monotonic", lambda: h.now)
    wire = Wire(h.ledger, "ssh_frontend")
    budget = frontend.BudgetChannel(wire, wire.role, 160); budget.bind(1, h.action_digest)
    def change(value):
        if mutation == "eof": raise EOFError("closed")
        value[mutation] = None if mutation == "lease" else True
        return value
    wire.modify = change
    with pytest.raises((ValueError, EOFError)): budget.connection(1)
    assert budget.failed and budget.continuity_lost
    before = len(wire.messages)
    with pytest.raises(frontend.BudgetRefused): budget.connection(1)
    assert len(wire.messages) == before


def test_frontend_constructor_refuses_unrelated_endpoint(monkeypatch):
    from test_stock_ssh_recorder import PortableListener
    listener = PortableListener(); listener.bind(("127.0.0.1", 0)); listener.listen()
    try:
        with pytest.raises(ValueError): frontend.HttpService("http_headers", listener, deadline=160, budget=None)
        with pytest.raises(ValueError): frontend.SshService("ssh_keys", listener, deadline=160, budget=None,
            connection_factory=lambda *args: None, connection_finalizer=lambda *args: None)
    finally:
        listener.close()


def test_idle_listener_refuses_queued_connection_instead_of_reusing_it():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); listener.listen()
        frontend.require_idle_listener(listener)
        with socket.socket() as client:
            client.connect(listener.getsockname())
            with pytest.raises(ValueError, match="unbound_connection"):
                frontend.require_idle_listener(listener)
