"""Plaintext protocol doubles exercise enforcement; they are not stock evidence."""

from copy import deepcopy
import socket
import struct

import pytest

from recon_cockpit.secure_agent import network_tools_ssh_fixture as fixture
from recon_cockpit.secure_agent import stock_ssh_packets as packets
from recon_cockpit.secure_agent import stock_ssh_recorder as recorder
from recon_cockpit.secure_agent import stock_ssh_spec as spec


def banner(configuration="A", case="O2"):
    suffix = packets.HOSTILE_ADDENDUM if case == "R1" else b"Owned-lab-B" if configuration == "B" else b""
    return b"SSH-2.0-OpenSSH_10.2p1" + (b" " + suffix if suffix else b"") + b"\r\n"


CLIENT_IDENTIFICATION = b"SSH-2.0-OpenSSH_10.2p1 test-collector\r\n"


class PortableListener(socket.socket):
    """Real TCP traffic; emulate only the nonportable SO_ACCEPTCONN query.

    The flag changes only after the real listen syscall succeeds. Production
    Linux socket checks remain unchanged and have separate native coverage.
    """

    def __init__(self):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self._listening = False

    def listen(self, backlog=0):
        super().listen(backlog)
        self._listening = True

    def getsockopt(self, level, option, *args):
        if self.fileno() >= 0 and (level, option) == (socket.SOL_SOCKET, socket.SO_ACCEPTCONN) and not args:
            return int(self._listening)
        return super().getsockopt(level, option, *args)


def kex(configuration="A", *, server=False):
    names = [b"diffie-hellman-group14-sha256", b"rsa-sha2-256" if configuration == "A" else b"rsa-sha2-512",
             b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b""]
    if server:
        names[0] += b",ext-info-s,kex-strict-s-v00@openssh.com"
    return packets.synthetic_packet(b"\x14" + b"K" * 16 + b"".join(packets.ssh_string(x) for x in names) + b"\0" * 5)


def dh():
    return packets.synthetic_packet(b"\x1e" + fixture.mpint(1024))


def reply(configuration="A"):
    signature = packets.ssh_string(b"rsa-sha2-256" if configuration == "A" else b"rsa-sha2-512") + packets.ssh_string(b"S" * 256)
    return packets.synthetic_packet(b"\x1f" + packets.ssh_string(fixture.public_blob())
                                    + fixture.mpint(2048) + packets.ssh_string(signature))


class Harness:
    def __init__(self, monkeypatch, configuration="A", case="O2"):
        self.clock, self.configuration, self.case = 100.0, configuration, case
        monkeypatch.setattr(recorder.time, "monotonic", lambda: self.clock)
        self.listener = PortableListener()
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(8)
        self.address = self.listener.getsockname()
        # Bind real loopback traffic to the test endpoint; the constructor
        # still requires exact getsockname equality and AF_INET.
        monkeypatch.setitem(recorder.CONFIGURATIONS, configuration, self.address)
        self.peers, self.clients, self.finalized, self.factories = [], [], [], []
        def factory(number, deadline):
            assert len(self.finalized) == len(self.factories)
            self.factories.append((number, deadline))
            channel, peer = socket.socketpair()
            peer.setblocking(False)
            self.peers.append(peer)
            return channel
        self.service = recorder.Service(configuration, case, self.listener, deadline=self.clock + 60,
            connection_factory=factory, connection_finalizer=self.finalized.append)

    def connect(self, *, armed=True):
        if armed and not self.service.ledger["armed"]:
            self.service.arm(self.clock + 5)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(self.address); client.setblocking(False)
        self.clients.append(client)
        self.until(lambda: self.service.ledger["connections_attempted"] == len(self.clients))
        if armed and len(self.clients) <= self.service.connection_cap:
            self.until(lambda: len(self.peers) == len(self.clients))
        return client

    def step(self, seconds=.001):
        self.service.tick(.001)
        self.clock += seconds

    def until(self, predicate, maximum=1000):
        for _ in range(maximum):
            self.step()
            if predicate():
                return
        pytest.fail("bounded SSH protocol double did not reach expected state")

    def initial(self):
        client = self.connect()
        self.peers[-1].sendall(banner(self.configuration, self.case))
        self.until(lambda: self.service.ledger["client_bytes_delivered"] > 0 or self.service.ledger["finalized"]
                   or self.service.active is not None and self.service.active["withhold"])
        return client

    def exchange_to_server_kex(self):
        client = self.initial()
        client.sendall(CLIENT_IDENTIFICATION + kex(self.configuration))
        self.until(lambda: self.service.ledger["client_packets_forwarded"] == 1)
        self.peers[-1].sendall(kex(self.configuration, server=True))
        self.until(lambda: len(self.service.ledger["connections"][-1]["server_messages"]) == 2)
        return client

    def exchange_to_reply(self):
        client = self.exchange_to_server_kex()
        client.sendall(dh())
        self.until(lambda: self.service.ledger["client_packets_forwarded"] == 2)
        self.peers[-1].sendall(reply(self.configuration) + packets.synthetic_packet(b"\x15"))
        self.until(lambda: self.service.active is None)
        return client

    def read_closed(self, client, expected):
        client.settimeout(1)
        received = bytearray()
        while True:
            part = client.recv(16384)
            if not part:
                break
            received.extend(part)
            assert len(received) <= len(expected)
        assert bytes(received) == expected
        return bytes(received)

    def close(self):
        self.service.close()
        for channel in self.clients + self.peers:
            channel.close()


@pytest.fixture
def harness(monkeypatch):
    instances = []
    def make(configuration="A", case="O2"):
        result = Harness(monkeypatch, configuration, case)
        instances.append(result)
        return result
    yield make
    for instance in instances:
        instance.close()


def test_standalone_constants_match_compiled_contract():
    assert recorder.CASES == spec.CASES
    assert recorder.CONFIGURATIONS == {c: (spec.action(c, "O1")["target"], spec.action(c, "O1")["parameters"]["port"])
                                        for c in spec.CONFIGURATIONS}
    assert packets.GROUP14_P == fixture.GROUP14_P
    assert packets.HOSTILE_ADDENDUM.decode() == spec.HOSTILE_ADDENDUM
    assert packets.MAX_IDENTIFICATION == spec.budgets("O2")["max_identification_bytes"]


@pytest.mark.parametrize("configuration,case", spec.TRIALS)
def test_full_finite_corpus_retains_real_input_and_explicit_transform(harness, configuration, case):
    h = harness(configuration, case)
    if case in ("O1", "N1"):
        client = h.initial(); h.until(lambda: h.service.active is None)
    elif case in ("N3", "N4"):
        client = h.initial()
        if case == "N3":
            assert not h.service.ledger["client_bytes_delivered"]
            h.clock += 5; h.step()
    elif case == "N6":
        client = h.exchange_to_server_kex(); h.until(lambda: h.service.active is None)
    else:
        client = h.exchange_to_reply()
    saved = h.service.snapshot()
    row = saved["connections"][0]
    original = bytes.fromhex(row["original_daemon_hex"])
    proposed = bytes.fromhex(row["proposed_response_hex"])
    delivered = bytes.fromhex(row["delivered_response_hex"])
    assert original.startswith(banner(configuration, case))
    assert h.finalized == [1] and h.factories == [(1, 105.0)]
    assert saved["connections_admitted"] == saved["daemon_connections"] == 1
    if case == "N3":
        assert saved["terminal_reason"] == "action_deadline" and proposed == delivered == b""
    elif case == "N4":
        assert saved["terminal_reason"] == "response_limit" and len(proposed) == 8193 and delivered == b""
    else:
        assert delivered == proposed
    if case in ("O1", "O2", "R1", "R2"):
        assert original.startswith(delivered)
    if case in ("O2", "R1", "R2", "N2", "N5"):
        assert original.endswith(packets.synthetic_packet(b"\x15"))
        assert not delivered.endswith(packets.synthetic_packet(b"\x15"))
        assert saved["client_packets_forwarded"] == 2
        assert bytes.fromhex(row["forwarded_client_hex"]) == CLIENT_IDENTIFICATION + kex(configuration) + dh()
    if case == "R2":
        assert all(t["disposition"] == "fragmented" for t in row["transforms"])
        writes = [w for w in row["writes"] if w["direction"] == "client"]
        assert len(writes) == 8 and all(b["elapsed_ms"] - a["elapsed_ms"] >= 4 for a, b in zip(writes, writes[1:]))
    h.read_closed(client, delivered)
    h.service.close()
    assert h.service.snapshot()["finalized"]


@pytest.mark.parametrize("message", [b"SSH-1.5-OpenSSH\r\n", b"SSH-2.0-X\n", b"SSH-2.0-X\x00\r\n",
    b"SSH-2.0-" + b"x" * 246 + b"\r\n", b"notice\r\nSSH-2.0-X\r\n"])
def test_invalid_client_identification_is_never_forwarded(harness, message):
    h = harness(); client = h.connect(); client.sendall(message)
    h.until(lambda: h.service.active is None)
    saved = h.service.snapshot()
    assert saved["connections_denied"] == 1 and saved["client_bytes_forwarded"] == 0
    assert h.finalized == [1]


@pytest.mark.parametrize("message", [b"\x15", b"\x32", b"\x05", b"\x5a", b"\x14" + b"\0" * 30])
def test_newkeys_userauth_services_channels_and_invalid_kex_never_forward(harness, message):
    h = harness(); client = h.initial()
    client.sendall(CLIENT_IDENTIFICATION)
    h.until(lambda: h.service.ledger["client_bytes_forwarded"] == len(CLIENT_IDENTIFICATION))
    client.sendall(packets.synthetic_packet(message))
    h.until(lambda: h.service.active is None)
    saved = h.service.snapshot()
    assert bytes.fromhex(saved["connections"][0]["forwarded_client_hex"]) == CLIENT_IDENTIFICATION
    assert saved["connections_denied"] == 1 and saved["client_packets_forwarded"] == 0


def test_coalesced_extra_client_packet_drops_unforwarded_valid_prefix(harness):
    h = harness(); client = h.exchange_to_server_kex()
    client.sendall(dh() + packets.synthetic_packet(b"\x15"))
    h.until(lambda: h.service.active is None)
    saved = h.service.snapshot()
    assert saved["connections_denied"] == 1 and saved["client_packets_forwarded"] == 1
    assert bytes.fromhex(saved["connections"][0]["forwarded_client_hex"]) == CLIENT_IDENTIFICATION + kex()


def test_fragmented_client_messages_wait_for_complete_valid_frame(harness):
    h = harness(); client = h.initial()
    raw = CLIENT_IDENTIFICATION + kex()
    for part in (raw[:3], raw[3:len(CLIENT_IDENTIFICATION) - 1], raw[len(CLIENT_IDENTIFICATION) - 1:]):
        client.sendall(part)
        h.step()
    h.until(lambda: h.service.ledger["client_packets_forwarded"] == 1)
    assert h.service.ledger["client_bytes_forwarded"] == len(raw)
    h.service.snapshot()


def test_nmap_forwarding_is_zero_even_for_a_single_application_byte(harness):
    h = harness(case="O1"); client = h.connect(); client.sendall(b"X")
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "client_limit"
    assert saved["client_bytes_received"] == 1 and saved["client_bytes_forwarded"] == 0
    assert h.peers[0].recv(1) == b""


def test_aggregate_nmap_connections_rate_and_reap_barrier(harness):
    h = harness(case="O1")
    for _ in range(3):
        client = h.initial(); h.until(lambda: h.service.active is None)
        h.read_closed(client, banner())
    denied = h.connect()
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    saved = h.service.snapshot()
    assert saved["connections_attempted"] == 4 and saved["connections_admitted"] == 3
    assert h.finalized == [1, 2, 3] and len(h.factories) == 3
    assert all(b - a >= 249 for a, b in zip(saved["admissions_elapsed_ms"], saved["admissions_elapsed_ms"][1:]))
    assert saved["client_bytes_forwarded"] == 0 and saved["client_bytes_delivered"] == 3 * len(banner())


def test_unarmed_connections_never_start_an_instance(harness):
    h = harness(); h.connect(armed=False)
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    assert not h.factories and not h.finalized
    h.service.snapshot()


def test_cancellation_closes_both_channels_and_finalizes_once(harness):
    h = harness(); h.initial(); h.service.close("cancelled"); h.service.close("cancelled")
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "cancelled" and h.finalized == [1]
    assert saved["active_connections"] == saved["pending_connections"] == 0
    assert h.peers[0].recv(1) == b""


def test_finalizer_failure_stops_admission_and_is_not_hidden(harness):
    h = harness(case="O1"); client = h.connect()
    def failed(number):
        h.finalized.append(number)
        raise RuntimeError("process_not_reaped")
    h.service.connection_finalizer = failed
    client.close(); h.until(lambda: h.service.ledger["finalized"])
    assert h.service.snapshot()["terminal_reason"] == "instance_cleanup_failed"


@pytest.mark.parametrize("raw", [b"SSH-2.0-Other_1\r\n", banner().replace(b"10.2p1", b"10.2"), b"x" * 255])
def test_unexpected_stock_identification_never_becomes_output(harness, raw):
    h = harness(); h.connect(); h.peers[0].sendall(raw)
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "daemon_response_invalid" and not saved["client_bytes_delivered"]
    assert saved["connections"][0]["original_daemon_hex"] == raw.hex()


@pytest.mark.parametrize("mutation", ["action", "counter", "input", "output", "transform", "source_offset",
    "message", "writes", "admission", "ready", "daemon", "bool_counter"])
def test_snapshot_replay_refuses_counter_stream_provenance_and_authority_forgery(harness, mutation):
    h = harness(); h.exchange_to_reply(); saved = h.service.snapshot(); row = saved["connections"][0]
    if mutation == "action": saved["case"] = "N1"
    elif mutation == "counter": saved["client_bytes_forwarded"] += 1
    elif mutation == "input": row["original_daemon_hex"] = "00" + row["original_daemon_hex"][2:]
    elif mutation == "output": row["delivered_response_hex"] = "00" + row["delivered_response_hex"][2:]
    elif mutation == "transform": row["transforms"][-1]["disposition"] = "unchanged-but-forged"
    elif mutation == "source_offset": row["transforms"][-1]["source_offset"] += 1
    elif mutation == "message": row["client_messages"][-1]["stage"] = "userauth"
    elif mutation == "writes": row["writes"].pop()
    elif mutation == "admission": saved["admissions_elapsed_ms"] = [999]
    elif mutation == "ready": saved["authorized"] = True
    elif mutation == "daemon": row["daemon_connected"] = False
    else: saved["connections_attempted"] = True
    with pytest.raises(ValueError): recorder.validate_snapshot(saved)


@pytest.mark.parametrize("kind", ["wrong_family", "wrong_endpoint", "not_listener", "missing_finalizer", "expired"])
def test_constructor_refuses_unbound_endpoint_or_missing_custody(monkeypatch, kind):
    channel = PortableListener()
    channel.bind(("127.0.0.1", 0)); channel.listen(1)
    monkeypatch.setitem(recorder.CONFIGURATIONS, "A", channel.getsockname())
    if kind == "wrong_family":
        channel.close(); channel, peer = socket.socketpair(); peer.close()
    elif kind == "wrong_endpoint": monkeypatch.setitem(recorder.CONFIGURATIONS, "A", ("10.77.0.20", 2222))
    elif kind == "not_listener":
        channel.close(); channel = PortableListener()
        channel.bind(("127.0.0.1", 0)); monkeypatch.setitem(recorder.CONFIGURATIONS, "A", channel.getsockname())
    try:
        with pytest.raises(ValueError):
            recorder.Service("A", "O2", channel, deadline=recorder.time.monotonic() + (-1 if kind == "expired" else 60),
                connection_factory=lambda *_: None, connection_finalizer=None if kind == "missing_finalizer" else lambda *_: None)
    finally:
        channel.close()


@pytest.mark.parametrize("bad", [struct.pack("!I", 8192), struct.pack("!I", 1), struct.pack("!I", 13),
                                  struct.pack("!I", 0xffffffff)])
def test_invalid_packet_prefix_is_rejected_before_body_allocation(bad):
    with pytest.raises(ValueError): packets.packet_size(bad)


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_protocol_validators_require_pinned_key_and_selected_algorithm(configuration):
    raw = reply(configuration)
    key, public, signature = packets.host_key_reply(packets.payload(raw), configuration)
    assert key == fixture.public_blob()
    tampered = bytearray(packets.payload(raw)); tampered[24] ^= 1
    with pytest.raises(ValueError): packets.host_key_reply(bytes(tampered), configuration)
    other = "B" if configuration == "A" else "A"
    with pytest.raises(ValueError): packets.host_key_reply(packets.payload(raw), other)
    with pytest.raises(ValueError): packets.kexinit(packets.payload(kex(other, server=True)), configuration, server=True)
    for number in (0, 1, packets.GROUP14_P - 1):
        with pytest.raises(ValueError): packets.dh_init(b"\x1e" + fixture.mpint(number))


def test_fault_transformations_require_valid_original_and_preserve_host_key_provenance():
    for stage, raw in (("identification", banner()), ("kexinit", kex(server=True)), ("key_reply", reply())):
        with pytest.raises(ValueError): packets.transform(stage, raw[:-1], "A", "N5")
    transformed, _, reason = packets.transform("key_reply", reply(), "A", "N5")
    raw = packets.payload(transformed[0])
    key, _ = packets.take_string(raw, 1)
    name, offset = packets.take_string(key, 0); exponent, offset = packets.take_string(key, offset)
    modulus, offset = packets.take_string(key, offset)
    assert name == b"ssh-rsa" and packets.mpint(exponent) == 65537 and packets.mpint(modulus).bit_length() == 1024
    assert reason == "unsupported_rsa1024_blob"


def test_deadline_that_expires_while_polling_prevents_queued_delivery(harness, monkeypatch):
    h = harness(); h.initial()
    client = h.clients[0]
    client.sendall(CLIENT_IDENTIFICATION)
    original = recorder.select.select
    def expires(reads, writes, errors, timeout):
        result = original(reads, writes, errors, timeout)
        h.clock = h.service.action_deadline
        return result
    monkeypatch.setattr(recorder.select, "select", expires)
    h.step()
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "action_deadline"
    assert saved["client_bytes_forwarded"] == 0 and h.finalized == [1]


@pytest.mark.parametrize("reason", ["owner_deadline", "action_deadline"])
def test_expiration_before_admission_never_calls_factory(harness, reason):
    h = harness()
    h.service.arm(h.clock + 5)
    if reason == "owner_deadline": h.clock += 60
    else: h.clock += 5
    h.step()
    assert h.service.snapshot()["terminal_reason"] == reason and not h.factories


def test_raw_daemon_overflow_retains_only_one_witness_byte_and_delivers_nothing(harness):
    h = harness(); h.connect(); h.peers[0].sendall(b"x" * 16384)
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "response_limit"
    assert saved["daemon_bytes_received"] == 8193 and saved["client_bytes_delivered"] == 0
    assert len(bytes.fromhex(saved["connections"][0]["original_daemon_hex"])) == 8193


def test_client_overflow_retains_only_one_witness_byte_and_never_forwards(harness):
    h = harness(); client = h.connect(); client.sendall(b"x" * 16384)
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "client_limit"
    assert saved["client_bytes_received"] == 8193 and saved["client_bytes_forwarded"] == 0


def test_incomplete_server_packet_is_retained_but_never_transformed(harness):
    h = harness(); client = h.initial(); client.sendall(CLIENT_IDENTIFICATION + kex())
    h.until(lambda: h.service.ledger["client_packets_forwarded"] == 1)
    h.peers[0].sendall(kex(server=True)[:-1]); h.peers[0].shutdown(socket.SHUT_WR)
    h.until(lambda: h.service.active is None)
    saved = h.service.snapshot(); row = saved["connections"][0]
    assert row["reason"] == "server_incomplete" and len(row["transforms"]) == 1
    assert bytes.fromhex(row["original_daemon_hex"]) == banner() + kex(server=True)[:-1]
    assert bytes.fromhex(row["delivered_response_hex"]) == banner()


def test_reset_empty_nmap_scan_does_not_consume_later_useful_exchange(harness):
    h = harness(case="O1"); client = h.connect()
    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); client.close()
    h.until(lambda: h.service.active is None)
    assert h.service.snapshot()["connections"][0]["reason"] == "empty_probe"
    client = h.initial(); h.until(lambda: h.service.active is None)
    h.read_closed(client, banner())
    saved = h.service.snapshot()
    assert saved["connections_admitted"] == 2 and saved["client_bytes_delivered"] == len(banner())


def test_cleanup_exception_during_terminal_close_is_visible(harness):
    h = harness(); h.connect()
    def failed(number): raise RuntimeError("not_reaped")
    h.service.connection_finalizer = failed
    h.service.close("cancelled")
    assert h.service.snapshot()["terminal_reason"] == "instance_cleanup_failed"


def test_factory_failure_finalizes_attempt_and_cannot_be_retried(harness):
    h = harness(); original = h.service.connection_factory
    def failed(number, deadline): raise OSError("instance_failed")
    h.service.connection_factory = failed
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM); client.connect(h.address); h.clients.append(client)
    h.service.arm(h.clock + 5)
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "io_failure" and saved["connections_denied"] == 1
    assert saved["daemon_connections"] == 0 and h.finalized == [1]


def test_fragment_partial_write_is_explicit_nonuseful_failure(harness):
    h = harness(case="R2"); h.connect()
    channel = h.service.active["socket"]
    class Partial:
        def send(self, raw): return channel.send(raw[:1])
        def close(self): return channel.close()
    active = h.service.active
    h.peers[0].sendall(banner())
    h.until(lambda: bool(active["chunks"]))
    # First planned fragment is one byte; send it before forcing a partial
    # second fragment. It is retained, then the recorder stops and reaps.
    h.service._write("client")
    h.clock += .005
    active["socket"] = Partial()
    h.service._write("client")
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "fragment_write_partial" and h.finalized == [1]
    assert saved["client_bytes_delivered"] == 2


def test_snapshot_is_detached_and_replay_never_uses_factory(harness):
    h = harness(); h.exchange_to_reply()
    saved = h.service.snapshot()
    original = deepcopy(saved)
    saved["connections"][0]["writes"].clear()
    assert h.service.snapshot() == original
    h.service.connection_factory = lambda *_: pytest.fail("snapshot created instance")
    assert recorder.validate_snapshot(original) == original
