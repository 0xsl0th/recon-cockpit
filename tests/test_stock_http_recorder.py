"""Transport accounting tests; socket peers are doubles, not nginx evidence."""

from copy import deepcopy
import socket

import pytest

from recon_cockpit.secure_agent import stock_http_recorder as recorder, stock_http_spec as spec


def response(body=b"owned public response", *, status=200):
    return (f"HTTP/1.1 {status} Test\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body)


@pytest.mark.parametrize("configuration,case", spec.TRIALS)
def test_standalone_request_constants_match_accepted_spec(configuration, case):
    assert recorder.request_bytes(configuration, case) == spec.request_bytes(configuration, case)
    assert set(recorder.CASES) == set(spec.CASES)
    assert set(recorder.CONFIGURATIONS) == set(spec.CONFIGURATIONS)


@pytest.mark.parametrize("case", spec.CASES)
def test_transform_preserves_original_and_declares_only_selected_fault(case):
    raw = response()
    chunks, delay, disposition = recorder.transform_response(case, raw)
    changed = b"".join(chunks)
    assert raw == response()
    if case == "R2":
        assert len(chunks) == 4 and delay == .005 and changed == raw
        assert len(chunks[0]) == 1
        assert sum(map(len, chunks[:2])) == raw.index(b"\r\n\r\n") + 2
        assert len(chunks[-1]) < len(b"owned public response")
    elif case == "N1":
        assert changed == raw[:-1]
    elif case == "N2":
        assert changed == b"H" and disposition == "reset_before_header"
    elif case == "N3":
        assert changed == b"" and disposition == "withheld_until_deadline"
    elif case == "N4":
        assert len(changed) == 2049 and changed.startswith(raw)
    elif case == "N5":
        assert changed.count(b"Content-Length:") == 2
        assert b"Content-Length: 22\r\n" in changed
    else:
        assert changed == raw and disposition == "unchanged"


@pytest.mark.parametrize("raw", [b"", b"HTTP/1.1 200 OK\r\n\r\nx", response()[:-1], response() + b"x",
    response().replace(b"Content-Length: 21", b"Content-Length: 20"),
    response().replace(b"Content-Length:", b"Transfer-Encoding:"),
    response().replace(b"Content-Length: 21", b"Content-Length: 21\r\nContent-Length: 21"),
    response().replace(b"HTTP/1.1", b"HTTP/2"), response().replace(b"200 Test", b"500 Test")])
def test_fault_injection_refuses_incomplete_or_invalid_daemon_bytes(raw):
    with pytest.raises(ValueError):
        recorder.transform_response("N4", raw)


class Harness:
    def __init__(self, monkeypatch, configuration="A", case="O1"):
        self.clock = 100.0
        monkeypatch.setattr(recorder.time, "monotonic", lambda: self.clock)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.address = self.listener.getsockname()
        self.service = recorder.Service(configuration, case, self.listener, deadline=self.clock + 60)
        self.peers, self.clients = [], []
        def private():
            channel, peer = socket.socketpair()
            channel.setblocking(False)
            peer.setblocking(False)
            self.peers.append(peer)
            return channel
        monkeypatch.setattr(recorder, "_private_connection", private)

    def arm(self):
        self.service.arm(self.clock + (5 if self.service.nmap else 1))

    def client(self, raw=b""):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(self.address)
        client.setblocking(False)
        if raw:
            client.sendall(raw)
        self.clients.append(client)
        return client

    def step(self, seconds=.001):
        self.service.tick(0)
        self.clock += seconds

    def until(self, condition, maximum=1000):
        for _ in range(maximum):
            self.step()
            if condition():
                return
        pytest.fail("bounded test peer did not reach expected state")

    def reply(self, raw=None):
        self.until(lambda: self.service.ledger["requests_delivered"] == 1)
        peer = self.peers[0]
        assert peer.recv(1024) == self.service.expected
        peer.sendall(response() if raw is None else raw)
        peer.shutdown(socket.SHUT_WR)

    def close(self):
        self.service.close()
        for channel in self.peers + self.clients:
            channel.close()


@pytest.fixture
def harness(monkeypatch):
    instances = []
    def make(configuration="A", case="O1"):
        instance = Harness(monkeypatch, configuration, case)
        instances.append(instance)
        return instance
    yield make
    for instance in instances:
        instance.close()


def test_unarmed_connections_are_counted_and_refused_without_private_connection(harness):
    h = harness()
    h.client(spec.request_bytes("A", "O1"))
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    saved = h.service.snapshot()
    assert saved["connections_attempted"] == 1
    assert saved["connections_admitted"] == saved["requests_delivered"] == 0
    assert not h.peers
    assert saved["events"][-1]["reason"] == "not_armed"


@pytest.mark.parametrize("raw", [b"GET /outside HTTP/1.1\r\n\r\n", spec.request_bytes("A", "O1") + b"x",
                               spec.request_bytes("A", "O1") * 2, b"POST /harbordesk/portal.html HTTP/1.1\r\n\r\n"])
def test_changed_or_pipelined_request_never_reaches_private_daemon(harness, raw):
    h = harness()
    h.arm()
    h.client(raw)
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    saved = h.service.snapshot()
    assert saved["requests_validated"] == saved["requests_delivered"] == 0
    assert saved["request_bytes_received"] > 0 and not h.peers


def test_partial_request_is_not_forwarded_before_exact_completion(harness):
    h = harness()
    h.arm()
    raw = spec.request_bytes("A", "O1")
    client = h.client(raw[:1])
    for _ in range(5):
        h.step()
    assert not h.peers
    client.sendall(raw[1:])
    h.reply()
    h.until(lambda: h.service.ledger["client_response_bytes"] == len(response()))
    assert client.recv(4096) == response()
    saved = h.service.snapshot()
    assert saved["requests_validated"] == saved["requests_delivered"] == saved["daemon_connections"] == 1
    assert saved["request_bytes_received"] == saved["request_bytes_delivered"] == len(raw)
    assert saved["original_response_hex"] == saved["transformed_response_hex"] == response().hex()
    h.service.close()
    saved = h.service.snapshot()
    assert saved["finalized"] and saved["active_connections"] == saved["pending_connections"] == 0


def test_later_request_bytes_are_never_forwarded(harness):
    h = harness()
    h.arm()
    client = h.client(spec.request_bytes("A", "O1"))
    h.until(lambda: h.service.ledger["requests_delivered"] == 1)
    client.sendall(b"GET /outside HTTP/1.1\r\n\r\n")
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    assert h.peers[0].recv(1024) == spec.request_bytes("A", "O1")
    assert h.peers[0].recv(1024) == b""
    assert h.service.snapshot()["events"][-1]["reason"] == "extra_request_bytes"


def test_second_connection_is_denied_and_not_erased_from_ledger(harness):
    h = harness()
    h.arm()
    h.client(spec.request_bytes("A", "O1"))
    h.reply()
    h.until(lambda: h.service.active is None)
    h.client(spec.request_bytes("A", "O1"))
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    saved = h.service.snapshot()
    assert saved["connections_attempted"] == 2 and saved["connections_admitted"] == 1
    assert saved["requests_delivered"] == 1 and len(h.peers) == 1


def test_nmap_empty_scan_and_null_exchanges_then_exact_get_obey_rate_and_cap(harness):
    h = harness(case="O5")
    h.arm()
    first = h.client()
    first.close()
    h.until(lambda: any(e["kind"] == "empty" for e in h.service.ledger["events"]))
    second = h.client()
    second.close()
    third = h.client(spec.request_bytes("A", "O5"))
    h.reply()
    h.until(lambda: h.service.active is None)
    assert third.recv(4096) == response()
    saved = h.service.snapshot()
    assert saved["connections_attempted"] == saved["connections_admitted"] == 3
    assert saved["requests_delivered"] == 1
    assert all(b - a >= 249 for a, b in zip(saved["admissions_elapsed_ms"], saved["admissions_elapsed_ms"][1:]))
    h.client(spec.request_bytes("A", "O5"))
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    assert h.service.snapshot()["connections_attempted"] == 4


@pytest.mark.parametrize("case", ["R2", "N1", "N2", "N3", "N4", "N5"])
def test_each_fault_occurs_after_one_real_peer_delivery_and_preserves_original(harness, case):
    h = harness(case=case)
    h.arm()
    client = h.client(spec.request_bytes("A", case))
    h.reply()
    if case == "N3":
        h.until(lambda: h.service.active is not None and h.service.active["stage"] == "withhold")
        with pytest.raises(BlockingIOError):
            client.recv(4096)
        h.clock = h.service.action_deadline
        h.step()
        assert h.service.snapshot()["terminal_reason"] == "action_deadline"
    else:
        h.until(lambda: h.service.active is None)
    saved = h.service.snapshot()
    assert saved["requests_delivered"] == 1 and saved["original_response_hex"] == response().hex()
    chunks, _, _ = recorder.transform_response(case, response())
    assert saved["transformed_response_hex"] == b"".join(chunks).hex()
    assert saved["client_response_bytes"] == sum(map(len, chunks))
    if case == "R2":
        assert len(saved["writes"]) == 4
        assert all(b["elapsed_ms"] - a["elapsed_ms"] >= 4 for a, b in zip(saved["writes"], saved["writes"][1:]))


def test_invalid_or_oversized_daemon_stream_stops_without_client_success(harness):
    h = harness()
    h.arm()
    h.client(spec.request_bytes("A", "O1"))
    h.reply(response()[:-1])
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "daemon_response_invalid"
    assert saved["requests_delivered"] == 1 and saved["client_response_bytes"] == 0


def test_cancel_closes_pending_active_and_private_sockets_without_additional_writes(harness):
    h = harness()
    h.arm()
    h.client(spec.request_bytes("A", "O1"))
    h.until(lambda: h.service.ledger["requests_delivered"] == 1)
    h.service.close("cancelled")
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "cancelled" and saved["finalized"]
    assert saved["client_response_bytes"] == 0
    h.step()
    assert h.service.snapshot() == saved


def test_action_expiry_prevents_forwarding_even_when_request_is_ready(harness):
    h = harness()
    h.arm()
    h.client(spec.request_bytes("A", "O1"))
    h.clock = h.service.action_deadline
    h.step()
    assert not h.peers and h.service.snapshot()["terminal_reason"] == "action_deadline"


@pytest.mark.parametrize("change", [lambda r: r.update(extra=True), lambda r: r.update(requests_delivered=True),
    lambda r: r.update(connections_admitted=4), lambda r: r.update(configuration="external"),
    lambda r: r.update(original_response_hex="zz"), lambda r: r.update(finalized=True),
    lambda r: r.update(transformed_response_hex="00"), lambda r: r.update(client_response_bytes=1),
    lambda r: r["writes"][0].update(offset=1), lambda r: r["events"][0].update(reason="unbounded")])
def test_snapshot_rejects_tampering(harness, change):
    h = harness()
    h.arm()
    h.client(spec.request_bytes("A", "O1"))
    h.reply()
    h.until(lambda: h.service.active is None)
    saved = h.service.snapshot()
    changed = deepcopy(saved)
    change(changed)
    with pytest.raises(ValueError):
        recorder.validate_snapshot(changed)
    assert h.service.snapshot() == saved


def test_invalid_arm_and_poll_are_inert(harness):
    h = harness()
    for deadline in (True, float("nan"), h.clock, h.clock + 1.1):
        with pytest.raises(ValueError):
            h.service.arm(deadline)
    h.arm()
    with pytest.raises(ValueError):
        h.service.arm(h.clock + .5)
    for interval in (True, float("nan"), -.1, .011):
        with pytest.raises(ValueError):
            h.service.tick(interval)
    assert not h.peers


@pytest.mark.parametrize("case", ["O1", "O5"])
def test_incomplete_request_eof_is_recorded_without_private_delivery(harness, case):
    h = harness(case=case)
    h.arm()
    client = h.client(b"GET /")
    client.shutdown(socket.SHUT_WR)
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    saved = h.service.snapshot()
    assert not h.peers and saved["events"][-1]["reason"] == "request_incomplete"
    assert saved["request_bytes_delivered"] == 0


def test_nmap_fourth_empty_connection_is_rejected_by_connection_budget(harness):
    h = harness(case="O6")
    h.arm()
    for number in range(3):
        h.client().close()
        h.until(lambda: sum(e["kind"] == "empty" for e in h.service.ledger["events"]) == number + 1)
    h.client().close()
    h.until(lambda: h.service.ledger["connections_denied"] == 1)
    saved = h.service.snapshot()
    assert saved["connections_attempted"] == 4 and saved["connections_admitted"] == 3
    assert saved["events"][-1]["reason"] == "connection_limit"
    assert not h.peers


def test_owner_deadline_closes_unarmed_listener(harness):
    h = harness()
    h.clock = h.service.deadline
    h.step()
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "owner_deadline" and not saved["armed"]
    with pytest.raises(ValueError):
        h.arm()


def test_oversized_daemon_reply_never_crosses_owner_capture_cap(harness):
    h = harness()
    h.arm()
    h.client(spec.request_bytes("A", "O1"))
    h.reply(response(b"x" * 3000))
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "daemon_response_limit"
    assert saved["daemon_response_bytes"] <= 2049 and saved["client_response_bytes"] == 0


def test_private_connect_failure_is_explicit_and_leaks_no_action_result(harness, monkeypatch):
    h = harness()
    h.arm()
    def refused():
        raise OSError("private test peer unavailable")
    monkeypatch.setattr(recorder, "_private_connection", refused)
    h.client(spec.request_bytes("A", "O1"))
    h.until(lambda: h.service.ledger["finalized"])
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "io_failure"
    assert saved["requests_validated"] == 1 and saved["requests_delivered"] == 0


def test_reset_option_failure_is_not_reported_as_successful_fault(harness):
    h = harness(case="N2")
    h.arm()
    h.client(spec.request_bytes("A", "N2"))
    h.reply()
    h.until(lambda: h.service.active is not None and h.service.active["stage"] == "send_response")
    channel = h.service.active["socket"]
    class RefuseReset:
        def __getattr__(self, name):
            return getattr(channel, name)
        def setsockopt(self, *args):
            raise OSError("test reset denied")
    h.service.active["socket"] = RefuseReset()
    h.until(lambda: h.service.ledger["finalized"])
    assert h.service.snapshot()["terminal_reason"] == "io_failure"
    assert channel.fileno() == -1


def test_attempt_flood_stops_at_bounded_event_ledger(harness):
    h = harness()
    for _ in range(33):
        if h.service.ledger["finalized"]:
            break
        h.client().close()
        h.step()
    saved = h.service.snapshot()
    assert saved["terminal_reason"] == "event_limit"
    assert len(saved["events"]) == recorder.MAX_EVENTS
    assert saved["requests_delivered"] == 0 and not h.peers


@pytest.mark.parametrize("configuration,case", [("C", "O1"), ("A", "O7"), (True, "O1"), ("A", [])])
def test_invalid_selection_precedes_listener_access(configuration, case):
    with pytest.raises(ValueError):
        recorder.Service(configuration, case, object(), deadline=1)


@pytest.mark.parametrize("kind", ["attempt", "admit", "validated", "delivered", "received", "forwarded", "daemon_received"])
def test_removed_accounting_event_cannot_keep_unchanged_success_totals(harness, kind):
    h = harness()
    h.arm()
    h.client(spec.request_bytes("A", "O1"))
    h.reply()
    h.until(lambda: h.service.active is None)
    value = h.service.snapshot()
    value["events"] = [row for row in value["events"] if row["kind"] != kind]
    with pytest.raises(ValueError):
        recorder.validate_snapshot(value)
