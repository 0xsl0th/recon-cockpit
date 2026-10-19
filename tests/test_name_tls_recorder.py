"""Real loopback transport checks; fixture/native acceptance is separate."""

import socket
import time
from contextlib import contextmanager

import pytest

from recon_cockpit.secure_agent import name_tls_recorder as recorder, name_tls_wire as wire
from test_name_tls_wire_parser import dns_exchange, client_hello, server_hello


class Budget:
    def __init__(self, refuse=None):
        self.refuse, self.calls, self.observations = refuse, [], []

    def connection(self, local_id):
        self.calls.append(("connection", local_id))
        if self.refuse == "connection":
            raise OSError("denied")
        return True

    def request(self, operation):
        self.calls.append(("operation", operation))
        if self.refuse == "operation":
            raise OSError("denied")

    def before_write(self, active, direction, amount):
        self.calls.append(("reserve", direction, amount))
        if self.refuse == direction:
            raise OSError("denied")
        credits = active.setdefault("credits", {"request": 0, "response": 0})
        credits[direction] = max(credits[direction], amount)

    def after_write(self, active, direction, count):
        assert active["credits"][direction] >= count
        active["credits"][direction] -= count
        self.calls.append(("delivered", direction, count))

    def observe_dns(self, semantic, **commitments):
        self.observations.append((semantic, commitments))

    def finish(self, **summary):
        self.calls.append(("finish", summary))


class TranslatedSocket:
    """Test-only loopback substitution; assert production's fixed endpoint."""

    def __init__(self, stream, fixed, loopback):
        self.stream, self.fixed, self.loopback = stream, fixed, loopback
        self.connections = []

    def connect_ex(self, endpoint):
        assert endpoint == self.fixed
        self.connections.append(endpoint)
        return self.stream.connect_ex(self.loopback)

    def __getattr__(self, name):
        return getattr(self.stream, name)


def listener():
    stream = socket.socket()
    stream.bind(("127.0.0.1", 0))
    stream.listen(4)
    stream.setblocking(False)
    return stream


def run_exchange(operation, configuration, case, request, response, *, refuse=None, second=False, response_chunk=7):
    front, server = listener(), listener()
    client, private = socket.socket(), socket.socket()
    budget = Budget(refuse)
    row = wire.ROWS[configuration]
    endpoint = (row[0], row[1]) if operation == "dns" else (row[2], row[3] if operation == "http" else row[5])
    translated = TranslatedSocket(private, endpoint, server.getsockname())
    service = recorder.Service(operation, front, translated, configuration=configuration, case=case,
                               deadline=time.monotonic() + 2, budget=budget, second_observation=second)
    peer, received, delivered = None, bytearray(), bytearray()
    response_offset, eof = 0, False
    try:
        client.connect(front.getsockname())
        client.sendall(request)
        client.setblocking(False)
        until = time.monotonic() + 2.2
        while time.monotonic() < until:
            service.tick()
            if peer is None:
                try:
                    peer, _ = server.accept()
                    peer.setblocking(False)
                except BlockingIOError:
                    pass
            if peer is not None:
                try:
                    received.extend(peer.recv(8192))
                except BlockingIOError:
                    pass
                if len(received) >= len(request) and response_offset < len(response) and not service.done:
                    try:
                        response_offset += peer.send(response[response_offset:response_offset + response_chunk])
                    except BlockingIOError:
                        pass
                if response_offset == len(response):
                    peer.close()
                    peer = None
            try:
                chunk = client.recv(16384)
                if not chunk:
                    eof = True
                delivered.extend(chunk)
            except (BlockingIOError, ConnectionResetError):
                pass
            if service.done and eof:
                break
            time.sleep(.0002)
        assert service.done, service.snapshot()
        return service, bytes(received), bytes(delivered), budget, translated
    finally:
        service.close()
        for stream in (front, server, client, private, peer):
            if stream is not None:
                stream.close()


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", ("O1", "R2", "N6", "N7", "N8", "N1"))
def test_dns_delivery_and_provenance(configuration, case):
    request, original = dns_exchange(configuration)
    service, received, delivered, budget, translated = run_exchange("dns", configuration, case, request, original,
                                                                   second=case == "N1")
    assert service.reason == "complete"
    assert received == request
    expected = wire.transformed_dns_response(configuration, case, request, original, second_observation=case == "N1")
    assert delivered == expected
    assert len(translated.connections) == 1
    streams = service.raw_streams()
    assert streams == dict(request=request, delivered_request=request, original_response=original,
                           proposed_response=expected, delivered_response=expected)
    assert len(budget.observations) == int(case != "N8")
    snapshot = service.snapshot()
    assert snapshot["request_bytes_delivered"] == len(request)
    assert snapshot["response_bytes_delivered"] == len(expected)
    if case == "R2":
        actual = [call[2] for call in budget.calls if call[:2] == ("delivered", "response")]
        assert actual == [1, 1, 11, len(original) - 13]


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_http_requires_exact_name_before_private_connect(configuration):
    request = wire.http_request(configuration, "O2")
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    service, received, delivered, _, _ = run_exchange("http", configuration, "O2", request, response)
    assert service.reason == "complete" and received == request and delivered == response
    invalid = request.replace(b"harbordesk.test", b"otherdesk.test")
    service, received, delivered, _, private = run_exchange("http", configuration, "N9", invalid, response)
    assert service.reason == "http_request_mismatch"
    assert received == delivered == b"" and not private.connections


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_tls_plaintext_negotiation_before_forward(configuration):
    request = client_hello()
    response = server_hello() + b"\x17\3\3\0\x11" + b"x" * 17
    service, received, delivered, _, _ = run_exchange("tls", configuration, "O3", request, response)
    assert service.reason == "complete"
    assert received == request and delivered == response
    assert service.snapshot()["client_records"] == 1
    assert service.snapshot()["daemon_records"] == 2


@contextmanager
def tls_dialogue(case):
    """A live local exchange with independently timed reads, writes and EOFs."""
    front, server = listener(), listener()
    client, private = socket.socket(), socket.socket()
    budget = Budget()
    translated = TranslatedSocket(private, (wire.ROWS["A"][2], wire.ROWS["A"][5]), server.getsockname())
    service = recorder.Service("tls", front, translated, configuration="A", case=case,
                               deadline=time.monotonic() + 2, budget=budget)
    peer, request, response = None, bytearray(), bytearray()

    def pump(until):
        nonlocal peer
        deadline = time.monotonic() + 1
        while not until():
            service.tick()
            if peer is None:
                try:
                    peer, _ = server.accept()
                    peer.setblocking(False)
                except BlockingIOError:
                    pass
            for stream, output in ((peer, request), (client, response)):
                if stream is not None:
                    try:
                        output.extend(stream.recv(16384))
                    except (BlockingIOError, ConnectionResetError):
                        pass
            assert time.monotonic() < deadline, service.snapshot()
            time.sleep(.0002)

    try:
        client.connect(front.getsockname())
        client.sendall(client_hello())
        client.setblocking(False)
        pump(lambda: bytes(request) == client_hello())
        yield service, budget, client, peer, request, response, pump
    finally:
        service.close()
        for stream in (front, server, client, private, peer):
            if stream is not None:
                stream.close()


@pytest.mark.parametrize("case", ("N11", "N12", "N13"))
@pytest.mark.parametrize("first_eof", ("client", "daemon"))
def test_terminal_client_alert_is_charged_delivered_and_waits_for_both_eofs(case, first_eof):
    flight = server_hello() + b"\x17\3\3\0\x11" + b"x" * 17
    alert = wire.tls_verification_alert(case)
    with tls_dialogue(case) as (service, budget, client, peer, request, response, pump):
        peer.sendall(flight)
        pump(lambda: bytes(response) == flight)
        client.sendall(alert)
        pump(lambda: bytes(request) == client_hello() + alert)
        first, second = (client, peer) if first_eof == "client" else (peer, client)
        first.shutdown(socket.SHUT_WR)
        pump(lambda: getattr(service, first_eof + "_eof"))
        assert not service.done
        assert not getattr(service, ("daemon" if first_eof == "client" else "client") + "_eof")
        for _ in range(3):
            service.tick()
        assert not service.done
        second.shutdown(socket.SHUT_WR)
        pump(lambda: service.done)
        assert service.reason == "complete" and service.client_eof and service.daemon_eof
        assert service.raw_streams()["request"] == service.raw_streams()["delivered_request"] == bytes(request)
        assert service.raw_streams()["original_response"] == service.raw_streams()["delivered_response"] == flight
        assert ("reserve", "request", len(alert)) in budget.calls
        assert ("delivered", "request", len(alert)) in budget.calls
        assert budget.calls[-1][0] == "finish"
        assert budget.calls[-1][1]["request_bytes"] == len(request)


@pytest.mark.parametrize("coalesced", (False, True))
@pytest.mark.parametrize("tail", (b"x", b"\x15\3\3\0\2\2*", client_hello()))
def test_no_client_byte_after_terminal_alert_even_after_daemon_eof(coalesced, tail):
    flight = server_hello() + b"\x17\3\3\0\x11" + b"x" * 17
    alert = wire.tls_verification_alert("N11")
    with tls_dialogue("N11") as (service, budget, client, peer, request, response, pump):
        peer.sendall(flight)
        pump(lambda: bytes(response) == flight)
        client.sendall(alert + (tail if coalesced else b""))
        if not coalesced:
            pump(lambda: bytes(request) == client_hello() + alert)
            peer.shutdown(socket.SHUT_WR)
            pump(lambda: service.daemon_eof)
            assert not service.done
            client.sendall(tail)
        pump(lambda: service.done)
        assert service.reason == "additional_tls_handshake"
        assert service.raw_streams()["delivered_request"] in (client_hello(), client_hello() + alert)
        assert budget.calls[-1][1]["reason"] == "additional_tls_handshake"


@pytest.mark.parametrize("delivered", (0, "all_but_one"))
def test_alert_requires_actual_complete_server_record_delivery(delivered):
    class LimitedWrite:
        def __init__(self, stream, remaining):
            self.stream, self.remaining = stream, remaining

        def send(self, raw):
            if not self.remaining:
                raise BlockingIOError()
            count = self.stream.send(raw[:self.remaining])
            self.remaining -= count
            return count

        def __getattr__(self, name):
            return getattr(self.stream, name)

    flight = server_hello() + b"\x17\3\3\0\x11" + b"x" * 17
    amount = 0 if delivered == 0 else len(flight) - 1
    with tls_dialogue("N11") as (service, budget, client, peer, request, response, pump):
        service.client = LimitedWrite(service.client, amount)
        peer.sendall(flight)
        pump(lambda: service.server_encrypted and len(service.raw["delivered_response"]) == amount)
        client.sendall(wire.tls_verification_alert("N11"))
        pump(lambda: service.done)
        assert service.reason == "additional_tls_handshake"
        assert service.raw_streams()["delivered_request"] == client_hello()
        assert service.raw_streams()["original_response"] == flight


def test_verification_case_cannot_complete_without_client_alert():
    with tls_dialogue("N12") as (service, budget, client, peer, request, response, pump):
        peer.sendall(server_hello() + b"\x17\3\3\0\x11" + b"x" * 17)
        peer.shutdown(socket.SHUT_WR)
        pump(lambda: service.daemon_eof)
        assert not service.done
        client.shutdown(socket.SHUT_WR)
        pump(lambda: service.done)
        assert service.reason == "incomplete_verification_alert"


@pytest.mark.parametrize("refuse,request_delivered,response_delivered", (("connection", False, False), ("operation", False, False),
                                                                     ("request", False, False), ("response", True, False)))
def test_owner_refusal_precedes_delivery(refuse, request_delivered, response_delivered):
    request, original = dns_exchange()
    service, received, delivered, budget, _ = run_exchange("dns", "A", "O1", request, original, refuse=refuse)
    assert service.reason == "io_failure"
    assert bool(received) is request_delivered and bool(delivered) is response_delivered
    assert service.raw_streams()["delivered_response"] == b""
    assert not budget.observations


@pytest.mark.parametrize("mutation", (lambda q: q + q, lambda q: q[:14] + b"\xc0\x0c" + q[16:]))
def test_second_or_malformed_question_never_connects_daemon(mutation):
    request, response = dns_exchange()
    service, received, delivered, _, private = run_exchange("dns", "A", "O1", mutation(request), response)
    assert service.reason != "complete"
    assert not private.connections and received == delivered == b""


@pytest.mark.parametrize("tail", ("second_frame", "trailing_byte"))
@pytest.mark.parametrize("coalesced", (False, True))
def test_dns_later_read_cannot_append_to_an_already_forwarded_answer(tail, coalesced):
    request, original = dns_exchange()
    response = original + (original if tail == "second_frame" else b"\0")
    service, received, delivered, budget, _ = run_exchange("dns", "A", "O1", request, response,
        response_chunk=len(response) if coalesced else len(original))
    assert service.reason not in ("complete", "timeout", "cancelled")
    assert received == request and delivered == b"" and not budget.observations
    assert service.daemon_write_closed
    assert not service.raw_streams()["delivered_response"]


@pytest.mark.parametrize("case", ("O1", "N8"))
def test_dns_query_half_close_precedes_response_completion(case):
    request, response = dns_exchange()
    service, received, delivered, budget, _ = run_exchange("dns", "A", case, request, response)
    assert service.reason == "complete" and service.daemon_eof and service.daemon_write_closed
    assert received == request and delivered
    assert bool(budget.observations) == (case != "N8")
