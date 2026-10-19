"""Real loopback transport checks; fixture/native acceptance is separate."""

import socket
import time

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


def run_exchange(operation, configuration, case, request, response, *, refuse=None, second=False):
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
                if len(received) >= len(request) and response_offset < len(response):
                    try:
                        response_offset += peer.send(response[response_offset:response_offset + 7])
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
