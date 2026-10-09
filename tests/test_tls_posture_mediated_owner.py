"""Portable relay tests use unnamed socketpairs, never a network target."""

import errno
import hashlib
import io
import json
import queue
import socket
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import tls_posture_mediated_owner as owner


def vector(raw, width=2):
    return len(raw).to_bytes(width, "big") + raw


def extension(kind, raw):
    return kind.to_bytes(2, "big") + vector(raw)


def hello(version="tls1_3", *, retry=False):
    protocol, _, cipher = owner.fixture.VERSIONS[version]
    extensions = extension(0, vector(b"\0" + vector(b"harbordesk.test")))
    extensions += extension(10, b"\0\2\0\x17")
    if version == "tls1_3":
        extensions += extension(13, b"\0\2\4\3") + extension(43, b"\2\3\4")
        extensions += extension(51, vector(b"\0\x17" + vector(b"\4" + b"x" * 64)))
        if retry:
            extensions += extension(44, vector(owner.fixture.COOKIE))
    body = min(protocol, 0x0303).to_bytes(2, "big") + b"r" * 32 + vector(b"", 1)
    body += vector(cipher.to_bytes(2, "big") + b"\0\xff") + b"\1\0" + vector(extensions)
    return b"\x16\3\1" + vector(b"\1" + len(body).to_bytes(3, "big") + body)


class Listener:
    """Supply accepted stream sockets without binding an Internet socket."""

    def __init__(self):
        self.pending = queue.Queue()
        self.timeout = 0.05

    def settimeout(self, timeout):
        self.timeout = timeout

    def accept(self):
        try:
            return self.pending.get(timeout=self.timeout), None
        except queue.Empty:
            raise socket.timeout from None

    def connect(self):
        client, accepted = socket.socketpair()
        client.settimeout(2)
        self.pending.put(accepted)
        return client


@pytest.fixture
def build_service(monkeypatch):
    # Reject/HRR branches never use the TLS context. Avoid replacing either the
    # relay, gate, record parser, socket operations or fixture request handler.
    monkeypatch.setattr(owner.fixture, "tls_context", lambda case, ledger: None)
    services = []

    def build(case="hrr", version="tls1_3"):
        listener = Listener()
        request = {"case": case, "version": version, "deadline": time.monotonic() + 3}
        service = owner.Service(request, listener)
        services.append(service)
        return service, listener

    yield build
    for service in services:
        service.close()
        while not service.listener.pending.empty():
            service.listener.pending.get_nowait().close()


def read_record(connection):
    raw = bytearray()
    size = 5
    while len(raw) < size:
        chunk = connection.recv(size - len(raw))
        assert chunk, "unexpected relay EOF"
        raw.extend(chunk)
        if len(raw) == 5:
            size += int.from_bytes(raw[3:5], "big")
    return bytes(raw)


def snapshot(service):
    return service.snapshot(0, 0, time.monotonic() + 2)


def wait_until(predicate):
    deadline = time.monotonic() + 1
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(0.002)


@pytest.mark.parametrize("version", owner.fixture.VERSIONS)
def test_actual_socketpair_rejection_preserves_peer_and_relay_evidence(build_service, version):
    service, listener = build_service("reject", version)
    with listener.connect() as client:
        raw = hello(version)
        client.sendall(raw)
        assert read_record(client) == b"\x15\3\3\0\2\2\x46"
        assert client.recv(1) == b""
        receipt = snapshot(service)
    peer, mediation = receipt["diagnostic"], receipt["mediation"]
    assert receipt["connection_count"] == receipt["request_count"] == 1
    assert peer["client_hellos"] == 1 and peer["error"] is None
    assert not peer["handshake_completed"] and not mediation["blocked"]
    assert mediation["error"] is None and mediation["threads_joined"] and mediation["completed"]
    assert mediation["client_ingress_records"] == mediation["client_forwarded_records"] == peer["received_records"]
    assert mediation["client_ingress_bytes"] == mediation["client_forwarded_bytes"] == len(raw)
    assert mediation["client_transmitted_bytes"] == len(raw)
    assert mediation["server_forwarded_bytes"] == mediation["server_transmitted_bytes"] == 7
    assert mediation["server_forwarded_records"] == mediation["server_ingress_records"]
    assert mediation["server_pending_record"] is None
    assert mediation["peer_streams_admitted"] == mediation["forwarded_client_hellos"] == 1


@pytest.mark.parametrize("compatibility_ccs", [False, True])
def test_second_client_hello_reaches_ingress_but_never_private_peer(build_service, compatibility_ccs):
    service, listener = build_service()
    initial, retry = hello(), hello(retry=True)
    with listener.connect() as client:
        client.sendall(initial)
        response = read_record(client)
        assert owner.fixture.HRR_RANDOM in response and owner.fixture.COOKIE in response
        ccs = b"\x14\3\3\0\1\1" if compatibility_ccs else b""
        client.sendall(ccs + retry)
        assert client.recv(1) == b""
        receipt = snapshot(service)
    peer, mediation = receipt["diagnostic"], receipt["mediation"]
    assert mediation["completed"] and mediation["threads_joined"]
    assert mediation["blocked"] and mediation["block_reason"] == "extra_client_hello"
    assert mediation["blocked_record_index"] == (2 if compatibility_ccs else 1)
    assert mediation["gate_state"] == "blocked" and mediation["error"] is None
    assert peer["hrr_sent"] and peer["client_hellos"] == 1
    assert peer["error"] == "tls_posture_owner_eof"
    assert [bytes.fromhex(item["raw_hex"]) for item in peer["received_records"]] == ([initial, ccs] if ccs else [initial])
    assert mediation["client_forwarded_records"] == peer["received_records"]
    assert mediation["client_ingress_records"][-1]["raw_hex"] == retry.hex()
    assert mediation["client_forwarded_bytes"] == len(initial + ccs)
    assert mediation["client_ingress_bytes"] == len(initial + ccs + retry)
    assert mediation["forwarded_client_hellos"] == mediation["peer_streams_admitted"] == 1
    # A normal retry refusal closes the private stream and records actual EOF;
    # it must not impersonate explicit owner cancellation during peer teardown.
    assert service.stop.is_set() and not service.cancel_peer.is_set()
    service.close()
    assert service.cancel_peer.is_set()
    assert service.ledger["error"] == "tls_posture_owner_eof"
    assert service.mediation["completed"] and service.mediation["threads_joined"]


def test_partial_first_hello_is_not_forwarded_until_complete(build_service):
    service, listener = build_service("reject")
    with listener.connect() as client:
        raw = hello()
        client.sendall(raw[:-1])
        wait_until(lambda: service.mediation["client_ingress_bytes"] == len(raw) - 1)
        assert service.ledger["received_bytes"] == service.mediation["client_forwarded_bytes"] == 0
        client.sendall(raw[-1:])
        assert read_record(client) == b"\x15\3\3\0\2\2\x46"
        receipt = snapshot(service)
    assert receipt["mediation"]["client_forwarded_bytes"] == len(raw)
    assert receipt["diagnostic"]["client_hellos"] == 1


@pytest.mark.parametrize("raw,reason", [(b"\x16\3", "partial_record"),
    (b"\x16\3\3\0\0", "record_payload_limit"),
    (b"\x17\3\3\0\1x", "invalid_first_client_hello"),
    (b"\x16\3\3\x20\0", "direction_byte_limit"),
    (b"\x16\3\4\0\1x", "invalid_record_header")])
def test_invalid_or_partial_ingress_never_creates_peer_request(build_service, raw, reason):
    service, listener = build_service("reject")
    with listener.connect() as client:
        client.sendall(raw)
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError as error:
            # A complete invalid record may already have closed the peer.
            # Darwin reports ENOTCONN when this races our half-close.
            if error.errno != errno.ENOTCONN:
                raise
        try:
            assert client.recv(1) == b""
        except ConnectionResetError:
            pass  # Refused header can leave an unread payload byte in the socket.
        receipt = snapshot(service)
    mediation = receipt["mediation"]
    assert mediation["blocked"] and mediation["block_reason"] == reason
    assert receipt["request_count"] == 0 and receipt["diagnostic"]["client_hellos"] == 0
    assert mediation["client_forwarded_records"] == []
    assert mediation["client_transmitted_bytes"] == mediation["peer_streams_admitted"] == 0
    assert mediation["threads_joined"] and mediation["completed"]


def test_extra_queued_connection_gets_no_second_peer_stream(build_service):
    service, listener = build_service("reject")
    with listener.connect() as client, listener.connect() as extra:
        client.sendall(hello())
        assert read_record(client) == b"\x15\3\3\0\2\2\x46"
        receipt = snapshot(service)
        assert extra.recv(1) == b""
    assert receipt["connection_count"] == 2 and receipt["request_count"] == 1
    assert receipt["mediation"]["extra_frontend_connections_refused"] == 1
    assert receipt["mediation"]["frontend_connections_admitted"] == 1
    assert receipt["mediation"]["peer_streams_admitted"] == 1


def test_connection_deadline_terminates_partial_record_and_joins_both_threads(build_service, monkeypatch):
    monkeypatch.setattr(owner, "CONNECTION_SECONDS", 0.1)
    service, listener = build_service("reject")
    with listener.connect() as client:
        client.sendall(b"\x16\3")
        assert client.recv(1) == b""
        receipt = snapshot(service)
    assert receipt["mediation"]["connection_deadline_expired"]
    assert receipt["mediation"]["error"] == "tls_posture_owner_deadline"
    assert receipt["mediation"]["client_forwarded_bytes"] == 0
    assert receipt["mediation"]["threads_joined"] and receipt["mediation"]["completed"]


def test_idle_snapshot_cancels_and_closes_private_descriptors(build_service):
    service, _ = build_service()
    receipt = snapshot(service)
    assert receipt["connection_count"] == receipt["request_count"] == 0
    assert receipt["mediation"]["threads_joined"] and receipt["mediation"]["completed"]
    assert service.relay_pair.fileno() == service.peer_pair.fileno() == -1
    assert not service.thread.is_alive() and not service.peer_thread.is_alive()
    service.close()  # Idempotent cleanup never creates a replacement socketpair.


def test_cancellation_interrupts_connected_partial_read(build_service):
    service, listener = build_service()
    with listener.connect() as client:
        client.sendall(b"\x16\3")
        wait_until(lambda: service.mediation["client_ingress_bytes"] == 2)
        service.close()
        assert client.recv(1) == b""
    assert service.mediation["threads_joined"] and service.mediation["completed"]
    assert service.relay_pair.fileno() == service.peer_pair.fileno() == -1
    assert service.mediation["client_forwarded_records"] == []


def test_peer_read_cancellation_does_not_depend_on_cross_thread_socket_close():
    # Some platforms do not promptly wake a blocking read when another thread
    # closes that descriptor. Keep both endpoints OPEN to test cancellation's
    # independent wake mechanism instead of relying on shutdown behavior.
    stop = threading.Event()
    errors = []
    receiving, sending = socket.socketpair()
    with receiving, sending:
        ledger = owner.fixture.new_ledger("hrr", "tls1_3")
        records = owner.fixture.RecordIO(receiving, time.monotonic() + 3,
                                         ledger, cancel_event=stop)
        def receive():
            try:
                records.receive()
            except ValueError as error:
                errors.append(str(error))
        thread = threading.Thread(target=receive)
        thread.start()
        sending.sendall(b"\x16\3")
        wait_until(lambda: ledger["received_bytes"] == 2)
        stop.set()
        thread.join(timeout=0.5)
        assert not thread.is_alive()
        assert errors == ["tls_posture_owner_cancelled"]
        assert receiving.fileno() >= 0 and sending.fileno() >= 0


def test_record_metadata_hashes_server_without_duplicating_raw_bytes():
    raw = b"\x15\3\3\0\2\2\x46"
    assert owner.record_description(raw, include_raw=False) == {
        "type": 21, "version": "0303", "payload_length": 2,
        "raw_sha256": hashlib.sha256(raw).hexdigest()}


def test_standalone_owner_import_uses_reviewed_sibling_modules():
    code = ("import importlib.util; s=importlib.util.spec_from_file_location('owner',%r); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "assert m.MediatedOwner().service_port({}) == 8080") % owner.__file__
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()


def test_cumulative_byte_cap_rejects_declared_payload_before_reading_it(build_service):
    service, listener = build_service()
    with listener.connect() as client:
        first = hello()
        client.sendall(first)
        assert owner.fixture.HRR_RANDOM in read_record(client)
        # This record alone fits, but the established stream no longer has room.
        client.sendall(b"\x16\3\3" + (owner.CLIENT_BYTES - 5).to_bytes(2, "big"))
        assert client.recv(1) == b""
        receipt = snapshot(service)
    mediation = receipt["mediation"]
    assert mediation["blocked"] and mediation["block_reason"] == "direction_byte_limit"
    assert mediation["client_ingress_bytes"] == len(first) + 5
    assert mediation["client_forwarded_bytes"] == len(first)
    assert mediation["blocked_record_index"] is None
    assert receipt["diagnostic"]["client_hellos"] == 1


def test_owner_rejects_a_lifetime_beyond_thirty_seconds():
    request = {"case": "modern", "version": "tls1_3", "host_namespaces": {},
               "deadline": time.monotonic() + 40}
    with pytest.raises(ValueError, match="tls_mediated_owner_deadline"):
        owner.MediatedOwner().read_request(io.BytesIO(json.dumps(request).encode() + b"\n"))
