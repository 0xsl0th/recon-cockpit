"""Finite initial RDP frames and independent no-followup owner evidence."""

import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_rdp_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


class Connection:
    def __init__(self, raw=None, *, chunk_size=512, at_eof=None):
        self.input = io.BytesIO(fixture.RDP_REQUEST if raw is None else raw)
        self.output, self.timeouts, self.writes = bytearray(), [], []
        self.chunk_size, self.closed, self.at_eof = chunk_size, False, at_eof

    def recv(self, count):
        chunk = self.input.read(min(count, self.chunk_size))
        if not chunk and self.at_eof is not None:
            raise self.at_eof
        return chunk

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, raw):
        self.writes.append(raw)
        self.output.extend(raw)

    def close(self):
        self.closed = True


@pytest.mark.parametrize("case", [case for case in fixture.RDP_CASES if case != "rdp-stalled"])
@pytest.mark.parametrize("chunk_size", [1, 3, 512])
def test_fixed_request_and_write_eof_count_once_before_one_finite_reply(case, chunk_size, monkeypatch):
    connection, calls = Connection(chunk_size=chunk_size), []
    monkeypatch.setattr(server.time, "sleep", lambda _: None)
    def counted():
        assert not connection.output and connection.input.tell() == len(fixture.RDP_REQUEST)
        calls.append(1)
    server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=counted)
    assert calls == [1] and bytes(connection.output) == fixture.rdp_response(case)
    assert len(connection.output) <= fixture.RDP_MAX_RESPONSE_BYTES
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)
    if case == "rdp-fragmented":
        assert len(connection.writes) == 19 and all(len(chunk) == 1 for chunk in connection.writes)
    else:
        assert len(connection.writes) == 1


def test_stall_counts_validated_finite_request_before_waiting(monkeypatch):
    connection, calls, waits = Connection(), [], []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    server.serve(connection, case="rdp-stalled", deadline=time.monotonic() + 5,
        on_request=lambda: calls.append(1))
    assert calls == [1] and not connection.output and len(waits) == 1
    assert 0 < waits[0] <= 5


@pytest.mark.parametrize("position", range(19))
def test_every_changed_request_byte_is_rejected_without_count_or_reply(position):
    raw = bytearray(fixture.RDP_REQUEST)
    raw[position] ^= 1
    connection, calls = Connection(bytes(raw)), []
    with pytest.raises(ValueError):
        server.serve(connection, case="rdp-tls", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("length", range(19))
def test_truncated_request_cannot_count_as_execution(length):
    connection, calls = Connection(fixture.RDP_REQUEST[:length]), []
    with pytest.raises(ValueError):
        server.serve(connection, case="rdp-tls", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("extra", [b"\x00", fixture.RDP_REQUEST, b"\x16\x03\x03", b"Cookie: mstshash=user\r\n",
    b"username=password", b"MCS", b"CredSSP", b"\x03\x00\x00\x08"])
def test_any_followup_bytes_prevent_reply_and_validated_request_count(extra):
    connection, calls = Connection(fixture.RDP_REQUEST + extra), []
    with pytest.raises(ValueError, match="followup_forbidden"):
        server.serve(connection, case="rdp-tls", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("failure", [socket.timeout(), ConnectionResetError(), OSError("closed")])
def test_eof_is_required_and_not_inferred_from_timeout_or_reset(failure):
    connection, calls = Connection(at_eof=failure), []
    with pytest.raises(OSError):
        server.serve(connection, case="rdp-tls", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("size", [0, 3, 11, 18, 20, 8192, 65535])
def test_frame_size_is_checked_before_reading_payload(size):
    connection = Connection(b"\x03\x00" + struct.pack("!H", size) + b"X" * 100)
    with pytest.raises(ValueError, match="frame_limit"):
        server.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 4


def test_fixture_shapes_cover_meaningful_selections_failures_and_pressure():
    assert fixture.RDP_REQUEST.hex() == "030000130ee000000000000100080001000000"
    assert fixture.validate_rdp_request(fixture.RDP_REQUEST) == fixture.RDP_REQUEST
    assert fixture.rdp_response("rdp-tls").hex() == "030000130ed000000000000200080001000000"
    assert fixture.rdp_response("rdp-standard")[-4:] == b"\x00" * 4
    assert fixture.rdp_response("rdp-legacy").hex() == "0300000b06d00000000000"
    assert fixture.rdp_response("rdp-nla-required")[11:] == struct.pack("<BBHI", 3, 0, 8, 5)
    assert fixture.rdp_response("rdp-entra-required")[11:] == struct.pack("<BBHI", 3, 0, 8, 7)
    assert fixture.rdp_response("rdp-unoffered")[-4:] == struct.pack("<I", 2)
    assert fixture.rdp_response("rdp-unknown-failure")[-4:] == struct.pack("<I", 8)
    assert len(fixture.rdp_response("rdp-truncated")) == 10
    assert fixture.rdp_response("rdp-stalled") is None
    oversized = fixture.rdp_response("rdp-oversized")
    assert int.from_bytes(oversized[2:4], "big") == len(oversized) == 20
    trailing = fixture.rdp_response("rdp-trailing")
    assert trailing[:19] == fixture.rdp_response("rdp-tls")
    assert trailing[19:] == fixture.HOSTILE_NOTE.encode("ascii")


@pytest.mark.parametrize("case", fixture.RDP_CASES)
def test_spec_pins_initial_wire_and_no_followup_counter_meaning(case):
    definition = contract.spec(case)
    response = fixture.rdp_response(case)
    assert definition["request_sha256"] == hashlib.sha256(fixture.RDP_REQUEST).hexdigest()
    assert definition["response_sha256"] == (None if response is None else hashlib.sha256(response).hexdigest())
    assert definition["tool_id"] == fixture.RDP_TOOL_ID
    assert definition["requested_protocols"] == ["tls"]
    assert definition["max_connections"] == definition["max_requests"] == definition["max_client_frames"] == 1
    assert definition["max_request_bytes"] == definition["max_frame_bytes"] == 19
    assert definition["client_write_half_close_before_response"] is True
    assert definition["client_write_half_close_is_owned_profile_constraint"] is True
    assert definition["request_count_means"] == "validated_fixed_initial_requests_followed_by_client_write_eof_before_response"
    for name in ("udp", "retries", "followup", "tls_handshake", "credssp", "credentials", "authentication",
        "mcs", "remote_session", "clipboard", "channels", "external_egress", "resume",
        "service_identity_claim", "vulnerability_claim", "trailing_bytes_inspected"):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {"identity": identity, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, identity) == context
    for change in ({"connection_count": 2}, {"request_count": 2}, {"connection_count": 0}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize("case", ["rdp-tls", "rdp-malformed", "rdp-nla-required"])
def test_owner_rejects_second_connection_without_reading_or_counting(case):
    peers = [Connection(), Connection()]
    pending = iter(peers)
    service = owner.NetworkToolsService.__new__(owner.NetworkToolsService)
    service.case, service.rpc, service.context = case, None, None
    service.connections = service.requests = 0
    service.failed = False
    service.condition = threading.Condition()
    service.deadline = time.monotonic() + 5
    service.listener = SimpleNamespace(accept=lambda: (next(pending), None))
    service._serve()
    assert service.connections == service.requests == 1 and service.failed
    assert all(peer.closed for peer in peers)
    assert peers[1].input.tell() == 0 and not peers[1].output


def test_all_133_accepted_fixture_specs_remain_byte_identical():
    definitions = {case: contract.spec(case) for case in contract.CASES if case not in fixture.RDP_CASES + fixture.SMB2_CASES + fixture.SMTP_TLS_CASES}
    assert len(definitions) == 133
    raw = json.dumps(definitions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == "704cd750a3d1c3ed73a5839f5ff20fabe0cd88009bb5a49381564a2ecfbe6f07"


def test_owner_module_imports_without_package_under_isolated_python(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_rdp_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.RDP_CASES) == 13
print('isolated RDP owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated RDP owner ready\n" and result.stderr == ""
