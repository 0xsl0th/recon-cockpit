"""Finite SMB2 frames and independent no-followup owner evidence."""

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
from recon_cockpit.secure_agent import network_tools_smb2_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


class Connection:
    def __init__(self, raw=None, *, chunk_size=512, at_eof=None):
        self.input = io.BytesIO(fixture.SMB2_REQUEST if raw is None else raw)
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


@pytest.mark.parametrize("case", [case for case in fixture.SMB2_CASES if case != "smb2-stalled"])
@pytest.mark.parametrize("chunk_size", [1, 3, 512])
def test_fixed_request_and_write_eof_count_once_before_one_finite_reply(case, chunk_size, monkeypatch):
    connection, calls = Connection(chunk_size=chunk_size), []
    monkeypatch.setattr(server.time, "sleep", lambda _: None)
    def counted():
        assert not connection.output and connection.input.tell() == len(fixture.SMB2_REQUEST)
        calls.append(1)
    server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=counted)
    assert calls == [1] and bytes(connection.output) == fixture.smb2_response(case)
    assert len(connection.output) <= fixture.SMB2_MAX_RESPONSE_BYTES
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)
    if case == "smb2-fragmented":
        assert len(connection.writes) == 132 and all(len(chunk) == 1 for chunk in connection.writes)
    else:
        assert len(connection.writes) == 1


def test_stall_counts_validated_finite_request_before_waiting(monkeypatch):
    connection, calls, waits = Connection(), [], []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    server.serve(connection, case="smb2-stalled", deadline=time.monotonic() + 5,
        on_request=lambda: calls.append(1))
    assert calls == [1] and not connection.output and len(waits) == 1
    assert 0 < waits[0] <= 5


@pytest.mark.parametrize("position", range(108))
def test_every_changed_request_byte_is_rejected_without_count_or_reply(position):
    raw = bytearray(fixture.SMB2_REQUEST)
    raw[position] ^= 1
    connection, calls = Connection(bytes(raw)), []
    with pytest.raises(ValueError):
        server.serve(connection, case="smb2-21-optional", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("length", range(108))
def test_truncated_request_cannot_count_as_execution(length):
    connection, calls = Connection(fixture.SMB2_REQUEST[:length]), []
    with pytest.raises(ValueError):
        server.serve(connection, case="smb2-21-optional", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("extra", [b"\x00", fixture.SMB2_REQUEST, b"SESSION_SETUP", b"NTLMSSP\x00", b"username=password", b"TREE_CONNECT"])
def test_any_followup_bytes_prevent_reply_and_validated_request_count(extra):
    connection, calls = Connection(fixture.SMB2_REQUEST + extra), []
    with pytest.raises(ValueError, match="followup_forbidden"):
        server.serve(connection, case="smb2-21-optional", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("failure", [socket.timeout(), ConnectionResetError(), OSError("closed")])
def test_eof_is_required_and_not_inferred_from_timeout_or_reset(failure):
    connection, calls = Connection(at_eof=failure), []
    with pytest.raises(OSError):
        server.serve(connection, case="smb2-21-optional", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("size", [0, 3, 72, 103, 105, 8192, 65535])
def test_frame_size_is_checked_before_reading_payload(size):
    connection = Connection(b"\x00" + size.to_bytes(3, "big") + b"X" * 100)
    with pytest.raises(ValueError, match="frame_limit"):
        server.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 4


def test_fixture_shapes_cover_meaningful_selections_failures_and_pressure():
    raw = fixture.SMB2_REQUEST
    assert len(raw) == 108 and raw[:4] == b"\x00\x00\x00\x68"
    assert raw[4:8] == b"\xfeSMB" and struct.unpack_from("<H", raw, 16) == (0,)
    assert struct.unpack_from("<HHHHI", raw, 68) == (36, 2, 1, 0, 0)
    assert raw[80:96].hex() == "18764adc93774428a96643d43d6e6bd4"
    assert struct.unpack_from("<HH", raw, 104) == (0x0210, 0x0302)
    assert fixture.validate_smb2_request(raw) == raw
    for case, dialect, mode in (("smb2-21-optional",0x210,1), ("smb2-21-required",0x210,3),
            ("smb2-302-optional",0x302,1), ("smb2-302-required",0x302,3)):
        response = fixture.smb2_response(case)
        assert len(response) == 132 and int.from_bytes(response[1:4],"big") == 128
        assert struct.unpack_from("<I",response,12) == (0,)
        assert struct.unpack_from("<HHH",response,68) == (65,mode,dialect)
    refusal = fixture.smb2_response("smb2-not-supported")
    assert len(refusal) == 76 and struct.unpack_from("<I",refusal,12) == (0xc00000bb,)
    assert struct.unpack_from("<HBBI",refusal,68) == (9,0,0,0)
    opaque = fixture.smb2_response("smb2-opaque")
    assert opaque[132:] == fixture.HOSTILE_NOTE.encode("ascii")
    assert struct.unpack_from("<HH",opaque,124) == (128,len(opaque)-132)
    assert fixture.smb2_response("smb2-fragmented") == fixture.smb2_response("smb2-302-optional")
    assert len(fixture.smb2_response("smb2-truncated")) == 100
    assert fixture.smb2_response("smb2-stalled") is None
    assert fixture.smb2_response("smb2-oversized") == b"\x00\x00\x10\x01"


@pytest.mark.parametrize("case", fixture.SMB2_CASES)
def test_spec_pins_initial_wire_and_no_followup_counter_meaning(case):
    definition = contract.spec(case)
    response = fixture.smb2_response(case)
    assert definition["request_sha256"] == hashlib.sha256(fixture.SMB2_REQUEST).hexdigest()
    assert definition["response_sha256"] == (None if response is None else hashlib.sha256(response).hexdigest())
    assert definition["tool_id"] == fixture.SMB2_TOOL_ID
    assert definition["offered_dialects"] == [0x210, 0x302]
    assert definition["client_capabilities"] == 0
    assert definition["max_connections"] == definition["max_requests"] == definition["max_client_frames"] == 1
    assert definition["max_request_bytes"] == 108
    assert definition["max_response_bytes"] == 4100 and definition["max_security_buffer_bytes"] == 256
    assert definition["client_write_half_close_before_response"] is True
    assert definition["client_write_half_close_is_owned_profile_constraint"] is True
    assert definition["request_count_means"] == "validated_fixed_negotiate_requests_followed_by_client_write_eof_before_response"
    for name in ("udp", "retries", "followup", "session_setup", "ntlm_exchange", "credentials", "authentication",
        "share_access", "token_interpretation", "external_egress", "resume",
        "service_identity_claim", "vulnerability_claim", "signing_enforcement_verified"):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {"identity": identity, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, identity) == context
    for change in ({"connection_count": 2}, {"request_count": 2}, {"connection_count": 0}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize("case", ["smb2-21-optional", "smb2-malformed", "smb2-not-supported"])
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


def test_all_146_accepted_fixture_specs_remain_byte_identical():
    definitions = {case: contract.spec(case) for case in contract.CASES if case not in fixture.SMB2_CASES + fixture.SMTP_TLS_CASES + fixture.LDAP_TLS_CASES + fixture.FTP_TLS_CASES + fixture.DNS_NSID_CASES + fixture.DNS_AXFR_CASES + fixture.HTTP_OPTIONS_CASES + fixture.SNMP_NEXT_CASES + fixture.SSH_ALGORITHMS_CASES + fixture.TLS_CERTIFICATE_CASES + fixture.NUCLEI_CASES}
    assert len(definitions) == 146
    raw = json.dumps(definitions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == "7619299113f850d378d2e9590444ef5909e9c9788b3301ee4e511c8ad04801a8"


def test_owner_module_imports_without_package_under_isolated_python(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_smb2_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.SMB2_CASES) == 14
print('isolated SMB2 owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated SMB2 owner ready\n" and result.stderr == ""
