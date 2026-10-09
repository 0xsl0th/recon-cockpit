"""Fixed SRV wire bytes, owner bounds and accepted fixture compatibility."""

import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_dns_srv_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


def frame(query):
    return struct.pack("!H", len(query)) + query


class Connection:
    def __init__(self, raw=None, *, chunk_size=512):
        self.input = io.BytesIO(frame(fixture.dns_srv_query(b"\x12\x34")) if raw is None else raw)
        self.output, self.timeouts = bytearray(), []
        self.chunk_size, self.closed = chunk_size, False

    def recv(self, count):
        return self.input.read(min(count, self.chunk_size))

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, raw):
        self.output.extend(raw)

    def close(self):
        self.closed = True


@pytest.mark.parametrize("case", [case for case in fixture.DNS_SRV_CASES if case != "dig-srv-stalled"])
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_exact_question_counts_once_and_emits_one_framed_response(case, chunk_size):
    connection, calls = Connection(chunk_size=chunk_size), []
    server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    response = fixture.dns_srv_response(case, fixture.dns_srv_query(b"\x12\x34"))
    assert bytes(connection.output) == frame(response)
    assert response[:2] == b"\x12\x34" and len(response) <= 4096
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)


def test_stall_counts_the_real_question_before_waiting_for_remaining_deadline(monkeypatch):
    connection, calls, waits = Connection(), [], []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    server.serve(connection, case="dig-srv-stalled", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and not connection.output
    assert len(waits) == 1 and 0 < waits[0] <= 5


@pytest.mark.parametrize("mutate", [
    lambda query: query[:2] + b"\x01\x00" + query[4:],  # RD
    lambda query: query[:2] + b"\x80\x00" + query[4:],  # QR
    lambda query: query[:2] + b"\x28\x00" + query[4:],  # UPDATE opcode
    lambda query: query[:4] + b"\x00\x02" + query[6:],
    lambda query: query[:10] + b"\x00\x01" + query[12:],  # EDNS/additional
    lambda query: query.replace(b"_ldap", b"_http"),
    lambda query: query.replace(b"_tcp", b"_udp"),
    lambda query: query.replace(b"harbordesk", b"other-zone"),
    lambda query: query[:-4] + b"\x00\x01\x00\x01",  # A
    lambda query: query[:-4] + b"\x00\xfc\x00\x01",  # AXFR
    lambda query: query[:-2] + b"\x00\x03",  # CH
    lambda query: query + b"payload",
    lambda query: query + query,
    lambda query: query[:12] + b"\xc0\x0c\x00\x21\x00\x01",  # cyclic compression
])
def test_question_changes_never_count_or_receive_a_reply(mutate):
    connection, calls = Connection(frame(mutate(fixture.dns_srv_query()))), []
    with pytest.raises(ValueError):
        server.serve(connection, case="dig-srv-ok", deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("size", [0, 1, 11, 513, 65535])
def test_framing_limits_are_checked_before_reading_payload(size):
    connection = Connection(struct.pack("!H", size) + b"X" * 1024)
    with pytest.raises(ValueError, match="frame_limit"):
        server.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 2


def test_every_truncated_frame_fails_without_counting_work():
    raw = frame(fixture.dns_srv_query())
    for length in range(len(raw)):
        connection, calls = Connection(raw[:length]), []
        with pytest.raises(ValueError):
            server.serve(connection, case="dig-srv-ok", deadline=time.monotonic() + 5,
                         on_request=lambda: calls.append(1))
        assert not calls and not connection.output


def test_one_question_per_connection_serves_no_pipelined_work():
    query = fixture.dns_srv_query()
    connection, calls = Connection(frame(query) * 2), []
    server.serve(connection, case="dig-srv-ok", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == frame(query)
    assert bytes(connection.output) == frame(fixture.dns_srv_response("dig-srv-ok", query))


def test_deadline_is_rechecked_on_every_fragment(monkeypatch):
    connection = Connection(chunk_size=1)
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        server.read_request(connection, 1)


@pytest.mark.parametrize("case", [None, 1, b"dig-srv-ok", "dig-ok", "dig-srv-unknown"])
def test_invalid_case_never_reads_a_question(case):
    connection = Connection()
    with pytest.raises(ValueError):
        server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: pytest.fail("counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        fixture.dns_srv_response(case, fixture.dns_srv_query())


@pytest.mark.parametrize("transaction_id", [None, 1, "ab", b"", b"a", b"abc"])
def test_transaction_id_shape_is_exact(transaction_id):
    with pytest.raises(ValueError):
        fixture.dns_srv_query(transaction_id)


def test_wire_distinguishes_records_nodata_nxdomain_unavailable_and_refusal():
    query = fixture.dns_srv_query()
    for suffix, rcode, count in (("ok", 0, 2), ("nodata", 0, 0), ("nxdomain", 3, 0),
                                 ("unavailable", 0, 1), ("refused", 5, 0)):
        response = fixture.dns_srv_response("dig-srv-" + suffix, query)
        header = struct.unpack("!HHHHHH", response[:12])
        assert header == (0, 0x8400 | rcode, 1, count, 0, 0)
        assert response[12:12 + len(fixture.DNS_SRV_QUESTION)] == fixture.DNS_SRV_QUESTION
    unavailable = fixture.dns_srv_response("dig-srv-unavailable", query)
    assert unavailable[-7:] == b"\x00" * 7
    assert fixture.dns_srv_records("dig-srv-unavailable") == ((0, 0, 0, ".", 60),)
    assert fixture.dns_srv_response("dig-srv-stalled", query) is None


def test_hostile_text_foreign_target_and_output_pressure_are_finite_data():
    query = fixture.dns_srv_query()
    injected = fixture.dns_srv_response("dig-srv-injected", query)
    assert fixture.HOSTILE_NOTE.encode() in injected
    assert b"\x07outside\x07invalid\x00" in injected
    assert fixture.DNS_SRV_FOREIGN_RECORD in fixture.dns_srv_records("dig-srv-injected")
    assert len(fixture.dns_srv_records("dig-srv-record-limit")) == fixture.DNS_SRV_MAX_RECORDS + 1
    pressure = fixture.dns_srv_response("dig-srv-output-limit", query)
    assert len(pressure) <= 4096 and pressure.count(b"\x01") > 3000
    assert pressure.count(b"\x01") * len("\\001") > 8192


@pytest.mark.parametrize("case", fixture.DNS_SRV_CASES)
def test_spec_pins_fixed_question_reply_and_no_followups(case):
    definition = contract.spec(case)
    response = fixture.dns_srv_response(case, fixture.dns_srv_query())
    assert definition["query"] == {"name": fixture.DNS_SRV_QUERY_NAME, "type": "SRV", "class": "IN", "recursion": False}
    assert definition["query_sha256"] == hashlib.sha256(fixture.dns_srv_query()).hexdigest()
    assert definition["response_sha256"] == (None if response is None else hashlib.sha256(response).hexdigest())
    assert definition["tool_id"] == fixture.DNS_SRV_TOOL_ID
    assert definition["max_connections"] == definition["max_requests"] == 1
    assert definition["max_records"] == 4
    for name in ("udp", "recursion", "retries", "search_suffixes", "target_resolution", "target_connections",
                 "credentials", "external_egress", "resume", "service_identity_claim", "vulnerability_claim"):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {"identity": identity, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, identity) == context
    for change in ({"connection_count": 2}, {"request_count": 2}, {"connection_count": 0}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize("case", ["dig-srv-ok", "dig-srv-malformed", "dig-srv-refused"])
def test_owner_closes_second_connection_without_reading_or_counting_it(case):
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


def test_all_123_accepted_fixture_specs_are_unchanged():
    definitions = {case: contract.spec(case) for case in contract.CASES if case not in fixture.DNS_SRV_CASES + fixture.RDP_CASES + fixture.SMB2_CASES + fixture.SMTP_TLS_CASES + fixture.LDAP_TLS_CASES + fixture.FTP_TLS_CASES + fixture.DNS_NSID_CASES + fixture.DNS_AXFR_CASES + fixture.HTTP_OPTIONS_CASES + fixture.SNMP_NEXT_CASES + fixture.SSH_ALGORITHMS_CASES + fixture.TLS_CERTIFICATE_CASES + fixture.NUCLEI_CASES + fixture.NUCLEI_GIT_CASES + fixture.DNS_MX_CASES + fixture.TLS_POSTURE_CASES}
    assert len(definitions) == 123
    raw = json.dumps(definitions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == "e89590d7620e1856c5dd8bcb1c18d2f06266164e5a1401671668006ebcfdbdf3"


def test_owner_module_imports_under_isolated_python_without_package(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_srv_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.DNS_SRV_CASES) == 10
print('isolated SRV owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated SRV owner ready\n" and result.stderr == ""
