"""Fixed NSID wire bytes, owner bounds and accepted fixture compatibility."""

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
from recon_cockpit.secure_agent import network_tools_dns_nsid_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


def frame(query):
    return struct.pack("!H", len(query)) + query


class Connection:
    def __init__(self, raw=None, *, chunk_size=512):
        self.input = io.BytesIO(frame(fixture.dns_nsid_query(b"\x12\x34")) if raw is None else raw)
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


@pytest.mark.parametrize("case", [case for case in fixture.DNS_NSID_CASES if case != "dig-nsid-stalled"])
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_exact_question_counts_once_and_emits_one_framed_response(case, chunk_size):
    connection, calls = Connection(chunk_size=chunk_size), []
    server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    response = fixture.dns_nsid_response(case, fixture.dns_nsid_query(b"\x12\x34"))
    assert bytes(connection.output) == frame(response)
    assert response[:2] == b"\x12\x34" and len(response) <= 4096
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)


def test_stall_counts_the_real_question_before_waiting_for_remaining_deadline(monkeypatch):
    connection, calls, waits = Connection(), [], []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    server.serve(connection, case="dig-nsid-stalled", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and not connection.output
    assert len(waits) == 1 and 0 < waits[0] <= 5


@pytest.mark.parametrize("case", fixture.DNS_NSID_CASES)
def test_every_nontransaction_query_byte_is_fixed_and_mutations_never_count(case):
    query = fixture.dns_nsid_query()
    for offset in range(2, len(query)):
        changed = query[:offset] + bytes([query[offset] ^ 1]) + query[offset + 1:]
        connection, calls = Connection(frame(changed)), []
        with pytest.raises(ValueError):
            server.serve(connection, case=case, deadline=time.monotonic() + 5,
                         on_request=lambda: calls.append(1))
        assert not calls and not connection.output


@pytest.mark.parametrize("change", [
    lambda query: query + b"payload",
    lambda query: query + query,
    lambda query: query[:12] + b"\xc0\x0c\x00\x01\x00\x01" + query[33:],
    lambda query: query[:33],
    lambda query: query[:-4] + b"\x00\x0a\x00\x00",  # COOKIE option instead of NSID.
    lambda query: query[:-4] + b"\x00\x03\x00\x01X",  # Nonempty request option.
])
def test_additional_payload_cookie_or_compressed_question_is_rejected(change):
    connection, calls = Connection(frame(change(fixture.dns_nsid_query()))), []
    with pytest.raises(ValueError):
        server.serve(connection, case="dig-nsid-ok", deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("size", [0, 1, 11, 513, 65535])
def test_framing_limits_are_checked_before_reading_payload(size):
    connection = Connection(struct.pack("!H", size) + b"X" * 1024)
    with pytest.raises(ValueError, match="frame_limit"):
        server.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 2


def test_every_truncated_frame_fails_without_counting_work():
    raw = frame(fixture.dns_nsid_query())
    for length in range(len(raw)):
        connection, calls = Connection(raw[:length]), []
        with pytest.raises(ValueError):
            server.serve(connection, case="dig-nsid-ok", deadline=time.monotonic() + 5,
                         on_request=lambda: calls.append(1))
        assert not calls and not connection.output


def test_one_question_per_connection_serves_no_pipelined_work():
    query = fixture.dns_nsid_query()
    connection, calls = Connection(frame(query) * 2), []
    server.serve(connection, case="dig-nsid-ok", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == frame(query)
    assert bytes(connection.output) == frame(fixture.dns_nsid_response("dig-nsid-ok", query))


def test_deadline_is_rechecked_on_every_fragment(monkeypatch):
    connection = Connection(chunk_size=1)
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        server.read_request(connection, 1)


@pytest.mark.parametrize("case", [None, 1, b"dig-nsid-ok", "dig-ok", "dig-nsid-unknown"])
def test_invalid_case_never_reads_a_question(case):
    connection = Connection()
    with pytest.raises(ValueError):
        server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: pytest.fail("counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        fixture.dns_nsid_response(case, fixture.dns_nsid_query())


@pytest.mark.parametrize("transaction_id", [None, 1, "ab", b"", b"a", b"abc"])
def test_transaction_id_shape_is_exact(transaction_id):
    with pytest.raises(ValueError):
        fixture.dns_nsid_query(transaction_id)


def test_query_has_exact_empty_nsid_edns0_no_flags_and_tcp_body_length():
    query = fixture.dns_nsid_query(b"\x12\x34")
    assert len(query) == 48 and len(frame(query)) == 50
    assert struct.unpack("!HHHHHH", query[:12]) == (0x1234, 0, 1, 0, 0, 1)
    assert query[12:33] == b"\x0aharbordesk\x04test\x00\x00\x01\x00\x01"
    assert query[33:] == b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 4) + struct.pack("!HH", 3, 0)
    assert fixture.validate_dns_nsid_query(query) == query


@pytest.mark.parametrize("case", fixture.DNS_NSID_CASES)
def test_wire_distinguishes_absent_empty_noedns_and_negative_options(case):
    query = fixture.dns_nsid_query()
    response = fixture.dns_nsid_response(case, query)
    if case == "dig-nsid-stalled":
        assert response is None
        return
    rcode = 5 if case == "dig-nsid-refused" else 0
    assert struct.unpack("!HHHHHH", response[:12]) == (0, 0x8400 | rcode, 1, 0, 0, int(case != "dig-nsid-noedns"))
    assert response[12:33] == fixture.DNS_NSID_QUESTION
    if case == "dig-nsid-noedns":
        assert response[33:] == b""
        return
    assert response[33] == 0
    rr_type, udp_size, ttl, rdlength = struct.unpack("!HHIH", response[34:44])
    assert (rr_type, udp_size, ttl) == (41, 1232, (1 << 24) if case == "dig-nsid-badvers" else 0)
    assert rdlength == len(response[44:])
    if case in ("dig-nsid-absent", "dig-nsid-refused", "dig-nsid-badvers"):
        assert rdlength == 0
    elif case == "dig-nsid-empty":
        assert response[44:] == struct.pack("!HH", 3, 0)
    elif case == "dig-nsid-binary":
        assert response[44:] == struct.pack("!HH", 3, 5) + fixture.DNS_NSID_BINARY
    elif case == "dig-nsid-injected":
        assert response[48:] == fixture.HOSTILE_NOTE.encode("ascii")
        assert len(response[48:]) <= fixture.DNS_NSID_MAX_NSID_BYTES
    elif case == "dig-nsid-malformed":
        assert response[44:] == struct.pack("!HH", 3, 5) + b"X"
    elif case == "dig-nsid-duplicate":
        option = struct.pack("!HH", 3, len(fixture.DNS_NSID_VALUE)) + fixture.DNS_NSID_VALUE
        assert response[44:] == option * 2
    elif case == "dig-nsid-oversize":
        assert response[44:] == struct.pack("!HH", 3, 65) + b"X" * 65
    elif case == "dig-nsid-output-limit":
        assert response[44:] == struct.pack("!HH", 3, 3000) + b"\x01" * 3000
        assert len(response) <= 4096 and 3 * len(response[48:]) > 8192
    elif case == "dig-nsid-unexpected-option":
        assert response.endswith(struct.pack("!HH", 65001, 4) + b"nope")
    else:
        assert response[44:] == struct.pack("!HH", 3, len(fixture.DNS_NSID_VALUE)) + fixture.DNS_NSID_VALUE


@pytest.mark.parametrize("case", fixture.DNS_NSID_CASES)
def test_spec_pins_fixed_question_reply_and_no_followups(case):
    definition = contract.spec(case)
    response = fixture.dns_nsid_response(case, fixture.dns_nsid_query())
    assert definition["query"] == {"name": fixture.DNS_NSID_QUERY_NAME, "type": "A", "class": "IN",
        "recursion": False, "ad": False, "cd": False, "edns_version": 0,
        "udp_payload_size": 1232, "options": [{"code": 3, "bytes": 0}]}
    assert definition["query_bytes"] == 48
    assert definition["request_count_means"] == "validated_fixed_nsid_questions"
    assert definition["query_sha256"] == hashlib.sha256(fixture.dns_nsid_query()).hexdigest()
    assert definition["response_sha256"] == (None if response is None else hashlib.sha256(response).hexdigest())
    assert definition["tool_id"] == fixture.DNS_NSID_TOOL_ID
    assert definition["max_connections"] == definition["max_requests"] == 1
    assert definition["max_nsid_bytes"] == 64
    for name in ("udp", "recursion", "retries", "search_suffixes", "target_resolution", "target_connections",
                 "credentials", "external_egress", "resume", "service_identity_claim", "service_identity_verified",
                 "zone_transfer", "cookies", "edns_negotiation", "best_effort", "vulnerability_claim"):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {"identity": identity, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, identity) == context
    for change in ({"connection_count": 2}, {"request_count": 2}, {"connection_count": 0}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize("case", ["dig-nsid-ok", "dig-nsid-malformed", "dig-nsid-refused"])
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


def test_all_195_accepted_fixture_specs_are_unchanged():
    definitions = {case: contract.spec(case) for case in contract.CASES if case not in fixture.DNS_NSID_CASES + fixture.DNS_AXFR_CASES + fixture.HTTP_OPTIONS_CASES}
    assert len(definitions) == 195
    raw = json.dumps(definitions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == "0486810cecbc8da827470d330219f1159e6169daab796ee40dc2bec20133fa70"


def test_owner_module_imports_under_isolated_python_without_package(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_nsid_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.DNS_NSID_CASES) == 14
print('isolated NSID owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated NSID owner ready\n" and result.stderr == ""
