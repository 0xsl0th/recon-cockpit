"""Fixed AXFR wire bytes, owner bounds and accepted fixture compatibility."""

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
from recon_cockpit.secure_agent import network_tools_dns_axfr_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


def frame(query):
    return struct.pack("!H", len(query)) + query


class Connection:
    def __init__(self, raw=None, *, chunk_size=512):
        self.input = io.BytesIO(frame(fixture.dns_axfr_query(b"\x12\x34")) if raw is None else raw)
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


@pytest.mark.parametrize("case", [case for case in fixture.DNS_AXFR_CASES if case != "dig-axfr-stalled"])
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_exact_question_counts_once_before_finite_response_bytes(case, chunk_size, monkeypatch):
    connection, calls = Connection(chunk_size=chunk_size), []
    monkeypatch.setattr(server.time, "sleep", lambda _: None)
    def send(raw):
        assert calls == [1]  # Counter witnesses request validation, not transfer success.
        connection.output.extend(raw)
    connection.sendall = send
    server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    query = fixture.dns_axfr_query(b"\x12\x34")
    assert bytes(connection.output) == fixture.dns_axfr_wire(case, query)
    responses = fixture.dns_axfr_responses(case, query)
    assert all(response[:2] == b"\x12\x34" and len(response) <= 4096 for response in responses)
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)


def test_stall_counts_the_real_question_before_waiting_for_remaining_deadline(monkeypatch):
    connection, calls, waits = Connection(), [], []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    server.serve(connection, case="dig-axfr-stalled", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and not connection.output
    assert len(waits) == 1 and 0 < waits[0] <= 5


@pytest.mark.parametrize("case", fixture.DNS_AXFR_CASES)
def test_every_nontransaction_query_byte_is_fixed_and_mutations_never_count(case):
    query = fixture.dns_axfr_query()
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
    lambda query: query[:12] + b"\xc0\x0c\x00\xfc\x00\x01",
    lambda query: query[:-4] + b"\x00\x01\x00\x01",  # A query.
    lambda query: query[:-4] + b"\x00\xfb\x00\x01",  # IXFR query.
    lambda query: query[:-4] + b"\x00\xfc\x00\x03",  # CH class.
    lambda query: fixture.dns_nsid_query(query[:2]),
])
def test_additional_payload_edns_or_different_question_is_rejected(change):
    connection, calls = Connection(frame(change(fixture.dns_axfr_query()))), []
    with pytest.raises(ValueError):
        server.serve(connection, case="dig-axfr-ok", deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("size", [0, 1, 11, 513, 65535])
def test_framing_limits_are_checked_before_reading_payload(size):
    connection = Connection(struct.pack("!H", size) + b"X" * 1024)
    with pytest.raises(ValueError, match="frame_limit"):
        server.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 2


def test_every_truncated_frame_fails_without_counting_work():
    raw = frame(fixture.dns_axfr_query())
    for length in range(len(raw)):
        connection, calls = Connection(raw[:length]), []
        with pytest.raises(ValueError):
            server.serve(connection, case="dig-axfr-ok", deadline=time.monotonic() + 5,
                         on_request=lambda: calls.append(1))
        assert not calls and not connection.output


def test_one_question_per_connection_serves_no_pipelined_work():
    query = fixture.dns_axfr_query()
    connection, calls = Connection(frame(query) * 2), []
    server.serve(connection, case="dig-axfr-ok", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == frame(query)
    assert bytes(connection.output) == fixture.dns_axfr_wire("dig-axfr-ok", query)


def test_deadline_is_rechecked_on_every_fragment(monkeypatch):
    connection = Connection(chunk_size=1)
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        server.read_request(connection, 1)


@pytest.mark.parametrize("case", [None, 1, b"dig-axfr-ok", "dig-ok", "dig-axfr-unknown"])
def test_invalid_case_never_reads_a_question(case):
    connection = Connection()
    with pytest.raises(ValueError):
        server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: pytest.fail("counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        fixture.dns_axfr_responses(case, fixture.dns_axfr_query())


@pytest.mark.parametrize("transaction_id", [None, 1, "ab", b"", b"a", b"abc"])
def test_transaction_id_shape_is_exact(transaction_id):
    with pytest.raises(ValueError):
        fixture.dns_axfr_query(transaction_id)


def test_query_has_exact_axfr_question_without_edns_or_flags():
    query = fixture.dns_axfr_query(b"\x12\x34")
    assert len(query) == 33 and len(frame(query)) == 35
    assert struct.unpack("!HHHHHH", query[:12]) == (0x1234, 0, 1, 0, 0, 0)
    assert query[12:] == b"\x0aharbordesk\x04test\x00\x00\xfc\x00\x01"
    assert fixture.validate_dns_axfr_query(query) == query


def read_name(raw, offset):
    labels = []
    while raw[offset]:
        size = raw[offset]
        assert 1 <= size <= 63  # Public synthetic fixtures do not use compression.
        labels.append(raw[offset + 1:offset + 1 + size].decode("ascii"))
        offset += 1 + size
    return ".".join(labels) + ".", offset + 1


def records(message):
    _, flags, questions, count, authority, additional = struct.unpack("!HHHHHH", message[:12])
    assert flags >> 15 == 1 and authority == additional == 0 and questions in (0, 1)
    offset = 12
    if questions:
        name, offset = read_name(message, offset)
        qtype, qclass = struct.unpack("!HH", message[offset:offset + 4])
        assert name == "harbordesk.test." and qclass == 1 and qtype in (1, 252)
        offset += 4
    result = []
    for _ in range(count):
        name, offset = read_name(message, offset)
        kind, cls, ttl, size = struct.unpack("!HHIH", message[offset:offset + 10])
        offset += 10
        data = message[offset:offset + size]
        assert cls == 1 and ttl == 60 and len(data) == size
        assert name == "harbordesk.test." or name.endswith(".harbordesk.test.")
        result.append((name, kind, ttl, data))
        offset += size
    assert offset == len(message)
    return result


@pytest.mark.parametrize("case", fixture.DNS_AXFR_CASES)
def test_finite_synthetic_messages_exercise_exact_transfer_boundaries(case):
    query = fixture.dns_axfr_query()
    messages = fixture.dns_axfr_responses(case, query)
    if case == "dig-axfr-stalled":
        assert messages is None and fixture.dns_axfr_wire(case, query) is None
        return
    rows = [record for message in messages for record in records(message)]
    assert len(messages) <= 5 and max(map(len, messages)) <= 4096
    assert len(fixture.dns_axfr_wire(case, query)) <= 16384
    if case == "dig-axfr-refused":
        assert len(messages) == 1 and not rows
        assert struct.unpack("!H", messages[0][2:4])[0] == 0x8405
        return
    assert rows[0][1] == 6
    if case == "dig-axfr-missing-soa":
        assert len(rows) == 4 and rows[-1][1] == 16
    elif case == "dig-axfr-midstream-error":
        assert len(messages) == 2 and len(rows) == 2
        assert struct.unpack("!HHHHH", messages[1][2:12]) == (0x8402, 0, 0, 0, 0)
    else:
        assert rows[-1][1] == 6
        assert (rows[0] == rows[-1]) is (case != "dig-axfr-mismatched-soa")
    if case == "dig-axfr-multiframe":
        assert list(map(lambda m: len(records(m)), messages)) == [2, 2, 1]
        assert [struct.unpack("!H", m[4:6])[0] for m in messages] == [1, 0, 0]
    elif case == "dig-axfr-frame-limit":
        assert len(messages) == 5 and len(rows) == 5
    elif case == "dig-axfr-record-limit":
        assert len(messages) == 1 and len(rows) == 17
    elif case == "dig-axfr-wrong-question":
        assert messages[0][12:33] == fixture.DNS_QUESTION
    elif case == "dig-axfr-truncated":
        assert fixture.dns_axfr_wire(case, query) == frame(messages[0])[:-1]
    elif case == "dig-axfr-output-limit":
        assert len(rows) == 3 and rows[1][1] == 16
        assert rows[1][3] == (bytes([255]) + b"\x01" * 255) * 12
        assert len(rows[1][3]) * 4 > 8192  # Native decimal escape expansion.
    elif case == "dig-axfr-injected":
        assert rows[3][3] == bytes([len(fixture.HOSTILE_NOTE)]) + fixture.HOSTILE_NOTE.encode("ascii")
    elif case in ("dig-axfr-ok", "dig-axfr-fragmented"):
        assert [row[1] for row in rows] == [6, 2, 1, 16, 6]
    name, offset = read_name(rows[0][3], 0)
    mailbox, offset = read_name(rows[0][3], offset)
    assert (name, mailbox, *struct.unpack("!IIIII", rows[0][3][offset:])) == fixture.DNS_AXFR_SOA


@pytest.mark.parametrize("case", fixture.DNS_AXFR_CASES)
def test_spec_pins_fixed_question_finite_wire_and_acceptance_limits(case):
    definition = contract.spec(case)
    query = fixture.dns_axfr_query()
    messages, wire = fixture.dns_axfr_responses(case, query), fixture.dns_axfr_wire(case, query)
    assert definition["query"] == {"name": fixture.DNS_AXFR_QUERY_NAME, "type": "AXFR", "class": "IN",
        "recursion": False, "ad": False, "cd": False, "edns": False}
    assert definition["query_bytes"] == 33
    assert definition["request_count_means"] == "validated_fixed_axfr_questions"
    assert definition["query_sha256"] == hashlib.sha256(query).hexdigest()
    assert definition["response_sha256"] == (None if messages is None else [hashlib.sha256(m).hexdigest() for m in messages])
    assert definition["response_wire_sha256"] == (None if wire is None else hashlib.sha256(wire).hexdigest())
    assert definition["response_wire_bytes"] == (0 if wire is None else len(wire))
    assert definition["tool_id"] == fixture.DNS_AXFR_TOOL_ID
    assert definition["max_connections"] == definition["max_requests"] == 1
    assert (definition["max_messages"], definition["max_records"]) == (4, 16)
    assert definition["message_record_limits"] == "parser_and_fixture_acceptance_only"
    for name in ("udp", "recursion", "retries", "search_suffixes", "target_resolution", "target_connections",
                 "credentials", "external_egress", "resume", "service_identity_verified", "native_wire_ingress_cap",
                 "ixfr", "notify", "update", "tsig", "edns", "cookies", "edns_negotiation", "best_effort", "vulnerability_claim"):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {"identity": identity, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, identity) == context
    for change in ({"connection_count": 2}, {"request_count": 2}, {"connection_count": 0}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize("case", ["dig-axfr-ok", "dig-axfr-truncated", "dig-axfr-refused"])
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


def test_all_209_accepted_fixture_specs_are_unchanged():
    definitions = {case: contract.spec(case) for case in contract.CASES if case not in fixture.DNS_AXFR_CASES + fixture.DNS_AXFR_CASES}
    assert len(definitions) == 209
    raw = json.dumps(definitions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == "ec7d1e0198a5383aa0137a72c8a28c215a1d50b6276dcd81cd3da53e974bcf8e"


def test_owner_module_imports_under_isolated_python_without_package(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_axfr_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.DNS_AXFR_CASES) == 14
print('isolated AXFR owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated AXFR owner ready\n" and result.stderr == ""
