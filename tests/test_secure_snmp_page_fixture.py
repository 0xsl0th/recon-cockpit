"""A GETBULK page cannot acquire another seed, request, community or operation."""

import io
from pathlib import Path
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_snmp_page_spec as spec
from recon_cockpit.secure_agent import network_tools_snmp_page_fixture as fixture
from recon_cockpit.secure_agent import network_tools_snmp_next_fixture as predecessor
from recon_cockpit.secure_agent import network_tools_redis_snmp_fixture as accepted


SEED = bytes.fromhex("2b0601020102020102")
COMMUNITY = b"recon-fixture-public"


def ber(tag, raw):
    size = len(raw)
    length = bytes([size]) if size < 128 else bytes([0x81, size]) if size < 256 else b"\x82" + size.to_bytes(2, "big")
    return bytes([tag]) + length + raw


def query(*, request_id=b"\x12\x34", community=COMMUNITY, version=b"\x01", pdu=0xa5,
          non_repeaters=b"\0", repetitions=b"\x04", oids=(SEED,), value=(5, b""), extra=b""):
    bindings = b"".join(ber(0x30, ber(6, oid) + ber(*value)) for oid in oids)
    operation = ber(pdu, ber(2, request_id) + ber(2, non_repeaters) + ber(2, repetitions)
        + ber(0x30, bindings) + extra)
    return ber(0x30, ber(2, version) + ber(4, community) + operation)


class Connection:
    def __init__(self, raw=None, *, chunk_size=3):
        self.input = io.BytesIO(query() if raw is None else raw)
        self.output, self.timeouts, self.writes = bytearray(), [], []
        self.chunk_size = chunk_size

    def recv(self, count):
        return self.input.read(min(count, self.chunk_size))

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, raw):
        self.writes.append(raw)
        self.output.extend(raw)


@pytest.mark.parametrize("request_id", [b"\0", b"\x01", b"\x7f", b"\0\x80", b"\x12\x34", b"\x7f\xff\xff\xff"])
def test_compiled_request_is_one_getbulk_with_zero_nonrepeaters_and_four_repetitions(request_id):
    assert fixture.request(request_id) == query(request_id=request_id)
    assert fixture.parse_request(query(request_id=request_id)) == request_id
    assert fixture.read_request(Connection(query(request_id=request_id)), time.monotonic() + 5) == request_id
    assert spec.SEED_OID == spec.QUERY_OID == ".1.3.6.1.2.1.2.2.1.2"
    assert spec.SEED_OID_BYTES == SEED and spec.COMMUNITY == COMMUNITY
    assert spec.NON_REPEATERS == 0 and spec.MAX_REPETITIONS == 4


@pytest.mark.parametrize("case", spec.CASES)
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_each_case_counts_one_complete_validated_question_before_response(case, chunk_size, monkeypatch):
    connection, calls, sleeps = Connection(chunk_size=chunk_size), [], []
    monkeypatch.setattr(fixture.time, "sleep", sleeps.append)
    original_send = connection.sendall
    def after_count(raw):
        assert calls == [1]
        original_send(raw)
    connection.sendall = after_count
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    assert bytes(connection.output) == (fixture.response(case, b"\x12\x34") or b"")
    assert len(connection.output) <= spec.MAX_RESPONSE_BYTES
    assert bool(sleeps) is (case == "snmp-page-stalled")
    if sleeps:
        assert len(sleeps) == 1 and 0 < sleeps[0] <= 5
    assert all(0 < value <= 2 for value in connection.timeouts)
    assert (spec.HOSTILE_NOTE.encode() in connection.output) is (case == "snmp-page-injected")


@pytest.mark.parametrize("options", [
    {"community": b"public"}, {"community": b"real-secret"}, {"community": b""},
    {"version": b"\0"}, {"version": b"\x03"}, {"version": b"\0\x01"},
    {"pdu": 0xa0}, {"pdu": 0xa1}, {"pdu": 0xa2}, {"pdu": 0xa3},
    {"non_repeaters": b"\x01"}, {"non_repeaters": b"\0\0"}, {"non_repeaters": b""},
    {"repetitions": b"\0"}, {"repetitions": b"\x01"}, {"repetitions": b"\x05"},
    {"repetitions": b"\0\x04"}, {"repetitions": b"\xff"}, {"repetitions": b""},
    {"request_id": b""}, {"request_id": b"\x80"}, {"request_id": b"\xff"},
    {"request_id": b"\0\x01"}, {"request_id": b"\0\x7f"}, {"request_id": b"\0\x80\0\0\0"},
    {"oids": ()}, {"oids": (SEED, SEED)}, {"oids": (SEED + b"\x01",)},
    {"oids": (SEED[:-1],)}, {"oids": (SEED[:-1] + b"\x03",)},
    {"value": (4, b"")}, {"value": (5, b"\0")}, {"extra": b"\x05\0"},
])
def test_changed_operation_seed_community_or_repetition_fields_never_count(options):
    connection, calls = Connection(query(**options)), []
    with pytest.raises(ValueError):
        fixture.serve(connection, case="snmp-page-ok", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("raw", [b"", b"\x30", b"\x30\x80", b"\x30\x83\x01\0\0", b"\x30\x82\x08\0",
    b"\x30\x81\x01\0", b"\x30\x82\0\x80", b"\x31" + query()[1:], query()[:-1],
    b"\x30\x81" + query()[1:], b"\x30\x82\0" + query()[1:]])
def test_noncanonical_incomplete_indefinite_and_excess_ber_never_counts(raw):
    connection, calls = Connection(raw), []
    with pytest.raises(ValueError):
        fixture.parse_request(raw)
    with pytest.raises(ValueError):
        fixture.serve(connection, case="snmp-page-ok", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def test_every_request_truncation_is_rejected_before_progress():
    raw = query()
    for length in range(len(raw)):
        connection, calls = Connection(raw[:length]), []
        with pytest.raises(ValueError):
            fixture.serve(connection, case="snmp-page-ok", deadline=time.monotonic() + 5,
                on_request=lambda: calls.append(1))
        assert not calls and not connection.output


def test_announced_frame_bound_rejects_before_payload_read():
    connection = Connection(b"\x30\x82\x08\x00" + b"X" * 2048)
    with pytest.raises(ValueError, match="frame_limit"):
        fixture.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 4 and spec.MAX_REQUEST_BYTES == 2048


def test_buffered_second_question_is_never_interpreted():
    trailing = query(pdu=0xa3)
    connection, calls = Connection(query() + trailing), []
    fixture.serve(connection, case="snmp-page-ok", deadline=time.monotonic() + 5,
        on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == trailing
    assert bytes(connection.output) == fixture.response("snmp-page-ok", b"\x12\x34")
    with pytest.raises(ValueError, match="trailing_fields"):
        fixture.parse_request(query() + trailing)


def test_fragmented_delivery_keeps_identical_reply_and_checks_deadline(monkeypatch):
    connection, calls = Connection(), []
    fixture.serve(connection, case="snmp-page-fragmented", deadline=time.monotonic() + 5,
        on_request=lambda: calls.append(1))
    assert calls == [1] and len(connection.writes) > 1
    assert all(0 < len(chunk) <= 3 for chunk in connection.writes)
    assert bytes(connection.output) == fixture.response("snmp-page-ok", b"\x12\x34")
    connection, calls = Connection(), []
    monkeypatch.setattr(fixture.time, "monotonic", lambda: 0)
    def expires_after_first_write(_):
        monkeypatch.setattr(fixture.time, "monotonic", lambda: 5)
    connection.sendall = expires_after_first_write
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case="snmp-page-fragmented", deadline=1, on_request=lambda: calls.append(1))
    assert calls == [1]


def test_fragmented_request_rechecks_deadline_before_progress(monkeypatch):
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(clock))
    connection, calls = Connection(chunk_size=1), []
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case="snmp-page-ok", deadline=1, on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def response_fields(raw):
    outer = accepted.Reader(raw)
    message = accepted.Reader(outer.expect(0x30))
    outer.end()
    assert message.expect(2) == b"\x01" and message.expect(4) == COMMUNITY
    pdu = accepted.Reader(message.expect(0xa2))
    message.end()
    request_id, status, index = pdu.expect(2), pdu.expect(2), pdu.expect(2)
    bindings = accepted.Reader(pdu.expect(0x30))
    pdu.end()
    values = []
    while bindings.offset < len(bindings.raw):
        binding = accepted.Reader(bindings.expect(0x30))
        oid = binding.expect(6)
        tag, value = binding.tlv()
        binding.end()
        values.append((oid, tag, value))
    bindings.end()
    return request_id, status, index, values


@pytest.mark.parametrize("case", spec.SUCCESS_CASES)
def test_success_cases_encode_complete_page_or_explicit_typed_boundary(case):
    request_id, status, index, rows = response_fields(fixture.response(case, b"\x12\x34"))
    assert (request_id, status, index) == (b"\x12\x34", b"\0", b"\0")
    assert 1 <= len(rows) <= 4
    outside = [(SEED[:-1] + b"\x03" + bytes([index]), 2, b"\x06") for index in range(1, 5)]
    normal = [(SEED + bytes([index]), 4, description.encode()) for index, description in enumerate(spec.DESCRIPTIONS, 1)]
    if case == "snmp-page-end-of-view":
        assert rows == [(SEED, 0x82, b"")]
    elif case == "snmp-page-outside-subtree":
        assert rows == outside
    elif case == "snmp-page-mixed-boundary":
        assert rows == normal[:2] + outside[:2]
    elif case == "snmp-page-end-after-rows":
        assert rows == normal[:2] + [(normal[1][0], 0x82, b"")] * 2
    else:
        if case == "snmp-page-empty":
            normal = [(oid, tag, b"") for oid, tag, value in normal]
        elif case == "snmp-page-injected":
            normal[1] = (normal[1][0], 4, spec.HOSTILE_NOTE.encode())
        assert rows == normal
        assert all(len(value) <= 255 for oid, tag, value in rows)


def test_semantic_negative_pages_are_distinct_from_supported_full_or_terminal_pages():
    rows = lambda name: response_fields(fixture.response("snmp-page-" + name))[3]
    assert len(rows("short")) == 3 and rows("empty-page") == []
    assert rows("nonincreasing")[1][0] > rows("nonincreasing")[2][0]
    assert rows("duplicate")[0] == rows("duplicate")[1]
    assert rows("wrong-type")[1][1] == 2 and len(rows("extra-varbind")) == 5
    assert [row[1] for row in rows("after-end")] == [4, 0x82, 4, 4]
    assert response_fields(fixture.response("snmp-page-denied")) == (
        b"\x01", b"\x10", b"\x01", [(SEED, 5, b"")])
    assert fixture.response("snmp-page-truncated") == fixture.response("snmp-page-ok")[:-1]
    assert fixture.response("snmp-page-malformed") == b"\x30\x80\0\0"
    assert fixture.response("snmp-page-stalled") is None
    assert 8192 < len(fixture.response("snmp-page-output-limit")) <= spec.MAX_RESPONSE_BYTES


@pytest.mark.parametrize("request_id", [None, 1, "x", b"", b"\x80", b"\xff", b"\0\x01", b"\0\x7f", b"\0\x80\0\0\0"])
def test_compiled_query_and_response_reject_unbounded_or_noncanonical_ids(request_id):
    with pytest.raises(ValueError):
        fixture.request(request_id)
    with pytest.raises(ValueError):
        fixture.response("snmp-page-ok", request_id)


@pytest.mark.parametrize("case", [None, 1, b"snmp-page-ok", "snmp-ok", "snmp-next-ok", "snmp-page-unknown"])
def test_invalid_case_never_reads_or_counts(case):
    connection = Connection()
    with pytest.raises(ValueError):
        fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
            on_request=lambda: pytest.fail("request counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        fixture.response(case)


def test_accepted_get_and_getnext_reject_getbulk_and_new_profile_rejects_both():
    for parser in (accepted.parse_snmp_request, predecessor.parse_request):
        with pytest.raises(ValueError):
            parser(query())
    for operation in (0xa0, 0xa1):
        with pytest.raises(ValueError):
            fixture.parse_request(query(pdu=operation, repetitions=b"\0"))


def test_owner_loads_with_isolated_python_outside_repository(tmp_path):
    script = """import importlib.util, sys
definition = importlib.util.spec_from_file_location('isolated_snmp_page_owner', sys.argv[1])
module = importlib.util.module_from_spec(definition)
definition.loader.exec_module(module)
assert len(module.spec.CASES) == 20
assert module.parse_request(module.request(b'\\x12\\x34')) == b'\\x12\\x34'
assert module.response('snmp-page-end-of-view')
print('isolated owner import ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
        str(Path(fixture.__file__).resolve())], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated owner import ready\n" and result.stderr == ""
