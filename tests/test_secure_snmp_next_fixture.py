"""Finite GetNext framing, exact request validation and owned response meaning."""

import io
from pathlib import Path
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as public
from recon_cockpit.secure_agent import network_tools_snmp_next_fixture as fixture
from recon_cockpit.secure_agent import network_tools_redis_snmp_fixture as accepted


SEED = bytes.fromhex("2b0601020102020102")
COMMUNITY = b"recon-fixture-public"


def ber(tag, raw):
    size = len(raw)
    length = bytes([size]) if size < 128 else bytes([0x81, size]) if size < 256 else b"\x82" + size.to_bytes(2, "big")
    return bytes([tag]) + length + raw


def query(*, request_id=b"\x12\x34", community=COMMUNITY, version=b"\x01", pdu=0xa1,
          error=b"\0", index=b"\0", oids=(SEED,), value=(5, b""), extra=b""):
    bindings = b"".join(ber(0x30, ber(6, oid) + ber(*value)) for oid in oids)
    request = ber(pdu, ber(2, request_id) + ber(2, error) + ber(2, index) + ber(0x30, bindings) + extra)
    return ber(0x30, ber(2, version) + ber(4, community) + request)


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
def test_compiled_query_is_exactly_one_canonical_getnext_with_fixed_seed(request_id):
    raw = query(request_id=request_id)
    assert public.snmp_next_request(request_id) == raw
    assert fixture.parse_request(raw) == request_id
    assert fixture.read_request(Connection(raw), time.monotonic() + 5) == request_id
    assert public.SNMP_NEXT_SEED_OID == ".1.3.6.1.2.1.2.2.1.2"
    assert public.SNMP_NEXT_SEED_OID_BYTES == SEED


@pytest.mark.parametrize("case", public.SNMP_NEXT_CASES)
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_each_finite_case_requires_one_actual_validated_query(case, chunk_size, monkeypatch):
    connection, calls, sleeps = Connection(chunk_size=chunk_size), [], []
    monkeypatch.setattr(fixture.time, "sleep", sleeps.append)
    original_send = connection.sendall
    def after_count(raw):
        assert calls == [1]
        original_send(raw)
    connection.sendall = after_count
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                  on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    assert bytes(connection.output) == (public.snmp_next_response(case, b"\x12\x34") or b"")
    assert len(connection.output) <= public.SNMP_NEXT_MAX_RESPONSE_BYTES
    assert bool(sleeps) is (case == "snmp-next-stalled")
    if sleeps:
        assert len(sleeps) == 1 and 0 < sleeps[0] <= 5
    assert all(0 < value <= 2 for value in connection.timeouts)
    assert public.tool_for_case(case) == "snmp_interface_next_v1"
    assert (public.HOSTILE_NOTE.encode() in connection.output) is (case == "snmp-next-injected")


@pytest.mark.parametrize("options", [
    {"community": b"public"}, {"community": b"real-secret"}, {"community": b""},
    {"version": b"\0"}, {"version": b"\x03"}, {"version": b"\0\x01"},
    {"pdu": 0xa0}, {"pdu": 0xa2}, {"pdu": 0xa3}, {"pdu": 0xa5},
    {"error": b"\x01"}, {"index": b"\x01"}, {"error": b"\0\0"}, {"index": b""},
    {"request_id": b""}, {"request_id": b"\x80"}, {"request_id": b"\xff"},
    {"request_id": b"\0\x01"}, {"request_id": b"\0\x7f"}, {"request_id": b"\0\x80\0\0\0"},
    {"oids": ()}, {"oids": (SEED, SEED)}, {"oids": (SEED + b"\x01",)},
    {"oids": (SEED[:-1],)}, {"oids": (SEED[:-1] + b"\x03",)},
    {"oids": public.SNMP_SYSTEM_OID_BYTES}, {"value": (4, b"")}, {"value": (5, b"\0")},
    {"extra": b"\x05\0"},
])
def test_unreviewed_community_operation_bindings_and_fields_never_count(options):
    connection, calls = Connection(query(**options)), []
    with pytest.raises(ValueError):
        fixture.serve(connection, case="snmp-next-ok", deadline=time.monotonic() + 5,
                      on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("raw", [b"", b"\x30", b"\x30\x80", b"\x30\x83\x01\0\0", b"\x30\x82\x08\0",
    b"\x30\x81\x01\0", b"\x30\x82\0\x80", b"\x31" + query()[1:], query()[:-1],
    b"\x30\x81" + query()[1:], b"\x30\x82\0" + query()[1:]])
def test_noncanonical_indefinite_incomplete_and_excess_ber_fails_before_count(raw):
    connection, calls = Connection(raw), []
    with pytest.raises(ValueError):
        fixture.parse_request(raw)
    with pytest.raises(ValueError):
        fixture.serve(connection, case="snmp-next-ok", deadline=time.monotonic() + 5,
                      on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def test_every_truncated_query_fails_without_counting():
    raw = query()
    for length in range(len(raw)):
        connection, calls = Connection(raw[:length]), []
        with pytest.raises(ValueError):
            fixture.serve(connection, case="snmp-next-ok", deadline=time.monotonic() + 5,
                          on_request=lambda: calls.append(1))
        assert not calls and not connection.output


def test_announced_frame_limit_is_rejected_before_payload_read():
    connection = Connection(b"\x30\x82\x08\x00" + b"X" * 2048)
    with pytest.raises(ValueError, match="frame_limit"):
        fixture.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 4
    assert public.SNMP_NEXT_MAX_REQUEST_BYTES == public.SNMP_MAX_REQUEST_BYTES == 2048


def test_no_second_question_is_interpreted_from_pipelined_bytes():
    trailing = query(pdu=0xa3)
    connection, calls = Connection(query() + trailing), []
    fixture.serve(connection, case="snmp-next-ok", deadline=time.monotonic() + 5,
                  on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == trailing
    assert bytes(connection.output) == public.snmp_next_response("snmp-next-ok", b"\x12\x34")
    with pytest.raises(ValueError, match="trailing_fields"):
        fixture.parse_request(query() + trailing)


def test_fragmented_delivery_preserves_response_and_rechecks_deadline(monkeypatch):
    connection, calls = Connection(), []
    fixture.serve(connection, case="snmp-next-fragmented", deadline=time.monotonic() + 5,
                  on_request=lambda: calls.append(1))
    assert calls == [1] and len(connection.writes) > 1
    assert all(0 < len(chunk) <= 3 for chunk in connection.writes)
    assert bytes(connection.output) == public.snmp_next_response("snmp-next-ok", b"\x12\x34")
    connection, calls = Connection(), []
    monkeypatch.setattr(fixture.time, "monotonic", lambda: 0)
    def expires_after_first_write(_):
        monkeypatch.setattr(fixture.time, "monotonic", lambda: 5)
    connection.sendall = expires_after_first_write
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case="snmp-next-fragmented", deadline=1,
                      on_request=lambda: calls.append(1))
    assert calls == [1]


def test_read_deadline_is_rechecked_during_fragmented_request(monkeypatch):
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(clock))
    connection, calls = Connection(chunk_size=1), []
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case="snmp-next-ok", deadline=1,
                      on_request=lambda: calls.append(1))
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


@pytest.mark.parametrize("case", public.SNMP_NEXT_SUCCESS_CASES)
def test_useful_cases_have_explicit_successor_exception_and_empty_meanings(case):
    request_id, status, index, values = response_fields(public.snmp_next_response(case, b"\x12\x34"))
    assert (request_id, status, index) == (b"\x12\x34", b"\0", b"\0")
    if case == "snmp-next-end-of-view":
        assert values == [(SEED, 0x82, b"")]
    elif case == "snmp-next-outside-subtree":
        assert values == [(bytes.fromhex("2b060102010202010301"), 2, b"\x06")]
    else:
        description = b"" if case == "snmp-next-empty" else public.HOSTILE_NOTE.encode() if case == "snmp-next-injected" else b"HarborDesk synthetic interface"
        assert values == [(SEED + b"\x01", 4, description)]
        assert len(description) <= 255


def test_semantic_negatives_do_not_resemble_valid_interface_successors():
    assert response_fields(public.snmp_next_response("snmp-next-nonincreasing"))[3][0][0] == SEED
    assert response_fields(public.snmp_next_response("snmp-next-wrong-type"))[3] == [(SEED + b"\x01", 2, b"\x06")]
    assert len(response_fields(public.snmp_next_response("snmp-next-extra-varbind"))[3]) == 2
    request_id, status, index, values = response_fields(public.snmp_next_response("snmp-next-denied"))
    assert (request_id, status, index, values) == (b"\x01", b"\x10", b"\x01", [(SEED, 5, b"")])
    ordinary = public.snmp_next_response("snmp-next-ok")
    assert public.snmp_next_response("snmp-next-truncated") == ordinary[:-1]
    assert public.snmp_next_response("snmp-next-malformed") == b"\x30\x80\x00\x00"
    assert public.snmp_next_response("snmp-next-stalled") is None
    assert 8192 < len(public.snmp_next_response("snmp-next-output-limit")) <= public.SNMP_NEXT_MAX_RESPONSE_BYTES


@pytest.mark.parametrize("request_id", [None, 1, "x", b"", b"\x80", b"\xff", b"\0\x01", b"\0\x7f", b"\0\x80\0\0\0"])
def test_public_query_and_response_reject_noncanonical_or_unbounded_ids(request_id):
    with pytest.raises(ValueError):
        public.snmp_next_request(request_id)
    with pytest.raises(ValueError):
        public.snmp_next_response("snmp-next-ok", request_id)


@pytest.mark.parametrize("case", [None, 1, b"snmp-next-ok", "snmp-ok", "snmp-next-unknown"])
def test_invalid_case_never_reads_or_counts(case):
    connection = Connection()
    with pytest.raises(ValueError):
        fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                      on_request=lambda: pytest.fail("request counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        public.snmp_next_response(case)


def test_accepted_get_profile_cannot_accept_getnext_and_new_profile_rejects_get():
    with pytest.raises(ValueError):
        accepted.parse_snmp_request(query())
    with pytest.raises(ValueError):
        fixture.parse_request(query(pdu=0xa0, oids=public.SNMP_SYSTEM_OID_BYTES))


def test_owner_loads_under_isolated_python_outside_repository(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_snmp_next_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.SNMP_NEXT_CASES) == 14
assert module.parse_request(module.fixture.snmp_next_request(b'\\x12\\x34')) == b'\\x12\\x34'
assert module.fixture.snmp_next_response('snmp-next-end-of-view')
print('isolated owner import ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
        str(Path(fixture.__file__).resolve())], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated owner import ready\n" and result.stderr == ""
