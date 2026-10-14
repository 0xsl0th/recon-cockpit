"""Exact finite AAAA/PTR wire questions, owner progress and pure identities."""

import hashlib
from ipaddress import IPv6Address
import io
from pathlib import Path
import struct
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_dns_address_spec as spec
from recon_cockpit.secure_agent import network_tools_dns_address_fixture as fixture
from recon_cockpit.secure_agent import network_tools_dns_address_identity as identity


QUESTIONS = {
    spec.AAAA: b"\x0aharbordesk\x04test\0\0\x1c\0\x01",
    spec.PTR: b"\x011\x010\x010\x03127\x07in-addr\x04arpa\0\0\x0c\0\x01",
}


def query(tool, transaction_id=b"\x12\x34"):
    return transaction_id + b"\0\0\0\x01\0\0\0\0\0\0" + QUESTIONS[tool]


def frame(raw):
    return struct.pack("!H", len(raw)) + raw


class Connection:
    def __init__(self, tool=spec.AAAA, raw=None, *, chunk_size=3):
        self.input = io.BytesIO(frame(query(tool)) if raw is None else raw)
        self.output, self.timeouts, self.writes = bytearray(), [], []
        self.chunk_size = chunk_size

    def recv(self, count):
        return self.input.read(min(count, self.chunk_size))

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, raw):
        self.writes.append(raw)
        self.output.extend(raw)


def test_corpus_is_closed_and_usefulness_denominators_are_explicit():
    assert spec.TOOL_IDS == ("dig_dns_aaaa_v1", "dig_dns_ptr_v1")
    assert len(spec.CASES) == len(set(spec.CASES)) == 38
    assert len(spec.ORDINARY_CASES) == 11
    assert len(spec.ROBUSTNESS_CASES) == 4
    assert len(spec.SUCCESS_CASES) == 15
    assert len(spec.NEGATIVE_CASES) == 23
    assert set(spec.CASES) == set(spec.SUCCESS_CASES) | set(spec.NEGATIVE_CASES)
    assert not set(spec.SUCCESS_CASES) & set(spec.NEGATIVE_CASES)
    assert sum(spec.tool_for_case(case) == spec.AAAA for case in spec.ORDINARY_CASES) == 6
    assert sum(spec.tool_for_case(case) == spec.PTR for case in spec.ORDINARY_CASES) == 5
    assert spec.PARAMETERS == {"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192}
    assert spec.LIMITS == {"max_steps": 1, "max_runtime_seconds": 60, "max_output_bytes": 8192}


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
@pytest.mark.parametrize("transaction_id", [b"\0\0", b"\0\x01", b"\x12\x34", b"\xff\xff"])
def test_only_the_exact_fixed_in_question_is_generated(tool, transaction_id):
    raw = query(tool, transaction_id)
    assert fixture.query(tool, transaction_id) == raw
    assert fixture.validate_query(raw, tool) == raw
    assert fixture.read_request(Connection(tool, frame(raw)), time.monotonic() + 5, tool) == raw
    assert len(raw) == (33 if tool == spec.AAAA else 40)


@pytest.mark.parametrize("case", spec.CASES)
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_every_case_counts_one_validated_question_before_any_response(case, chunk_size, monkeypatch):
    tool = spec.tool_for_case(case)
    connection, calls, sleeps = Connection(tool, chunk_size=chunk_size), [], []
    monkeypatch.setattr(fixture.time, "sleep", sleeps.append)
    original_send = connection.sendall

    def send_after_count(raw):
        assert calls == [1]
        original_send(raw)

    connection.sendall = send_after_count
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                  on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    expected = fixture.response(case, query(tool))
    assert bytes(connection.output) == (b"" if expected is None else frame(expected))
    if expected is not None:
        assert expected[:2] == b"\x12\x34" and len(expected) <= 4096
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)
    assert bool(sleeps) is case.endswith("-stalled")
    if sleeps:
        assert len(sleeps) == 1 and 0 < sleeps[0] <= 5
    assert (spec.HOSTILE_NOTE.encode() in connection.output) is case.endswith("-injected")


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
@pytest.mark.parametrize("mutate", [
    lambda raw: raw[:2] + b"\x01\0" + raw[4:],  # Recursion desired.
    lambda raw: raw[:2] + b"\x80\0" + raw[4:],  # A response, not a query.
    lambda raw: raw[:2] + b"\x28\0" + raw[4:],  # UPDATE opcode.
    lambda raw: raw[:2] + b"\0\x20" + raw[4:],  # AD flag.
    lambda raw: raw[:2] + b"\0\x10" + raw[4:],  # CD flag.
    lambda raw: raw[:4] + b"\0\x02" + raw[6:],
    lambda raw: raw[:6] + b"\0\x01" + raw[8:],
    lambda raw: raw[:8] + b"\0\x01" + raw[10:],
    lambda raw: raw[:10] + b"\0\x01" + raw[12:],  # EDNS/additional.
    lambda raw: raw[:13] + bytes([raw[13] ^ 1]) + raw[14:],
    lambda raw: raw[:-4] + b"\0\x01\0\x01",  # A.
    lambda raw: raw[:-4] + b"\0\xfc\0\x01",  # AXFR.
    lambda raw: raw[:-2] + b"\0\x03",  # CH class.
    lambda raw: raw + b"payload",
    lambda raw: raw + raw,
    lambda raw: raw[:12] + b"\xc0\x0c" + raw[-4:],  # Cyclic name compression.
])
def test_changed_questions_never_count_or_receive_a_reply(tool, mutate):
    connection, calls = Connection(tool, frame(mutate(query(tool)))), []
    with pytest.raises(ValueError):
        fixture.serve(connection, case=spec.PREFIXES[tool] + "ok", deadline=time.monotonic() + 5,
                      on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
def test_profiles_reject_each_others_question_before_progress(tool):
    other = spec.PTR if tool == spec.AAAA else spec.AAAA
    connection, calls = Connection(tool, frame(query(other))), []
    with pytest.raises(ValueError, match="question"):
        fixture.serve(connection, case=spec.PREFIXES[tool] + "ok", deadline=time.monotonic() + 5,
                      on_request=lambda: calls.append(1))
    assert not calls and not connection.output
    with pytest.raises(ValueError, match="question"):
        fixture.response(spec.PREFIXES[tool] + "ok", query(other))


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
@pytest.mark.parametrize("size", [0, 1, 11, 513, 65535])
def test_oversized_or_short_frames_stop_before_payload_read(tool, size):
    connection = Connection(tool, struct.pack("!H", size) + b"X" * 1024)
    with pytest.raises(ValueError, match="frame_limit"):
        fixture.read_request(connection, time.monotonic() + 5, tool)
    assert connection.input.tell() == 2


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
def test_every_truncated_request_frame_fails_before_counting(tool):
    raw = frame(query(tool))
    for length in range(len(raw)):
        connection, calls = Connection(tool, raw[:length]), []
        with pytest.raises(ValueError):
            fixture.serve(connection, case=spec.PREFIXES[tool] + "ok", deadline=time.monotonic() + 5,
                          on_request=lambda: calls.append(1))
        assert not calls and not connection.output


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
def test_pipelined_work_is_not_read_or_counted(tool):
    raw = frame(query(tool))
    connection, calls = Connection(tool, raw + raw), []
    fixture.serve(connection, case=spec.PREFIXES[tool] + "ok", deadline=time.monotonic() + 5,
                  on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == raw
    assert bytes(connection.output) == frame(fixture.response(spec.PREFIXES[tool] + "ok", query(tool)))


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
def test_fragmentation_changes_delivery_only_and_rechecks_deadline(tool, monkeypatch):
    connection, calls = Connection(tool), []
    fixture.serve(connection, case=spec.PREFIXES[tool] + "fragmented", deadline=time.monotonic() + 5,
                  on_request=lambda: calls.append(1))
    assert calls == [1] and len(connection.writes) > 1
    assert all(0 < len(chunk) <= 3 for chunk in connection.writes)
    assert bytes(connection.output) == frame(fixture.response(spec.PREFIXES[tool] + "ok", query(tool)))
    connection, calls = Connection(tool), []
    monkeypatch.setattr(fixture.time, "monotonic", lambda: 0)

    def expire(_):
        monkeypatch.setattr(fixture.time, "monotonic", lambda: 5)

    connection.sendall = expire
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case=spec.PREFIXES[tool] + "fragmented", deadline=1,
                      on_request=lambda: calls.append(1))
    assert calls == [1]


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
def test_fragmented_request_checks_deadline_before_progress(tool, monkeypatch):
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(clock))
    connection, calls = Connection(tool, chunk_size=1), []
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case=spec.PREFIXES[tool] + "ok", deadline=1,
                      on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def decoded_records(raw, tool):
    question = QUESTIONS[tool]
    header = struct.unpack("!HHHHHH", raw[:12])
    assert raw[12:12 + len(question)] == question
    cursor, result = 12 + len(question), []
    for _ in range(header[3]):
        assert raw[cursor:cursor + 2] == b"\xc0\x0c"
        kind, record_class, ttl, length = struct.unpack("!HHIH", raw[cursor + 2:cursor + 12])
        assert record_class == 1
        cursor += 12
        value = raw[cursor:cursor + length]
        assert len(value) == length
        result.append((kind, ttl, value))
        cursor += length
    return header, result, raw[cursor:]


def decode_name(raw):
    cursor, labels = 0, []
    while raw[cursor]:
        size = raw[cursor]
        assert size <= 63 and cursor + size < len(raw)
        labels.append(raw[cursor + 1:cursor + 1 + size].decode("ascii"))
        cursor += 1 + size
    assert cursor == len(raw) - 1
    return ".".join(labels) + "."


@pytest.mark.parametrize("case", spec.SUCCESS_CASES)
def test_supported_wire_records_are_complete_typed_and_finite(case):
    tool = spec.tool_for_case(case)
    header, rows, extra = decoded_records(fixture.response(case, query(tool)), tool)
    expected_status = 3 if case.endswith("-nxdomain") else 0
    assert header == (0x1234, 0x8400 | expected_status, 1, len(rows), 0, int(case.endswith("-injected")))
    assert len(rows) <= 4
    values = []
    for kind, ttl, raw in rows:
        assert kind == (28 if tool == spec.AAAA else 12) and ttl == 60
        if tool == spec.AAAA:
            assert len(raw) == 16
            values.append((str(IPv6Address(raw)), ttl))
        else:
            values.append((decode_name(raw), ttl))
    expected = [(str(IPv6Address(value)) if tool == spec.AAAA else value, ttl)
                for value, ttl in fixture.records(case)]
    assert values == expected
    assert bool(extra) is case.endswith("-injected")
    if extra:
        assert extra[:2] == b"\xc0\x0c"
        assert struct.unpack("!HHIH", extra[2:12]) == (16, 1, 60, len(extra) - 12)
        assert extra[12:] == bytes([len(spec.HOSTILE_NOTE)]) + spec.HOSTILE_NOTE.encode()


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
def test_wire_negatives_cannot_be_confused_with_supported_absence(tool):
    prefix = spec.PREFIXES[tool]
    reply = lambda suffix: fixture.response(prefix + suffix, query(tool))
    header, rows, extra = decoded_records(reply("record-limit"), tool)
    assert header[3] == len(rows) == 5 and not extra
    _, rows, _ = decoded_records(reply("duplicate"), tool)
    assert rows[0][0] == rows[1][0] and rows[0][2] == rows[1][2] and rows[0][1] != rows[1][1]
    assert all(row[0] == 1 for row in decoded_records(reply("wrong-type"), tool)[1])
    assert all(row[0] == 5 and decode_name(row[2]) == "outside.invalid."
               for row in decoded_records(reply("alias"), tool)[1])
    question_length = len(QUESTIONS[tool])
    assert reply("wrong-question")[12:12 + question_length] == QUESTIONS[tool][:-4] + b"\0\x01\0\x01"
    assert reply("malformed") == reply("ok")[:12 + question_length] + b"\xc0"
    assert reply("truncated") == reply("ok")[:-1]
    assert reply("stalled") is None
    assert decoded_records(reply("refused"), tool) == ((0x1234, 0x8405, 1, 0, 0, 0), [], b"")
    _, rows, _ = decoded_records(reply("malformed-value"), tool)
    if tool == spec.AAAA:
        assert all(kind == 28 and len(value) == 15 for kind, _, value in rows)
    else:
        assert [decode_name(value) for _, _, value in rows] == ["_bad.harbordesk.test."]
        assert [decode_name(value) for _, _, value in decoded_records(reply("root"), tool)[1]] == ["."]


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
def test_output_pressure_is_bounded_wire_data_with_oversized_native_rendering(tool):
    raw = fixture.response(spec.PREFIXES[tool] + "output-limit", query(tool))
    assert len(raw) <= spec.MAX_RESPONSE_BYTES == 4096
    _, rows, extra = decoded_records(raw, tool)
    assert len(rows) == 2 and extra[:2] == b"\xc0\x0c"
    assert struct.unpack("!HHIH", extra[2:12]) == (16, 1, 60, 3072)
    assert extra[12:] == (b"\xff" + b"\x01" * 255) * 12
    assert extra[12:].count(b"\x01") * len("\\001") > 8192


@pytest.mark.parametrize("tool", spec.TOOL_IDS)
@pytest.mark.parametrize("transaction_id", [None, 1, True, "ab", b"", b"a", b"abc", bytearray(b"ab")])
def test_transaction_id_shape_is_exact(tool, transaction_id):
    with pytest.raises(ValueError):
        fixture.query(tool, transaction_id)


@pytest.mark.parametrize("tool", [None, 1, True, [], b"dig_dns_aaaa_v1", "dig_dns_query_v1", "dig_dns_mx_v1"])
def test_unknown_tools_cannot_generate_questions(tool):
    with pytest.raises(ValueError):
        fixture.query(tool)
    with pytest.raises(ValueError):
        fixture.validate_query(query(spec.AAAA), tool)


@pytest.mark.parametrize("case", [None, 1, [], b"dig-aaaa-ok", "dig-ok", "dig-mx-ok", "dig-aaaa-root", "dig-ptr-mapped"])
def test_unknown_cases_are_rejected_before_reading(case):
    connection = Connection()
    with pytest.raises(ValueError):
        fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                      on_request=lambda: pytest.fail("request counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        fixture.response(case, query(spec.AAAA))
    with pytest.raises(ValueError):
        fixture.records(case)


@pytest.mark.parametrize("case", spec.CASES)
def test_pure_identity_binds_each_canonical_question_and_response(case):
    tool = spec.tool_for_case(case)
    canonical = query(tool, b"\0\0")
    assert identity.CANONICAL_QUERIES_BY_TOOL[tool] == canonical
    assert identity.QUERY_BYTES_BY_TOOL[tool] == len(canonical)
    assert identity.QUERY_SHA256_BY_TOOL[tool] == hashlib.sha256(canonical).hexdigest()
    response = fixture.response(case, canonical)
    assert identity.RESPONSE_SHA256_BY_CASE[case] == (
        None if response is None else hashlib.sha256(response).hexdigest())


def test_owner_imports_with_only_its_spec_outside_package(tmp_path):
    script = """import importlib.util, sys
definition = importlib.util.spec_from_file_location('isolated_address_owner', sys.argv[1])
module = importlib.util.module_from_spec(definition)
definition.loader.exec_module(module)
assert len(module.spec.CASES) == 38
for tool in module.spec.TOOL_IDS:
    raw = module.query(tool, b'\\x12\\x34')
    assert module.validate_query(raw, tool) == raw
    assert module.response(module.spec.PREFIXES[tool] + 'ok', raw)
print('isolated DNS address owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
        str(Path(fixture.__file__).resolve())], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated DNS address owner ready\n" and result.stderr == ""


def test_identity_is_immutable_and_does_not_load_fixture_or_io_modules(tmp_path):
    script = """import importlib.util, sys
definition = importlib.util.spec_from_file_location('pure_address_identity', sys.argv[1])
module = importlib.util.module_from_spec(definition)
before = set(sys.modules)
definition.loader.exec_module(module)
assert not ({'socket', 'struct', 'time', 'pathlib', 'ipaddress'} & (set(sys.modules) - before))
assert not any('fixture' in name for name in set(sys.modules) - before)
assert len(module.RESPONSE_SHA256_BY_CASE) == 38
try:
    module.QUERY_SHA256_BY_TOOL['dig_dns_aaaa_v1'] = 'changed'
except TypeError:
    pass
else:
    raise AssertionError('identity changed')
print('pure DNS address identity ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
        str(Path(identity.__file__).resolve())], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "pure DNS address identity ready\n" and result.stderr == ""
