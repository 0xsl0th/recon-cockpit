"""Fixed MX wire bytes, owner bounds and accepted fixture compatibility."""

import hashlib
import io
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_dns_mx_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


def frame(query):
    return struct.pack("!H", len(query)) + query


class Connection:
    def __init__(self, raw=None, *, chunk_size=512):
        self.input = io.BytesIO(frame(server.dns_mx_query(b"\x12\x34")) if raw is None else raw)
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


@pytest.mark.parametrize("case", [case for case in server.DNS_MX_CASES if case != "dig-mx-stalled"])
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_exact_question_counts_once_and_emits_one_framed_response(case, chunk_size):
    connection, calls = Connection(chunk_size=chunk_size), []
    server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    response = server.dns_mx_response(case, server.dns_mx_query(b"\x12\x34"))
    assert bytes(connection.output) == frame(response)
    assert response[:2] == b"\x12\x34" and len(response) <= 4096
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)


def test_stall_counts_the_real_question_before_waiting_for_remaining_deadline(monkeypatch):
    connection, calls, waits = Connection(), [], []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    server.serve(connection, case="dig-mx-stalled", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and not connection.output
    assert len(waits) == 1 and 0 < waits[0] <= 5


@pytest.mark.parametrize("mutate", [
    lambda query: query[:2] + b"\x01\x00" + query[4:],  # RD
    lambda query: query[:2] + b"\x80\x00" + query[4:],  # QR
    lambda query: query[:2] + b"\x28\x00" + query[4:],  # UPDATE opcode
    lambda query: query[:4] + b"\x00\x02" + query[6:],
    lambda query: query[:10] + b"\x00\x01" + query[12:],  # EDNS/additional
    lambda query: query.replace(b"harbordesk", b"other-zone"),
    lambda query: query[:-4] + b"\x00\x01\x00\x01",  # A
    lambda query: query[:-4] + b"\x00\xfc\x00\x01",  # AXFR
    lambda query: query[:-2] + b"\x00\x03",  # CH
    lambda query: query + b"payload",
    lambda query: query + query,
    lambda query: query[:12] + b"\xc0\x0c\x00\x0f\x00\x01",  # cyclic compression
])
def test_question_changes_never_count_or_receive_a_reply(mutate):
    connection, calls = Connection(frame(mutate(server.dns_mx_query()))), []
    with pytest.raises(ValueError):
        server.serve(connection, case="dig-mx-ok", deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("size", [0, 1, 11, 513, 65535])
def test_framing_limits_are_checked_before_reading_payload(size):
    connection = Connection(struct.pack("!H", size) + b"X" * 1024)
    with pytest.raises(ValueError, match="frame_limit"):
        server.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 2


def test_every_truncated_frame_fails_without_counting_work():
    raw = frame(server.dns_mx_query())
    for length in range(len(raw)):
        connection, calls = Connection(raw[:length]), []
        with pytest.raises(ValueError):
            server.serve(connection, case="dig-mx-ok", deadline=time.monotonic() + 5,
                         on_request=lambda: calls.append(1))
        assert not calls and not connection.output


def test_one_question_per_connection_serves_no_pipelined_work():
    query = server.dns_mx_query()
    connection, calls = Connection(frame(query) * 2), []
    server.serve(connection, case="dig-mx-ok", deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == frame(query)
    assert bytes(connection.output) == frame(server.dns_mx_response("dig-mx-ok", query))


def test_deadline_is_rechecked_on_every_fragment(monkeypatch):
    connection = Connection(chunk_size=1)
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        server.read_request(connection, 1)


@pytest.mark.parametrize("case", [None, 1, b"dig-mx-ok", "dig-ok", "dig-mx-unknown"])
def test_invalid_case_never_reads_a_question(case):
    connection = Connection()
    with pytest.raises(ValueError):
        server.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: pytest.fail("counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        server.dns_mx_response(case, server.dns_mx_query())


@pytest.mark.parametrize("transaction_id", [None, 1, "ab", b"", b"a", b"abc"])
def test_transaction_id_shape_is_exact(transaction_id):
    with pytest.raises(ValueError):
        server.dns_mx_query(transaction_id)


def test_wire_distinguishes_records_nodata_nxdomain_null_and_refusal():
    query = server.dns_mx_query()
    for suffix, rcode, count in (("ok", 0, 2), ("single", 0, 1), ("nodata", 0, 0),
                                 ("nxdomain", 3, 0), ("null", 0, 1), ("refused", 5, 0)):
        response = server.dns_mx_response("dig-mx-" + suffix, query)
        header = struct.unpack("!HHHHHH", response[:12])
        assert header == (0, 0x8400 | rcode, 1, count, 0, 0)
        assert response[12:12 + len(server.DNS_MX_QUESTION)] == server.DNS_MX_QUESTION
    null_mx = server.dns_mx_response("dig-mx-null", query)
    assert null_mx[-3:] == b"\x00" * 3
    assert server.dns_mx_records("dig-mx-null") == ((0, ".", 60),)
    assert server.dns_mx_records("dig-mx-null-mixed") == ((0, ".", 60), (10, "mail1.harbordesk.test.", 60))
    assert server.dns_mx_records("dig-mx-null-preference") == ((10, ".", 60),)
    assert server.dns_mx_response("dig-mx-stalled", query) is None


def test_hostile_text_foreign_target_and_output_pressure_are_finite_data():
    query = server.dns_mx_query()
    injected = server.dns_mx_response("dig-mx-injected", query)
    assert server.DNS_MX_HOSTILE_NOTE.encode() in injected
    assert b"\x07outside\x07invalid\x00" in injected
    assert server.DNS_MX_FOREIGN_RECORD in server.dns_mx_records("dig-mx-injected")
    assert len(server.dns_mx_records("dig-mx-record-limit")) == server.DNS_MX_MAX_RECORDS + 1
    pressure = server.dns_mx_response("dig-mx-output-limit", query)
    assert len(pressure) <= 4096 and pressure.count(b"\x01") > 3000
    assert pressure.count(b"\x01") * len("\\001") > 8192


@pytest.mark.parametrize("case", server.DNS_MX_CASES)
def test_spec_pins_fixed_question_reply_and_no_followups(case):
    definition = contract.spec(case)
    response = server.dns_mx_response(case, server.dns_mx_query())
    assert definition["query"] == {"name": server.DNS_MX_QUERY_NAME, "type": "MX", "class": "IN", "recursion": False}
    assert definition["query_sha256"] == hashlib.sha256(server.dns_mx_query()).hexdigest()
    assert definition["response_sha256"] == (None if response is None else hashlib.sha256(response).hexdigest())
    assert definition["tool_id"] == server.DNS_MX_TOOL_ID
    assert definition["max_connections"] == definition["max_requests"] == 1
    assert definition["max_records"] == 4
    for name in ("udp", "recursion", "retries", "search_suffixes", "exchange_resolution", "exchange_connections",
                 "credentials", "external_egress", "resume", "service_identity_claim", "vulnerability_claim"):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {"identity": identity, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, identity) == context
    for change in ({"connection_count": 2}, {"request_count": 2}, {"connection_count": 0}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize("case", ["dig-mx-ok", "dig-mx-malformed", "dig-mx-refused"])
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


def test_owner_module_imports_under_isolated_python_without_package(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_mx_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.DNS_MX_CASES) == 13
print('isolated MX owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated MX owner ready\n" and result.stderr == ""
