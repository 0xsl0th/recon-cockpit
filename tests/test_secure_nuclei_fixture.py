"""Bounded original HTTP fixture bytes and GET progress, without running Nuclei."""

import gzip
import io
from pathlib import Path
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_nuclei_fixture as fixture


class Connection:
    def __init__(self, raw=None, *, write_size=None):
        self.input = io.BytesIO(fixture.NUCLEI_REQUEST if raw is None else raw)
        self.output, self.timeouts = bytearray(), []
        self.write_size = write_size

    def recv(self, count):
        return self.input.read(count)

    def settimeout(self, value):
        self.timeouts.append(value)

    def send(self, raw):
        selected = raw if self.write_size is None else raw[:self.write_size]
        self.output.extend(selected)
        return len(selected)


def execute(case="nuclei-index", raw=None, **kwargs):
    connection, counted, chunks = Connection(raw, **kwargs), [], []
    result = fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        on_request=lambda: counted.append(1), on_response=chunks.append)
    return connection, counted, chunks, result


@pytest.mark.parametrize("case", fixture.NUCLEI_CASES[:-1])
def test_full_get_is_counted_once_before_any_recorded_response(case):
    connection, counted, chunks = Connection(write_size=17), [], []
    def observed(raw):
        assert counted == [1]
        assert bytes(connection.output).endswith(raw)
        chunks.append(raw)
    result = fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        on_request=lambda: counted.append(1), on_response=observed)
    assert counted == [1] and connection.input.read() == b""
    assert bytes(connection.output) == b"".join(chunks) == fixture.response(case)
    assert result == {"response_bytes_sent": len(connection.output), "response_send_complete": True}
    assert len(connection.output) <= fixture.NUCLEI_MAX_RESPONSE_BYTES
    assert all(0 < value <= 2 for value in connection.timeouts)


@pytest.mark.parametrize("case", fixture.NUCLEI_SUCCESS_CASES)
def test_useful_fixtures_have_complete_finite_ascii_bodies_and_expected_predicate(case):
    raw = fixture.response(case)
    headers, body = raw.split(b"\r\n\r\n", 1)
    lines = headers.split(b"\r\n")
    fields = dict(line.split(b": ", 1) for line in lines[1:])
    assert int(fields[b"Content-Length"]) == len(body) <= fixture.NUCLEI_MAX_BODY_BYTES
    assert fields[b"Connection"] == b"close" and body.decode("ascii")
    expected_status = b"404 Not Found" if case == "nuclei-not-found" else b"200 OK"
    assert lines[0] == b"HTTP/1.1 " + expected_status
    matched = (expected_status == b"200 OK"
        and all(marker in body for marker in (b"<title>Index of /public/</title>",
            b"<h1>Index of /public/</h1>", b'href="../"')))
    assert matched == (case in fixture.NUCLEI_MATCHED_CASES)
    assert (fixture.NUCLEI_HOSTILE_NOTE.encode() in body) == (case == "nuclei-injected")


def test_original_wire_negatives_retain_distinguishing_framing_not_engine_normalization():
    raw = fixture.response("nuclei-chunked")
    headers, body = raw.split(b"\r\n\r\n", 1)
    assert b"Transfer-Encoding: chunked" in headers and b"Content-Length:" not in headers
    size, chunk = body.split(b"\r\n", 1)
    assert int(size, 16) == len(fixture.NUCLEI_INDEX_BODY)
    assert chunk == fixture.NUCLEI_INDEX_BODY + b"\r\n0\r\n\r\n"
    raw = fixture.response("nuclei-encoded")
    headers, body = raw.split(b"\r\n\r\n", 1)
    assert b"Content-Encoding: gzip" in headers
    assert body == fixture.NUCLEI_ENCODED_BODY and gzip.decompress(body) == fixture.NUCLEI_INDEX_BODY
    raw = fixture.response("nuclei-conflicting-length")
    assert raw.count(b"Content-Length:") == 2
    raw = fixture.response("nuclei-incomplete")
    headers, body = raw.split(b"\r\n\r\n", 1)
    assert b"Content-Length: " + str(len(body) + 17).encode() in headers
    assert len(fixture.response("nuclei-oversized").split(b"\r\n\r\n", 1)[1]) == 2049


@pytest.mark.parametrize("case,destination", (("nuclei-redirect-ip", b"127.0.0.2:8080"),
    ("nuclei-redirect-port", b"127.0.0.1:8081")))
def test_redirect_is_only_a_finite_untrusted_response_not_an_owner_operation(case, destination):
    connection, counted, _, _ = execute(case)
    assert counted == [1] and b"Location: http://" + destination + b"/public/\r\n" in connection.output


@pytest.mark.parametrize("replacement", (b"POST /public/ HTTP/1.1", b"HEAD /public/ HTTP/1.1",
    b"GET / HTTP/1.1", b"GET /public/?x=1 HTTP/1.1", b"GET /private/ HTTP/1.1",
    b"GET http://127.0.0.1:8080/public/ HTTP/1.1", b"GET /public/ HTTP/1.0"))
def test_fixed_request_line_cannot_change(replacement):
    raw = fixture.NUCLEI_REQUEST.replace(b"GET /public/ HTTP/1.1", replacement)
    with pytest.raises(ValueError, match="fixed_get_only"):
        execute(raw=raw)


@pytest.mark.parametrize("change", (
    lambda raw: raw.replace(b"127.0.0.1:8080", b"127.0.0.2:8080"),
    lambda raw: raw.replace(b"127.0.0.1:8080", b"127.0.0.1:8081"),
    lambda raw: raw.replace(b"Connection: close", b"Connection: keep-alive"),
    lambda raw: raw.replace(b"Accept-Encoding: identity", b"Accept-Encoding: gzip"),
    lambda raw: raw.replace(b"Accept: */*", b"Accept: application/json"),
    lambda raw: raw.replace(b"Accept-Language: en", b"Accept-Language: fr"),
    lambda raw: raw.replace(fixture.NUCLEI_USER_AGENT.encode(), b"another-client"),
    lambda raw: raw.replace(b"Host: ", b"Host:\t"),
    lambda raw: raw.replace(b"Host: ", b"Host : "),
    lambda raw: raw.replace(b"\r\n", b"\n"),
    lambda raw: raw.replace(b"Connection: close\r\n", b""),
    lambda raw: raw.replace(b"Accept: */*\r\n", b""),
    lambda raw: raw.replace(b"Accept-Language: en\r\n", b""),
    lambda raw: raw.replace(b"Accept-Encoding: identity", b"Host: 127.0.0.1:8080"),
))
def test_changed_missing_or_ambiguous_headers_are_rejected_before_progress(change):
    connection, counted = Connection(change(fixture.NUCLEI_REQUEST)), []
    with pytest.raises(ValueError):
        fixture.serve(connection, case="nuclei-index", deadline=time.monotonic() + 5,
            on_request=lambda: counted.append(1))
    assert counted == [] and connection.output == b""


@pytest.mark.parametrize("header", (b"Authorization: Basic secret", b"Proxy-Authorization: Basic secret",
    b"Cookie: session=secret", b"Content-Length: 0", b"Content-Length: 3",
    b"Transfer-Encoding: chunked", b"X-HTTP-Method-Override: DELETE", b"Accept: */*"))
def test_extra_headers_and_payload_authority_are_not_accepted(header):
    raw = fixture.NUCLEI_REQUEST.replace(b"\r\n\r\n", b"\r\n" + header + b"\r\n\r\n")
    with pytest.raises(ValueError):
        execute(raw=raw)


def test_each_truncated_request_fails_before_count_or_response():
    for length in range(len(fixture.NUCLEI_REQUEST)):
        connection, counted = Connection(fixture.NUCLEI_REQUEST[:length]), []
        with pytest.raises(ValueError):
            fixture.serve(connection, case="nuclei-index", deadline=time.monotonic() + 5,
                on_request=lambda: counted.append(1))
        assert counted == [] and not connection.output


def test_request_budget_stops_reading_and_pipelining_never_adds_work():
    connection = Connection(b"x" * (fixture.NUCLEI_MAX_REQUEST_BYTES + 20))
    with pytest.raises(ValueError, match="request_limit"):
        fixture.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == fixture.NUCLEI_MAX_REQUEST_BYTES
    extra = b"DELETE /private/ HTTP/1.1\r\n\r\n"
    connection, counted, _, _ = execute(raw=fixture.NUCLEI_REQUEST + extra)
    assert counted == [1] and connection.input.read() == extra
    with pytest.raises(ValueError):
        fixture.validate_request(fixture.NUCLEI_REQUEST + extra)


def test_partial_write_failure_never_records_unsent_suffix():
    connection, recorded = Connection(write_size=11), []
    send = connection.send
    def interrupted(raw):
        if connection.output:
            raise BrokenPipeError("peer closed")
        return send(raw)
    connection.send = interrupted
    with pytest.raises(BrokenPipeError):
        fixture.serve(connection, case="nuclei-index", deadline=time.monotonic() + 5,
            on_request=lambda: None, on_response=recorded.append)
    assert b"".join(recorded) == bytes(connection.output) == fixture.response("nuclei-index")[:11]


@pytest.mark.parametrize("returned", (0, -1, True, None, 99999))
def test_invalid_write_progress_cannot_be_recorded(returned):
    connection, recorded = Connection(), []
    connection.send = lambda raw: returned
    with pytest.raises(ValueError, match="response_write"):
        fixture.send_response(connection, b"finite", time.monotonic() + 5, on_response=recorded.append)
    assert recorded == []


def test_stall_retains_only_valid_request_progress(monkeypatch):
    waits = []
    monkeypatch.setattr(fixture.time, "sleep", waits.append)
    connection, counted, chunks, result = execute("nuclei-stalled")
    assert counted == [1] and chunks == [] and connection.output == b""
    assert result == {"response_bytes_sent": 0, "response_send_complete": False}
    assert len(waits) == 1 and 0 < waits[0] <= 5


def test_deadline_is_checked_during_reads_and_each_partial_write(monkeypatch):
    connection, counted = Connection(), []
    clock = iter((0, .1, 5))
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case="nuclei-index", deadline=1, on_request=lambda: counted.append(1))
    assert counted == [] and not connection.output
    monkeypatch.setattr(fixture.time, "monotonic", lambda: 0)
    connection, recorded = Connection(write_size=3), []
    def records_then_expires(raw):
        recorded.append(raw)
        monkeypatch.setattr(fixture.time, "monotonic", lambda: 5)
    with pytest.raises(ValueError, match="deadline"):
        fixture.send_response(connection, b"abcdef", 1, on_response=records_then_expires)
    assert recorded == [b"abc"] and connection.output == b"abc"


@pytest.mark.parametrize("value", (None, True, "nuclei-unknown", "http-options-ok"))
def test_invalid_case_fails_before_connection_activity(value):
    connection = Connection()
    with pytest.raises(ValueError, match="invalid_nuclei_fixture_case"):
        fixture.serve(connection, case=value, deadline=time.monotonic() + 5,
            on_request=lambda: pytest.fail("unexpected request"))
    assert connection.input.tell() == 0 and connection.timeouts == []


def test_standalone_fixture_import_requires_no_package_or_site_runtime():
    code = "import importlib.util; s=importlib.util.spec_from_file_location('fixture',%r); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert len(m.NUCLEI_CASES)==13" % str(Path(fixture.__file__))
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
