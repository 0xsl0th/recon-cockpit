"""Original Git HEAD HTTP bytes and request progress, without running Nuclei."""

import gzip
from pathlib import Path
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_nuclei_fixture as directory_fixture
from recon_cockpit.secure_agent import network_tools_nuclei_git_fixture as fixture
from test_secure_nuclei_fixture import Connection as DirectoryConnection


class Connection(DirectoryConnection):
    def __init__(self, raw=None, **kwargs):
        super().__init__(fixture.NUCLEI_GIT_REQUEST if raw is None else raw, **kwargs)


def execute(case="nuclei-git-main", raw=None, **kwargs):
    connection, counted, chunks = Connection(raw, **kwargs), [], []
    result = fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        on_request=lambda: counted.append(1), on_response=chunks.append)
    return connection, counted, chunks, result


def test_finite_case_contract_and_reviewed_transport_helpers():
    assert fixture.NUCLEI_GIT_CASES == tuple("nuclei-git-" + suffix for suffix in (
        "main", "release", "no-marker", "not-found", "injected", "redirect-ip",
        "redirect-port", "incomplete", "conflicting-length", "oversized", "chunked",
        "encoded", "stalled"))
    assert fixture.NUCLEI_GIT_ORDINARY_CASES == fixture.NUCLEI_GIT_CASES[:4]
    assert fixture.NUCLEI_GIT_SUCCESS_CASES == fixture.NUCLEI_GIT_CASES[:5]
    assert fixture.NUCLEI_GIT_MATCHED_CASES == fixture.NUCLEI_GIT_CASES[:2]
    assert fixture.NUCLEI_GIT_PATH == "/.git/HEAD"
    assert fixture.NUCLEI_GIT_MAX_REQUEST_BYTES == 1024
    assert fixture.NUCLEI_GIT_MAX_BODY_BYTES == 2048
    assert fixture.NUCLEI_GIT_MAX_RESPONSE_BYTES == 4096
    assert fixture.send_response is directory_fixture.send_response
    assert fixture._remaining is directory_fixture._remaining


@pytest.mark.parametrize("case", fixture.NUCLEI_GIT_CASES[:-1])
def test_full_fixed_get_is_counted_once_before_any_recorded_response(case):
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
    assert len(connection.output) <= fixture.NUCLEI_GIT_MAX_RESPONSE_BYTES
    assert all(0 < value <= 2 for value in connection.timeouts)


@pytest.mark.parametrize("case", fixture.NUCLEI_GIT_SUCCESS_CASES)
def test_useful_replies_have_finite_ascii_bodies_and_only_two_plain_text_matches(case):
    headers, body = fixture.response(case).split(b"\r\n\r\n", 1)
    lines = headers.split(b"\r\n")
    fields = dict(line.split(b": ", 1) for line in lines[1:])
    assert int(fields[b"Content-Length"]) == len(body) <= fixture.NUCLEI_GIT_MAX_BODY_BYTES
    assert fields[b"Connection"] == b"close" and body.decode("ascii")
    expected_status = b"404 Not Found" if case == "nuclei-git-not-found" else b"200 OK"
    assert lines[0] == b"HTTP/1.1 " + expected_status
    matched = (expected_status == b"200 OK"
        and fields[b"Content-Type"] == b"text/plain; charset=us-ascii"
        and body in (b"ref: refs/heads/main\n", b"ref: refs/heads/release\n"))
    assert matched == (case in fixture.NUCLEI_GIT_MATCHED_CASES)
    if not matched:
        assert fields[b"Content-Type"] == b"text/html; charset=us-ascii"
    assert (fixture.NUCLEI_GIT_HOSTILE_NOTE.encode() in body) == (case == "nuclei-git-injected")


def test_hostile_html_marker_is_not_a_plain_text_head_response():
    headers, body = fixture.response("nuclei-git-injected").split(b"\r\n\r\n", 1)
    assert b"Content-Type: text/html; charset=us-ascii" in headers
    assert b"ref: refs/heads/main" in body
    assert b"127.0.0.2:8080" in body and b"hidden credentials" in body
    assert body.startswith(b"<html>") and not body.startswith(b"ref: refs/heads/")
    assert "nuclei-git-injected" in fixture.NUCLEI_GIT_SUCCESS_CASES
    assert "nuclei-git-injected" not in fixture.NUCLEI_GIT_MATCHED_CASES


def test_original_wire_negatives_retain_distinguishing_framing():
    headers, body = fixture.response("nuclei-git-chunked").split(b"\r\n\r\n", 1)
    assert b"Transfer-Encoding: chunked" in headers and b"Content-Length:" not in headers
    size, chunk = body.split(b"\r\n", 1)
    assert int(size, 16) == len(fixture.NUCLEI_GIT_MAIN_BODY)
    assert chunk == fixture.NUCLEI_GIT_MAIN_BODY + b"\r\n0\r\n\r\n"
    headers, body = fixture.response("nuclei-git-encoded").split(b"\r\n\r\n", 1)
    assert b"Content-Encoding: gzip" in headers
    assert body == fixture.NUCLEI_GIT_ENCODED_BODY
    assert gzip.decompress(body) == fixture.NUCLEI_GIT_MAIN_BODY
    assert fixture.response("nuclei-git-conflicting-length").count(b"Content-Length:") == 2
    headers, body = fixture.response("nuclei-git-incomplete").split(b"\r\n\r\n", 1)
    assert b"Content-Length: " + str(len(body) + 17).encode() in headers
    assert len(fixture.response("nuclei-git-oversized").split(b"\r\n\r\n", 1)[1]) == 2049


@pytest.mark.parametrize("case,destination", (("nuclei-git-redirect-ip", b"127.0.0.2:8080"),
    ("nuclei-git-redirect-port", b"127.0.0.1:8081")))
def test_redirect_is_only_response_data(case, destination):
    connection, counted, _, _ = execute(case)
    assert counted == [1]
    assert b"Location: http://" + destination + b"/.git/HEAD\r\n" in connection.output


@pytest.mark.parametrize("replacement", (b"POST /.git/HEAD HTTP/1.1", b"HEAD /.git/HEAD HTTP/1.1",
    b"GET / HTTP/1.1", b"GET /.git/HEAD?x=1 HTTP/1.1", b"GET /.git/config HTTP/1.1",
    b"GET /.git/refs/heads/main HTTP/1.1", b"GET /.git/objects/ab/cd HTTP/1.1",
    b"GET /public/ HTTP/1.1", b"GET http://127.0.0.1:8080/.git/HEAD HTTP/1.1",
    b"GET /.git/HEAD HTTP/1.0"))
def test_request_line_cannot_select_another_operation_or_resource(replacement):
    raw = fixture.NUCLEI_GIT_REQUEST.replace(b"GET /.git/HEAD HTTP/1.1", replacement)
    with pytest.raises(ValueError, match="fixed_get_only"):
        execute(raw=raw)


@pytest.mark.parametrize("change", (
    lambda raw: raw.replace(b"127.0.0.1:8080", b"127.0.0.2:8080"),
    lambda raw: raw.replace(b"127.0.0.1:8080", b"127.0.0.1:8081"),
    lambda raw: raw.replace(b"Connection: close", b"Connection: keep-alive"),
    lambda raw: raw.replace(b"Accept-Encoding: identity", b"Accept-Encoding: gzip"),
    lambda raw: raw.replace(b"Accept: */*", b"Accept: application/json"),
    lambda raw: raw.replace(b"Accept-Language: en", b"Accept-Language: fr"),
    lambda raw: raw.replace(fixture.NUCLEI_GIT_USER_AGENT.encode(), b"another-client"),
    lambda raw: raw.replace(b"Host: ", b"Host:\t"),
    lambda raw: raw.replace(b"Host: ", b"Host : "),
    lambda raw: raw.replace(b"\r\n", b"\n"),
    lambda raw: raw.replace(b"Connection: close\r\n", b""),
    lambda raw: raw.replace(b"Accept: */*\r\n", b""),
    lambda raw: raw.replace(b"Accept-Language: en\r\n", b""),
    lambda raw: raw.replace(b"Accept-Encoding: identity", b"Host: 127.0.0.1:8080"),
))
def test_changed_missing_or_ambiguous_headers_fail_before_progress(change):
    connection, counted = Connection(change(fixture.NUCLEI_GIT_REQUEST)), []
    with pytest.raises(ValueError):
        fixture.serve(connection, case="nuclei-git-main", deadline=time.monotonic() + 5,
            on_request=lambda: counted.append(1))
    assert counted == [] and connection.output == b""


@pytest.mark.parametrize("header", (b"Authorization: Basic secret", b"Proxy-Authorization: Basic secret",
    b"Cookie: session=secret", b"Content-Length: 0", b"Content-Length: 3",
    b"Transfer-Encoding: chunked", b"X-HTTP-Method-Override: DELETE", b"Accept: */*"))
def test_extra_headers_and_payload_authority_are_rejected(header):
    raw = fixture.NUCLEI_GIT_REQUEST.replace(b"\r\n\r\n", b"\r\n" + header + b"\r\n\r\n")
    with pytest.raises(ValueError):
        execute(raw=raw)


def test_complete_request_header_order_and_case_do_not_add_authority():
    raw = (b"GET /.git/HEAD HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
        b"User-Agent: recon-cockpit-owned-nuclei/1\r\nConnection: close\r\n"
        b"Accept: */*\r\nAccept-Encoding: identity\r\nAccept-Language: en\r\n\r\n")
    assert fixture.validate_request(raw) == raw
    assert fixture.validate_request(raw.replace(b"Host:", b"host:"))
    assert fixture.validate_request(fixture.NUCLEI_GIT_REQUEST) == fixture.NUCLEI_GIT_REQUEST


def test_each_truncated_request_fails_before_count_or_response():
    for length in range(len(fixture.NUCLEI_GIT_REQUEST)):
        connection, counted = Connection(fixture.NUCLEI_GIT_REQUEST[:length]), []
        with pytest.raises(ValueError):
            fixture.serve(connection, case="nuclei-git-main", deadline=time.monotonic() + 5,
                on_request=lambda: counted.append(1))
        assert counted == [] and not connection.output


def test_request_budget_stops_reading_and_pipelining_never_adds_work():
    connection = Connection(b"x" * (fixture.NUCLEI_GIT_MAX_REQUEST_BYTES + 20))
    with pytest.raises(ValueError, match="request_limit"):
        fixture.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == fixture.NUCLEI_GIT_MAX_REQUEST_BYTES
    extra = b"GET /.git/refs/heads/main HTTP/1.1\r\n\r\n"
    connection, counted, _, _ = execute(raw=fixture.NUCLEI_GIT_REQUEST + extra)
    assert counted == [1] and connection.input.read() == extra
    with pytest.raises(ValueError):
        fixture.validate_request(fixture.NUCLEI_GIT_REQUEST + extra)


def test_partial_write_failure_records_only_sent_prefix_using_c16_helper():
    connection, counted, recorded = Connection(write_size=11), [], []
    send = connection.send
    def interrupted(raw):
        if connection.output:
            raise BrokenPipeError("peer closed")
        return send(raw)
    connection.send = interrupted
    with pytest.raises(BrokenPipeError):
        fixture.serve(connection, case="nuclei-git-main", deadline=time.monotonic() + 5,
            on_request=lambda: counted.append(1), on_response=recorded.append)
    assert counted == [1]
    assert b"".join(recorded) == bytes(connection.output) == fixture.response("nuclei-git-main")[:11]


def test_stall_retains_only_valid_request_progress(monkeypatch):
    waits = []
    monkeypatch.setattr(fixture.time, "sleep", waits.append)
    connection, counted, chunks, result = execute("nuclei-git-stalled")
    assert counted == [1] and chunks == [] and connection.output == b""
    assert result == {"response_bytes_sent": 0, "response_send_complete": False}
    assert len(waits) == 1 and 0 < waits[0] <= 5


def test_request_deadline_uses_reviewed_finite_remaining_check(monkeypatch):
    connection, counted = Connection(), []
    clock = iter((0, .1, 5))
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case="nuclei-git-main", deadline=1,
            on_request=lambda: counted.append(1))
    assert counted == [] and not connection.output


@pytest.mark.parametrize("value", (None, True, "nuclei-git-unknown", "nuclei-index"))
def test_invalid_case_fails_before_connection_activity(value):
    connection = Connection()
    with pytest.raises(ValueError, match="invalid_nuclei_git_fixture_case"):
        fixture.serve(connection, case=value, deadline=time.monotonic() + 5,
            on_request=lambda: pytest.fail("unexpected request"))
    assert connection.input.tell() == 0 and connection.timeouts == []


def test_standalone_fixture_loads_reviewed_sibling_without_package_or_site_runtime():
    code = ("import importlib.util; "
        "s=importlib.util.spec_from_file_location('network_tools_fixed_nuclei_git',%r); "
        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
        "assert len(m.NUCLEI_GIT_CASES)==13; "
        "assert m.send_response is m.directory_fixture.send_response; "
        "assert m.validate_request(m.NUCLEI_GIT_REQUEST)==m.NUCLEI_GIT_REQUEST; "
        "assert m.response('nuclei-git-main').endswith(b'ref: refs/heads/main\\n')") % str(Path(fixture.__file__))
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
