"""Finite OPTIONS owner protocol tests; no socket, login or web backend."""

import io
from pathlib import Path
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_http_options_fixture as server
from recon_cockpit.secure_agent import network_tools_http_options_parser as parser


class Connection:
    def __init__(self, raw=None):
        self.input = io.BytesIO(fixture.HTTP_OPTIONS_REQUEST if raw is None else raw)
        self.output, self.timeouts, self.writes = bytearray(), [], []

    def recv(self, count):
        return self.input.read(count)

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, raw):
        self.writes.append(raw)
        self.output.extend(raw)


def serve(case="http-options-ok", raw=None):
    connection, calls = Connection(raw), []
    server.serve(connection, case=case, deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    return connection, calls


@pytest.mark.parametrize("case", [case for case in fixture.HTTP_OPTIONS_CASES
                                  if case != "http-options-stalled"])
def test_exact_options_counts_once_before_finite_response(case):
    connection, calls = Connection(), []
    send = connection.sendall
    def send_after_count(raw):
        assert calls == [1]
        send(raw)
    connection.sendall = send_after_count
    server.serve(connection, case=case, deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    assert calls == [1] and connection.input.read() == b""
    assert bytes(connection.output) == fixture.http_options_response(case)
    assert len(connection.output) <= fixture.HTTP_OPTIONS_MAX_RESPONSE_BYTES
    assert all(0 < value <= 2 for value in connection.timeouts)
    assert (fixture.HOSTILE_NOTE.encode() in connection.output) is case.endswith("-injected")
    assert fixture.tool_for_case(case) == "curl_http_options_v1"


@pytest.mark.parametrize("method", [b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"PATCH", b"TRACE", b"CONNECT", b"options"])
def test_no_other_method_can_be_invoked(method):
    connection, calls = Connection(fixture.HTTP_OPTIONS_REQUEST.replace(b"OPTIONS", method, 1)), []
    with pytest.raises(ValueError, match="fixed_options_only"):
        server.serve(connection, case="http-options-ok", deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b"HTTP/1.1", b"HTTP/1.0", 1),
    lambda raw: raw.replace(b"Host: 127.0.0.1:8080", b"Host: 127.0.0.2:8080"),
    lambda raw: raw.replace(b"Host: 127.0.0.1:8080", b"Host: 127.0.0.1:8081"),
    lambda raw: raw.replace(b"Host: 127.0.0.1:8080", b"Host: harbordesk.test:8080"),
    lambda raw: raw.replace(b"Connection: close", b"Connection: keep-alive"),
    lambda raw: raw.replace(fixture.HTTP_OPTIONS_USER_AGENT.encode(), b"custom"),
    lambda raw: raw.replace(b"Accept: */*", b"Accept: application/json"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nContent-Length: 0\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nContent-Length: 4\r\n\r\nbody"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nAuthorization: Basic secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nProxy-Authorization: Basic secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nCookie: session=secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nExpect: 100-continue\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nX-HTTP-Method-Override: DELETE\r\n\r\n"),
    lambda raw: raw.replace(b"\r\nAccept: */*", b"\r\nHost: 127.0.0.1:8080"),
    lambda raw: raw.replace(b"\r\nAccept: */*", b""),
    lambda raw: raw.replace(b"\r\n", b"\n"),
    lambda raw: raw.replace(b"Host: ", b"Host\t: "),
    lambda raw: raw.replace(b"Host: ", b"Host:\t"),
    lambda raw: raw.replace(b"OPTIONS /", b"OPTIONS http://127.0.0.1:8080/", 1),
])
def test_unreviewed_credentialed_and_ambiguous_requests_are_refused_before_count(change):
    connection, calls = Connection(change(fixture.HTTP_OPTIONS_REQUEST)), []
    with pytest.raises(ValueError):
        server.serve(connection, case="http-options-ok", deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("path", ["*", "/", "/harbordesk/private", "/wsman", "/harbordesk/portal.html?x=1",
                                  "/harbordesk/../admin", "/harbordesk/%70ortal.html"])
def test_only_the_fixed_resource_can_be_selected(path):
    with pytest.raises(ValueError, match="fixed_options_only"):
        serve(raw=fixture.HTTP_OPTIONS_REQUEST.replace(fixture.HTTP_OPTIONS_PATH.encode(), path.encode(), 1))


def test_every_truncated_request_is_rejected_without_response_or_count():
    for length in range(len(fixture.HTTP_OPTIONS_REQUEST)):
        connection, calls = Connection(fixture.HTTP_OPTIONS_REQUEST[:length]), []
        with pytest.raises(ValueError):
            server.serve(connection, case="http-options-ok", deadline=time.monotonic() + 5,
                         on_request=lambda: calls.append(1))
        assert not calls and not connection.output


def test_request_limit_is_enforced_before_reading_more_bytes():
    connection = Connection(b"X" * 4096 + b"\r\n\r\n")
    with pytest.raises(ValueError, match="request_limit"):
        server.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == fixture.HTTP_OPTIONS_MAX_REQUEST_BYTES


def test_owner_does_not_interpret_pipelined_requests():
    # Framing ends the sole OPTIONS request. Bytes after it never become work.
    trailing = fixture.HTTP_OPTIONS_REQUEST.replace(b"OPTIONS", b"DELETE", 1)
    connection, calls = serve(raw=fixture.HTTP_OPTIONS_REQUEST + trailing)
    assert calls == [1] and connection.input.read() == trailing
    assert bytes(connection.output) == fixture.http_options_response("http-options-ok")


def test_request_deadline_is_rechecked_for_every_byte(monkeypatch):
    connection, calls = Connection(), []
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        server.serve(connection, case="http-options-ok", deadline=1,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def test_fragmentation_preserves_bytes_and_checks_each_write_deadline(monkeypatch):
    connection, calls = serve("http-options-fragmented")
    assert calls == [1] and len(connection.writes) > 1
    assert all(0 < len(chunk) <= 7 for chunk in connection.writes)
    assert bytes(connection.output) == fixture.http_options_response("http-options-ok")
    connection, calls = Connection(), []
    def expires_after_first_write(_):
        monkeypatch.setattr(server.time, "monotonic", lambda: 5)
    connection.sendall = expires_after_first_write
    monkeypatch.setattr(server.time, "monotonic", lambda: 0)
    with pytest.raises(ValueError, match="deadline"):
        server.serve(connection, case="http-options-fragmented", deadline=1,
                     on_request=lambda: calls.append(1))
    assert calls == [1]


def test_stall_is_one_real_request_then_only_a_bounded_wait(monkeypatch):
    waits = []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    connection, calls = serve("http-options-stalled")
    assert calls == [1] and not connection.output
    assert len(waits) == 1 and 0 < waits[0] <= 5
    assert fixture.http_options_response("http-options-stalled") is None


@pytest.mark.parametrize("case", fixture.HTTP_OPTIONS_SUCCESS_CASES)
def test_useful_wire_has_unambiguous_finite_response_framing(case):
    raw = fixture.http_options_response(case)
    head, separator, body = raw.partition(b"\r\n\r\n")
    assert separator and len(raw) < 8192
    assert b"Connection: close\r\n" in raw
    assert b"Transfer-Encoding:" not in raw and b"Content-Encoding:" not in raw
    if case == "http-options-no-content":
        assert head.startswith(b"HTTP/1.1 204 ") and body == b""
        assert b"Content-Length:" not in head
    else:
        lengths = [line.partition(b": ")[2] for line in head.split(b"\r\n")
                   if line.startswith(b"Content-Length:")]
        assert lengths == [str(len(body)).encode()] and 0 < len(body) <= 4096


def test_absent_and_empty_allow_are_distinct_and_401_and_405_keep_required_headers():
    absent = fixture.http_options_response("http-options-absent-allow")
    empty = fixture.http_options_response("http-options-empty-allow")
    assert absent.startswith(b"HTTP/1.1 200 ") and b"Allow:" not in absent
    assert empty.startswith(b"HTTP/1.1 200 ") and b"Allow: \r\n" in empty
    authentication = fixture.http_options_response("http-options-auth-required")
    assert authentication.startswith(b"HTTP/1.1 401 ")
    assert b'WWW-Authenticate: Basic realm="HarborDesk owned"\r\n' in authentication
    assert b'WWW-Authenticate: Bearer realm="HarborDesk owned"\r\n' in authentication
    unsupported = fixture.http_options_response("http-options-method-not-allowed")
    assert unsupported.startswith(b"HTTP/1.1 405 ") and b"Allow: GET, HEAD, OPTIONS\r\n" in unsupported


def test_negative_wire_exercises_malformed_truncated_and_output_pressure():
    assert b"Allow: GET, BAD METHOD\r\n" in fixture.http_options_response("http-options-malformed")
    raw = fixture.http_options_response("http-options-truncated")
    header, _, body = raw.partition(b"\r\n\r\n")
    assert b"Content-Length: " + str(len(body) + 1).encode() + b"\r\n" in header
    pressure = fixture.http_options_response("http-options-output-limit")
    assert 8192 < len(pressure) <= fixture.HTTP_OPTIONS_MAX_RESPONSE_BYTES
    assert b"X-Owned-Padding: " in pressure


@pytest.mark.parametrize("case", fixture.HTTP_OPTIONS_CASES)
def test_finite_response_labels_match_independent_parser_acceptance(case):
    response = fixture.http_options_response(case)
    if case not in fixture.HTTP_OPTIONS_SUCCESS_CASES:
        with pytest.raises(ValueError):
            parser.parse_output(response or b"")
        return
    result = parser.parse_output(response)
    assert result["service_identity_verified"] is False
    assert fixture.HOSTILE_NOTE not in repr(result)
    assert "HarborDesk owned" not in repr(result)
    assert result["auth_schemes"] == (["basic", "bearer"] if case == "http-options-auth-required" else [])
    assert result["allow_present"] is (case != "http-options-absent-allow")
    assert result["allowed_methods"] == ([] if case in (
        "http-options-absent-allow", "http-options-empty-allow") else ["GET", "HEAD", "OPTIONS"])


@pytest.mark.parametrize("case, destination", [
    ("http-options-redirect-ip", b"127.0.0.2:8080"),
    ("http-options-redirect-port", b"127.0.0.1:8081"),
])
def test_redirects_advertise_only_the_compiled_negative_destination(case, destination):
    connection, calls = serve(case)
    assert calls == [1] and bytes(connection.output).startswith(b"HTTP/1.1 302 ")
    assert b"Location: http://" + destination + b"/harbordesk/portal.html\r\n" in connection.output
    assert bytes(connection.output).endswith(b"\r\n\r\n")


@pytest.mark.parametrize("case", [None, 1, b"http-options-ok", "winrm-ok", "http-options-unknown"])
def test_invalid_case_never_reads_a_request(case):
    connection = Connection()
    with pytest.raises(ValueError):
        server.serve(connection, case=case, deadline=time.monotonic() + 5,
                     on_request=lambda: pytest.fail("request counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        fixture.http_options_response(case)


def test_owner_loads_under_isolated_python_without_repository_on_path(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_http_options_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.HTTP_OPTIONS_CASES) == 14
assert module.fixture.HTTP_OPTIONS_REQUEST.startswith(b'OPTIONS /harbordesk/portal.html HTTP/1.1')
assert b'Allow: GET, HEAD, OPTIONS' in module.fixture.http_options_response('http-options-ok')
print('isolated owner import ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
        str(Path(server.__file__).resolve())], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated owner import ready\n" and result.stderr == ""
