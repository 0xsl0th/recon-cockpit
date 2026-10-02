"""Finite HTTP metadata protocol tests without sockets or a service backend."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_http_metadata_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract


class Connection:
    def __init__(self, request=b""):
        self.input = io.BytesIO(request)
        self.output = bytearray()
        self.timeouts = []

    def recv(self, count):
        return self.input.read(count)

    def sendall(self, value):
        self.output.extend(value)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)


def request(case):
    path = fixture.HTTP_METADATA_PATHS[fixture.tool_for_case(case)]
    return ("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
            "User-Agent: recon-cockpit-b6/1\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()


def serve(case, raw=None):
    connection, calls = Connection(request(case) if raw is None else raw), []
    server.serve(connection, case=case, deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    return connection, calls


@pytest.mark.parametrize("case", [case for case in fixture.HTTP_METADATA_CASES if not case.endswith("-stalled")])
def test_one_fixed_get_yields_exact_compiled_response_and_one_query(case):
    connection, calls = serve(case)
    assert calls == [1]
    assert bytes(connection.output) == fixture.http_metadata_response(case)
    assert len(connection.output) <= 8192
    assert all(0 < value <= 2 for value in connection.timeouts)
    assert (fixture.HOSTILE_NOTE.encode() in connection.output) is case.endswith("-injected")


@pytest.mark.parametrize("case", ["docker-ping-ok", "docker-version-ok", "winrm-ok"])
@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b"GET ", b"POST ", 1),
    lambda raw: raw.replace(b"GET ", b"HEAD ", 1),
    lambda raw: raw.replace(b"HTTP/1.1", b"HTTP/1.0", 1),
    lambda raw: raw.replace(b"Host: 127.0.0.1:8080", b"Host: 127.0.0.2:8080"),
    lambda raw: raw.replace(b"Host: 127.0.0.1:8080", b"Host: 127.0.0.1:8081"),
    lambda raw: raw.replace(b"Connection: close", b"Connection: keep-alive"),
    lambda raw: raw.replace(b"User-Agent: recon-cockpit-b6/1", b"User-Agent: custom"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nContent-Length: 0\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nAuthorization: Negotiate secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nCookie: key=secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\nAccept: */*", b"\r\nHost: 127.0.0.1:8080"),
    lambda raw: raw.replace(b"\r\n", b"\n"),
    lambda raw: raw.replace(b"GET /", b"GET http://127.0.0.1:8080/", 1),
    lambda raw: raw.replace(b" HTTP/1.1", b"?action=exec HTTP/1.1", 1),
])
def test_mutating_credentialed_redirected_and_ambiguous_requests_are_refused(case, change):
    connection, calls = Connection(change(request(case))), []
    with pytest.raises(ValueError):
        server.serve(connection, case=case, deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert calls == [] and not connection.output


@pytest.mark.parametrize("path", ["/containers/json", "/containers/create", "/info", "/exec", "/version/../containers", "/_ping?x=1", "/wsman", "/"])
def test_ping_cannot_select_other_metadata_or_backend_paths(path):
    with pytest.raises(ValueError, match="fixed_get_only"):
        serve("docker-ping-ok", request("docker-ping-ok").replace(b"/_ping", path.encode(), 1))


@pytest.mark.parametrize("raw", [b"", b"GET /_ping HTTP/1.1\r\n", b"X" * 2048 + b"\r\n\r\n"])
def test_request_is_bounded_and_requires_complete_crlf_framing(raw):
    with pytest.raises(ValueError):
        serve("docker-ping-ok", raw)


def test_read_deadline_is_rechecked_for_every_byte(monkeypatch):
    connection, calls = Connection(request("docker-ping-ok")), []
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        server.serve(connection, case="docker-ping-ok", deadline=1, on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("case", ["docker-ping-stalled", "docker-version-stalled", "winrm-stalled"])
def test_stalled_reply_follows_exactly_one_validated_query(monkeypatch, case):
    waits = []
    monkeypatch.setattr(server.time, "sleep", lambda duration: waits.append(duration))
    connection, calls = serve(case)
    assert calls == [1] and not connection.output and len(waits) == 1 and 0 < waits[0] <= 5


def test_http_fixture_has_no_empty_ping_or_invented_version_and_auth_results():
    assert fixture.http_metadata_response("docker-ping-ok").endswith(b"\r\n\r\nOK")
    assert fixture.http_metadata_response("docker-ping-unavailable").startswith(b"HTTP/1.1 503 ")
    assert fixture.http_metadata_response("docker-version-empty").endswith(b"\r\n\r\n{}")
    raw = fixture.http_metadata_response("winrm-no-auth")
    assert raw.startswith(b"HTTP/1.1 405 ") and b"Allow: POST\r\n" in raw
    assert b"WWW-Authenticate:" not in raw and raw.endswith(b"\r\n\r\n")
    metadata = json.loads(fixture.http_metadata_response("docker-version-ok").partition(b"\r\n\r\n")[2])
    assert metadata == fixture.DOCKER_VERSION_METADATA


@pytest.mark.parametrize("case", fixture.HTTP_METADATA_CASES)
def test_b6_spec_pins_response_bytes_and_preserves_one_request_connection_bounds(case):
    spec = contract.spec(case)
    assert spec["response_sha256"] == (None if case.endswith("-stalled") else
        hashlib.sha256(fixture.http_metadata_response(case)).hexdigest())
    expected = contract.identity(case, str(uuid4()))
    context = {"identity": expected, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, expected) == context
    for changes in ({"connection_count": 2}, {"request_count": 2}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **changes}, expected)


def test_public_specs_do_not_import_owner_implementation(monkeypatch):
    import builtins
    original = builtins.__import__
    def reject_owner(name, *args, **kwargs):
        assert "http_metadata_fixture" not in name
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", reject_owner)
    for case in fixture.HTTP_METADATA_CASES:
        assert contract.spec(case)["external_egress"] is False


def test_owner_file_loads_under_isolated_python_outside_repository(tmp_path):
    # Native owners are bootstrapped with -I -S and importlib file loading,
    # rather than package imports or the working directory on sys.path.
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_http_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.fixture.http_metadata_response('docker-ping-ok').endswith(b'\\r\\n\\r\\nOK')
assert len(module.fixture.HTTP_METADATA_CASES) == 21
print('isolated owner import ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
        str(Path(server.__file__).resolve())], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated owner import ready\n" and result.stderr == ""
