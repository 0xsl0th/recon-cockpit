"""Fixed passive HTTP fixtures, protocol counters and compatibility without sockets."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_whatweb_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


class Connection:
    def __init__(self, request=fixture.WHATWEB_REQUEST, *, chunk_size=2048):
        self.input, self.output = io.BytesIO(request), bytearray()
        self.chunk_size, self.timeouts, self.closed = chunk_size, [], False

    def recv(self, count):
        return self.input.read(min(count, self.chunk_size))

    def sendall(self, raw):
        self.output.extend(raw)

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


def serve(case, request=fixture.WHATWEB_REQUEST, *, chunk_size=2048):
    connection, calls = Connection(request, chunk_size=chunk_size), []
    server.serve(connection, case=case, deadline=time.monotonic() + 5,
                 on_request=lambda: calls.append(1))
    return connection, calls


@pytest.mark.parametrize("case", [case for case in fixture.WHATWEB_CASES if case != "whatweb-stalled"])
@pytest.mark.parametrize("chunk_size", [1, 7, 2048])
def test_one_validated_get_counts_once_even_for_negative_reply(case, chunk_size):
    connection, calls = serve(case, chunk_size=chunk_size)
    assert calls == [1] and bytes(connection.output) == fixture.whatweb_response(case)
    assert connection.input.read() == b""
    assert all(0 < value <= 2 for value in connection.timeouts)


def test_stall_counts_validated_get_and_waits_only_for_remaining_deadline(monkeypatch):
    waits = []
    monkeypatch.setattr(server.time, "sleep", waits.append)
    connection, calls = serve("whatweb-stalled")
    assert calls == [1] and not connection.output
    assert len(waits) == 1 and 0 < waits[0] <= 5


@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b"GET ", b"POST ", 1),
    lambda raw: raw.replace(b"GET ", b"HEAD ", 1),
    lambda raw: raw.replace(b"HTTP/1.1", b"HTTP/1.0", 1),
    lambda raw: raw.replace(b"/harbordesk/portal.html", b"/private", 1),
    lambda raw: raw.replace(b"/harbordesk/portal.html", b"/harbordesk/portal.html?scan=1", 1),
    lambda raw: raw.replace(b"GET /", b"GET http://127.0.0.1:8080/", 1),
    lambda raw: raw.replace(b"127.0.0.1:8080", b"127.0.0.2:8080"),
    lambda raw: raw.replace(b"127.0.0.1:8080", b"127.0.0.1:8081"),
    lambda raw: raw.replace(b"recon-cockpit-c3/1", b"unreviewed"),
    lambda raw: raw.replace(b"Connection: close", b"Connection: keep-alive"),
    lambda raw: raw.replace(b"Accept-Encoding: identity", b"Accept-Encoding: gzip"),
    lambda raw: raw.replace(b"Accept: */*", b"Accept: text/html"),
    lambda raw: raw.replace(b"Accept: */*", b"Host: 127.0.0.1:8080"),
    lambda raw: raw.replace(b"Accept: */*", b"Accept : */*"),
    lambda raw: raw.replace(b"Accept: */*", b"Accept:\t*/*"),
    lambda raw: raw.replace(b"\r\nAccept: */*", b""),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nContent-Length: 0\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nAuthorization: Basic secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nCookie: key=secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nProxy-Authorization: Basic secret\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n", b"\n"),
    lambda raw: raw + b"body",
    lambda raw: raw * 2,
])
def test_mutation_authority_credentials_extra_requests_and_ambiguity_are_refused(change):
    connection, calls = Connection(change(fixture.WHATWEB_REQUEST)), []
    with pytest.raises(ValueError):
        server.serve(connection, case="whatweb-ok", deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def test_header_order_and_case_do_not_add_request_capabilities():
    lines = fixture.WHATWEB_REQUEST[:-4].split(b"\r\n")
    request = b"\r\n".join([lines[0]] + [line.lower() for line in reversed(lines[1:])]) + b"\r\n\r\n"
    connection, calls = serve("whatweb-ok", request)
    assert calls == [1] and bytes(connection.output) == fixture.whatweb_response("whatweb-ok")


def test_all_truncated_headers_fail_without_counting_work():
    for length in range(len(fixture.WHATWEB_REQUEST)):
        connection, calls = Connection(fixture.WHATWEB_REQUEST[:length]), []
        with pytest.raises(ValueError):
            server.serve(connection, case="whatweb-ok", deadline=time.monotonic() + 5,
                         on_request=lambda: calls.append(1))
        assert not calls and not connection.output


@pytest.mark.parametrize("raw", [b"X" * 2048, b"X" * 2048 + b"\r\n\r\n", b"\r\n\r\n"])
def test_request_size_and_framing_are_bounded(raw):
    with pytest.raises(ValueError):
        serve("whatweb-ok", raw)


def test_read_deadline_is_rechecked_for_each_fragment(monkeypatch):
    connection, calls = Connection(chunk_size=1), []
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="deadline"):
        server.serve(connection, case="whatweb-ok", deadline=1, on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("case", ["unreviewed", "whatweb-default", None, 1, b"whatweb-ok"])
def test_unknown_case_never_reads_or_sends(case):
    connection, calls = Connection(), []
    with pytest.raises(ValueError, match="invalid_whatweb_fixture_case"):
        server.serve(connection, case=case, deadline=time.monotonic() + 5,
                     on_request=lambda: calls.append(1))
    assert not calls and not connection.output and not connection.timeouts
    assert connection.input.tell() == 0
    with pytest.raises(ValueError):
        fixture.whatweb_response(case)


def test_ordinary_and_empty_hint_responses_are_distinct_without_product_claims():
    raw = fixture.whatweb_response("whatweb-ok")
    assert raw.startswith(b"HTTP/1.1 200 OK\r\n")
    for hint in (fixture.WHATWEB_TITLE, fixture.WHATWEB_SERVER, fixture.WHATWEB_POWERED_BY,
                 fixture.WHATWEB_GENERATOR, fixture.WHATWEB_JQUERY_VERSION):
        assert hint.encode() in raw
    empty = fixture.whatweb_response("whatweb-no-hints")
    assert empty.startswith(b"HTTP/1.1 200 OK\r\n")
    for marker in (b"Server:", b"X-Powered-By:", b"<title>", b"generator", b"jquery"):
        assert marker not in empty
    assert fixture.whatweb_response("whatweb-denied").startswith(b"HTTP/1.1 403 ")
    assert fixture.whatweb_response("whatweb-eof") == b""


def test_hostile_text_and_redirects_stay_in_fixture_response_data():
    assert fixture.HOSTILE_NOTE.encode() in fixture.whatweb_response("whatweb-injected")
    redirect = fixture.whatweb_response("whatweb-redirect")
    assert redirect.startswith(b"HTTP/1.1 302 ")
    assert ("Location: " + fixture.WHATWEB_FORBIDDEN_URL).encode() in redirect
    meta = fixture.whatweb_response("whatweb-meta-redirect")
    assert meta.startswith(b"HTTP/1.1 200 ")
    assert b'http-equiv="refresh"' in meta and b"window.location=" in meta
    assert meta.count(fixture.WHATWEB_FORBIDDEN_URL.encode()) == 2


def test_input_pressure_and_json_output_pressure_are_different_fixtures():
    assert len(fixture.whatweb_response("whatweb-oversized")) > fixture.WHATWEB_MAX_RESPONSE_BYTES
    raw = fixture.whatweb_response("whatweb-output-limit")
    assert len(raw) < fixture.WHATWEB_MAX_RESPONSE_BYTES
    title = raw.split(b"<title>", 1)[1].split(b"</title>", 1)[0].decode()
    assert title == '"' * 6000
    assert len(json.dumps({"Title": {"string": [title]}}).encode()) > 8192
    for case in fixture.WHATWEB_CASES:
        response = fixture.whatweb_response(case)
        assert response is None or len(response) <= fixture.WHATWEB_MAX_FIXTURE_BYTES
        if case not in ("whatweb-oversized", "whatweb-stalled"):
            assert len(response) <= fixture.WHATWEB_MAX_RESPONSE_BYTES


@pytest.mark.parametrize("case", fixture.WHATWEB_CASES)
def test_spec_pins_one_get_bounded_passive_plugins_and_synthetic_response(case):
    spec = contract.spec(case)
    assert spec["tool_id"] == fixture.WHATWEB_TOOL_ID
    assert spec["method"] == "GET" and spec["path"] == fixture.WHATWEB_PATH
    assert spec["max_connections"] == spec["max_requests"] == 1
    assert spec["plugins"] == list(fixture.WHATWEB_PLUGINS) and spec["aggression"] == 1
    assert spec["request_sha256"] == hashlib.sha256(fixture.WHATWEB_REQUEST).hexdigest()
    response = fixture.whatweb_response(case)
    assert spec["response_sha256"] == (None if response is None else hashlib.sha256(response).hexdigest())
    assert spec["request_count_means"] == "validated_fixed_gets"
    for field in ("external_egress", "resume", "authentication", "credentials", "cookies", "redirects_followed",
                  "scripts_executed", "subresources_fetched", "backend", "product_identity_claim", "vulnerability_claim"):
        assert spec[field] is False
    expected = contract.identity(case, str(uuid4()))
    context = {"identity": expected, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(context, expected) == context
    for change in ({"connection_count": 2}, {"request_count": 2}, {"request_count": True}, {"connection_count": 0}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, expected)


@pytest.mark.parametrize("case", ["whatweb-ok", "whatweb-eof", "whatweb-redirect"])
def test_owner_closes_second_connection_before_reading_or_counting_it(case):
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
    assert bytes(peers[0].output) == fixture.whatweb_response(case)
    assert peers[1].input.tell() == 0 and not peers[1].output


def test_all_112_accepted_fixture_specs_remain_byte_identical():
    definitions = {case: contract.spec(case) for case in contract.CASES
                   if case not in fixture.WHATWEB_CASES + fixture.DNS_SRV_CASES + fixture.RDP_CASES + fixture.SMB2_CASES + fixture.SMTP_TLS_CASES + fixture.LDAP_TLS_CASES + fixture.FTP_TLS_CASES + fixture.DNS_NSID_CASES}
    assert len(definitions) == 112
    raw = json.dumps(definitions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == "fde5f39ad56dbec5db32b2748fa51444ca1feb8840dcb31190bdbe41c55f3237"


def test_public_spec_does_not_import_owner_implementation(monkeypatch):
    import builtins
    original = builtins.__import__
    def reject_owner(name, *args, **kwargs):
        assert "whatweb_fixture" not in name
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", reject_owner)
    for case in fixture.WHATWEB_CASES:
        assert contract.spec(case)["backend"] is False


def test_owner_file_loads_under_isolated_python_outside_repository(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_whatweb_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.WHATWEB_CASES) == 11
assert module.fixture.whatweb_response('whatweb-ok').startswith(b'HTTP/1.1 200 ')
print('isolated owner import ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated owner import ready\n" and result.stderr == ""
