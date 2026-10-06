"""Finite shared wire phases, hostile raw evidence, and disposable ownership."""

import base64
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import http_headers_fixture as headers
from recon_cockpit.secure_agent import network_tools_fixture as network
from recon_cockpit.secure_agent import service_web_fixture as fixture
from recon_cockpit.secure_agent import service_web_lab_worker as worker
from recon_cockpit.secure_agent import web_tools_fixture as web
from recon_cockpit.secure_agent import web_tools_parser as parser
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.service_web_lab import ServiceWebLab
from recon_cockpit.secure_agent.session_limits import SessionLimits


class Connection:
    def __init__(self, raw=b""):
        self.input = io.BytesIO(raw)
        self.output = bytearray()
        self.closed = False
        self.timeouts = []

    def recv(self, count):
        return self.input.read(count)

    def sendall(self, raw):
        self.output.extend(raw)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def close(self):
        self.closed = True


def ffuf_get(path):
    return (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
            "User-Agent: Fuzz Faster U Fool v2.1.0\r\nAccept-Encoding: gzip\r\n\r\n").encode("ascii")


def serve(raw_requests, case="vulnerable"):
    connections = [raw if isinstance(raw, Connection) else Connection(raw) for raw in raw_requests]
    pending = iter(connections)

    class Listener:
        def accept(self):
            return next(pending), ("127.0.0.1", 1)

    service = object.__new__(worker.ServiceWebService)
    service.case, service.listener = case, Listener()
    service.deadline = time.monotonic() + 10
    service.condition = threading.Condition()
    service.discovered = set()
    service.connections = service.requests = 0
    service.failed = False
    service._serve()
    return service, connections


def initial(*, separate_null=False):
    return [b""] + ([b""] if separate_null else []) + [fixture.NMAP_GET]


class ResetConnection(Connection):
    def recv(self, count):
        chunk = super().recv(count)
        if chunk:
            return chunk
        raise ConnectionResetError("native connect scan reset")


def test_native_initial_connect_reset_without_application_bytes_still_allows_work():
    scan = ResetConnection()
    raw = [scan, fixture.NMAP_GET] + [ffuf_get(path) for path in fixture.FFUF_PATHS] + [fixture.HEADER_GET]
    service, connections = serve(raw)
    assert scan.closed and not scan.output and scan.input.tell() == 0
    assert service.connections == 11 and service.requests == 10
    assert bytes(connections[-1].output) == fixture.wire_response("vulnerable", "headers", fixture.PORTAL_PATH)


@pytest.mark.parametrize("prefix,partial", [([], b"G"), ([b""], b""), ([b""], b"GET /"),
    (initial(), b""), (initial(), b"GET /harbordesk/portal.html"),
    (initial() + [ffuf_get(path) for path in fixture.FFUF_PATHS], b"")])
def test_partial_initial_or_any_later_reset_stops_owner_without_counting_query(prefix, partial):
    reset = ResetConnection(partial)
    service, connections = serve(prefix + [reset])
    assert service.failed and reset.closed and not reset.output
    assert service.requests == (9 if len(prefix) == 10 else 1 if len(prefix) == 2 else 0)
    with pytest.raises(RuntimeError, match="owned_lab_service_failed"):
        service.snapshot(0, 0, time.monotonic() + 1)


@pytest.mark.parametrize("error", [TimeoutError, ConnectionAbortedError, PermissionError])
def test_initial_scan_does_not_swallow_other_socket_errors(error):
    class BrokenConnection(Connection):
        def recv(self, count):
            raise error("not a reviewed empty reset")
    connection = BrokenConnection()
    service, _ = serve([connection])
    assert service.failed and connection.closed and service.requests == 0


@pytest.mark.parametrize("case", fixture.CASES)
@pytest.mark.parametrize("separate_null", [False, True])
@pytest.mark.parametrize("reverse_paths", [False, True])
def test_actual_request_shapes_complete_exactly_three_phases(case, separate_null, reverse_paths):
    paths = fixture.FFUF_PATHS[::-1] if reverse_paths else fixture.FFUF_PATHS
    raw = initial(separate_null=separate_null) + [ffuf_get(path) for path in paths] + [fixture.HEADER_GET]
    service, connections = serve(raw, case)
    assert service.requests == 10 and service.connections == 11 + separate_null
    assert all(connection.closed for connection in connections)
    start = 2 + separate_null
    assert bytes(connections[start - 1].output) == fixture.NMAP_RESPONSE
    for path, connection in zip(paths, connections[start:-1]):
        assert bytes(connection.output) == fixture.wire_response(case, "ffuf", path)
    assert bytes(connections[-1].output) == fixture.wire_response(case, "headers", fixture.PORTAL_PATH)
    assert all(0 < timeout <= 2 for connection in connections for timeout in connection.timeouts)


@pytest.mark.parametrize("separate_null", [False, True])
def test_extra_request_is_closed_without_reading_or_counting_it(separate_null):
    raw = initial(separate_null=separate_null) + [ffuf_get(path) for path in fixture.FFUF_PATHS]
    service, connections = serve(raw + [fixture.HEADER_GET, fixture.HEADER_GET])
    extra = connections[-1]
    assert service.failed and service.requests == 10 and service.connections == 11 + separate_null
    assert extra.closed and extra.input.tell() == 0 and not extra.output


@pytest.mark.parametrize("raw", [fixture.NMAP_GET, ffuf_get(fixture.PORTAL_PATH), b"x", b"\r\n\r\n"])
def test_scan_connection_must_close_without_application_payload(raw):
    service, connections = serve([raw])
    assert service.failed and service.requests == 0 and not connections[0].output


def test_only_one_optional_null_close_is_accepted():
    service, connections = serve([b"", b"", b"", fixture.NMAP_GET])
    assert service.failed and service.connections == 3 and service.requests == 0
    assert not any(connection.output for connection in connections)
    assert connections[-1].input.tell() == 0


@pytest.mark.parametrize("raw", [b"", fixture.HEADER_GET, b"GET / HTTP/1.1\r\n\r\n",
    fixture.NMAP_GET + b"body", fixture.NMAP_GET + fixture.NMAP_GET,
    b"GET / HTTP/1.0\r\nAuthorization: secret\r\n\r\n"])
def test_nmap_phase_has_one_exact_get_after_scan_and_optional_null(raw):
    service, connections = serve([b"", b"", raw])
    assert service.failed and service.requests == 0 and not connections[-1].output


@pytest.mark.parametrize("raw", [fixture.NMAP_GET, b"", b"x" * 4096,
    b"GET /harbordesk/admin HTTP/1.1\r\n", b"GET /private HTTP/1.1\r\n\r\n",
    b"GET http://127.0.0.2:8080/harbordesk/admin HTTP/1.1\r\n\r\n",
    ffuf_get(fixture.PORTAL_PATH).replace(b"GET ", b"POST ", 1),
    ffuf_get(fixture.PORTAL_PATH).replace(b"127.0.0.1", b"127.0.0.2"),
    ffuf_get(fixture.PORTAL_PATH).replace(b"Accept-Encoding: gzip", b"Authorization: secret"),
    ffuf_get(fixture.PORTAL_PATH).replace(b"Accept-Encoding: gzip", b"Content-Length: 0"),
    ffuf_get(fixture.PORTAL_PATH).replace(b"Accept-Encoding: gzip", b"Transfer-Encoding: chunked"),
    ffuf_get(fixture.PORTAL_PATH).replace(b"Accept-Encoding: gzip", b"Host: 127.0.0.1:8080"),
    ffuf_get(fixture.PORTAL_PATH).replace(b"Accept-Encoding: gzip", b"Cookie: secret"),
    ffuf_get(fixture.PORTAL_PATH) + b"body", ffuf_get(fixture.PORTAL_PATH) * 2])
def test_content_phase_rejects_incomplete_extra_and_unreviewed_requests(raw):
    service, connections = serve(initial() + [raw])
    assert service.failed and service.requests == 1 and not connections[-1].output


def test_duplicate_discovery_cannot_stand_in_for_complete_coverage():
    service, connections = serve(initial() + [ffuf_get(fixture.PORTAL_PATH)] * 2)
    assert service.failed and service.requests == 2 and not connections[-1].output
    with pytest.raises(RuntimeError, match="owned_lab_service_failed"):
        service.snapshot(0, 0, time.monotonic() + 1)


def test_expired_owner_deadline_prevents_reading_application_bytes():
    connection = Connection(fixture.NMAP_GET)
    with pytest.raises(TimeoutError):
        worker.read_http(connection, time.monotonic() - 1)
    assert connection.input.tell() == 0 and not connection.output


@pytest.mark.parametrize("raw", [ffuf_get(fixture.PORTAL_PATH), fixture.NMAP_GET,
    fixture.HEADER_GET.replace(b"portal.html", b"admin"), fixture.HEADER_GET + b"body", b""])
def test_final_headers_are_exact_and_cannot_repeat_discovery(raw):
    service, connections = serve(initial() + [ffuf_get(path) for path in fixture.FFUF_PATHS] + [raw])
    assert service.failed and service.requests == 9 and not connections[-1].output


@pytest.mark.parametrize("case", fixture.CASES)
def test_existing_probe_and_final_header_bytes_are_reused(case):
    assert fixture.NMAP_GET == network.NMAP_SERVICE_GET
    assert fixture.wire_response(case, "nmap", "/") == network.NMAP_SERVICE_HTTP
    assert fixture.header_response(case) == headers.response(case, headers.PORTAL_PATH)
    assert fixture.ffuf_response(case, fixture.PORTAL_PATH)[0] == 200
    assert fixture.ffuf_response(case, fixture.FFUF_PATHS[-1])[0] == 404


def test_injected_metadata_survives_raw_ffuf_json_but_cannot_become_a_destination():
    rows = []
    for position, path in enumerate(fixture.FFUF_PATHS, start=1):
        status, body, extra = fixture.ffuf_response("injected", path)
        content_type = extra.decode("ascii").removeprefix("Content-Type: ").removesuffix("\r\n")
        rows.append({"input": {"FUZZ": base64.b64encode(web.WORDS[position - 1].encode()).decode(),
            "FFUFHASH": base64.b64encode(str(position).encode()).decode()}, "position": position,
            "status": status, "length": len(body), "words": 3, "lines": 1,
            "content-type": content_type, "redirectlocation": "", "scraper": {}, "duration": 1000,
            "resultfile": "", "url": "http://127.0.0.1:8080" + path, "host": "127.0.0.1:8080"})
    raw = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    result = parser.parse_tool_output(parser.FFUF_TOOL_ID, raw)
    assert fixture.HOSTILE_NOTE.encode() in raw and len(raw) <= 8192
    assert result["coverage"] == "complete" and result["baseline"] == "not_found"
    assert result["responses"][0]["status_code"] == 200
    assert "127.0.0.2" not in json.dumps(result)
    assert set(result["responses"][0]) == {"path", "status_code", "bytes"}


@pytest.mark.parametrize("fault", ["case", "extra", "past", "long", "bool", "nan", "duplicate", "oversized"])
def test_owner_bootstrap_refuses_expanded_or_ambiguous_configuration(fault):
    value = {"case": "vulnerable", "deadline": time.monotonic() + 30, "host_namespaces": {}}
    assert worker.read_request(io.BytesIO(json.dumps(value).encode() + b"\n")) == value
    if fault == "case": value["case"] = "curl-ok"
    if fault == "extra": value["url"] = "http://example.invalid/"
    if fault == "past": value["deadline"] = 0
    if fault == "long": value["deadline"] += 60
    if fault == "bool": value["deadline"] = True
    if fault == "nan": value["deadline"] = float("nan")
    raw = json.dumps(value).encode() + b"\n"
    if fault == "duplicate": raw = raw[:-2] + b',"case":"corrected"}\n'
    if fault == "oversized": raw = b"x" * 8193 + b"\n"
    with pytest.raises(ValueError): worker.read_request(io.BytesIO(raw))


@pytest.mark.parametrize("field", ["max_steps", "max_runtime_seconds", "max_output_bytes"])
def test_lab_refuses_expanded_session_and_cannot_restart_after_close(field):
    values = {"max_steps": 3, "max_runtime_seconds": 60, "max_output_bytes": 18432}
    lab = ServiceWebLab("vulnerable", str(uuid4()), SessionLimits(**values), execute=False)
    receipt = lab.close()
    assert receipt["status"] == "closed" and receipt["request_count"] == 0
    assert receipt == lab.close() and not lab.started
    with pytest.raises(IsolationUnavailable): lab.__enter__()
    values[field] += 1
    with pytest.raises(ValueError): ServiceWebLab("vulnerable", str(uuid4()), SessionLimits(**values))


def test_owner_loads_from_fixed_files_with_isolated_python(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_service_web', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.fixture.MAX_REQUESTS == 10
assert module.fixture.NMAP_GET == b'GET / HTTP/1.0\\r\\n\\r\\n'
print('isolated service web owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(worker.__file__).resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated service web owner ready\n" and not result.stderr
