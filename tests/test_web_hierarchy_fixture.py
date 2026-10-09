"""Finite owner replies and independent concurrency accounting, without sockets."""

import base64
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import web_hierarchy_fixture as fixture
from recon_cockpit.secure_agent import web_hierarchy_owner as owner
from recon_cockpit.secure_agent import web_hierarchy_spec as spec


def request(path=spec.PATHS[0]):
    return (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
            "User-Agent: Fuzz Faster U Fool\r\nAccept-Encoding: gzip\r\n\r\n").encode("ascii")


@pytest.mark.parametrize("case", spec.CASES)
def test_all_compiled_replies_are_complete_bounded_http(case):
    for path in spec.PATHS:
        raw = fixture.wire_response(case, path)
        header, body = raw.split(b"\r\n\r\n", 1)
        fields = dict(line.split(b": ", 1) for line in header.split(b"\r\n")[1:])
        assert len(raw) <= spec.MAX_WIRE_BYTES
        assert int(fields[b"Content-Length"]) == len(body)
        assert fields[b"Connection"] == b"close"
        assert fixture.validate_request(request(path)) == ("GET", path)


def test_useful_and_ambiguous_corpora_are_distinct_without_followup():
    def status(case, path):
        return int(fixture.wire_response(case, path).split(b" ", 2)[1])
    assert {path for path in spec.PATHS if status("nested", path) == 200} == set(fixture.PRESENT_PATHS)
    assert {status("empty", path) for path in spec.PATHS} == {404}
    assert len({fixture.wire_response("wildcard", path) for path in spec.PATHS}) == 1
    controls = [spec.PREFIXES[1] + name for name in spec.CONTROL_NAMES]
    assert [status("mixed-controls", path) for path in controls] == [404, 200]
    assert b"Location: http://203.0.113.9/outside\r\n" in fixture.wire_response("redirect", spec.PREFIXES[1] + "index.html")
    hostile = fixture.wire_response("hostile", fixture.PRESENT_PATHS[0])
    assert fixture.HOSTILE_BODY in hostile and b"X-Untrusted-Instruction:" in hostile
    assert "http://203.0.113.9/outside" not in spec.PATHS


@pytest.mark.parametrize("replacement", [
    b"POST /harbordesk/index.html HTTP/1.1", b"HEAD /harbordesk/index.html HTTP/1.1",
    b"GET /harbordesk/index.html HTTP/1.0", b"GET /private HTTP/1.1",
    b"GET /harbordesk/../../private HTTP/1.1", b"GET http://127.0.0.1:8080/harbordesk/index.html HTTP/1.1",
])
def test_only_body_free_gets_for_compiled_paths_are_accepted(replacement):
    raw = replacement + b"\r\n" + request().split(b"\r\n", 1)[1]
    with pytest.raises(ValueError):
        fixture.validate_request(raw)


@pytest.mark.parametrize("extra", [b"Content-Length: 0", b"Transfer-Encoding: chunked",
    b"Authorization: Basic secret", b"Proxy-Authorization: Basic secret", b"Cookie: secret",
    b"Host: 127.0.0.1:8080", b"Bad Header: value", b"No colon", b"X-Header: value\x00"])
def test_payload_credentials_duplicate_or_malformed_headers_refuse(extra):
    with pytest.raises(ValueError):
        fixture.validate_request(request().replace(b"\r\n\r\n", b"\r\n" + extra + b"\r\n\r\n"))


@pytest.mark.parametrize("raw", [b"", b"x" * 1025, request()[:-1], request() + b"body",
                                     request().replace(b"127.0.0.1:8080", b"127.0.0.2:8080")])
def test_partial_excess_or_changed_authority_requests_refuse(raw):
    with pytest.raises(ValueError):
        fixture.validate_request(raw)


class Connection:
    def __init__(self, raw, write_size=None):
        self.received = bytearray(raw)
        self.sent = bytearray()
        self.closed = self.eof = False
        self.write_size = write_size

    def setblocking(self, value):
        assert value is False

    def recv(self, count):
        if self.received:
            raw = bytes(self.received[:count])
            del self.received[:count]
            return raw
        if self.eof:
            return b""
        raise BlockingIOError

    def send(self, raw):
        selected = raw if self.write_size is None else raw[:self.write_size]
        self.sent.extend(selected)
        return len(selected)

    def close(self):
        self.closed = True


class Listener:
    def __init__(self):
        self.queue = []
        self.closed = False

    def setblocking(self, value):
        assert value is False

    def accept(self):
        if not self.queue:
            raise BlockingIOError
        return self.queue.pop(0), ("127.0.0.1", 12345)

    def close(self):
        self.closed = True


@pytest.fixture
def service_factory(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(owner.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(owner.threading.Thread, "start", lambda self: None)
    def select_ready(readers, writers, errors, timeout):
        ready = [item for item in readers if (isinstance(item, Listener) and item.queue)
                 or (isinstance(item, Connection) and (item.received or item.eof))]
        return ready, list(writers), []
    monkeypatch.setattr(owner.select, "select", select_ready)
    def build(case="nested"):
        listener = Listener()
        service = owner.Service({"case": case, "deadline": 60}, listener)
        return service, listener, clock
    return build


def cycle(service, count=1):
    for _ in range(count):
        service._poll_once()


def test_concurrent_clients_are_observed_during_delayed_response(service_factory):
    service, listener, clock = service_factory()
    first, second = Connection(request(spec.PATHS[0])), Connection(request(spec.PATHS[1]))
    listener.queue.extend((first, second))
    cycle(service, 3)
    assert service.requests == service.active_requests == service.max_active_requests == 2
    assert not first.sent and not second.sent
    clock[0] += owner.RESPONSE_DELAY_SECONDS + .001
    cycle(service)
    value = service.snapshot(2, 2, 60)
    assert value["diagnostic"]["max_active_requests"] == 2
    assert all(row["completed"] for row in value["diagnostic"]["ledger"])
    assert service.active_requests == 0 and first.closed and second.closed


@pytest.mark.parametrize("case", spec.CASES[:-1])
def test_serial_native_shape_records_exact_twelve_paths_and_sent_bytes(service_factory, case):
    service, listener, clock = service_factory(case)
    for path in spec.PATHS:
        connection = Connection(request(path), write_size=17)
        listener.queue.append(connection)
        cycle(service, 2)
        clock[0] += .06
        cycle(service, 70)
        assert connection.closed and bytes(connection.sent) == fixture.wire_response(case, path)
    value = service.snapshot(12, 12, 60)
    assert value["connection_count"] == value["request_count"] == 12
    assert value["diagnostic"]["max_active_requests"] == 1
    assert value["diagnostic"]["errors"] == []
    assert [row["path"] for row in value["diagnostic"]["ledger"]] == list(spec.PATHS)
    assert all(base64.b64decode(row["raw_request_base64"]) == request(row["path"])
               and base64.b64decode(row["response_base64"]) == fixture.wire_response(case, row["path"])
               and row["completed"] for row in value["diagnostic"]["ledger"])
    value["diagnostic"]["ledger"].clear()
    assert len(service.ledger) == 12


def test_stalled_request_keeps_progress_and_peer_fin_settles_active_count(service_factory):
    service, listener, clock = service_factory("stalled")
    connection = Connection(request())
    listener.queue.append(connection)
    cycle(service, 2)
    clock[0] += 5
    cycle(service)
    assert service.active_requests == 1 and not connection.sent
    connection.eof = True
    cycle(service)
    row = service.snapshot(1, 1, 60)["diagnostic"]["ledger"][0]
    assert not row["completed"] and row["response_base64"] == ""
    assert service.active_requests == 0 and connection.closed


def test_duplicate_and_unexpected_paths_are_counted_and_cannot_hide_in_clean_receipt(service_factory):
    service, listener, clock = service_factory()
    for path in (spec.PATHS[0], spec.PATHS[0], "/unexpected"):
        listener.queue.append(Connection(request(path)))
        cycle(service, 2)
        clock[0] += .06
        cycle(service)
    value = service.snapshot(3, 3, 60)
    assert value["request_count"] == value["connection_count"] == 3
    assert set(value["diagnostic"]["errors"]) == {"duplicate_path", "unexpected_path"}
    assert len(value["diagnostic"]["ledger"]) == 3


def test_connection_request_and_owner_caps_refuse_without_truncating_evidence(service_factory):
    service, listener, clock = service_factory()
    for _ in range(spec.MAX_CONNECTIONS):
        connection = Connection(b"x" * (spec.MAX_REQUEST_BYTES + 10))
        listener.queue.append(connection)
        cycle(service, 2)
        assert len(connection.received) == 10 and connection.closed
    assert listener.closed and service.listener is None
    assert service.connections == service.requests == len(service.ledger) == 16
    assert all(len(base64.b64decode(row["raw_request_base64"])) == spec.MAX_REQUEST_BYTES
               for row in service.ledger)
    with pytest.raises(ValueError, match="owner_record_limit"):
        service.snapshot(16, 16, 60)


def test_partial_send_then_failure_records_only_sent_prefix(service_factory):
    service, listener, clock = service_factory()
    connection = Connection(request(), write_size=11)
    listener.queue.append(connection)
    cycle(service, 2)
    clock[0] += .06
    cycle(service)
    def fail(raw):
        raise BrokenPipeError
    connection.send = fail
    cycle(service)
    row = service.snapshot(1, 1, 60)["diagnostic"]["ledger"][0]
    assert base64.b64decode(row["response_base64"]) == bytes(connection.sent)
    assert len(connection.sent) == 11 and not row["completed"]
    assert service.errors == ["response_write"] and service.active_requests == 0


@pytest.mark.parametrize("changes", [{"case": "unknown"}, {"deadline": float("nan")},
    {"deadline": float("inf")}, {"deadline": True}, {"deadline": 0}, {"extra": 1}])
def test_owner_request_rejects_unknown_fields_cases_and_unbounded_deadlines(changes, monkeypatch):
    monkeypatch.setattr(owner.time, "monotonic", lambda: 10)
    value = {"case": "nested", "deadline": 60, "host_namespaces": {}}
    value.update(changes)
    with pytest.raises(ValueError):
        owner.Owner().read_request(io.BytesIO(json.dumps(value).encode() + b"\n"))


def test_owner_has_fixed_service_port_and_standalone_sibling_imports():
    assert owner.Owner().service_port({}) == 8080
    code = ("import importlib.util; s=importlib.util.spec_from_file_location('owner',%r); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "assert m.Owner().service_port({}) == 8080") % str(Path(owner.__file__))
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
