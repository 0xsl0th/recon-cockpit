"""Finite Nmap discovery fixture: a connect check is not a metadata query."""

import hashlib
import io
from pathlib import Path
import subprocess
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_nmap_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as lab_worker


class Connection:
    def __init__(self, raw=b""):
        self.input = io.BytesIO(raw)
        self.output = bytearray()
        self.timeouts = []
        self.closed = False

    def recv(self, count):
        return self.input.read(count)

    def sendall(self, value):
        self.output.extend(value)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def close(self):
        self.closed = True


def serve(case, raw=b"", index=1):
    connection, counts = Connection(raw), []
    server.serve(connection, case=case, connection_index=index,
                 deadline=time.monotonic() + 5, on_metadata=lambda: counts.append(1))
    return connection, counts


@pytest.mark.parametrize("case", fixture.NMAP_SERVICE_CASES)
def test_initial_connect_scan_requires_empty_eof_and_never_counts_metadata(case):
    connection, counts = serve(case)
    assert counts == [] and not connection.output
    with pytest.raises(ValueError, match="scan_must_be_empty"):
        serve(case, fixture.NMAP_SERVICE_GET)


def test_ssh_emits_one_reviewed_banner_without_login_or_query():
    connection, counts = serve("nmap-service-ssh", index=2)
    assert counts == [1] and bytes(connection.output) == b"SSH-2.0-OpenSSH_9.7\r\n"
    with pytest.raises(ValueError, match="repeated_banner"):
        serve("nmap-service-ssh", index=3)


@pytest.mark.parametrize("case", ["nmap-service-http", "nmap-service-unknown", "nmap-service-injected", "nmap-service-malformed"])
@pytest.mark.parametrize("index", [2, 3])
def test_one_exact_get_yields_compiled_response_with_bounded_receives(case, index):
    connection, counts = serve(case, fixture.NMAP_SERVICE_GET, index)
    assert counts == [1] and bytes(connection.output) == fixture.nmap_service_response(case)
    assert len(connection.timeouts) == len(fixture.NMAP_SERVICE_GET) + 1
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)
    assert (fixture.HOSTILE_NOTE.encode() in connection.output) is (case == "nmap-service-injected")


@pytest.mark.parametrize("case", [case for case in fixture.NMAP_SERVICE_CASES if case != "nmap-service-ssh"])
def test_null_probe_may_end_before_get_without_inventing_progress(case):
    connection, counts = serve(case, index=2)
    assert not counts and not connection.output
    with pytest.raises(ValueError, match="incomplete_get"):
        serve(case, index=3)


@pytest.mark.parametrize("null_probe_ends_separately", [False, True])
def test_owner_allows_only_one_metadata_query_across_connections(null_probe_ends_separately):
    scan = Connection()
    second = Connection(b"" if null_probe_ends_separately else fixture.NMAP_SERVICE_GET)
    third = Connection(fixture.NMAP_SERVICE_GET)
    connections = iter([scan, second, third])

    class Listener:
        def accept(self):
            return next(connections), ("127.0.0.1", 1)

    service = object.__new__(lab_worker.NetworkToolsService)
    service.case = "nmap-service-http"
    service.listener = Listener()
    service.deadline = time.monotonic() + 5
    service.condition = threading.Condition()
    service.rpc = None
    service.connections = service.requests = 0
    service.failed = False
    service._serve()

    assert service.requests == 1
    assert service.connections == (3 if null_probe_ends_separately else 2)
    assert not scan.output
    assert bytes(second.output) == (b"" if null_probe_ends_separately else fixture.NMAP_SERVICE_HTTP)
    assert bytes(third.output) == (fixture.NMAP_SERVICE_HTTP if null_probe_ends_separately else b"")
    assert all(connection.closed for connection in (scan, second, third))
    assert third.input.tell() == (len(fixture.NMAP_SERVICE_GET) if null_probe_ends_separately else 0)


@pytest.mark.parametrize("raw", [b"GET / HTTP/1.0\r\n", b"GET / HTTP/1.1\r\n\r\n",
    b"GET /version HTTP/1.0\r\n\r\n", b"OPTIONS / HTTP/1.0\r\n\r\n",
    b"POST / HTTP/1.0\r\n\r\n", b"GET http://127.0.0.2:8080/ HTTP/1.0\r\n\r\n",
    b"GET / HTTP/1.0\n\n", b"GET / HTTP/1.0\r\nAuthorization: secret\r\n\r\n",
    b"GET / HTTP/1.0\r\nContent-Length: 0\r\n\r\n", b"\x16\x03\x01TLS", b"\x80RPC",
    b"\r\n\r\n", b"x" * 8192])
def test_unreviewed_methods_headers_paths_protocols_and_partial_queries_are_rejected(raw):
    connection, counts = Connection(raw), []
    with pytest.raises(ValueError):
        server.serve(connection, case="nmap-service-http", connection_index=2,
                     deadline=time.monotonic() + 5, on_metadata=lambda: counts.append(1))
    assert not counts and not connection.output


def test_stalled_response_occurs_after_one_validated_get(monkeypatch):
    waits = []
    monkeypatch.setattr(server.time, "sleep", lambda duration: waits.append(duration))
    connection, counts = serve("nmap-service-stalled", fixture.NMAP_SERVICE_GET, 2)
    assert counts == [1] and not connection.output
    assert len(waits) == 1 and 0 < waits[0] <= 5


def test_get_deadline_is_rechecked_per_byte(monkeypatch):
    values = iter([0, 0.1, 0.2, 2])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(values))
    connection, counts = Connection(fixture.NMAP_SERVICE_GET), []
    with pytest.raises(ValueError, match="deadline"):
        server.serve(connection, case="nmap-service-http", connection_index=2,
                     deadline=1, on_metadata=lambda: counts.append(1))
    assert not counts and not connection.output


@pytest.mark.parametrize("index", [0, 4, True, "2"])
def test_extra_connections_cannot_expand_probe_scope(index):
    with pytest.raises(ValueError, match="invalid_nmap_service_exchange"):
        serve("nmap-service-http", fixture.NMAP_SERVICE_GET, index)


@pytest.mark.parametrize("case", fixture.NMAP_SERVICE_CASES)
def test_new_specs_pin_metadata_bytes_and_only_b7_has_three_connection_ceiling(case):
    definition = contract.spec(case)
    raw = fixture.nmap_service_response(case)
    assert definition["service"]["response_sha256"] == (None if raw is None else hashlib.sha256(raw).hexdigest())
    assert definition["max_connections"] == 3 and definition["max_requests"] == 1
    expected = contract.identity(case, str(uuid4()))
    context = {"identity": expected, "connection_count": 3, "request_count": 1}
    assert contract.validate_context(context, expected) == context
    for changes in ({"connection_count": 4}, {"request_count": 2}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **changes}, expected)


def test_owner_file_loads_with_isolated_python_without_repository_on_search_path(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_nmap_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.fixture.NMAP_SERVICE_GET == b'GET / HTTP/1.0\\r\\n\\r\\n'
assert len(module.fixture.NMAP_SERVICE_CASES) == 6
print('isolated owner import ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated owner import ready\n" and not result.stderr


def test_public_lab_specs_do_not_import_owner_module(monkeypatch):
    import builtins
    original = builtins.__import__
    def reject_owner(name, *args, **kwargs):
        assert "network_tools_nmap_fixture" not in name
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", reject_owner)
    for case in fixture.NMAP_SERVICE_CASES:
        assert contract.spec(case)["external_egress"] is False
