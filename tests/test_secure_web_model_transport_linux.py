"""Actual isolated web-model TLS exchanges against an owned synthetic peer."""

from contextlib import contextmanager
import json
import os
import socket
import ssl
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import provider_pilot as pilot
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import LinuxFixtureBackend
from recon_cockpit.secure_agent.provider_lab import _certificates
from recon_cockpit.secure_agent.provider_pilot_contract import CHECKS, PilotError
from recon_cockpit.secure_agent.web_model_contract import decode_response, validate_request
from recon_cockpit.secure_agent.web_model_transport import LinuxWebModelTransport
from test_secure_provider_pilot import KEY, config
from test_secure_provider_pilot_linux import children
from test_secure_web_model_transport import request, response


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def owned_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned web-model TLS tests")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxFixtureBackend().check_available()
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-canary-never-read")
    monkeypatch.setenv("HTTPS_PROXY", "http://external.invalid:1234")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: pytest.fail("DNS attempted"))
    original = socket.socket.connect_ex

    def connect(sock, address):
        assert address[0] == "127.0.0.1", "only the owned TLS listener is permitted"
        return original(sock, address)

    monkeypatch.setattr(socket.socket, "connect_ex", connect)
    monkeypatch.setattr(pilot, "_credential_file", lambda *_: pytest.fail("real credential source consulted"))


@contextmanager
def server(tmp_path, scenario="success"):
    ca = _certificates(tmp_path, scenario, ExecutionControl(time.monotonic() + 10))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "server.crt", tmp_path / "server.key")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(.1)
    state = {"connections": 0, "requests": 0, "error": None}
    stop, received = threading.Event(), threading.Event()

    def serve():
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            state["connections"] += 1
            try:
                raw.settimeout(5)
                with context.wrap_socket(raw, server_side=True) as connection:
                    wire = b""
                    while b"\r\n\r\n" not in wire:
                        chunk = connection.recv(4096)
                        if not chunk: raise ValueError("truncated request")
                        wire += chunk
                        if len(wire) > 24576: raise ValueError("oversize request")
                    headers, body = wire.split(b"\r\n\r\n", 1)
                    fields = dict(line.split(b": ", 1) for line in headers.split(b"\r\n")[1:])
                    length = int(fields[b"Content-Length"])
                    assert 1 <= length <= 16384
                    while len(body) < length:
                        chunk = connection.recv(min(4096, length - len(body)))
                        if not chunk: raise ValueError("truncated request")
                        body += chunk
                    assert body == request() and validate_request(body) == body
                    assert headers.split(b"\r\n")[0] == b"POST /v1/responses HTTP/1.1"
                    assert fields[b"Authorization"] == b"Bearer " + KEY.encode()
                    assert fields[b"Host"] == b"provider.owned.invalid"
                    assert fields[b"Accept-Encoding"] == b"identity"
                    state["requests"] += 1
                    received.set()
                    if scenario == "slow":
                        stop.wait(5)
                        continue
                    value = response()
                    if scenario == "refusal":
                        value["output"][0]["content"] = [{"type": "refusal", "refusal": "private refusal"}]
                    if scenario == "incomplete":
                        value.update(status="incomplete", incomplete_details={"reason": "max_output_tokens"})
                    if scenario == "missing_usage": value.pop("usage")
                    if scenario == "bad_output": value["output"][0]["content"][0]["text"] = "not valid JSON"
                    if scenario == "credential_echo": value["metadata"] = KEY
                    body = json.dumps(value).encode()
                    if scenario == "malformed": body = b'{"id":1,"id":2}'
                    if scenario == "escaped_credential_echo":
                        body = b'{"echo":"' + b"".join(f"\\u{ord(c):04x}".encode() for c in KEY) + b'"}'
                    if scenario == "oversized": body = b"x" * 65537
                    status = "302 Redirect" if scenario == "redirect" else "200 OK"
                    header = (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\n"
                              f"Content-Length: {len(body)}\r\n\r\n").encode()
                    if scenario == "chunked":
                        header = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                        body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
                    connection.sendall(header + body)
            except (ssl.SSLError, OSError):
                pass
            except BaseException as exc:
                state["error"] = exc
            finally:
                raw.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], ca, state, received
    finally:
        stop.set()
        listener.close()
        thread.join(6)
        assert not thread.is_alive()
        assert state["error"] is None


@pytest.mark.parametrize("scenario", ["success", "chunked", "refusal", "incomplete", "missing_usage", "bad_output"])
def test_real_tls_returns_bounded_private_output_and_billing(tmp_path, children, scenario):
    with server(tmp_path, scenario) as (port, ca, counts, _):
        transport = LinuxWebModelTransport(config(port=port), ca_pem=ca, synthetic_credential=KEY)
        authorized = []

        def authorize():
            assert counts["connections"] == 0
            assert set(transport.boundary_checks) == CHECKS and all(transport.boundary_checks.values())
            authorized.append(True)

        result = transport.exchange(request(), control=ExecutionControl(time.monotonic() + 15), authorize=authorize)
        assert authorized == [True] and counts["connections"] == counts["requests"] == 1
        assert result["status"] == "ok" and result["http_status"] == 200
        assert result["summary"]["output_status"] == (scenario if scenario in {"refusal", "incomplete"} else "proposal")
        assert (result["summary"]["usage"] is None) == (scenario == "missing_usage")
        assert transport.cleanup_verified is True
        if scenario in {"refusal", "incomplete"}:
            assert result["response"] is None
        elif scenario == "bad_output":
            with pytest.raises(ValueError): decode_response(result["response"])
        else:
            assert json.loads(decode_response(result["response"]))["action"]["tool_id"] == "nmap_tcp_connect_v1"
        assert KEY not in repr(result) and "resp_owned_fixture" not in repr(result) and "private_metadata" not in repr(result)
        with pytest.raises(PilotError, match="^pilot_reused$"):
            transport.exchange(request(), control=ExecutionControl(time.monotonic() + 15), authorize=authorize)


@pytest.mark.parametrize("scenario,status", [
    ("wrong_hostname", "tls_error"), ("untrusted_certificate", "tls_error"),
    ("redirect", "http_error"), ("malformed", "malformed_response"),
    ("oversized", "response_too_large"), ("credential_echo", "credential_reflection"),
    ("escaped_credential_echo", "credential_reflection"),
])
def test_real_tls_rejection_has_no_response_release_or_retry(tmp_path, children, scenario, status):
    with server(tmp_path, scenario) as (port, ca, counts, _):
        transport = LinuxWebModelTransport(config(port=port), ca_pem=ca, synthetic_credential=KEY)
        result = transport.exchange(request(), control=ExecutionControl(time.monotonic() + 15), authorize=lambda: None)
        assert result["status"] == status and result["summary"] is result["response"] is None
        assert transport.cleanup_verified is True and counts["connections"] == 1
        assert counts["requests"] == (0 if scenario in {"wrong_hostname", "untrusted_certificate"} else 1)
        assert KEY not in repr(result)


@pytest.mark.parametrize("cancel", [True, False])
def test_real_cancel_and_deadline_reap_worker(tmp_path, children, cancel):
    with server(tmp_path, "slow") as (port, ca, counts, received):
        transport = LinuxWebModelTransport(config(port=port), ca_pem=ca, synthetic_credential=KEY)
        stopped = threading.Event()

        def cancellation():
            if received.wait(10): stopped.set()

        thread = threading.Thread(target=cancellation) if cancel else None
        if thread: thread.start()
        try:
            with pytest.raises(ExecutionStopped):
                transport.exchange(request(), control=ExecutionControl(time.monotonic() + (15 if cancel else 2), stopped),
                                   authorize=lambda: None)
        finally:
            if thread: thread.join(11)
        assert transport.cleanup_verified is True and counts["connections"] == counts["requests"] == 1


def test_real_missing_namespace_stops_before_authorize_or_connect(tmp_path, children, monkeypatch):
    original = pilot._command

    def weakened(*args):
        argv = original(*args)
        argv.remove("--unshare-net")
        return argv

    monkeypatch.setattr(pilot, "_command", weakened)
    with server(tmp_path) as (port, ca, counts, _):
        transport = LinuxWebModelTransport(config(port=port), ca_pem=ca, synthetic_credential=KEY)
        with pytest.raises(PilotError):
            transport.exchange(request(), control=ExecutionControl(time.monotonic() + 5),
                               authorize=lambda: pytest.fail("authorized an unconfined worker"))
        assert counts["connections"] == counts["requests"] == 0 and transport.cleanup_verified is True


def test_real_failed_durable_dispatch_stops_before_connect(tmp_path, children):
    with server(tmp_path) as (port, ca, counts, _):
        transport = LinuxWebModelTransport(config(port=port), ca_pem=ca, synthetic_credential=KEY)

        def broken():
            raise OSError("private failure must not leak")

        with pytest.raises(PilotError, match="^pilot_transport_failed$"):
            transport.exchange(request(), control=ExecutionControl(time.monotonic() + 15), authorize=broken)
        assert counts["connections"] == counts["requests"] == 0 and transport.cleanup_verified is True
