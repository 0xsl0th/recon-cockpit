"""Owned loopback TLS only: actual credential isolation and financial lifecycle."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import provider_pilot as pilot
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import LinuxFixtureBackend
from recon_cockpit.secure_agent.provider_lab import _certificates
from recon_cockpit.secure_agent.provider_pilot_contract import PilotError, request_bytes
from test_secure_provider_pilot import KEY, config, ledger, response
from test_secure_provider_linux import descendants, assert_no_survivors


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual Linux owned TLS tests")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxFixtureBackend().check_available()
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-canary-never-read")
    monkeypatch.setenv("HTTPS_PROXY", "http://external.invalid:1234")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: pytest.fail("DNS attempted"))
    original = socket.socket.connect_ex
    def connect(sock, address):
        assert address[0] == "127.0.0.1", "no external provider connections permitted"
        return original(sock, address)
    monkeypatch.setattr(socket.socket, "connect_ex", connect)
    monkeypatch.setattr(pilot, "_credential_file", lambda *_: pytest.fail("real credential source consulted"))


@pytest.fixture
def children(monkeypatch):
    children = []
    original = subprocess.Popen
    def launch(argv, *args, **kwargs):
        process = original(argv, *args, **kwargs)
        children.append((process, argv, kwargs.get("env", {})))
        return process
    monkeypatch.setattr(subprocess, "Popen", launch)
    yield children
    for process, argv, env in children:
        assert process.poll() is not None
        assert KEY not in str(argv) + str(env)
        assert "ambient-canary" not in str(env)
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)


@contextmanager
def server(tmp_path, scenario="success"):
    ca = _certificates(tmp_path, scenario, ExecutionControl(time.monotonic() + 10))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "server.crt", tmp_path / "server.key")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(.1)
    state = {"connections": 0, "requests": 0, "wire": b"", "error": None}
    stop = threading.Event()
    received = threading.Event()
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
                        if len(wire) > 16384: raise ValueError("oversize request")
                    headers, body = wire.split(b"\r\n\r\n", 1)
                    fields = dict(line.split(b": ", 1) for line in headers.split(b"\r\n")[1:])
                    length = int(fields[b"Content-Length"])
                    while len(body) < length:
                        chunk = connection.recv(4096)
                        if not chunk: raise ValueError("truncated request")
                        body += chunk
                    assert body == request_bytes()
                    assert headers.split(b"\r\n")[0] == b"POST /v1/responses HTTP/1.1"
                    assert fields[b"Authorization"] == b"Bearer " + KEY.encode()
                    assert fields[b"Host"] == b"provider.owned.invalid"
                    state["requests"] += 1
                    state["wire"] = headers + b"\r\n\r\n" + body
                    received.set()
                    if scenario == "slow":
                        stop.wait(5)
                        continue
                    value = response()
                    if scenario == "missing_usage": value.pop("usage")
                    if scenario == "bad_output": value["output"][0]["content"][0]["text"] = "do something else"
                    if scenario == "credential_echo": value["echo"] = KEY
                    body = json.dumps(value).encode()
                    if scenario == "escaped_credential_echo":
                        body = b'{"echo":"' + b"".join(f"\\u{ord(c):04x}".encode() for c in KEY) + b'"}'
                    if scenario == "oversized": body = b"x" * 65537
                    status = "302 Redirect" if scenario == "redirect" else "429 Rate Limit" if scenario == "rate_limit" else "200 OK"
                    headers = (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\n"
                               f"Content-Length: {len(body)}\r\n\r\n").encode()
                    if scenario == "truncated": body = body[:10]
                    if scenario == "chunked":
                        headers = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                        body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
                    connection.sendall(headers + body)
            except (ssl.SSLError, OSError):
                pass  # Expected when the client refuses TLS or closes early.
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


def make_call(ledger, ca, port, audit):
    transport = pilot.LinuxPilotTransport(config(port=port), ca_pem=ca, synthetic_credential=KEY)
    return pilot.ControlledProviderCall(ledger, audit, transport)


@pytest.mark.parametrize("scenario", ["success", "chunked"])
def test_owned_tls_capability_cost_settlement_and_private_receipt(tmp_path, ledger, children, scenario):
    with server(tmp_path, scenario) as (port, ca, counts, received):
        with AuditSink(tmp_path / "private" / "audit.jsonl") as audit:
            call = make_call(ledger, ca, port, audit)
            result = call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 15))
            assert result["ack"] is True and result["actual_microusd"] == 50
            assert counts["connections"] == counts["requests"] == 1
            assert ledger.attempt(call.attempt_id)["state"] == "settled"
            with pytest.raises(PilotError, match="pilot_reused"):
                call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 15))
    log = (tmp_path / "private" / "audit.jsonl").read_text()
    assert KEY not in log and "resp_owned_fixture" not in log and "Authorization" not in log
    assert any(Path(argv[0]).name == "bwrap" for _, argv, _ in children)


@pytest.mark.parametrize("scenario", ["wrong_hostname", "untrusted_certificate", "redirect", "rate_limit",
    "truncated", "oversized", "credential_echo", "escaped_credential_echo", "missing_usage", "bad_output"])
def test_adversarial_owned_tls_retains_cost_without_retry(tmp_path, ledger, children, scenario):
    with server(tmp_path, scenario) as (port, ca, counts, received):
        with AuditSink(tmp_path / "private" / "audit.jsonl") as audit:
            call = make_call(ledger, ca, port, audit)
            with pytest.raises(PilotError):
                call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 15))
            attempt = ledger.attempt(call.attempt_id)
            assert attempt["state"] == ("settled" if scenario == "bad_output" else "uncertain")
            assert attempt["reserved_microusd"] == (0 if scenario == "bad_output" else 419236)
            assert counts["connections"] == 1
            assert counts["requests"] == (0 if scenario in {"wrong_hostname", "untrusted_certificate"} else 1)
    assert KEY not in (tmp_path / "private" / "audit.jsonl").read_text()


@pytest.mark.parametrize("cancel", [True, False])
def test_post_send_stop_reaps_worker_and_keeps_full_hold(tmp_path, ledger, children, cancel):
    with server(tmp_path, "slow") as (port, ca, counts, received):
        stopped = threading.Event()
        def cancel_after_request():
            if received.wait(10): stopped.set()
        thread = threading.Thread(target=cancel_after_request) if cancel else None
        if thread: thread.start()
        try:
            with AuditSink(tmp_path / "private" / "audit.jsonl") as audit:
                call = make_call(ledger, ca, port, audit)
                with pytest.raises(ExecutionStopped):
                    call.run(scope_id="action", control=ExecutionControl(time.monotonic() + (15 if cancel else 2), stopped))
                assert ledger.attempt(call.attempt_id)["state"] == "uncertain"
                assert ledger.attempt(call.attempt_id)["reserved_microusd"] == 419236
                assert counts["requests"] == counts["connections"] == 1
        finally:
            if thread: thread.join(11)


def test_real_isolation_failure_cancels_before_any_connection(tmp_path, ledger, children, monkeypatch):
    with server(tmp_path) as (port, ca, counts, received):
        original = pilot._command
        def invalid(stdlib, files, module):
            argv = original(stdlib, files, module)
            argv.remove("--unshare-net")
            return argv
        monkeypatch.setattr(pilot, "_command", invalid)
        with AuditSink(tmp_path / "private" / "audit.jsonl") as audit:
            call = make_call(ledger, ca, port, audit)
            with pytest.raises(PilotError):
                call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 3))
            assert ledger.attempt(call.attempt_id)["state"] == "cancelled"
            assert counts["connections"] == counts["requests"] == 0


def test_audit_failure_after_ready_prevents_connection(tmp_path, ledger, children):
    class BrokenAudit:
        def emit(self, event):
            if event["event_type"] == "pilot_dispatch_started":
                raise OSError("synthetic-private-diagnostic")
    with server(tmp_path) as (port, ca, counts, received):
        call = make_call(ledger, ca, port, BrokenAudit())
        with pytest.raises(PilotError, match="^pilot_audit_failed$"):
            call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 15))
        assert ledger.attempt(call.attempt_id)["state"] == "uncertain"
        assert counts["connections"] == counts["requests"] == 0


def test_missing_reconnect_restriction_fails_before_credential_handoff(tmp_path, ledger, children, monkeypatch):
    source = Path(pilot.__file__).with_name("provider_pilot_worker.py")
    weaker = tmp_path / "weaker-worker.py"
    weaker.write_text(source.read_text().replace('"connect", "bind",', '"bind",'))
    original = pilot._command
    def weakened(*args):
        return [str(weaker) if part == str(source) else part for part in original(*args)]
    monkeypatch.setattr(pilot, "_command", weakened)
    with server(tmp_path) as (port, ca, counts, received):
        with AuditSink(tmp_path / "private" / "audit.jsonl") as audit:
            call = make_call(ledger, ca, port, audit)
            with pytest.raises(PilotError, match="pilot_transport_failed"):
                call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 15))
            assert ledger.attempt(call.attempt_id)["state"] == "cancelled"
            assert counts["connections"] == counts["requests"] == 0


def test_controller_crash_keeps_durable_dispatch_and_kills_descendants(tmp_path, ledger, children):
    script = tmp_path / "owned_controller.py"
    # Fresh interpreter: do not inherit an open SQLite handle across fork.
    script.write_text('''
import sys, time
from pathlib import Path
from recon_cockpit.secure_agent.provider_pilot import ControlledProviderCall, LinuxPilotTransport
from recon_cockpit.secure_agent.provider_pilot_contract import PilotConfig, MODEL
from recon_cockpit.secure_agent.cost_contract import PriceCard
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.execution import ExecutionControl
price = PriceCard("openai", MODEL, "owned-fixture-v1", 400000, 100000, 1600000)
config = PilotConfig("127.0.0.1", price, 500000, mode="owned", enabled=True, port=int(sys.argv[2]))
with CostLedger(sys.argv[1]) as ledger, AuditSink(Path(sys.argv[3]) / "private/crash.jsonl") as audit:
    transport = LinuxPilotTransport(config, ca_pem=(Path(sys.argv[3]) / "server.crt").read_text(),
                                    synthetic_credential="synthetic-" + "a" * 64)
    call = ControlledProviderCall(ledger, audit, transport)
    print(call.attempt_id, flush=True)
    call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 15))
''')
    with server(tmp_path, "slow") as (port, ca, counts, received):
        process = subprocess.Popen([sys.executable, str(script), str(ledger.directory), str(port), str(tmp_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "PYTHONPATH": str(Path.cwd())})
        try:
            assert received.wait(10)
            identities = descendants(process.pid)
            assert len(identities) >= 3
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            assert stderr == b""
            attempt = ledger.attempt(stdout.decode().strip())
            assert attempt["state"] == "dispatched" and attempt["reserved_microusd"] == 419236
            assert attempt["actual_microusd"] is None
            assert_no_survivors(identities)
            assert counts["connections"] == counts["requests"] == 1
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
