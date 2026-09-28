"""Opted-in Linux witnesses for the synthetic credential-bearing TLS boundary."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import provider_lab
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import LinuxFixtureBackend
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES as PARSER_BOUNDARIES
from recon_cockpit.secure_agent.provider_adapter import OwnedTLSProvider
from recon_cockpit.secure_agent.provider_broker import OwnedProviderBroker
from recon_cockpit.secure_agent.provider_contract import (
    BOUNDARY_NAMES, MAX_OUTPUT_TOKENS, ProviderError, ProviderLimits,
    SyntheticTariff, build_request, success_response,
)


pytestmark = pytest.mark.integration
OBSERVATION = b'{"step":1,"untrusted_observation":null}'


@pytest.fixture(autouse=True)
def require_real_linux():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual owned TLS isolation")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxFixtureBackend().check_available()


@pytest.fixture
def processes(monkeypatch):
    children = []
    original = subprocess.Popen

    def launch(argv, *args, **kwargs):
        process = original(argv, *args, **kwargs)
        children.append((process, list(argv), dict(kwargs.get("env", {}))))
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    return children


class Audit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def make_broker(scenario="success", *, limits=None, audit=None):
    return OwnedProviderBroker(audit or Audit(), provider_lab.LinuxOwnedProviderTransport(scenario), limits=limits)


def assert_reaped(processes):
    assert processes
    assert any(Path(argv[0]).name == "bwrap" for _, argv, _ in processes)
    for process, _, _ in processes:
        assert process.poll() is not None
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)


def assert_reservation(broker, count=1):
    request = build_request(OBSERVATION)
    assert dict(broker.snapshot) == {
        "calls_reserved": count,
        "output_tokens_reserved": count * MAX_OUTPUT_TOKENS,
        "request_bytes_reserved": count * len(request),
        "synthetic_cost_units_reserved": count * SyntheticTariff().reserve(len(request)),
    }


def assert_boundaries(receipt, *, requests=1):
    assert receipt["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
    assert receipt["cleanup"] == {"owner_reaped": True, "worker_reaped": True}
    assert receipt["connection_count"] == 1
    assert receipt["request_count"] == requests


def descendants(pid):
    """Record process start times as well as PIDs to detect surviving identities."""
    result, pending = {}, [pid]
    while pending:
        current = pending.pop()
        try:
            fields = Path(f"/proc/{current}/stat").read_text().rsplit(")", 1)[1].split()
            children = Path(f"/proc/{current}/task/{current}/children").read_text().split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        result[current] = fields[19]
        pending.extend(map(int, children))
    return result


def assert_no_survivors(identities):
    deadline = time.monotonic() + 3
    while True:
        live = []
        for pid, started in identities.items():
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if fields[19] == started and fields[0] not in {"Z", "X"}:
                live.append(pid)
        if not live or time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    assert live == []


def test_real_owned_tls_success_is_decoded_by_a_separate_networkless_parser(tmp_path, processes):
    path = tmp_path / "audit.jsonl"
    with AuditSink(path) as audit:
        provider = OwnedTLSProvider(audit)
        raw = provider.propose(OBSERVATION, control=ExecutionControl(time.monotonic() + 30))
    assert json.loads(raw) == {"schema_version": "1", "action": None, "done": True}
    assert provider.boundary_checks == dict.fromkeys(PARSER_BOUNDARIES, True)
    assert_boundaries(provider.broker.last_receipt)
    assert provider.broker.last_receipt["status"] == "ok"
    assert_reservation(provider.broker)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [event["event_type"] for event in events] == ["provider_request_reserved", "provider_exchange_finished"]
    assert events[-1]["exchange_status"] == "succeeded"
    assert events[-1]["response_bytes"] == len(success_response())
    assert len([argv for _, argv, _ in processes if "/app/openai_worker.py" in argv]) == 1
    assert len([argv for _, argv, _ in processes if "/app/provider_lab_worker.py" in argv]) == 1
    assert len([argv for _, argv, _ in processes if "/app/provider_worker.py" in argv]) == 1
    assert_reaped(processes)


@pytest.mark.parametrize("scenario,status,http_status,requests", [
    ("redirect", "http_error", 302, 1),
    ("rate_limit", "http_error", 429, 1),
    ("oversized", "response_too_large", 200, 1),
    ("truncated", "malformed_response", 200, 1),
    ("malformed", "malformed_response", 200, 1),
    ("credential_echo", "credential_reflection", 200, 1),
    ("escaped_credential_echo", "credential_reflection", 200, 1),
    ("untrusted_certificate", "tls_error", None, 0),
    ("wrong_hostname", "tls_error", None, 0),
])
def test_real_adversarial_tls_attempt_has_one_connection_no_retry_and_no_refund(
        processes, scenario, status, http_status, requests):
    audit = Audit()
    broker = make_broker(scenario, audit=audit)
    with pytest.raises(ProviderError, match="^provider_" + status + "$" ):
        broker.exchange(OBSERVATION, build_request(OBSERVATION), control=ExecutionControl(time.monotonic() + 30))
    receipt = broker.last_receipt
    assert receipt["status"] == status and receipt["http_status"] == http_status
    assert_boundaries(receipt, requests=requests)
    assert_reservation(broker)
    assert len(audit.events) == 2 and audit.events[-1]["exchange_status"] == "failed"
    assert audit.events[-1]["reason"] == "provider_" + status
    assert len([argv for _, argv, _ in processes if "/app/provider_worker.py" in argv]) == 1
    assert_reaped(processes)


def test_explicit_failed_attempts_each_reserve_before_retry_exhaustion(processes):
    audit = Audit()
    broker = make_broker("rate_limit", audit=audit, limits=ProviderLimits(max_calls=2))
    control = ExecutionControl(time.monotonic() + 40)
    for count in (1, 2):
        with pytest.raises(ProviderError, match="^provider_http_error$"):
            broker.exchange(OBSERVATION, build_request(OBSERVATION), control=control)
        assert_reservation(broker, count)
        assert_boundaries(broker.last_receipt)
    launches = len(processes)
    with pytest.raises(ProviderError, match="^provider_call_limit$"):
        broker.exchange(OBSERVATION, build_request(OBSERVATION), control=control)
    assert len(processes) == launches
    assert_reservation(broker, 2)
    assert [event["event_type"] for event in audit.events] == [
        "provider_request_reserved", "provider_exchange_finished",
        "provider_request_reserved", "provider_exchange_finished", "provider_request_rejected",
    ]
    assert_reaped(processes)


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_stop_during_active_tls_reaps_both_namespace_trees(monkeypatch, processes, stop):
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic() + (4 if stop == "deadline" else 30), cancelled)
    original = provider_lab._send
    identities = {}
    observed_connection = []

    def send(supervisor, process, raw, *, close=False):
        original(supervisor, process, raw, close=close)
        if not close or process is not supervisor.processes.get("worker"):
            return

        def connected():
            tree = descendants(process.pid)
            for pid in tree:
                try:
                    argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                    if b"/app/provider_worker.py" not in argv or "python" not in Path(os.fsdecode(argv[0])).name:
                        continue
                    rows = Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if any(row.split()[3] == "01" and any(address.endswith(":20FB")
                           for address in row.split()[1:3]) for row in rows):
                    observed_connection.append(pid)
                    for child in supervisor.processes.values():
                        identities.update(descendants(child.pid))
                    return True
            return False

        supervisor.wait_for(connected, worker_may_exit=True)
        if stop == "cancel":
            cancelled.set()

    monkeypatch.setattr(provider_lab, "_send", send)
    audit = Audit()
    broker = make_broker("slow", audit=audit)
    started = time.monotonic()
    reason = "session_cancelled" if stop == "cancel" else "session_timeout"
    with pytest.raises(ExecutionStopped, match="^" + reason + "$"):
        broker.exchange(OBSERVATION, build_request(OBSERVATION), control=control)
    assert observed_connection and len(identities) >= 2
    assert time.monotonic() - started < 8
    assert_reservation(broker)
    assert broker.last_receipt["cleanup"] == {"owner_reaped": True, "worker_reaped": True}
    assert audit.events[-1]["exchange_status"] == "stopped" and audit.events[-1]["reason"] == reason
    if stop == "deadline":
        assert broker.last_receipt["status"] == "deadline_exceeded"
    assert_no_survivors(identities)
    assert_reaped(processes)


@pytest.mark.parametrize("stage", ["send_snapshot", "read_snapshot"])
def test_cancel_after_response_before_owner_counts_preserves_stop_and_partial_receipt(monkeypatch, processes, stage):
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic() + 30, cancelled)
    original_send, original_message = provider_lab._send, provider_lab._message
    snapshots = []

    def send(supervisor, process, raw, *, close=False):
        if raw == b"SNAP\n":
            snapshots.append(True)
            if stage == "send_snapshot":
                cancelled.set()
        return original_send(supervisor, process, raw, close=close)

    def message(supervisor, offset):
        if snapshots and stage == "read_snapshot":
            cancelled.set()
        return original_message(supervisor, offset)

    monkeypatch.setattr(provider_lab, "_send", send)
    monkeypatch.setattr(provider_lab, "_message", message)
    audit = Audit()
    broker = make_broker(audit=audit)
    with pytest.raises(ExecutionStopped, match="^session_cancelled$"):
        broker.exchange(OBSERVATION, build_request(OBSERVATION), control=control)

    assert snapshots == [True]
    assert_reservation(broker)
    receipt = broker.last_receipt
    assert receipt["status"] == "transport_error" and receipt["http_status"] == 200
    assert receipt["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
    assert receipt["connection_count"] is None and receipt["request_count"] is None
    assert receipt["cleanup"] == {"owner_reaped": True, "worker_reaped": True}
    assert broker.last_error == "session_cancelled"
    assert len(audit.events) == 2 and audit.events[-1]["exchange_status"] == "stopped"
    assert audit.events[-1]["reason"] == "session_cancelled" and audit.events[-1]["receipt"] == receipt
    assert "response_bytes" not in audit.events[-1] and "response_digest" not in audit.events[-1]
    assert_reaped(processes)


def test_real_worker_cannot_read_host_canaries_or_inherit_namespace_handles(tmp_path, monkeypatch, processes):
    sentinel = tmp_path / "host-private-key"
    sentinel.write_text("HOST_FILE_PROVIDER_CANARY")
    sentinel.chmod(0o600)
    monkeypatch.setenv("OPENAI_API_KEY", "HOST_ENV_PROVIDER_CANARY")
    monkeypatch.setenv("HTTPS_PROXY", "http://HOST_PROXY_PROVIDER_CANARY.invalid")
    source_fd = os.open(sentinel, os.O_RDONLY)
    inherited_fd = fcntl.fcntl(source_fd, fcntl.F_DUPFD, 128)
    os.close(source_fd)
    os.set_inheritable(inherited_fd, True)
    command = provider_lab._command
    source = Path(provider_lab.__file__).with_name("provider_worker.py").read_text()
    checks = (
        "    assert 'OPENAI_API_KEY' not in os.environ and 'HTTPS_PROXY' not in os.environ\n"
        f"    assert not os.path.exists({str(sentinel)!r})\n"
        f"    assert not os.path.exists({('/proc/' + str(os.getpid()) + '/root' + str(sentinel))!r})\n"
        f"    assert not os.path.exists('/proc/self/fd/{inherited_fd}')\n"
        "    assert not os.path.exists('/run/provider/server.key')\n"
        "    assert not os.path.exists('/run/provider/server.crt')\n"
        "    assert not os.path.exists('/usr/sbin/nft')\n"
        # Startup checks all inherited descriptors before runtime imports.
        # ctypes may subsequently retain a handle to its mounted libffi.
        "    for fd in os.listdir('/proc/self/fd'):\n"
        "        try:\n"
        "            target = os.readlink('/proc/self/fd/' + fd)\n"
        "        except (FileNotFoundError, ProcessLookupError):\n"
        "            continue\n"
        "        assert not target.startswith(('user:[', 'net:[', 'mnt:[', 'pid:[', 'ipc:[', 'uts:[', 'cgroup:['))\n"
        "    for path in ('/proc/self/cmdline', '/proc/self/environ'):\n"
        "        with open(path, 'rb') as current:\n"
        "            assert launch['credential'].encode('ascii') not in current.read()\n"
    )
    assert source.count("def execute(launch):\n") == 1
    checked_worker = tmp_path / "checked_provider_worker.py"
    checked_worker.write_text(source.replace("def execute(launch):\n", "def execute(launch):\n" + checks))

    def checked_command(stdlib, files, module):
        argv = command(stdlib, files, module)
        if module == "provider_worker.py":
            index = argv.index("/app/provider_worker.py")
            assert argv[index - 2] == "--ro-bind"
            argv[index - 1] = str(checked_worker)
        return argv

    original_send = provider_lab._send
    credentials = []

    def send(supervisor, process, raw, *, close=False):
        if close and process is supervisor.processes.get("worker"):
            credentials.append(json.loads(raw)["credential"])
        return original_send(supervisor, process, raw, close=close)

    monkeypatch.setattr(provider_lab, "_command", checked_command)
    monkeypatch.setattr(provider_lab, "_send", send)
    audit_path = tmp_path / "audit.jsonl"
    try:
        with AuditSink(audit_path) as audit:
            broker = make_broker(audit=audit)
            body = broker.exchange(OBSERVATION, build_request(OBSERVATION),
                                   control=ExecutionControl(time.monotonic() + 30))
    finally:
        os.close(inherited_fd)
    assert body == success_response() and len(credentials) == 1
    exposed = audit_path.read_text() + json.dumps(broker.last_receipt) + body.decode()
    for _, argv, environment in processes:
        exposed += json.dumps(argv) + json.dumps(environment)
    assert credentials[0] not in exposed
    assert "HOST_ENV_PROVIDER_CANARY" not in exposed
    assert "HOST_PROXY_PROVIDER_CANARY" not in exposed
    assert "HOST_FILE_PROVIDER_CANARY" not in exposed
    assert_boundaries(broker.last_receipt)
    assert_reaped(processes)
