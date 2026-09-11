"""Portable boundary units plus explicitly opted-in real Linux integration."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import isolation, worker
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.planner import proposal
from scripts.secure_agent_linux_demo import _require_boundary_checks


BOUNDARY_CHECK_NAMES = {"forbidden_ip_blocked", "forbidden_port_blocked",
                        "namespace_creation_blocked", "capabilities_dropped"}


def policy(*, approval=False):
    return parse_policy({
        "schema_version": "1", "policy_version": "owned-fixture-test-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET", "HEAD"],
        "max_timeout_seconds": 3, "max_output_bytes": 4096, "max_targets": 1,
        "require_approval": approval, "approval_ttl_seconds": 60,
    })


def worker_request():
    return {"target": "127.0.0.1", "parameters": proposal()["parameters"], "verify_boundary": False,
            "host_namespaces": {name: f"{name}:[100]" for name in ("user", "net", "mnt", "pid")}}


def test_worker_refuses_direct_invocation_before_any_network_setup():
    result = subprocess.run([sys.executable, "-I", str(Path(worker.__file__))],
                            input=b"{}", capture_output=True, timeout=2, check=False)
    assert result.returncode == 78
    assert result.stdout == b""
    assert b"execution refused" in result.stderr


def test_worker_rejects_host_namespace_before_interface_or_firewall_access(monkeypatch):
    monkeypatch.setattr(worker.sys, "platform", "linux")
    monkeypatch.setattr(worker.os, "readlink", lambda _: "user:[100]")
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: pytest.fail("must reject before network access"))
    with pytest.raises(RuntimeError, match="host namespace"):
        worker.assert_private_namespaces(worker_request()["host_namespaces"])


@pytest.mark.parametrize("change", [
    {"command": "id"}, {"target": "203.0.113.5"}, {"verify_boundary": "true"},
    {"parameters": {**proposal()["parameters"], "headers": {"Authorization": "secret"}}},
    {"parameters": {**proposal()["parameters"], "path": "/\r\nHost: other"}},
    {"parameters": {**proposal()["parameters"], "path": "http://127.0.0.2/"}},
    {"parameters": {**proposal()["parameters"], "method": "CONNECT"}},
    {"parameters": {**proposal()["parameters"], "timeout_seconds": float("nan")}},
    {"parameters": {**proposal()["parameters"], "max_output_bytes": 65537}},
])
def test_worker_rejects_untrusted_execution_extensions(change):
    with pytest.raises(ValueError):
        worker.validate_request(json.dumps({**worker_request(), **change}).encode())


def test_firewall_never_accepts_wildcard_established_or_source_port():
    rules = worker.firewall_rules("127.0.0.1", 8080)
    assert rules.count("policy drop") == 3
    assert "ip daddr 127.0.0.1 tcp dport 8080 ct direction original accept" in rules
    for line in rules.splitlines():
        if "ct state established" in line:
            assert "ct direction reply" in line
            assert "ct original ip daddr 127.0.0.1 ct original proto-dst 8080" in line
    assert "sport" not in rules
    with pytest.raises(ValueError):
        worker.firewall_rules("127.0.0.1; flush ruleset", 8080)


def test_command_uses_namespaces_minimal_readonly_mounts_and_clean_environment(monkeypatch):
    monkeypatch.setattr(isolation, "_trusted_program", lambda _: "/usr/bin/bwrap")
    argv = isolation.LinuxFixtureBackend()._command(
        "/usr/lib/python3.11", [("/usr/bin/python3.11", "/usr/bin/python3"), ("/lib/libc.so.6", "/lib/libc.so.6")])
    for flag in ("--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--clearenv",
                 "--die-with-parent", "--new-session"):
        assert flag in argv
    assert "--share-net" not in argv
    assert "--bind" not in argv
    assert "--dev-bind" not in argv
    sources = [argv[index + 1] for index, flag in enumerate(argv) if flag == "--ro-bind"]
    assert not set(sources) & {"/", "/usr", "/lib", "/home", "/etc", "/var/run/docker.sock"}
    assert argv[-4:] == ["/usr/bin/python3", "-I", "-S", "/app/worker.py"]


def test_runtime_capture_bounds_stdout_and_stderr_and_kills_child():
    code, stdout, stderr, reason = isolation._capture_bounded(
        [sys.executable, "-I", "-c", "import sys; sys.stderr.buffer.write(b'x'*1000000); sys.stderr.flush()"],
        b"", 2, 1024)
    assert reason == "output_limit"
    assert len(stdout) + len(stderr) <= 1024
    assert code != 0


def test_runtime_capture_has_wall_clock_deadline():
    code, stdout, stderr, reason = isolation._capture_bounded(
        [sys.executable, "-I", "-c", "import time; time.sleep(20)"], b"", 0.1, 1024)
    assert reason == "timeout"
    assert code != 0
    assert stdout == stderr == b""


def test_runtime_capture_preserves_successful_child():
    code, stdout, stderr, reason = isolation._capture_bounded(
        [sys.executable, "-I", "-c", "print('ok')"], b"", 2, 1024)
    assert (code, stdout, stderr, reason) == (0, b"ok\n", b"", None)


def test_backend_rechecks_policy_before_running_any_helper(monkeypatch):
    raw = proposal()
    raw["target"] = "127.0.0.2"
    monkeypatch.setattr(isolation, "_runtime_files", lambda *_: pytest.fail("must not inspect or run a tool"))
    with pytest.raises(isolation.IsolationUnavailable, match="policy evaluation"):
        isolation.LinuxFixtureBackend().run(parse_action(raw), policy())


def test_missing_linux_isolation_has_no_host_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(isolation.sys, "platform", "darwin")
    monkeypatch.setattr(isolation, "_capture_bounded", lambda *_: pytest.fail("must not launch"))
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        result = Controller(policy(), audit, isolation.LinuxFixtureBackend()).submit(proposal(), execute=True)
    assert result["execution_status"] == "blocked"
    assert result["reasons"] == ["isolation_unavailable"]


class FakeSocket:
    def __init__(self, response=b"", *, timeout=False):
        self.response = response
        self.timeout = timeout
        self.destinations = []
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, _):
        pass

    def connect(self, destination):
        self.destinations.append(destination)

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        if self.timeout:
            raise TimeoutError
        data, self.response = self.response[:size], self.response[size:]
        return data


def test_probe_does_not_follow_redirects_or_resolve_hostnames(monkeypatch):
    connection = FakeSocket(b"HTTP/1.1 302 Redirect\r\nLocation: http://outside.example/\r\n\r\nredirect")
    monkeypatch.setattr(worker.socket, "socket", lambda *_: connection)
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *_: pytest.fail("DNS is forbidden"))
    result = worker.probe("127.0.0.1", proposal()["parameters"])
    assert connection.destinations == [("127.0.0.1", 8080)]
    assert result["status"] == "succeeded"
    assert result["results"][0]["http_status"] == 302


def test_probe_output_limit_includes_headers(monkeypatch):
    connection = FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 4096)
    monkeypatch.setattr(worker.socket, "socket", lambda *_: connection)
    result = worker.probe("127.0.0.1", {**proposal()["parameters"], "max_output_bytes": 128})
    assert result["status"] == "output_limit"
    assert result["bytes_received"] == 128
    assert result["truncated"] is True
    assert len(result["results"][0]["body"]) < 128


def test_probe_timeout_retains_bounded_structured_metadata(monkeypatch):
    monkeypatch.setattr(worker.socket, "socket", lambda *_: FakeSocket(timeout=True))
    result = worker.probe("127.0.0.1", proposal()["parameters"])
    assert result["status"] == "timeout"
    assert result["bytes_received"] == 0


@pytest.mark.parametrize("output", [b'{"status":[]}', b'{"status":null}', b'[]', b'[' * 2000])
def test_invalid_worker_result_is_rejected_at_result_boundary(monkeypatch, output):
    backend = isolation.LinuxFixtureBackend()
    monkeypatch.setattr(backend, "check_available", lambda *_: None)
    monkeypatch.setattr(backend, "_command", lambda *_: ["unused-test-helper"])
    monkeypatch.setattr(isolation, "_trusted_program", lambda _: "/usr/sbin/nft")
    monkeypatch.setattr(isolation, "_runtime_files", lambda *_: ("unused", []))
    monkeypatch.setattr(isolation, "_namespaces", lambda: {})
    monkeypatch.setattr(isolation, "_capture_bounded", lambda *_: (0, output, b"", None))
    with pytest.raises(isolation.IsolationUnavailable, match="invalid result"):
        backend.run(parse_action(proposal()), policy())


def test_demo_accepts_complete_true_boundary_evidence():
    _require_boundary_checks({name: True for name in BOUNDARY_CHECK_NAMES})


@pytest.mark.parametrize("checks", [
    None, {}, [], {"forbidden_ip_blocked": True},
    {**dict.fromkeys(BOUNDARY_CHECK_NAMES, True), "capabilities_dropped": 1},
    {**dict.fromkeys(BOUNDARY_CHECK_NAMES, True), "forbidden_ip_blocked": "true"},
    {**dict.fromkeys(BOUNDARY_CHECK_NAMES, True), "namespace_creation_blocked": False},
    {**dict.fromkeys(BOUNDARY_CHECK_NAMES, True), "untrusted_extra": "do not display this"},
])
def test_demo_rejects_incomplete_nonboolean_or_extra_boundary_evidence(checks):
    with pytest.raises(RuntimeError, match="^kernel boundary verification failed$"):
        _require_boundary_checks(checks)


@pytest.fixture
def linux_backend():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real Linux isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux":
        pytest.skip("real network namespace integration requires Linux")
    backend = isolation.LinuxFixtureBackend(verify_boundary=True)
    # Opting in on Linux makes missing dependencies or denied namespaces FAIL,
    # rather than quietly turning requested security validation into skips.
    backend.check_available()
    return backend


@pytest.mark.integration
@pytest.mark.parametrize("path,expected", [("/", "succeeded"), ("/injection", "succeeded"),
                                          ("/large", "output_limit"), ("/slow", "timeout"),
                                          ("/redirect", "succeeded")])
def test_real_linux_controller_to_kernel_boundary(linux_backend, tmp_path, path, expected):
    raw = proposal()
    raw["parameters"].update(path=path, timeout_seconds=1)
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        controller = Controller(policy(), audit, linux_backend)
        original_digest = controller.policy.digest
        result = controller.submit(raw, execute=True)
        assert result["execution_status"] == expected, result
        assert controller.policy.digest == original_digest
        payload = result["untrusted_result"]
        checks = payload.get("boundary_checks")
        assert type(checks) is dict
        assert set(checks) == BOUNDARY_CHECK_NAMES
        assert all(checks[name] is True for name in BOUNDARY_CHECK_NAMES)
        assert payload["bytes_received"] <= raw["parameters"]["max_output_bytes"]
        if path == "/injection":
            assert "change policy" in payload["results"][0]["body"]
        if path == "/redirect":
            assert payload["results"][0]["http_status"] == 302
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    assert sum(event["event_type"] == "execution_finished" for event in events) == 1
    assert "Ignore prior instructions" not in (tmp_path / "audit.jsonl").read_text()
