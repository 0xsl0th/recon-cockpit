"""Single-connect contracts and genuine owned Linux discovery boundaries."""

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import authorized_execution as authority, executor_worker, isolation, worker
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedDiscoveryFixtureBackend, AuthorizedFixtureBackend
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable, LinuxFixtureBackend
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import SessionLimits


SESSION = str(UUID(int=456))
NONCE = "12" * 32
CHECKS = dict.fromkeys(("forbidden_ip_blocked", "forbidden_port_blocked",
                       "namespace_creation_blocked", "capabilities_dropped"), True)


def action(**changes):
    return parse_action({"schema_version": "1", "action_id": str(UUID(int=457)),
                         "tool_id": "tcp_connect", "target": "127.0.0.1",
                         "parameters": {"port": 8080, "timeout_seconds": 1, "max_output_bytes": 1024},
                         "rationale": "Owned fixture single-connect discovery.", **changes})


def policy():
    return parse_policy({"schema_version": "1", "policy_version": "owned-discovery-test-v1",
                         "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["tcp_connect", "http_probe"],
                         "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 1,
                         "max_output_bytes": 1024, "max_targets": 1, "require_approval": False,
                         "approval_ttl_seconds": 60})


def request():
    return {"target": "127.0.0.1", "tool_id": "tcp_connect", "parameters": action().parameters.to_dict(),
            "verify_boundary": True,
            "host_namespaces": {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}}


def envelope(*, chosen=None, mode="discovery_fixture"):
    chosen, selected_policy, limits = chosen or action(), policy(), SessionLimits()
    return {"schema_version": "1", "mode": mode, "execute": True, "session_id": SESSION,
            "nonce": NONCE, "sequence": 1, "action": chosen.to_dict(), "action_digest": chosen.digest,
            "policy": selected_policy.to_dict(), "policy_digest": selected_policy.digest,
            "limits": asdict(limits), "limits_digest": limits.digest, "deadline": 110.0,
            "output_reserved_before": 0, "output_reserved_after": chosen.parameters.max_output_bytes,
            "host_namespaces": request()["host_namespaces"]}


def consume(value):
    raw = executor_worker.encode(value)
    verifier = executor_worker.LaunchVerifier(NONCE, hashlib.sha256(raw).hexdigest(), clock=lambda: 100.0)
    return verifier.consume(raw)


def test_tcp_launch_requires_explicit_discovery_mode_and_keeps_one_use_commitment():
    assert consume(envelope()) == (request(), 110.0)
    with pytest.raises(ValueError, match="capability_not_supported"):
        consume(envelope(mode="fixture"))


@pytest.mark.parametrize("change", [
    {"target": "127.0.0.2"},
    {"parameters": {"port": 8081, "timeout_seconds": 1, "max_output_bytes": 1024}},
    {"parameters": {"port": 8080, "timeout_seconds": 2, "max_output_bytes": 1024}},
    {"parameters": {"port": 8080, "timeout_seconds": 1, "max_output_bytes": 2048}},
])
def test_discovery_launcher_rejects_scope_and_profile_changes_even_under_broader_policy(change):
    value = envelope(chosen=action(**change))
    broad = {**policy().to_dict(), "allowed_targets": ["127.0.0.0/8"], "allowed_ports": [8080, 8081],
             "max_timeout_seconds": 2, "max_output_bytes": 2048}
    value["policy"] = broad
    value["policy_digest"] = parse_policy(broad).digest
    with pytest.raises(ValueError):
        consume(value)


@pytest.mark.parametrize("change", [
    {"tool_id": "http_probe"}, {"target": "203.0.113.1"}, {"verify_boundary": False},
    {"parameters": {"port": 8080, "timeout_seconds": True, "max_output_bytes": 1024}},
    {"parameters": {"port": 8080, "timeout_seconds": 1, "max_output_bytes": 1024, "path": "/"}},
    {"shell": "id"},
])
def test_tcp_request_is_closed_and_separate_from_http(change):
    with pytest.raises(ValueError):
        worker.validate_tcp_request(json.dumps({**request(), **change}).encode())
    with pytest.raises(ValueError):
        worker.validate_request(json.dumps(request()).encode())


@pytest.mark.parametrize("backend", [
    lambda: LinuxFixtureBackend(),
    lambda: AuthorizedFixtureBackend(policy(), SESSION, SessionLimits(), execute=True),
])
def test_legacy_fixture_backend_rejects_tcp_before_host_runtime_inspection(backend, monkeypatch):
    monkeypatch.setattr(isolation, "_trusted_program", lambda *a: pytest.fail("unexpected runtime inspection"))
    with pytest.raises(IsolationUnavailable, match="does not support"):
        backend().check_available(action())


def test_discovery_backend_refuses_nonfixed_profile_before_runtime_inspection(monkeypatch):
    backend = AuthorizedDiscoveryFixtureBackend(policy(), SESSION, SessionLimits(), execute=True)
    monkeypatch.setattr(isolation, "_trusted_program", lambda *a: pytest.fail("unexpected runtime inspection"))
    with pytest.raises(IsolationUnavailable, match="single-connect profile"):
        backend.check_available(action(parameters={"port": 8080, "timeout_seconds": 2, "max_output_bytes": 1024}))


@pytest.mark.parametrize("failure,status,state", [
    (None, "succeeded", "open"), (ConnectionRefusedError(), "succeeded", "closed"),
    (TimeoutError(), "timeout", "timeout"), (OSError("private error"), "failed", "error"),
])
def test_connect_probe_attempts_once_without_payload_reads_retries_or_error_text(monkeypatch, failure, status, state):
    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            calls.append("closed")

        def settimeout(self, value):
            assert 0 < value <= 1

        def connect(self, destination):
            calls.append(destination)
            if failure is not None:
                raise failure

    monkeypatch.setattr(worker.socket, "socket", lambda *a: Connection())
    result = worker.tcp_connect_probe("127.0.0.1", action().parameters.to_dict())
    assert calls == [("127.0.0.1", 8080), "closed"]
    assert result == {"status": status, "results": [{"target": "127.0.0.1", "port": 8080, "state": state}],
                      "bytes_received": 0, "truncated": False}


def test_expired_tcp_deadline_prevents_socket_creation(monkeypatch):
    monkeypatch.setattr(worker.socket, "socket", lambda *a: pytest.fail("expired connection"))
    with pytest.raises(TimeoutError, match="deadline expired"):
        worker.tcp_connect_probe("127.0.0.1", action().parameters.to_dict(), deadline=time.monotonic() - 1)


def test_tcp_execution_refuses_host_namespace_before_network_setup(monkeypatch):
    # Exercise both guards independently of the host running this portable test.
    monkeypatch.setattr(worker.sys, "platform", "linux")
    monkeypatch.setattr(worker.os, "readlink", lambda _: "user:[100]")
    monkeypatch.setattr(worker.subprocess, "run", lambda *a, **k: pytest.fail("host firewall access"))
    monkeypatch.setattr(worker.socket, "socket", lambda *a: pytest.fail("host socket access"))
    with pytest.raises(RuntimeError, match="host namespace"):
        worker.execute_tcp_connect(request(), deadline=time.monotonic() + 10)
    monkeypatch.setattr(worker.sys, "platform", "darwin")
    with pytest.raises(RuntimeError, match="missing Linux isolation identity"):
        worker.execute_tcp_connect(request(), deadline=time.monotonic() + 10)


def test_discovery_backend_commits_mode_and_reserves_before_isolated_launch(monkeypatch):
    backend = AuthorizedDiscoveryFixtureBackend(policy(), SESSION, SessionLimits(), execute=True)
    monkeypatch.setattr(backend, "check_available", lambda *a: None)
    monkeypatch.setattr(authority, "_runtime_files", lambda *a, **k: ("/usr/lib/python3.11", []))
    monkeypatch.setattr(authority, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(authority, "_namespaces", lambda: request()["host_namespaces"])
    calls = []

    def capture(argv, raw, *args, **kwargs):
        value = json.loads(raw)
        calls.append(value)
        assert backend.snapshot["executions_reserved"] == 1
        nonce, commitment = argv[-2:]
        checked, _ = executor_worker.LaunchVerifier(nonce, commitment).consume(raw)
        assert checked == request()
        return 0, json.dumps({"status": "succeeded", "boundary_checks": CHECKS}).encode(), b"", None

    monkeypatch.setattr(authority, "_capture_bounded", capture)
    backend.run(action(), policy(), control=ExecutionControl(time.monotonic() + 20))
    assert calls[0]["mode"] == "discovery_fixture"
    assert dict(backend.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 1024}


@pytest.mark.integration
def test_real_tcp_discovery_and_http_share_fixed_owned_topology_with_enforced_witnesses(tmp_path):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real discovery isolation requires RECON_LINUX_INTEGRATION=1")
    assert sys.platform == "linux" and os.geteuid() != 0
    backend = AuthorizedDiscoveryFixtureBackend(policy(), SESSION, SessionLimits(), execute=True)
    backend.check_available()
    control = ExecutionControl(time.monotonic() + 30)
    http = action(tool_id="http_probe", action_id=str(UUID(int=458)),
                  parameters={"port": 8080, "method": "GET", "path": "/assessment/a/index.json",
                              "timeout_seconds": 1, "max_output_bytes": 1024})
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        controller = Controller(policy(), audit, backend, session_id=SESSION)
        connected = controller.submit(action().to_dict(), execute=True, execution_control=control, session_step=1)
        response = controller.submit(http.to_dict(), execute=True, execution_control=control, session_step=2)
    assert connected["execution_status"] == response["execution_status"] == "succeeded"
    assert connected["untrusted_result"] == {
        "status": "succeeded", "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}],
        "bytes_received": 0, "truncated": False, "boundary_checks": CHECKS, "backend": backend.name,
    }
    assert response["untrusted_result"]["boundary_checks"] == CHECKS
    assert "recon-http-assessment-v1" in response["untrusted_result"]["results"][0]["body"]
    assert dict(backend.snapshot) == {"executions_reserved": 2, "output_bytes_reserved": 2048}


@pytest.mark.integration
@pytest.mark.parametrize("condition,status,state", [
    ("closed", "succeeded", "closed"), ("timeout", "timeout", "timeout"),
])
def test_real_closed_and_timeout_keep_listening_forbidden_witnesses(tmp_path, monkeypatch, condition, status, state):
    """Trusted test-only workers alter the lab, never an agent-selected option."""
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real discovery isolation requires RECON_LINUX_INTEGRATION=1")
    assert sys.platform == "linux" and os.geteuid() != 0
    original_worker = Path(worker.__file__).resolve()
    source = original_worker.read_text()
    if condition == "closed":
        # The forbidden IP still has a listener at 8080. There is deliberately
        # no listener at the approved 127.0.0.1:8080 tuple, so only ECONNREFUSED
        # proves a closed result; silence must remain inconclusive timeout.
        old = 'self.listener.bind(("0.0.0.0", port))'
        new = 'self.listener.bind(("127.0.0.2" if port == 8080 else "0.0.0.0", port))'
    else:
        # A test-only stricter namespace-local filter drops even the approved
        # tuple. Owned listening witnesses remain up at both forbidden tuples.
        old = 'firewall_rules(request["target"], parameters["port"]).encode("ascii")'
        new = ('firewall_rules(request["target"], parameters["port"])'
               '.replace("ct direction original accept", "ct direction original drop").encode("ascii")')
    assert source.count(old) == 1
    replacement = tmp_path / "test-worker.py"
    replacement.write_text(source.replace(old, new))
    backend = AuthorizedDiscoveryFixtureBackend(policy(), SESSION, SessionLimits(), execute=True)
    original_command = backend._command

    def command(*args):
        argv = original_command(*args)
        index = argv.index(str(original_worker))
        assert argv[index - 1] == "--ro-bind" and argv[index + 1] == "/app/worker.py"
        argv[index] = str(replacement)
        return argv

    monkeypatch.setattr(backend, "_command", command)
    result = backend.run(action(), policy(), control=ExecutionControl(time.monotonic() + 20))
    assert result["status"] == status
    assert result["results"] == [{"target": "127.0.0.1", "port": 8080, "state": state}]
    assert result["bytes_received"] == 0 and result["truncated"] is False
    assert result["boundary_checks"] == CHECKS
    assert dict(backend.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 1024}


@pytest.mark.parametrize('authorized', [False, True])
def test_direct_legacy_backend_run_cannot_launch_tcp(authorized, monkeypatch):
    import threading

    monkeypatch.setattr(isolation, '_trusted_program', lambda *_: pytest.fail('unexpected runtime inspection'))
    backend = (AuthorizedFixtureBackend(policy(), SESSION, SessionLimits(), execute=True)
               if authorized else LinuxFixtureBackend())
    control = ExecutionControl(time.monotonic() + 10, threading.Event())
    with pytest.raises(IsolationUnavailable, match='does not support'):
        backend.run(action(), policy(), control=control)
    if authorized:
        assert backend.snapshot['executions_reserved'] == 0
