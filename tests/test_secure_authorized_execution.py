"""Authority launch binding, independent validation, and real fixture evidence."""

from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import authorized_execution as authority, executor_worker as executor, isolation, worker
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import SessionLimits
from recon_cockpit.secure_agent.session_planner import proposal
from scripts.secure_agent_session_demo import demo_policy


SESSION_ID = str(UUID(int=123))
NONCE = "ab" * 32
CHECKS = dict.fromkeys({"forbidden_ip_blocked", "forbidden_port_blocked",
                       "namespace_creation_blocked", "capabilities_dropped"}, True)


def action(step=1):
    return parse_action(proposal("three_step", {"step": step, "untrusted_observation": None})["action"])


def launch():
    chosen = action()
    policy = demo_policy()
    limits = SessionLimits()
    return {
        "schema_version": "1", "mode": "fixture", "execute": True, "session_id": SESSION_ID,
        "nonce": NONCE, "sequence": 1, "action": chosen.to_dict(), "action_digest": chosen.digest,
        "policy": policy.to_dict(), "policy_digest": policy.digest,
        "limits": asdict(limits), "limits_digest": limits.digest, "deadline": 110.0,
        "output_reserved_before": 0, "output_reserved_after": 1024,
        "host_namespaces": {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")},
    }


def verifier(raw, *, nonce=NONCE, now=100.0):
    return executor.LaunchVerifier(nonce, hashlib.sha256(raw).hexdigest(), clock=lambda: now)


def test_launch_is_consumed_once_and_contains_no_approval_or_backend_override():
    raw = executor.encode(launch())
    trusted = verifier(raw)
    request, deadline = trusted.consume(raw)
    assert deadline == 110.0
    assert request == {"target": "127.0.0.1", "parameters": action().parameters.to_dict(),
                       "verify_boundary": True, "host_namespaces": launch()["host_namespaces"]}
    with pytest.raises(ValueError, match="already_consumed"):
        trusted.consume(raw)


def test_previous_launch_cannot_be_replayed_into_a_fresh_nonce():
    raw = executor.encode(launch())
    with pytest.raises(ValueError, match="invalid_executor_launch"):
        verifier(raw, nonce="cd" * 32).consume(raw)


@pytest.mark.parametrize("field,value", [
    ("action", {**action().to_dict(), "rationale": "changed after authority decision"}),
    ("session_id", str(UUID(int=124))), ("deadline", 120.0), ("sequence", 2),
])
def test_committed_context_rejects_changed_action_session_deadline_or_sequence(field, value):
    original = executor.encode(launch())
    changed = launch()
    changed[field] = value
    trusted = verifier(original)
    with pytest.raises(ValueError, match="context_mismatch"):
        trusted.consume(executor.encode(changed))
    with pytest.raises(ValueError, match="already_consumed"):
        trusted.consume(original)


@pytest.mark.parametrize("change", [
    {"schema_version": "2"}, {"mode": "routed"}, {"execute": False}, {"execute": 1},
    {"approval": True}, {"verify_boundary": False}, {"command": "id"},
    {"session_id": "not-a-uuid"}, {"sequence": 0}, {"sequence": 4}, {"sequence": True},
    {"deadline": 100.0}, {"deadline": 160.01}, {"deadline": True},
    {"action_digest": "0" * 64}, {"policy_digest": "0" * 64}, {"limits_digest": "0" * 64},
    {"output_reserved_before": -1}, {"output_reserved_before": True},
    {"output_reserved_before": 1}, {"output_reserved_after": 1023}, {"output_reserved_after": 4096},
    {"host_namespaces": {}}, {"host_namespaces": {"user": "net:[100]"}},
])
def test_independent_validation_rejects_bad_context_even_if_host_committed_it(change):
    value = {**launch(), **change}
    raw = executor.encode(value)
    with pytest.raises(ValueError):
        verifier(raw).consume(raw)


@pytest.mark.parametrize("name,value", [
    ("max_steps", 17), ("max_runtime_seconds", 601), ("max_output_bytes", 1048577),
    ("max_steps", True), ("max_output_bytes", 0),
])
def test_executor_resource_ceilings_are_independent_of_committed_limit_digest(name, value):
    envelope = launch()
    envelope["limits"][name] = value
    envelope["limits_digest"] = executor.digest(envelope["limits"])
    raw = executor.encode(envelope)
    with pytest.raises(ValueError, match="invalid_executor_limits"):
        verifier(raw).consume(raw)


@pytest.mark.parametrize("mode", ["target", "port", "allowance", "broadened_policy", "authority_field"])
def test_executor_rechecks_policy_schema_and_fixture_scope(mode):
    envelope = launch()
    if mode == "target":
        envelope["action"]["target"] = "127.0.0.2"
    elif mode == "port":
        envelope["action"]["parameters"]["port"] = 80
        envelope["policy"]["allowed_ports"] = [80]
    elif mode == "allowance":
        envelope["action"]["parameters"]["max_output_bytes"] = 2048
        envelope["output_reserved_after"] = 2048
    elif mode == "broadened_policy":
        envelope["policy"]["allowed_targets"] = ["127.0.0.0/8"]
        envelope["action"]["target"] = "127.0.0.2"
    else:
        envelope["action"]["approval_reference"] = "forged"
    envelope["action_digest"] = executor.digest(envelope["action"])
    envelope["policy_digest"] = executor.digest(envelope["policy"])
    raw = executor.encode(envelope)
    with pytest.raises(ValueError):
        verifier(raw).consume(raw)


@pytest.mark.parametrize("mode", ["oversize", "second_request", "duplicate_key", "truncated"])
def test_launch_requires_one_bounded_complete_json_object(mode):
    raw = executor.encode(launch())
    if mode == "oversize":
        raw += b" " * 32768
    elif mode == "second_request":
        raw += raw
    elif mode == "duplicate_key":
        raw = b'{"mode":"fixture",' + raw[1:]
    else:
        raw = raw[:-1]
    with pytest.raises(ValueError):
        verifier(raw).consume(raw)


def test_worker_requires_pipe_and_checks_launch_before_fixture_code(monkeypatch, capsys):
    raw = executor.encode({**launch(), "execute": False})
    monkeypatch.setattr(executor.sys, "argv", ["executor", NONCE, hashlib.sha256(raw).hexdigest()])
    monkeypatch.setattr(executor.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw), close=lambda: None))
    monkeypatch.setattr(executor.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO))
    monkeypatch.setattr(executor.worker, "execute", lambda *a, **k: pytest.fail("must validate before fixture setup"))
    assert executor.main() == 78
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "secure_executor_launch_refused\n"


def test_executor_direct_host_entry_has_static_failure_and_no_traceback():
    result = subprocess.run([sys.executable, "-I", "-S", str(Path(executor.__file__)), NONCE, "0" * 64],
                            input=b"{}", capture_output=True, timeout=2, check=False)
    assert result.returncode == 78
    assert result.stdout == b""
    assert result.stderr == b"secure_executor_launch_refused\n"


@pytest.fixture
def fake_launch(monkeypatch):
    backend = AuthorizedFixtureBackend(demo_policy(), SESSION_ID, SessionLimits(), execute=True)
    monkeypatch.setattr(backend, "check_available", lambda action=None: None)
    monkeypatch.setattr(authority, "_runtime_files", lambda *a, **k: ("/usr/lib/python3.11", []))
    monkeypatch.setattr(authority, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(authority, "_namespaces", lambda: launch()["host_namespaces"])
    calls = []
    reply = {"code": 0, "reason": None, "body": {"status": "succeeded", "boundary_checks": CHECKS}}

    def capture(argv, request, *args, **kwargs):
        calls.append((argv, json.loads(request), kwargs))
        nonce, commitment = argv[-2:]
        executor.LaunchVerifier(nonce, commitment).consume(request)
        return reply["code"], json.dumps(reply["body"]).encode(), b"private diagnostic", reply["reason"]

    monkeypatch.setattr(authority, "_capture_bounded", capture)
    return backend, calls, reply


def test_authority_reserves_monotonic_fresh_contexts_without_mounting_host_authority(fake_launch):
    backend, calls, _reply = fake_launch
    control = ExecutionControl(time.monotonic() + 20)
    for step in (1, 2):
        assert backend.run(action(step), demo_policy(), control=control)["status"] == "succeeded"
    assert dict(backend.snapshot) == {"executions_reserved": 2, "output_bytes_reserved": 2048}
    assert calls[0][1]["nonce"] != calls[1][1]["nonce"]
    assert [call[1]["sequence"] for call in calls] == [1, 2]
    assert [call[1]["output_reserved_before"] for call in calls] == [0, 1024]
    assert all(call[1]["session_id"] == SESSION_ID and call[1]["deadline"] == control.deadline for call in calls)
    assert all(call[2]["control"] is control for call in calls)
    command = calls[0][0]
    sources = [command[index + 1] for index, value in enumerate(command) if value == "--ro-bind"]
    names = {Path(source).name for source in sources}
    assert {"worker.py", "executor_worker.py", "models.py"} <= names
    assert not names & {"controller.py", "approvals.py", "audit.py", "session.py", "openai_broker.py",
                        "authorized_execution.py", "control_plane.py", "coordinator_worker.py"}
    assert not set(sources) & {"/", "/home", "/etc", "/run"}
    assert "--unshare-net" in command and "--clearenv" in command and "--new-session" in command
    with pytest.raises(TypeError):
        backend.snapshot["executions_reserved"] = 0


@pytest.mark.parametrize("mode", ["policy", "scope", "missing_control", "foreign_clock", "extended_deadline"])
def test_adapter_refuses_wrong_authority_before_a_reservation_or_launch(fake_launch, mode):
    backend, calls, _reply = fake_launch
    selected, policy, control = action(), demo_policy(), ExecutionControl(time.monotonic() + 20)
    if mode == "policy":
        policy = parse_policy({**policy.to_dict(), "policy_version": "changed-policy"})
    elif mode == "scope":
        selected = parse_action({**selected.to_dict(), "target": "127.0.0.2"})
    elif mode == "missing_control":
        control = None
    elif mode == "foreign_clock":
        control = ExecutionControl(110, clock=lambda: 100)
    else:
        control = ExecutionControl(time.monotonic() + 120)
    with pytest.raises(IsolationUnavailable):
        backend.run(selected, policy, control=control)
    assert calls == []
    assert dict(backend.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}


def test_dry_mode_cannot_be_upgraded_by_calling_run(monkeypatch):
    backend = AuthorizedFixtureBackend(demo_policy(), SESSION_ID, SessionLimits())
    monkeypatch.setattr(authority, "_runtime_files", lambda *a, **k: pytest.fail("dry-run launched a helper"))
    with pytest.raises(IsolationUnavailable):
        backend.run(action(), demo_policy(), control=ExecutionControl(time.monotonic() + 20))
    assert backend.snapshot["executions_reserved"] == 0


def test_policy_and_limits_are_cloned_at_construction():
    policy, limits = demo_policy(), SessionLimits()
    backend = AuthorizedFixtureBackend(policy, SESSION_ID, limits, execute=True)
    object.__setattr__(policy, "require_approval", True)
    object.__setattr__(limits, "max_steps", 16)
    assert backend._policy.require_approval is False
    assert backend._limits.max_steps == 3


def test_session_control_identity_cannot_reset_cancellation_or_deadline(fake_launch):
    backend, calls, _reply = fake_launch
    control = ExecutionControl(time.monotonic() + 20, cancelled=threading.Event())
    backend.run(action(), demo_policy(), control=control)
    replacement = ExecutionControl(control.deadline, cancelled=threading.Event())
    with pytest.raises(IsolationUnavailable, match="cannot be replaced"):
        backend.run(action(2), demo_policy(), control=replacement)
    assert len(calls) == 1
    assert backend.snapshot["executions_reserved"] == 1


@pytest.mark.parametrize("failure", ["helper", "bad_result", "false_boundary", "deadline"])
def test_failed_execution_keeps_full_reservation(fake_launch, monkeypatch, failure):
    backend, _calls, reply = fake_launch
    if failure == "helper":
        reply["code"] = 78
    elif failure == "bad_result":
        reply["body"] = []
    elif failure == "false_boundary":
        reply["body"] = {"status": "succeeded", "boundary_checks": {**CHECKS, "forbidden_ip_blocked": False}}
    else:
        def stopped(*args, **kwargs):
            raise ExecutionStopped("session_timeout")
        monkeypatch.setattr(authority, "_capture_bounded", stopped)
    with pytest.raises((IsolationUnavailable, ExecutionStopped)):
        backend.run(action(), demo_policy(), control=ExecutionControl(time.monotonic() + 20))
    assert dict(backend.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 1024}


@pytest.mark.parametrize("reason", ["session_timeout", "session_cancelled"])
def test_stop_during_result_decode_cannot_return_success(fake_launch, monkeypatch, reason):
    backend, _calls, _reply = fake_launch
    now = [100.0]
    clock = lambda: now[0]
    cancelled = threading.Event()
    control = ExecutionControl(110.0, cancelled=cancelled, clock=clock)
    monkeypatch.setattr(authority, "time", SimpleNamespace(monotonic=clock))
    raw = json.dumps({"status": "succeeded", "boundary_checks": CHECKS}).encode()
    monkeypatch.setattr(authority, "_capture_bounded", lambda *a, **k: (0, raw, b"", None))

    def decode(raw):
        result = json.loads(raw)
        if reason == "session_timeout":
            now[0] = 111.0
        else:
            cancelled.set()
        return result

    monkeypatch.setattr(authority, "json", SimpleNamespace(loads=decode))
    with pytest.raises(ExecutionStopped) as error:
        backend.run(action(), demo_policy(), control=control)
    assert error.value.reason == reason
    assert dict(backend.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 1024}


def test_exhausted_adapter_cannot_launch_more_actions_or_refund_results(fake_launch):
    backend, calls, _reply = fake_launch
    control = ExecutionControl(time.monotonic() + 20)
    for step in (1, 2, 3):
        backend.run(action(step), demo_policy(), control=control)
    with pytest.raises(IsolationUnavailable, match="budget exhausted"):
        backend.run(action(), demo_policy(), control=control)
    assert len(calls) == 3
    assert dict(backend.snapshot) == {"executions_reserved": 3, "output_bytes_reserved": 3072}


def test_expired_fixture_deadline_refuses_before_nft_or_socket_setup(monkeypatch):
    request, _ = verifier(executor.encode(launch())).consume(executor.encode(launch()))
    monkeypatch.setattr(worker, "assert_private_namespaces", lambda _: None)
    monkeypatch.setattr(worker.subprocess, "run", lambda *a, **k: pytest.fail("expired nft launch"))
    monkeypatch.setattr(worker, "OwnedFixture", lambda *a, **k: pytest.fail("expired socket setup"))
    with pytest.raises(TimeoutError, match="deadline expired"):
        worker.execute(request, deadline=time.monotonic() - 1)


def test_deadline_used_up_by_privilege_setup_prevents_fixture_socket(monkeypatch):
    request, _ = verifier(executor.encode(launch())).consume(executor.encode(launch()))
    now = [100.0]
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(worker, "assert_private_namespaces", lambda _: None)
    monkeypatch.setattr(worker, "_set_limits", lambda _: None)
    monkeypatch.setattr(worker.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(worker, "drop_privileges", lambda: now.__setitem__(0, 111.0))
    monkeypatch.setattr(worker, "OwnedFixture", lambda *a, **k: pytest.fail("expired fixture socket"))
    with pytest.raises(TimeoutError, match="deadline expired"):
        worker.execute(request, deadline=110.0)


@pytest.mark.integration
def test_real_authorized_executor_controller_pipe_and_kernel_boundary(tmp_path):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real executor isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux":
        pytest.skip("real executor isolation requires Linux")
    policy = demo_policy()
    backend = AuthorizedFixtureBackend(policy, SESSION_ID, SessionLimits(), execute=True)
    backend.check_available()
    path = tmp_path / "audit.jsonl"
    control = ExecutionControl(time.monotonic() + 30)
    with AuditSink(path) as audit:
        controller = Controller(policy, audit, backend, session_id=SESSION_ID)
        result = controller.submit(action(2).to_dict(), execute=True, execution_control=control, session_step=1)
    assert result["execution_status"] == "succeeded", result
    assert result["untrusted_result"]["boundary_checks"] == CHECKS
    assert result["untrusted_result"]["results"][0]["body"] == worker.INJECTION_FIXTURE.decode("ascii")
    assert dict(backend.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 1024}
    text = path.read_text()
    assert "Ignore prior instructions" not in text
    records = [json.loads(line) for line in text.splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in records) == 1
    assert sum(event["event_type"] == "execution_finished" for event in records) == 1
    assert all(event.get("approval_reference") is None for event in records)
