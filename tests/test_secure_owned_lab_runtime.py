"""Portable adversarial checks for the owned lab's separate launch contract."""

from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import isolation, owned_lab, owned_lab_executor as executor, owned_lab_worker as owner
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.owned_lab_contract import identity
from recon_cockpit.secure_agent.session import SessionLimits


SESSION = str(UUID(int=111))
NONCE = "ab" * 32
HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
LAB = {name: name + ":[101]" for name in HOST}


def policy():
    source = Path(__file__).resolve().parents[1] / "examples/secure-agent-discovery-policy.json"
    return parse_policy({**json.loads(source.read_text()), "require_approval": False})


def envelope(step=1):
    action = parse_action(discovery_action("a", step))
    limits = SessionLimits()
    selected_policy = policy()
    launch = {"schema_version": "1", "mode": "discovery_fixture", "execute": True,
              "session_id": SESSION, "nonce": NONCE, "sequence": step,
              "action": action.to_dict(), "action_digest": action.digest,
              "policy": selected_policy.to_dict(), "policy_digest": selected_policy.digest,
              "limits": asdict(limits), "limits_digest": limits.digest,
              "deadline": time.monotonic() + 30, "output_reserved_before": (step - 1) * 1024,
              "output_reserved_after": step * 1024, "host_namespaces": HOST}
    return {"mode": "owned_lab", "launch": launch, "identity": identity("a", str(UUID(int=222))),
            "namespaces": LAB.copy()}


def consume(value):
    raw = executor.encode(value)
    return executor.validate_launch(raw, NONCE, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("step", [1, 2, 3])
def test_owned_wrapper_rechecks_legacy_authority_and_binds_case_and_namespace(step):
    value = envelope(step)
    request, deadline, namespaces = consume(value)
    assert request["parameters"] == value["launch"]["action"]["parameters"]
    assert namespaces == LAB and deadline == value["launch"]["deadline"]
    assert request["host_namespaces"] == HOST


@pytest.mark.parametrize("change", [
    {"mode": "discovery_fixture"}, {"resume": True}, {"identity": {}},
    {"namespaces": HOST}, {"namespaces": {**LAB, "net": "net:[100]"}},
    {"namespaces": {**LAB, "net": "user:[101]"}}, {"namespaces": {**LAB, "fd": 10}},
])
def test_owned_wrapper_rejects_committed_unknown_modes_identity_and_scope(change):
    with pytest.raises(ValueError):
        consume({**envelope(), **change})


@pytest.mark.parametrize("field,value", [
    ("mode", "fixture"), ("execute", False), ("session_id", "invalid"),
    ("sequence", True), ("deadline", -1), ("policy_digest", "0" * 64),
    ("output_reserved_after", 1025), ("command", "id"),
])
def test_owned_executor_cannot_weaken_existing_independent_authority_validation(field, value):
    data = envelope()
    data["launch"][field] = value
    with pytest.raises(ValueError):
        consume(data)


@pytest.mark.parametrize("change", [
    {"path": "/assessment/b/index.json"}, {"method": "HEAD"},
    {"max_output_bytes": 1000}, {"timeout_seconds": 2},
])
def test_executor_rejects_cross_case_or_nonfixed_http_profile_even_if_policy_permits(change):
    data = envelope(2)
    data["launch"]["action"]["parameters"].update(change)
    action = parse_action(data["launch"]["action"])
    data["launch"]["action_digest"] = action.digest
    data["launch"]["output_reserved_after"] = 1024 + action.parameters.max_output_bytes
    with pytest.raises(ValueError):
        consume(data)


def test_context_commitment_covers_instance_and_namespace_before_any_execution():
    data = envelope()
    raw = executor.encode(data)
    data["namespaces"]["net"] = "net:[999]"
    with pytest.raises(ValueError, match="launch_mismatch"):
        executor.validate_launch(executor.encode(data), NONCE, hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError):
        executor.validate_launch(raw, "cd" * 32, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("change", [
    {"case": ""}, {"case": "ab"}, {"case": "x"}, {"case": True},
    {"deadline": True}, {"deadline": 0}, {"deadline": float("inf")},
    {"target": "203.0.113.1"},
])
def test_owner_request_has_only_fixed_case_host_identity_and_bounded_deadline(change):
    raw = json.dumps({"case": "a", "deadline": time.monotonic() + 30,
                      "host_namespaces": HOST, **change}).encode() + b"\n"
    with pytest.raises(ValueError):
        owner.read_request(io.BytesIO(raw))


def test_owner_rejects_duplicate_fields_and_unterminated_frames():
    raw = json.dumps({"case": "a", "deadline": time.monotonic() + 30, "host_namespaces": HOST}).encode()
    with pytest.raises(ValueError):
        owner.read_request(io.BytesIO(raw))
    with pytest.raises(ValueError):
        owner.read_request(io.BytesIO(b'{"case":"b",' + raw[1:] + b"\n"))


def test_constructor_and_close_never_start_processes_and_instances_are_never_reused(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("metadata cannot start a process"))
    lab = owned_lab.OwnedLab("a", SESSION, SessionLimits())
    another = owned_lab.OwnedLab("a", SESSION, SessionLimits())
    assert not lab.started and lab.identity != another.identity
    assert lab.identity["spec_sha256"] == another.identity["spec_sha256"]
    assert lab.close() == {"identity": lab.identity, "status": "closed", "connection_count": 0, "request_count": 0}
    assert lab.close() == lab.close()
    with pytest.raises(IsolationUnavailable, match="unavailable"):
        lab.start(ExecutionControl(time.monotonic() + 30))


def test_no_owned_runtime_setup_occurs_before_independent_policy_recheck(monkeypatch):
    lab = owned_lab.OwnedLab("a", SESSION, SessionLimits())
    backend = owned_lab.AuthorizedOwnedLabBackend(policy(), SESSION, SessionLimits(), lab, execute=True)
    monkeypatch.setattr(lab, "start", lambda *_: pytest.fail("denied action cannot start a lab"))
    chosen = parse_action({**discovery_action("a", 1), "target": "127.0.0.2"})
    with pytest.raises(IsolationUnavailable, match="authority"):
        backend.run(chosen, policy(), control=ExecutionControl(time.monotonic() + 30))
    assert backend.snapshot["executions_reserved"] == 0


def test_expired_control_cannot_start_or_recreate_the_lab(monkeypatch):
    lab = owned_lab.OwnedLab("a", SESSION, SessionLimits())
    monkeypatch.setattr(isolation, "_trusted_program", lambda *_: pytest.fail("expired control cannot inspect runtime"))
    with pytest.raises(ExecutionStopped):
        lab.start(ExecutionControl(time.monotonic() - 1))
    with pytest.raises(IsolationUnavailable):
        lab.start(ExecutionControl(time.monotonic() + 30))


def test_action_command_joins_only_pinned_namespaces_and_keeps_fresh_user_pid_mount(monkeypatch):
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(owned_lab, "_trusted_program", lambda name: "/usr/bin/" + name)
    lab = owned_lab.OwnedLab("a", SESSION, SessionLimits())
    lab._namespace_fds = (11, 12)
    backend = owned_lab.AuthorizedOwnedLabBackend(policy(), SESSION, SessionLimits(), lab, execute=True)
    argv = backend._command("/usr/lib/python3.13", [], NONCE, "cd" * 32)
    assert argv[:5] == ["/usr/bin/nsenter", "--user=/proc/self/fd/11", "--net=/proc/self/fd/12", "--preserve-credentials", "--"]
    assert argv[5:10] == ["/usr/bin/python3", "-I", "-S", "-c", owned_lab._CLOSE_NAMESPACE_FDS]
    for flag in ("--unshare-user", "--unshare-pid", "--unshare-ipc", "--clearenv", "--die-with-parent"):
        assert flag in argv
    assert "--unshare-net" not in argv and "CAP_NET_ADMIN" not in argv
    assert "CAP_SETPCAP" in argv and "--bind" not in argv
    assert all(not str(item).startswith("/home/") or str(item).endswith(".py") for item in argv)
    assert argv[-6:] == ["/usr/bin/python3", "-I", "-S", "/app/owned_lab_executor.py", NONCE, "cd" * 32]


def test_inherited_namespace_or_management_fd_is_rejected_before_network(monkeypatch):
    descriptor = os.open(os.devnull, os.O_RDONLY)
    try:
        monkeypatch.setattr(executor.os, "listdir", lambda _: ["0", "1", "2", str(descriptor)])
        with pytest.raises(RuntimeError, match="inherited_descriptor"):
            executor.assert_private_descriptors()
    finally:
        os.close(descriptor)


def test_transient_proc_directory_descriptor_is_not_a_leak(monkeypatch):
    descriptor = os.open(os.devnull, os.O_RDONLY)
    os.close(descriptor)
    monkeypatch.setattr(executor.os, "listdir", lambda _: ["0", "1", "2", str(descriptor)])
    executor.assert_private_descriptors()


def test_bounded_capture_passes_only_explicit_fds_and_does_not_close_the_callers_copy():
    reader, writer = os.pipe()
    try:
        argv = [sys.executable, "-I", "-S", "-c", f"import os; os.write({writer},b'owned'); print('ok')"]
        code, stdout, stderr, reason = isolation._capture_bounded(argv, b"", 3, 1024, pass_fds=(writer,))
        assert (code, stdout, stderr, reason) == (0, b"ok\n", b"", None)
        assert os.read(reader, 5) == b"owned"
        os.fstat(writer)
    finally:
        os.close(reader)
        os.close(writer)


@pytest.mark.parametrize("reply,minimum_connections,minimum_requests", [
    ({"sequence": True, "connection_count": 1, "request_count": 0}, 1, 0),
    ({"sequence": 1, "connection_count": 0, "request_count": 0}, 1, 0),
    ({"sequence": 1, "connection_count": 1, "request_count": 0}, 1, 1),
])
def test_counter_acknowledgement_requires_integer_sequence_and_requested_barrier(
        monkeypatch, reply, minimum_connections, minimum_requests):
    lab = owned_lab.OwnedLab("a", SESSION, SessionLimits())
    lab._started = True
    lab._supervisor = SimpleNamespace(processes={"lab": SimpleNamespace(stdin=io.BytesIO())}, close=lambda: None)
    monkeypatch.setattr(lab, "_check", lambda *_: None)
    monkeypatch.setattr(lab, "_verify_pins", lambda: None)
    monkeypatch.setattr(lab, "_read_message", lambda: reply)
    with pytest.raises(IsolationUnavailable):
        lab.snapshot(ExecutionControl(time.monotonic() + 30), minimum_connections=minimum_connections,
                     minimum_requests=minimum_requests)
    assert lab._closed
    assert lab.close()["connection_count"] == 0


def _require_linux_proc():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1" or sys.platform != "linux":
        pytest.skip("real Linux descriptor checks require RECON_LINUX_INTEGRATION=1")


@pytest.mark.integration
def test_fixed_bootstrap_closes_inherited_descriptors_but_preserves_private_stdin():
    _require_linux_proc()
    reader, writer = os.pipe()
    try:
        check = """import os,sys
live=[]
for name in os.listdir('/proc/self/fd'):
    if int(name)>2:
        try: os.fstat(int(name)); live.append(name)
        except OSError: pass
assert not live, live
print(sys.stdin.buffer.read().decode())
"""
        argv = [sys.executable, "-I", "-S", "-c", owned_lab._CLOSE_NAMESPACE_FDS,
                sys.executable, "-I", "-S", "-c", check]
        code, stdout, stderr, reason = isolation._capture_bounded(argv, b"private-authority-pipe", 3, 1024,
                                                                pass_fds=(writer,))
        assert (code, stdout, stderr, reason) == (0, b"private-authority-pipe\n", b"", None)
        os.fstat(writer)
    finally:
        os.close(reader)
        os.close(writer)


@pytest.mark.integration
def test_real_executor_entry_rejects_inherited_fd_before_runtime_imports():
    _require_linux_proc()
    descriptor = os.open(os.devnull, os.O_RDONLY)
    try:
        code, stdout, stderr, reason = isolation._capture_bounded(
            [sys.executable, "-I", "-S", executor.__file__], b"", 3, 1024, pass_fds=(descriptor,))
        assert (code, stdout, stderr, reason) == (78, b"", b"owned_lab_executor_refused\n", None)
    finally:
        os.close(descriptor)
