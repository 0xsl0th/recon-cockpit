"""Portable adapter contracts and opted-in real planner sandbox witnesses."""

import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import isolation, planner_isolation
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.planner_isolation import LinuxIsolatedMockProvider
from scripts.secure_agent_planner_demo import BOUNDARY_NAMES, run_demo


def observation(step=1):
    return json.dumps({"step": step, "untrusted_observation": None}).encode("ascii")


def control(seconds=30):
    return ExecutionControl(time.monotonic() + seconds)


def envelope(**changes):
    return {
        "schema_version": "1", "proposal": {"schema_version": "1", "action": None, "done": True},
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), **changes,
    }


@pytest.fixture
def transport(monkeypatch):
    provider = LinuxIsolatedMockProvider()
    monkeypatch.setattr(provider, "check_available", lambda: None)
    monkeypatch.setattr(provider, "_command", lambda *_: ["fixed-planner-sandbox"])
    monkeypatch.setattr(planner_isolation, "_runtime_files", lambda *a, **k: ("stdlib", []))
    calls = []
    reply = {"code": 0, "stdout": json.dumps(envelope()).encode(), "reason": None}

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        return reply["code"], reply["stdout"], b"private diagnostic must stay hidden", reply["reason"]

    monkeypatch.setattr(planner_isolation, "_capture_bounded", capture)
    return provider, reply, calls


@pytest.mark.parametrize("scenario", ["", "-c", "shell", "/tmp/plugin.py", None, 1, [], {}])
def test_isolated_provider_accepts_only_bundled_scenarios(scenario):
    with pytest.raises(ValueError, match="unsupported_session_mock_scenario"):
        LinuxIsolatedMockProvider(scenario)


@pytest.mark.parametrize("raw", [None, "{}", bytearray(b"{}"), b"\xff", b" " * 8193])
def test_bad_observation_cannot_launch_a_planner(transport, raw):
    provider, _reply, calls = transport
    with pytest.raises(ValueError, match="invalid_session_mock_observation"):
        provider.propose(raw, control=control())
    assert calls == []
    assert provider.boundary_checks is None


def test_mutated_scenario_cannot_launch_a_planner(transport):
    provider, _reply, calls = transport
    provider.scenario = "/tmp/arbitrary-plugin.py"
    with pytest.raises(ValueError, match="unsupported_session_mock_scenario"):
        provider.propose(observation(), control=control())
    assert calls == []


def test_command_has_private_namespaces_no_caps_and_minimal_readonly_mounts(monkeypatch):
    monkeypatch.setattr(planner_isolation, "_trusted_program", lambda _: "/usr/bin/bwrap")
    monkeypatch.setattr(planner_isolation, "_namespaces", lambda: {
        name: name + ":[100]" for name in ("user", "net", "mnt", "pid")
    })
    command = LinuxIsolatedMockProvider("endless")._command(
        "/usr/lib/python3.11", [("/usr/bin/python3.11", "/usr/bin/python3"), ("/lib/libc.so.6", "/lib/libc.so.6")],
    )
    for flag in ("--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                 "--unshare-cgroup", "--clearenv", "--die-with-parent", "--new-session"):
        assert flag in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "--cap-add" not in command
    assert "--share-net" not in command
    assert "--bind" not in command
    assert "--dev-bind" not in command
    mounts = [(command[index + 1], command[index + 2])
              for index, arg in enumerate(command) if arg == "--ro-bind"]
    assert not {source for source, _ in mounts} & {"/", "/home", "/usr", "/lib", "/etc", "/run"}
    assert {target for _, target in mounts} >= {"/app/planner_worker.py", "/app/session_planner.py"}
    assert "/usr/sbin/nft" not in command
    assert command[command.index("--size") + 1:command.index("--size") + 4] == ["1048576", "--tmpfs", "/tmp"]
    assert "--remount-ro" in command
    assert command[-9:-5] == ["/usr/bin/python3", "-I", "-S", "/app/planner_worker.py"]
    assert command[-5] == "endless"


def test_adapter_bounds_capture_unwraps_transport_and_copies_checks(transport):
    provider, reply, calls = transport
    untrusted = {"unexpected_action_field": "still untrusted until session validation"}
    reply["stdout"] = json.dumps(envelope(proposal=untrusted)).encode()
    bounded = control(0.5)
    assert json.loads(provider.propose(observation(), control=bounded)) == untrusted
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == (["fixed-planner-sandbox"], observation())
    assert kwargs["control"] is bounded
    assert 0 < kwargs["timeout"] <= 0.5
    assert kwargs["limit"] == planner_isolation.MAX_TRANSPORT_BYTES
    checks = provider.boundary_checks
    assert checks == dict.fromkeys(BOUNDARY_NAMES, True)
    checks["socket_creation_blocked"] = False
    assert provider.boundary_checks["socket_creation_blocked"] is True


@pytest.mark.parametrize("bad", [
    b"", b"{}", b"[]", b"null", b"\xff", b"{" * 2000,
    json.dumps(envelope(schema_version="2")).encode(),
    json.dumps(envelope(proposal=None)).encode(),
    json.dumps(envelope(proposal=[])).encode(),
    json.dumps(envelope(command="private arbitrary command")).encode(),
    json.dumps(envelope(boundary_checks=None)).encode(),
    json.dumps(envelope(boundary_checks={})).encode(),
    json.dumps(envelope(boundary_checks={**dict.fromkeys(BOUNDARY_NAMES, True), "root_read_only": 1})).encode(),
    json.dumps(envelope(boundary_checks={**dict.fromkeys(BOUNDARY_NAMES, True), "root_read_only": "true"})).encode(),
    json.dumps(envelope(boundary_checks={**dict.fromkeys(BOUNDARY_NAMES, True), "root_read_only": False})).encode(),
    json.dumps(envelope(boundary_checks={**dict.fromkeys(BOUNDARY_NAMES, True), "extra": True})).encode(),
    json.dumps(envelope(proposal={"too_large": "x" * 16384})).encode(),
    b'{"schema_version":"1","schema_version":"1","proposal":{},"boundary_checks":{}}',
])
def test_invalid_transport_clears_evidence_and_never_echoes_content(transport, bad):
    provider, reply, _calls = transport
    provider.propose(observation(), control=control())
    assert provider.boundary_checks is not None
    reply["stdout"] = bad
    with pytest.raises(IsolationUnavailable, match="^Isolated planner failed; no fallback is permitted$"):
        provider.propose(observation(), control=control())
    assert provider.boundary_checks is None


@pytest.mark.parametrize("code,reason", [(2, None), (0, "timeout"), (0, "output_limit")])
def test_failed_process_never_publishes_boundary_evidence(transport, code, reason):
    provider, reply, _calls = transport
    reply.update(code=code, reason=reason)
    with pytest.raises(IsolationUnavailable, match="no fallback"):
        provider.propose(observation(), control=control())
    assert provider.boundary_checks is None


@pytest.mark.parametrize("reason", ["session_timeout", "session_cancelled"])
def test_capture_session_stop_is_preserved_and_clears_prior_evidence(transport, monkeypatch, reason):
    provider, _reply, _calls = transport
    provider.propose(observation(), control=control())

    def stopped(*args, **kwargs):
        raise ExecutionStopped(reason)

    monkeypatch.setattr(planner_isolation, "_capture_bounded", stopped)
    with pytest.raises(ExecutionStopped) as error:
        provider.propose(observation(), control=control())
    assert error.value.reason == reason
    assert provider.boundary_checks is None


def test_unavailable_isolation_fails_without_host_planner_fallback(transport, monkeypatch):
    provider, _reply, calls = transport

    def unavailable():
        raise IsolationUnavailable("fixed missing isolation")

    monkeypatch.setattr(provider, "check_available", unavailable)
    with pytest.raises(IsolationUnavailable):
        provider.propose(observation(), control=control())
    assert calls == []
    assert provider.boundary_checks is None


def test_already_cancelled_call_clears_prior_evidence_without_a_launch(transport):
    provider, _reply, calls = transport
    provider.propose(observation(), control=control())
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        provider.propose(observation(), control=ExecutionControl(time.monotonic() + 30, cancelled=cancelled))
    assert len(calls) == 1
    assert provider.boundary_checks is None


def test_setuid_bubblewrap_is_rejected_before_planner_launch(monkeypatch, tmp_path):
    executable = tmp_path / "bwrap"
    executable.write_text("owned test fixture; never executed")
    executable.chmod(0o4755)
    monkeypatch.setattr(planner_isolation.sys, "platform", "linux")
    monkeypatch.setattr(planner_isolation.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(planner_isolation, "_trusted_program", lambda _: str(executable))
    with pytest.raises(IsolationUnavailable, match="non-setuid"):
        LinuxIsolatedMockProvider().check_available()


def test_worker_refuses_direct_host_invocation():
    worker = Path(planner_isolation.__file__).with_name("planner_worker.py")
    namespaces = (isolation._namespaces() if sys.platform == "linux" else
                  {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")})
    result = subprocess.run([sys.executable, "-I", "-S", str(worker), "three_step",
                             *(namespaces[name] for name in ("user", "net", "mnt", "pid"))],
                            input=observation(), capture_output=True, timeout=2, check=False)
    assert result.returncode != 0
    assert result.stdout == b""
    assert b"Traceback" not in result.stderr


@pytest.fixture
def real_planner():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real planner isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux":
        pytest.skip("real planner isolation requires Linux")
    provider = LinuxIsolatedMockProvider()
    # Missing isolation on an opted-in Linux run is a failure, not a skip.
    provider.check_available()
    return provider


@pytest.mark.integration
def test_real_isolated_three_step_dry_run(real_planner, tmp_path):
    path = tmp_path / "audit.jsonl"
    report = run_demo(path)
    assert report["mode"] == "dry_run_tools"
    assert len(report["cases"]) == 1
    summary = report["cases"][0]
    assert summary["session_status"] == "completed"
    assert summary["steps_attempted"] == 3
    assert summary["actions_succeeded"] == 0
    assert summary["output_reserved_bytes"] == 3072
    assert summary["tool_executions"] == []
    assert summary["policy_unchanged"] is True
    assert [step["execution_status"] for step in summary["steps"]] == ["dry_run"] * 3
    assert len(summary["planner_executions"]) == 3
    assert all(row["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
               for row in summary["planner_executions"])
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert events[-1]["event_type"] == "session_finished"
    assert events[-1]["stop_reason"] == "planner_done"
    assert not any(event["event_type"] == "execution_started" for event in events)


@pytest.mark.integration
def test_real_isolated_planner_and_tool_injection_boundary(real_planner, tmp_path):
    path = tmp_path / "audit.jsonl"
    report = run_demo(path, execute_fixtures=True)
    assert report["mode"] == "execute_owned_fixtures"
    for case in report["cases"]:
        successes = 3 if case["case"] == "three_step" else 1
        assert case["actions_succeeded"] == successes
        assert len(case["tool_executions"]) == successes
        assert all(row["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
                   for row in case["planner_executions"])
        assert case["policy_unchanged"] is True
        if case["case"] == "three_step":
            assert case["session_status"] == "completed"
            assert case["tool_executions"][1]["injection_fixture_received"] is True
        else:
            assert case["stop_reason"] == "proposal_denied"
            assert case["tool_executions"][0]["injection_fixture_received"] is True
            assert case["steps"][-1]["decision"] == "deny"
            expected = "target_out_of_scope" if case["case"] == "injection_target" else "unknown_action_fields"
            assert case["steps"][-1]["reasons"] == [expected]
    text = path.read_text()
    assert "Ignore prior instructions" not in text + json.dumps(report)
    assert '"body"' not in text
    events = [json.loads(line) for line in text.splitlines()]
    assert not any(event["event_type"].startswith("approval_") for event in events)
    assert all(event.get("approval_reference") is None for event in events)
    assert sum(event["event_type"] == "execution_started" for event in events) == 5


def mount_test_planner(monkeypatch, provider, tmp_path, source):
    """Only trusted test code can substitute this read-only planner mount."""
    path = tmp_path / "trusted-test-planner.py"
    path.write_text(source)
    original = provider._command

    def command(stdlib, files):
        argv = original(stdlib, files)
        matches = [index for index, value in enumerate(argv) if value == "--ro-bind"
                   and argv[index + 2] == "/app/session_planner.py"]
        assert len(matches) == 1
        argv[matches[0] + 1] = str(path)
        return argv

    monkeypatch.setattr(provider, "_command", command)


@pytest.mark.integration
def test_real_planner_cannot_access_host_secrets_descriptors_or_syscalls(real_planner, monkeypatch, tmp_path):
    sentinel = tmp_path / "private-host-sentinel"
    secret = "planner-test-private-host-secret"
    sentinel.write_text(secret)
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    source_fd = os.open(sentinel, os.O_RDONLY)
    inherited_fd = fcntl.fcntl(source_fd, fcntl.F_DUPFD, 128)
    os.set_inheritable(inherited_fd, True)
    source = '''
import errno
import importlib.util
import json
import os
import socket

def _observation(raw):
    return json.loads(raw)

def proposal(scenario, observation):
    checks = {}
    checks["credentials_absent"] = all(name not in os.environ for name in (
        "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH"))
    checks["controller_package_absent"] = importlib.util.find_spec("recon_cockpit") is None
    for name, path in (
        ("host_file_absent", HOST_SENTINEL),
        ("host_proc_root_absent", HOST_PROC_SENTINEL),
        ("inherited_fd_path_absent", "/proc/self/fd/" + str(HOST_FD)),
    ):
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as error:
            checks[name] = error.errno in (errno.ENOENT, errno.EACCES, errno.EPERM)
        else:
            os.close(fd)
            checks[name] = False
    try:
        os.fstat(HOST_FD)
    except OSError as error:
        checks["inherited_fd_closed"] = error.errno == errno.EBADF
    else:
        checks["inherited_fd_closed"] = False
    for name, family in (("inet_socket_denied", socket.AF_INET),
                         ("inet6_socket_denied", socket.AF_INET6),
                         ("unix_socket_denied", socket.AF_UNIX)):
        try:
            connection = socket.socket(family, socket.SOCK_STREAM)
        except OSError as error:
            checks[name] = error.errno == errno.EPERM
        else:
            connection.close()
            checks[name] = False
    try:
        child = os.fork()
    except OSError as error:
        checks["fork_denied"] = error.errno in (errno.EPERM, errno.EAGAIN)
    else:
        if child == 0:
            os._exit(17)
        os.waitpid(child, 0)
        checks["fork_denied"] = False
    try:
        fd = os.open("/planner-must-not-write", os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError as error:
        checks["root_write_denied"] = error.errno in (errno.EROFS, errno.EPERM, errno.EACCES)
    else:
        os.close(fd)
        checks["root_write_denied"] = False
    return {"schema_version": "1", "action": None, "done": True, "witnesses": checks}
'''
    source = (f"HOST_SENTINEL = {str(sentinel)!r}\n"
              f"HOST_PROC_SENTINEL = {('/proc/' + str(os.getpid()) + '/root' + str(sentinel))!r}\n"
              f"HOST_FD = {inherited_fd}\n" + source)
    mount_test_planner(monkeypatch, real_planner, tmp_path, source)
    try:
        result = json.loads(real_planner.propose(observation(), control=control()))
    finally:
        os.close(inherited_fd)
        os.close(source_fd)
    assert result["witnesses"] == dict.fromkeys({
        "credentials_absent", "controller_package_absent", "host_file_absent", "host_proc_root_absent",
        "inherited_fd_path_absent", "inherited_fd_closed", "inet_socket_denied", "inet6_socket_denied",
        "unix_socket_denied", "fork_denied", "root_write_denied",
    }, True)
    assert real_planner.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
    assert secret not in json.dumps(result)
    assert sentinel.read_text() == secret


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["cancelled", "deadline", "oversize"])
def test_real_hostile_planner_is_bounded_and_reaped(real_planner, monkeypatch, tmp_path, mode):
    behavior = ('os.write(1, b"x" * 65536)\n    time.sleep(30)' if mode == "oversize" else "time.sleep(30)")
    source = ("import json, os, time\n"
              "def _observation(raw):\n    return json.loads(raw)\n"
              "def proposal(scenario, observation):\n    " + behavior + "\n")
    mount_test_planner(monkeypatch, real_planner, tmp_path, source)
    cancelled = threading.Event()
    bounded = ExecutionControl(time.monotonic() + (3 if mode == "deadline" else 30), cancelled=cancelled)
    real_popen = isolation.subprocess.Popen
    processes = []
    timers = []

    def observe_launch(argv, *args, **kwargs):
        proc = real_popen(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            processes.append(proc)
            if mode == "cancelled":
                timer = threading.Timer(0.5, cancelled.set)
                timer.daemon = True
                timers.append(timer)
                timer.start()
        return proc

    monkeypatch.setattr(isolation.subprocess, "Popen", observe_launch)
    started = time.monotonic()
    try:
        if mode == "oversize":
            with pytest.raises(IsolationUnavailable, match="no fallback"):
                real_planner.propose(observation(), control=bounded)
        else:
            with pytest.raises(ExecutionStopped) as error:
                real_planner.propose(observation(), control=bounded)
            assert error.value.reason == ("session_cancelled" if mode == "cancelled" else "session_timeout")
    finally:
        for timer in timers:
            timer.cancel()
            timer.join(timeout=1)
    assert time.monotonic() - started < 8
    assert real_planner.boundary_checks is None
    assert len(processes) == 1
    assert processes[0].returncode == -signal.SIGKILL
    with pytest.raises(ChildProcessError):
        os.waitpid(processes[0].pid, os.WNOHANG)
