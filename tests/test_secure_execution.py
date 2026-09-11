"""Portable deadline/cancellation coverage with real supervised subprocesses."""

from dataclasses import FrozenInstanceError
import os
import select
import signal
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import isolation, routed
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action
from scripts.secure_agent_routed_demo import lab_action, lab_policy


def command(code):
    return [sys.executable, "-I", "-S", "-c", code]


@pytest.fixture
def processes(monkeypatch):
    original = subprocess.Popen
    children = []

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    yield children
    # Assert production cleanup, but do not leave a process behind on failure.
    alive = [child for child in children if child.poll() is None]
    for child in alive:
        child.kill()
        child.wait(timeout=2)
    assert not alive


@pytest.mark.parametrize("deadline", [True, False, "1", None, float("nan"), float("inf"), -float("inf")])
def test_deadline_is_a_finite_number(deadline):
    with pytest.raises(ValueError, match="deadline"):
        ExecutionControl(deadline)


def test_deadline_is_immutable_and_expiration_is_exclusive():
    now = [10.0]
    control = ExecutionControl(11.0, clock=lambda: now[0])
    assert control.remaining() == 1.0
    with pytest.raises(FrozenInstanceError):
        control.deadline = 100.0
    now[0] = 11.0
    with pytest.raises(ExecutionStopped) as error:
        control.check()
    assert error.value.reason == "session_timeout"


def test_cancellation_is_explicit_and_wins_over_expiration():
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(ExecutionStopped) as error:
        ExecutionControl(0, cancelled, clock=lambda: 1).remaining()
    assert error.value.reason == "session_cancelled"
    with pytest.raises(ValueError, match="cancellation"):
        ExecutionControl(1, True)
    with pytest.raises(ValueError, match="clock"):
        ExecutionControl(1, clock=None)


@pytest.mark.parametrize("backend", [isolation.LinuxFixtureBackend, routed.LinuxRoutedBackend])
def test_expired_backend_never_validates_or_launches(backend, monkeypatch):
    instance = backend()
    monkeypatch.setattr(instance, "check_available", lambda *_: pytest.fail("must stop before setup"))
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    with pytest.raises(ExecutionStopped) as error:
        instance.run(None, None, control=ExecutionControl(0))
    assert error.value.reason == "session_timeout"


def test_expired_capture_never_launches(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    with pytest.raises(ExecutionStopped):
        isolation._capture_bounded(command("pass"), b"", 5, 1024, control=ExecutionControl(0))


def test_capture_session_deadline_reaps_live_child(processes):
    with pytest.raises(ExecutionStopped) as error:
        isolation._capture_bounded(command("import time; time.sleep(30)"), b"", 10, 1024,
                                   control=ExecutionControl(time.monotonic() + 0.15))
    assert error.value.reason == "session_timeout"
    assert len(processes) == 1 and processes[0].poll() is not None


def test_capture_cancellation_reaps_child_even_with_blocked_large_input(processes):
    cancelled = threading.Event()
    timer = threading.Timer(0.15, cancelled.set)
    timer.start()
    try:
        with pytest.raises(ExecutionStopped) as error:
            isolation._capture_bounded(command("import time; time.sleep(30)"), b"x" * 1048576,
                                       10, 1024, control=ExecutionControl(time.monotonic() + 5, cancelled))
        assert error.value.reason == "session_cancelled"
    finally:
        timer.join()
    assert len(processes) == 1 and processes[0].poll() is not None


def test_capture_cancellation_kills_pipe_holder_after_direct_child_exits(monkeypatch, processes):
    cancelled = threading.Event()
    readers = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        readers.append(os.dup(child.stdout.fileno()))
        # Force the precise race: the immediate child is already reaped, while
        # its same-group descendant still holds both captured output pipes.
        assert child.wait(timeout=2) == 0
        assert not select.select(readers, [], [], 0)[0]
        cancelled.set()
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    holder = command("import time; time.sleep(30)")
    parent = command(f"import os,subprocess; subprocess.Popen({holder!r}); os._exit(0)")
    try:
        with pytest.raises(ExecutionStopped) as error:
            isolation._capture_bounded(parent, b"", 5, 1024,
                                       control=ExecutionControl(time.monotonic() + 5, cancelled))
        assert error.value.reason == "session_cancelled"
        assert len(processes) == 1 and processes[0].returncode == 0
        # EOF proves the descendant no longer retains the pipe even though the
        # immediate child's successful exit alone cannot establish cleanup.
        assert select.select(readers, [], [], 1)[0], "descendant still holds captured output"
        assert os.read(readers[0], 1) == b""
    finally:
        # Also terminate the descendant if any assertion or production cleanup
        # fails. The processes fixture reaps our direct child; an orphaned
        # descendant is reaped by the operating system after the group kill.
        for child in processes:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for reader in readers:
            os.close(reader)


def test_capture_nonblocking_input_delivers_all_data_and_eof(processes):
    request = b"x" * 1048576
    result = isolation._capture_bounded(
        command("import sys; data = sys.stdin.buffer.read(); print(len(data))"),
        request, 5, 1024, control=ExecutionControl(time.monotonic() + 5),
    )
    assert result == (0, b"1048576\n", b"", None)


def test_capture_deadline_also_covers_wait_after_output_eof(processes):
    with pytest.raises(ExecutionStopped) as error:
        isolation._capture_bounded(
            command("import os,time; os.close(1); os.close(2); time.sleep(30)"), b"", 10, 1024,
            control=ExecutionControl(time.monotonic() + 0.15),
        )
    assert error.value.reason == "session_timeout"
    assert processes[0].poll() is not None


@pytest.mark.parametrize("control_enabled", [False, True])
def test_capture_output_flood_remains_bounded_and_reaped(processes, control_enabled):
    kwargs = {"control": ExecutionControl(time.monotonic() + 5)} if control_enabled else {}
    code, stdout, stderr, reason = isolation._capture_bounded(
        command("import os,time; os.write(2,b'x'*65536); time.sleep(30)"), b"", 5, 1024, **kwargs,
    )
    assert reason == "output_limit"
    assert code != 0
    assert len(stdout) + len(stderr) <= 1024
    assert processes[0].poll() is not None


def test_runtime_inspection_propagates_session_stop_and_reaps(monkeypatch, processes):
    capture = isolation._capture_bounded

    def delayed_probe(_argv, request, timeout, limit, *, control):
        return capture(command("import time; time.sleep(30)"), request, timeout, limit, control=control)

    monkeypatch.setattr(isolation, "_capture_bounded", delayed_probe)
    with pytest.raises(ExecutionStopped) as error:
        isolation._runtime_files(sys.executable, "/unused/nft",
                                 control=ExecutionControl(time.monotonic() + 0.15))
    assert error.value.reason == "session_timeout"
    assert processes[0].poll() is not None


def test_runtime_inspection_output_has_live_limit(processes):
    with pytest.raises(isolation.IsolationUnavailable, match="bound"):
        isolation._runtime_probe(command("import os,time; os.write(1,b'x'*65536); time.sleep(30)"),
                                 5, 1024, ExecutionControl(time.monotonic() + 5))
    assert processes[0].poll() is not None


def test_fixture_stop_after_runtime_discovery_prevents_sandbox_launch(monkeypatch):
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic() + 5, cancelled)
    backend = isolation.LinuxFixtureBackend()

    def discovered(*_args, **kwargs):
        assert kwargs["control"] is control
        cancelled.set()
        return "unused", []

    monkeypatch.setattr(backend, "check_available", lambda *_: None)
    monkeypatch.setattr(backend, "_command", lambda *_: command("pass"))
    monkeypatch.setattr(isolation, "_runtime_files", discovered)
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(isolation, "_namespaces", lambda: {})
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    with pytest.raises(ExecutionStopped) as error:
        backend.run(parse_action(lab_action("127.0.0.1")), lab_policy("127.0.0.1"), control=control)
    assert error.value.reason == "session_cancelled"


def test_transport_inspection_propagates_cancellation(monkeypatch, processes):
    original = isolation._runtime_probe
    cancelled = threading.Event()
    timer = threading.Timer(0.15, cancelled.set)

    def delayed_probe(_argv, timeout, limit, control):
        return original(command("import time; time.sleep(30)"), timeout, limit, control)

    monkeypatch.setattr(routed, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(routed, "_runtime_probe", delayed_probe)
    timer.start()
    try:
        with pytest.raises(ExecutionStopped) as error:
            routed._transport_files(control=ExecutionControl(time.monotonic() + 5, cancelled))
        assert error.value.reason == "session_cancelled"
    finally:
        timer.join()
    assert processes[0].poll() is not None


def test_supervisor_expired_launch_creates_no_child(monkeypatch):
    supervisor = routed._Supervisor(10, 1024, control=ExecutionControl(0))
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    try:
        with pytest.raises(ExecutionStopped):
            supervisor.launch("worker", command("pass"))
    finally:
        supervisor.close()


def test_supervisor_cancellation_overrides_ready_predicate_and_reaps_both(processes):
    cancelled = threading.Event()
    supervisor = routed._Supervisor(10, 1024, control=ExecutionControl(time.monotonic() + 10, cancelled))
    ends = supervisor.pipe()
    try:
        for name in ("worker", "transport"):
            supervisor.launch(name, command("import time; time.sleep(30)"))
        cancelled.set()
        with pytest.raises(ExecutionStopped) as error:
            supervisor.wait_for(lambda: True)
        assert error.value.reason == "session_cancelled"
    finally:
        supervisor.close()
    assert len(processes) == 2 and all(child.poll() is not None for child in processes)
    for fd in ends:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_supervisor_deadline_while_waiting_for_readiness_reaps_both(processes):
    supervisor = routed._Supervisor(10, 1024, control=ExecutionControl(time.monotonic() + 0.15))
    try:
        for name in ("worker", "transport"):
            supervisor.launch(name, command("import time; time.sleep(30)"))
        with pytest.raises(ExecutionStopped) as error:
            supervisor.wait_for(lambda: False)
        assert error.value.reason == "session_timeout"
    finally:
        supervisor.close()
    assert len(processes) == 2 and all(child.poll() is not None for child in processes)


def test_routed_cancellation_at_release_gate_never_sends_go(monkeypatch, tmp_path, processes):
    """Real pipes/processes exercise the final gate; this is not a kernel test."""
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic() + 10, cancelled)
    backend = routed.LinuxRoutedBackend()
    marker = tmp_path / "released"
    supervisors = []
    original_supervisor = routed._Supervisor

    class CancelAtRelease(original_supervisor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            supervisors.append(self)

        def wait_for(self, *args, **kwargs):
            super().wait_for(*args, **kwargs)
            if "transport_ready" in self.eof:
                cancelled.set()

    def fake_worker(_stdlib, _files, info_fd):
        return command(
            "import os,sys,time; from pathlib import Path; "
            f"os.write({info_fd}, b'{{\"child-pid\":123}}'); os.close({info_fd}); "
            "sys.stdin.buffer.readline(); os.write(1,b'READY\\n'); "
            f"release=sys.stdin.buffer.readline(); Path({str(marker)!r}).touch() if release == b'GO\\n' else None; "
            "time.sleep(30)"
        )

    def fake_transport(_files, _user_fd, _net_fd, ready_fd, _exit_fd, _timeout):
        return command(f"import os,time; os.write({ready_fd},b'1'); os.close({ready_fd}); time.sleep(30)")

    monkeypatch.setattr(backend, "check_available", lambda *_: None)
    monkeypatch.setattr(backend, "_worker_command", fake_worker)
    monkeypatch.setattr(backend, "_transport_command", fake_transport)
    monkeypatch.setattr(routed, "_runtime_files", lambda *_args, **_kwargs: ("unused", []))
    monkeypatch.setattr(routed, "_transport_files", lambda **_kwargs: [])
    monkeypatch.setattr(routed, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(routed, "_pin_namespaces", lambda *_: (os.open(os.devnull, os.O_RDONLY),
                                                            os.open(os.devnull, os.O_RDONLY)))
    monkeypatch.setattr(routed, "_namespaces", lambda: {name: f"{name}:[100]" for name in ("user", "net", "mnt", "pid")})
    monkeypatch.setattr(routed, "_Supervisor", CancelAtRelease)
    with pytest.raises(ExecutionStopped) as error:
        backend.run(parse_action(lab_action()), lab_policy(), control=control)
    assert error.value.reason == "session_cancelled"
    assert not marker.exists()
    assert len(processes) == 2 and all(child.poll() is not None for child in processes)
    assert not supervisors[0].fds
