"""Portable supervision and configuration regressions, separate from kernel tests."""

import json
import os
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import routed
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from scripts.secure_agent_routed_demo import lab_action, lab_policy


def python_command(code):
    return [sys.executable, "-I", "-S", "-c", code]


def test_worker_mounts_are_complete_before_root_becomes_readonly(monkeypatch):
    monkeypatch.setattr(routed, "_trusted_program", lambda _: "/usr/bin/bwrap")
    command = routed.LinuxRoutedBackend()._worker_command("/usr/lib/python3.14", [], 10)
    assert command.index("/app/routed_worker.py") < command.index("--remount-ro")
    assert command[-4:] == ["/usr/bin/python3", "-I", "-S", "/app/routed_worker.py"]
    for flag in ("--unshare-net", "--unshare-user", "--unshare-pid", "--clearenv", "--die-with-parent"):
        assert flag in command


def test_transport_has_only_explicit_runtime_and_tun_no_host_sockets_or_dns(monkeypatch):
    monkeypatch.setattr(routed, "_trusted_program", lambda _: "/usr/bin/bwrap")
    command = routed.LinuxRoutedBackend()._transport_command([], 10, 11, 12, 13, 1)
    assert command[command.index("--userns") + 1] == "10"
    assert command[-2:] == ["/proc/self/fd/11", "tap0"]
    assert "--unshare-net" not in command  # trusted transport only; worker must unshare net
    assert "--bind" not in command
    assert command[command.index("--dev-bind") + 1:command.index("--dev-bind") + 3] == ["/dev/net/tun"] * 2
    sources = [command[i + 1] for i, value in enumerate(command) if value in {"--ro-bind", "--dev-bind"}]
    assert sources == ["/dev/net/tun"]
    for flag in ("--disable-host-loopback", "--disable-dns", "--enable-sandbox", "--enable-seccomp",
                 "--ready-fd=12", "--exit-fd=13", "--as=268435456", "--nofile=64"):
        assert flag in command
    assert not any(item.startswith(("--api-socket", "--enable-ipv6", "--outbound-addr")) for item in command)


def test_routed_backend_rechecks_policy_before_inspecting_runtime(monkeypatch):
    backend = routed.LinuxRoutedBackend()
    monkeypatch.setattr(backend, "check_available", lambda *_: pytest.fail("must deny before setup"))
    with pytest.raises(IsolationUnavailable, match="policy evaluation"):
        backend.run(parse_action(lab_action("192.0.2.11")), lab_policy())


@pytest.mark.parametrize("pid", [True, None, 0, 1, "123", [], {}])
def test_namespace_pinning_rejects_invalid_pid_before_opening_proc(monkeypatch, pid):
    monkeypatch.setattr(routed.os, "open", lambda *_: pytest.fail("must not open invalid PID"))
    with pytest.raises(IsolationUnavailable):
        routed._pin_namespaces(json.dumps({"child-pid": pid}).encode(), {})


def test_namespace_pinning_rejects_host_identity_and_closes_descriptor(monkeypatch):
    fd = os.open(os.devnull, os.O_RDONLY)
    monkeypatch.setattr(routed.os, "open", lambda *_: fd)
    monkeypatch.setattr(routed.os, "readlink", lambda _: "user:[100]")
    with pytest.raises(IsolationUnavailable):
        routed._pin_namespaces(b'{"child-pid": 123}', {"user": "user:[100]", "net": "net:[101]"})
    with pytest.raises(OSError):
        os.fstat(fd)


def test_supervisor_timeout_reaps_both_processes_and_closes_owned_pipes():
    supervisor = routed._Supervisor(0.15, 1024)
    ends = supervisor.pipe()
    try:
        processes = [supervisor.launch(name, python_command("import time; time.sleep(30)"))
                     for name in ("worker", "transport")]
        with pytest.raises(routed._BudgetExceeded) as error:
            supervisor.wait_for(lambda: False)
        assert error.value.status == "timeout"
    finally:
        supervisor.close()
    assert all(proc.poll() is not None for proc in processes)
    for fd in ends:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_supervisor_bounds_transport_stderr_and_reaps_worker():
    supervisor = routed._Supervisor(2, 1024)
    try:
        worker = supervisor.launch("worker", python_command("import time; time.sleep(30)"))
        helper = supervisor.launch("transport", python_command(
            "import os,time; os.write(2,b'x'*8192); time.sleep(30)"))
        with pytest.raises(routed._BudgetExceeded) as error:
            supervisor.wait_for(lambda: False)
        assert error.value.status == "output_limit"
        assert sum(map(len, supervisor.buffers.values())) <= 1024
    finally:
        supervisor.close()
    assert worker.poll() is not None and helper.poll() is not None


@pytest.mark.parametrize("failed_process", ["worker", "transport"])
def test_early_process_exit_never_releases_waiting_worker(failed_process):
    supervisor = routed._Supervisor(2, 1024)
    try:
        worker = supervisor.launch("worker", python_command(
            "raise SystemExit(1)" if failed_process == "worker" else "import time; time.sleep(30)"))
        supervisor.launch("transport", python_command(
            "raise SystemExit(1)" if failed_process == "transport" else "import time; time.sleep(30)"))
        with pytest.raises(IsolationUnavailable, match="prematurely"):
            supervisor.wait_for(lambda: False)
    finally:
        supervisor.close()
    assert worker.poll() is not None


@pytest.mark.parametrize("worker_ready,helper_ready", [(b"WRONG\n", b"1"), (b"READY\n", b""),
                                                       (b"READY\n", b"11"), (b"READY\n", b"true")])
def test_bad_bootstrap_messages_never_release_probe_and_reap_processes(
    monkeypatch, tmp_path, worker_ready, helper_ready,
):
    # Real supervised processes and pipes, with fixed test helpers replacing
    # namespaces/transport. Kernel routing is established by separate tests.
    backend = routed.LinuxRoutedBackend()
    marker = tmp_path / "released"
    supervisors = []
    original_supervisor = routed._Supervisor

    class RecordingSupervisor(original_supervisor):
        def __init__(self, *args):
            super().__init__(*args)
            supervisors.append(self)

    def fake_worker(_stdlib, _files, info_fd):
        code = (
            "import os,sys,time; from pathlib import Path; "
            f"os.write({info_fd}, b'{{\"child-pid\":123}}'); os.close({info_fd}); "
            f"os.write(1,{worker_ready!r}); sys.stdin.buffer.readline(); "
            f"release=sys.stdin.buffer.readline(); Path({str(marker)!r}).touch() if release == b'GO\\n' else None; "
            "time.sleep(30)"
        )
        return python_command(code)

    def fake_transport(_files, _user_fd, _net_fd, ready_fd, _exit_fd, _timeout):
        return python_command(f"import os,time; os.write({ready_fd},{helper_ready!r}); os.close({ready_fd}); time.sleep(30)")

    monkeypatch.setattr(backend, "check_available", lambda *_: None)
    monkeypatch.setattr(backend, "_worker_command", fake_worker)
    monkeypatch.setattr(backend, "_transport_command", fake_transport)
    monkeypatch.setattr(routed, "_runtime_files", lambda *_: ("unused", []))
    monkeypatch.setattr(routed, "_transport_files", lambda: [])
    monkeypatch.setattr(routed, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(routed, "_pin_namespaces", lambda *_: (os.open(os.devnull, os.O_RDONLY),
                                                            os.open(os.devnull, os.O_RDONLY)))
    monkeypatch.setattr(routed, "_namespaces", lambda: {name: f"{name}:[100]" for name in ("user", "net", "mnt", "pid")})
    monkeypatch.setattr(routed, "_Supervisor", RecordingSupervisor)
    with pytest.raises(IsolationUnavailable, match="readiness"):
        backend.run(parse_action(lab_action()), lab_policy())
    assert not marker.exists()
    assert all(process.poll() is not None for process in supervisors[0].processes.values())


def test_expired_supervisor_deadline_cannot_be_overridden_by_a_ready_predicate():
    supervisor = routed._Supervisor(-1, 100)
    try:
        with pytest.raises(routed._BudgetExceeded):
            supervisor.wait_for(lambda: True)
    finally:
        supervisor.close()
