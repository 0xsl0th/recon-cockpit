"""Actual B8 transport/task witnesses and its distinct launcher bootstrap tag."""

import os
import sys
import time

import pytest

from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_contract import action
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_fixture_launcher_linux import instrument
from test_secure_network_tools_gates_linux import boundary


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned Kerberos gates")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run",
                        lambda *a, **k: pytest.fail("host tool executed"))


def replace_once(source, old, new):
    assert source.count(old) == 1
    return source.replace(old, new)


def witness_diagnostics(tmp_path, monkeypatch, refusal, *, worker_transform=lambda source: source):
    """Expose only an exact native refusal; never execute with a widened guard.

    The production witness and readiness-prefix check remain intact. A test-only
    exec sentinel prevents any Kerbrute traffic even if the witness regresses.
    The outer marker is emitted only after the native capture has completed and
    its exact refusal, empty stdout and exit code have been verified.
    """
    expected = ("B8-WITNESS:" + refusal + "\n").encode("ascii")
    marker = ("B8-VERIFIED:" + refusal + "\n").encode("ascii")

    def worker(source):
        source = worker_transform(source)
        source = replace_once(source,
            'os.execve(argv[0], argv, runtime.execution_environment(request["tool_id"]))',
            'raise RuntimeError("unexpected_kerbrute_exec")')
        return replace_once(source,
            '    except Exception:\n        sys.stderr.write("network_tool_worker_refused\\n")\n        return 78',
            '    except Exception as exc:\n        sys.stderr.write("B8-WITNESS:" + str(exc) + "\\n")\n        return 78')

    def runtime(source):
        return replace_once(source, '    if not stderr.startswith(prefix):',
            f'    if code == 78 and stdout == b"" and stderr == {expected!r} and reason is None:\n'
            f'        os.write(2, {marker!r})\n'
            '    if not stderr.startswith(prefix):')

    instrument(tmp_path, monkeypatch, worker, name="network_tools_worker")
    instrument(tmp_path, monkeypatch, runtime, name="network_tools_runtime")
    return marker


def assert_witness_refusal(tmp_path, marker):
    control = ExecutionControl(time.monotonic() + 40)
    with boundary(tmp_path, control, case="kerberos-ok", approval_required=False) as (
            audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("kerberos-ok"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers["worker_err"])
        assert b"unexpected_kerbrute_exec" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0


def test_udp_socket_permission_is_refused_before_kerbrute_exec(tmp_path, monkeypatch):
    def allow_udp(source):
        # Retain every other syscall/family/type/protocol restriction. The
        # production transport witness opens then closes a real UDP socket;
        # no send operation occurs and the owned firewall is unchanged.
        source = replace_once(source,
            '            if kind != socket.SOCK_STREAM:',
            '            if kind not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):')
        return replace_once(source,
            '        deny("socket", [Argument(2, 6, socket.IPPROTO_TCP, 0)])',
            '        for protocol in range(socket.IPPROTO_TCP + 1, socket.IPPROTO_UDP):\n'
            '            deny("socket", [Argument(2, 4, protocol, 0)])\n'
            '        deny("socket", [Argument(2, 6, socket.IPPROTO_UDP, 0)])')

    instrument(tmp_path, monkeypatch, allow_udp, name="tool_worker_common")
    marker = witness_diagnostics(tmp_path, monkeypatch, "kerbrute_udp_socket_allowed")
    assert_witness_refusal(tmp_path, marker)


def test_broadened_task_ceiling_is_refused_before_kerbrute_exec(tmp_path, monkeypatch):
    def widen(source):
        return replace_once(source,
            '    if tool_id == runtime.KERBRUTE:\n        threads = 16',
            '    if tool_id == runtime.KERBRUTE:\n        threads = 32')

    marker = witness_diagnostics(tmp_path, monkeypatch,
                                 "web_tool_thread_bound_not_verified", worker_transform=widen)
    assert_witness_refusal(tmp_path, marker)


@pytest.mark.parametrize("case,expected,substitute", [
    ("kerberos-ok", "kerberos-tools-launch-preconditions", "network-tools-launch-preconditions"),
    ("dig-ok", "network-tools-launch-preconditions", "kerberos-tools-launch-preconditions"),
])
def test_kerberos_and_normal_bootstrap_tags_cannot_relabel_each_other(
        tmp_path, monkeypatch, case, expected, substitute):
    original = LinuxFixtureLauncher._command

    def changed(self, *args):
        argv = original(self, *args)
        assert argv[-1] == expected
        argv[-1] = substitute
        return argv

    monkeypatch.setattr(LinuxFixtureLauncher, "_command", changed)
    control = ExecutionControl(time.monotonic() + 30)
    with boundary(tmp_path, control, case=case, approval_required=False) as (
            audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action(case), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["request_count"] == 0
