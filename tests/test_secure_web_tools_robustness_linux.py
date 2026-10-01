"""Actual bounded tools under cancellation, hostile output and private inputs.

Only owned fixture/worker code is instrumented. No tool runs on the host, and
synthetic unattended test policy does not claim a human approval or acceptance.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.web_tools_backend import AuthorizedWebToolsBackend
from recon_cockpit.secure_agent.web_tools_contract import LIMITS, action
from recon_cockpit.secure_agent.web_tools_lab import WebToolsLab
from test_secure_fixture_launcher_linux import descendants, instrument
from test_secure_owned_launcher_linux import assert_reaped
from test_secure_web_tools_gates_linux import boundary


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned web-tool robustness")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(WebToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedWebToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


class _FixedProposal:
    """Trusted test provider; its sole action still crosses every real gate."""

    def __init__(self, case):
        self.case = case
        self.session_id = None

    def bind_session(self, session_id):
        assert self.session_id is None
        self.session_id = session_id

    def propose(self, observation, *, control):
        control.check()
        assert json.loads(observation) == {"step": 1, "untrusted_observation": None}
        return json.dumps({"schema_version": "1", "action": action(self.case), "done": True},
                          sort_keys=True, separators=(",", ":")).encode("ascii")


@pytest.mark.parametrize("case,binary", [("curl-stalled", b"/tool/curl"), ("ffuf-stalled", b"/tool/ffuf")])
def test_cancellation_after_actual_exec_reaps_tree_and_retains_authority_reservation(tmp_path, case, binary):
    setup = ExecutionControl(time.monotonic() + 40)
    observed = set()
    with boundary(tmp_path, setup, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        runner = AuthoritySession(policy, audit, launcher, LinuxOfflineCoordinator(), SessionLimits(**LIMITS),
            session_id=session, provider=_FixedProposal(case), approvals=approvals, deadline=setup.deadline)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(runner.run, execute=True, interactive=False)
            seen = False
            try:
                expiry = min(setup.deadline, time.monotonic() + 20)
                while time.monotonic() < expiry and not pending.done():
                    process = getattr(launcher, "_process", None)
                    if process is not None:
                        observed.add(process.pid)
                        observed.update(descendants(process.pid))
                    for pid in tuple(observed):
                        try:
                            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0", 1)[0]
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        seen |= command == binary
                    if seen:
                        break
                    time.sleep(0.01)
                assert seen and not pending.done(), "actual confined tool never reached its stalled run"
                runner.cancel()
                summary = pending.result(timeout=8)
            finally:
                runner.cancel()
            assert summary["stop_reason"] == "session_cancelled"
            assert summary["session_status"] == "stopped" and summary["actions_succeeded"] == 0
            assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
            assert launcher._closed and launcher._process.poll() is not None
            assert launcher.close()["status"] == "closed"
            # No completion receipt arrived; closure must not invent final
            # request totals or reset/restart authority to recover the budget.
            with pytest.raises(RuntimeError, match="session_already_used"):
                runner.run(execute=True)
        assert_reaped(observed)
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    reservations = [event for event in events if event["event_type"] == "session_output_reserved"]
    assert len(reservations) == 1 and reservations[0]["output_reserved_bytes"] == 8192
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    finished = [event for event in events if event["event_type"] == "execution_finished"]
    assert len(finished) == 1 and finished[0]["execution_status"] == "cancelled"


@pytest.mark.parametrize("case", ["curl-ok", "ffuf-normal"])
def test_actual_tool_oversized_output_is_truncated_without_observation(tmp_path, monkeypatch, case):
    def oversized(source):
        original = "connection.sendall(fixture.wire_response(self.case, path))"
        assert source.count(original) == 1
        # curl includes these headers; ffuf copies Content-Type into its JSON
        # result even with response-body fetching disabled. The body stays empty.
        response = (b"HTTP/1.1 200 Owned\r\nContent-Length: 0\r\nConnection: close\r\n"
                    b"Content-Type: text/" + b"x" * 16384 + b"\r\n\r\n")
        return source.replace(original, "connection.sendall(" + repr(response) + ")")
    instrument(tmp_path, monkeypatch, oversized, name="web_tools_lab_worker")
    control = ExecutionControl(time.monotonic() + 40)
    with boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action(case), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "output_limit", result
        captured = result["untrusted_result"]
        stdout = base64.b64decode(captured["raw_output_base64"], validate=True)
        stderr = base64.b64decode(captured["raw_stderr_base64"], validate=True)
        assert captured["truncated"] is True and captured["tool_observation"] is None
        assert captured["provenance"]["stop_reason"] == "output_limit"
        assert captured["bytes_received"] == len(stdout) + len(stderr) <= 8192
        assert all(captured["boundary_checks"].values())
        assert 1 <= captured["owned_lab"]["request_count"] <= (1 if case.startswith("curl-") else 8)
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
        observed = descendants(launcher._process.pid) | {launcher._process.pid}
        assert launcher.close()["status"] == "closed"
        assert_reaped(observed)
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    assert [event["execution_status"] for event in events if event["event_type"] == "execution_finished"] == ["output_limit"]


@pytest.mark.parametrize("case", ["curl-ok", "ffuf-normal"])
def test_tool_cannot_read_host_canary_bootstrap_source_or_authority_descriptors(tmp_path, monkeypatch, case):
    canary = tmp_path / "private-host-canary"
    secret = "WEB-TOOLS-PRIVATE-CANARY-ONLY"
    canary.write_text(secret)
    canary.chmod(0o600)
    monkeypatch.setenv("WEB_TOOLS_HOST_CANARY", secret)
    def check_private_inputs(source):
        original = 'os.execve(argv[0], argv, runtime.execution_environment(request["tool_id"]))'
        assert source.count(original) == 1
        checks = f"""if os.environ.get('WEB_TOOLS_HOST_CANARY') is not None:
            raise RuntimeError('unexpected_host_environment')
        for candidate in ({str(canary)!r}, '/app/recon_cockpit/secure_agent/web_tools_worker.py'):
            try:
                leaked = os.open(candidate, os.O_RDONLY)
            except OSError:
                pass
            else:
                os.close(leaked)
                raise RuntimeError('unexpected_private_file')
        for candidate in range(3, 128):
            try:
                os.fstat(candidate)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise RuntimeError('unexpected_authority_descriptor')
        {original}"""
        return source.replace(original, checks)
    instrument(tmp_path, monkeypatch, check_private_inputs, name="web_tools_worker")
    control = ExecutionControl(time.monotonic() + 40)
    with boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action(case), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "succeeded", result
        assert result["untrusted_result"]["tool_observation"] is not None
        assert secret not in json.dumps(result)
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
    assert secret not in (tmp_path / "audit.jsonl").read_text()
