"""Real web-tool authority gates and the enforced Go thread ceiling."""

from contextlib import contextmanager
import json
import os
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.web_tools_backend import AuthorizedWebToolsBackend
from recon_cockpit.secure_agent.web_tools_contract import BACKEND, LIMITS, action
from recon_cockpit.secure_agent.web_tools_lab import WebToolsLab
from recon_cockpit.secure_agent.web_tools_runtime import inspect_tool_runtime
from test_secure_approval_linux import scripted_review, terminal
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import instrument
from test_secure_web_tools_runtime import policy as required_policy


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned web-tool gates")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(WebToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedWebToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


@contextmanager
def boundary(tmp_path, control, *, case="curl-ok", approval_required=True):
    value = required_policy().to_dict()
    value["require_approval"] = approval_required
    policy, session = parse_policy(value), str(uuid4())
    limits = SessionLimits(**LIMITS)
    lab = WebToolsLab(case, session, limits)
    backend = AuthorizedWebToolsBackend(policy, session, limits, lab, execute=True)
    backend._web_tools_manifest = inspect_tool_runtime(action(case)["tool_id"], control)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session


@pytest.mark.parametrize("case,requests", [("curl-ok", 1), ("ffuf-normal", 8)])
def test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, case, requests):
    control = ExecutionControl(time.monotonic() + 40)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        reference, prompt = scripted_review(approvals, selected, policy, terminal, control)
        assert reference is not None and selected.digest.encode() in prompt
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        result = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert result["execution_status"] == "succeeded", result
        assert result["untrusted_result"]["owned_lab"]["request_count"] == requests
        assert result["untrusted_result"]["tool_observation"] is not None
        replay = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert replay["execution_status"] == "blocked" and replay["reasons"] == ["approval_unknown_or_replayed"]
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(row["event_type"] == "approval_consumed" for row in events) == 1


@pytest.mark.parametrize("case", ["curl-ok", "ffuf-normal"])
def test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, case):
    instrument(tmp_path, monkeypatch, lambda source: source.replace("granted = gate.admit(",
        "os.write(2, b'UNEXPECTED-WEB-TOOLS-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        event = intent(selected, policy, session, backend=BACKEND)
        event["approval_reference"] = "a" * 48
        audit.emit(event)
        with pytest.raises((IsolationUnavailable, ExecutionStopped)):
            launcher.run(selected, policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert b"UNEXPECTED-WEB-TOOLS-ADMISSION" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0


def test_absent_kernel_thread_ceiling_is_refused_before_ffuf_exec(tmp_path, monkeypatch):
    # Widen the actual kernel limit while retaining the production witness.
    # A seventeenth task (including the private supervisor and worker) exceeds
    # the advertised total; its creation must cause refusal before ffuf exec.
    def widen(source):
        assert "threads = 16 if tool_id == runtime.FFUF else 1" in source
        return source.replace("threads = 16 if tool_id == runtime.FFUF else 1",
                              "threads = 32 if tool_id == runtime.FFUF else 1")
    instrument(tmp_path, monkeypatch, widen, name="web_tools_worker")
    control = ExecutionControl(time.monotonic() + 30)
    with boundary(tmp_path, control, case="ffuf-normal", approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("ffuf-normal"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert launcher.close()["request_count"] == 0


@pytest.mark.parametrize("tag", ["launch-preconditions", "http-headers-launch-preconditions"])
def test_existing_bootstrap_tags_cannot_relabel_new_profile(tmp_path, monkeypatch, tag):
    original = LinuxFixtureLauncher._command
    def changed(self, *args):
        argv = original(self, *args)
        assert argv[-1] == "web-tools-launch-preconditions"
        argv[-1] = tag
        return argv
    monkeypatch.setattr(LinuxFixtureLauncher, "_command", changed)
    control = ExecutionControl(time.monotonic() + 20)
    with boundary(tmp_path, control, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("curl-ok"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked"
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["request_count"] == 0
