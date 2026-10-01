"""Real launch/approval gates; synthetic grants never assert user acceptance."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import approval_protocol
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.http_headers_backend import AuthorizedHTTPHeadersBackend
from recon_cockpit.secure_agent.http_headers_contract import BACKEND, LIMITS, action
from recon_cockpit.secure_agent.http_headers_lab import HTTPHeadersLab
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.nmap_runtime import inspect_nmap_runtime
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_approval_linux import scripted_review, terminal
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import instrument


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned HTTP header launch gates")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(HTTPHeadersLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedHTTPHeadersBackend, "run", lambda *_a, **_k: pytest.fail("host tool executed"))


@contextmanager
def boundary(tmp_path, control):
    value = json.loads(Path("examples/secure-agent-http-headers-policy.json").read_text())
    value["policy_version"] = "synthetic-http-headers-approval-test-v1"
    policy, session = parse_policy(value), str(uuid4())
    limits = SessionLimits(**LIMITS)
    lab = HTTPHeadersLab("injected", session, limits)
    backend = AuthorizedHTTPHeadersBackend(policy, session, limits, lab, execute=True)
    backend._nmap_manifest = inspect_nmap_runtime(control)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session


def test_real_required_grant_executes_headers_once_and_replay_is_blocked(tmp_path, terminal):
    control = ExecutionControl(time.monotonic() + 40)
    selected = parse_action(action("injected", 2))
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        reference, prompt = scripted_review(approvals, selected, policy, terminal, control)
        assert reference is not None and selected.digest.encode() in prompt
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        result = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert result["execution_status"] == "succeeded", result
        output = result["untrusted_result"]
        assert output["http_headers"]["csp"] == "absent"
        assert output["owned_lab"]["request_count"] == 1
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 2048}
        replay = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert replay["execution_status"] == "blocked" and replay["reasons"] == ["approval_unknown_or_replayed"]
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 2048}
        process = launcher._process
    assert process.poll() is not None
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(row["event_type"] == "execution_started" for row in events) == 1
    assert sum(row["event_type"] == "approval_consumed" for row in events) == 1


@pytest.mark.parametrize("fault", ["missing_consumed_proof", "forged_host_consume_reply"])
def test_durable_intent_without_real_consumed_proof_never_reaches_admission(tmp_path, monkeypatch, terminal, fault):
    instrument(tmp_path, monkeypatch, lambda source: source.replace("granted = gate.admit(",
        "os.write(2, b'UNEXPECTED-HEADERS-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action("injected", 2))
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        if fault == "forged_host_consume_reply":
            reference, _ = scripted_review(approvals, selected, policy, terminal, control)
            sent = []
            monkeypatch.setattr(approvals, "_send", lambda raw: sent.append(approval_protocol.decode(raw)))
            monkeypatch.setattr(approvals, "_reply", lambda: approval_protocol.receipt(sent[-1], None))
            controller = Controller(policy, audit, launcher, approvals, session_id=session)
            result = controller.submit(selected.to_dict(), execute=True, interactive=True,
                approval_reference=reference, execution_control=control)
            assert result["execution_status"] in {"blocked", "timeout"}
        else:
            event = intent(selected, policy, session, backend=BACKEND)
            event["approval_reference"] = "a" * 48
            audit.emit(event)
            with pytest.raises((IsolationUnavailable, ExecutionStopped)):
                launcher.run(selected, policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert b"UNEXPECTED-HEADERS-ADMISSION" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["connection_count"] == 0


@pytest.mark.parametrize("tag", ["web-launch-preconditions", "launch-preconditions"])
def test_previous_bootstrap_tags_cannot_relabel_new_profile(tmp_path, monkeypatch, terminal, tag):
    command = LinuxFixtureLauncher._command
    def changed(self, *args):
        argv = command(self, *args)
        assert argv[-1] == "http-headers-launch-preconditions"
        argv[-1] = tag
        return argv
    monkeypatch.setattr(LinuxFixtureLauncher, "_command", changed)
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action("injected", 2))
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        reference, _ = scripted_review(approvals, selected, policy, terminal, control)
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            selected.to_dict(), execute=True, interactive=True, approval_reference=reference, execution_control=control)
        assert result["execution_status"] == "blocked"
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["connection_count"] == 0


def test_out_of_scope_proposal_records_denial_without_launcher_or_approval(tmp_path):
    control = ExecutionControl(time.monotonic() + 20)
    selected = {**action("injected", 2), "target": "127.0.0.2"}
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            selected, execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked" and result["reasons"] == ["target_out_of_scope"]
        assert launcher._supervisor is approvals._supervisor is None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(row["event_type"] == "policy_decision" and row["decision"] == "deny" for row in events)
    assert not any(row["event_type"] == "execution_started" for row in events)
