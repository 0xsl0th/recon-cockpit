"""Synthetic PTY grants verify Nmap launch gates, never operator acceptance."""

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
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.nmap_backend import AuthorizedNmapOwnedBackend
from recon_cockpit.secure_agent.nmap_contract import BACKEND, LIMITS, action
from recon_cockpit.secure_agent.nmap_runtime import inspect_nmap_runtime
from recon_cockpit.secure_agent.owned_lab import OwnedLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_approval_linux import scripted_review, terminal
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import instrument


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for synthetic Nmap approval gates")
    assert sys.platform == "linux" and os.geteuid() != 0


@contextmanager
def boundary(tmp_path, control):
    value = json.loads(Path("examples/secure-agent-nmap-policy.json").read_text())
    # Keep approval mandatory. This label distinguishes a harness-controlled
    # synthetic terminal from actual user approval or milestone acceptance.
    value["policy_version"] = "synthetic-nmap-approval-test-v1"
    policy, session = parse_policy(value), str(uuid4())
    limits = SessionLimits(**LIMITS)
    lab = OwnedLab("a", session, limits, execute=True)
    backend = AuthorizedNmapOwnedBackend(policy, session, limits, lab, execute=True)
    backend._nmap_manifest = inspect_nmap_runtime(control)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session


def test_required_synthetic_grant_launches_nmap_once_and_replay_cannot_reserve_again(
        tmp_path, monkeypatch, terminal):
    monkeypatch.setattr(OwnedLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNmapOwnedBackend, "run",
                        lambda *_a, **_k: pytest.fail("host Nmap executor called"))
    control = ExecutionControl(time.monotonic() + 40)
    selected = parse_action(action("a", 1))
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        reference, prompt = scripted_review(approvals, selected, policy, terminal, control)
        assert reference is not None and selected.digest.encode() in prompt
        assert approvals._witness_writer is None
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        result = controller.submit(selected.to_dict(), execute=True, interactive=True,
                                   approval_reference=reference, execution_control=control)
        assert result["execution_status"] == "succeeded", result
        assert result["untrusted_result"]["results"] == [
            {"target": "127.0.0.1", "port": 8080, "state": "open"},
        ]
        assert launcher._approval_reader is None
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 16384}
        replay = controller.submit(selected.to_dict(), execute=True, interactive=True,
                                   approval_reference=reference, execution_control=control)
        assert replay["execution_status"] == "blocked"
        assert replay["reasons"] == ["approval_unknown_or_replayed"]
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 16384}
        process = launcher._process
    assert process.poll() is not None
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(row["event_type"] == "execution_started" for row in events) == 1
    assert sum(row["event_type"] == "approval_consumed" for row in events) == 1
    assert any(row["event_type"] == "approval_rejected" for row in events)


@pytest.mark.parametrize("fault", ["missing_consumed_proof", "forged_host_consume_reply"])
def test_durable_nmap_intent_without_direct_consumed_proof_never_reaches_admission(
        tmp_path, monkeypatch, terminal, fault):
    instrument(tmp_path, monkeypatch, lambda source: source.replace(
        "granted = gate.admit(",
        "os.write(2, b'UNEXPECTED-NMAP-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action("a", 1))
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        if fault == "forged_host_consume_reply":
            reference, _ = scripted_review(approvals, selected, policy, terminal, control)
            sent = []
            # Fabricate only the host-visible consume RPC reply. The real
            # isolated approval worker never consumes the reviewed test grant
            # and cannot provide the launcher's direct consumed-grant proof.
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
        assert b"UNEXPECTED-NMAP-ADMISSION" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["connection_count"] == 0
        events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert any(row["event_type"] == "execution_started" for row in events)
        with pytest.raises(IsolationUnavailable):
            launcher.run(selected, policy, control=ExecutionControl(time.monotonic() + 10))
