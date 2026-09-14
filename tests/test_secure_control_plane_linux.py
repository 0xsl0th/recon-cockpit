"""Opt-in real coordinator → authority → executor acceptance witnesses."""

import json
import os
import sys
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy, run_demo


@pytest.fixture
def linux_lab():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for real Linux boundaries")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxCoordinator().check_available()


@pytest.mark.integration
@pytest.mark.parametrize("execute", [False, True])
def test_real_control_plane_adversarial_demo(linux_lab, tmp_path, execute):
    report = run_demo(tmp_path / "private-audit" / "events.jsonl", execute_fixtures=execute)
    assert report["demo"] == "passed"
    assert report["live_calls_enabled"] is False
    cases = {row["case"]: row for row in report["cases"]}
    assert len(cases) == (11 if execute else 9)
    assert cases["three_step"]["actions_succeeded"] == (3 if execute else 0)
    assert all(cases[name]["actions_succeeded"] == 0 for name in (
        "wrong_session", "forge_approval", "oversized", "early_exit", "approval_required"))
    assert cases["replay"]["actions_succeeded"] == (1 if execute else 0)
    assert cases["replay"]["stop_reason"] == "coordinator_protocol_error"
    assert cases["output_budget"]["output_reserved_bytes"] == 1024
    if execute:
        assert cases["injection_target"]["steps"][-1]["reasons"] == ["target_out_of_scope"]
        assert cases["injection_authority"]["steps"][-1]["reasons"] == ["unknown_action_fields"]


@pytest.mark.integration
def test_real_executor_requires_fresh_host_grant_per_action(linux_lab, tmp_path):
    # A trusted test callback exercises grant mechanics. It does not claim a
    # human approved anything; the production CLI uses the controlling TTY.
    policy = demo_policy(approval=True)
    session_id, limits = str(uuid4()), SessionLimits()
    coordinator = LinuxCoordinator("three_step")
    backend = AuthorizedFixtureBackend(policy, session_id, limits, execute=True)
    approvals = []

    def approve(controller, raw, *, control):
        control.check()
        action = parse_action(raw)
        grant = controller.approvals.issue(action, controller.policy)
        approvals.append((action.digest, grant.reference))
        return grant.reference

    path = tmp_path / "private-audit" / "events.jsonl"
    with AuditSink(path) as audit:
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id)
        summary = authority.run(execute=True, interactive=True, approval=approve)
    assert summary["session_status"] == "completed"
    assert summary["actions_succeeded"] == len(approvals) == 3
    assert len({reference for _, reference in approvals}) == 3
    records = [json.loads(line) for line in path.read_text().splitlines()]
    consumed = [row for row in records if row["event_type"] == "approval_consumed"]
    launched = [row for row in records if row["event_type"] == "execution_started"]
    assert [(row["action_digest"], row["approval_reference"]) for row in consumed] == approvals
    assert [(row["action_digest"], row["approval_reference"]) for row in launched] == approvals
    assert all(reference not in json.dumps(summary) for _, reference in approvals)
