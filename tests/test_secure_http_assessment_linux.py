"""Actual Linux assessment/evidence witnesses; provider data remains synthetic."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.assessment import AssessmentProvider
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES, LinuxOfflineCoordinator
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy


@pytest.fixture
def linux_lab():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual Linux isolation")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxOfflineCoordinator().check_available()


def build(*, approval=False, execute=True):
    policy = demo_policy(approval=approval)
    limits = SessionLimits(max_steps=2, max_output_bytes=2048)
    session_id = str(uuid4())
    backend = AuthorizedFixtureBackend(policy, session_id, limits, execute=execute)
    return policy, limits, session_id, backend, LinuxOfflineCoordinator()


@pytest.mark.integration
@pytest.mark.parametrize("case,outcome,succeeded,exchanges", [
    ("a", "validated", 2, 2), ("b", "not_demonstrated", 2, 2),
    ("c", "inconclusive", 2, 2), ("d", "inconclusive", 1, 2),
    ("e", "inconclusive", 1, 2), ("f", "inconclusive", 1, 1),
])
def test_real_fixture_workflow_and_report_provenance(linux_lab, tmp_path, monkeypatch, case, outcome, succeeded, exchanges):
    policy, limits, session_id, backend, coordinator = build()
    directory, audit_path = tmp_path / "evidence", tmp_path / "private-audit" / "events.jsonl"
    children = []
    original_popen = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original_popen(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    with AuditSink(audit_path) as audit, EvidenceStore(directory, session_id=session_id, policy=policy, case=case) as evidence:
        provider = AssessmentProvider(case, audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        summary = authority.run(execute=True)
        report = evidence.finalize(summary)
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert inspect_assessment(directory) == report
    assert summary["actions_succeeded"] == succeeded
    assert provider.broker.snapshot["calls_reserved"] == exchanges
    assert provider.broker.snapshot["output_tokens_reserved"] == exchanges * 1024
    assert backend.snapshot["executions_reserved"] == exchanges
    assert backend.snapshot["output_bytes_reserved"] == exchanges * 1024
    assert len(report["records"]) == exchanges
    assert len(children) == 1 + exchanges * 2
    assert all(child.poll() is not None for child in children)
    assert coordinator.boundary_checks == provider.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in directory.iterdir())
    if case in {"d", "e"}:
        expected = "timeout" if case == "d" else "output_limit"
        assert summary["stop_reason"] == "action_" + expected
        assert report["records"][-1]["execution_status"] == expected
    else:
        assert summary["session_status"] == "completed"
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    starts = [row for row in events if row["event_type"] == "execution_started"]
    finishes = [row for row in events if row["event_type"] == "execution_finished"]
    assert [row["execution_id"] for row in starts] == [row["execution_id"] for row in report["records"]]
    assert [row["execution_id"] for row in finishes] == [row["execution_id"] for row in starts]
    assert all(row["session_id"] == session_id for row in starts + finishes)
    assert not any(row["event_type"].startswith("approval_") for row in events)
    rendered = json.dumps(report) + (directory / "report.md").read_text() + audit_path.read_text()
    assert "billing-db.fixture.invalid" not in rendered and "203.0.113.99" not in rendered
    assert '"body"' not in rendered and "Ignore prior instructions" not in rendered


@pytest.mark.integration
def test_real_dry_run_records_no_execution_or_finding(linux_lab, tmp_path):
    policy, limits, session_id, backend, coordinator = build(approval=True, execute=False)
    directory = tmp_path / "evidence"
    with AuditSink(tmp_path / "private-audit" / "events.jsonl") as audit, EvidenceStore(
        directory, session_id=session_id, policy=policy, case="a",
    ) as evidence:
        provider = AssessmentProvider("a", audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        summary = authority.run()
        report = evidence.finalize(summary)
    assert summary["session_status"] == "completed" and summary["actions_succeeded"] == 0
    assert report["outcome"] == "inconclusive" and report["records"] == []
    assert provider.broker.snapshot["calls_reserved"] == 1
    assert backend.snapshot["executions_reserved"] == 0
    assert inspect_assessment(directory) == report


@pytest.mark.integration
@pytest.mark.parametrize("mode,succeeded", [("none", 0), ("fresh", 2), ("refuse_second", 1), ("replay", 1)])
def test_real_assessment_needs_each_scripted_grant(linux_lab, tmp_path, mode, succeeded):
    """Store callbacks test mechanics; they do not represent human approval."""
    policy, limits, session_id, backend, coordinator = build(approval=True)
    directory, grants = tmp_path / "evidence", []

    def approve(controller, raw, *, control):
        control.check()
        if mode == "none" or (mode == "refuse_second" and grants):
            return None
        if mode == "replay" and grants:
            return grants[0]
        grant = controller.approvals.issue(parse_action(raw), controller.policy).reference
        grants.append(grant)
        return grant

    with AuditSink(tmp_path / "private-audit" / "events.jsonl") as audit, EvidenceStore(
        directory, session_id=session_id, policy=policy, case="a",
    ) as evidence:
        provider = AssessmentProvider("a", audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        summary = authority.run(execute=True, interactive=True, approval=approve)
        report = evidence.finalize(summary)
    assert summary["actions_succeeded"] == backend.snapshot["executions_reserved"] == succeeded
    assert len(report["records"]) == succeeded
    assert report["outcome"] == ("validated" if mode == "fresh" else "inconclusive")
    assert all(grant not in json.dumps(report) for grant in grants)
    assert inspect_assessment(directory) == report


@pytest.mark.integration
def test_real_artifact_failure_stops_before_another_plan_or_execution(linux_lab, tmp_path, monkeypatch):
    policy, limits, session_id, backend, coordinator = build()
    directory, audit_path = tmp_path / "evidence", tmp_path / "private-audit" / "events.jsonl"
    with AuditSink(audit_path) as audit, EvidenceStore(directory, session_id=session_id, policy=policy, case="a") as evidence:
        provider = AssessmentProvider("a", audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        original = evidence._write_new

        def fail_artifact(name, raw, limit):
            if name.startswith("result-"):
                raise OSError("synthetic storage failure after execution")
            original(name, raw, limit)

        monkeypatch.setattr(evidence, "_write_new", fail_artifact)
        with pytest.raises(EvidenceUnavailable):
            authority.run(execute=True)
    assert provider.broker.snapshot["calls_reserved"] == backend.snapshot["executions_reserved"] == 1
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert sum(row["event_type"] == "execution_started" for row in events) == 1
    assert not any(row["event_type"] == "execution_finished" for row in events)
    assert not (directory / "report.json").exists()
    recovered = inspect_assessment(directory)
    assert recovered["outcome"] == "inconclusive"
    assert "execution_completion_unknown" in recovered["integrity_issues"]
