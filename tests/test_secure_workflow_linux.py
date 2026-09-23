"""Actual Linux workflow decisions with isolated TCP/HTTP execution and evidence."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.assessment import WorkflowAssessmentProvider
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedDiscoveryFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES, LinuxOfflineCoordinator
from recon_cockpit.secure_agent.evidence import EvidenceStore, inspect_assessment
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import SessionLimits
from recon_cockpit.secure_agent.workflow import card_identity


@pytest.fixture
def linux_lab():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual Linux isolation")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxOfflineCoordinator().check_available()


def build(*, approval=False, execute=True, limits=None):
    path = Path(__file__).resolve().parents[1] / "examples/secure-agent-discovery-policy.json"
    policy = parse_policy({**json.loads(path.read_text()), "require_approval": approval})
    limits = limits or SessionLimits(max_steps=3, max_output_bytes=3072)
    session_id = str(uuid4())
    backend = AuthorizedDiscoveryFixtureBackend(policy, session_id, limits, execute=execute)
    return policy, limits, session_id, backend, LinuxOfflineCoordinator()


@pytest.mark.integration
@pytest.mark.parametrize("case,outcome,succeeded,exchanges", [
    ("a", "validated", 3, 3), ("b", "not_demonstrated", 3, 3), ("c", "inconclusive", 3, 3),
    ("d", "inconclusive", 2, 3), ("e", "inconclusive", 2, 3), ("f", "inconclusive", 2, 2),
])
def test_real_workflow_card_decisions_are_traceable_to_isolated_execution(
        linux_lab, tmp_path, monkeypatch, case, outcome, succeeded, exchanges):
    policy, limits, session_id, backend, coordinator = build()
    directory, audit_path = tmp_path / "evidence", tmp_path / "audit" / "events.jsonl"
    children = []
    original_popen = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original_popen(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    with AuditSink(audit_path) as audit, EvidenceStore(
            directory, session_id=session_id, policy=policy, case=case, discovery=True, workflow=True) as evidence:
        provider = WorkflowAssessmentProvider(case, audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        summary = authority.run(execute=True)
        report = evidence.finalize(summary)
    assert report["workflow_card"] == card_identity()
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert summary["actions_succeeded"] == succeeded
    assert provider.broker.snapshot["calls_reserved"] == backend.snapshot["executions_reserved"] == exchanges
    assert backend.snapshot["output_bytes_reserved"] == summary["output_reserved_bytes"] == exchanges * 1024
    assert provider.broker.snapshot["output_tokens_reserved"] == exchanges * 1024
    assert len(report["decision_trace"]) == 3 and len(report["records"]) == exchanges
    assert len(children) == 1 + exchanges * 2
    assert all(child.poll() is not None for child in children)
    assert coordinator.boundary_checks == provider.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
    assert report["records"][0]["observation"]["classification"] == "reachable"
    assert [row["action"]["tool_id"] for row in report["records"]] == [
        "tcp_connect", *(["http_probe"] * (exchanges - 1))]
    for index, decision in enumerate(report["decision_trace"]):
        assert decision["workflow_digest"] == card_identity()["sha256"]
        assert decision["predecessors"] == [
            {key: row[key] for key in ("execution_id", "observation_id")}
            for row in report["records"][:index]]
        if decision["decision_kind"] == "propose":
            execution = report["records"][index]
            assert decision["execution_id"] == execution["execution_id"]
            assert decision["execution_status"] == execution["execution_status"]
            assert decision["action_digest"] == execution["action_digest"]
            artifact = json.loads((directory / execution["artifact"]["filename"]).read_text())
            assert artifact["boundary_checks"] == dict.fromkeys(
                ("forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked", "capabilities_dropped"), True)
        else:
            assert case == "f" and decision["reason"] == "fixture_index_not_established"
            assert decision["execution_status"] == "not_proposed" and decision["execution_id"] is None
    if case in {"d", "e"}:
        expected = "action_timeout" if case == "d" else "action_output_limit"
        assert summary["stop_reason"] == report["terminal_decision"]["reason"] == expected
    else:
        assert summary["session_status"] == "completed"
    journal = [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]
    for index, entry in enumerate(journal):
        if entry["event_type"] == "assessment_execution_started":
            previous = journal[index - 1]
            assert previous["event_type"] == "assessment_workflow_decision"
            assert previous["decision"]["action_digest"] == entry["record"]["action_digest"]
    assert [entry["event_type"] for entry in journal[-2:]] == [
        "assessment_workflow_terminal", "assessment_finished"]
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    assert inspect_assessment(directory) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in directory.iterdir())
    rendered = json.dumps(report) + (directory / "report.md").read_text() + audit_path.read_text()
    assert "billing-db.fixture.invalid" not in rendered and "Ignore prior instructions" not in rendered
    assert "203.0.113.99" not in rendered and '"body"' not in rendered


@pytest.mark.integration
@pytest.mark.parametrize("mode,executions,reason", [
    ("dry_run", 0, "dry_run_has_no_execution_evidence"),
    ("no_approval", 0, "noninteractive_approval_required"),
    ("output_budget", 1, "output_limit"),
    ("step_budget", 1, "step_limit"),
])
def test_real_workflow_proposals_preserve_authority_stops(linux_lab, tmp_path, mode, executions, reason):
    limits = SessionLimits(max_steps=1 if mode == "step_budget" else 3,
                           max_output_bytes=1024 if mode == "output_budget" else 3072)
    execute = mode != "dry_run"
    policy, limits, session_id, backend, coordinator = build(
        approval=mode == "no_approval", execute=execute, limits=limits)
    directory = tmp_path / "evidence"
    with AuditSink(tmp_path / "audit" / "events.jsonl") as audit, EvidenceStore(
            directory, session_id=session_id, policy=policy, case="a", discovery=True, workflow=True) as evidence:
        provider = WorkflowAssessmentProvider("a", audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        summary = authority.run(execute=execute)
        report = evidence.finalize(summary)
    assert backend.snapshot["executions_reserved"] == summary["actions_succeeded"] == executions
    assert report["outcome"] == "inconclusive" and report["integrity_issues"] == []
    assert report["terminal_decision"]["reason"] == reason
    assert inspect_assessment(directory) == report
    if mode in {"dry_run", "no_approval", "output_budget"}:
        unexecuted = report["decision_trace"][executions]
        assert unexecuted["decision_kind"] == "propose" and unexecuted["execution_status"] == "not_executed"
        assert unexecuted["execution_id"] is None
    if mode == "dry_run":
        assert provider.broker.snapshot["calls_reserved"] == 1
        assert report["decision_trace"][-1]["reason"] == "predecessor_evidence_missing"


@pytest.mark.integration
@pytest.mark.parametrize("mode,executions,reason", [
    ("fresh", 3, "seeded_diagnostic_metadata_exposed"),
    ("refuse_http", 1, "approval_missing"),
    ("replay_tcp", 1, "approval_unknown_or_replayed"),
])
def test_real_workflow_requires_a_fresh_scripted_grant_for_each_action(
        linux_lab, tmp_path, mode, executions, reason):
    # Scripted grants test enforcement; they are not evidence of human consent.
    policy, limits, session_id, backend, coordinator = build(approval=True)
    grants = []

    def approve(controller, raw, *, control):
        control.check()
        if mode == "refuse_http" and grants:
            return None
        if mode == "replay_tcp" and grants:
            return grants[0]
        grant = controller.approvals.issue(parse_action(raw), controller.policy).reference
        grants.append(grant)
        return grant

    directory = tmp_path / "evidence"
    with AuditSink(tmp_path / "audit" / "events.jsonl") as audit, EvidenceStore(
            directory, session_id=session_id, policy=policy, case="a", discovery=True, workflow=True) as evidence:
        provider = WorkflowAssessmentProvider("a", audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        summary = authority.run(execute=True, interactive=True, approval=approve)
        report = evidence.finalize(summary)
    assert backend.snapshot["executions_reserved"] == summary["actions_succeeded"] == executions
    assert report["outcome"] == ("validated" if mode == "fresh" else "inconclusive")
    assert report["terminal_decision"]["reason"] == reason
    assert inspect_assessment(directory) == report
    assert all(grant not in json.dumps(report) for grant in grants)
    if mode != "fresh":
        assert report["decision_trace"][-1]["decision_kind"] == "propose"
        assert report["decision_trace"][-1]["execution_status"] == "not_executed"
        assert report["decision_trace"][-1]["execution_id"] is None
