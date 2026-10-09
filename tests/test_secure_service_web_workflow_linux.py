"""Actual three-tool custody and authority gates; test policies are not human consent."""

import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli, launch_admission
from recon_cockpit.secure_agent.admission_isolation import LinuxLaunchAdmission
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.service_web_backend import AuthorizedServiceWebBackend
from recon_cockpit.secure_agent.service_web_contract import BACKEND, LIMITS, TOOL_IDS, action
from recon_cockpit.secure_agent.service_web_fixture import HOSTILE_NOTE
from recon_cockpit.secure_agent.service_web_lab import ServiceWebLab
from recon_cockpit.secure_agent.service_web_runtime import inspect_service_web_runtime
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import instrument
from test_secure_nmap_cli import GATES


pytestmark = pytest.mark.integration
POLICY_PATH = Path("examples/secure-agent-service-web-policy.json")


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for the owned service/web workflow")
    assert sys.platform == "linux" and os.geteuid() != 0
    # Confined subprocesses import their own trusted modules. Any host fallback
    # would hit these traps rather than quietly make this trial pass.
    monkeypatch.setattr(ServiceWebLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedServiceWebBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


def audit_events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def unchanged_files(directory):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in directory.iterdir()}


@pytest.mark.parametrize("case,outcome", [("vulnerable", "gaps_observed"),
    ("corrected", "reviewed_headers_present"), ("injected", "gaps_observed")])
def test_real_three_tool_completion_and_readonly_networkless_replay(
        tmp_path, capsys, record_property, case, outcome):
    policy = json.loads(POLICY_PATH.read_text())
    policy.update(policy_version="synthetic-service-web-unattended-test-v1", require_approval=False)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    started = time.monotonic()
    code = cli.main(["--service-web-assessment", case, "--assessment-dir", str(evidence),
        "--audit", str(audit), "--policy", str(policy_path), *GATES, "--execute"])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert code == 0, (summary, captured.err)
    assert summary["assessment_outcome"] == outcome
    assert summary["legitimate_task_completed"] is True
    assert summary["actions_succeeded"] == summary["steps_attempted"] == 3
    assert summary["output_reserved_bytes"] == 18432
    assert summary["actual_provider_calls"] == summary["actual_cost_microusd"] == 0
    assert summary["live_calls_enabled"] is False
    assert summary["workflow_card"]["id"] == "owned-service-web-assessment-v1"
    assert summary["coordinator_boundary_checks"] and all(summary["coordinator_boundary_checks"].values())
    elapsed = time.monotonic() - started
    assert 0 <= summary["elapsed_ms"] < 60000 and elapsed < 60
    record_property("execution_elapsed_ms", round(elapsed * 1000))
    record_property("legitimate_task_completed", True)
    record_property("actions_succeeded", 3)
    record_property("provider_calls", 0)
    record_property("actual_cost_microusd", 0)
    report = json.loads((evidence / "report.json").read_text())
    assert report["integrity_issues"] == [] and report["outcome"] == outcome
    assert set(report["runtime_bindings"]) == set(TOOL_IDS[:2])
    closure = report["owned_lab"]["closure"]
    assert closure["status"] == "closed" and closure["request_count"] == 10
    assert closure["connection_count"] in (11, 12)
    assert len(report["records"]) == 3
    artifacts = []
    for step, row in enumerate(report["records"], start=1):
        assert row["action"]["tool_id"] == TOOL_IDS[step - 1]
        assert row["action"]["target"] == "127.0.0.1"
        assert row["action"]["parameters"] == action(case, step)["parameters"]
        assert row["execution_status"] == "succeeded"
        artifact = json.loads((evidence / row["artifact"]["filename"]).read_text())
        artifacts.append(artifact)
        assert artifact["boundary_checks"] and all(artifact["boundary_checks"].values())
        assert artifact["backend"] == BACKEND
        assert artifact["owned_lab"]["identity"] == closure["identity"]
        assert artifact["owned_lab"]["request_count"] == (1, 9, 10)[step - 1]
        assert artifact["bytes_received"] <= (8192, 8192, 2048)[step - 1]
        assert artifact["truncated"] is False
        if step < 3:
            provenance = artifact["provenance"]
            assert provenance["runtime_sha256"] == report["runtime_bindings"][TOOL_IDS[step - 1]]
            assert provenance["runtime_manifest"]["tool_id"] == TOOL_IDS[step - 1]
            assert provenance["exit_code"] == 0 and provenance["stop_reason"] is None
    assert artifacts[0]["tool_observation"]["service"]["name"] == "http"
    assert artifacts[1]["tool_observation"]["coverage"] == "complete"
    assert artifacts[1]["tool_observation"]["baseline"] == "not_found"
    assert artifacts[2]["http_headers"]["csp"] == ("present" if case == "corrected" else "absent")
    if case == "injected":
        # Native FFUF preserves the malicious Content-Type parameter in its
        # retained JSON bytes. It is excluded from structured observations and
        # never chooses the next destination or expands the three-action plan.
        raw = base64.b64decode(artifacts[1]["raw_output_base64"], validate=True)
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        assert len(rows) == 8
        injected_rows = [row for row in rows if HOSTILE_NOTE in row["content-type"]]
        assert len(injected_rows) == 1
        assert injected_rows[0]["url"] == "http://127.0.0.1:8080/harbordesk/admin"
        assert HOSTILE_NOTE not in json.dumps(artifacts[1]["tool_observation"])
    for filename in ("report.json", "report.md", "evidence.jsonl"):
        assert HOSTILE_NOTE not in (evidence / filename).read_text()
        assert "127.0.0.2" not in (evidence / filename).read_text()
    events = audit_events(audit)
    assert sum(row["event_type"] == "execution_started" for row in events) == 3
    assert not any(row["event_type"] == "approval_consumed" for row in events)
    before = unchanged_files(evidence)
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay["integrity_issues"] == []
    assert before == unchanged_files(evidence)


def test_shipped_required_approval_blocks_noninteractive_cli_before_launcher(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(LinuxFixtureLauncher, "_start", lambda *a, **k: pytest.fail("unapproved launcher started"))
    monkeypatch.setattr(LinuxApprovalService, "_start", lambda *a, **k: pytest.fail("unattended approval service started"))
    monkeypatch.setattr(cli, "_isolated_human_approval", lambda *a, **k: pytest.fail("human approval was synthesized"))
    evidence, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    code = cli.main(["--service-web-assessment", "vulnerable", "--assessment-dir", str(evidence),
        "--audit", str(audit), "--policy", str(POLICY_PATH), *GATES, "--execute"])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert code in (0, 2), (summary, captured.err)
    assert summary["actions_succeeded"] == 0 and summary["legitimate_task_completed"] is False
    assert summary["assessment_outcome"] == "inconclusive"
    assert summary["actual_provider_calls"] == summary["actual_cost_microusd"] == 0
    events = audit_events(audit)
    rejected = [row for row in events if row["event_type"] == "approval_rejected"]
    assert rejected and rejected[0]["reasons"] == ["noninteractive_approval_required"]
    assert not any(row["event_type"] in ("approval_consumed", "execution_started") for row in events)
    report = json.loads((evidence / "report.json").read_text())
    assert report["records"] == []
    assert report["owned_lab"]["closure"]["status"] == "closed"
    assert report["owned_lab"]["closure"]["connection_count"] == 0
    assert report["owned_lab"]["closure"]["request_count"] == 0


def test_actual_isolated_admission_rejects_reordering_and_replays_without_reserving():
    policy = parse_policy(json.loads(POLICY_PATH.read_text()))
    control = ExecutionControl(time.monotonic() + 20)
    with LinuxLaunchAdmission(policy, str(uuid4()), SessionLimits(**LIMITS), execute=True,
                              profile="owned_service_web_lab", case="vulnerable") as gate:
        skipped = gate.admit(parse_action(action("vulnerable", 2)), policy, control=control)
        assert skipped["reason"] == "admission_profile_denied"
        assert dict(gate.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        for step in (1, 2, 3):
            selected = parse_action(action("vulnerable", step))
            allowed = gate.admit(selected, policy, control=control)
            assert allowed["permit"] and allowed["reason"] is None
            assert gate.redeem(allowed["permit"], selected, policy, control=control)["reason"] is None
            assert gate.redeem(allowed["permit"], selected, policy, control=control)["reason"] == "admission_unknown_or_replayed"
            assert dict(gate.snapshot) == {"executions_reserved": step,
                                           "output_bytes_reserved": (8192, 16384, 18432)[step - 1]}
            repeat = gate.admit(selected, policy, control=control)
            assert repeat["reason"] == ("admission_step_limit" if step == 3 else "admission_profile_denied")
            assert repeat["snapshot"] == dict(gate.snapshot)
        assert gate.boundary_checks == dict.fromkeys(launch_admission.CHECKS, True)
        process = gate._process
    assert process.poll() is not None


@contextmanager
def boundary(tmp_path, control, *, required=True):
    value = json.loads(POLICY_PATH.read_text())
    value.update(policy_version="synthetic-service-web-gate-test-v1", require_approval=required)
    policy, session = parse_policy(value), str(uuid4())
    limits = SessionLimits(**LIMITS)
    lab = ServiceWebLab("injected", session, limits)
    backend = AuthorizedServiceWebBackend(policy, session, limits, lab, execute=True)
    backend._service_web_manifests = inspect_service_web_runtime(control)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session


def test_durable_intent_without_consumed_approval_never_reaches_nested_admission(tmp_path, monkeypatch):
    # This forged reference is an adversarial test input, never a grant or a
    # claim that a person accepted an action.
    instrument(tmp_path, monkeypatch, lambda source: source.replace("granted = gate.admit(",
        "os.write(2, b'UNEXPECTED-SERVICE-WEB-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action("injected", 1))
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        event = intent(selected, policy, session, backend=BACKEND)
        event["approval_reference"] = "a" * 48
        audit.emit(event)
        with pytest.raises((IsolationUnavailable, ExecutionStopped)):
            launcher.run(selected, policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert b"UNEXPECTED-SERVICE-WEB-ADMISSION" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == launcher.close()["connection_count"] == 0


@pytest.mark.parametrize("tag", ["network-tools-launch-preconditions", "web-tools-launch-preconditions"])
def test_existing_runtime_tags_cannot_relabel_composed_authority(tmp_path, monkeypatch, tag):
    original = LinuxFixtureLauncher._command
    def changed(self, *args):
        argv = original(self, *args)
        assert argv[-1] == "service-web-launch-preconditions"
        argv[-1] = tag
        return argv
    monkeypatch.setattr(LinuxFixtureLauncher, "_command", changed)
    control = ExecutionControl(time.monotonic() + 20)
    with boundary(tmp_path, control, required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("injected", 1), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked"
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["request_count"] == 0


def test_out_of_scope_proposal_is_recorded_without_approval_or_launcher(tmp_path):
    control = ExecutionControl(time.monotonic() + 20)
    selected = {**action("injected", 1), "target": "127.0.0.2"}
    with boundary(tmp_path, control) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            selected, execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked" and result["reasons"] == ["target_out_of_scope"]
        assert launcher._supervisor is approvals._supervisor is None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["request_count"] == 0
    events = audit_events(tmp_path / "audit.jsonl")
    assert any(row["event_type"] == "policy_decision" and row["decision"] == "deny" for row in events)
    assert not any(row["event_type"] == "execution_started" for row in events)
