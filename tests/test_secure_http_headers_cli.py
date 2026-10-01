"""HTTP header CLI selection and dry-run behavior with portable service doubles.

These tests make no OS isolation or human-approval acceptance claim.
"""

import json
import os
from pathlib import Path
import socket

import pytest

from recon_cockpit.secure_agent import cli
from test_secure_offline_authority import Coordinator


GATES = ("--owned-lab", "--isolated-audit", "--isolated-approvals", "--isolated-launch-admission",
         "--isolated-launcher", "--require-launch-audit", "--require-launch-approval")


def arguments(tmp_path, case="vulnerable"):
    return ["--http-headers-assessment", case, "--assessment-dir", str(tmp_path / "evidence"),
            "--audit", str(tmp_path / "audit.jsonl"), "--policy", "examples/secure-agent-http-headers-policy.json"]


@pytest.mark.parametrize("missing", GATES)
def test_every_launch_gate_is_mandatory_before_policy_read_or_filesystem_writes(tmp_path, monkeypatch, missing):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("policy read before option refusal"))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path), *(gate for gate in GATES if gate != missing)])
    assert error.value.code == 2
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("option,value", [
    ("--session-max-steps", "4"), ("--session-max-seconds", "61"),
    ("--session-max-output-bytes", "18433"), ("--session-max-steps", "0"),
    ("--session-max-seconds", "0"), ("--session-max-output-bytes", "0"),
])
def test_headers_session_overrides_cannot_expand_or_disable_reviewed_caps(tmp_path, monkeypatch, option, value):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("policy read before option refusal"))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path), *GATES, option, value])
    assert error.value.code == 2
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("option", ("--assessment-planning-offline", "--assessment-planning-owned-tls"))
def test_existing_planning_profiles_cannot_be_substituted_into_headers_workflow(tmp_path, monkeypatch, option):
    from recon_cockpit.secure_agent.assessment_planning_contract import SCENARIOS
    from recon_cockpit.secure_agent.assessment_planning_tls_contract import SCENARIOS as TLS_SCENARIOS
    scenario = next(iter(TLS_SCENARIOS if option.endswith("tls") else SCENARIOS))
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("policy read before option refusal"))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path), *GATES, option, scenario])
    assert error.value.code == 2
    assert not list(tmp_path.iterdir())


def test_headers_example_policy_keeps_singleton_scope_and_fresh_approval():
    value = json.loads(Path("examples/secure-agent-http-headers-policy.json").read_text())
    assert value["require_approval"] is True
    assert value["allowed_targets"] == ["127.0.0.1/32"]
    assert value["allowed_ports"] == [8080] and value["allowed_methods"] == ["GET"]
    assert value["allowed_tools"] == ["nmap_tcp_connect_v1", "http_headers_v1"]


@pytest.fixture
def portable_services(monkeypatch):
    """Keep bootstrap objects; fake IPC custody and OS audit/coordinator activity."""
    from recon_cockpit.secure_agent import audit_isolation, coordinator_isolation, nmap_runtime
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    from recon_cockpit.secure_agent.owned_lab import OwnedLab

    writers = []
    events = []

    def audit_start(sink):
        sink._witness_reader, writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        writers.append(writer)

    def approval_witness(service):
        reader, service._witness_writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        service._witness_taken = True
        info = os.fstat(reader.fileno())
        return reader, {"version": "1", "broker_id": service._identity,
                        "device": info.st_dev, "inode": info.st_ino}

    monkeypatch.setattr(audit_isolation.LinuxAuditSink, "_start", audit_start)
    monkeypatch.setattr(audit_isolation.LinuxAuditSink, "emit", lambda _, event: events.append(dict(event)))
    monkeypatch.setattr(audit_isolation.LinuxAuditSink, "close", lambda sink: sink._cleanup())
    monkeypatch.setattr(coordinator_isolation, "LinuxOfflineCoordinator", Coordinator)
    monkeypatch.setattr(LinuxApprovalService, "take_launch_witness", approval_witness)
    monkeypatch.setattr(nmap_runtime, "inspect_nmap_runtime", lambda *_: pytest.fail("dry-run inspected scanner runtime"))
    monkeypatch.setattr(nmap_runtime, "parse_isolated_xml", lambda *a, **k: pytest.fail("dry-run started XML parser"))
    from recon_cockpit.secure_agent import http_headers_parser_runtime
    monkeypatch.setattr(http_headers_parser_runtime, "parse_isolated_headers", lambda *a, **k: pytest.fail("dry-run started HTTP parser"))
    monkeypatch.setattr(OwnedLab, "start", lambda *_: pytest.fail("dry-run started lab"))
    monkeypatch.setattr(LinuxApprovalService, "_start", lambda *_: pytest.fail("dry-run started approval service"))
    monkeypatch.setattr(LinuxFixtureLauncher, "_start", lambda *_: pytest.fail("dry-run started launcher"))
    try:
        yield events
    finally:
        for writer in writers:
            writer.close()


@pytest.mark.parametrize("case", ("vulnerable", "corrected", "injected"))
def test_dry_run_uses_headers_profile_without_tool_runtime_and_inspects_read_only(
        tmp_path, capsys, portable_services, case):
    assert cli.main([*arguments(tmp_path, case), *GATES, "--dry-run"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["actions_succeeded"] == 0
    assert summary["assessment_outcome"] == "inconclusive"
    assert summary["actual_provider_calls"] == 0 and summary["live_calls_enabled"] is False
    assert summary["workflow_card"]["id"] == "owned-http-headers-assessment-v1"
    assert summary["capability"]["http_paths"] == ["/harbordesk/portal.html"]
    assert not any(event["event_type"] == "execution_started" for event in portable_services)
    evidence = tmp_path / "evidence"
    manifest = json.loads((evidence / "manifest.json").read_text())
    assert manifest["workflow"] == "owned-http-headers-assessment-v1"
    assert manifest["owned_lab"]["scenario"] == case
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in evidence.iterdir()}
    assert not list(evidence.glob("result-*"))
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["integrity_issues"] == [] and report["outcome"] == "inconclusive"
    assert before == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in evidence.iterdir()}


@pytest.mark.parametrize("workflow,selected", [
    ("owned-http-headers-assessment-v1", "reviewed"),
    ("owned-nmap-http-assessment-v1", "reviewed"),
    ("owned-http-assessment-v1", "legacy"),
])
def test_inspection_selects_only_the_reviewed_manifest_workflow(tmp_path, monkeypatch, capsys, workflow, selected):
    from recon_cockpit.secure_agent import evidence, nmap_evidence
    directory = tmp_path / "evidence"
    directory.mkdir(mode=0o700)
    manifest = directory / "manifest.json"
    manifest.write_text(json.dumps({"workflow": workflow}))
    manifest.chmod(0o600)
    monkeypatch.setattr(evidence, "inspect_assessment", lambda _: {"selected": "legacy", "integrity_issues": []})
    monkeypatch.setattr(nmap_evidence, "inspect_assessment", lambda _: {"selected": "reviewed", "integrity_issues": []})
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("inspection read execution policy"))
    assert cli.main(["--inspect-assessment", str(directory)]) == 0
    assert json.loads(capsys.readouterr().out)["selected"] == selected


@pytest.mark.parametrize('workflow', [[], {}, None, 7])
def test_malformed_manifest_workflow_returns_structured_refusal(tmp_path, capsys, workflow):
    directory = tmp_path / 'evidence'
    directory.mkdir(mode=0o700)
    manifest = directory / 'manifest.json'
    manifest.write_text(json.dumps({'workflow': workflow}))
    manifest.chmod(0o600)
    before = manifest.read_bytes(), manifest.stat().st_mtime_ns
    assert cli.main(['--inspect-assessment', str(directory)]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report['execution_status'] == 'evidence_error'
    assert before == (manifest.read_bytes(), manifest.stat().st_mtime_ns)
