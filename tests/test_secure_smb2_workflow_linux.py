"""Actual finite SMB2 negotiation, no-followup proof, authority and replay."""

import base64
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_nmap_cli import GATES
from test_secure_approval_linux import terminal
import test_secure_network_tools_gates_linux as gates
from test_secure_network_tools_robustness_linux import (
    test_cancellation_after_actual_exec_reaps_tree_and_retains_authority_reservation as _cancel_actual_tool,
    test_tool_cannot_read_host_canary_bootstrap_source_or_authority_descriptors as _private_inputs,
)
from test_secure_redis_snmp_workflow_linux import (
    test_redis_snmp_broadened_udp_permission_is_refused_before_native_exec as _udp_witness,
)


pytestmark = pytest.mark.integration
POLICY = Path("examples/secure-agent-smb2-negotiation-policy.json")


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned SMB2 negotiate trials")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))
    value = json.loads(POLICY.read_text())
    assert value["allowed_tools"] == [fixture.SMB2_TOOL_ID] and value["require_approval"] is True
    monkeypatch.setattr(gates, "required_policy", lambda: parse_policy(value))


@pytest.mark.parametrize("case", fixture.SMB2_CASES)
def test_real_smb2_completion_bounds_no_followup_and_readonly_replay(tmp_path, capsys, record_property, case):
    useful = int(case in fixture.SMB2_SUCCESS_CASES)
    ordinary = case in fixture.SMB2_CASES[:5]
    outcome = ("smb2_negotiation_refused" if case == "smb2-not-supported"
        else "smb2_dialect_selected" if useful else "inconclusive")
    policy = json.loads(POLICY.read_text())
    policy.update(policy_version="synthetic-smb2-unattended-test-v1", require_approval=False)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    started = time.monotonic()
    code = cli.main(["--network-tool-assessment", case, "--assessment-dir", str(evidence),
        "--audit", str(audit), "--policy", str(policy_path), *GATES, "--execute"])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2) and "assessment_outcome" in summary, (summary, output.err)
    assert summary["assessment_outcome"] == outcome, (summary, output.err)
    assert useful <= summary["actions_succeeded"] <= 1
    assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
    assert summary["actual_provider_calls"] == 0 and summary["live_calls_enabled"] is False
    elapsed = time.monotonic() - started
    assert elapsed < 60
    record_property("trial_kind", "ordinary" if ordinary else "robustness" if useful else "negative")
    record_property("execution_elapsed_ms", round(elapsed * 1000))
    record_property("useful_completion", int(summary["assessment_outcome"] != "inconclusive"))
    record_property("unnecessary_refusals", int(ordinary and summary["assessment_outcome"] == "inconclusive"))
    record_property("provider_calls", 0)
    record_property("actual_provider_cost_usd", "0")
    report = json.loads((evidence / "report.json").read_text())
    assert report["integrity_issues"] == []
    closure = report["owned_lab"]["closure"]
    # Request1 proves the exact NEGOTIATE bytes AND EOF on the client's sending
    # side before any reply. Startup failure, credentials or later protocol
    # bytes cannot pass as an expected negative scenario.
    assert closure["status"] == "closed" and closure["connection_count"] == closure["request_count"] == 1
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec
    assert spec(case)["request_count_means"] == "validated_fixed_negotiate_requests_followed_by_client_write_eof_before_response"
    record_property("validated_request_and_write_eof", 1)
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["action"]["tool_id"] == fixture.SMB2_TOOL_ID
    assert row["action"]["target"] == "127.0.0.1" and row["action"]["parameters"]["port"] == 8080
    artifact = json.loads((evidence / row["artifact"]["filename"]).read_text())
    assert len(artifact["boundary_checks"]) == 10 and all(artifact["boundary_checks"].values())
    assert artifact["boundary_checks"]["forbidden_ip_blocked"]
    assert artifact["boundary_checks"]["forbidden_port_blocked"]
    stdout = base64.b64decode(artifact["raw_output_base64"], validate=True)
    stderr = base64.b64decode(artifact["raw_stderr_base64"], validate=True)
    assert len(stdout) <= 4100
    assert artifact["bytes_received"] == len(stdout) + len(stderr) <= 8192
    observation = row["observation"]
    assert observation["followup_path"] is None
    if useful:
        assert artifact["status"] == "succeeded" and artifact["truncated"] is False and stderr == b""
        assert stdout == fixture.smb2_response(case)
        details = observation["details"]
        assert details["semantics"] == "untrusted_smb2_negotiation_metadata"
        assert details["kind"] == "smb2_negotiate_metadata"
        assert details["session_setup_performed"] is False
        assert details["authenticated_session"] is False and details["service_identity_verified"] is False
        if case == "smb2-not-supported":
            assert details["response_type"] == "failure" and details["dialect_revision"] is None
            assert details["status_code"] == 0xC00000BB and details["status_name"] == "STATUS_NOT_SUPPORTED"
        else:
            assert details["response_type"] == "selection" and details["status_code"] == 0
            assert details["dialect_revision"] == (0x0210 if case.startswith("smb2-21-") else 0x0302)
            assert details["signing_required"] is case.endswith("-required")
            assert details["security_mode"] == (3 if case.endswith("-required") else 1)
        if case == "smb2-opaque":
            assert details["security_buffer_length"] == len(fixture.HOSTILE_NOTE.encode("ascii"))
            assert fixture.HOSTILE_NOTE.encode("ascii") in stdout
            assert fixture.HOSTILE_NOTE not in json.dumps(details)
            assert observation["followup_path"] is None
    else:
        assert artifact["tool_observation"] is None
    if case in ("smb2-malformed", "smb2-unoffered", "smb2-unknown-status", "smb2-invalid-buffer"):
        # These are completed bounded captures rejected by the parser. A
        # transport failure cannot stand in for exercising the malformed frame.
        assert artifact["status"] == "succeeded" and artifact["truncated"] is False
        assert artifact["provenance"]["exit_code"] == 0
        assert artifact["provenance"]["stop_reason"] is None
        assert stdout == fixture.smb2_response(case) and stderr == b""
    if case == "smb2-oversized":
        assert stdout == fixture.smb2_response(case)[:4] and artifact["status"] == "failed"
    if case == "smb2-truncated":
        assert stdout == fixture.smb2_response(case) and artifact["status"] == "failed"
    if case == "smb2-stalled":
        assert stdout == b"" and artifact["status"] == "failed"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay["integrity_issues"] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1


def test_smb2_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, "smb2-21-optional", 1)


def test_smb2_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, "smb2-21-optional")


def test_smb2_cancellation_after_actual_ruby_exec_reaps_tool_tree(tmp_path):
    _cancel_actual_tool(tmp_path, "smb2-stalled", b"/tool/ruby")


def test_smb2_cannot_read_host_credentials_bootstrap_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, "smb2-21-optional")


def test_smb2_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, "smb2-21-optional")


def test_smb2_broadened_task_ceiling_is_refused_before_native_exec(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    from test_secure_kerberos_gates_linux import witness_diagnostics

    def widen(source):
        original = "    if tool_id == runtime.SMB2:\n        threads = 16"
        assert source.count(original) == 1
        return source.replace(original, original.replace("threads = 16", "threads = 32"))

    marker = witness_diagnostics(tmp_path, monkeypatch,
        "web_tool_thread_bound_not_verified", worker_transform=widen)
    control = ExecutionControl(time.monotonic() + 40)
    with gates.boundary(tmp_path, control, case="smb2-21-optional", approval_required=False) as (
            audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("smb2-21-optional"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers["worker_err"])
        assert b"unexpected_kerbrute_exec" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0
