"""Actual owned SSH policy execution, finite usefulness, enforcement and replay."""

import base64
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import assessment_inspection, cli
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_ssh_policy_parser as parser
from recon_cockpit.secure_agent import network_tools_ssh_policy_spec as spec
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


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned SSH policy trials")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))
    value = json.loads(Path("examples/secure-agent-ssh-policy-policy.json").read_text())
    assert value["allowed_tools"] == [spec.TOOL_ID] and value["require_approval"] is True
    monkeypatch.setattr(gates, "required_policy", lambda: parse_policy(value))


def _snapshot(directory):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
            for p in directory.iterdir()}


@pytest.mark.parametrize("case", spec.CASES)
def test_real_ssh_policy_usefulness_bounds_enforcement_and_both_replays(tmp_path, capsys, record_property, case):
    useful = case in spec.USEFUL_CASES
    ordinary = case in spec.ORDINARY_CASES
    expected_status = spec.expected_status(case)
    outcome = "ssh_policy_" + expected_status if useful else "inconclusive"
    policy = json.loads(Path("examples/secure-agent-ssh-policy-policy.json").read_text())
    policy.update(policy_version="synthetic-ssh-policy-unattended-test-v1", require_approval=False)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    directory, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    started = time.monotonic()
    code = cli.main(["--network-tool-assessment", case, "--assessment-dir", str(directory),
        "--audit", str(audit), "--policy", str(policy_path), *GATES, "--execute"])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2) and summary.get("assessment_outcome") == outcome, (summary, output.err)
    elapsed = time.monotonic() - started
    assert elapsed < 60
    assert int(case in spec.SUCCESS_CASES) <= summary["actions_succeeded"] <= 1
    assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
    assert summary["actual_provider_calls"] == 0 and summary["live_calls_enabled"] is False
    kind = ("ordinary" if ordinary else "robustness" if useful else
            "unknown" if case in spec.UNKNOWN_CASES else "negative")
    for name, value in {"trial_kind": kind, "execution_elapsed_ms": round(elapsed * 1000),
                        "useful_completion": int(useful), "unnecessary_refusals": 0,
                        "provider_calls": 0, "actual_provider_cost_usd": "0"}.items():
        record_property(name, value)
    report = json.loads((directory / "report.json").read_bytes())
    assert report["integrity_issues"] == [] and report["outcome"] == outcome
    assert report["metrics"]["legitimate_task_completed"] is useful
    assert report["metrics"]["useful_actions_completed"] == int(useful)
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert report["metrics"]["comparative_overhead"] is None
    closure = report["owned_lab"]["closure"]
    # Every negative trial must reach the actual request boundary. A refused
    # startup does not count as handling an unsupported peer response.
    assert closure["status"] == "closed" and closure["connection_count"] == closure["request_count"] == 1
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec as lab_spec
    definition = lab_spec(case)
    assert definition["request_bytes"] == len(fixture.SSH_ALGORITHMS_REQUEST) == 184
    assert definition["request_count_means"] == "validated_fixed_ssh_kexinit_template_and_client_write_eof_before_response"
    assert definition["policy_id"] == parser.POLICY_ID and definition["policy_sha256"] == parser.POLICY_SHA256
    record_property("validated_request_template_and_write_eof", 1)
    assert len(report["records"]) == len(summary["steps"]) == 1
    row = report["records"][0]
    assert row["action"]["tool_id"] == spec.TOOL_ID
    assert row["action"]["target"] == "127.0.0.1" and row["action"]["parameters"]["port"] == 8080
    artifact = json.loads((directory / row["artifact"]["filename"]).read_bytes())
    assert len(artifact["boundary_checks"]) == 10 and all(artifact["boundary_checks"].values())
    stdout = base64.b64decode(artifact["raw_output_base64"], validate=True)
    stderr = base64.b64decode(artifact["raw_stderr_base64"], validate=True)
    assert artifact["bytes_received"] == len(stdout) + len(stderr) <= 8192
    assert len(stdout) <= 4355 and artifact["truncated"] is False
    observation = row["observation"]
    assert observation["followup_path"] is None
    if case in spec.SUCCESS_CASES:
        assert artifact["status"] == "succeeded" and artifact["provenance"]["exit_code"] == 0
        assert artifact["provenance"]["stop_reason"] is None and stderr == b""
        assert stdout == spec.useful_capture(case)
        details = observation["details"]
        assert details == parser.parse_output(stdout)
        assert details["policy_status"] == expected_status
        assert details["semantics"] == parser.SEMANTICS
        assert details["key_exchange_completed"] is details["authenticated_session"] is details["service_identity_verified"] is False
        assert all(step["decision"] == "allow" for step in summary["steps"])
        if case == "ssh-policy-mixed-unknown":
            assert details["rules"]["kex_algorithms"] == {"status": "inconclusive",
                "disallowed": ["diffie-hellman-group1-sha1"], "unknown": ["unknown@owned.test"]}
        if case == "ssh-policy-guessed":
            assert len(stdout) < len(spec.response(case))
        if case == "ssh-policy-injected":
            assert fixture.HOSTILE_NOTE.encode() in stdout
            assert fixture.HOSTILE_NOTE not in json.dumps(details)
            assert fixture.HOSTILE_NOTE not in (directory / "report.md").read_text()
    else:
        assert artifact["tool_observation"] is None
        if case in ("ssh-policy-truncated", "ssh-policy-stalled", "ssh-policy-oversized"):
            assert artifact["status"] == "failed" and artifact["provenance"]["exit_code"] != 0
            assert stdout == (spec.response(case) or b"") and stderr
        else:
            assert artifact["status"] == "succeeded" and artifact["provenance"]["exit_code"] == 0
            assert stdout == spec.response(case) and stderr == b""
    before = _snapshot(directory)
    assert assessment_inspection.inspect_saved_assessment(directory) == report
    assert cli.main(["--inspect-assessment", str(directory)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert _snapshot(directory) == before
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    assert not any(event["event_type"].startswith("approval_") for event in events)
    decisions = [event for event in events if event["event_type"] == "policy_decision"]
    assert len(decisions) == 2 and all(event["decision"] == "allow" for event in decisions)


def test_ssh_policy_grant_consumption_and_replay_refusal(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, "ssh-policy-conforming", 1)


def test_ssh_policy_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, "ssh-policy-conforming")


def test_ssh_policy_cancellation_after_actual_exec_reaps_tree(tmp_path):
    _cancel_actual_tool(tmp_path, "ssh-policy-stalled", b"/tool/ruby")


def test_ssh_policy_cannot_read_host_inputs_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, "ssh-policy-conforming")


def test_ssh_policy_broadened_udp_permission_is_refused_before_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, "ssh-policy-conforming")


def test_ssh_policy_broadened_task_ceiling_is_refused_before_exec(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    from test_secure_kerberos_gates_linux import witness_diagnostics

    def widen(source):
        original = "    if tool_id == runtime.SSH_POLICY:\n        threads = 16"
        assert source.count(original) == 1
        return source.replace(original, original.replace("threads = 16", "threads = 32"))

    marker = witness_diagnostics(tmp_path, monkeypatch,
        "web_tool_thread_bound_not_verified", worker_transform=widen)
    control = ExecutionControl(time.monotonic() + 40)
    with gates.boundary(tmp_path, control, case="ssh-policy-conforming", approval_required=False) as (
            audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("ssh-policy-conforming"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0
