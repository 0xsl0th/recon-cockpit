"""Actual bounded dig AXFR execution, useful results, authority and replay."""

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


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned DNS AXFR trials")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))
    value = json.loads(Path("examples/secure-agent-dns-axfr-policy.json").read_text())
    assert value["allowed_tools"] == [fixture.DNS_AXFR_TOOL_ID] and value["require_approval"] is True
    monkeypatch.setattr(gates, "required_policy", lambda: parse_policy(value))


@pytest.mark.parametrize("case", fixture.DNS_AXFR_CASES)
def test_real_axfr_completion_bounds_enforcement_and_readonly_replay(tmp_path, capsys, record_property, case):
    useful = int(case in fixture.DNS_AXFR_SUCCESS_CASES)
    ordinary = case in fixture.DNS_AXFR_CASES[:3]
    outcome = ("dns_axfr_refused" if case == "dig-axfr-refused"
        else "dns_axfr_completed" if useful else "inconclusive")
    policy = json.loads(Path("examples/secure-agent-dns-axfr-policy.json").read_text())
    policy.update(policy_version="synthetic-dns-axfr-unattended-test-v1", require_approval=False)
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
    # An explicit server REFUSED reply is useful transfer behavior, distinct
    # from an authority denial. Process exit alone never establishes either.
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
    # Negative fixtures must follow a real validated AXFR question. Startup
    # failure or skipped execution cannot masquerade as an expected refusal.
    assert closure["status"] == "closed" and closure["connection_count"] == closure["request_count"] == 1
    # The owner increments only after the complete 33-byte DNS message with
    # the fixed AXFR question, not merely after a connection is accepted.
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec
    definition = spec(case)
    assert definition["query_bytes"] == 33
    assert definition["request_count_means"] == "validated_fixed_axfr_questions"
    record_property("validated_fixed_dns_axfr_question", 1)
    record_property("fixed_query_body_bytes", 33)
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["action"]["tool_id"] == fixture.DNS_AXFR_TOOL_ID
    assert row["action"]["target"] == "127.0.0.1" and row["action"]["parameters"]["port"] == 8080
    artifact = json.loads((evidence / row["artifact"]["filename"]).read_text())
    assert len(artifact["boundary_checks"]) == 10 and all(artifact["boundary_checks"].values())
    assert artifact["boundary_checks"]["forbidden_ip_blocked"]
    assert artifact["boundary_checks"]["forbidden_port_blocked"]
    stdout = base64.b64decode(artifact["raw_output_base64"], validate=True)
    stderr = base64.b64decode(artifact["raw_stderr_base64"], validate=True)
    assert artifact["bytes_received"] == len(stdout) + len(stderr) <= 8192
    observation = row["observation"]
    assert observation["followup_path"] is None
    assert len(summary["steps"]) == 1
    if useful:
        # Native dig may emit its fixed denied socket-capability probe before
        # completing the TCP question; arbitrary diagnostics remain unsupported.
        from recon_cockpit.secure_agent.network_tools_dns_srv_parser import DIG_DENIED_PROBE
        assert artifact["status"] == "succeeded" and artifact["truncated"] is False
        assert stderr in (b"", DIG_DENIED_PROBE)
        assert fixture.DNS_AXFR_QUERY_NAME.encode() in stdout
        assert artifact["provenance"]["exit_code"] == 0
        assert artifact["provenance"]["stop_reason"] is None
        refused = case == "dig-axfr-refused"
        details = observation["details"]
        assert details == {"parser_version": "dig-dns-axfr-text-v1", "kind": "dns_axfr_metadata",
            "semantics": "untrusted_dns_zone_transfer_metadata", "query_name": fixture.DNS_AXFR_QUERY_NAME,
            "query_type": "AXFR", "transport": "tcp", "status": "REFUSED" if refused else "NOERROR",
            "transfer_complete": not refused,
            "message_count": 3 if case == "dig-axfr-multiframe" else 1,
            "answer_record_count": 0 if refused else 5,
            "soa_serial": None if refused else 2026100801, "service_identity_verified": False}
        # Hostile TXT stays in raw evidence; omitting its text from this bounded
        # summary does not claim general injection detection or DNS identity.
        if case == "dig-axfr-injected":
            assert fixture.HOSTILE_NOTE.encode("ascii") in stdout
        assert fixture.HOSTILE_NOTE not in json.dumps(details)
        assert fixture.HOSTILE_NOTE not in (evidence / "report.md").read_text()
        assert all(step["decision"] == "allow" for step in summary["steps"])
        if refused:
            assert details["transfer_complete"] is False
            assert details["answer_record_count"] == 0 and details["soa_serial"] is None
    else:
        assert artifact["tool_observation"] is None
    if case == "dig-axfr-output-limit":
        assert artifact["status"] == "output_limit" and artifact["truncated"] is True
        assert artifact["provenance"]["stop_reason"] == "output_limit"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay["integrity_issues"] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    assert not any(event["event_type"].startswith("approval_") for event in events)
    decisions = [event for event in events if event["event_type"] == "policy_decision"]
    assert len(decisions) == 2 and all(event["decision"] == "allow" for event in decisions)


def test_axfr_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, "dig-axfr-ok", 1)


def test_axfr_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, "dig-axfr-ok")


def test_axfr_cancellation_after_actual_dig_exec_reaps_tool_tree(tmp_path):
    _cancel_actual_tool(tmp_path, "dig-axfr-stalled", b"/tool/dig")


def test_axfr_cannot_read_host_credentials_bootstrap_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, "dig-axfr-ok")


def test_axfr_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, "dig-axfr-ok")


def test_axfr_broadened_task_ceiling_is_refused_before_native_exec(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    from test_secure_kerberos_gates_linux import witness_diagnostics

    def widen(source):
        original = "    if tool_id == runtime.DIG_AXFR:\n        threads = 16"
        assert source.count(original) == 1
        return source.replace(original, original.replace("threads = 16", "threads = 32"))

    marker = witness_diagnostics(tmp_path, monkeypatch,
        "web_tool_thread_bound_not_verified", worker_transform=widen)
    control = ExecutionControl(time.monotonic() + 40)
    with gates.boundary(tmp_path, control, case="dig-axfr-ok", approval_required=False) as (
            audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("dig-axfr-ok"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers["worker_err"])
        assert b"unexpected_kerbrute_exec" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0
