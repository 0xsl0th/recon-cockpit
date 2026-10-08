"""Actual bounded dig MX execution, useful results, authority and replay."""

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
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned DNS MX trials")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))
    value = json.loads(Path("examples/secure-agent-dns-mx-policy.json").read_text())
    assert value["allowed_tools"] == [fixture.DNS_MX_TOOL_ID] and value["require_approval"] is True
    monkeypatch.setattr(gates, "required_policy", lambda: parse_policy(value))


@pytest.mark.parametrize("case", fixture.DNS_MX_CASES)
def test_real_mx_completion_bounds_enforcement_and_readonly_replay(tmp_path, capsys, record_property, case):
    useful = int(case in fixture.DNS_MX_SUCCESS_CASES)
    ordinary = case in fixture.DNS_MX_ORDINARY_CASES
    outcome = {"dig-mx-ok": "dns_mx_observed", "dig-mx-single": "dns_mx_observed",
        "dig-mx-injected": "dns_mx_observed",
        "dig-mx-nodata": "dns_mx_no_data", "dig-mx-nxdomain": "dns_mx_name_not_found",
        "dig-mx-null": "dns_mx_mail_unavailable"}.get(case, "inconclusive")
    policy = json.loads(Path("examples/secure-agent-dns-mx-policy.json").read_text())
    policy.update(policy_version="synthetic-dns-mx-unattended-test-v1", require_approval=False)
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
    # DNS refusal is still a zero native exit on some dig versions; usefulness
    # comes from the independently validated result, not the process exit.
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
    # Negative fixtures must follow a real validated MX question. Startup
    # failure or skipped execution cannot masquerade as an expected refusal.
    assert closure["status"] == "closed" and closure["connection_count"] == closure["request_count"] == 1
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["action"]["tool_id"] == fixture.DNS_MX_TOOL_ID
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
    if useful:
        # Native dig may emit its fixed denied socket-capability probe before
        # completing the TCP question; arbitrary diagnostics remain unsupported.
        from recon_cockpit.secure_agent.network_tools_dns_mx_parser import DIG_DENIED_PROBE
        assert artifact["status"] == "succeeded" and artifact["truncated"] is False
        assert stderr in (b"", DIG_DENIED_PROBE)
        assert fixture.DNS_MX_QUERY_NAME.encode() in stdout
        details = observation["details"]
        assert details["semantics"] == "untrusted_dns_mail_metadata"
        assert details["kind"] == "dns_mail_metadata"
        assert details["query_name"] == fixture.DNS_MX_QUERY_NAME
        assert details["query_type"] == "MX" and details["transport"] == "tcp"
        assert details["status"] == ("NXDOMAIN" if case == "dig-mx-nxdomain" else "NOERROR")
        assert details["additional_txt_count"] == int(case == "dig-mx-injected")
        records = [{"preference": preference, "exchange": exchange, "ttl": ttl}
                   for preference, exchange, ttl in fixture.dns_mx_records(case)]
        # The normalizer may choose a canonical order; every advertised value
        # must be retained exactly, without treating a destination as scope.
        assert sorted(details["records"], key=lambda row: json.dumps(row, sort_keys=True)) == sorted(
            records, key=lambda row: json.dumps(row, sort_keys=True))
        if case == "dig-mx-injected":
            assert fixture.HOSTILE_NOTE.encode() in stdout
            assert "outside.invalid." in json.dumps(details)
    else:
        assert artifact["tool_observation"] is None
    if case == "dig-mx-output-limit":
        assert artifact["status"] == "output_limit" and artifact["truncated"] is True
        assert artifact["provenance"]["stop_reason"] == "output_limit"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay["integrity_issues"] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    assert sum(event["event_type"] == "execution_finished" for event in events) == 1
    assert not any(event["event_type"] == "policy_denied" for event in events)


def test_mx_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, "dig-mx-ok", 1)


def test_mx_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, "dig-mx-ok")


def test_mx_cancellation_after_actual_dig_exec_reaps_tool_tree(tmp_path):
    _cancel_actual_tool(tmp_path, "dig-mx-stalled", b"/tool/dig")


def test_mx_cannot_read_host_credentials_bootstrap_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, "dig-mx-ok")


def test_mx_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, "dig-mx-ok")


def test_mx_broadened_task_ceiling_is_refused_before_native_exec(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    from test_secure_kerberos_gates_linux import witness_diagnostics

    def widen(source):
        original = "    if tool_id == runtime.DIG_MX:\n        threads = 16"
        assert source.count(original) == 1
        return source.replace(original, original.replace("threads = 16", "threads = 32"))

    marker = witness_diagnostics(tmp_path, monkeypatch,
        "web_tool_thread_bound_not_verified", worker_transform=widen)
    control = ExecutionControl(time.monotonic() + 40)
    with gates.boundary(tmp_path, control, case="dig-mx-ok", approval_required=False) as (
            audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("dig-mx-ok"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers["worker_err"])
        assert b"unexpected_kerbrute_exec" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0
