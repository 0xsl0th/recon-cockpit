"""Actual bounded curl HTTP OPTIONS execution, useful results, authority and replay."""

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
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned HTTP OPTIONS trials")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))
    value = json.loads(Path("examples/secure-agent-http-options-policy.json").read_text())
    assert value["allowed_tools"] == [fixture.HTTP_OPTIONS_TOOL_ID] and value["require_approval"] is True
    monkeypatch.setattr(gates, "required_policy", lambda: parse_policy(value))


@pytest.mark.parametrize("case", fixture.HTTP_OPTIONS_CASES)
def test_real_http_options_completion_bounds_enforcement_and_readonly_replay(tmp_path, capsys, record_property, case):
    useful = int(case in fixture.HTTP_OPTIONS_SUCCESS_CASES)
    ordinary = case in fixture.HTTP_OPTIONS_CASES[:6]
    outcome = "http_options_observed" if useful else "inconclusive"
    policy = json.loads(Path("examples/secure-agent-http-options-policy.json").read_text())
    policy.update(policy_version="synthetic-http-options-unattended-test-v1", require_approval=False)
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
    # Server status is metadata, never an approval denial.
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
    # Negative fixtures must follow a real validated OPTIONS request. Startup
    # failure or skipped execution cannot masquerade as an expected refusal.
    assert closure["status"] == "closed" and closure["connection_count"] == closure["request_count"] == 1
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec
    definition = spec(case)
    assert definition['request_bytes'] == len(fixture.HTTP_OPTIONS_REQUEST)
    assert definition['request_count_means'] == 'validated_fixed_http_options_request'
    record_property('validated_fixed_http_options_request', 1)
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["action"]["tool_id"] == fixture.HTTP_OPTIONS_TOOL_ID
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
        assert artifact['status'] == 'succeeded' and artifact['truncated'] is False
        assert stderr == b'' and artifact['provenance']['exit_code'] == 0
        assert artifact['provenance']['stop_reason'] is None
        details = observation['details']
        status = 204 if case == 'http-options-no-content' else 401 if case == 'http-options-auth-required' else 405 if case == 'http-options-method-not-allowed' else 200
        assert details == {'parser_version': 'curl-http-options-v1', 'kind': 'http_options_metadata',
            'semantics': 'untrusted_http_options_metadata', 'status_code': status,
            'allow_present': case != 'http-options-absent-allow',
            'allowed_methods': [] if case in ('http-options-absent-allow', 'http-options-empty-allow') else ['GET', 'HEAD', 'OPTIONS'],
            'auth_schemes': ['basic', 'bearer'] if case == 'http-options-auth-required' else [],
            'service_identity_verified': False}
        if case == 'http-options-injected':
            assert fixture.HOSTILE_NOTE.encode('ascii') in stdout
        assert fixture.HOSTILE_NOTE not in json.dumps(details)
        assert fixture.HOSTILE_NOTE not in (evidence / 'report.md').read_text()
        assert 'HarborDesk owned' not in json.dumps(details)
        assert all(step['decision'] == 'allow' for step in summary['steps'])
    else:
        assert artifact["tool_observation"] is None
    if case == "http-options-output-limit":
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


def test_http_options_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, "http-options-ok", 1)


def test_http_options_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, "http-options-ok")


def test_http_options_cancellation_after_actual_curl_exec_reaps_tool_tree(tmp_path):
    _cancel_actual_tool(tmp_path, "http-options-stalled", b"/tool/curl")


def test_http_options_cannot_read_host_credentials_bootstrap_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, "http-options-ok")


def test_http_options_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, "http-options-ok")


