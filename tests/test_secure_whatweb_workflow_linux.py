"""Actual passive WhatWeb under all authority gates; no host/native fallback."""

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
from recon_cockpit.secure_agent.network_tools_fixture import (
    WHATWEB_CASES, WHATWEB_SUCCESS_CASES, WHATWEB_TOOL_ID, HOSTILE_NOTE,
)
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
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned WhatWeb trials")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))
    # Reused boundary tests still use the new profile's one-tool shipped policy.
    value = json.loads(Path("examples/secure-agent-whatweb-policy.json").read_text())
    assert value["allowed_tools"] == [WHATWEB_TOOL_ID] and value["require_approval"] is True
    monkeypatch.setattr(gates, "required_policy", lambda: parse_policy(value))


@pytest.mark.parametrize("case", WHATWEB_CASES)
def test_real_whatweb_completion_bounds_enforcement_and_readonly_replay(tmp_path, capsys, record_property, case):
    useful = int(case in WHATWEB_SUCCESS_CASES)
    outcome = ("http_fingerprint_no_hints" if case == "whatweb-no-hints"
               else "http_fingerprint_observed" if useful else "inconclusive")
    policy = json.loads(Path("examples/secure-agent-whatweb-policy.json").read_text())
    policy.update(policy_version="synthetic-whatweb-unattended-test-v1", require_approval=False)
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
    # WhatWeb may exit zero for an HTTP denial/redirect. Useful completion is
    # the independently parsed assessment outcome, never process exit alone.
    assert useful <= summary["actions_succeeded"] <= 1, (summary, output.err)
    assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
    assert summary["actual_provider_calls"] == 0 and summary["live_calls_enabled"] is False
    elapsed = time.monotonic() - started
    assert elapsed < 60
    ordinary = case in ("whatweb-ok", "whatweb-no-hints")
    record_property("trial_kind", "ordinary" if ordinary else "robustness" if useful else "negative")
    record_property("execution_elapsed_ms", round(elapsed * 1000))
    record_property("useful_completion", int(summary["assessment_outcome"] != "inconclusive"))
    record_property("unnecessary_refusals", int(ordinary and summary["assessment_outcome"] == "inconclusive"))
    record_property("provider_calls", 0)
    record_property("actual_provider_cost_usd", "0")
    report = json.loads((evidence / "report.json").read_text())
    assert report["integrity_issues"] == []
    closure = report["owned_lab"]["closure"]
    # Even EOF, malformed, denied or oversized responses follow a real GET.
    # A startup/guard failure cannot satisfy the expected negative result.
    assert closure["status"] == "closed" and closure["connection_count"] == closure["request_count"] == 1
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["action"]["tool_id"] == WHATWEB_TOOL_ID
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
        assert artifact["status"] == "succeeded" and artifact["truncated"] is False and not stderr
        details = observation["details"]
        assert details["semantics"] == "untrusted_application_hints"
        assert details["kind"] == "http_fingerprint" and details["status_code"] == 200
        if case == "whatweb-no-hints":
            assert details["hints"] == []
        else:
            assert len(details["hints"]) == 5
        if case == "whatweb-injected":
            assert HOSTILE_NOTE in json.dumps(details) and HOSTILE_NOTE.encode() in stdout
    else:
        assert artifact["tool_observation"] is None
    if case == "whatweb-output-limit":
        assert artifact["status"] == "output_limit" and artifact["truncated"] is True
        assert artifact["provenance"]["stop_reason"] == "output_limit"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay["integrity_issues"] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1


def test_whatweb_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, "whatweb-ok", 1)


def test_whatweb_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, "whatweb-ok")


def test_whatweb_cancellation_after_actual_ruby_exec_reaps_tool_tree(tmp_path):
    _cancel_actual_tool(tmp_path, "whatweb-stalled", b"/tool/ruby")


def test_whatweb_cannot_read_host_credentials_bootstrap_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, "whatweb-ok")


def test_whatweb_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, "whatweb-ok")


def test_whatweb_broadened_task_ceiling_is_refused_before_native_exec(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    from test_secure_kerberos_gates_linux import witness_diagnostics

    def widen(source):
        original = "    if tool_id == runtime.WHATWEB:\n        threads = 16"
        assert source.count(original) == 1
        return source.replace(original, original.replace("threads = 16", "threads = 32"))

    # Reuse the existing test-only sentinel. Its exact diagnostic proves that
    # the production thread witness refused the widened kernel limit, before
    # the reviewed Ruby executable could run.
    marker = witness_diagnostics(tmp_path, monkeypatch,
        "web_tool_thread_bound_not_verified", worker_transform=widen)
    control = ExecutionControl(time.monotonic() + 40)
    with gates.boundary(tmp_path, control, case="whatweb-ok", approval_required=False) as (
            audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("whatweb-ok"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert marker in bytes(launcher._supervisor.buffers["worker_err"])
        assert b"unexpected_kerbrute_exec" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0
