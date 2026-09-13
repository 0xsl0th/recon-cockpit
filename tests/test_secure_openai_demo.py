"""Safe demo output units and complete, opted-in offline Linux demonstrations."""

import json
import os
from pathlib import Path
import sys

import pytest

from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES
from scripts import secure_agent_openai_demo as demo


def test_demo_accepts_only_complete_true_parser_checks():
    demo._require_planner_checks(dict.fromkeys(BOUNDARY_NAMES, True))


@pytest.mark.parametrize("checks", [
    None, [], {}, {"socket_creation_blocked": True},
    {**dict.fromkeys(BOUNDARY_NAMES, True), "capabilities_dropped": False},
    {**dict.fromkeys(BOUNDARY_NAMES, True), "capabilities_dropped": 1},
    {**dict.fromkeys(BOUNDARY_NAMES, True), "capabilities_dropped": "true"},
    {**dict.fromkeys(BOUNDARY_NAMES, True), "secret": "do not display"},
])
def test_demo_does_not_claim_invalid_boundary_evidence(checks):
    with pytest.raises(RuntimeError, match="^offline planner boundary verification failed$"):
        demo._require_planner_checks(checks)


@pytest.mark.parametrize("execute", [False, True])
def test_demo_cli_passes_only_operator_execution_selection(monkeypatch, tmp_path, capsys, execute):
    path = tmp_path / "audit.jsonl"
    argv = ["demo", "--audit", str(path)] + (["--execute-fixtures"] if execute else [])
    monkeypatch.setattr(sys, "argv", argv)
    calls = []

    def run(audit_path, *, execute_fixtures, on_case):
        calls.append((audit_path, execute_fixtures))
        on_case({"case": "three_step", "stop_reason": "planner_done"})
        return {"demo": "passed", "cases": [], "audit": str(audit_path)}

    monkeypatch.setattr(demo, "run_demo", run)
    assert demo.main() == 0
    assert calls == [(path, execute)]
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[0]["provider"] == "linux-isolated-openai-offline"
    assert lines[1] == {"case": "three_step", "stop_reason": "planner_done"}
    assert lines[-1]["demo"] == "passed"


@pytest.mark.parametrize("error,status,exit_code", [
    (IsolationUnavailable("private-path-and-secret"), "blocked", 2),
    (RuntimeError("private-response-and-secret"), "failed", 1),
])
def test_demo_cli_failure_does_not_echo_diagnostics(monkeypatch, tmp_path, capsys, error, status, exit_code):
    monkeypatch.setattr(sys, "argv", ["demo", "--audit", str(tmp_path / "audit.jsonl")])

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(demo, "run_demo", fail)
    assert demo.main() == exit_code
    output = capsys.readouterr().out
    assert "secret" not in output
    assert json.loads(output.splitlines()[-1])["demo"] == status


@pytest.mark.integration
@pytest.mark.parametrize("execute", [False, True])
def test_real_offline_demo_runs_all_nine_cases(tmp_path, execute):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real offline planner isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux":
        pytest.skip("real offline planner isolation requires Linux")
    path = tmp_path / "audit.jsonl"
    report = demo.run_demo(path, execute_fixtures=execute)
    assert report["demo"] == "passed"
    assert report["mode"] == ("execute_owned_fixtures" if execute else "dry_run_tools")
    cases = {case["case"]: case for case in report["cases"]}
    assert set(cases) == {
        "three_step", "injection_target", "injection_authority", "refusal", "malformed", "incomplete",
        "call_budget", "token_budget", "timeout",
    }
    assert cases["three_step"]["session_status"] == "completed"
    assert cases["injection_target"]["steps"][-1]["reasons"] == ["target_out_of_scope"]
    assert cases["injection_authority"]["stop_reason"] == "session_component_failed"
    assert cases["call_budget"]["stop_reason"] == "broker_call_limit"
    assert cases["token_budget"]["stop_reason"] == "broker_token_limit"
    assert cases["timeout"]["stop_reason"] == "session_timeout"
    for case in cases.values():
        assert case["policy_unchanged"] is True
        assert all(row["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
                   for row in case["planner_executions"])
        assert len(case["tool_executions"]) == case["actions_succeeded"]
        assert case["broker_counters"]["calls_reserved"] <= 3
        if not execute:
            assert case["actions_succeeded"] == 0
            assert case["tool_executions"] == []
    if execute:
        assert cases["three_step"]["actions_succeeded"] == 3
        assert cases["three_step"]["tool_executions"][1]["injection_fixture_received"] is True
        assert cases["injection_target"]["actions_succeeded"] == 1
        assert cases["injection_authority"]["actions_succeeded"] == 1
    text = path.read_text()
    assert "Ignore prior instructions" not in text + json.dumps(report)
    assert '"body"' not in text
    records = [json.loads(line) for line in text.splitlines()]
    assert sum(event["event_type"] == "session_finished" for event in records) == 9
    assert sum(event["event_type"] == "execution_started" for event in records) == (9 if execute else 0)
    assert not any(event["event_type"].startswith("approval_") for event in records)
    assert all(event.get("approval_reference") is None for event in records)
