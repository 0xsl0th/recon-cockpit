"""Demo evidence validation; process doubles here do not establish Linux isolation."""

import json
import os
import sys

import pytest

from recon_cockpit.secure_agent import openai_provider
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
from scripts import secure_agent_offline_authority_demo as demo


@pytest.mark.parametrize("names", [demo.BOUNDARY_NAMES, demo.PARSER_BOUNDARY_NAMES, demo.EXECUTOR_BOUNDARY_NAMES])
def test_demo_requires_complete_true_boundary_evidence(names):
    demo._require_checks(dict.fromkeys(names, True), names)
    first = next(iter(names))
    for checks in (None, [], {}, {first: True}, {**dict.fromkeys(names, True), first: False},
                   {**dict.fromkeys(names, True), first: 1},
                   {**dict.fromkeys(names, True), "secret": "must never be displayed"}):
        with pytest.raises(RuntimeError, match="^offline_authority_boundary_verification_failed$"):
            demo._require_checks(checks, names)


@pytest.fixture
def demo_process_doubles(monkeypatch):
    """Exercise real authority/broker/decoder logic; replace all OS boundaries."""
    def run(self, init, exchange, *, control):
        initial = json.loads(init)
        assert initial["schema_version"] == "2"
        self._boundary_checks = dict.fromkeys(demo.BOUNDARY_NAMES, True)
        for step in range(1, 17):
            request = {**initial, "sequence": step, "operation": "plan"}
            response = json.loads(exchange(json.dumps(request).encode(), control=control))
            if not response["stop"]:
                request.update(operation="propose", plan=response["plan"])
                response = json.loads(exchange(json.dumps(request).encode(), control=control))
            if response["stop"]:
                return json.dumps({**initial, "status": "closed"}).encode()
        pytest.fail("authority did not close")

    class Parser:
        boundary_checks = None

        def plan(self, config, observation, exchange, *, control):
            self.boundary_checks = None
            result = decode_response(exchange(build_request(config, observation), control=control))
            self.boundary_checks = dict.fromkeys(demo.PARSER_BOUNDARY_NAMES, True)
            return result

    def execute(self, action, policy, *, control):
        # Synthetic executor result: this verifies the demo's accounting and
        # output validation. Real executor behavior has separate Linux tests.
        control.check()
        assert self._execute is True
        assert self._policy.digest == policy.digest
        self._sequence += 1
        self._output += action.parameters.max_output_bytes
        body = demo.INJECTION_FIXTURE.decode("ascii") if action.parameters.path == "/injection" else "fixture"
        return {"status": "succeeded", "results": [{"body": body}], "bytes_received": len(body),
                "truncated": False, "boundary_checks": dict.fromkeys(demo.EXECUTOR_BOUNDARY_NAMES, True)}

    monkeypatch.setattr(demo.LinuxOfflineCoordinator, "run", run)
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", Parser)
    monkeypatch.setattr(demo.AuthorizedFixtureBackend, "check_available", lambda *_a, **_k: None)
    monkeypatch.setattr(demo.AuthorizedFixtureBackend, "run", execute)


@pytest.mark.parametrize("execute", [False, True])
def test_demo_orchestrates_all_cases_with_safe_correlated_evidence(tmp_path, demo_process_doubles, execute):
    path = tmp_path / "audit.jsonl"
    emitted = []
    report = demo.run_demo(path, execute_fixtures=execute, on_case=emitted.append)
    assert report["demo"] == "passed"
    assert report["live_calls_enabled"] is False
    assert report["mode"] == ("execute_owned_fixtures" if execute else "dry_run_tools")
    assert emitted == report["cases"]
    cases = {case["case"]: case for case in report["cases"]}
    assert set(cases) == {
        "three_step", "injection_target", "injection_authority", "refusal", "malformed", "incomplete",
        "call_budget", "token_budget", "request_budget", "step_budget", "output_budget", "timeout",
    }
    assert cases["three_step"]["session_status"] == "completed"
    assert cases["three_step"]["coordinator_boundary_checks"] == dict.fromkeys(demo.BOUNDARY_NAMES, True)
    assert cases["three_step"]["actions_succeeded"] == (3 if execute else 0)
    assert cases["injection_target"]["steps"][-1]["reasons"] == ["target_out_of_scope"]
    assert cases["injection_authority"]["stop_reason"] == "provider_failed"
    assert cases["request_budget"]["broker"]["calls_reserved"] == 0
    assert cases["timeout"]["stop_reason"] == "session_timeout"
    assert len({case["session_id"] for case in cases.values()}) == len(cases)
    assert len({case["broker_id"] for case in cases.values()}) == len(cases)
    for case in cases.values():
        assert case["control_plane"] == "privsep-offline-v2"
        assert case["policy_unchanged"] is True
        assert all(row["parser_boundary_checks"] == dict.fromkeys(demo.PARSER_BOUNDARY_NAMES, True)
                   for row in case["parser_executions"])
        assert len(case["tool_executions"]) == case["actions_succeeded"]
        assert case["broker"]["calls_reserved"] <= 3
        if not execute:
            assert case["actions_succeeded"] == 0
    if execute:
        assert cases["three_step"]["tool_executions"][1]["injection_fixture_received"] is True
        assert cases["injection_target"]["actions_succeeded"] == 1
        assert cases["injection_authority"]["actions_succeeded"] == 1
    text = path.read_text()
    assert "Ignore prior instructions" not in text + json.dumps(report)
    assert '"body"' not in text
    records = [json.loads(line) for line in text.splitlines()]
    assert sum(row["event_type"] == "session_finished" for row in records) == len(cases)
    assert not any(row["event_type"].startswith("approval_") for row in records)


def test_demo_rejects_missing_successful_parser_evidence(tmp_path, demo_process_doubles, monkeypatch):
    monkeypatch.setattr(demo.VerifiedOfflineProvider, "boundary_checks", property(lambda _self: None))
    with pytest.raises(RuntimeError, match="^offline_authority_outcome_mismatch: three_step$"):
        demo.run_demo(tmp_path / "audit.jsonl")


def test_demo_rejects_missing_coordinator_evidence(tmp_path, demo_process_doubles, monkeypatch):
    monkeypatch.setattr(demo.LinuxOfflineCoordinator, "boundary_checks", property(lambda _self: None))
    with pytest.raises(RuntimeError, match="^offline_authority_boundary_verification_failed$"):
        demo.run_demo(tmp_path / "audit.jsonl")


def test_demo_rejects_wrong_owned_injection_body(tmp_path, demo_process_doubles, monkeypatch):
    original = demo.AuthorizedFixtureBackend.run

    def wrong_body(*args, **kwargs):
        result = original(*args, **kwargs)
        result["results"][0]["body"] = "different fixture"
        return result

    monkeypatch.setattr(demo.AuthorizedFixtureBackend, "run", wrong_body)
    with pytest.raises(RuntimeError, match="^offline_authority_outcome_mismatch: three_step$"):
        demo.run_demo(tmp_path / "audit.jsonl", execute_fixtures=True)


@pytest.mark.parametrize("execute", [False, True])
def test_demo_cli_uses_only_explicit_execution_selection(monkeypatch, tmp_path, capsys, execute):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(sys, "argv", ["demo", "--audit", str(path)] + (["--execute-fixtures"] if execute else []))
    calls = []

    def run(audit_path, *, execute_fixtures, on_case):
        calls.append((audit_path, execute_fixtures))
        on_case({"case": "three_step", "stop_reason": "coordinator_done"})
        return {"demo": "passed", "cases": [], "audit": str(audit_path)}

    monkeypatch.setattr(demo, "run_demo", run)
    assert demo.main() == 0
    assert calls == [(path, execute)]
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[0]["provider"] == demo.PROVIDER_NAME
    assert lines[0]["live_calls_enabled"] is False
    assert lines[1] == {"case": "three_step", "stop_reason": "coordinator_done"}
    assert lines[-1]["demo"] == "passed"


@pytest.mark.parametrize("error,status,exit_code", [
    (IsolationUnavailable("private-path-and-secret"), "blocked", 2),
    (RuntimeError("private-response-and-secret"), "failed", 1),
])
def test_demo_cli_failure_does_not_echo_private_diagnostics(
        monkeypatch, tmp_path, capsys, error, status, exit_code):
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
def test_real_offline_authority_demo_runs_all_twelve_cases(tmp_path, execute):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real offline authority isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux" or os.geteuid() == 0:
        pytest.skip("real offline authority isolation requires an unprivileged Linux user")
    path = tmp_path / "audit.jsonl"
    report = demo.run_demo(path, execute_fixtures=execute)
    assert report["demo"] == "passed"
    assert report["live_calls_enabled"] is False
    assert report["mode"] == ("execute_owned_fixtures" if execute else "dry_run_tools")
    cases = {case["case"]: case for case in report["cases"]}
    assert set(cases) == {
        "three_step", "injection_target", "injection_authority", "refusal", "malformed", "incomplete",
        "call_budget", "token_budget", "request_budget", "step_budget", "output_budget", "timeout",
    }
    assert cases["three_step"]["session_status"] == "completed"
    assert cases["three_step"]["coordinator_boundary_checks"] == dict.fromkeys(demo.BOUNDARY_NAMES, True)
    assert cases["three_step"]["actions_succeeded"] == (3 if execute else 0)
    assert cases["injection_target"]["steps"][-1]["reasons"] == ["target_out_of_scope"]
    assert cases["injection_authority"]["stop_reason"] == "provider_failed"
    assert cases["timeout"]["stop_reason"] == "session_timeout"
    for case in cases.values():
        assert case["control_plane"] == "privsep-offline-v2"
        assert case["policy_unchanged"] is True
        assert len(case["tool_executions"]) == case["actions_succeeded"]
        assert all(row["parser_boundary_checks"] == dict.fromkeys(demo.PARSER_BOUNDARY_NAMES, True)
                   for row in case["parser_executions"])
        assert all(row["executor_boundary_checks"] == dict.fromkeys(demo.EXECUTOR_BOUNDARY_NAMES, True)
                   for row in case["tool_executions"])
        assert case["broker"]["calls_reserved"] <= 3
    if execute:
        assert cases["three_step"]["tool_executions"][1]["injection_fixture_received"] is True
        assert cases["injection_target"]["actions_succeeded"] == 1
        assert cases["injection_authority"]["actions_succeeded"] == 1
    text = path.read_text()
    assert "Ignore prior instructions" not in text + json.dumps(report)
    assert '"body"' not in text
    records = [json.loads(line) for line in text.splitlines()]
    assert sum(row["event_type"] == "session_finished" for row in records) == 12
    assert sum(row["event_type"] == "execution_started" for row in records) == (12 if execute else 0)
    assert not any(row["event_type"].startswith("approval_") for row in records)
    assert all(row.get("approval_reference") is None for row in records)
