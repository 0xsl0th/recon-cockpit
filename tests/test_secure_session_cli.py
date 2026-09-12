"""Portable CLI/session wiring; these tests never execute a network probe."""

import json
import os
from pathlib import Path
import signal

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.session import SessionRunner
from recon_cockpit.secure_agent.session_provider import SessionMockProvider
from recon_cockpit.secure_agent.planner_isolation import LinuxIsolatedMockProvider
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-policy.json"


def arguments(tmp_path, *extra):
    return ["--policy", str(POLICY), "--audit", str(tmp_path / "audit" / "events.jsonl"),
            "--session-mock", "three_step", *extra]


def test_cli_dry_session_emits_safe_progress_and_one_summary(tmp_path, capsys):
    assert cli.main(arguments(tmp_path, "--dry-run")) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    progress = [json.loads(line) for line in captured.err.splitlines()]
    assert summary["session_status"] == "completed"
    assert summary["provider"] == "deterministic-session-mock-no-model"
    assert summary["steps_attempted"] == 3
    assert summary["actions_succeeded"] == 0
    assert summary["output_reserved_bytes"] == 3072
    assert len(progress) == 3
    assert all(row["session_id"] == summary["session_id"] for row in progress)
    assert all(row["execution_status"] == "dry_run" for row in progress)
    assert all(row["event_type"] == "session_step_finished" for row in progress)
    assert "untrusted_result" not in captured.out + captured.err
    assert "rationale" not in captured.out + captured.err


@pytest.mark.parametrize("option,value,reason", [
    ("--session-max-steps", "2", "step_limit"),
    ("--session-max-output-bytes", "1024", "output_limit"),
])
def test_cli_limits_report_stopped_with_exit_two(tmp_path, capsys, option, value, reason):
    assert cli.main(arguments(tmp_path, option, value)) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["session_status"] == "stopped"
    assert summary["stop_reason"] == reason


@pytest.mark.parametrize("option,value", [
    ("--session-max-steps", "0"), ("--session-max-steps", "17"),
    ("--session-max-seconds", "601"), ("--session-max-output-bytes", "-1"),
])
def test_cli_rejects_invalid_limits_without_planning(tmp_path, capsys, monkeypatch, option, value):
    monkeypatch.setattr(SessionMockProvider, "propose", lambda *_a, **_k: pytest.fail("must not plan"))
    assert cli.main(arguments(tmp_path, option, value)) == 2
    assert json.loads(capsys.readouterr().out)["reasons"] == ["configuration_or_input_error"]


@pytest.mark.parametrize("args", [
    ["--session-max-steps", "2"],
    ["--session-mock", "three_step", "--routed"],
    ["--session-mock", "three_step", "--mock"],
    ["--session-mock", "three_step", "--proposal", "unused"],
    ["--isolated-session-mock", "three_step", "--session-mock", "three_step"],
    ["--isolated-session-mock", "three_step", "--routed"],
])
def test_cli_rejects_unsupported_combinations_before_opening_files(monkeypatch, args):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("must not read policy"))
    with pytest.raises(SystemExit) as error:
        cli.main(args)
    assert error.value.code == 2


def test_session_execution_requires_actual_interactive_approval(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_human_approval", lambda *_a, **_k: pytest.fail("no scripted human grant"))
    assert cli.main(arguments(tmp_path, "--execute")) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["stop_reason"] == "action_blocked"
    assert summary["steps"][0]["reasons"] == ["noninteractive_approval_required"]
    assert summary["actions_succeeded"] == 0


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM])
def test_session_signals_cancel_and_restore_handlers(tmp_path, capsys, monkeypatch, number):
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def interrupted_proposal(self, observation, *, control):
        os.kill(os.getpid(), number)
        control.check()
        pytest.fail("must stop after signal")

    monkeypatch.setattr(SessionMockProvider, "propose", interrupted_proposal)
    assert cli.main(arguments(tmp_path)) == 2
    assert json.loads(capsys.readouterr().out)["stop_reason"] == "session_cancelled"
    assert all(signal.getsignal(sig) == handler for sig, handler in previous.items())
    rows = [json.loads(line) for line in (tmp_path / "audit/events.jsonl").read_text().splitlines()]
    assert rows[-1]["event_type"] == "session_finished"
    assert rows[-1]["stop_reason"] == "session_cancelled"


def test_session_audit_error_returns_exit_three_and_restores_handlers(tmp_path, capsys, monkeypatch):
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def failed(*_args, **_kwargs):
        raise AuditUnavailable("private details")

    monkeypatch.setattr(SessionRunner, "run", failed)
    assert cli.main(arguments(tmp_path)) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["reasons"] == ["audit_unavailable"]
    assert "private details" not in json.dumps(result)
    assert all(signal.getsignal(sig) == handler for sig, handler in previous.items())


def test_isolated_planner_selection_never_falls_back_on_setup_failure(tmp_path, capsys, monkeypatch):
    calls = []

    def unavailable(self, observation, *, control):
        calls.append(self.scenario)
        raise IsolationUnavailable("untrusted internals")

    monkeypatch.setattr(LinuxIsolatedMockProvider, "propose", unavailable)
    monkeypatch.setattr(SessionMockProvider, "propose", lambda *_a, **_k: pytest.fail("must not fall back"))
    args = arguments(tmp_path)
    args[args.index("--session-mock")] = "--isolated-session-mock"
    assert cli.main(args) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["provider"] == "linux-isolated-session-mock-no-model"
    assert summary["stop_reason"] == "session_component_failed"
    assert summary["actions_succeeded"] == 0
    assert calls == ["three_step"]
    assert "untrusted internals" not in json.dumps(summary)


def test_isolated_planner_retains_session_limits_and_normal_completion(tmp_path, capsys, monkeypatch):
    calls = []

    def done(self, observation, *, control):
        calls.append(json.loads(observation))
        control.check()
        return b'{"schema_version":"1","action":null,"done":true}'

    monkeypatch.setattr(LinuxIsolatedMockProvider, "propose", done)
    args = arguments(tmp_path, "--session-max-steps", "1")
    args[args.index("--session-mock")] = "--isolated-session-mock"
    assert cli.main(args) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["provider"] == "linux-isolated-session-mock-no-model"
    assert summary["session_status"] == "completed"
    assert summary["steps_attempted"] == 1
    assert calls == [{"step": 1, "untrusted_observation": None}]
