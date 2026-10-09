"""CLI gates, scope selection and offline dry-run/replay behavior."""

import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import cli
from test_secure_http_headers_cli import GATES, portable_services


def arguments(tmp_path):
    return ["--configurable-assessment", "examples/secure-agent-configurable-scope.json",
            "--policy", "examples/secure-agent-configurable-policy.json",
            "--assessment-dir", str(tmp_path / "evidence"), "--audit", str(tmp_path / "audit.jsonl")]


@pytest.mark.parametrize("missing", GATES)
def test_all_gates_required_before_read_or_write(tmp_path, monkeypatch, missing):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("read before gate refusal"))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path), *(gate for gate in GATES if gate != missing)])
    assert error.value.code == 2 and not list(tmp_path.iterdir())


@pytest.mark.parametrize("extra", [
    ["--session-max-steps", "5"], ["--session-max-seconds", "61"],
    ["--session-max-output-bytes", "26625"], ["--session-max-steps", "0"],
    ["--openai-model", "unused"], ["--assessment-planning-offline", "success"],
    ["--routed"], ["--fixture"], ["--list-tools"],
])
def test_cannot_expand_limits_or_substitute_provider(tmp_path, monkeypatch, extra):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("read before refusal"))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path), *GATES, *extra])
    assert error.value.code == 2 and not list(tmp_path.iterdir())


@pytest.mark.parametrize("suffix", ("", "-alternate"))
def test_policies_require_personal_approval_for_all_scoped_actions(suffix):
    from recon_cockpit.secure_agent.configurable_contract import action
    from recon_cockpit.secure_agent.models import parse_action, parse_policy
    scope = json.loads(Path("examples/secure-agent-configurable-scope" + suffix + ".json").read_text())
    policy = parse_policy(Path("examples/secure-agent-configurable-policy" + suffix + ".json").read_bytes())
    for step in range(1, 5):
        assert policy.evaluate(parse_action(action(scope, step))).decision == "approval_required"


def test_dry_run_never_inspects_native_runtime_or_claims_work(tmp_path, monkeypatch, capsys, portable_services):
    from recon_cockpit.secure_agent import configurable_runtime, configurable_parser_runtime
    monkeypatch.setattr(configurable_runtime, "inspect_configurable_runtime", lambda *_: pytest.fail("dry runtime inspection"))
    monkeypatch.setattr(configurable_parser_runtime, "parse_isolated_tool_output", lambda *a, **k: pytest.fail("dry parser execution"))
    assert cli.main([*arguments(tmp_path), *GATES, "--dry-run"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["actions_succeeded"] == 0 and summary["assessment_outcome"] == "dry_run"
    assert summary["metrics"]["legitimate_task_completed"] is False
    assert summary["metrics"]["actual_provider_calls"] == summary["metrics"]["actual_cost_microusd"] == 0
    assert not any(row["event_type"] == "execution_started" for row in portable_services)
    directory = tmp_path / "evidence"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in directory.iterdir()}
    assert cli.main(["--inspect-assessment", str(directory)]) == 0
    assert json.loads(capsys.readouterr().out)["integrity_issues"] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in directory.iterdir()}


@pytest.mark.parametrize("outcome,exit_code", [("completed", 0), ("dry_run", 0), ("incomplete", 2)])
def test_terminal_adapter_uses_shared_service_and_restores_signal_handlers(
        tmp_path, monkeypatch, capsys, outcome, exit_code):
    import signal
    from recon_cockpit.secure_agent import configurable_cli

    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    observed = []

    class Service:
        def __init__(self, request):
            assert request.execute is False
            assert request.limits.max_steps == 4
            assert request.assessment_dir == tmp_path / "evidence"
            self.cancelled = False

        def cancel(self):
            self.cancelled = True

        def snapshot(self):
            return {"session_id": "test-terminal-session"}

        def run(self, *, interactive_terminal, on_step):
            assert type(interactive_terminal) is bool
            for number in previous:
                assert signal.getsignal(number) is not previous[number]
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            assert self.cancelled
            on_step({"step": 1, "execution_status": "dry_run"})
            observed.append(True)
            return {"assessment_outcome": outcome, "live_calls_enabled": False}

    monkeypatch.setattr(configurable_cli, "ConfigurableAssessmentService", Service)
    monkeypatch.setattr(cli, "parse_policy", lambda *_: pytest.fail("generic CLI policy path"))
    monkeypatch.setattr(cli, "AuditSink", lambda *_: pytest.fail("generic CLI audit path"))
    assert cli.main([*arguments(tmp_path), *GATES, "--dry-run"]) == exit_code
    captured = capsys.readouterr()
    assert json.loads(captured.out)["assessment_outcome"] == outcome
    assert json.loads(captured.err)["session_id"] == "test-terminal-session"
    assert observed == [True]
    assert all(signal.getsignal(number) is handler for number, handler in previous.items())


@pytest.mark.parametrize("reason", ["session_cancelled", "session_timeout"])
def test_setup_stop_is_structured_and_terminal_handlers_are_restored(tmp_path, monkeypatch, capsys, reason):
    import signal
    from recon_cockpit.secure_agent import configurable_cli
    from recon_cockpit.secure_agent.execution import ExecutionStopped

    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    class Service:
        def __init__(self, request):
            pass

        def cancel(self):
            pass

        def run(self, **kwargs):
            raise ExecutionStopped(reason)

    monkeypatch.setattr(configurable_cli, "ConfigurableAssessmentService", Service)
    assert cli.main([*arguments(tmp_path), *GATES, "--execute"]) == 2
    assert json.loads(capsys.readouterr().out)["reasons"] == [reason]
    assert not list(tmp_path.iterdir())
    assert all(signal.getsignal(number) is handler for number, handler in previous.items())


def test_invalid_scope_is_rejected_before_opening_audit(tmp_path, capsys):
    scope = tmp_path / "scope.json"
    scope.write_text('{"unrecognized": true}')
    args = arguments(tmp_path)
    args[1] = str(scope)
    assert cli.main([*args, *GATES, "--dry-run"]) == 2
    assert json.loads(capsys.readouterr().out)["execution_status"] == "blocked"
    assert list(tmp_path.iterdir()) == [scope]
