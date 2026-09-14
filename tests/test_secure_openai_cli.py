"""Offline OpenAI CLI routing and configuration; no real model or network."""

import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import cli, openai_provider
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-policy.json"


def arguments(tmp_path, *extra):
    return ["--policy", str(POLICY), "--audit", str(tmp_path / "audit/events.jsonl"),
            "--openai-offline", "three_step", "--openai-model", "offline-fixture-model", *extra]


@pytest.fixture
def parser_double(monkeypatch):
    calls = []

    class Parser:
        boundary_checks = None

        def plan(self, config, observation, exchange, *, control):
            calls.append(json.loads(observation))
            return decode_response(exchange(build_request(config, observation), control=control))

    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", Parser)
    return calls


def test_offline_cli_uses_broker_and_keeps_safe_summary(tmp_path, capsys, parser_double):
    assert cli.main(arguments(tmp_path)) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["provider"] == "linux-isolated-openai-offline"
    assert summary["live_calls_enabled"] is False
    assert summary["broker"]["calls_reserved"] == 3
    assert summary["broker"]["output_tokens_reserved"] == 3072
    assert summary["actions_succeeded"] == 0
    assert summary["stop_reason"] == "planner_done"
    assert len(parser_double) == 3
    events = [json.loads(line) for line in (tmp_path / "audit/events.jsonl").read_text().splitlines()]
    binding = next(row for row in events if row["event_type"] == "offline_provider_session_bound")
    assert binding["broker_id"] == summary["broker_id"]
    assert binding["session_id"] == summary["session_id"]
    assert all(value not in captured.out + captured.err for value in ("rationale", "untrusted_result", "input_text"))


@pytest.mark.parametrize("option,value,reason", [
    ("--broker-max-calls", "1", "broker_call_limit"),
    ("--broker-max-output-tokens", "1024", "broker_token_limit"),
    ("--broker-max-request-bytes", "1", "broker_request_limit"),
])
def test_offline_cli_reports_broker_limits(tmp_path, capsys, parser_double, option, value, reason):
    assert cli.main(arguments(tmp_path, option, value)) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["stop_reason"] == reason
    assert summary["actions_succeeded"] == 0


@pytest.mark.parametrize("extra", [
    ["--openai-offline", "three_step"],
    ["--openai-offline", "three_step", "--openai-model", "x", "--routed"],
    ["--openai-offline", "three_step", "--openai-model", "x", "--session-mock", "three_step"],
    ["--openai-model", "x"], ["--broker-max-calls", "1"],
    ["--openai-max-output-tokens", "32"],
    ["--openai-offline", "three_step", "--openai-model", "x", "--live"],
])
def test_offline_options_reject_invalid_combinations_before_reading_files(monkeypatch, extra):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("must not read policy"))
    with pytest.raises(SystemExit) as error:
        cli.main(extra)
    assert error.value.code == 2


@pytest.mark.parametrize("option,value", [
    ("--openai-model", "https://example.invalid"), ("--openai-model", ""),
    ("--openai-max-output-tokens", "0"), ("--openai-max-output-tokens", "4097"),
    ("--broker-max-calls", "0"), ("--broker-max-calls", "17"),
    ("--broker-max-output-tokens", "-1"), ("--broker-max-request-bytes", "262145"),
])
def test_offline_invalid_configuration_never_plans(tmp_path, capsys, parser_double, option, value):
    assert cli.main(arguments(tmp_path, option, value)) == 2
    assert parser_double == []
    assert json.loads(capsys.readouterr().out)["reasons"] == ["configuration_or_input_error"]


def test_offline_cli_preserves_required_approval(tmp_path, capsys, parser_double, monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli, "_human_approval", lambda *_a, **_kw: pytest.fail("no manufactured grant"))
    assert cli.main(arguments(tmp_path, "--execute")) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["stop_reason"] == "action_blocked"
    assert summary["steps"][0]["reasons"] == ["noninteractive_approval_required"]
    assert summary["broker"]["calls_reserved"] == 1


def test_offline_parser_failure_cannot_select_portable_fallback(tmp_path, capsys, monkeypatch):
    class FailedParser:
        boundary_checks = None

        def plan(self, *args, **kwargs):
            raise IsolationUnavailable("PRIVATE PARSER DETAILS")

    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", FailedParser)
    assert cli.main(arguments(tmp_path)) == 2
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["stop_reason"] == "session_component_failed"
    assert summary["broker"]["calls_reserved"] == 0
    assert "PRIVATE PARSER DETAILS" not in captured.out + captured.err
