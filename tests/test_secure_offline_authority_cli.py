"""Combined CLI wiring with process doubles; these tests do not prove isolation."""

import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import cli, coordinator_isolation, openai_provider
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES as PARSER_BOUNDARY_NAMES


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-policy.json"


def arguments(tmp_path, *extra):
    return ["--policy", str(POLICY), "--audit", str(tmp_path / "audit/events.jsonl"),
            "--control-plane-openai-offline", "three_step", "--openai-model", "offline-fixture-model", *extra]


@pytest.fixture
def process_doubles(monkeypatch):
    seen = {"requests": [], "responses": [], "observations": [], "controls": []}

    def run(self, init, exchange, *, control):
        initial = json.loads(init)
        assert set(initial) == {"schema_version", "session_id"}
        assert initial["schema_version"] == "2"
        seen["controls"].append(control)
        self._boundary_checks = dict.fromkeys(coordinator_isolation.BOUNDARY_NAMES, True)
        for step in range(1, 17):
            request = {**initial, "sequence": step, "operation": "plan"}
            for operation in ("plan", "propose"):
                seen["requests"].append(dict(request))
                response = json.loads(exchange(json.dumps(request).encode(), control=control))
                seen["responses"].append(response)
                assert set(response) == {"schema_version", "session_id", "sequence", "stop", "plan"}
                if response["stop"]:
                    return json.dumps({**initial, "status": "closed"}).encode()
                assert operation == "plan" or response["plan"] is None
                request.update(operation="propose", plan=response["plan"])
        pytest.fail("authority did not stop")

    class Parser:
        boundary_checks = None

        def plan(self, config, observation, exchange, *, control):
            seen["observations"].append(json.loads(observation))
            seen["controls"].append(control)
            self.boundary_checks = None
            result = decode_response(exchange(build_request(config, observation), control=control))
            self.boundary_checks = dict.fromkeys(PARSER_BOUNDARY_NAMES, True)
            return result

    monkeypatch.setattr(coordinator_isolation.LinuxOfflineCoordinator, "run", run)
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", Parser)
    return seen


def test_combined_cli_uses_one_bound_broker_authority_and_shared_deadline(tmp_path, capsys, monkeypatch, process_doubles):
    from recon_cockpit.secure_agent import session

    monkeypatch.setattr(session, "SessionRunner", lambda *_a, **_k: pytest.fail("combined mode must use authority"))
    assert cli.main(arguments(tmp_path)) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["control_plane"] == "privsep-offline-v2"
    assert summary["provider"] == "linux-isolated-coordinator-openai-offline"
    assert summary["mode"] == "dry_run"
    assert summary["live_calls_enabled"] is False
    assert summary["stop_reason"] == "coordinator_done"
    assert summary["steps_attempted"] == 3
    assert summary["output_reserved_bytes"] == 3072
    assert summary["actions_succeeded"] == 0
    assert summary["broker"]["calls_reserved"] == 3
    assert summary["broker"]["output_tokens_reserved"] == 3072
    assert summary["broker_error"] is None
    assert summary["coordinator_boundary_checks"] == dict.fromkeys(coordinator_isolation.BOUNDARY_NAMES, True)
    assert summary["parser_boundary_checks"] == dict.fromkeys(PARSER_BOUNDARY_NAMES, True)
    assert [row["operation"] for row in process_doubles["requests"]] == ["plan", "propose"] * 3
    assert [row["step"] for row in process_doubles["observations"]] == [1, 2, 3]
    assert all(control is process_doubles["controls"][0] for control in process_doubles["controls"])
    events = [json.loads(line) for line in (tmp_path / "audit/events.jsonl").read_text().splitlines()]
    bindings = [row for row in events if row["event_type"] == "offline_provider_session_bound"]
    assert len(bindings) == 1
    assert bindings[0]["broker_id"] == summary["broker_id"]
    assert bindings[0]["session_id"] == summary["session_id"]
    assert all(value not in captured.out + captured.err for value in (
        "rationale", "untrusted_result", "input_text", "OFFLINE API FIXTURE", "Ignore prior instructions"))


@pytest.mark.parametrize("option,value,reason,calls", [
    ("--broker-max-calls", "1", "broker_call_limit", 1),
    ("--broker-max-output-tokens", "1024", "broker_token_limit", 1),
    ("--broker-max-request-bytes", "1", "broker_request_limit", 0),
    ("--session-max-steps", "1", "step_limit", 1),
    ("--session-max-output-bytes", "1024", "output_limit", 2),
])
def test_combined_cli_reports_independent_budgets(tmp_path, capsys, process_doubles, option, value, reason, calls):
    assert cli.main(arguments(tmp_path, option, value)) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["stop_reason"] == reason
    assert summary["broker"]["calls_reserved"] == calls
    assert summary["actions_succeeded"] == 0


@pytest.mark.parametrize("scenario,reason,calls", [
    ("injection_target", "proposal_denied", 2), ("injection_authority", "provider_failed", 2),
    ("malformed", "provider_failed", 1), ("refusal", "provider_failed", 1),
    ("incomplete", "provider_failed", 1),
])
def test_combined_cli_closes_on_untrusted_response(tmp_path, capsys, process_doubles, scenario, reason, calls):
    args = arguments(tmp_path)
    args[args.index("three_step")] = scenario
    assert cli.main(args) == 2
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["stop_reason"] == reason
    assert summary["broker"]["calls_reserved"] == calls
    assert summary["actions_succeeded"] == 0
    assert process_doubles["responses"][-1]["stop"] is True
    assert "Synthetic refusal" not in captured.out + captured.err


def test_combined_cli_requires_fresh_operator_approval(tmp_path, capsys, process_doubles, monkeypatch):
    from recon_cockpit.secure_agent import authorized_execution, isolation

    selected = []
    original = authorized_execution.AuthorizedFixtureBackend.__init__

    def init(self, policy, session_id, limits, *, execute):
        selected.append((session_id, execute))
        original(self, policy, session_id, limits, execute=execute)

    monkeypatch.setattr(authorized_execution.AuthorizedFixtureBackend, "__init__", init)
    monkeypatch.setattr(isolation.LinuxFixtureBackend, "check_available",
                        lambda *_a, **_k: pytest.fail("approval must precede backend launch"))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli, "_human_approval", lambda *_a, **_k: pytest.fail("no manufactured human grant"))
    assert cli.main(arguments(tmp_path, "--execute", "--fixture")) == 2
    summary = json.loads(capsys.readouterr().out)
    assert selected == [(summary["session_id"], True)]
    assert summary["steps"][0]["reasons"] == ["noninteractive_approval_required"]
    assert summary["actions_succeeded"] == 0
    assert summary["broker"]["calls_reserved"] == 1


@pytest.mark.parametrize("extra", [
    [], ["--openai-model", "offline-model", "--routed"],
    ["--openai-model", "offline-model", "--openai-offline", "three_step"],
    ["--openai-model", "offline-model", "--control-plane-mock", "three_step"],
    ["--openai-model", "offline-model", "--session-mock", "three_step"],
    ["--openai-model", "offline-model", "--live"],
])
def test_invalid_combined_options_reject_before_policy_read(monkeypatch, extra):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("must not read policy"))
    with pytest.raises(SystemExit) as error:
        cli.main(["--control-plane-openai-offline", "three_step", *extra])
    assert error.value.code == 2


@pytest.mark.parametrize("option,value", [
    ("--openai-model", "https://example.invalid"), ("--openai-model", ""),
    ("--openai-max-output-tokens", "4097"), ("--broker-max-calls", "0"),
    ("--broker-max-output-tokens", "-1"), ("--broker-max-request-bytes", "262145"),
])
def test_invalid_combined_config_never_starts_coordinator(tmp_path, capsys, process_doubles, option, value):
    assert cli.main(arguments(tmp_path, option, value)) == 2
    assert process_doubles["requests"] == []
    assert process_doubles["observations"] == []
    assert json.loads(capsys.readouterr().out)["reasons"] == ["configuration_or_input_error"]


@pytest.mark.parametrize("component,reason", [("coordinator", "coordinator_failed"), ("parser", "provider_failed")])
def test_combined_boundary_failure_has_no_fallback_or_private_diagnostics(
        tmp_path, capsys, monkeypatch, process_doubles, component, reason):
    def fail(*_args, **_kwargs):
        raise IsolationUnavailable("PRIVATE CHILD DIAGNOSTIC")

    if component == "coordinator":
        monkeypatch.setattr(coordinator_isolation.LinuxOfflineCoordinator, "run", fail)
    else:
        monkeypatch.setattr(openai_provider.LinuxOpenAIPlanner, "plan", fail)
    assert cli.main(arguments(tmp_path)) == 2
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["stop_reason"] == reason
    assert summary["broker"]["calls_reserved"] == 0
    assert summary["actions_succeeded"] == 0
    assert summary["parser_boundary_checks"] is None
    assert "PRIVATE CHILD DIAGNOSTIC" not in captured.out + captured.err
