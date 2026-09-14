"""CLI selects the authority path; doubles here do not establish isolation."""

import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import cli, coordinator_isolation
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.session_planner import proposal


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-policy.json"


def arguments(tmp_path, *extra):
    return ["--policy", str(POLICY), "--audit", str(tmp_path / "audit/events.jsonl"),
            "--control-plane-mock", "three_step", *extra]


@pytest.fixture
def coordinator_double(monkeypatch):
    calls = []

    def run(self, init, exchange, *, control):
        session_id = json.loads(init)["session_id"]
        previous = None
        self._boundary_checks = dict.fromkeys(coordinator_isolation.BOUNDARY_NAMES, True)
        for step in range(1, 18):
            request = {"schema_version": "1", "session_id": session_id, "sequence": step,
                       "plan": proposal(self.scenario, {"step": step, "untrusted_observation": previous})}
            calls.append(request)
            response = json.loads(exchange(json.dumps(request).encode(), control=control))
            if response["stop"]:
                return json.dumps({"schema_version": "1", "session_id": session_id,
                                   "status": "closed"}).encode()
            previous = response["observation"]
        pytest.fail("authority did not stop")

    monkeypatch.setattr(coordinator_isolation.LinuxCoordinator, "run", run)
    return calls


def test_cli_selects_authority_and_keeps_untrusted_data_out_of_output(tmp_path, capsys, coordinator_double):
    assert cli.main(arguments(tmp_path)) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["control_plane"] == "privsep-v1"
    assert summary["provider"] == "linux-isolated-coordinator-mock"
    assert summary["mode"] == "dry_run"
    assert summary["live_calls_enabled"] is False
    assert summary["steps_attempted"] == len(coordinator_double) == 3
    assert summary["output_reserved_bytes"] == 3072
    assert summary["actions_succeeded"] == 0
    assert summary["stop_reason"] == "coordinator_done"
    assert all(value not in captured.out + captured.err for value in (
        "rationale", "untrusted_result", "DETERMINISTIC SESSION MOCK"))


def test_cli_keeps_operator_approval_outside_coordinator(tmp_path, capsys, coordinator_double, monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli, "_human_approval", lambda *_a, **_k: pytest.fail("must not manufacture approval"))
    assert cli.main(arguments(tmp_path, "--execute", "--fixture")) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["steps"][0]["reasons"] == ["noninteractive_approval_required"]
    assert summary["actions_succeeded"] == 0
    assert len(coordinator_double) == 1


def test_cli_host_limits_stop_coordinator(tmp_path, capsys, coordinator_double):
    assert cli.main(arguments(tmp_path, "--session-max-output-bytes", "1024")) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["stop_reason"] == "output_limit"
    assert summary["output_reserved_bytes"] == 1024
    assert len(coordinator_double) == 2


@pytest.mark.parametrize("extra", [
    ["--routed"], ["--session-mock", "three_step"], ["--openai-offline", "three_step"],
    ["--openai-model", "offline-model"], ["--broker-max-calls", "1"], ["--live"],
])
def test_invalid_combinations_fail_before_reading_policy(monkeypatch, extra):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("must not read policy"))
    with pytest.raises(SystemExit) as error:
        cli.main(["--control-plane-mock", "three_step", *extra])
    assert error.value.code == 2


def test_coordinator_failure_never_falls_back(tmp_path, capsys, monkeypatch):
    def fail(*_a, **_k):
        raise IsolationUnavailable("PRIVATE CHILD DIAGNOSTIC")

    monkeypatch.setattr(coordinator_isolation.LinuxCoordinator, "run", fail)
    assert cli.main(arguments(tmp_path)) == 2
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["stop_reason"] == "coordinator_failed"
    assert summary["actions_succeeded"] == 0
    assert summary["boundary_checks"] is None
    assert "PRIVATE CHILD DIAGNOSTIC" not in captured.out + captured.err
