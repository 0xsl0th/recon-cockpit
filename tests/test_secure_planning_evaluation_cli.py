"""CLI selection, early refusal and immutable per-trial accounting snapshots."""

import json
from pathlib import Path
import signal
import sys
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent import planning_evaluation_runtime as runtime
from recon_cockpit.secure_agent.assessment_planning_contract import INPUT_LIMIT, OUTPUT_LIMIT, PRICE
from recon_cockpit.secure_agent.cost_contract import TokenUsage
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.models import parse_policy


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-evaluation-policy.json"


@pytest.mark.parametrize("arguments", [
    ["--evaluate-owned-planning"],
    ["--evaluate-owned-planning", "--evaluate-owned-lab", "--evaluation-dir", "unused"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--fixture"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--owned-lab"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--routed"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--isolated-audit"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--session-max-seconds", "120"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--assessment-planning-owned-tls", "success"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--planning-ledger", "unused-cost"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--planning-budget-microusd", "1"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--openai-model", "real-model"],
    ["--evaluate-owned-planning", "--evaluation-dir", "unused", "--audit", "elsewhere.jsonl"],
    ["--inspect-planning-evaluation", "unused", "--execute"],
    ["--inspect-planning-evaluation", "unused", "--dry-run"],
    ["--inspect-planning-evaluation", "unused", "--evaluation-repeats", "1"],
    ["--inspect-planning-evaluation", "unused", "--fixture"],
    ["--inspect-planning-evaluation", "unused", "--inspect-evaluation", "other"],
])
def test_profile_overrides_refuse_before_policy_or_filesystem_work(monkeypatch, arguments):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("policy accessed before refusal"))
    with pytest.raises(SystemExit) as caught:
        cli.main(arguments)
    assert caught.value.code == 2


@pytest.mark.parametrize("execute", [False, True])
def test_cli_selects_planning_runner_with_explicit_limits_and_restores_signals(tmp_path, monkeypatch, capsys, execute):
    calls = []
    handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    class Runner:
        def __init__(self, directory, policy, limits):
            calls.append((directory, policy, limits))

        def cancel(self):
            pytest.fail("no signal sent")

        def run(self, *, execute, on_trial):
            calls.append(execute)
            on_trial({"trial_id": "trial-001-a", "grade": {"verdict": "passed", "issues": []}})
            return {"status": "passed" if execute else "dry_run", "profile": "owned-planning-evaluation-v1"}

    monkeypatch.setitem(sys.modules, "recon_cockpit.secure_agent.planning_evaluation",
                        SimpleNamespace(PlanningEvaluationRunner=Runner))
    options = ["--evaluate-owned-planning", "--evaluation-dir", str(tmp_path / "batch"),
               "--policy", str(POLICY), "--evaluation-repeats", "1", "--evaluation-max-seconds", "90"]
    assert cli.main(options + (["--execute"] if execute else [])) == 0
    assert calls[0][0] == tmp_path / "batch"
    assert calls[0][1].require_approval is False
    assert calls[0][2].repeats == 1 and calls[0][2].max_runtime_seconds == 90
    assert calls[1] is execute
    assert all(signal.getsignal(number) is previous for number, previous in handlers.items())
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == ("passed" if execute else "dry_run")
    assert json.loads(output.err)["event_type"] == "evaluation_trial_graded"


@pytest.mark.parametrize("status,issues,exit_code", [("passed", [], 0), ("dry_run", [], 0),
                                                   ("failed", [], 2), ("passed", ["corrupt"], 2)])
def test_inspection_uses_only_readonly_profile_without_policy_or_runner(monkeypatch, capsys, status, issues, exit_code):
    calls = []
    def inspect(path):
        calls.append(path)
        return {"status": status, "integrity_issues": issues}
    monkeypatch.setitem(sys.modules, "recon_cockpit.secure_agent.planning_evaluation",
        SimpleNamespace(inspect_planning_evaluation=inspect,
                        PlanningEvaluationRunner=lambda *_: pytest.fail("inspection executed")))
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("inspection read policy"))
    assert cli.main(["--inspect-planning-evaluation", "saved-batch"]) == exit_code
    assert calls == [Path("saved-batch")]
    assert json.loads(capsys.readouterr().out) == {"status": status, "integrity_issues": issues}


def test_runtime_never_rewrites_approval_required_policy(tmp_path, monkeypatch):
    policy = json.loads(POLICY.read_bytes())
    policy["require_approval"] = True
    runner = SimpleNamespace(policy=parse_policy(policy))
    monkeypatch.setattr(runtime, "LinuxAuditSink", lambda *_a, **_k: pytest.fail("approval-required batch started"))
    with pytest.raises(ValueError, match="evaluation_requires_explicit_unattended_owned_policy"):
        runtime.run_trial(runner, tmp_path / "trial", "a", ledger=None,
                          account_scope_id="account", engagement_scope_id="engagement")
    assert runner.policy.require_approval is True and not (tmp_path / "trial").exists()


def test_trial_cost_snapshot_is_unchanged_by_later_sibling_spending(tmp_path):
    with CostLedger.create(tmp_path / "cost", account_id="account", limit_microusd=100_000,
                           mode="simulation") as ledger:
        ledger.add_scope("engagement", parent_id="account", kind="engagement")
        for number in (1, 2):
            ledger.add_scope("session-" + str(number), parent_id="engagement", kind="session")
            ledger.add_scope("action-" + str(number), parent_id="session-" + str(number), kind="action", limit_microusd=100_000)
        ledger.estimate("attempt-1", scope_id="action-1", request_digest="a" * 64, price=PRICE,
                        usage=TokenUsage(512, 128), input_token_limit=INPUT_LIMIT, output_token_limit=OUTPUT_LIMIT)
        ledger.reserve("attempt-1")
        ledger.begin_dispatch("attempt-1", request_digest="a" * 64)
        ledger.settle_usage("attempt-1", TokenUsage(512, 128), receipt_reference="fixture-one", event_id="usage-one")
        before = runtime._cost_snapshot(ledger, "action-1")
        effective_before = ledger.snapshot("action-1")["effective_available_microusd"]
        ledger.estimate("attempt-2", scope_id="action-2", request_digest="b" * 64, price=PRICE,
                        usage=TokenUsage(512, 128), input_token_limit=INPUT_LIMIT, output_token_limit=OUTPUT_LIMIT)
        ledger.reserve("attempt-2")
        assert ledger.snapshot("action-1")["effective_available_microusd"] < effective_before
        assert runtime._cost_snapshot(ledger, "action-1") == before
        assert len(before["attempts"]) == 1 and before["attempts"][0]["attempt_id"] == "attempt-1"
        assert before["summary"]["actual_microusd"] == 778
