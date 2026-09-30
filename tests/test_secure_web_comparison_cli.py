"""CLI selection, early refusal and immutable per-trial accounting snapshots."""

import json
from pathlib import Path
import signal
import sys
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent import web_comparison_runtime as runtime
from recon_cockpit.secure_agent.models import parse_policy


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-web-comparison-policy.json"


@pytest.mark.parametrize("arguments", [
    ["--evaluate-web-comparison"],
    ["--evaluate-web-comparison", "--evaluate-owned-lab", "--evaluation-dir", "unused"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--fixture"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--owned-lab"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--routed"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--isolated-audit"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--session-max-seconds", "120"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--assessment-planning-owned-tls", "success"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--planning-ledger", "unused-cost"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--planning-budget-microusd", "1"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--openai-model", "real-model"],
    ["--evaluate-web-comparison", "--evaluation-dir", "unused", "--audit", "elsewhere.jsonl"],
    ["--inspect-web-comparison", "unused", "--execute"],
    ["--inspect-web-comparison", "unused", "--dry-run"],
    ["--inspect-web-comparison", "unused", "--evaluation-repeats", "1"],
    ["--inspect-web-comparison", "unused", "--fixture"],
    ["--inspect-web-comparison", "unused", "--inspect-evaluation", "other"],
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
            return {"status": "passed" if execute else "dry_run", "profile": "owned-web-adversarial-comparison-v1"}

    monkeypatch.setitem(sys.modules, "recon_cockpit.secure_agent.web_comparison",
                        SimpleNamespace(WebComparisonRunner=Runner))
    options = ["--evaluate-web-comparison", "--evaluation-dir", str(tmp_path / "batch"),
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
    monkeypatch.setitem(sys.modules, "recon_cockpit.secure_agent.web_comparison",
        SimpleNamespace(inspect_comparison=inspect,
                        WebComparisonRunner=lambda *_: pytest.fail("inspection executed")))
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("inspection read policy"))
    assert cli.main(["--inspect-web-comparison", "saved-batch"]) == exit_code
    assert calls == [Path("saved-batch")]
    assert json.loads(capsys.readouterr().out) == {"status": status, "integrity_issues": issues}


def test_actual_dry_run_and_inspection_never_start_the_runtime(tmp_path, monkeypatch, capsys):
    from recon_cockpit.secure_agent.web_comparison import WebComparisonRunner
    from test_secure_web_comparison import snapshot
    monkeypatch.setattr(WebComparisonRunner, '_run_trial', lambda *_: pytest.fail('dry run started a trial'))
    directory = tmp_path / 'batch'
    assert cli.main(['--evaluate-web-comparison', '--evaluation-dir', str(directory),
                     '--policy', str(POLICY), '--dry-run']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'dry_run' and report['planned_trials'] == 18 and report['started_trials'] == 0
    before = snapshot(directory)
    assert cli.main(['--inspect-web-comparison', str(directory)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == snapshot(directory)


def test_runtime_requires_explicit_unattended_policy_without_rewriting_it(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.web_comparison import WebComparisonRunner
    value = json.loads(POLICY.read_bytes()); value['require_approval'] = True
    policy = parse_policy(value)
    monkeypatch.setattr(WebComparisonRunner, '_run_trial', lambda *_: pytest.fail('approval policy bypassed'))
    with pytest.raises(ValueError, match='explicit_unattended_owned_policy'):
        WebComparisonRunner(tmp_path / 'batch', policy)
    assert policy.require_approval is True and not (tmp_path / 'batch').exists()
