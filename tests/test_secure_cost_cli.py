"""Operator controls and a fully local, explicitly simulated cost lifecycle."""

import json

import pytest

from recon_cockpit.secure_agent.cost_cli import main
from scripts.secure_agent_cost_demo import run_demo, main as demo_main


def output(capsys):
    return json.loads(capsys.readouterr().out)


def test_cli_creates_controls_and_inspects_without_mutating(capsys, tmp_path):
    path = tmp_path / "ledger"
    base = ["--ledger", str(path)]
    assert main(base + ["create", "--account", "account", "--limit-microusd", "1000", "--period", "2026-09"]) == 0
    result = output(capsys)
    assert result["summary"]["mode"] == "provider"
    assert result["summary"]["period"] == "2026-09"
    assert main(base + ["add-scope", "--scope", "engagement", "--parent", "account", "--kind", "engagement"]) == 0
    output(capsys)
    assert main(base + ["set-limit", "--scope", "engagement", "--limit-microusd", "500", "--event-id", "limit-1"]) == 0
    assert output(capsys)["limit_microusd"] == 500
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert main(base + ["inspect", "--scope", "engagement"]) == 0
    assert output(capsys)["summary"]["effective_available_microusd"] == 500
    assert main(base + ["events", "--limit", "2"]) == 0
    assert len(output(capsys)["events"]) == 2
    assert main(base + ["attempts"]) == 0
    assert output(capsys) == {"attempts": []}
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}


def test_demo_default_is_inert_and_simulation_never_claims_a_real_bill(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert demo_main([]) == 0
    plan = output(capsys)
    assert plan["mode"] == "dry_run" and plan["actual_provider_calls"] == 0
    assert list(tmp_path.iterdir()) == []
    result = run_demo(tmp_path / "costs")
    assert result["status"] == "passed" and result["mode"] == "simulation"
    assert result["denied_by"] == "demo-engagement"
    summary = result["report"]["summary"]
    assert summary["mode"] == "simulation" and summary["unresolved_attempts"] == 1
    assert (summary["actual_microusd"], summary["reserved_microusd"], summary["available_microusd"]) == (25, 300, 175)
    assert not result["live_calls_enabled"]
    assert run_demo(tmp_path / "costs")["status"] == "failed"


def test_cli_reconciliation_requires_explicit_evidence_and_preserves_the_audit(capsys, tmp_path):
    path = tmp_path / "costs"
    assert run_demo(path)["status"] == "passed"
    base = ["--ledger", str(path)]
    assert main(base + ["cancel", "--attempt", "interrupted"]) == 2
    assert output(capsys) == {"status": "failed", "reason": "cost_reconciliation_required"}
    command = base + ["reconcile", "--attempt", "interrupted", "--actual-microusd", "42",
                      "--billing-reference", "new-demo-bill-line", "--event-id", "reconciled"]
    assert main(command) == 0
    assert output(capsys)["actual_microusd"] == 42
    assert main(command) == 0
    assert output(capsys)["actual_source"] == "billing_confirmed"
    assert main(base + ["inspect"]) == 0
    result = output(capsys)
    assert result["summary"]["actual_microusd"] == 67
    assert result["summary"]["reserved_microusd"] == 0
    assert result["summary"]["actual_complete"]


@pytest.mark.parametrize("command", [["inspect"], ["events"], ["attempts"],
    ["set-limit", "--scope", "account", "--limit-microusd", "1", "--event-id", "test"]])
def test_missing_ledger_fails_safely_without_creating_it(tmp_path, capsys, command):
    path = tmp_path / "missing"
    assert main(["--ledger", str(path), *command]) == 2
    assert output(capsys) == {"status": "failed", "reason": "cost_ledger_unavailable"}
    assert not path.exists()
