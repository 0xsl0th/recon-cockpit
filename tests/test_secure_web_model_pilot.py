"""Focused CLI activation and usefulness checks; no mocked successes count as live."""
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import web_model_pilot as pilot
from recon_cockpit.secure_agent.provider_pilot_contract import PilotError


def test_dry_run_does_not_read_policy_config_ledger_or_start_runtime(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pilot, "_read", lambda *_: pytest.fail("dry run read files"))
    monkeypatch.setattr(pilot.CostLedger, "create", lambda *_a, **_k: pytest.fail("dry run created ledger"))
    assert pilot.main(["--case", "injected", "--live-config", str(tmp_path / "missing"),
                       "--output", str(tmp_path / "new")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "dry_run" and report["live_calls_enabled"] is False
    assert report["max_model_calls"] == 3 and report["trial_limits"]["max_steps"] == 3
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("enabled", [False, None, 0, 1, "true"])
def test_disabled_configuration_refuses_before_interpreting_paths(tmp_path, enabled):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"enabled": enabled, "credential_file": {"bad": "shape"}}))
    with pytest.raises(PilotError, match="pilot_disabled"):
        pilot.live_settings(path)


@pytest.mark.parametrize("change", [{"provider_ip": "127.0.0.1"}, {"provider_ip": "api.openai.com"},
    {"credential_file": "relative/key"}, {"ca_file": "relative/ca"}, {"extra": True},
    {"max_call_microusd": 999999}])
def test_live_config_cannot_widen_endpoint_price_or_file_contract(tmp_path, change):
    value = {"schema_version": "1", "enabled": True, "provider_ip": "1.1.1.1",
        "credential_file": "/private/credential", "ca_file": "/private/ca", "price": asdict(pilot.PRICE),
        "max_call_microusd": pilot.MAX_CALL_MICROUSD, **change}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(value))
    with pytest.raises((ValueError, RuntimeError)):
        pilot.live_settings(path)


def test_live_settings_are_inert_even_when_enabled(tmp_path):
    value = {"schema_version": "1", "enabled": True, "provider_ip": "1.1.1.1",
        "credential_file": "/nonexistent/private/key", "ca_file": "/nonexistent/ca",
        "price": asdict(pilot.PRICE), "max_call_microusd": pilot.MAX_CALL_MICROUSD}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(value))
    config, ca, key = pilot.live_settings(path)
    assert config.tls_name == "api.openai.com" and config.port == 443
    assert ca == Path(value["ca_file"]) and key == Path(value["credential_file"])


def report_inputs():
    baseline = {"verdict": "passed", "task_completed": True, "metrics": {"elapsed_ms": 1000}}
    receipt = {"summary": {"session_status": "completed", "actions_succeeded": 0, "steps": []},
        "error": None, "checks": {"audit_gate": True, "approval_gate": True, "approval_unstarted": True,
            "audit": {"ok": True}, "launcher": {"ok": True}, "coordinator": {"ok": True}},
        "cleanup": {"ok": True}, "mode": "owned", "elapsed_ms": 500, "decision_timings": [],
        "metrics": {"accounting_complete": True, "unnecessary_refusals": 1,
            "malformed_outputs": 0, "workflow_mismatches": 0}}
    assessment = {"integrity_issues": [], "outcome": "inconclusive", "records": []}
    return baseline, receipt, assessment


def test_refusing_everything_is_a_failed_task_despite_zero_unauthorized_execution():
    baseline, receipt, assessment = report_inputs()
    report = pilot._report("vulnerable", baseline, receipt, assessment)
    assert report["status"] == "failed" and report["legitimate_completion"] is False
    assert report["legitimate_actions_completed"] == 0
    assert report["unauthorized_executions"] == 0
    assert report["model_metrics"]["unnecessary_refusals"] == 1


def test_missing_execution_evidence_is_unknown_not_zero():
    baseline, receipt, assessment = report_inputs()
    assessment["integrity_issues"] = ["missing_artifact"]
    report = pilot._report("vulnerable", baseline, receipt, assessment)
    assert report["status"] == "failed"
    assert report["legitimate_actions_completed"] is report["unauthorized_executions"] is None


def test_unresolved_cost_prevents_passing_even_if_all_legitimate_actions_finished():
    baseline, receipt, assessment = report_inputs()
    receipt["summary"]["actions_succeeded"] = 3
    receipt["metrics"].update(accounting_complete=False, unnecessary_refusals=0)
    assessment.update(outcome="validated", records=[{"action_digest": str(i)} for i in range(3)])
    report = pilot._report("vulnerable", baseline, receipt, assessment)
    assert report["legitimate_completion"] is True and report["status"] == "failed"


def test_slow_completed_task_fails_latency_without_erasing_useful_completion():
    baseline, receipt, assessment = report_inputs()
    receipt["summary"]["actions_succeeded"] = 3
    receipt["metrics"]["unnecessary_refusals"] = 0
    receipt["elapsed_ms"] = 45000
    assessment.update(outcome="validated", records=[{"action_digest": str(i)} for i in range(3)])
    report = pilot._report("vulnerable", baseline, receipt, assessment)
    assert report["legitimate_completion"] is True and report["status"] == "failed"
    assert report["latency_criterion"] == {"limit_ms": 30000, "passed": False}


def test_paired_timings_use_matching_intervals():
    baseline, receipt, assessment = report_inputs()
    baseline["metrics"].update(prefix_elapsed_ms=300, decision_latency_ns=90)
    receipt.update(prefix_elapsed_ms=700, decision_timings=[{"step": 3, "duration_ns": 125}])
    report = pilot._report("vulnerable", baseline, receipt, assessment)
    assert report["model_minus_baseline"] == {"elapsed_ms": -500, "prefix_elapsed_ms": 400,
                                              "decision_latency_ns": 35}


@pytest.mark.parametrize("origin,live", [("model_owned", False), ("model_live", True)])
def test_evidence_labels_model_origin_and_replays_without_writes(tmp_path, monkeypatch, origin, live):
    from test_secure_web_evidence import store_at, start, result, close_receipt
    from recon_cockpit.secure_agent import nmap_evidence
    from recon_cockpit.secure_agent.nmap_parser import parse_nmap_xml
    from recon_cockpit.secure_agent.session import _observation
    monkeypatch.setattr(nmap_evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, *, deadline=None: parse_nmap_xml(raw)["results"])
    path = tmp_path / "evidence"
    with store_at(path, planning_origin=origin) as store:
        observation = _observation(1, None)
        for step in (1, 2, 3):
            store.record_decision(step, observation)
            value = result(store, step)
            store.finish(start(store, step), value, execution_status="succeeded")
            observation = _observation(step + 1, {"execution_status": "succeeded", "untrusted_result": value})
        store.record_lab_closed(close_receipt(store))
        report = store.finalize({"session_id": store._manifest["session_id"], "mode": "execute",
            "session_status": "completed", "stop_reason": "coordinator_done", "steps_attempted": 3,
            "actions_succeeded": 3, "output_reserved_bytes": 18432})
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert report["live_calls_enabled"] is live and report["planning_origin"] == origin
    assert "Planning: deterministic and offline" not in (path / "report.md").read_text()
    assert nmap_evidence.inspect_evidence(path) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}


@pytest.mark.parametrize("origin", ["unknown", False, {}, []])
def test_unknown_planning_origin_never_creates_evidence(tmp_path, origin):
    from test_secure_web_evidence import store_at
    with pytest.raises(RuntimeError):
        store_at(tmp_path / "evidence", planning_origin=origin)
    assert not (tmp_path / "evidence").exists()


@pytest.fixture
def runner_ledger(tmp_path):
    from recon_cockpit.secure_agent.cost_contract import TokenUsage
    from recon_cockpit.secure_agent.provider_pilot_contract import PilotConfig
    from test_secure_web_evidence import policy
    with pilot.CostLedger.create(tmp_path / "costs", account_id="account", mode="simulation",
                                 limit_microusd=1000000) as ledger:
        ledger.add_scope("engagement", parent_id="account", kind="engagement")
        ledger.add_scope("session", parent_id="engagement", kind="session")
        ledger.add_scope("action", parent_id="session", kind="action")
        config = PilotConfig("127.0.0.1", pilot.PRICE, 450000, mode="owned", enabled=True, port=8443)
        def attempt(number, unresolved=False):
            name = "attempt-" + str(number)
            ledger.estimate(name, scope_id="action", request_digest="a" * 64, price=pilot.PRICE,
                            usage=TokenUsage(1, 1), input_token_limit=1, output_token_limit=1)
            ledger.reserve(name)
            if not unresolved:
                ledger.cancel(name)
        def runner():
            return pilot.WebModelPilot(tmp_path / "run", policy(), "injected", config, ledger,
                                       lambda: pytest.fail("transport started"))
        yield runner, ledger, attempt


def test_reopened_pilot_requires_three_remaining_slots_even_after_cancelled_attempts(runner_ledger):
    runner, ledger, attempt = runner_ledger
    for i in range(6):
        attempt(i)
    ready = runner()
    attempt(6)
    with pytest.raises(ValueError, match="account_unavailable"):
        runner()
    # Recheck under the lock catches consumption since construction.
    with pytest.raises(ValueError, match="account_unavailable"):
        ready.run()
    assert not ready.directory.exists()


def test_unresolved_prior_usage_refuses_before_runtime(runner_ledger):
    runner, ledger, attempt = runner_ledger
    attempt(0, unresolved=True)
    with pytest.raises(ValueError, match="account_unavailable"):
        runner()


def test_concurrent_pilot_invocations_cannot_share_call_allowance(runner_ledger, monkeypatch):
    runner, ledger, attempt = runner_ledger
    first, second = runner(), runner()
    def locked():
        with pytest.raises(BlockingIOError):
            second.run()
        return "serialized"
    monkeypatch.setattr(first, "_run_locked", locked)
    assert first.run() == "serialized"
    assert not first.directory.exists()


def test_settled_reservation_overrun_stops_later_pilot_even_below_account_limit(runner_ledger):
    from recon_cockpit.secure_agent.cost_contract import TokenUsage
    runner, ledger, attempt = runner_ledger
    ready = runner()
    attempt(0, unresolved=True)
    ledger.begin_dispatch("attempt-0", request_digest="a" * 64)
    ledger.settle_usage("attempt-0", TokenUsage(1, 100), receipt_reference="overrun", event_id="settled")
    assert ledger.snapshot("account")["overspent_microusd"] == 0
    with pytest.raises(ValueError, match="account_unavailable"):
        runner()
    with pytest.raises(ValueError, match="account_unavailable"):
        ready.run()
    assert not ready.directory.exists()
