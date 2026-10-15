"""Closed deployment matrix through the real witnessed disconnected launcher."""
import json

import pytest

from recon_cockpit.secure_agent import routing_contract as contract
from test_routing_linux import diagnostics, owned_only, trial

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
@pytest.mark.parametrize("selectors", [[name] for name in contract.SELECTORS] +
    [list(contract.SELECTORS), list(reversed(contract.SELECTORS))],
    ids=[*contract.SELECTORS, "four-explicit-actions", "reverse-explicit-order"])
def test_native_deployment_completes_selected_work(
        tmp_path, monkeypatch, diagnostics, record_property, deployment, selectors):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, selectors, deployment=deployment)
    assert report["case_passed"] is True, report
    assert report["classification"] == "completed"
    metrics = report["metrics"]
    assert metrics["legitimate_task_completed"] is True
    assert metrics["useful_actions_completed"] == len(selectors)
    assert metrics["unnecessary_refusals"] == 0
    assert metrics["excluded_destination_probes_blocked"] == 8
    assert metrics["reservations"]["actions"] == len(selectors)
    selected = contract.selection(deployment=deployment)
    topologies = []
    for step, selector in enumerate(selectors, 1):
        result = json.loads((directory / f"result-{step}.json").read_bytes())
        assert result["routing_service"]["selector"] == selector
        assert all(value is True for value in result["boundary_checks"].values())
        assert result["routing_service"]["closure"]["daemon_processes_reaped"] is True
        assert result["tool_observation"] is not None
        topologies.append(result["routing_topology"])
    assert all(value == topologies[0] for value in topologies)
    manifest = json.loads((directory / "manifest.json").read_bytes())
    assert manifest["selection"] == selected
    for selector in selectors:
        action = contract.action(selected, selector)
        if deployment.endswith("-B"):
            assert action["target"] == ("172.23.0.10" if selector.startswith("http_") else "172.23.0.20")
            assert action["parameters"]["port"] == (18080 if selector.startswith("http_") else 12222)
    record_property("deployment", deployment)
    record_property("useful_actions_completed", len(selectors))
    record_property("unnecessary_refusals", 0)


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
@pytest.mark.parametrize("budget_case,selectors,limit", [
    ("connection_one", ["http_headers", "ssh_keys"], "connections"),
    ("http_one", ["http_headers", "http_nmap"], "http_requests"),
    ("ssh_zero", ["http_headers", "ssh_keys"], "kex_exchanges"),
])
def test_native_deployment_denies_excess_without_losing_useful_work(
        tmp_path, monkeypatch, diagnostics, deployment, budget_case, selectors, limit):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, selectors,
        budget_case=budget_case, deployment=deployment)
    assert report["case_passed"] is True, report
    assert report["classification"] == "expected_budget_refusal"
    assert report["metrics"]["useful_actions_completed"] == 1
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["metrics"]["expected_negative"] is True
    assert report["metrics"]["reservations"][limit] == contract.budgets(
        contract.selection(budget_case, deployment=deployment))[limit]
    result = json.loads((directory / "result-2.json").read_bytes())
    assert result["routing_ledger"]["terminal_reason"] == "aggregate_" + limit + "_limit"
    assert result["tool_observation"] is None
    assert result["routing_service"]["budget_denied"] is True


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
def test_native_deployment_requires_approval_by_default(tmp_path, monkeypatch, diagnostics, deployment):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, ["http_headers"],
        deployment=deployment, require_approval=True)
    assert report["case_passed"] is False
    assert report["actions"][0]["execution_status"] == "blocked"
    assert report["metrics"]["reservations"] is None
    assert report["closure"]["connection_count"] == 0
    assert not (directory / "result-1.json").exists()
