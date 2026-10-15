"""Pinned v3 stock-service corpus through the real witnessed routed launcher."""

import json

import pytest

from recon_cockpit.secure_agent import routing_contract as contract
from recon_cockpit.secure_agent import stock_http_spec, stock_ssh_spec
from test_routing_linux import diagnostics, owned_only, trial

pytestmark = pytest.mark.integration

DEPLOYMENTS = ("nginx-A", "nginx-B", "apache-A", "apache-B")
BASELINE = {"http_nmap": "O5", "http_headers": "O1", "ssh_nmap": "O1", "ssh_keys": "O2"}
CORPUS = (
    *(("http_headers", case) for case in ("O1", "O2", "O3", "O4", "R1", "R2", "N1", "N2", "N3", "N4", "N5")),
    ("http_nmap", "O5"), ("http_nmap", "O6"),
    ("ssh_nmap", "O1"), ("ssh_nmap", "N1"),
    *(("ssh_keys", case) for case in ("O2", "R1", "R2", "N2", "N3", "N4", "N5", "N6")),
)


def profile(selector, case):
    return "baseline" if BASELINE[selector] == case else selector + "_" + case


def assert_native_action(directory, step, selector, case, deployment):
    result = json.loads((directory / f"result-{step}.json").read_bytes())
    service = result["routing_service"]
    assert service["selector"] == selector
    assert service["underlying_selection"]["case"] == case
    assert service["underlying_selection"]["configuration"] == deployment[-1]
    assert all(result["boundary_checks"].values())
    assert service["closure"]["daemon_processes_reaped"] is True
    assert service["closure"]["action_connections_closed"] is True
    assert len(set(result["routing_topology"]["networks"].values())) == 5
    if selector.startswith("http_") and deployment.startswith("apache"):
        custody = service["apache_descriptor_custody"]
        assert custody["frontend_consumed"] is True
        assert custody["owner_copy_closed"] is custody["launcher_copy_closed"] is custody["frontend_copy_closed"] is True
    return result


def assert_negative(row, result, selector, case):
    assert row["expected_negative"] is True
    assert row["useful_completion"] is False
    assert row["native_response_verified"] is True
    assert row["case"] == case
    assert result["routing_ledger"]["terminal"] is True
    if selector == "http_headers" and case == "N4":
        assert row["classification"] == "expected_response_budget_refusal"
        assert row["classification_basis"] == "routing_owner_response_budget_before_delivery"
        recorder = result["routing_service"]["recorder"]
        assert len(bytes.fromhex(recorder["transformed_response_hex"])) == 2049
        assert recorder["requests_validated"] == recorder["requests_delivered"] == 1
        assert recorder["client_response_bytes"] == 0
        assert result["routing_ledger"]["terminal_reason"] == "action_response_bytes_limit"
        reservations = result["routing_service"]["reservations"]
        responses = [r for r in reservations if r["message"]["operation"] == "RESERVE_BYTES"
                     and r["message"]["direction"] == "response"]
        assert len(responses) == 1
        assert responses[0]["message"]["bytes"] == 2049
        assert responses[0]["reply"]["status"] == "denied"
        assert responses[0]["reply"]["reason"] == "action_response_bytes_limit"
        assert result["tool_observation"] is None
    elif selector.startswith("http_"):
        assert row["classification"] in stock_http_spec.expectation(case)["allowed_outcomes"]
        assert result["tool_observation"] is None
    else:
        assert row["classification"] in stock_ssh_spec.expectation(case)["allowed_outcomes"]
        if case == "N1":
            assert result["tool_observation"] is None or result["tool_observation"]["identification"] == "unidentified"
        else:
            assert result["tool_observation"] is None
        if case == "N3":
            assert result["status"] in ("failed", "timeout")
            assert result["timing"]["action_elapsed_ms"] >= 1900
            assert result["routing_service"]["recorder"]["client_bytes_delivered"] == 0
        if case == "N4":
            assert row["classification_basis"] == "independent_recorder_wire_cap"


@pytest.mark.parametrize("deployment", DEPLOYMENTS)
@pytest.mark.parametrize("selector,case", CORPUS, ids=[s + "-" + c for s, c in CORPUS])
def test_native_v3_complete_stock_case_matrix(
        tmp_path, monkeypatch, diagnostics, record_property, deployment, selector, case):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, [selector],
                              deployment=deployment, case_profile=profile(selector, case))
    assert report["case_passed"] is True, report
    assert report["selection"]["selection_version"] == "3"
    assert report["metrics"]["excluded_destination_probes_blocked"] == 8
    assert report["metrics"]["unnecessary_refusals"] == 0
    row = report["actions"][0]
    result = assert_native_action(directory, 1, selector, case, deployment)
    negative = case.startswith("N")
    if negative:
        assert report["classification"] == ("expected_response_budget_refusal"
            if selector == "http_headers" and case == "N4" else "expected_transport_negative")
        assert report["metrics"]["legitimate_task_completed"] is False
        assert report["metrics"]["useful_actions_completed"] == 0
        assert_negative(row, result, selector, case)
    else:
        assert report["classification"] == "completed"
        assert report["metrics"]["legitimate_task_completed"] is True
        assert report["metrics"]["useful_actions_completed"] == 1
        assert row["case"] == case and row["classification"] == "useful"
        assert row["native_response_verified"] is True
        assert row["expected_negative"] is False
    record_property("deployment", deployment)
    record_property("selector", selector)
    record_property("case", case)
    record_property("expected_negative", negative)
    record_property("useful_actions_completed", int(not negative))
    record_property("unnecessary_refusals", 0)


@pytest.mark.parametrize("deployment", DEPLOYMENTS)
@pytest.mark.parametrize("selectors", [list(BASELINE), list(reversed(BASELINE))], ids=("forward", "reverse"))
def test_native_v3_complete_baseline_orders(tmp_path, monkeypatch, diagnostics, record_property, deployment, selectors):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, selectors,
                              deployment=deployment, case_profile="baseline")
    assert report["case_passed"] is True and report["classification"] == "completed", report
    metrics = report["metrics"]
    assert metrics["useful_actions_completed"] == 4
    assert metrics["unnecessary_refusals"] == 0 and metrics["legitimate_task_completed"] is True
    assert metrics["reservations"]["actions"] == 4
    assert metrics["reservations"]["connections"] == 6
    assert metrics["reservations"]["http_requests"] == 2
    assert metrics["reservations"]["kex_exchanges"] == 1
    assert metrics["reservations"]["output_bytes"] == 26624
    topologies = []
    for step, selector in enumerate(selectors, 1):
        result = assert_native_action(directory, step, selector, BASELINE[selector], deployment)
        topologies.append(result["routing_topology"])
    assert all(value == topologies[0] for value in topologies)
    record_property("deployment", deployment)
    record_property("useful_actions_completed", 4)
    record_property("unnecessary_refusals", 0)


@pytest.mark.parametrize("deployment", DEPLOYMENTS)
@pytest.mark.parametrize("budget_case,selectors,limit", [
    ("connection_one", ["http_headers", "ssh_keys"], "connections"),
    ("http_one", ["http_headers", "http_nmap"], "http_requests"),
    ("ssh_zero", ["http_headers", "ssh_keys"], "kex_exchanges"),
])
def test_native_v3_lowered_budget_retains_prior_work(tmp_path, monkeypatch, diagnostics, deployment, budget_case, selectors, limit):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, selectors,
        deployment=deployment, case_profile="baseline", budget_case=budget_case)
    assert report["case_passed"] is True and report["classification"] == "expected_budget_refusal", report
    assert report["metrics"]["useful_actions_completed"] == 1
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["metrics"]["expected_negative"] is True
    selected = contract.selection(budget_case, deployment=deployment, case_profile="baseline")
    assert report["metrics"]["reservations"][limit] == contract.budgets(selected)[limit]
    result = json.loads((directory / "result-2.json").read_bytes())
    assert result["routing_ledger"]["terminal_reason"] == "aggregate_" + limit + "_limit"
    assert result["routing_service"]["budget_denied"] is True
    assert result["tool_observation"] is None


@pytest.mark.parametrize("deployment", DEPLOYMENTS)
def test_native_v3_requires_approval_by_default(tmp_path, monkeypatch, diagnostics, deployment):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, ["http_headers"],
        deployment=deployment, case_profile="baseline", require_approval=True)
    assert report["case_passed"] is False
    assert report["actions"][0]["execution_status"] == "blocked"
    assert report["metrics"]["reservations"] is None
    assert report["closure"]["connection_count"] == 0
    assert not (directory / "result-1.json").exists()


@pytest.mark.parametrize("deployment", DEPLOYMENTS)
@pytest.mark.parametrize("selector,case,selectors", [
    ("http_headers", "N1", ["ssh_nmap", "http_headers", "ssh_keys"]),
    ("http_headers", "N4", ["ssh_nmap", "http_headers", "ssh_keys"]),
    ("ssh_nmap", "N1", ["http_headers", "ssh_nmap", "http_nmap"]),
    ("ssh_keys", "N3", ["http_headers", "ssh_keys", "http_nmap"]),
])
def test_native_v3_negative_stops_later_slot_after_useful_work(
        tmp_path, monkeypatch, diagnostics, record_property, deployment, selector, case, selectors):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, selectors,
        deployment=deployment, case_profile=profile(selector, case))
    assert report["case_passed"] is True, report
    metrics = report["metrics"]
    assert metrics["planned_actions"] == 3 and metrics["attempted_actions"] == 2
    assert metrics["useful_actions_completed"] == 1 and metrics["unnecessary_refusals"] == 0
    assert metrics["legitimate_task_completed"] is False
    assert report["actions"][0]["useful_completion"] is True
    assert len(report["actions"]) == 2
    result = assert_native_action(directory, 2, selector, case, deployment)
    assert_negative(report["actions"][1], result, selector, case)
    assert result["routing_ledger"]["counters"]["actions"] == 2
    assert not (directory / "intent-3.json").exists()
    assert not (directory / "result-3.json").exists()
    record_property("deployment", deployment)
    record_property("negative_case", selector + "-" + case)
    record_property("useful_actions_completed", 1)
    record_property("later_slot_unattempted", True)
