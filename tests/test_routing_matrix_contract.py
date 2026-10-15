"""Closed v3 case commitments preserve the earlier routing authority bytes."""

from copy import deepcopy
from itertools import product

import pytest

from recon_cockpit.secure_agent import routing_contract as contract
from recon_cockpit.secure_agent.models import parse_action
from test_routing_contract import SESSION, INSTANCE, runtime as legacy_runtime
from test_stock_http_production_authority import runtime as http_runtime
from test_stock_ssh_client import manifests as ssh_runtime


BASELINE = {"http_nmap": "O5", "http_headers": "O1", "ssh_nmap": "O1", "ssh_keys": "O2"}
CASES = {"http_nmap": ("O5", "O6"),
         "http_headers": ("O1", "O2", "O3", "O4", "R1", "R2", "N1", "N2", "N3", "N4", "N5"),
         "ssh_nmap": ("O1", "N1"), "ssh_keys": ("O2", "R1", "R2", "N2", "N3", "N4", "N5", "N6")}


def runtime(selected):
    """Build finite portable manifests for the selected cases, without inspection."""
    return {name: (http_runtime(contract.http_implementation(selected), selected["configuration"], case)
                   if name.startswith("http_") else ssh_runtime(selected["configuration"], case))
            for name in contract.SELECTORS for case in (contract.selected_case(name, selected),)}


def identity(selected):
    return contract.identity(selected, SESSION, runtime(selected), instance_id=INSTANCE)


@pytest.mark.parametrize("deployment,pinned", (
    (None, "cbc7c7daceef4a17566d51996f8af753dfaf45cb633bbd01d4f8e16a163e7564"),
    ("nginx-A", "41b59cee9faa8557f0ba2968310fbe5925d72370354f948b64ae981aae63e913"),
    ("nginx-B", "c57715ed1a2768e154d512f88e20e22511e14e4161cc9cbe0d9cdf715d4f16dd"),
    ("apache-A", "fb4722471c311ef713487715fd40f6cfe0938ef2906aa0fbd4c99fa2a1661b74"),
    ("apache-B", "d3cf43664280bab13f739f0f6f1859a345eda1dfda57d4f3663e2ab68b2e0c55"),
))
def test_v1_v2_authority_and_runtime_fingerprints_are_byte_exact(deployment, pinned):
    # Pinned from f68e212 before v3 implementation, across every old budget preset.
    rows = []
    for budget in contract.BUDGET_CASES:
        selected = contract.selection(budget, deployment=deployment)
        assert contract.case_profile(selected) is None
        rows.append({"selection": selected, "actions": contract.actions(selected),
            "policy": contract.policy_for_selection(selected).to_dict(),
            "runtime_digests": contract.runtime_digests(legacy_runtime(deployment), selected),
            "scope": contract.scope(selected), "limits": contract.limits(selected)})
    assert contract.digest(rows) == pinned


def test_profile_inventory_is_exactly_the_pinned_twenty_single_slot_maps():
    expected = {"baseline"} | {name + "_" + case for name, cases in CASES.items()
                              for case in cases if case != BASELINE[name]}
    assert len(contract.CASE_PROFILES) == len(expected) == 20
    assert set(contract.CASE_PROFILES) == expected


@pytest.mark.parametrize("deployment,profile", tuple(product(contract.DEPLOYMENTS, contract.CASE_PROFILES)))
def test_every_matrix_profile_commits_all_slots_and_retains_limits(deployment, profile):
    selected = contract.selection(deployment=deployment, case_profile=profile)
    assert set(selected) == set(contract.MATRIX_SELECTION_FIELDS)
    assert selected["selection_version"] == "3" and contract.case_profile(selected) == profile
    assert contract.validate_selection(selected) == selected
    expected = dict(BASELINE)
    if profile != "baseline":
        name, case = profile.rsplit("_", 1)
        expected[name] = case
    assert {name: contract.selected_case(name, selected) for name in contract.SELECTORS} == expected
    old = contract.selection(deployment=deployment)
    assert selected["selection_sha256"] != old["selection_sha256"]
    assert contract.budgets(selected) == contract.budgets(old)
    assert contract.limits(selected) == contract.limits(old)
    assert contract.scope(selected) == contract.scope(old)
    for name, case in expected.items():
        action = contract.action(selected, name)
        underlying = contract.underlying_selection(name, selected)
        stock = contract.underlying_contract(name).action(underlying)
        assert {k: v for k, v in action.items() if k != "action_id"} == {k: v for k, v in stock.items() if k != "action_id"}
        assert action["action_id"] != contract.action(old, name)["action_id"]
        assert contract.case_is_negative(name, selected) is case.startswith("N")
        assert contract.action_selector(parse_action(action), selected) == name
    policy = contract.policy_for_selection(selected)
    assert all(policy.evaluate(parse_action(row)).decision == "approval_required" for row in contract.actions(selected).values())
    with pytest.raises(ValueError): contract.validate_policy(contract.policy_for_selection(old).to_dict(), selected)


@pytest.mark.parametrize("profile", contract.CASE_PROFILES)
def test_selected_runtime_identity_and_mounts_use_the_committed_case(profile):
    selected = contract.selection(deployment="apache-B", case_profile=profile)
    bundle = runtime(selected)
    assert contract.validate_runtime(bundle, selected) == bundle
    owner = contract.identity(selected, SESSION, bundle, instance_id=INSTANCE)
    assert contract.selection_from_identity(owner) == selected
    assert contract.validate_identity(owner, selection=selected, runtime=bundle) == owner
    mounts = sorted(set().union(*(set(contract.underlying_contract(name).runtime_source_mounts(
        bundle[name], contract.underlying_selection(name, selected))) for name in contract.SELECTORS)))
    assert contract.runtime_source_mounts(bundle, selected) == mounts
    if profile != "baseline":
        with pytest.raises(ValueError): contract.validate_runtime(legacy_runtime("apache-B"), selected)
        with pytest.raises(ValueError): contract.validate_identity(owner, runtime=legacy_runtime("apache-B"))
        changed = deepcopy(bundle)
        name, _ = profile.rsplit("_", 1)
        changed[name] = legacy_runtime("apache-B")[name]
        with pytest.raises(ValueError): contract.runtime_digests(changed, selected)
        with pytest.raises(ValueError): contract.runtime_source_mounts(changed, selected)


@pytest.mark.parametrize("profile", ("http_nmap_O6", "http_headers_O3", "ssh_nmap_N1", "ssh_keys_N3"))
def test_runtime_inspection_uses_selected_case_before_constructing_identity(monkeypatch, profile):
    from recon_cockpit.secure_agent import stock_http_production_contract as http, stock_ssh_runtime
    from recon_cockpit.secure_agent import stock_http_client_runtime, stock_ssh_client_runtime
    selected = contract.selection(deployment="nginx-B", case_profile=profile)
    bundle, observed = runtime(selected), []
    for protocol, daemon, client in (("http", http.implementation_runtime("nginx"), stock_http_client_runtime),
                                      ("ssh", stock_ssh_runtime, stock_ssh_client_runtime)):
        def inspect_daemon(configuration, case, control, protocol=protocol):
            observed.append((protocol, configuration, case))
            name = next(name for name in contract.SELECTORS if name.startswith(protocol)
                        and contract.selected_case(name, selected) == case)
            return deepcopy(bundle[name]["daemon"])
        def inspect_client(chosen, control, protocol=protocol):
            name = next(name for name in contract.SELECTORS if name.startswith(protocol)
                        and contract.underlying_selection(name, selected) == chosen)
            return deepcopy(bundle[name]["client"])
        monkeypatch.setattr(daemon, "inspect_runtime", inspect_daemon)
        monkeypatch.setattr(client, "inspect_client_runtime", inspect_client)
    class Control:
        def check(self): pass
    assert contract.inspect_runtime(selected, Control()) == bundle
    assert observed == [(name.split("_", 1)[0], "B", contract.selected_case(name, selected)) for name in contract.SELECTORS]


@pytest.mark.parametrize("budget", contract.BUDGET_CASES)
def test_only_explicit_baseline_accepts_lowered_budget_presets(budget):
    selected = contract.selection(budget, deployment="apache-A", case_profile="baseline")
    assert contract.budgets(selected) == contract.budgets(contract.selection(budget))
    if budget != "ordinary":
        for profile in contract.CASE_PROFILES[1:]:
            with pytest.raises(ValueError): contract.selection(budget, deployment="apache-A", case_profile=profile)


@pytest.mark.parametrize("profile", (True, 3, "", "O1", "http_headers_O1", "http_nmap_N1", "ssh_keys_O1", "ssh_keys_N7", {}, []))
def test_arbitrary_or_cross_slot_profiles_are_rejected(profile):
    with pytest.raises(ValueError): contract.selection(deployment="nginx-A", case_profile=profile)


@pytest.mark.parametrize("profile", contract.CASE_PROFILES)
def test_case_profiles_require_explicit_deployment(profile):
    with pytest.raises(ValueError): contract.selection(case_profile=profile)


@pytest.mark.parametrize("field,value", (("case_profile", "baseline"), ("case_profile", None),
    ("selection_version", "2"), ("selection_version", 3), ("implementation", "nginx"),
    ("configuration", "A"), ("budget_case", "http_one"), ("case_map", BASELINE)))
def test_v3_cannot_be_mutated_or_downgraded(field, value):
    selected = contract.selection(deployment="apache-B", case_profile="http_headers_N1")
    selected[field] = value
    with pytest.raises(ValueError): contract.validate_selection(selected)


def test_identity_extraction_cannot_discard_partial_case_profile():
    for old in (contract.selection(), contract.selection(deployment="nginx-A")):
        with pytest.raises(ValueError): contract.selection_from_identity({**old, "case_profile": "baseline"})
    selected = contract.selection(deployment="nginx-A", case_profile="baseline")
    del selected["case_profile"]
    with pytest.raises(ValueError): contract.selection_from_identity(selected)


def test_expected_semantics_are_committed_and_detached(monkeypatch):
    selected = contract.selection(deployment="apache-A", case_profile="http_headers_N4")
    expected = contract.case_expectation("http_headers", selected)
    assert expected["expected_negative"] and expected["category"] == "negative"
    assert expected["allowed_classifications"] == ["expected_response_budget_refusal"]
    assert expected["classification_basis"] == "routing_owner_response_budget_before_delivery"
    assert expected["requirements"] == {"proposed_response_bytes": 2049, "delivered_response_bytes": 0,
        "accepted_response_reservation_bytes": 0, "delivered_validated_requests": 1,
        "terminal_reason": "action_response_bytes_limit"}
    expected["allowed_classifications"].append("useful")
    assert contract.case_expectation("http_headers", selected)["allowed_classifications"] == ["expected_response_budget_refusal"]
    original = contract._case_expectation
    def changed(*args, **kwargs):
        value = original(*args, **kwargs)
        value["classification_basis"] = "changed"
        return value
    monkeypatch.setattr(contract, "_case_expectation", changed)
    with pytest.raises(ValueError): contract.validate_selection(selected)


@pytest.mark.parametrize("profile,basis", (("ssh_keys_N3", "withheld_response_and_native_two_second_timeout"),
                                         ("ssh_keys_N4", "independent_recorder_wire_cap")))
def test_ssh_negative_semantics_retain_the_accepted_classification_basis(profile, basis):
    selected = contract.selection(deployment="nginx-A", case_profile=profile)
    expected = contract.case_expectation("ssh_keys", selected)
    assert expected["classification_basis"] == basis
    assert expected["allowed_classifications"] == (["timeout"] if profile.endswith("N3") else ["output_limit"])
