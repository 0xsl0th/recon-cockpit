"""Finite routing commitments reuse stock cases without granting launch authority."""

from copy import deepcopy
import hashlib
from itertools import product
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import routing_contract as contract
from recon_cockpit.secure_agent.models import parse_action
from test_stock_ssh_client import manifests as ssh_runtime
from test_secure_network_tools_runtime import manifest as native_manifest

SESSION = str(UUID(int=3501))
INSTANCE = str(UUID(int=3502))


def http_runtime(case, configuration="A", implementation="nginx"):
    # Keep the contract fixtures independent from launcher implementation imports.
    if implementation == "apache":
        from test_stock_http_production_authority import runtime as production_runtime
        return production_runtime(implementation, configuration, case)
    from recon_cockpit.secure_agent import stock_http_runtime as daemon
    from recon_cockpit.secure_agent import stock_http_spec as spec
    from recon_cockpit.secure_agent.stock_http_production_nmap_runtime import from_native_manifest
    rows = [(daemon.EXECUTABLE, daemon.DESTINATION, b"native")]
    rows += [(daemon.LIBRARY_ROOT + "ld-linux-x86-64.so.2" if destination == daemon.INTERPRETER else destination,
              destination, b"native") for destination in sorted(daemon.DEPENDENCIES)]
    rows += list(spec.compiled_files(configuration, case))
    return {"daemon": {"schema_version": "1", "profile": daemon.PROFILE,
        "configuration": configuration, "case": case, "selection_sha256": spec.selection_digest(configuration, case),
        "executable": daemon.DESTINATION, "interpreter": daemon.INTERPRETER,
        "dependency_kind": "elf_linked_dependencies_only", "runtime_closure_verified": False,
        "daemon_execution_performed": False, "files": [
            {"source": source, "destination": destination, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for source, destination, raw in sorted(rows, key=lambda row: row[1])]},
        "client": from_native_manifest(native_manifest("nmap_service_identify_v1")) if case == "O5" else None}


def runtime(deployment=None):
    selected = contract.selection(deployment=deployment)
    configuration, implementation = selected["configuration"], contract.http_implementation(selected)
    return {"http_nmap": http_runtime("O5", configuration, implementation),
            "http_headers": http_runtime("O1", configuration, implementation),
            "ssh_nmap": ssh_runtime(configuration, "O1"), "ssh_keys": ssh_runtime(configuration, "O2")}


def identity(budget_case="ordinary", *, deployment=None):
    selected = contract.selection(budget_case, deployment=deployment)
    return contract.identity(selected, SESSION, runtime(deployment), instance_id=INSTANCE)


@pytest.mark.parametrize("case", contract.BUDGET_CASES)
def test_exact_four_actions_retain_stock_parameters_but_cannot_cross_profiles(case):
    selected = contract.selection(case)
    policy = contract.policy_for_selection(selected)
    assert contract.validate_selection(selected) == selected
    assert contract.limits(selected) == {"max_steps": 4, "max_runtime_seconds": 60, "max_output_bytes": 26624}
    assert set(contract.actions(selected)) == set(contract.SELECTORS)
    for selector in contract.SELECTORS:
        raw = contract.action(selected, selector)
        stock = contract.underlying_contract(selector).action(contract.underlying_selection(selector))
        assert raw["action_id"] != stock["action_id"]
        assert {key: item for key, item in raw.items() if key != "action_id"} == {
            key: item for key, item in stock.items() if key != "action_id"}
        parsed = parse_action(raw)
        assert contract.profile_allows(parsed, selected)
        assert policy.evaluate(parsed).decision == "approval_required"
        assert contract.action_selector(parsed, selected) == selector
        assert not contract.profile_allows(parse_action(stock), selected)
        assert not contract.underlying_contract(selector).profile_allows(parsed, contract.underlying_selection(selector))
    assert sum(contract.action_bounds(name)["output_bytes"] for name in contract.SELECTORS) == 26624


def test_negative_presets_lower_only_the_named_ceiling_and_change_action_authority():
    ordinary = contract.budgets(contract.selection())
    changes = {"connection_one": ("connections", 1), "http_one": ("http_requests", 1), "ssh_zero": ("kex_exchanges", 0)}
    for case, (key, maximum) in changes.items():
        assert contract.budgets(contract.selection(case)) == {**ordinary, key: maximum}
    assert len({contract.selection(case)["selection_sha256"] for case in contract.BUDGET_CASES}) == 4
    assert len({contract.action(contract.selection(case), name)["action_id"]
                for case, name in product(contract.BUDGET_CASES, contract.SELECTORS)}) == 16
    assert ordinary["request_bytes"] == sum(contract.action_bounds(name)["request_bytes"] for name in contract.SELECTORS)
    assert ordinary["response_bytes"] == sum(contract.action_bounds(name)["response_bytes"] for name in contract.SELECTORS)


@pytest.mark.parametrize("bad", (None, True, 1, "B", "arbitrary", {}, [], "ORDINARY"))
def test_no_arbitrary_targets_or_budget_configuration(bad):
    with pytest.raises(ValueError): contract.selection(bad)
    with pytest.raises(ValueError): contract.underlying_selection(bad)


@pytest.mark.parametrize("field,value", (("configuration", "B"), ("selection_sha256", "a" * 64),
    ("budget_case", "ssh_zero"), ("extra", False)))
def test_recommitted_selection_cannot_mutate_one_field(field, value):
    chosen = contract.selection(); chosen[field] = value
    with pytest.raises(ValueError): contract.validate_selection(chosen)


@pytest.mark.parametrize("field", ("max_steps", "max_runtime_seconds", "max_output_bytes"))
@pytest.mark.parametrize("change", (-1, 1, True))
def test_limits_are_exact_including_types(field, change):
    chosen = contract.selection(); limits = contract.limits(chosen)
    limits[field] = change if type(change) is bool else limits[field] + change
    with pytest.raises(ValueError): contract.validate_limits(limits, chosen)


@pytest.mark.parametrize("selector", contract.SELECTORS)
@pytest.mark.parametrize("field", ("action_id", "target", "rationale", "port", "timeout_seconds", "max_output_bytes"))
def test_mutated_action_rejected_even_if_broad_policy_might_allow_it(selector, field):
    chosen = contract.selection(); raw = contract.action(chosen, selector)
    if field == "action_id": raw[field] = str(UUID(int=3503))
    elif field == "target": raw[field] = "10.77.0.99"
    elif field == "rationale": raw[field] += " changed"
    else: raw["parameters"][field] += 1
    with pytest.raises(ValueError): contract.action_selector(raw, chosen)


def test_approval_mode_is_explicit_and_policy_is_bound_to_selection():
    chosen = contract.selection()
    for approval in (True, False):
        policy = contract.policy_for_selection(chosen, require_approval=approval)
        assert contract.validate_policy(policy.to_dict(), chosen) == policy
    for case in contract.BUDGET_CASES[1:]:
        with pytest.raises(ValueError): contract.validate_policy(contract.policy_for_selection(contract.selection(case)).to_dict(), chosen)
    with pytest.raises(ValueError): contract.policy_for_selection(chosen, require_approval=1)


def test_each_runtime_manifest_is_validated_against_its_own_case():
    chosen = contract.selection(); bundle = runtime()
    assert contract.validate_runtime(bundle, chosen) == bundle
    for first, second in (("http_nmap", "http_headers"), ("ssh_nmap", "ssh_keys")):
        changed = deepcopy(bundle)
        changed[second]["daemon"] = deepcopy(changed[first]["daemon"])
        with pytest.raises(ValueError): contract.validate_runtime(changed, chosen)
    for missing in contract.SELECTORS:
        changed = deepcopy(bundle); del changed[missing]
        with pytest.raises(ValueError): contract.validate_runtime(changed, chosen)


def test_identity_commits_independent_daemon_and_client_manifests_and_owner():
    chosen = contract.selection(); bundle = runtime(); owner = identity()
    assert contract.validate_identity(owner, selection=chosen, session_id=SESSION, runtime=bundle) == owner
    assert owner["runtimes"]["http_headers"]["client_runtime_sha256"] is None
    for selector in contract.SELECTORS:
        changed = deepcopy(bundle)
        changed[selector]["daemon"]["files"][0]["sha256"] = "b" * 64
        with pytest.raises(ValueError): contract.validate_identity(owner, runtime=changed)
    for field, value in (("session_id", str(UUID(int=3504))), ("budget_case", "ssh_zero"),
                         ("runtime_sha256", "b" * 64), ("instance_id", "not-a-uuid")):
        changed = deepcopy(owner); changed[field] = value
        with pytest.raises(ValueError): contract.validate_identity(changed, selection=chosen, session_id=SESSION, runtime=bundle)


def test_exact_source_mount_union_never_exposes_compiled_files_or_broad_directories():
    chosen = contract.selection(); bundle = runtime()
    expected = sorted(set().union(*(set(contract.underlying_contract(name).runtime_source_mounts(bundle[name],
        contract.underlying_selection(name))) for name in contract.SELECTORS)))
    assert contract.runtime_source_mounts(bundle, chosen) == expected
    assert not any(source.startswith("compiled:") or destination in ("/etc", "/usr", "/usr/lib", "/tool/sshd", "/tool/nginx")
                   for source, destination in expected)


def test_manifest_inspection_never_reuses_a_different_case_commitment(monkeypatch):
    from recon_cockpit.secure_agent import stock_http_runtime, stock_ssh_runtime
    from recon_cockpit.secure_agent import stock_http_client_runtime, stock_ssh_client_runtime
    bundle = runtime(); observed = []
    for service, daemon, client in (("http", stock_http_runtime, stock_http_client_runtime),
                                    ("ssh", stock_ssh_runtime, stock_ssh_client_runtime)):
        def inspect_daemon(configuration, case, control, service=service):
            observed.append((service, configuration, case))
            selector = next(name for name in contract.SELECTORS if name.startswith(service)
                            and contract.underlying_selection(name)["case"] == case)
            return deepcopy(bundle[selector]["daemon"])
        def inspect_client(selected, control, service=service):
            selector = next(name for name in contract.SELECTORS if name.startswith(service)
                            and contract.underlying_selection(name) == selected)
            return deepcopy(bundle[selector]["client"])
        monkeypatch.setattr(daemon, "inspect_runtime", inspect_daemon)
        monkeypatch.setattr(client, "inspect_client_runtime", inspect_client)
    class Control:
        def check(self): pass
    assert contract.inspect_runtime(contract.selection(), Control()) == bundle
    assert observed == [("http", "A", "O5"), ("http", "A", "O1"), ("ssh", "A", "O1"), ("ssh", "A", "O2")]


@pytest.mark.parametrize("case,selection_hash,action_ids", (
    ("ordinary", "a780639b912519b2d0c8a3b996698ca887592a2e2c856ffa42da6be45b0fe409",
     ("dbd7aaea-eabd-5b6a-8ee4-7cfeac01e0c0", "25321557-7322-5c7e-9471-89f0d2059af1", "ca4ffabb-fb4a-5144-b2ca-3108ee4a16d1", "5dce33ef-ff4c-57eb-b6f4-a73b9609915c")),
    ("connection_one", "666d0ca5fed6f5c80bbd808cd768b6c9e5e1d10626f78a2083b607c8716cdde0",
     ("6f8517f3-dff7-503f-a8e6-7d1ce553aa66", "27214f96-9cef-5adc-a223-d80f10b238e2", "a5a0b7b7-b144-5f44-9475-81de9f9e1950", "0106e4fd-8e0b-598a-8a00-1616ef658e96")),
    ("http_one", "e0f1f6b13e62013a6ae13179b07de3ede8f09a5d33b55c9260572d2faecf148b",
     ("1216ac6b-fb3c-5d54-a81b-e61e8dfb8418", "737f3792-eeac-5b9d-865a-036843189611", "8ada1f07-063f-5add-b3ad-e20528c979bf", "1b63c973-5c63-53c1-af58-57aa7c2253ed")),
    ("ssh_zero", "254b9ef96f413b9b54c92da7a8703a3ef8ca02563a8466cca07822b3fd9eaf59",
     ("4b438b67-2334-53fb-97ba-ff64c1fa4040", "e1994c57-43a3-5a24-b7ee-cce7cfb80484", "352221d0-ab71-54ff-9cdd-3638e89b4247", "2b80e0b1-4147-5a3b-baf4-c3c7ed680e76")),
))
def test_legacy_selection_hashes_and_action_ids_remain_pinned(case, selection_hash, action_ids):
    selected = contract.selection(case)
    assert selected == {"configuration": "A", "budget_case": case, "selection_sha256": selection_hash}
    assert tuple(contract.action(selected, name)["action_id"] for name in contract.SELECTORS) == action_ids
    assert contract.selection_from_identity(identity(case)) == selected


@pytest.mark.parametrize("deployment,case", tuple(product(contract.DEPLOYMENTS, contract.BUDGET_CASES)))
def test_explicit_deployments_bind_exact_actions_policy_runtime_and_identity(deployment, case):
    selected = contract.selection(case, deployment=deployment)
    implementation, configuration = deployment.split("-")
    assert set(selected) == set(contract.DEPLOYMENT_SELECTION_FIELDS)
    assert selected["selection_version"] == "2"
    assert selected["implementation"] == implementation and selected["configuration"] == configuration
    assert contract.validate_selection(selected) == selected
    assert selected["selection_sha256"] != contract.selection(case)["selection_sha256"]
    assert contract.http_implementation(selected) == implementation
    assert contract.budgets(selected) == contract.budgets(contract.selection(case))
    expected_targets = ["10.77.0.10", "10.77.0.20"] if configuration == "A" else ["172.23.0.10", "172.23.0.20"]
    expected_ports = [8080, 2222] if configuration == "A" else [18080, 12222]
    policy = contract.policy_for_selection(selected)
    assert policy.to_dict()["allowed_targets"] == expected_targets
    assert policy.to_dict()["allowed_ports"] == expected_ports
    for selector in contract.SELECTORS:
        underlying = contract.underlying_selection(selector, selected)
        assert underlying["configuration"] == configuration
        if selector.startswith("http_"): assert underlying["implementation"] == implementation
        action = contract.action(selected, selector)
        original = contract.underlying_contract(selector).action(underlying)
        assert {k: v for k, v in action.items() if k != "action_id"} == {k: v for k, v in original.items() if k != "action_id"}
        assert action["action_id"] != contract.action(contract.selection(case), selector)["action_id"]
        assert policy.evaluate(parse_action(action)).decision == "approval_required"
    bundle, owner = runtime(deployment), identity(case, deployment=deployment)
    assert contract.validate_runtime(bundle, selected) == bundle
    assert contract.validate_identity(owner, selection=selected, runtime=bundle) == owner
    assert contract.selection_from_identity(owner) == selected
    with pytest.raises(ValueError): contract.validate_identity(owner, selection=contract.selection(case))
    with pytest.raises(ValueError):
        contract.validate_policy(contract.policy_for_selection(contract.selection(case)).to_dict(), selected)


@pytest.mark.parametrize("deployment", (True, 2, "nginx", "apache-C", "Apache-A", "nginx-A-extra", "external-A", {}, []))
def test_deployment_selector_is_closed(deployment):
    with pytest.raises(ValueError): contract.selection(deployment=deployment)


@pytest.mark.parametrize("field,value", (("selection_version", 2), ("selection_version", "1"),
    ("implementation", "nginx"), ("configuration", "A"), ("budget_case", "ssh_zero"),
    ("selection_sha256", "a" * 64), ("target", "172.23.0.99")))
def test_extended_selection_cannot_be_mutated_or_downgraded(field, value):
    selected = contract.selection(deployment="apache-B"); selected[field] = value
    with pytest.raises(ValueError): contract.validate_selection(selected)


@pytest.mark.parametrize("source,destination", (("nginx-A", "nginx-B"), ("nginx-A", "apache-A"),
    ("apache-A", "apache-B"), ("apache-B", "nginx-B")))
def test_runtime_and_identity_cannot_cross_deployments(source, destination):
    selected = contract.selection(deployment=destination)
    with pytest.raises(ValueError): contract.validate_runtime(runtime(source), selected)
    with pytest.raises(ValueError): contract.validate_identity(identity(deployment=source), selection=selected)
    with pytest.raises(ValueError):
        contract.validate_policy(contract.policy_for_selection(contract.selection(deployment=source)).to_dict(), selected)


def test_identity_extraction_does_not_discard_partial_versioned_fields():
    for value in (None, {}, {**identity(), "implementation": "apache"},
                  {**identity(), "selection_version": "2"}):
        with pytest.raises(ValueError): contract.selection_from_identity(value)
    owner = identity(deployment="nginx-A")
    owner.pop("selection_version")
    with pytest.raises(ValueError): contract.selection_from_identity(owner)


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
def test_runtime_inspection_dispatches_selected_implementation_and_configuration(monkeypatch, deployment):
    from recon_cockpit.secure_agent import stock_http_production_contract as http, stock_ssh_runtime
    from recon_cockpit.secure_agent import stock_http_client_runtime, stock_ssh_client_runtime
    selected, bundle, observed = contract.selection(deployment=deployment), runtime(deployment), []
    implementation, configuration = deployment.split("-")
    for service, daemon, client in (("http", http.implementation_runtime(implementation), stock_http_client_runtime),
                                    ("ssh", stock_ssh_runtime, stock_ssh_client_runtime)):
        def inspect_daemon(config, case, control, service=service):
            observed.append((service, config, case))
            name = next(name for name in contract.SELECTORS if name.startswith(service)
                        and contract.underlying_selection(name, selected)["case"] == case)
            return deepcopy(bundle[name]["daemon"])
        def inspect_client(chosen, control, service=service):
            name = next(name for name in contract.SELECTORS if name.startswith(service)
                        and contract.underlying_selection(name, selected) == chosen)
            return deepcopy(bundle[name]["client"])
        monkeypatch.setattr(daemon, "inspect_runtime", inspect_daemon)
        monkeypatch.setattr(client, "inspect_client_runtime", inspect_client)
    class Control:
        def check(self): pass
    assert contract.inspect_runtime(selected, Control()) == bundle
    assert observed == [("http", configuration, "O5"), ("http", configuration, "O1"),
                        ("ssh", configuration, "O1"), ("ssh", configuration, "O2")]
