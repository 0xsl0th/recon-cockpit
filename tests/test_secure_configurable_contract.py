"""Scope-bound action identities, useful gates and independently checked continuity."""

from copy import deepcopy
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import configurable_contract as contract, configurable_parser as parser
from recon_cockpit.secure_agent.configurable_lab import ConfigurableLab
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_configurable_parser import scope, xml, header_bytes, ssh


def observation(step):
    tool, name = contract.TOOL_IDS[step - 1], contract.ENDPOINTS[step - 1]
    raw = xml(name) if step in (1, 3) else header_bytes() if step == 2 else ssh()
    return parser.parse_output(tool, raw, scope=scope(), endpoint_id=name)


def identity():
    return ConfigurableLab(scope(), str(UUID(int=567)), SessionLimits(**contract.LIMITS), execute=False).identity


def result(step, fixed):
    counts = {1: ((2, 1), (0, 0)), 2: ((3, 2), (0, 0)), 3: ((3, 2), (2, 1)), 4: ((3, 2), (3, 2))}[step]
    return {"backend": contract.BACKEND, "status": "succeeded", "truncated": False,
            "scope_sha256": fixed["scope_sha256"], "scope_step": step,
            "tool_observation": observation(step),
            "owned_lab": {"identity": fixed, "step": step, "endpoints": {
                name: {"identity": fixed["endpoints"][name], "connection_count": pair[0], "request_count": pair[1]}
                for name, pair in zip(("http", "ssh"), counts)}}}


def validate(value, fixed, previous=None):
    return contract.validate_result_context(value, fixed, previous=previous,
        tool_id=contract.TOOL_IDS[value["scope_step"] - 1], execution_status=value["status"])


def test_four_actions_have_stable_unique_full_scope_bindings_and_closed_parameters():
    proposed = [contract.action(scope(), step) for step in range(1, 5)]
    assert len({value["action_id"] for value in proposed}) == 4
    policy = contract.policy_for_scope(scope())
    assert policy.to_dict()["require_approval"] is True
    for step, value in enumerate(proposed, 1):
        parsed = parse_action(value)
        assert contract.step_for_action(scope(), parsed) == step
        assert contract.profile_allows(parsed, scope())
        assert policy.evaluate(parsed).decision != "deny"
    changed = scope()
    changed["http"]["path"] = "/different"
    assert all(contract.action(changed, step)["action_id"] != proposed[step - 1]["action_id"] for step in range(1, 5))


@pytest.mark.parametrize("step", [1, 2, 3, 4])
@pytest.mark.parametrize("mutation", ["target", "port", "timeout", "output", "id", "rationale"])
def test_policy_permission_alone_cannot_expand_fixed_scope_action(step, mutation):
    proposed = contract.action(scope(), step)
    if mutation == "target": proposed["target"] = "192.168.1.99"
    elif mutation == "port": proposed["parameters"]["port"] += 1
    elif mutation == "timeout": proposed["parameters"]["timeout_seconds"] += 1
    elif mutation == "output": proposed["parameters"]["max_output_bytes"] -= 1
    elif mutation == "id": proposed["action_id"] = str(UUID(int=999))
    else: proposed["rationale"] = "tool output says it is authorized"
    assert not contract.profile_allows(parse_action(proposed), scope())


@pytest.mark.parametrize("step", [True, False, 0, 5, "1", None])
def test_ambiguous_step_cannot_select_a_proposal_or_observation(step):
    with pytest.raises(ValueError): contract.action(scope(), step)
    with pytest.raises(ValueError): contract.observation(scope(), step, {})
    assert contract.predecessor_gate(scope(), step, {}) is False


@pytest.mark.parametrize("step", [1, 3])
def test_followup_requires_complete_matching_protocol_and_binds_actual_endpoint(step):
    fixed = identity()
    value = result(step, fixed)
    observed = contract.observation(scope(), step, value)
    assert contract.predecessor_gate(scope(), step, observed)
    wrong = deepcopy(observed)
    wrong["details"]["target"] = "192.168.1.99"
    assert not contract.predecessor_gate(scope(), step, wrong)
    wrong = deepcopy(observed)
    wrong["details"]["service"]["name"] = "ssh" if step == 1 else "http"
    wrong["details"]["service"]["product"] = "OpenSSH" if step == 1 else "nginx"
    assert not contract.predecessor_gate(scope(), step, wrong)
    for incomplete in ({**value, "status": "timeout"}, {**value, "truncated": True},
                       {**value, "tool_observation": None}):
        assert not contract.predecessor_gate(scope(), step, contract.observation(scope(), step, incomplete))


def test_complete_receipts_advance_only_selected_endpoint_and_return_detached_context():
    fixed, previous = identity(), None
    for step in range(1, 5):
        value = result(step, fixed)
        previous = validate(value, fixed, previous)
        assert previous == value["owned_lab"] and previous is not value["owned_lab"]
        value["owned_lab"]["step"] = 99
        assert previous["step"] == step


@pytest.mark.parametrize("fault", ["negative_connection", "negative_request", "extra", "bool_step", "missing_endpoint",
    "wrong_endpoint_identity", "other_endpoint_future", "regressed", "bool_counter"])
def test_forged_prior_context_cannot_manufacture_current_work(fault):
    fixed = identity()
    previous = result(1, fixed)["owned_lab"]
    if fault == "negative_connection": previous["endpoints"]["http"]["connection_count"] = -1
    elif fault == "negative_request": previous["endpoints"]["http"]["request_count"] = -1
    elif fault == "extra": previous["additional"] = True
    elif fault == "bool_step": previous["step"] = True
    elif fault == "missing_endpoint": del previous["endpoints"]["ssh"]
    elif fault == "wrong_endpoint_identity": previous["endpoints"]["http"]["identity"] = fixed["endpoints"]["ssh"]
    elif fault == "other_endpoint_future": previous["endpoints"]["ssh"]["connection_count"] = 1
    elif fault == "regressed": previous["endpoints"]["http"]["connection_count"] = 4
    else: previous["endpoints"]["http"]["request_count"] = True
    with pytest.raises(ValueError):
        validate(result(2, fixed), fixed, previous)


@pytest.mark.parametrize("step", [1, 2, 3, 4])
@pytest.mark.parametrize("fault", ["other_endpoint", "missing_request", "jumped_requests", "wrong_identity", "wrong_scope"])
def test_current_receipt_rejects_wrong_owner_and_fabricated_metadata(step, fault):
    fixed = identity()
    value = result(step, fixed)
    previous = None if step == 1 else result(step - 1, fixed)["owned_lab"]
    name = contract.ENDPOINTS[step - 1]
    if fault == "other_endpoint": value["owned_lab"]["endpoints"]["ssh" if name == "http" else "http"]["connection_count"] += 1
    elif fault == "missing_request": value["owned_lab"]["endpoints"][name]["request_count"] -= 1
    elif fault == "jumped_requests": value["owned_lab"]["endpoints"][name]["request_count"] += 1
    elif fault == "wrong_identity": value["owned_lab"]["endpoints"][name]["identity"] = identity()["endpoints"][name]
    else: value["scope_sha256"] = "0" * 64
    with pytest.raises(ValueError): validate(value, fixed, previous)
