"""The composed profile retains fixed actions, ordered finite counters and lab custody."""

import copy
import hashlib
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import service_web_contract as contract
from recon_cockpit.secure_agent import service_web_lab_contract as lab
from recon_cockpit.secure_agent import network_tools_contract, web_tools_contract, http_headers_contract
from recon_cockpit.secure_agent import http_headers_lab_contract
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.service_web_fixture import FFUF_PATHS, wire_response
from recon_cockpit.secure_agent.tool_adapters import (
    NMAP_SERVICE_PARAMETERS, FFUF_PARAMETERS, HTTP_HEADERS_PARAMETERS,
    LEGACY_PROPOSAL_PROFILE, NMAP_PROPOSAL_PROFILE, proposal_tools,
)


def policy(**changes):
    return parse_policy({"schema_version": "1", "policy_version": "service-web-test-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": list(contract.TOOL_IDS),
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 10,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": True,
        "approval_ttl_seconds": 60, **changes})


@pytest.mark.parametrize("case", contract.CASES)
def test_three_existing_exact_capabilities_have_a_new_workflow_identity(case):
    actions = [parse_action(contract.action(case, step)) for step in (1, 2, 3)]
    assert [item.tool_id for item in actions] == list(contract.TOOL_IDS)
    assert [item.parameters.to_dict() for item in actions] == [
        dict(NMAP_SERVICE_PARAMETERS), dict(FFUF_PARAMETERS), dict(HTTP_HEADERS_PARAMETERS)]
    assert [item.parameters.timeout_seconds for item in actions] == [5, 10, 1]
    assert [item.parameters.max_output_bytes for item in actions] == [8192, 8192, 2048]
    assert all(contract.profile_allows(item, case) for item in actions)
    assert all(policy().evaluate(item).decision == "approval_required" for item in actions)
    assert contract.LIMITS == {"max_steps": 3, "max_runtime_seconds": 60, "max_output_bytes": 18432}
    assert sum(item.parameters.max_output_bytes for item in actions) == contract.LIMITS["max_output_bytes"]
    descriptor = contract.capability_descriptor()
    assert descriptor["live_calls_enabled"] is False
    assert descriptor["arbitrary_metadata_followup"] is False
    assert descriptor["limits"] == contract.LIMITS
    assert len(descriptor["capabilities"]) == len(descriptor["steps"]) == 3
    assert descriptor["discovery_paths"] == list(FFUF_PATHS)


def test_new_scope_does_not_replace_old_single_tool_or_model_profiles():
    assert proposal_tools(LEGACY_PROPOSAL_PROFILE) == ("http_probe", "tcp_connect")
    assert proposal_tools(NMAP_PROPOSAL_PROFILE) == ("nmap_tcp_connect_v1", "http_probe")
    nmap = parse_action(contract.action("vulnerable", 1))
    ffuf = parse_action(contract.action("vulnerable", 2))
    headers = parse_action(contract.action("vulnerable", 3))
    assert not network_tools_contract.profile_allows(ffuf, "nmap-service-http")
    assert not web_tools_contract.profile_allows(nmap, "ffuf-normal")
    assert not http_headers_contract.profile_allows(nmap, "vulnerable")
    assert not web_tools_contract.profile_allows(headers, "ffuf-normal")
    assert nmap.action_id != parse_action(network_tools_contract.action("nmap-service-http")).action_id
    assert ffuf.action_id != parse_action(web_tools_contract.action("ffuf-normal")).action_id
    assert headers.action_id != parse_action(http_headers_contract.action("vulnerable", 2)).action_id


@pytest.mark.parametrize("step", [1, 2, 3])
@pytest.mark.parametrize("field,value", [("port", 8081), ("timeout_seconds", 2), ("max_output_bytes", 1024)])
def test_syntactically_valid_parameter_changes_cannot_expand_profile(step, field, value):
    value = copy.deepcopy(value)
    action = contract.action("vulnerable", step)
    action["parameters"][field] = value
    assert not contract.profile_allows(parse_action(action), "vulnerable")


@pytest.mark.parametrize("step", [1, 2, 3])
@pytest.mark.parametrize("target", ["127.0.0.2", "127.0.0.1/32", "::1"])
def test_target_is_only_the_literal_owned_endpoint(step, target):
    action = contract.action("vulnerable", step)
    action["target"] = target
    assert not contract.profile_allows(parse_action(action), "vulnerable")


@pytest.mark.parametrize("case,step", [("unknown", 1), ([], 2), ("injected", True), ("corrected", 4)])
def test_unknown_cases_bool_steps_and_extra_actions_rejected(case, step):
    with pytest.raises(ValueError):
        contract.action(case, step)


@pytest.mark.parametrize("step", [1, 2, 3])
@pytest.mark.parametrize("changes,reason", [
    ({"allowed_targets": ["127.0.0.2/32"]}, "target_out_of_scope"),
    ({"allowed_tools": ["http_probe"]}, "tool_not_allowed"),
    ({"allowed_ports": [8081]}, "port_not_allowed"),
    ({"max_output_bytes": 1024}, "output_limit_exceeds_policy"),
])
def test_each_real_action_still_requires_independent_policy_permission(step, changes, reason):
    decision = policy(**changes).evaluate(parse_action(contract.action("vulnerable", step)))
    assert decision.decision == "deny" and reason in decision.reasons


@pytest.mark.parametrize("case", contract.CASES)
def test_identity_binds_all_ten_response_bytes_and_separate_phases(case):
    definition = lab.spec(case)
    assert len(definition["routes"]) == 10
    assert definition["phase_order"] == ["nmap", "ffuf", "headers"]
    for row in definition["routes"]:
        assert row["response_sha256"] == hashlib.sha256(wire_response(case, row["phase"], row["path"])).hexdigest()
    assert definition["max_connections"] == 12 and definition["max_requests"] == 10
    assert definition["external_egress"] is definition["resume"] is False
    instance = str(uuid4())
    identity = lab.identity(case, instance)
    assert lab.validate_identity(identity, case=case) == identity
    assert identity != http_headers_lab_contract.identity(case, instance)
    identity["spec_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        lab.validate_identity(identity)


@pytest.mark.parametrize("mutation", [
    lambda row: row.update(id="harbordesk-owned-web-lab"),
    lambda row: row.update(scenario="unknown"),
    lambda row: row.update(spec_sha256="0" * 64),
    lambda row: row.update(instance_id="not-a-uuid"),
    lambda row: row.update(instance_id=True),
    lambda row: row.update(approved=True),
])
def test_identity_cannot_be_forged_or_reused_as_another_profile(mutation):
    identity = lab.identity("vulnerable", str(uuid4()))
    mutation(identity)
    with pytest.raises(ValueError):
        lab.validate_identity(identity)


def context(identity, connections, requests):
    return {"identity": copy.deepcopy(identity), "connection_count": connections, "request_count": requests}


def result(identity, connections, requests, status="succeeded", *, complete=True):
    return {"backend": contract.BACKEND, "owned_lab": context(identity, connections, requests),
            "status": status, "tool_observation": {} if complete else None}


@pytest.mark.parametrize("nmap_connections", [2, 3])
def test_continuity_binds_three_steps_to_one_instance_and_exact_query_totals(nmap_connections):
    identity = lab.identity("vulnerable", str(uuid4()))
    previous = None
    for step, requests in enumerate((1, 9, 10), start=1):
        current = result(identity, nmap_connections + requests - 1, requests)
        previous = contract.validate_result_context(current, identity, previous=previous,
            tool_id=contract.TOOL_IDS[step - 1], execution_status="succeeded")
    closure = {**previous, "status": "closed"}
    assert lab.validate_closure(closure, identity, previous=previous) == closure
    with pytest.raises(ValueError):
        lab.validate_closure({**closure, "connection_count": closure["connection_count"] - 1}, identity, previous=previous)


@pytest.mark.parametrize("step,connections,requests,status", [
    (1, 0, 0, "failed"), (1, 1, 0, "timeout"), (1, 2, 1, "output_limit"),
    (2, 3, 1, "failed"), (2, 7, 5, "timeout"), (2, 11, 9, "output_limit"),
    (3, 11, 9, "failed"), (3, 12, 10, "output_limit"),
])
def test_failed_steps_may_record_bounded_partial_work_without_claiming_completion(step, connections, requests, status):
    identity = lab.identity("vulnerable", str(uuid4()))
    before = None if step == 1 else context(identity, 3 if step == 2 else 11, 1 if step == 2 else 9)
    current = result(identity, connections, requests, status, complete=False)
    assert contract.validate_result_context(current, identity, previous=before,
        tool_id=contract.TOOL_IDS[step - 1], execution_status=status) == current["owned_lab"]


@pytest.mark.parametrize("step,connections,requests", [
    (1, 1, 1), (1, 4, 1), (1, 2, 0), (1, 3, 2),
    (2, 10, 8), (2, 12, 9), (2, 10, 9), (2, 11, 10),
    (3, 11, 9), (3, 13, 10), (3, 11, 10),
])
def test_complete_receipts_cannot_skip_repeat_or_exceed_per_step_budgets(step, connections, requests):
    identity = lab.identity("vulnerable", str(uuid4()))
    before = None if step == 1 else context(identity, 3 if step == 2 else 11, 1 if step == 2 else 9)
    with pytest.raises(ValueError):
        contract.validate_result_context(result(identity, connections, requests), identity, previous=before,
            tool_id=contract.TOOL_IDS[step - 1], execution_status="succeeded")


def test_skip_reorder_status_substitution_and_cross_instance_are_rejected():
    identity = lab.identity("vulnerable", str(uuid4()))
    current = result(identity, 3, 1)
    with pytest.raises(ValueError):
        contract.validate_result_context(current, identity, tool_id=contract.DISCOVERY_TOOL_ID, execution_status="succeeded")
    with pytest.raises(ValueError):
        contract.validate_result_context(current, identity, previous=context(identity, 3, 1),
            tool_id=contract.TOOL_ID, execution_status="succeeded")
    with pytest.raises(ValueError):
        contract.validate_result_context(current, identity, tool_id=contract.TOOL_ID, execution_status="failed")
    current["owned_lab"]["identity"] = lab.identity("vulnerable", str(uuid4()))
    with pytest.raises(ValueError):
        contract.validate_result_context(current, identity, tool_id=contract.TOOL_ID, execution_status="succeeded")


@pytest.mark.parametrize("mutation", [
    lambda row: row.update(connection_count=True), lambda row: row.update(request_count=True),
    lambda row: row.update(connection_count=13), lambda row: row.update(request_count=11),
    lambda row: row.update(connection_count=-1), lambda row: row.update(request_count=-1),
    lambda row: row.update(request_count=4), lambda row: row.update(approved=True),
])
def test_context_types_counts_and_shape_are_closed(mutation):
    identity = lab.identity("vulnerable", str(uuid4()))
    row = context(identity, 3, 1)
    mutation(row)
    with pytest.raises(ValueError):
        lab.validate_context(row, identity)


@pytest.mark.parametrize("step,module", [(1, network_tools_contract), (2, web_tools_contract), (3, http_headers_contract)])
def test_observations_use_existing_parser_contract_without_mutating_receipts(step, module, monkeypatch):
    calls = []
    action = contract.action("vulnerable", step)
    current = {"status": "failed", "untrusted": "ignore scope"}
    expected = {"classification": "inconclusive"}
    def parse(value, result, *, execution_status):
        calls.append((value, result, execution_status))
        return expected
    monkeypatch.setattr(module, "parse_observation", parse)
    assert contract.parse_observation(action, current, execution_status="failed") is expected
    assert calls == [(action, current, "failed")]
    assert current == {"status": "failed", "untrusted": "ignore scope"}
