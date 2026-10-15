"""Saved result continuity is verified independently of execution authority."""

from copy import deepcopy
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import routing_context as context, routing_contract as contract
from test_routing_evidence import closure, manifest, routed_results


@pytest.fixture(scope="module")
def complete_chain():
    chosen = manifest()
    with pytest.MonkeyPatch.context() as monkeypatch:
        results = routed_results(monkeypatch, chosen)
    contexts = []
    previous = None
    for result in results:
        previous = context.validate_result_context(result, chosen["identity"], previous=previous)
        contexts.append(previous)
    return chosen, results, contexts


def test_four_actions_preserve_one_topology_and_exact_ledger_prefix(complete_chain):
    chosen, results, contexts = complete_chain
    assert [item["routing_state"]["sequence"] for item in contexts] == [1, 2, 3, 4]
    assert [item["connection_count"] for item in contexts] == [1, 2, 3, 4]
    assert [item["request_count"] for item in contexts] == [1, 2, 2, 3]
    assert len({item["routing_state"]["topology_sha256"] for item in contexts}) == 1
    assert list(contexts[0]["routing_state"]["frontends"]) == ["http_frontend"]
    assert set(contexts[-1]["routing_state"]["frontends"]) == {"http_frontend", "ssh_frontend"}
    final = closure(chosen, 4, 3)
    assert context.validate_closure(final, chosen["identity"], previous=contexts[-1]) == final
    copied = context.validate_result_context(results[1], chosen["identity"], previous=contexts[0])
    copied["identity"]["instance_id"] = str(UUID(int=99))
    copied["routing_state"]["sequence"] = 4
    assert contexts[1]["routing_state"]["sequence"] == 2
    assert contexts[1]["identity"] == chosen["identity"]


@pytest.mark.parametrize("step,previous_index", ((1, None), (0, 0), (2, 0), (1, 1), (3, 0)))
def test_missing_replayed_or_skipped_action_prefix_is_rejected(complete_chain, step, previous_index):
    chosen, results, contexts = complete_chain
    previous = None if previous_index is None else contexts[previous_index]
    with pytest.raises(ValueError):
        context.validate_result_context(results[step], chosen["identity"], previous=previous)


@pytest.mark.parametrize("path,value", (
    (("identity",), None), (("identity", "instance_id"), str(UUID(int=99))),
    (("connection_count",), True), (("connection_count",), -1), (("connection_count",), 9),
    (("request_count",), True), (("request_count",), -1), (("request_count",), 4),
    (("owner_receipt_sha256",), None), (("owner_receipt_sha256",), "A" * 64),
    (("routing_state",), None), (("routing_state",), []), (("routing_state",), {}),
    (("routing_state", "sequence"), True), (("routing_state", "sequence"), 0),
    (("routing_state", "sequence"), 5), (("routing_state", "event_count"), True),
    (("routing_state", "event_count"), 0), (("routing_state", "event_count"), 1025),
    (("routing_state", "topology_sha256"), []), (("routing_state", "events_sha256"), "xyz"),
    (("routing_state", "actions_sha256"), "A" * 64), (("routing_state", "extra"), 1),
    (("routing_state", "frontends"), None), (("routing_state", "frontends"), {}),
    (("routing_state", "frontends"), {"launcher": "a" * 64}),
    (("routing_state", "frontends"), {"http_frontend": True}),
    (("extra",), 1),
))
def test_malformed_previous_is_rejected_by_results_and_closure(complete_chain, path, value):
    chosen, results, contexts = complete_chain
    previous = deepcopy(contexts[0])
    target = previous
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError, match="previous"):
        context.validate_result_context(results[1], chosen["identity"], previous=previous)
    with pytest.raises(ValueError, match="previous"):
        context.validate_closure(closure(chosen, 1, 1), chosen["identity"], previous=previous)


@pytest.mark.parametrize("field,value", (
    ("topology_sha256", "b" * 64), ("events_sha256", "b" * 64),
    ("actions_sha256", "b" * 64), ("event_count", 1),
))
def test_well_formed_but_changed_saved_prefix_is_rejected(complete_chain, field, value):
    chosen, results, contexts = complete_chain
    previous = deepcopy(contexts[0]); previous["routing_state"][field] = value
    with pytest.raises(ValueError, match="continuity"):
        context.validate_result_context(results[1], chosen["identity"], previous=previous)


@pytest.mark.parametrize("frontends", ({"ssh_frontend": "a" * 64}, {"http_frontend": "a" * 64},
    {"http_frontend": "a" * 64, "ssh_frontend": "a" * 64}))
def test_saved_frontend_prefix_cannot_forget_or_invent_a_role(complete_chain, frontends):
    chosen, results, contexts = complete_chain
    previous = deepcopy(contexts[0]); previous["routing_state"]["frontends"] = frontends
    with pytest.raises(ValueError, match="continuity"):
        context.validate_result_context(results[1], chosen["identity"], previous=previous)


@pytest.mark.parametrize("field,value", (("status", []), ("status", "blocked"), ("bytes_received", True),
    ("bytes_received", -1), ("bytes_received", 8193), ("backend", "linux-owned-fixture-v1")))
def test_result_status_output_and_backend_are_strict(complete_chain, field, value):
    chosen, results, _ = complete_chain
    result = deepcopy(results[0]); result[field] = value
    with pytest.raises(ValueError, match="action_changed"):
        context.validate_result_context(result, chosen["identity"])


@pytest.mark.parametrize("arguments", ({"tool_id": "configurable_ssh_host_keys_v1"}, {"execution_status": "failed"}))
def test_result_cannot_be_attributed_to_another_execution(complete_chain, arguments):
    chosen, results, _ = complete_chain
    with pytest.raises(ValueError, match="action_changed"):
        context.validate_result_context(results[0], chosen["identity"], **arguments)


@pytest.mark.parametrize("step", (1, 3))
@pytest.mark.parametrize("field", ("namespace", "mapping"))
def test_frontend_process_and_mapping_must_persist_between_role_actions(complete_chain, step, field):
    chosen, results, contexts = complete_chain
    result = deepcopy(results[step]); service = result["routing_service"]
    if field == "namespace":
        service["frontend_ready"]["namespaces"]["pid"] = "pid:[999]"
    else:
        service["frontend_mapping"].update(uid_map=[[0, 1001, 1]], gid_map=[[0, 1001, 1]],
                                            launcher_uid=1001, launcher_gid=1001)
        daemon_uid = 0 if service["selector"].startswith("http_") else 65534
        service["daemon_mapping"].update(uid_map=[[daemon_uid, 1001, 1]], gid_map=[[daemon_uid, 1001, 1]],
                                          launcher_uid=1001, launcher_gid=1001)
    result["owned_lab"]["owner_receipt_sha256"] = contract.digest({key: result[key] for key in
        ("routing_topology", "routing_ledger", "routing_service")})
    with pytest.raises(ValueError, match="frontend_continuity"):
        context.validate_result_context(result, chosen["identity"], previous=contexts[step - 1])


@pytest.mark.parametrize("field,value", (("connection_count", 3), ("request_count", 2),
    ("launcher_cleanup_verified", False), ("launcher_cleanup_verified", 1),
    ("counters_source", "final_owner_receipt"), ("status", "open")))
def test_closure_requires_physical_cleanup_and_acknowledged_counts(complete_chain, field, value):
    chosen, _, contexts = complete_chain
    final = closure(chosen, 4, 3); final[field] = value
    with pytest.raises(ValueError, match="closure"):
        context.validate_closure(final, chosen["identity"], previous=contexts[-1])


def test_never_started_closure_cannot_invent_observed_work():
    chosen = manifest(["http_headers"])
    assert context.validate_closure(closure(chosen), chosen["identity"])["connection_count"] == 0
    with pytest.raises(ValueError):
        context.validate_closure(closure(chosen, 1, 1), chosen["identity"])


def test_lowered_budget_also_bounds_saved_prefix():
    chosen = manifest(["ssh_keys"], case="ssh_zero")
    previous = {"identity": chosen["identity"], "connection_count": 1, "request_count": 3,
        "owner_receipt_sha256": "a" * 64, "routing_state": {"sequence": 1, "event_count": 2,
            "topology_sha256": "a" * 64, "events_sha256": "a" * 64, "actions_sha256": "a" * 64,
            "frontends": {"ssh_frontend": "a" * 64}}}
    with pytest.raises(ValueError, match="previous"):
        context.validate_closure(closure(chosen, 1, 3), chosen["identity"], previous=previous)
