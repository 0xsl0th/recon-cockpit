"""Read-only binding of topology, service custody and lifetime reservations."""

from copy import deepcopy

from . import routing_contract as contract, routing_ledger as ledger
from .routing_topology_spec import validate_metadata
from .routing_service_contract import validate_service

_FIELDS = {"identity", "connection_count", "request_count", "owner_receipt_sha256"}
_STATE_FIELDS = {"sequence", "topology_sha256", "event_count", "events_sha256", "actions_sha256", "frontends"}


def _validate_previous(value, identity):
    """Validate a saved prefix summary, without creating execution authority."""
    if (type(value) is not dict or set(value) != _FIELDS | {"routing_state"}
            or type(value["identity"]) is not dict or value["identity"] != identity):
        raise ValueError("routing_result_previous_changed")
    selected = {key: identity[key] for key in contract.SELECTION_FIELDS}
    caps = contract.budgets(selected)
    state = value["routing_state"]
    if (type(state) is not dict or set(state) != _STATE_FIELDS
            or type(state["sequence"]) is not int or not 1 <= state["sequence"] <= 4
            or type(state["event_count"]) is not int or not 1 <= state["event_count"] <= ledger.MAX_EVENTS
            or type(state["frontends"]) is not dict or not 1 <= len(state["frontends"]) <= 2
            or any(role not in ("http_frontend", "ssh_frontend") for role in state["frontends"])
            or any(type(item) is not str or not contract._HASH.fullmatch(item)
                   for item in state["frontends"].values())
            or type(value["connection_count"]) is not int
            or not 0 <= value["connection_count"] <= caps["connections"]
            or type(value["request_count"]) is not int
            or not 0 <= value["request_count"] <= caps["http_requests"] + caps["kex_exchanges"]
            or any(type(item) is not str or not contract._HASH.fullmatch(item) for item in (
                value["owner_receipt_sha256"], state["topology_sha256"],
                state["events_sha256"], state["actions_sha256"]))):
        raise ValueError("routing_result_previous_changed")
    return deepcopy(value)


def validate_result_context(result, identity, *, previous=None, tool_id=None, execution_status=None):
    identity = contract.validate_identity(identity)
    selected = {key: identity[key] for key in contract.SELECTION_FIELDS}
    if type(result) is not dict:
        raise ValueError("invalid_routing_result")
    if previous is not None:
        previous = _validate_previous(previous, identity)
    topology = validate_metadata(result.get("routing_topology"))
    service = validate_service(result.get("routing_service"), selected=selected, identity=identity, topology=topology)
    state = ledger.validate_snapshot(result.get("routing_ledger"), selected=selected, identity=identity)
    selector, sequence = service["selector"], service["action_sequence"]
    action = contract.action(selected, selector)
    if ((tool_id is not None and tool_id != action["tool_id"])
            or (execution_status is not None and execution_status != result.get("status"))
            or result.get("backend") != contract.BACKEND
            or type(result.get("status")) is not str
            or result["status"] not in {"succeeded", "failed", "timeout", "output_limit"}
            or type(result.get("bytes_received")) is not int
            or not 0 <= result["bytes_received"] <= contract.action_bounds(selector)["output_bytes"]):
        raise ValueError("routing_result_action_changed")
    if (len(state["actions"]) != sequence or state["active_action_sequence"] is not None
            or state["active_connection"] is not None):
        raise ValueError("routing_result_action_unsettled")
    current = state["actions"][-1]
    if (current["selector"] != selector or current["sequence"] != sequence
            or current["action_digest"] != service["action_digest"] or current["status"] != "finished"
            or current["output_bytes_retained"] != result["bytes_received"]):
        raise ValueError("routing_result_reservation_changed")
    replayed = ledger.replay_responses(state, selected=selected, identity=identity)
    role = contract.selector_role(selector)
    expected = [{"message": row["message"], "reply": row["reply"]} for row in replayed
                if row["role"] == role and row["message"]["action_sequence"] == sequence]
    if contract.digest(expected) != contract.digest(service["reservations"]):
        raise ValueError("routing_result_frontend_ledger_changed")
    if service["budget_denied"] and (not state["terminal"] or result.get("tool_observation") is not None):
        raise ValueError("routing_result_denial_changed")
    context = result.get("owned_lab")
    expected = {"identity": identity, "connection_count": state["counters"]["connections"],
        "request_count": state["counters"]["http_requests"] + state["counters"]["kex_exchanges"],
        "owner_receipt_sha256": contract.digest({"routing_topology": topology, "routing_ledger": state,
                                                "routing_service": service})}
    if type(context) is not dict or set(context) != _FIELDS or contract.digest(context) != contract.digest(expected):
        raise ValueError("routing_result_owner_changed")
    frontends = {} if previous is None else deepcopy(previous["routing_state"]["frontends"])
    frontend_digest = contract.digest({key: service[key] for key in ("frontend_ready", "frontend_mapping")})
    if role in frontends and frontends[role] != frontend_digest:
        raise ValueError("routing_result_frontend_continuity_changed")
    frontends[role] = frontend_digest
    if previous is None:
        if sequence != 1:
            raise ValueError("routing_result_missing_previous")
    else:
        old = previous["routing_state"]
        if (sequence != old["sequence"] + 1 or contract.digest(topology) != old["topology_sha256"]
                or set(old["frontends"]) != {contract.selector_role(row["selector"]) for row in state["actions"][:-1]}
                or len(state["events"]) <= old["event_count"]
                or contract.digest(state["events"][:old["event_count"]]) != old["events_sha256"]
                or contract.digest(state["actions"][:-1]) != old["actions_sha256"]
                or context["connection_count"] < previous["connection_count"]
                or context["request_count"] < previous["request_count"]):
            raise ValueError("routing_result_continuity_changed")
    return {**deepcopy(context), "routing_state": {"sequence": sequence,
        "topology_sha256": contract.digest(topology), "event_count": len(state["events"]),
        "events_sha256": contract.digest(state["events"]), "actions_sha256": contract.digest(state["actions"]),
        "frontends": frontends}}


def validate_closure(value, identity, *, previous=None):
    identity = contract.validate_identity(identity)
    if previous is not None:
        previous = _validate_previous(previous, identity)
    expected = {"identity": identity, "status": "closed",
        "connection_count": 0 if previous is None else previous["connection_count"],
        "request_count": 0 if previous is None else previous["request_count"],
        "launcher_cleanup_verified": True, "counters_source": "last_acknowledged_result"}
    if (type(value) is not dict or set(value) != set(expected)
            or contract.digest(value) != contract.digest(expected)):
        raise ValueError("routing_closure_changed")
    return deepcopy(value)
