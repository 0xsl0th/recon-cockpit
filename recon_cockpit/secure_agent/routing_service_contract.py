"""Read-only validation of routed service custody and reservation receipts."""

from copy import deepcopy

from . import routing_contract as contract, routing_ledger as ledger
from . import stock_http_production_contract as http_contract, stock_ssh_contract as ssh_contract
from . import stock_http_recorder as http, stock_ssh_recorder as ssh, stock_ssh_process as process
from .stock_http_owner_worker import BOUNDS
from .stock_ssh_owner_worker import validate_connected_identity


FIELDS = {"selector", "action_sequence", "action_digest", "underlying_selection", "daemon_ready",
    "daemon_mapping", "frontend_ready", "frontend_mapping", "recorder", "instances", "reservations",
    "budget_denied", "last_budget_reply", "closure"}


def validate_service(value, *, selected, identity, topology):
    selected = contract.validate_selection(selected)
    identity = contract.validate_identity(identity, selection=selected)
    if type(value) is not dict or set(value) != FIELDS:
        raise ValueError("routing_service_receipt_fields")
    selector = contract.validate_selector(value["selector"])
    role = contract.selector_role(selector)
    chosen = contract.underlying_selection(selector)
    if (type(value["action_sequence"]) is not int or not 1 <= value["action_sequence"] <= 4
            or value["action_digest"] != contract.digest(contract.action(selected, selector))
            or contract.digest(value["underlying_selection"]) != contract.digest(chosen)
            or type(value["budget_denied"]) is not bool):
        raise ValueError("routing_service_action_changed")
    front, daemon = value["frontend_ready"], value["daemon_ready"]
    if (type(front) is not dict or set(front) != {"ready", "role", "namespaces", "listener", "bounds", "private_pairs"}
            or front["ready"] is not True or front["role"] != role
            or contract.digest(front["bounds"]) != contract.digest(BOUNDS)
            or front["listener"] != (["10.77.0.10", 8080] if role == "http_frontend" else ["10.77.0.20", 2222])):
        raise ValueError("routing_service_frontend_changed")
    namespaces = ssh_contract.validate_namespaces(front["namespaces"])
    owner_namespaces = ssh_contract.validate_namespaces(topology["owner_namespaces"])
    if (namespaces["net"] != topology["networks"][role]
            or any(namespaces[name] == owner_namespaces[name] for name in ("user", "mnt", "pid"))):
        raise ValueError("routing_service_frontend_namespace_changed")
    if type(daemon) is not dict:
        raise ValueError("routing_service_daemon_changed")
    daemon_namespaces = ssh_contract.validate_namespaces(daemon.get("namespaces"))
    if (any(daemon_namespaces[name] in (namespaces[name], owner_namespaces[name]) for name in namespaces)
            or daemon_namespaces["net"] in topology["networks"].values()):
        raise ValueError("routing_service_daemon_namespace_changed")
    daemon_digest = identity["runtimes"][selector]["daemon_runtime_sha256"]
    if role == "http_frontend":
        if (type(daemon) is not dict or set(daemon) != {"namespaces", "bounds", "runtime_digest", "namespace_identity", "descriptor"}
                or contract.digest(daemon["bounds"]) != contract.digest(BOUNDS)
                or daemon["runtime_digest"] != daemon_digest or daemon["descriptor"] is not None
                or front["private_pairs"] != [] or value["instances"] != []):
            raise ValueError("routing_service_nginx_changed")
        http_contract.validate_daemon_identity(daemon["namespace_identity"], "nginx")
    else:
        ssh_contract.validate_custodian_ready(daemon, runtime_digest=daemon_digest, namespaces=daemon_namespaces)
        expected_pairs = [row["daemon"] for row in topology["private_ssh_pairs"]]
        if len(expected_pairs) != 4 or front["private_pairs"] != expected_pairs:
            raise ValueError("routing_service_private_pairs_changed")
        for pair in expected_pairs:
            validate_connected_identity(pair)
        if len({pair["inode"] for pair in expected_pairs}) != 4:
            raise ValueError("routing_service_private_pair_reused")
    front_mapping = http_contract.validate_launcher_mapping(value["frontend_mapping"], "nginx")
    daemon_mapping = http_contract.validate_launcher_mapping(value["daemon_mapping"], "nginx" if role == "http_frontend" else "apache")
    if any(front_mapping[key] != daemon_mapping[key] for key in ("launcher_uid", "launcher_gid")):
        raise ValueError("routing_service_launcher_changed")
    record = (http if role == "http_frontend" else ssh).validate_snapshot(value["recorder"], configuration="A", case=chosen["case"])
    if (record["armed"] is not True or record["finalized"] is not True
            or record["active_connections"] or record["pending_connections"]):
        raise ValueError("routing_service_connections_not_closed")
    if role == "ssh_frontend":
        connected = [row for row in record["connections"] if row["daemon_connected"]]
        if type(value["instances"]) is not list or len(value["instances"]) != len(connected):
            raise ValueError("routing_service_instance_count_changed")
        offset = 0 if selector == "ssh_nmap" else 3
        for index, (instance, connection) in enumerate(zip(value["instances"], connected, strict=True)):
            if (type(instance) is not dict or set(instance) != {"connection_id", "receipt"}
                    or type(instance["connection_id"]) is not int or instance["connection_id"] != connection["id"]):
                raise ValueError("routing_service_instance_identity_changed")
            receipt = process.validate_receipt(instance["receipt"])
            if receipt["descriptor"] != expected_pairs[offset + index]:
                raise ValueError("routing_service_instance_descriptor_changed")
    closure = {"daemon_processes_reaped": True, "action_connections_closed": True,
               "frontend_persists": True, "topology_persists": True}
    if type(value["closure"]) is not dict or contract.digest(value["closure"]) != contract.digest(closure):
        raise ValueError("routing_service_cleanup_changed")
    _reservations(value, record, role)
    return deepcopy(value)


def _reservations(value, record, role):
    rows = value["reservations"]
    if type(rows) is not list or len(rows) > 128:
        raise ValueError("routing_service_reservation_limit")
    lease, sequence, connections, requests, denied = None, None, 0, 0, False
    totals = {"request": 0, "response": 0}
    for row in rows:
        if type(row) is not dict or set(row) != {"message", "reply"}:
            raise ValueError("routing_service_reservation_fields")
        message, reply = row["message"], row["reply"]
        if (type(message) is not dict or message.get("operation") not in
                {"RESERVE_CONNECTION", "RESERVE_REQUEST", "RESERVE_BYTES", "FINISH_CONNECTION"}
                or set(message) != ledger._COMMON | ledger._EXTRA[message["operation"]]):
            raise ValueError("routing_service_reservation_message_fields")
        # Full owner replay independently enforces budget, rate and role state.
        # Here bind each frontend receipt and its accepted byte accounting.
        ledger.validate_reply(reply, message, role=role)
        if (type(message["sequence"]) is not int or message["sequence"] < 1
                or sequence is not None and message["sequence"] != sequence + 1
                or type(message["action_sequence"]) is not int
                or message["action_sequence"] != value["action_sequence"]
                or message["action_digest"] != value["action_digest"]):
            raise ValueError("routing_service_reservation_binding_changed")
        sequence = message["sequence"]
        operation = message["operation"]
        if operation not in {"RESERVE_CONNECTION", "RESERVE_REQUEST", "RESERVE_BYTES", "FINISH_CONNECTION"}:
            raise ValueError("routing_service_reservation_operation_changed")
        if denied and operation != "FINISH_CONNECTION":
            raise ValueError("routing_service_reservation_after_denial")
        if operation == "RESERVE_CONNECTION":
            if lease is not None or type(message.get("local_id")) is not int or message["local_id"] != connections + 1:
                raise ValueError("routing_service_connection_order_changed")
        elif lease is None or message.get("lease") != lease:
            raise ValueError("routing_service_reservation_lease_changed")
        if reply["status"] == "denied":
            denied = True
            continue
        if reply["status"] == "wait":
            if operation != "RESERVE_CONNECTION":
                raise ValueError("routing_service_invalid_wait")
            continue
        if operation == "RESERVE_CONNECTION":
            lease = reply["lease"]
            connections += 1
        elif operation == "FINISH_CONNECTION":
            lease = None
        elif operation == "RESERVE_REQUEST":
            if message["kind"] != ("http" if role == "http_frontend" else "kex"):
                raise ValueError("routing_service_request_kind_changed")
            requests += 1
        elif operation == "RESERVE_BYTES":
            if (message["direction"] not in totals or type(message["bytes"]) is not int
                    or not 0 < message["bytes"] <= 8192):
                raise ValueError("routing_service_byte_reservation_changed")
            totals[message["direction"]] += message["bytes"]
    if (lease is not None or connections != record["connections_admitted"]
            or value["budget_denied"] is not denied
            or value["last_budget_reply"] != (rows[-1]["reply"] if rows else None)):
        raise ValueError("routing_service_reservation_cleanup_changed")
    bounds = contract.action_bounds(value["selector"])
    actual_request = record["request_bytes_delivered"] if role == "http_frontend" else record["client_bytes_forwarded"]
    actual_response = record["client_response_bytes"] if role == "http_frontend" else record["client_bytes_delivered"]
    if (not actual_request <= totals["request"] <= bounds["request_bytes"]
            or not actual_response <= totals["response"] <= bounds["response_bytes"]
            or not int(actual_request > 0) <= requests <= bounds["http_requests"] + bounds["kex_exchanges"]):
        raise ValueError("routing_service_unreserved_payload")
