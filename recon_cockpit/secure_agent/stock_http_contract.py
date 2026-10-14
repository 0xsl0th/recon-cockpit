"""Closed one-action stock HTTP diagnostic; no catalog or workflow authority."""

from copy import deepcopy
import base64
import hashlib
import re
from uuid import UUID

from . import stock_http_spec as spec
from .models import Action, parse_policy

PROFILE = "stock_nginx_diagnostic_v1"
BACKEND = "linux-authorized-stock-nginx-diagnostic-v1"
_HASH = re.compile(r"[a-f0-9]{64}\Z")


def selection(configuration, case):
    spec.validate_selection(configuration, case)
    return {"configuration": configuration, "case": case,
            "selection_sha256": spec.selection_digest(configuration, case)}


def validate_selection(value):
    if (type(value) is not dict or set(value) != {"configuration", "case", "selection_sha256"}
            or value != selection(value["configuration"], value["case"])):
        raise ValueError("invalid_stock_http_selection")
    return deepcopy(value)


def action(value):
    value = validate_selection(value)
    return spec.action(value["configuration"], value["case"])


def scope(value):
    value = validate_selection(value)
    return spec._scope(value["configuration"])


def limits(value):
    selected = action(value)
    return {"max_steps": 1, "max_runtime_seconds": 60,
            "max_output_bytes": selected["parameters"]["max_output_bytes"]}


def validate_limits(value, selected):
    expected = limits(selected)
    if (type(value) is not dict or set(value) != set(expected)
            or any(type(value[key]) is not int or value[key] != expected[key] for key in expected)):
        raise ValueError("invalid_stock_http_limits")
    return dict(value)


def profile_allows(value, selected):
    try:
        return type(value) is Action and value.to_dict() == action(selected)
    except (ValueError, KeyError, TypeError):
        return False


def policy_for_selection(selected, *, require_approval=True):
    selected = validate_selection(selected)
    value = action(selected)
    parameters = value["parameters"]
    version = "stock-http-" + base64.b32encode(bytes.fromhex(selected["selection_sha256"])).decode("ascii").rstrip("=").lower()
    return parse_policy({"schema_version": "1", "policy_version": version,
        "allowed_targets": [value["target"]], "allowed_tools": [value["tool_id"]],
        "allowed_ports": [parameters["port"]], "allowed_methods": ["GET"],
        "max_timeout_seconds": parameters["timeout_seconds"],
        "max_output_bytes": parameters["max_output_bytes"], "max_targets": 1,
        "require_approval": require_approval, "approval_ttl_seconds": 60})


def validate_policy(value, selected):
    policy = parse_policy(value)
    if policy.to_dict() != policy_for_selection(selected, require_approval=policy.require_approval).to_dict():
        raise ValueError("stock_http_policy_binding_changed")
    return policy


def validate_runtime(value, selected):
    from .stock_http_runtime import validate_manifest
    from .stock_http_client_runtime import validate_client_runtime

    selected = validate_selection(selected)
    if type(value) is not dict or set(value) != {"daemon", "client"}:
        raise ValueError("invalid_stock_http_runtime")
    daemon = validate_manifest(value["daemon"])
    if any(daemon[key] != selected[key] for key in ("configuration", "case", "selection_sha256")):
        raise ValueError("stock_http_daemon_selection_changed")
    return {"daemon": daemon, "client": validate_client_runtime(value["client"], selected)}


def runtime_digests(value, selected):
    from .stock_http_runtime import manifest_digest
    from .network_tools_runtime import manifest_digest as client_digest

    value = validate_runtime(value, selected)
    return {"daemon_runtime_sha256": manifest_digest(value["daemon"]),
            "client_runtime_sha256": None if value["client"] is None else client_digest(value["client"])}


def runtime_source_mounts(value, selected):
    from .network_tools_runtime import runtime_source_mounts as client_mounts
    value = validate_runtime(value, selected)
    paths = {(row["source"], row["source"]) for row in value["daemon"]["files"]
             if not row["source"].startswith("compiled:")}
    # Retain the reviewed aliases for read-only pin verification in the
    # confined launcher. No broad library directory or host config is exposed.
    for row in value["daemon"]["files"]:
        if not row["source"].startswith("compiled:") and row["destination"] != "/tool/nginx":
            paths.add((row["source"], row["destination"]))
    if value["client"] is not None:
        paths.update(client_mounts(value["client"]))
    return sorted(paths)


def validate_identity(value, *, selection=None, session_id=None, runtime=None):
    fields = {"version", "profile", "instance_id", "session_id", "configuration", "case",
              "selection_sha256", "daemon_runtime_sha256", "client_runtime_sha256"}
    if (type(value) is not dict or set(value) != fields or value["version"] != "1"
            or value["profile"] != PROFILE):
        raise ValueError("invalid_stock_http_identity")
    for field in ("instance_id", "session_id"):
        if type(value[field]) is not str or str(UUID(value[field])) != value[field]:
            raise ValueError("invalid_stock_http_identity")
    selected = validate_selection({key: value[key] for key in ("configuration", "case", "selection_sha256")})
    if ((selection is not None and selected != validate_selection(selection))
            or (session_id is not None and value["session_id"] != session_id)):
        raise ValueError("stock_http_owner_binding_changed")
    if type(value["daemon_runtime_sha256"]) is not str or not _HASH.fullmatch(value["daemon_runtime_sha256"]):
        raise ValueError("invalid_stock_http_daemon_digest")
    client = value["client_runtime_sha256"]
    if spec.action_kind(selected["case"]) == "headers":
        if client is not None:
            raise ValueError("unexpected_stock_http_client_runtime")
    elif type(client) is not str or not _HASH.fullmatch(client):
        raise ValueError("invalid_stock_http_client_digest")
    if runtime is not None and any(value[key] != item for key, item in runtime_digests(runtime, selected).items()):
        raise ValueError("stock_http_runtime_binding_changed")
    return deepcopy(value)


def validate_context(value, expected):
    expected = validate_identity(expected)
    fields = {"identity", "connection_count", "request_count", "owner_receipt_sha256"}
    if (type(value) is not dict or set(value) != fields or value["identity"] != expected
            or type(value["connection_count"]) is not int or not 0 <= value["connection_count"] <= spec.budgets(expected["case"])["max_connections"]
            or type(value["request_count"]) is not int or not 0 <= value["request_count"] <= 1
            or value["request_count"] > value["connection_count"]
            or type(value["owner_receipt_sha256"]) is not str or not _HASH.fullmatch(value["owner_receipt_sha256"])):
        raise ValueError("invalid_stock_http_result_context")
    return deepcopy(value)


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    expected = validate_identity(expected)
    selected = {key: expected[key] for key in ("configuration", "case", "selection_sha256")}
    if (previous is not None or result.get("backend") != BACKEND
            or tool_id != action(selected)["tool_id"] or result.get("status") != execution_status
            or execution_status not in ("succeeded", "failed", "timeout", "output_limit")):
        raise ValueError("invalid_stock_http_result_binding")
    context = validate_context(result.get("owned_lab"), expected)
    receipt = result.get("stock_http_owner")
    if (type(receipt) is not dict or hashlib.sha256(spec.encode(receipt)).hexdigest() != context["owner_receipt_sha256"]):
        raise ValueError("stock_http_owner_receipt_changed")
    validate_owner_snapshot(receipt, expected)
    if any(context[key] != receipt[key] for key in ("connection_count", "request_count")):
        raise ValueError("stock_http_owner_counters_changed")
    validate_owner_closure(result.get("stock_http_closure"), expected, receipt)
    if result.get("tool_observation") is not None and context["request_count"] != 1:
        raise ValueError("stock_http_observation_without_request")
    return context


def validate_owner_snapshot(value, expected):
    from .stock_http_recorder import validate_snapshot
    expected = validate_identity(expected)
    if type(value) is not dict or set(value) != {"connection_count", "request_count", "recorder", "owner"}:
        raise ValueError("invalid_stock_http_owner_snapshot")
    ledger = validate_snapshot(value["recorder"], configuration=expected["configuration"], case=expected["case"])
    if (ledger["armed"] is not True or ledger["finalized"] is not True
            or type(value["connection_count"]) is not int or value["connection_count"] != ledger["connections_admitted"]
            or type(value["request_count"]) is not int or value["request_count"] != ledger["requests_delivered"]):
        raise ValueError("stock_http_owner_accounting_changed")
    owner = value["owner"]
    fields = {"recorder_namespaces", "daemon_namespaces", "witness_baselines", "recorder_bounds", "daemon_bounds",
              "private_socket_unmounted_from_client", "daemon_ready"}
    if (type(owner) is not dict or set(owner) != fields or any(owner[key] is not True for key in
            ("witness_baselines", "private_socket_unmounted_from_client", "daemon_ready"))):
        raise ValueError("invalid_stock_http_owner_boundary")
    for key in ("recorder_namespaces", "daemon_namespaces"):
        namespaces = owner[key]
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(name + r":\[\d+\]", item) is None
                       for name, item in namespaces.items())):
            raise ValueError("invalid_stock_http_owner_namespaces")
    if any(owner["recorder_namespaces"][key] == owner["daemon_namespaces"][key] for key in owner["recorder_namespaces"]):
        raise ValueError("stock_http_owners_not_separate")
    bounds = {"address_space_bytes": 268435456, "file_descriptors": 64,
              "scratch_bytes": 786432, "retained_evidence_bytes": 262144,
              "aggregate_storage_bytes": 1048576, "no_children": True}
    for key in ("recorder_bounds", "daemon_bounds"):
        if (type(owner[key]) is not dict or owner[key] != bounds
                or any(type(owner[key][name]) is not type(item) for name, item in bounds.items())):
            raise ValueError("stock_http_owner_bounds_changed")
    return deepcopy(value)


def validate_owner_closure(value, expected, snapshot):
    expected = validate_identity(expected)
    fields = {"identity", "status", "started", "connection_count", "request_count", "recorder",
              "processes_reaped", "namespace_descriptors_closed"}
    if (type(value) is not dict or set(value) != fields or value["identity"] != expected
            or value["status"] != "closed" or value["started"] is not True
            or value["processes_reaped"] is not True or value["namespace_descriptors_closed"] is not True
            or value["recorder"] != snapshot["recorder"]
            or any(type(value[key]) is not int or value[key] != snapshot[key]
                   for key in ("connection_count", "request_count"))):
        raise ValueError("stock_http_owner_cleanup_unverified")
    return deepcopy(value)


def validate_closure(value, expected, *, previous=None):
    expected = validate_identity(expected)
    if (type(value) is not dict or value.get("status") != "closed"
            or set(value) != {"identity", "connection_count", "request_count", "status"}
            or value["identity"] != expected
            or any(type(value[key]) is not int or value[key] < 0 for key in ("connection_count", "request_count"))):
        raise ValueError("invalid_stock_http_closure")
    before = previous or {"connection_count": 0, "request_count": 0}
    if any(value[key] != before[key] for key in ("connection_count", "request_count")):
        raise ValueError("stock_http_cleanup_counters_changed")
    return deepcopy(value)
