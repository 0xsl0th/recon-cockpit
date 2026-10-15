"""Separate one-action stock SSH commitment; never issues launch authority."""

from copy import deepcopy
import base64
import hashlib
import re
from uuid import UUID

from . import stock_ssh_spec as spec
from . import stock_ssh_process as process
from . import stock_ssh_nmap_spec as nmap
from .models import Action, parse_policy

PROFILE = "stock_ssh_compatibility_v1"
BACKEND = "linux-authorized-stock-ssh-compatibility-v1"
BOUNDARY_REVISION = "finite-inetd-custody-v1"
SELECTION_FIELDS = ("configuration", "case", "selection_sha256")
EVIDENCE_BOUNDS = {"max_total_bytes": 1048576, "max_json_bytes": 262144, "max_json_depth": 64, "max_files": 6}
_HASH = re.compile(r"[a-f0-9]{64}\Z")


def selection(configuration, case):
    spec.validate_selection(configuration, case)
    commitment = {"profile": PROFILE, "boundary_revision": BOUNDARY_REVISION,
        "preparation_selection_sha256": spec.selection_digest(configuration, case),
        "process_profile": process.PROFILE, "process_bounds": process.BOUNDS,
        "evidence_artifacts": EVIDENCE_BOUNDS,
        "custodian": {"processes": 1, "address_space_bytes": 268435456,
                      "file_descriptors": 64, "retained_bytes": 1048576},
        "client_recognition": {"profile": nmap.PROFILE,
                               "probes_sha256": hashlib.sha256(nmap.PROBES).hexdigest()},
        "private_transport": "preconnected-loopback-tcp-descriptor-no-live-listener",
        "launcher_mapping": "single-id-to-positive-launcher-uid-gid-before-server-input",
        "native_validation_required": True}
    return {"configuration": configuration, "case": case,
            "selection_sha256": hashlib.sha256(spec.encode(commitment)).hexdigest()}


def validate_selection(value):
    if (type(value) is not dict or set(value) != set(SELECTION_FIELDS)
            or value != selection(value["configuration"], value["case"])):
        raise ValueError("invalid_stock_ssh_selection")
    return deepcopy(value)


def preparation_selection(value):
    value = validate_selection(value)
    return {"configuration": value["configuration"], "case": value["case"],
            "selection_sha256": spec.selection_digest(value["configuration"], value["case"])}


def action(value):
    value = validate_selection(value)
    return spec.action(value["configuration"], value["case"])


def scope(value):
    return spec._scope(validate_selection(value)["configuration"])


def limits(value):
    selected = action(value)
    return {"max_steps": 1, "max_runtime_seconds": 60,
            "max_output_bytes": selected["parameters"]["max_output_bytes"]}


def validate_limits(value, selected):
    expected = limits(selected)
    if (type(value) is not dict or set(value) != set(expected)
            or any(type(value[key]) is not int or value[key] != item for key, item in expected.items())):
        raise ValueError("invalid_stock_ssh_limits")
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
    version = "stock-ssh-" + base64.b32encode(bytes.fromhex(selected["selection_sha256"])).decode("ascii").rstrip("=").lower()
    return parse_policy({"schema_version": "1", "policy_version": version,
        "allowed_targets": [value["target"]], "allowed_tools": [value["tool_id"]],
        "allowed_ports": [parameters["port"]], "allowed_methods": ["GET"],
        "max_timeout_seconds": parameters["timeout_seconds"],
        "max_output_bytes": parameters["max_output_bytes"], "max_targets": 1,
        "require_approval": require_approval, "approval_ttl_seconds": 60})


def validate_policy(value, selected):
    policy = parse_policy(value)
    if policy.to_dict() != policy_for_selection(selected, require_approval=policy.require_approval).to_dict():
        raise ValueError("stock_ssh_policy_binding_changed")
    return policy


def validate_runtime(value, selected):
    from . import stock_ssh_runtime as daemon
    from . import stock_ssh_nmap_runtime as client
    from . import network_tools_runtime as keyscan
    selected = validate_selection(selected)
    if type(value) is not dict or set(value) != {"daemon", "client"}:
        raise ValueError("invalid_stock_ssh_runtime")
    manifest = daemon.validate_manifest(value["daemon"])
    if any(manifest[key] != item for key, item in preparation_selection(selected).items()):
        raise ValueError("stock_ssh_runtime_selection_changed")
    native = client.validate_manifest(value["client"]) if spec.action_kind(selected["case"]) == "nmap" else keyscan.validate_manifest(value["client"])
    if spec.action_kind(selected["case"]) != "nmap" and native["tool_id"] != keyscan.SSH:
        raise ValueError("stock_ssh_client_changed")
    return {"daemon": manifest, "client": native}


def runtime_digests(value, selected):
    from . import stock_ssh_runtime as daemon
    from . import stock_ssh_nmap_runtime as client
    from . import network_tools_runtime as keyscan
    value = validate_runtime(value, selected)
    digest = client.manifest_digest if spec.action_kind(selected["case"]) == "nmap" else keyscan.manifest_digest
    return {"daemon_runtime_sha256": daemon.manifest_digest(value["daemon"]),
            "client_runtime_sha256": digest(value["client"])}


def validate_identity(value, *, selection=None, session_id=None, runtime=None):
    fields = {"version", "profile", "instance_id", "session_id", *SELECTION_FIELDS,
              "daemon_runtime_sha256", "client_runtime_sha256"}
    if (type(value) is not dict or set(value) != fields or value["version"] != "1" or value["profile"] != PROFILE):
        raise ValueError("invalid_stock_ssh_identity")
    for key in ("instance_id", "session_id"):
        if type(value[key]) is not str or str(UUID(value[key])) != value[key]:
            raise ValueError("invalid_stock_ssh_identity")
    selected = validate_selection({key: value[key] for key in SELECTION_FIELDS})
    if ((selection is not None and selected != validate_selection(selection))
            or (session_id is not None and value["session_id"] != session_id)):
        raise ValueError("stock_ssh_identity_binding_changed")
    for key in ("daemon_runtime_sha256", "client_runtime_sha256"):
        if type(value[key]) is not str or not _HASH.fullmatch(value[key]):
            raise ValueError("invalid_stock_ssh_runtime_digest")
    if runtime is not None and any(value[key] != item for key, item in runtime_digests(runtime, selected).items()):
        raise ValueError("stock_ssh_identity_runtime_changed")
    return deepcopy(value)


def runtime_source_mounts(value, selected):
    from .stock_ssh_client_runtime import runtime_source_mounts as client_mounts
    value = validate_runtime(value, selected)
    paths = {(row["source"], row["source"]) for row in value["daemon"]["files"]
             if not row["source"].startswith("compiled:")}
    for row in value["daemon"]["files"]:
        if not row["source"].startswith("compiled:") and row["destination"] != "/tool/sshd":
            paths.add((row["source"], row["destination"]))
    paths.update(client_mounts(value["client"], selected))
    return sorted(paths)


def validate_namespaces(value):
    if (type(value) is not dict or set(value) != {"user", "net", "mnt", "pid"}
            or any(type(item) is not str or re.fullmatch(name + r":\[\d+\]", item) is None
                   for name, item in value.items())):
        raise ValueError("invalid_stock_ssh_owner_namespaces")
    return dict(value)


def validate_custodian_ready(value, *, runtime_digest, namespaces):
    from .stock_http_production_contract import validate_daemon_identity
    fields = {"ready", "namespaces", "namespace_identity", "bounds", "runtime_digest"}
    if (type(value) is not dict or set(value) != fields or value["ready"] is not True
            or value["namespaces"] != validate_namespaces(namespaces)
            or value["runtime_digest"] != runtime_digest or value["bounds"] != process.BOUNDS
            or spec.encode(value["bounds"]) != spec.encode(process.BOUNDS)):
        raise ValueError("invalid_stock_ssh_custodian_ready")
    validate_daemon_identity(value["namespace_identity"], "apache")
    return deepcopy(value)


def validate_recorder_ready(value, *, runtime_digest, namespaces, custodian_namespaces, selected=None):
    from .stock_http_owner_worker import BOUNDS
    from .stock_ssh_owner_worker import validate_private_transport
    fields = {"ready", "namespaces", "witness_baselines", "bounds", "runtime_digest", "private_transport"}
    if (type(value) is not dict or set(value) != fields or value["ready"] is not True
            or value["namespaces"] != validate_namespaces(namespaces)
            or value["runtime_digest"] != runtime_digest or value["witness_baselines"] is not True
            or value["bounds"] != BOUNDS or spec.encode(value["bounds"]) != spec.encode(BOUNDS)):
        raise ValueError("invalid_stock_ssh_recorder_ready")
    if any(value["namespaces"][name] == item for name, item in validate_namespaces(custodian_namespaces).items()):
        raise ValueError("stock_ssh_owners_not_separate")
    validate_private_transport(value["private_transport"], selected)
    return deepcopy(value)


def validate_owner_snapshot(value, expected):
    from .stock_ssh_recorder import validate_snapshot
    from .stock_http_production_contract import validate_launcher_mapping
    expected = validate_identity(expected)
    selected = {key: expected[key] for key in SELECTION_FIELDS}
    if type(value) is not dict or set(value) != {"connection_count", "request_count", "recorder", "instances", "owner"}:
        raise ValueError("invalid_stock_ssh_owner_snapshot")
    ledger = validate_snapshot(value["recorder"], configuration=expected["configuration"], case=expected["case"])
    if (ledger["armed"] is not True or ledger["finalized"] is not True
            or type(value["connection_count"]) is not int or value["connection_count"] != ledger["connections_admitted"]
            or type(value["request_count"]) is not int or value["request_count"] != ledger["server_key_replies_forwarded"]):
        raise ValueError("stock_ssh_owner_accounting_changed")
    owner = value["owner"]
    if (type(owner) is not dict or set(owner) != {"recorder", "custodian", "launcher_mapping"}
            or type(owner["recorder"]) is not dict or type(owner["custodian"]) is not dict):
        raise ValueError("invalid_stock_ssh_owner_boundary")
    validate_custodian_ready(owner["custodian"], runtime_digest=expected["daemon_runtime_sha256"],
                             namespaces=owner["custodian"].get("namespaces"))
    validate_recorder_ready(owner["recorder"], runtime_digest=expected["daemon_runtime_sha256"],
        namespaces=owner["recorder"].get("namespaces"), custodian_namespaces=owner["custodian"]["namespaces"], selected=selected)
    validate_launcher_mapping(owner["launcher_mapping"], "apache")
    instances = value["instances"]
    connected = [row for row in ledger["connections"] if row["daemon_connected"]]
    if (type(instances) is not list or len(instances) != len(connected)
            or len(instances) > spec.budgets(expected["case"])["max_connections"]):
        raise ValueError("stock_ssh_instance_accounting_changed")
    for index, (instance, row) in enumerate(zip(instances, connected, strict=True)):
        if (type(instance) is not dict or set(instance) != {"connection_id", "receipt"}
                or type(instance["connection_id"]) is not int or instance["connection_id"] != row["id"]):
            raise ValueError("stock_ssh_instance_identity_changed")
        process.validate_receipt(instance["receipt"])
        if instance["receipt"]["descriptor"] != owner["recorder"]["private_transport"]["pairs"][index]:
            raise ValueError("stock_ssh_instance_descriptor_changed")
    return deepcopy(value)


def validate_context(value, expected):
    expected = validate_identity(expected)
    fields = {"identity", "connection_count", "request_count", "owner_receipt_sha256"}
    if (type(value) is not dict or set(value) != fields or value["identity"] != expected
            or type(value["connection_count"]) is not int or not 0 <= value["connection_count"] <= spec.budgets(expected["case"])["max_connections"]
            or type(value["request_count"]) is not int or not 0 <= value["request_count"] <= 1
            or value["request_count"] > value["connection_count"]
            or type(value["owner_receipt_sha256"]) is not str or not _HASH.fullmatch(value["owner_receipt_sha256"])):
        raise ValueError("invalid_stock_ssh_result_context")
    if expected["case"] in spec.NMAP_CASES and value["request_count"] != 0:
        raise ValueError("stock_ssh_banner_client_sent_request")
    return deepcopy(value)


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    expected = validate_identity(expected)
    selected = {key: expected[key] for key in SELECTION_FIELDS}
    if (previous is not None or result.get("backend") != BACKEND or tool_id != action(selected)["tool_id"]
            or result.get("status") != execution_status or execution_status not in ("succeeded", "failed", "timeout", "output_limit")):
        raise ValueError("invalid_stock_ssh_result_binding")
    context = validate_context(result.get("owned_lab"), expected)
    receipt = result.get("stock_ssh_owner")
    if type(receipt) is not dict or hashlib.sha256(spec.encode(receipt)).hexdigest() != context["owner_receipt_sha256"]:
        raise ValueError("stock_ssh_owner_receipt_changed")
    validate_owner_snapshot(receipt, expected)
    if any(context[key] != receipt[key] for key in ("connection_count", "request_count")):
        raise ValueError("stock_ssh_owner_counters_changed")
    validate_owner_closure(result.get("stock_ssh_closure"), expected, receipt)
    if result.get("tool_observation") is not None:
        if context["connection_count"] == 0 or selected["case"] not in spec.NMAP_CASES and context["request_count"] != 1:
            raise ValueError("stock_ssh_observation_without_exchange")
    return context


def validate_owner_closure(value, expected, snapshot):
    expected = validate_identity(expected)
    fields = {"identity", "status", "started", "connection_count", "request_count", "recorder", "instances",
              "processes_reaped", "namespace_descriptors_closed"}
    if (type(value) is not dict or set(value) != fields or value["identity"] != expected
            or value["status"] != "closed" or value["started"] is not True
            or value["processes_reaped"] is not True or value["namespace_descriptors_closed"] is not True
            or spec.encode(value["recorder"]) != spec.encode(snapshot["recorder"])
            or spec.encode(value["instances"]) != spec.encode(snapshot["instances"])
            or any(type(value[key]) is not int or value[key] != snapshot[key] for key in ("connection_count", "request_count"))):
        raise ValueError("stock_ssh_owner_cleanup_unverified")
    return deepcopy(value)


def validate_closure(value, expected, *, previous=None):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count", "status"}
            or value.get("status") != "closed" or value["identity"] != expected
            or any(type(value[key]) is not int or value[key] < 0 for key in ("connection_count", "request_count"))):
        raise ValueError("invalid_stock_ssh_closure")
    before = previous or {"connection_count": 0, "request_count": 0}
    if any(value[key] != before[key] for key in ("connection_count", "request_count")):
        raise ValueError("stock_ssh_cleanup_counters_changed")
    return deepcopy(value)
