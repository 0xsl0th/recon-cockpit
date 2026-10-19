"""Detached result/closure consistency; replay never creates a live owner."""

import base64
from copy import deepcopy
import hashlib
import json

from . import name_tls_contract as contract, name_tls_ledger as ledger
from . import name_tls_parser as parser, name_tls_public as public
from .name_tls_topology_spec import validate_metadata, validate_namespace_identity

RESULT_FIELDS = {"status", "results", "tool_observation", "bytes_received", "truncated", "boundary_checks", "timing",
                 "raw_output_base64", "raw_stderr_base64", "provenance", "name_tls_service", "backend",
                 "name_tls_ledger", "name_tls_messages", "name_tls_topology", "owned_lab", "client_observation"}
SERVICE_FIELDS = {"slot", "action_sequence", "action_digest", "action", "daemon_ready", "daemon_mapping", "native_ready",
                  "frontend_ready", "frontend_mapping", "recorder", "reservations", "descriptor_custody", "budget_denied",
                  "last_budget_reply", "parser_input_base64", "parsed", "parser_receipt", "binding", "closure", "parser_error"}
CONTEXT_FIELDS = {"identity", "sequence", "connection_count", "request_count", "binding", "topology_sha256",
                  "event_count", "events_sha256", "actions_sha256", "message_count", "messages_sha256", "frontends"}


def _base64(value, maximum):
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError("name_tls_context_encoding_limit")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ValueError("name_tls_context_encoding") from error
    if len(raw) > maximum or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("name_tls_context_encoding")
    return raw


def _previous(value, identity):
    if (type(value) is not dict or set(value) != CONTEXT_FIELDS or value["identity"] != identity
            or any(type(value[k]) is not int or not 0 <= value[k] <= cap for k, cap in
                   (("sequence", 3), ("connection_count", 3), ("request_count", 3), ("event_count", 1024), ("message_count", 1024)))
            or value["sequence"] < 1 or any(not contract._hash(value[k]) for k in
                   ("topology_sha256", "events_sha256", "actions_sha256", "messages_sha256"))
            or type(value["frontends"]) is not dict or any(k not in ledger.ROLES[1:] or not contract._hash(v)
                                                         for k, v in value["frontends"].items())):
        raise ValueError("name_tls_previous_context_changed")
    if value["binding"] is not None:
        contract.validate_binding(value["binding"], selected=identity["selection"], identity=identity)
    return deepcopy(value)


def _mapping(value):
    if type(value) is not dict or set(value) != {"launcher_uid", "launcher_gid", "uid_map", "gid_map"}:
        raise ValueError("name_tls_context_mapping")
    for name in ("uid", "gid"):
        number = value["launcher_" + name]
        if type(number) is not int or number <= 0 or value[name + "_map"] != [[65534, number, 1]]:
            raise ValueError("name_tls_context_mapping")


def validate_parser_receipt(value, parsed, raw):
    fields = {"readiness", "parent_observation", "wrapper_pid", "exit_code", "input_sha256", "reply_sha256",
              "elapsed_ms", "process_reaped", "python_sources_sha256"}
    if (type(value) is not dict or set(value) != fields or value["process_reaped"] is not True
            or type(value["exit_code"]) is not int or value["exit_code"] != 0
            or type(value["wrapper_pid"]) is not int or value["wrapper_pid"] <= 0
            or type(value["elapsed_ms"]) is not int or not 0 <= value["elapsed_ms"] <= 1000
            or any(not contract._hash(value[k]) for k in ("input_sha256", "reply_sha256", "python_sources_sha256"))
            or value["input_sha256"] != hashlib.sha256(raw).hexdigest()):
        raise ValueError("name_tls_parser_receipt")
    from .name_tls_parser_runtime import _readiness
    ready = _readiness(json.dumps(value["readiness"], sort_keys=True, separators=(",", ":")).encode("ascii"))
    observed = value["parent_observation"]
    if (type(observed) is not dict or set(observed) != {"payload_pid", "namespaces", "uid_map", "gid_map",
                                                       "retained_descriptors", "capabilities_zero", "no_new_privs", "threads"}
            or type(observed["payload_pid"]) is not int or observed["payload_pid"] <= 0
            or observed["namespaces"] != ready["namespaces"] or observed["retained_descriptors"] != [0, 1, 2]
            or observed["capabilities_zero"] is not True or observed["no_new_privs"] is not True
            or type(observed["threads"]) is not int or observed["threads"] != 1):
        raise ValueError("name_tls_parser_parent_observation")
    for name in ("uid", "gid"):
        rows = observed[name + "_map"]
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not list or len(rows[0]) != 3
                or any(type(n) is not int for n in rows[0]) or rows[0][0] != 65534 or rows[0][2] != 1 or rows[0][1] <= 0):
            raise ValueError("name_tls_parser_parent_mapping")
    reply = {**ready, "status": "parsed", "result": parsed}
    encoded = json.dumps(reply, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    if hashlib.sha256(encoded).hexdigest() != value["reply_sha256"]:
        raise ValueError("name_tls_parser_reply_commitment")
    return deepcopy(value)


def validate_result_context(result, identity, *, previous=None, tool_id=None, execution_status=None):
    identity = contract.validate_identity(identity)
    selected = identity["selection"]
    previous = None if previous is None else _previous(previous, identity)
    if type(result) is dict and "name_tls_refusal" in result:
        return _validate_refusal(result, identity, previous, tool_id, execution_status)
    if (type(result) is not dict or set(result) != RESULT_FIELDS or result["backend"] != contract.BACKEND
            or result["owned_lab"] != {"identity": identity} or result["results"] != []
            or result["status"] not in ("succeeded", "failed", "timeout", "output_limit", "cancelled")
            or execution_status is not None and result["status"] != execution_status):
        raise ValueError("name_tls_result_shape")
    service = result["name_tls_service"]
    if type(service) is not dict or set(service) not in (SERVICE_FIELDS, SERVICE_FIELDS - {"parser_error"}):
        raise ValueError("name_tls_service_shape")
    sequence, slot = service["action_sequence"], service["slot"]
    if type(sequence) is not int or sequence != (1 if previous is None else previous["sequence"] + 1):
        raise ValueError("name_tls_action_sequence")
    action = contract.validate_action(service["action"], selected, identity,
                                     None if previous is None else previous["binding"])
    operation = contract.operation(slot)
    if (action["parameters"]["operation_slot"] != slot or contract.digest(action) != service["action_digest"]
            or tool_id is not None and action["tool_id"] != tool_id):
        raise ValueError("name_tls_result_action")
    from .name_tls_client_worker import BOUNDARY_NAMES
    if (type(result["boundary_checks"]) is not dict or set(result["boundary_checks"]) != set(BOUNDARY_NAMES)
            or any(flag is not True for flag in result["boundary_checks"].values())
            or type(result["timing"]) is not dict or set(result["timing"]) != {"client_startup_ms", "action_elapsed_ms", "owner_and_action_elapsed_ms"}
            or any(type(n) is not int or not 0 <= n <= 60000 for n in result["timing"].values())):
        raise ValueError("name_tls_result_boundary")
    topology = validate_metadata(result["name_tls_topology"], configuration=selected["configuration"])
    client_observation = result["client_observation"]
    if (type(client_observation) is not dict or set(client_observation) != {"namespaces", "mapping", "native_ready"}
            or type(client_observation["namespaces"]) is not dict or set(client_observation["namespaces"]) != {"user", "net", "mnt", "pid"}
            or client_observation["namespaces"]["net"] != topology["networks"][operation + "_client"]
            or any(client_observation["namespaces"][key] == topology["owner_namespaces"][key] for key in ("user", "mnt", "pid"))
            or (operation == "http") != (client_observation["native_ready"] is None)):
        raise ValueError("name_tls_client_parent_observation")
    _mapping(client_observation["mapping"])
    state = ledger.validate_snapshot(result["name_tls_ledger"], selected=selected, identity=identity,
                                     messages=result["name_tls_messages"])
    if len(state["actions"]) != sequence or state["active_action_sequence"] is not None or state["active_connection"] is not None:
        raise ValueError("name_tls_action_unsettled")
    current = state["actions"][-1]
    if (current["slot"] != slot or current["sequence"] != sequence or current["status"] != "finished"
            or current["action_digest"] != service["action_digest"] or current["output_bytes_retained"] != result["bytes_received"]
            or service["binding"] != state["binding"]):
        raise ValueError("name_tls_result_reservation")
    expected_messages = [row for row in result["name_tls_messages"]
                         if row["role"] == contract.selector_role(slot) and row["message"]["action_sequence"] == sequence]
    if expected_messages != service["reservations"]:
        raise ValueError("name_tls_recorder_message_transcript")
    raw = _base64(service["parser_input_base64"], parser.MAX_INPUT_BYTES)
    header, streams = parser.decode_input(raw)
    output_cap = contract.action_bounds(slot)["output_bytes"]
    stdout, stderr = (_base64(result[key], output_cap) for key in ("raw_output_base64", "raw_stderr_base64"))
    provenance = result["provenance"]
    if (type(provenance) is not dict or set(provenance) != {"runtime_sha256", "runtime_manifest", "output_sha256", "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
            or provenance["parser_version"] != parser.PARSER_VERSION or provenance["output_sha256"] != hashlib.sha256(stdout).hexdigest()
            or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
            or type(result["bytes_received"]) is not int or result["bytes_received"] != len(stdout) + len(stderr)
            or result["bytes_received"] > output_cap or type(result["truncated"]) is not bool
            or result["truncated"] != (result["status"] == "output_limit")
            or any(header[key] != expected for key, expected in (("operation", operation), ("configuration", selected["configuration"]),
                   ("case", selected["case"]), ("exit_code", provenance["exit_code"]), ("stop_reason", provenance["stop_reason"]), ("truncated", result["truncated"])))
            or streams["stdout"] != stdout or streams["stderr"] != stderr):
        raise ValueError("name_tls_native_result_provenance")
    from . import name_tls_role_spec as roles
    if operation == "http":
        if provenance["runtime_sha256"] is not None or provenance["runtime_manifest"] is not None:
            raise ValueError("name_tls_http_runtime_identity")
    elif roles.manifest_digest(roles.validate_manifest(provenance["runtime_manifest"], role=operation + "_client")) != provenance["runtime_sha256"]:
        raise ValueError("name_tls_client_runtime_identity")
    recorder = service["recorder"]
    if (type(recorder) is not dict or not contract._hash(recorder.get("transcript_sha256"))
            or recorder["transcript_sha256"] != public.digest({k: v for k, v in recorder.items() if k != "transcript_sha256"})
            or recorder.get("operation") != operation or recorder.get("configuration") != selected["configuration"] or recorder.get("case") != selected["case"]
            or recorder.get("done") is not True or type(recorder.get("streams")) is not dict
            or set(recorder["streams"]) != set(streams) - {"stdout", "stderr"}):
        raise ValueError("name_tls_recorder_commitment")
    for key, item in recorder["streams"].items():
        if item != {"bytes": len(streams[key]), "sha256": hashlib.sha256(streams[key]).hexdigest()}:
            raise ValueError("name_tls_recorder_raw_commitment")
    if (recorder["request_bytes_delivered"] != len(streams["delivered_request"])
            or recorder["response_bytes_delivered"] != len(streams["delivered_response"])):
        raise ValueError("name_tls_recorder_delivered_count")
    parsed = service["parsed"]
    if parsed is not None:
        parser.validate_result(parsed)
        if (parsed != result["tool_observation"] or parsed["input_sha256"] != hashlib.sha256(raw).hexdigest()
                or parsed["streams"] != {key: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()} for key, value in streams.items()}
                or service.get("parser_error") is not None or recorder["reason"] != "complete" or recorder["delivery_unknown"] is not False
                or service["budget_denied"] is not False):
            raise ValueError("name_tls_parsed_observation_commitment")
        validate_parser_receipt(service["parser_receipt"], parsed, raw)
    elif (result["tool_observation"] is not None or service["parser_receipt"] is not None
          or service.get("parser_error") not in ("invalid_native_observation", "parser_isolation_unavailable")):
        raise ValueError("name_tls_failed_parser_receipt")
    native = {key: deepcopy(result[key]) for key in ("status", "results", "tool_observation", "bytes_received", "truncated",
              "boundary_checks", "timing", "raw_output_base64", "raw_stderr_base64", "provenance", "client_observation")}
    native["tool_observation"] = None
    native["timing"].pop("owner_and_action_elapsed_ms")
    if (current["native_result_sha256"] != public.digest(native) or current["parsed_result_sha256"] != public.digest(parsed)
            or current["native_success"] is not bool(parsed and (parsed["useful_task_completed"] or parsed["expected_negative"]))):
        raise ValueError("name_tls_final_result_digest")
    _mapping(service["daemon_mapping"])
    _mapping(service["frontend_mapping"])
    validate_namespace_identity(service["daemon_ready"]["namespace_identity"])
    validate_namespace_identity(service["frontend_ready"]["payload_identity"])
    if (service["closure"] != {"daemon_processes_reaped": True, "action_connections_closed": True,
                              "frontend_persists": True, "topology_persists": True}):
        raise ValueError("name_tls_action_cleanup")
    frontends = {} if previous is None else deepcopy(previous["frontends"])
    role = contract.selector_role(slot)
    frontend_digest = public.digest({k: service[k] for k in ("frontend_ready", "frontend_mapping")})
    if role in frontends and frontends[role] != frontend_digest:
        raise ValueError("name_tls_frontend_continuity")
    frontends[role] = frontend_digest
    if previous is not None:
        if (public.digest(topology) != previous["topology_sha256"]
                or public.digest(state["events"][:previous["event_count"]]) != previous["events_sha256"]
                or public.digest(state["actions"][:-1]) != previous["actions_sha256"]
                or public.digest(result["name_tls_messages"][:previous["message_count"]]) != previous["messages_sha256"]):
            raise ValueError("name_tls_owner_continuity")
    return {"identity": identity, "sequence": sequence, "binding": deepcopy(state["binding"]),
            "connection_count": state["counters"]["connections"],
            "request_count": sum(state["counters"][k] for k in ("dns_queries", "http_requests", "tls_handshakes")),
            "topology_sha256": public.digest(topology), "event_count": len(state["events"]),
            "events_sha256": public.digest(state["events"]), "actions_sha256": public.digest(state["actions"]),
            "message_count": len(result["name_tls_messages"]), "messages_sha256": public.digest(result["name_tls_messages"]),
            "frontends": frontends}


def _validate_refusal(result, identity, previous, tool_id, execution_status):
    fields = {"status", "backend", "results", "tool_observation", "bytes_received", "truncated", "name_tls_refusal",
              "name_tls_ledger", "name_tls_messages", "name_tls_topology", "owned_lab", "timing"}
    selected = identity["selection"]
    if (previous is None or selected["case"] != "N14" or set(result) != fields or result["status"] != "blocked"
            or execution_status is not None and execution_status != "blocked" or result["backend"] != contract.BACKEND
            or result["results"] != [] or result["tool_observation"] is not None or type(result["bytes_received"]) is not int
            or result["bytes_received"] != 0 or result["truncated"] is not False or result["owned_lab"] != {"identity": identity}
            or type(result["timing"]) is not dict or set(result["timing"]) != {"owner_and_action_elapsed_ms"}
            or type(result["timing"]["owner_and_action_elapsed_ms"]) is not int or not 0 <= result["timing"]["owner_and_action_elapsed_ms"] <= 60000):
        raise ValueError("name_tls_refusal_shape")
    refusal = result["name_tls_refusal"]
    if (type(refusal) is not dict or set(refusal) != {"action", "execution_sequence", "reason", "source", "before"}
            or type(refusal["execution_sequence"]) is not int or refusal["execution_sequence"] != previous["sequence"] + 1
            or refusal["execution_sequence"] not in (2, 3) or refusal["reason"] != "binding_expired"
            or refusal["source"] != ("owner_arm" if refusal["execution_sequence"] == 2 else "owner_terminal")):
        raise ValueError("name_tls_refusal_identity")
    action = contract.validate_action(refusal["action"], selected, identity, previous["binding"])
    if (action["parameters"]["operation_slot"] != ("http" if refusal["execution_sequence"] == 2 else "tls")
            or tool_id is not None and action["tool_id"] != tool_id):
        raise ValueError("name_tls_refusal_action")
    before = refusal["before"]
    if type(before) is not dict or set(before) != {"ledger", "messages"}:
        raise ValueError("name_tls_refusal_before")
    before_state = ledger.validate_snapshot(before["ledger"], selected=selected, identity=identity, messages=before["messages"])
    state = ledger.validate_snapshot(result["name_tls_ledger"], selected=selected, identity=identity, messages=result["name_tls_messages"])
    topology = validate_metadata(result["name_tls_topology"], configuration=selected["configuration"])
    if (public.digest(topology) != previous["topology_sha256"] or public.digest(before_state["events"]) != previous["events_sha256"]
            or public.digest(before_state["actions"]) != previous["actions_sha256"] or public.digest(before["messages"]) != previous["messages_sha256"]
            or state["actions"] != before_state["actions"] or state["counters"] != before_state["counters"]
            or state["active_action_sequence"] is not None or state["active_connection"] is not None
            or state["terminal"] is not True or state["terminal_reason"] != "binding_expired"
            or result["name_tls_messages"][:len(before["messages"])] != before["messages"]):
        raise ValueError("name_tls_refusal_continuity")
    suffix = result["name_tls_messages"][len(before["messages"]):]
    if refusal["source"] == "owner_arm":
        if (len(suffix) != 1 or suffix[0]["role"] != "launcher" or suffix[0]["message"]["operation"] != "ARM"
                or suffix[0]["message"]["action"] != action or suffix[0]["message"]["action_digest"] != contract.digest(action)
                or suffix[0]["reply"]["status"] != "denied" or suffix[0]["reply"]["reason"] != "binding_expired"
                or before_state["terminal"] is not False):
            raise ValueError("name_tls_refusal_arm_evidence")
    elif suffix or before_state != state or before_state["terminal"] is not True:
        raise ValueError("name_tls_refusal_terminal_evidence")
    return {**deepcopy(previous), "sequence": refusal["execution_sequence"], "binding": deepcopy(state["binding"]),
            "event_count": len(state["events"]), "events_sha256": public.digest(state["events"]),
            "message_count": len(result["name_tls_messages"]), "messages_sha256": public.digest(result["name_tls_messages"])}


def validate_closure(value, identity, *, previous=None):
    identity = contract.validate_identity(identity)
    if previous is not None:
        _previous(previous, identity)
    expected = {"identity": identity, "status": "closed", "launcher_cleanup_verified": True,
                "counters_source": "last_acknowledged_result", "last_result": previous}
    if type(value) is not dict or set(value) != set(expected) or public.encode(value) != public.encode(expected):
        raise ValueError("name_tls_closure_changed")
    return deepcopy(value)
