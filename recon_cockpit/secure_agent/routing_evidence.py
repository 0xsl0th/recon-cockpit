"""Private routed evidence with read-only replay, never restored authority."""

import base64
from copy import deepcopy
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import threading
from uuid import uuid4

from . import routing_contract as contract, routing_ledger
from .stock_http_spec import encode
from .evidence import EvidenceStore, EvidenceUnavailable, _read_private, _uuid
from .models import parse_action

MAX_BYTES = contract.EVIDENCE_BOUNDS["max_total_bytes"]
MAX_JSON_BYTES = contract.EVIDENCE_BOUNDS["max_json_bytes"]
FILES = frozenset({"manifest.json", "outcomes.json", "report.json", "closure.json", "audit.jsonl",
                   *(f"{kind}-{step}.json" for kind in ("intent", "result") for step in range(1, 5))})
STATUSES = frozenset({"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"})


def _decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
        raise ValueError("routing_evidence_json_limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("routing_evidence_duplicate_key")
            result[key] = value
        return result
    def number(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("routing_evidence_nonfinite_number")
        return value
    def constant(_):
        raise ValueError("routing_evidence_nonfinite_number")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                           parse_float=number, parse_constant=constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("routing_evidence_invalid_json") from error
    if type(value) is not dict:
        raise ValueError("routing_evidence_invalid_json")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > contract.EVIDENCE_BOUNDS["max_json_depth"]:
            raise ValueError("routing_evidence_json_depth")
        children = item.values() if type(item) is dict else item if type(item) is list else ()
        pending.extend((child, depth + 1) for child in children)
    return value


def _directory_contents(directory_fd):
    names, total = set(), 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > contract.EVIDENCE_BOUNDS["max_files"] or entry.name not in FILES:
                raise ValueError("routing_evidence_file_limit")
            info = entry.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError("routing_evidence_artifact_changed")
            if info.st_size > MAX_JSON_BYTES:
                raise ValueError("routing_evidence_artifact_limit")
            total += info.st_size
            if total > MAX_BYTES:
                raise ValueError("routing_evidence_aggregate_limit")
    return names, total


def validate_manifest(value):
    fields = {"schema_version", "assessment_id", "session_id", "selection", "selectors", "policy", "limits", "runtime", "identity"}
    if type(value) is not dict or set(value) != fields or value["schema_version"] != "1" or not _uuid(value["assessment_id"]):
        raise ValueError("invalid_routing_evidence_manifest")
    selected = contract.validate_selection(value["selection"])
    selectors = value["selectors"]
    if (type(selectors) is not list or not 1 <= len(selectors) <= 4
            or any(type(name) is not str or name not in contract.SELECTORS for name in selectors)
            or len(set(selectors)) != len(selectors)):
        raise ValueError("invalid_routing_operator_selection")
    contract.validate_policy(value["policy"], selected)
    contract.validate_limits(value["limits"], selected)
    bundle = contract.validate_runtime(value["runtime"], selected)
    contract.validate_identity(value["identity"], selection=selected, session_id=value["session_id"], runtime=bundle)
    return deepcopy(value)


def validate_outcome(value, manifest, step, result):
    from .controller import result_metadata
    if type(step) is not int or not 1 <= step <= len(manifest["selectors"]):
        raise ValueError("invalid_routing_step")
    action = parse_action(contract.action(manifest["selection"], manifest["selectors"][step - 1]))
    policy = contract.validate_policy(manifest["policy"], manifest["selection"])
    decision = policy.evaluate(action)
    fixed = {"action_id": action.action_id, "action_digest": action.digest,
        "policy_version": policy.policy_version, "policy_digest": policy.digest,
        "session_id": manifest["session_id"], "session_step": step, "tool_id": action.tool_id,
        "target": action.target, "decision": decision.decision}
    fields = set(fixed) | {"approval_reference", "reasons", "execution_status"}
    if result is not None:
        fields |= {"execution_id", "result_metadata"}
    if (type(value) is not dict or set(value) != fields
            or any(value[key] != item or type(value[key]) is not type(item) for key, item in fixed.items())
            or type(value["reasons"]) is not list or any(type(reason) is not str for reason in value["reasons"])
            or value["reasons"] not in [list(decision.reasons), ["noninteractive_approval_required"],
                ["isolation_unavailable"], ["session_timeout"], ["session_cancelled"], ["approval_missing"],
                ["approval_unknown_or_replayed"], ["approval_expired"], ["approval_action_changed"], ["approval_policy_changed"]]):
        raise ValueError("routing_outcome_binding_changed")
    reference = value["approval_reference"]
    if reference is not None and (not policy.require_approval or type(reference) is not str or len(reference) != 48
                                  or any(character not in "0123456789abcdef" for character in reference)):
        raise ValueError("invalid_routing_approval_reference")
    if result is None:
        if value["execution_status"] not in ("dry_run", "blocked"):
            raise ValueError("routing_outcome_without_execution")
    elif (not _uuid(value["execution_id"]) or value["execution_status"] != result["status"]
            or encode(value["result_metadata"]) != encode(result_metadata(result))
            or policy.require_approval and reference is None):
        raise ValueError("routing_outcome_execution_changed")
    return deepcopy(value)


def _base64(value, maximum):
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError("routing_output_encoding_limit")
    raw = base64.b64decode(value, validate=True)
    if len(raw) > maximum or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("invalid_routing_output_encoding")
    return raw


def validate_result(result, manifest, step, previous=None, *, deadline=None):
    from .routing_context import validate_result_context
    from .routing_client_runtime import BOUNDARY_NAMES
    if type(step) is not int or not 1 <= step <= len(manifest["selectors"]):
        raise ValueError("invalid_routing_step")
    selector = manifest["selectors"][step - 1]
    action = contract.action(manifest["selection"], selector)
    tool = action["tool_id"]
    if type(result) is not dict or type(result.get("status")) is not str or result["status"] not in STATUSES:
        raise ValueError("invalid_routing_result")
    if set(result) == {"status"} and result["status"] != "succeeded":
        return previous, None
    native = selector != "http_headers"
    fields = {"status", "results", "bytes_received", "truncated", "boundary_checks", "timing", "tool_observation",
              "backend", "routing_topology", "routing_ledger", "routing_service", "owned_lab"}
    if native:
        fields |= {"raw_output_base64", "raw_stderr_base64", "provenance"}
    if (set(result) != fields or type(result["bytes_received"]) is not int
            or type(result["truncated"]) is not bool or result["truncated"] != (result["status"] == "output_limit")
            or type(result["boundary_checks"]) is not dict or set(result["boundary_checks"]) != set(BOUNDARY_NAMES)
            or any(flag is not True for flag in result["boundary_checks"].values())
            or type(result["routing_service"]) is not dict
            or result["routing_service"].get("selector") != selector
            or result["routing_service"].get("action_sequence") != step
            or result["routing_service"].get("action_digest") != contract.digest(action)):
        raise ValueError("routing_result_shape_changed")
    context = validate_result_context(result, manifest["identity"], previous=previous,
        tool_id=tool, execution_status=result["status"])
    routing_ledger.validate_snapshot(result["routing_ledger"], selected=manifest["selection"], identity=manifest["identity"])
    timing = result["timing"]
    if (type(timing) is not dict or set(timing) != {"owner_startup_ms", "client_startup_ms", "action_elapsed_ms", "owner_teardown_ms"}
            or any(type(item) is not int or not 0 <= item <= 60000 for item in timing.values())):
        raise ValueError("invalid_routing_result_timing")
    maximum = action["parameters"]["max_output_bytes"]
    if selector.startswith("http_"):
        from .configurable_parser import parser_version
        from .configurable_parser_runtime import parse_isolated_tool_output
        parse = lambda raw, stderr: parse_isolated_tool_output(tool, raw, stderr,
            scope=contract.scope(manifest["selection"]), endpoint_id="http", deadline=deadline)
    else:
        from .stock_ssh_parser import parser_version
        from .stock_ssh_parser_runtime import parse_isolated_tool_output
        parse = lambda raw, stderr: parse_isolated_tool_output(tool, raw, stderr,
            configuration=manifest["selection"]["configuration"], deadline=deadline)
    if native:
        raw, stderr = (_base64(result[key], maximum) for key in ("raw_output_base64", "raw_stderr_base64"))
        provenance = result["provenance"]
        expected_digest = manifest["identity"]["runtimes"][selector]["client_runtime_sha256"]
        if (result["results"] != [] or type(provenance) is not dict or set(provenance) != {
                "runtime_sha256", "runtime_manifest", "output_sha256", "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
                or encode(provenance["runtime_manifest"]) != encode(manifest["runtime"][selector]["client"])
                or provenance["runtime_sha256"] != expected_digest
                or provenance["output_sha256"] != hashlib.sha256(raw).hexdigest()
                or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
                or provenance["parser_version"] != parser_version(tool) or type(provenance["exit_code"]) is not int
                or not -64 <= provenance["exit_code"] <= 255
                or provenance["stop_reason"] != (result["status"] if result["status"] in ("timeout", "output_limit") else None)
                or result["status"] == "succeeded" and provenance["exit_code"] != 0):
            raise ValueError("routing_native_provenance_changed")
    else:
        if type(result["results"]) is not list or len(result["results"]) != 1:
            raise ValueError("invalid_routing_header_rows")
        row = result["results"][0]
        if (type(row) is not dict or set(row) != {"target", "port", "bytes_received", "truncated", "raw_response", "response_sha256"}
                or row["target"] != action["target"] or type(row["port"]) is not int
                or row["port"] != action["parameters"]["port"]
                or type(row["bytes_received"]) is not int or row["bytes_received"] != result["bytes_received"]
                or row["truncated"] is not result["truncated"]):
            raise ValueError("routing_header_custody_changed")
        raw, stderr = _base64(row["raw_response"], maximum), b""
        if row["response_sha256"] != hashlib.sha256(raw).hexdigest():
            raise ValueError("routing_header_hash_changed")
        recorder = result["routing_service"]["recorder"]
        delivered = bytes.fromhex(recorder["transformed_response_hex"])[:recorder["client_response_bytes"]]
        if not delivered.startswith(raw):
            raise ValueError("routing_header_not_from_frontend")
    if len(raw) + len(stderr) != result["bytes_received"] or result["bytes_received"] > maximum:
        raise ValueError("routing_output_accounting_changed")
    parsed = None
    if result["status"] == "succeeded" and not result["routing_service"]["budget_denied"]:
        try:
            parsed = parse(raw, stderr)
        except ValueError:
            pass
    if encode(parsed) != encode(result["tool_observation"]):
        raise ValueError("routing_observation_replay_changed")
    return context, parsed


def _native_and_useful(selector, result, observation, selected=None):
    if result is None or "routing_service" not in result or result["routing_service"]["budget_denied"]:
        return False, False
    selected = contract.underlying_selection(selector, selected)
    service = result["routing_service"]
    if selector.startswith("http_"):
        from .stock_http_production_evidence import _native_case_verified, _identified_service_matches
        from . import stock_http_spec
        native = _native_case_verified(selected, {**result, "stock_http_owner": {"recorder": service["recorder"]}})
        if not native or observation is None:
            return bool(native), False
        if selector == "http_headers":
            expected = stock_http_spec.expectation("O1")["headers"]
            useful = all(observation.get("headers", {}).get(key) == value for key, value in expected.items())
        else:
            header = bytes.fromhex(service["recorder"]["original_response_hex"]).split(b"\r\n\r\n", 1)[0]
            banners = [row.split(b":", 1)[1].strip().decode("ascii", "replace") for row in header.split(b"\r\n")[1:]
                       if row.split(b":", 1)[0].lower() == b"server"]
            useful = len(banners) == 1 and _identified_service_matches(selected, observation, banners[0])
    else:
        from .stock_ssh_evidence import _native_case_verified
        from . import stock_ssh_spec
        native = _native_case_verified(selected, {**result, "stock_ssh_owner": {
            "recorder": service["recorder"], "instances": service["instances"]}})
        if not native or observation is None:
            return bool(native), False
        if selector == "ssh_nmap":
            useful = observation.get("identification") == "identified" and observation.get("service") == {
                "name": "ssh", "product": "OpenSSH", "version": stock_ssh_spec.OPENSSH_VERSION}
        else:
            expected = stock_ssh_spec.public_test_key_facts()
            useful = all(observation.get(key) == expected[key] for key in
                         ("key_type", "key_bits", "key_base64", "fingerprint_sha256", "trust"))
    return bool(native), bool(useful and result["status"] == "succeeded")


def _routed_http_overflow_verified(selected, result):
    """Verify the undelivered proposal, without claiming standalone overflow."""
    from .stock_http_recorder import transform_response
    from .stock_http_production_evidence import _server_matches
    from . import stock_http_spec
    service = result["routing_service"]
    record, owner = service["recorder"], result["routing_ledger"]
    if (not service["budget_denied"] or not owner["terminal"]
            or owner["terminal_reason"] != "action_response_bytes_limit"
            or record["terminal_reason"] != "io_failure"
            or record["requests_validated"] != 1 or record["requests_delivered"] != 1
            or record["connections_admitted"] != 1 or record["connections_denied"] != 0
            or record["request_bytes_delivered"] != len(stock_http_spec.request_bytes(selected["configuration"], "N4"))
            or record["client_response_bytes"] != 0 or record["writes"]
            or result["bytes_received"] != 0 or result["tool_observation"] is not None):
        return False
    original = bytes.fromhex(record["original_response_hex"])
    try:
        chunks, _, disposition = transform_response("N4", original)
    except ValueError:
        return False
    proposal = b"".join(chunks)
    if len(chunks) != 1 or len(proposal) != 2049 or bytes.fromhex(record["transformed_response_hex"]) != proposal:
        return False
    # transform_response validates complete framing and length. Independently
    # bind the preserved original to the compiled stock body and daemon banner.
    header, body = original.split(b"\r\n\r\n", 1)
    status = header.split(b"\r\n", 1)[0].split(b" ", 2)
    servers = [line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")[1:]
               if line.split(b":", 1)[0].lower() == b"server"]
    if (len(status) != 3 or status[1] != b"200"
            or body != stock_http_spec.response_body("N4")
            or len(servers) != 1 or not _server_matches(selected, servers[0])):
        return False
    events = record["events"]
    transforms = [row for row in events if row["kind"] == "transform"]
    if (sum(row["kind"] == "daemon_response" for row in events) != 1
            or len(transforms) != 1 or transforms[0]["reason"] != disposition
            or transforms[0]["bytes"] != 2049 or any(row["kind"] == "complete" for row in events)):
        return False
    response = [row for row in service["reservations"] if row["message"]["operation"] == "RESERVE_BYTES"
                and row["message"]["direction"] == "response"]
    requests = [row for row in service["reservations"] if row["message"]["operation"] == "RESERVE_REQUEST"
                and row["reply"]["status"] == "ok"]
    return bool(len(response) == 1 and response[0]["message"]["bytes"] == 2049
        and response[0]["reply"]["status"] == "denied"
        and response[0]["reply"]["reason"] == "action_response_bytes_limit"
        and len(requests) == 1 and requests[0]["message"]["kind"] == "http"
        and owner["actions"][-1]["counters"]["response_bytes"] == 0)


def _matrix_case_outcome(selector, result, observation, selected):
    """Grade v3 committed cases separately from the actual client exit status."""
    underlying = contract.underlying_selection(selector, selected)
    case = underlying["case"]
    expected = contract.case_expectation(selector, selected)
    native = useful = negative = False
    classification, basis = "inconclusive", None
    if result is not None and result["status"] in ("timeout", "output_limit"):
        classification, basis = result["status"], "client_watchdog"
    if result is not None and "routing_service" in result:
        service = result["routing_service"]
        record = service["recorder"]
        if selector == "http_headers" and case == "N4":
            native = _routed_http_overflow_verified(underlying, result)
            if native and observation is None:
                classification, basis = "expected_response_budget_refusal", "routing_owner_response_budget_before_delivery"
                negative = True
        elif not service["budget_denied"]:
            if selector.startswith("http_"):
                from .stock_http_production_evidence import _native_case_verified, _identified_service_matches
                native = _native_case_verified(underlying, {**result, "stock_http_owner": {"recorder": record}})
                if native and observation is not None and not expected["expected_negative"]:
                    if selector == "http_headers":
                        headers = expected["native_expectation"]["headers"]
                        useful = all(observation.get("headers", {}).get(key) == value for key, value in headers.items())
                    else:
                        header = bytes.fromhex(record["original_response_hex"]).split(b"\r\n\r\n", 1)[0]
                        banners = [line.split(b":", 1)[1].strip().decode("ascii", "replace") for line in header.split(b"\r\n")[1:]
                                   if line.split(b":", 1)[0].lower() == b"server"]
                        useful = len(banners) == 1 and _identified_service_matches(underlying, observation, banners[0])
                no_positive = observation is None
            else:
                from .stock_ssh_evidence import _native_case_verified
                from . import stock_ssh_spec
                native = _native_case_verified(underlying, {**result, "stock_ssh_owner": {
                    "recorder": record, "instances": service["instances"]}})
                if native and observation is not None and not expected["expected_negative"]:
                    if selector == "ssh_nmap":
                        useful = observation.get("identification") == "identified" and observation.get("service") == {
                            "name": "ssh", "product": "OpenSSH", "version": stock_ssh_spec.OPENSSH_VERSION}
                    else:
                        facts = stock_ssh_spec.public_test_key_facts()
                        useful = all(observation.get(key) == facts[key] for key in
                                     ("key_type", "key_bits", "key_base64", "fingerprint_sha256", "trust"))
                no_positive = observation is None or case == "N1" and observation.get("identification") == "unidentified"
                if native and case == "N4":
                    classification, basis = "output_limit", "independent_recorder_wire_cap"
                if case == "N3":
                    corroborated_timeout = (native and observation is None and result["status"] in ("failed", "timeout")
                        and result["timing"]["action_elapsed_ms"] >= 1900 and record["client_bytes_delivered"] == 0)
                    if corroborated_timeout:
                        classification, basis = "timeout", "withheld_response_and_native_two_second_timeout"
                    else:
                        # A client watchdog label alone does not prove the
                        # declared native two-second withheld-response case.
                        no_positive = False
            negative = bool(native and expected["expected_negative"] and no_positive
                            and classification in expected["allowed_classifications"])
    useful = bool(useful and result["status"] == "succeeded" and not expected["expected_negative"])
    if useful:
        classification, basis = "useful", None
    return {"case": case, "native_response_verified": bool(native), "useful_completion": useful,
        "classification": classification, "classification_basis": basis,
        "expected_negative": bool(negative), "case_passed": bool(useful or negative)}


def report_for(manifest, results, outcomes, closure, elapsed_ms, *, deadline=None):
    from .routing_context import validate_closure
    manifest = validate_manifest(manifest)
    if (type(outcomes) is not list or not 1 <= len(outcomes) <= len(manifest["selectors"])
            or type(results) is not list or len(results) != len(outcomes)
            or type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 120000):
        raise ValueError("invalid_routing_assessment_outcomes")
    matrix = contract.case_profile(manifest["selection"]) is not None
    rows, previous, final_ledger = [], None, None
    negative_attempted = False
    actual_wire = {"request_bytes": 0, "response_bytes": 0}
    for step, (outcome, result) in enumerate(zip(outcomes, results, strict=True), 1):
        selector = manifest["selectors"][step - 1]
        if negative_attempted:
            raise ValueError("routing_action_after_declared_negative")
        validate_outcome(outcome, manifest, step, result)
        observation = None
        if result is not None:
            previous, observation = validate_result(result, manifest, step, previous, deadline=deadline)
        if matrix:
            graded = _matrix_case_outcome(selector, result, observation, manifest["selection"])
            native, useful = graded["native_response_verified"], graded["useful_completion"]
            negative_attempted = result is not None and contract.case_is_negative(selector, manifest["selection"])
        else:
            native, useful = _native_and_useful(selector, result, observation, manifest["selection"])
        if result is not None and "routing_ledger" in result:
            final_ledger = result["routing_ledger"]
            recorder = result["routing_service"]["recorder"]
            actual_wire["request_bytes"] += recorder["request_bytes_delivered"] if selector.startswith("http_") else recorder["client_bytes_forwarded"]
            actual_wire["response_bytes"] += recorder["client_response_bytes"] if selector.startswith("http_") else recorder["client_bytes_delivered"]
        rows.append({"selector": selector, "step": step, "execution_status": outcome["execution_status"],
                     "native_response_verified": native, "useful_completion": useful,
                     "observation": observation, "timing": None if result is None else result.get("timing")})
        if matrix:
            rows[-1].update(graded)
    validate_closure(closure, manifest["identity"], previous=previous)
    case = manifest["selection"]["budget_case"]
    expected_reason = {"connection_one": "aggregate_connections_limit", "http_one": "aggregate_http_requests_limit",
                       "ssh_zero": "aggregate_kex_exchanges_limit"}.get(case)
    expected_negative = bool(expected_reason and final_ledger and final_ledger["terminal"]
        and final_ledger["terminal_reason"] == expected_reason
        and any(event.get("kind") == "message" and event["reply"]["status"] == "denied"
                and event["reply"]["reason"] == expected_reason for event in final_ledger["events"]))
    useful = sum(row["useful_completion"] for row in rows)
    completed = bool(case == "ordinary" and len(rows) == len(manifest["selectors"]) and useful == len(rows)
        and final_ledger and (not final_ledger["terminal"] or final_ledger["terminal_reason"] == "completed"))
    transport_negative = bool(matrix and case == "ordinary" and rows[-1]["expected_negative"]
                              and all(row["useful_completion"] for row in rows[:-1]))
    if matrix:
        expected_negative = bool(transport_negative or expected_negative
            and all(row["useful_completion"] for row in rows[:-1]))
    reservations = None if final_ledger is None else deepcopy(final_ledger["counters"])
    explicit_denials = 0 if final_ledger is None else sum(event.get("kind") == "message"
        and event["reply"]["status"] == "denied" for event in final_ledger["events"])
    topology = next((result["routing_topology"] for result in results
                     if result is not None and "routing_topology" in result), None)
    filtered = [] if topology is None else topology["filtered"]
    report = {"schema_version": "1", "profile": contract.PROFILE, "assessment_id": manifest["assessment_id"],
        "session_id": manifest["session_id"], "selection": manifest["selection"], "selectors": manifest["selectors"],
        "disconnected_owned_lab_only": True, "operator_selected_independent_actions": True,
        "case_passed": bool(completed or expected_negative), "classification": "completed" if completed else
            "expected_budget_refusal" if expected_negative else "incomplete", "actions": rows,
        "metrics": {"legitimate_task_completed": bool(completed), "useful_actions_completed": useful,
            "planned_actions": len(manifest["selectors"]), "attempted_actions": len(rows),
            "unnecessary_refusals": len(rows) - useful if case == "ordinary" and all(
                row["execution_status"] not in ("dry_run", "blocked", "cancelled") for row in rows) else None,
            "expected_negative": expected_negative, "explicit_budget_or_protocol_denials": explicit_denials,
            "destination_probe_attempts": len(filtered),
            "excluded_destination_probes_blocked": sum(row["connected"] is False for row in filtered),
            "reservations": reservations, "actual_wire_bytes": actual_wire,
            "retained_output_bytes": sum(result.get("bytes_received", 0) for result in results if result is not None),
            "actual_provider_calls": 0, "actual_cost_microusd": 0, "elapsed_ms": elapsed_ms,
            "comparison_baseline": None, "cleanup_verified": True},
        "closure": deepcopy(closure), "limitations": [
            ("Fixed configuration A with nginx and OpenSSH only; routed Apache, configuration B and broader hostile corpus remain future work."
             if "selection_version" not in manifest["selection"] else
             "Four fixed nginx/Apache A/B deployments with ordinary independent actions only; the full hostile/negative routing corpus remains future work."),
            "Actions are explicitly chosen independently; no response-directed workflow or attached target support.",
            "Reservations are charged before delivery and may exceed actual wire bytes after a failed or partial write.",
            "Public SSH host keys remain unverified observations; no authentication or encrypted user session is attempted.",
            "Closure verifies physical launcher cleanup with last acknowledged counters; it does not invent a graceful final owner receipt.",
            "Local hashes establish consistency, not resistance to malicious rewriting by the host owner.",
            "Credentials, paid models, live-model evaluation and comparative overhead benchmarking remain deferred."]}
    if matrix:
        if transport_negative:
            report["classification"] = ("expected_response_budget_refusal"
                if rows[-1]["classification"] == "expected_response_budget_refusal" else "expected_transport_negative")
        report["metrics"]["unnecessary_refusals"] = (sum(not row["useful_completion"] for row in rows
            if not contract.case_is_negative(row["selector"], manifest["selection"]))
            if case == "ordinary" and all(row["execution_status"] not in ("dry_run", "blocked", "cancelled")
                                           for row in rows) else None)
        report["limitations"][0] = "Finite committed HTTP/SSH cases across four owned nginx/Apache A/B deployments only."
    return report


def _durable(method):
    @wraps(method)
    def checked(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
            self._failed = True
            raise EvidenceUnavailable("routing_evidence_unavailable") from None
    return checked


class RoutingEvidenceStore(EvidenceStore):
    def __init__(self, directory, manifest, *, deadline=None):
        self.directory = Path(directory)
        self._fd = self._journal = None
        self._failed = self._finalized = False
        self._lock = threading.Lock()
        self._manifest = validate_manifest(manifest)
        self._deadline = deadline
        self._records, self._results, self._previous = {}, {}, None
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._write_new("manifest.json", encode(self._manifest), MAX_JSON_BYTES)
        except BaseException:
            self.close()
            raise

    def _write_new(self, name, raw, limit):
        self._check()
        names, total = _directory_contents(self._fd)
        if name not in FILES or len(names | {name}) > contract.EVIDENCE_BOUNDS["max_files"]:
            raise EvidenceUnavailable("routing_evidence_file_limit")
        if total + len(raw) > MAX_BYTES:
            raise EvidenceUnavailable("routing_evidence_aggregate_limit")
        _decode(raw)
        return super()._write_new(name, raw, min(limit, MAX_JSON_BYTES))

    @_durable
    def start(self, action, policy, *, session_id, session_step, backend):
        with self._lock:
            self._check()
            if (type(session_step) is not int or not 1 <= session_step <= len(self._manifest["selectors"])
                    or session_step <= max(self._records, default=0) or set(self._records) != set(self._results)
                    or session_id != self._manifest["session_id"] or backend != contract.BACKEND
                    or action.to_dict() != contract.action(self._manifest["selection"], self._manifest["selectors"][session_step - 1])
                    or policy.to_dict() != self._manifest["policy"]):
                raise ValueError("routing_evidence_start_changed")
            row = {"execution_id": str(uuid4()), "action": action.to_dict(), "session_id": session_id,
                   "session_step": session_step, "backend": backend}
            self._write_new(f"intent-{session_step}.json", encode(row), MAX_JSON_BYTES)
            self._records[session_step] = row
            return row["execution_id"]

    @_durable
    def finish(self, execution_id, result, *, execution_status):
        with self._lock:
            self._check()
            step = max(self._records, default=0)
            if (not step or self._records[step]["execution_id"] != execution_id or step in self._results
                    or type(result) is not dict or result.get("status") != execution_status):
                raise ValueError("routing_evidence_completion_changed")
            context, _ = validate_result(result, self._manifest, step, self._previous, deadline=self._deadline)
            self._write_new(f"result-{step}.json", encode(result), MAX_JSON_BYTES)
            self._results[step], self._previous = deepcopy(result), context

    @_durable
    def finalize(self, outcomes, *, closure, elapsed_ms):
        with self._lock:
            self._check()
            if type(outcomes) is not list or set(self._records) != set(self._results):
                raise ValueError("routing_evidence_incomplete")
            safe = [{key: item for key, item in outcome.items() if key != "untrusted_result"} for outcome in outcomes]
            if any(step > len(safe) or safe[step - 1].get("execution_id") != row["execution_id"]
                   for step, row in self._records.items()):
                raise ValueError("routing_evidence_execution_changed")
            results = [self._results.get(step) for step in range(1, len(safe) + 1)]
            report = report_for(self._manifest, results, safe, closure, elapsed_ms, deadline=self._deadline)
            self._write_new("closure.json", encode(closure), MAX_JSON_BYTES)
            self._write_new("outcomes.json", encode({"outcomes": safe, "elapsed_ms": elapsed_ms}), MAX_JSON_BYTES)
            self._write_new("report.json", encode(report), MAX_JSON_BYTES)
            self._finalized = True
            return report


def _validate_audit(events, manifest, outcomes, results):
    policy = contract.validate_policy(manifest["policy"], manifest["selection"])
    expected = []
    for step, (outcome, result) in enumerate(zip(outcomes, results, strict=True), 1):
        validate_outcome(outcome, manifest, step, result)
        action = parse_action(contract.action(manifest["selection"], manifest["selectors"][step - 1]))
        initial = {key: outcome[key] for key in ("action_id", "action_digest", "policy_version", "policy_digest",
            "session_id", "session_step", "tool_id", "target", "decision")}
        initial.update(approval_reference=None, reasons=list(policy.evaluate(action).reasons), execution_status="not_started")
        expected.append({**initial, "event_type": "policy_decision", "untrusted_agent_context": {
            "rationale": "[REDACTED]", "rationale_length": len(action.rationale)}})
        if policy.require_approval and outcome["approval_reference"] is not None:
            initial["approval_reference"] = outcome["approval_reference"]
            expected.append({**initial, "event_type": "approval_consumed"})
        if result is not None:
            expected.extend(({**initial, "event_type": "execution_started", "execution_status": "started",
                "execution_id": outcome["execution_id"], "backend": contract.BACKEND},
                {**outcome, "event_type": "execution_finished", "backend": contract.BACKEND}))
        elif outcome["execution_status"] == "blocked":
            kind = "approval_rejected" if outcome["reasons"] in (["noninteractive_approval_required"], ["approval_missing"],
                ["approval_unknown_or_replayed"], ["approval_expired"], ["approval_action_changed"], ["approval_policy_changed"]) else "execution_blocked"
            expected.append({**outcome, "event_type": kind})
    if len(events) != len(expected):
        raise ValueError("routing_audit_sequence_changed")
    envelope = {"event_schema_version", "event_id", "timestamp", "source"}
    identifiers = set()
    for event, payload in zip(events, expected, strict=True):
        if (type(event) is not dict or set(event) != set(payload) | envelope or event["event_schema_version"] != "1"
                or event["source"] != "recon-cockpit.secure-agent" or not _uuid(event["event_id"])
                or event["event_id"] in identifiers or type(event["timestamp"]) is not str or not 1 <= len(event["timestamp"]) <= 64):
            raise ValueError("invalid_routing_audit_event")
        identifiers.add(event["event_id"])
        if datetime.fromisoformat(event["timestamp"]).utcoffset() != timedelta(0):
            raise ValueError("invalid_routing_audit_timestamp")
        if encode({key: event[key] for key in payload}) != encode(payload):
            raise ValueError("routing_audit_binding_changed")


def inspect_trial(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("routing_evidence_directory_changed")
        names, _ = _directory_contents(fd)
        read = lambda name: _decode(_read_private(fd, name, MAX_JSON_BYTES))
        manifest, saved = validate_manifest(read("manifest.json")), read("outcomes.json")
        if (set(saved) != {"outcomes", "elapsed_ms"} or type(saved["outcomes"]) is not list
                or not 1 <= len(saved["outcomes"]) <= len(manifest["selectors"])):
            raise ValueError("invalid_routing_saved_outcomes")
        outcomes, results = saved["outcomes"], []
        expected = {"manifest.json", "outcomes.json", "report.json", "closure.json", "audit.jsonl"}
        for step, outcome in enumerate(outcomes, 1):
            if type(outcome) is not dict:
                raise ValueError("invalid_routing_saved_outcome")
            if "execution_id" in outcome:
                expected.update({f"intent-{step}.json", f"result-{step}.json"})
                intent = read(f"intent-{step}.json")
                if (intent != {"execution_id": outcome["execution_id"],
                        "action": contract.action(manifest["selection"], manifest["selectors"][step - 1]),
                        "session_id": manifest["session_id"], "session_step": step, "backend": contract.BACKEND}
                        or not _uuid(outcome["execution_id"])):
                    raise ValueError("routing_evidence_intent_changed")
                results.append(read(f"result-{step}.json"))
            else:
                results.append(None)
        if names != expected:
            raise ValueError("routing_evidence_files_changed")
        raw_audit = _read_private(fd, "audit.jsonl", MAX_JSON_BYTES)
        if not raw_audit.endswith(b"\n") or len(raw_audit.splitlines()) > 16:
            raise ValueError("invalid_routing_audit")
        _validate_audit([_decode(line) for line in raw_audit.splitlines()], manifest, outcomes, results)
        report = report_for(manifest, results, outcomes, read("closure.json"), saved["elapsed_ms"])
        if encode(report) != encode(read("report.json")):
            raise ValueError("routing_report_replay_changed")
        return report
    finally:
        os.close(fd)
