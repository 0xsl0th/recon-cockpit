"""Fixed stock SSH evidence; inspection restores no authority.

The accepted diagnostic remains separate. SSH reports revalidate their
own authority identity, complete peer bytes, namespace custody and cleanup.
"""

import base64
from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
from uuid import uuid4

from . import stock_ssh_contract as contract
from . import stock_ssh_spec as spec
from .evidence import EvidenceStore, EvidenceUnavailable, _read_private, _uuid
from .models import parse_action

# SSH transcripts and process receipts have separate saved-artifact limits.
# These do not enlarge tool output, owner buffers or accepted HTTP/model limits.
MAX_BYTES = contract.EVIDENCE_BOUNDS["max_total_bytes"]
MAX_JSON_BYTES = contract.EVIDENCE_BOUNDS["max_json_bytes"]
FILES = frozenset({"manifest.json", "intent.json", "result.json", "outcome.json", "report.json", "audit.jsonl"})


def _decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
        raise ValueError("invalid_stock_ssh_evidence_json")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_stock_ssh_evidence_key")
            result[key] = value
        return result
    def number(value):
        decoded = float(value)
        if not math.isfinite(decoded):
            raise ValueError("invalid_stock_ssh_evidence_number")
        return decoded
    def constant(_):
        raise ValueError("invalid_stock_ssh_evidence_number")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_float=number, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid_stock_ssh_evidence_json") from error
    if type(value) is not dict:
        raise ValueError("invalid_stock_ssh_evidence_json")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > contract.EVIDENCE_BOUNDS["max_json_depth"]:
            raise ValueError("stock_ssh_evidence_json_depth")
        children = item.values() if type(item) is dict else item if type(item) is list else ()
        pending.extend((child, depth + 1) for child in children)
    return value


def _directory_contents(directory_fd):
    names, total = set(), 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > contract.EVIDENCE_BOUNDS["max_files"] or entry.name not in FILES:
                raise ValueError("stock_evidence_file_limit")
            info = entry.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError("invalid_stock_evidence_artifact")
            total += info.st_size
            if total > MAX_BYTES:
                raise ValueError("stock_evidence_aggregate_limit")
    return names, total


def validate_outcome(value, manifest, result):
    from .controller import result_metadata
    action = parse_action(contract.action(manifest["selection"]))
    policy = contract.validate_policy(manifest["policy"], manifest["selection"])
    decision = policy.evaluate(action)
    fixed = {"action_id": action.action_id, "action_digest": action.digest,
        "policy_version": policy.policy_version, "policy_digest": policy.digest,
        "session_id": manifest["session_id"], "session_step": 1, "tool_id": action.tool_id,
        "target": action.target, "decision": decision.decision}
    fields = set(fixed) | {"approval_reference", "reasons", "execution_status"}
    if result is not None:
        fields |= {"execution_id", "result_metadata"}
    if (type(value) is not dict or set(value) != fields or any(value[key] != item or type(value[key]) is not type(item) for key, item in fixed.items())
            or type(value["reasons"]) is not list or any(type(reason) is not str for reason in value["reasons"])
            or value["reasons"] not in [list(decision.reasons), ["noninteractive_approval_required"],
                ["isolation_unavailable"], ["session_timeout"], ["session_cancelled"], ["approval_missing"],
                ["approval_unknown_or_replayed"], ["approval_expired"], ["approval_action_changed"], ["approval_policy_changed"]]):
        raise ValueError("invalid_stock_outcome_binding")
    reference = value["approval_reference"]
    if reference is not None and (not policy.require_approval or type(reference) is not str or len(reference) != 48
                                  or any(character not in "0123456789abcdef" for character in reference)):
        raise ValueError("invalid_stock_approval_reference")
    if result is None:
        if value["execution_status"] not in {"dry_run", "blocked"}:
            raise ValueError("stock_outcome_without_execution")
    elif (not _uuid(value["execution_id"]) or value["execution_status"] != result["status"]
            or spec.encode(value["result_metadata"]) != spec.encode(result_metadata(result))
            or policy.require_approval and reference is None):
        raise ValueError("stock_outcome_execution_mismatch")
    return deepcopy(value)


def validate_manifest(value):
    fields = {"schema_version", "assessment_id", "session_id", "selection", "policy", "limits", "runtime", "identity"}
    if type(value) is not dict or set(value) != fields or value["schema_version"] != "1" or not _uuid(value["assessment_id"]):
        raise ValueError("invalid_stock_evidence_manifest")
    selected = contract.validate_selection(value["selection"])
    contract.validate_policy(value["policy"], selected)
    contract.validate_limits(value["limits"], selected)
    runtime = contract.validate_runtime(value["runtime"], selected)
    contract.validate_identity(value["identity"], selection=selected, session_id=value["session_id"], runtime=runtime)
    return deepcopy(value)



def validate_result(result, manifest, *, deadline=None):
    """Reparse bytes in a networkless worker; saved conclusions grant nothing."""
    from .stock_ssh_parser_runtime import parse_isolated_tool_output
    from .stock_ssh_parser import parser_version
    from .stock_ssh_client_runtime import boundary_names, client_runtime_module
    if type(result) is not dict or result.get("status") not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}:
        raise ValueError("invalid_stock_ssh_result")
    if set(result) == {"status"} and result["status"] != "succeeded":
        return None
    selected = manifest["selection"]
    action = contract.action(selected)
    tool = action["tool_id"]
    fields = {"status", "results", "bytes_received", "truncated", "boundary_checks", "timing", "tool_observation",
              "backend", "stock_ssh_owner", "owned_lab", "stock_ssh_closure", "raw_output_base64", "raw_stderr_base64", "provenance"}
    if (set(result) != fields or result["results"] != [] or type(result["bytes_received"]) is not int
            or type(result["truncated"]) is not bool or result["truncated"] != (result["status"] == "output_limit")
            or type(result["boundary_checks"]) is not dict or set(result["boundary_checks"]) != set(boundary_names(selected))
            or any(flag is not True for flag in result["boundary_checks"].values())):
        raise ValueError("invalid_stock_ssh_result_shape")
    contract.validate_result_context(result, manifest["identity"], tool_id=tool, execution_status=result["status"])
    timing = result["timing"]
    if (type(timing) is not dict or set(timing) != {"owner_startup_ms", "client_startup_ms", "action_elapsed_ms", "owner_teardown_ms"}
            or any(type(item) is not int or not 0 <= item <= 60000 for item in timing.values())):
        raise ValueError("invalid_stock_ssh_timing")
    decoded = []
    for field in ("raw_output_base64", "raw_stderr_base64"):
        encoded = result[field]
        if type(encoded) is not str or len(encoded) > 10924:
            raise ValueError("invalid_stock_ssh_output_encoding")
        payload = base64.b64decode(encoded, validate=True)
        if base64.b64encode(payload).decode("ascii") != encoded:
            raise ValueError("invalid_stock_ssh_output_encoding")
        decoded.append(payload)
    raw, stderr = decoded
    provenance = result["provenance"]
    if (type(provenance) is not dict or set(provenance) != {"runtime_sha256", "runtime_manifest", "output_sha256",
            "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
            or provenance["runtime_manifest"] != manifest["runtime"]["client"]
            or provenance["runtime_sha256"] != client_runtime_module(selected).manifest_digest(manifest["runtime"]["client"])
            or provenance["output_sha256"] != hashlib.sha256(raw).hexdigest()
            or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
            or provenance["parser_version"] != parser_version(tool) or type(provenance["exit_code"]) is not int
            or provenance["stop_reason"] != (result["status"] if result["status"] in {"timeout", "output_limit"} else None)
            or result["status"] == "succeeded" and provenance["exit_code"] != 0):
        raise ValueError("invalid_stock_ssh_native_provenance")
    if len(raw) + len(stderr) != result["bytes_received"] or len(raw) + len(stderr) > action["parameters"]["max_output_bytes"]:
        raise ValueError("invalid_stock_ssh_output_accounting")
    parsed = None
    if result["status"] == "succeeded":
        try:
            parsed = parse_isolated_tool_output(tool, raw, stderr, configuration=selected["configuration"], deadline=deadline)
        except ValueError:
            pass
    if spec.encode(parsed) != spec.encode(result["tool_observation"]):
        raise ValueError("stock_ssh_observation_replay_mismatch")
    return parsed


def _native_case_verified(selected, result):
    if result is None or "stock_ssh_owner" not in result:
        return False
    owner = result["stock_ssh_owner"]
    ledger = owner["recorder"]
    case = selected["case"]
    permitted_stops = {"processes_exited", "stock_ssh_instance_cancelled"}
    if case == "N3":
        permitted_stops.add("stock_ssh_instance_timeout")
    if any(instance["receipt"]["stop_reason"] not in permitted_stops for instance in owner["instances"]):
        return False
    if ledger["connections_denied"] != 0 or not ledger["connections_admitted"]:
        return False
    if ledger["terminal_reason"] not in ({"response_limit"} if case == "N4" else {"closed", "action_deadline"}):
        return False
    rows = [row for row in ledger["connections"] if row["server_messages"]]
    if not rows or any(row["reason"] in {"instance_failure", "daemon_response_invalid", "io_failure"} for row in ledger["connections"]):
        return False
    expected_stages = (["identification"] if case in spec.NMAP_CASES or case in ("N3", "N4")
                       else ["identification", "kexinit"] if case == "N6" else ["identification", "kexinit", "key_reply"])
    if not any([message["stage"] for message in row["server_messages"]] == expected_stages for row in rows):
        return False
    expected_fault = {"N1": "malformed_identification", "N2": "truncated_host_key_reply",
        "N3": "withheld_until_deadline", "N4": "cross_wire_capture_cap",
        "N5": "unsupported_rsa1024_blob", "N6": "unsupported_host_key_algorithm"}.get(case)
    transformations = [item for row in rows for item in row["transforms"]]
    if expected_fault is not None and not any(item["disposition"] == expected_fault for item in transformations):
        return False
    if case == "R2" and any(item["disposition"] != "fragmented" for item in transformations):
        return False
    if case not in (*spec.NMAP_CASES, "N3", "N4"):
        from .stock_ssh_process import EXECUTABLES
        if not any([event["image"] for event in instance["receipt"]["events"] if event["operation"] == "exec_completed"]
                   == list(EXECUTABLES)
                   and sum(event["operation"] == "fork_completed" for event in instance["receipt"]["events"]) == 2
                   for instance in owner["instances"]):
            return False
    return True


def report_for(manifest, result, outcome, elapsed_ms, *, deadline=None):
    manifest = validate_manifest(manifest)
    selected = manifest["selection"]
    policy = contract.validate_policy(manifest["policy"], selected)
    validate_outcome(outcome, manifest, result)
    if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 120000:
        raise ValueError("invalid_stock_ssh_elapsed")
    observation = validate_result(result, manifest, deadline=deadline) if result is not None else None
    if result is not None and outcome["execution_status"] != result["status"]:
        raise ValueError("stock_ssh_status_changed")
    case = selected["case"]
    ledger = None if result is None else result.get("stock_ssh_owner", {}).get("recorder")
    native = _native_case_verified(selected, result)
    useful = False
    if native and observation is not None and case not in spec.NEGATIVE_CASES:
        if case in spec.NMAP_CASES:
            useful = observation.get("identification") == "identified" and observation.get("service") == {
                "name": "ssh", "product": "OpenSSH", "version": spec.OPENSSH_VERSION}
        else:
            expected = spec.public_test_key_facts()
            useful = all(observation.get(key) == expected[key] for key in
                ("key_type", "key_bits", "key_base64", "fingerprint_sha256", "trust"))
    classification = "useful" if useful else "inconclusive"
    basis = None
    if result is not None and result.get("status") in {"timeout", "output_limit"}:
        classification, basis = result["status"], "client_watchdog"
    if native and case == "N4" and ledger["terminal_reason"] == "response_limit":
        classification, basis = "output_limit", "independent_recorder_wire_cap"
    # Preserve the native failed exit. Only the timed withheld-response case
    # qualifies as a native timeout, corroborated by the recorder and latency.
    if (native and case == "N3" and observation is None and result["status"] in {"failed", "timeout"}
            and result["timing"]["action_elapsed_ms"] >= 1900
            and ledger["client_bytes_delivered"] == 0):
        classification, basis = "timeout", "withheld_response_and_native_two_second_timeout"
    no_positive = observation is None or case == "N1" and observation.get("identification") == "unidentified"
    expected_negative = bool(native and case in spec.NEGATIVE_CASES and no_positive
        and classification in spec.expectation(case)["allowed_outcomes"])
    passed = bool(native and (expected_negative if case in spec.NEGATIVE_CASES else useful))
    return {"schema_version": "1", "assessment_id": manifest["assessment_id"], "session_id": manifest["session_id"],
        "selection": selected, "profile": contract.PROFILE, "implementation": "openssh", "diagnostic_only": False,
        "disconnected_owned_lab_only": True,
        "approval_mode": "required" if policy.require_approval else "explicit_unattended_owned_lab_test",
        "execution_status": outcome["execution_status"], "classification": classification, "classification_basis": basis,
        "native_response_verified": bool(native), "case_passed": passed, "observation": observation,
        "metrics": {"useful_completion": useful, "expected_negative": expected_negative,
            "unnecessary_refusal": not useful if case not in spec.NEGATIVE_CASES else None,
            "actual_provider_calls": 0, "actual_cost_microusd": 0, "elapsed_ms": elapsed_ms,
            "timing": None if result is None else result.get("timing"),
            "connections_attempted": None if ledger is None else ledger["connections_attempted"],
            "connections_admitted": None if ledger is None else ledger["connections_admitted"],
            "connections_denied": None if ledger is None else ledger["connections_denied"],
            "client_packets_forwarded": None if ledger is None else ledger["client_packets_forwarded"],
            "server_key_replies_forwarded": None if ledger is None else ledger["server_key_replies_forwarded"]},
        "limitations": ["Finite disconnected owned SSH compatibility only; no attached or external network support.",
            "Host keys remain unverified observations; no authentication or encrypted user session is attempted.",
            "Mediator faults are labeled transformations of preserved original stock bytes.",
            "Unattended test policy is not a personal approval or permission for another action.",
            "Hashes establish saved-evidence consistency, not tamper resistance against a compromised host.",
            "Comparative overhead, credentials and live-model evaluation remain deferred."]}

class StockSshEvidenceStore(EvidenceStore):
    def __init__(self, directory, manifest, *, deadline=None):
        self.directory = Path(directory)
        self._fd = self._journal = None
        self._failed = self._finalized = False
        self._lock = threading.Lock()
        self._manifest = validate_manifest(manifest)
        self._deadline = deadline
        self._record = self._result = None
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._write_new("manifest.json", spec.encode(self._manifest), MAX_BYTES)
        except BaseException:
            self.close()
            raise

    def _write_new(self, name, raw, limit):
        self._check()
        names, total = _directory_contents(self._fd)
        if name not in FILES or len(names | {name}) > contract.EVIDENCE_BOUNDS["max_files"]:
            raise EvidenceUnavailable("stock_evidence_file_limit")
        if total + len(raw) > MAX_BYTES:
            raise EvidenceUnavailable("stock_evidence_aggregate_limit")
        return super()._write_new(name, raw, min(limit, MAX_JSON_BYTES))

    def start(self, action, policy, *, session_id, session_step, backend):
        self._check()
        if (self._record is not None or session_id != self._manifest["session_id"] or session_step != 1
                or backend != contract.BACKEND or action.to_dict() != contract.action(self._manifest["selection"])
                or policy.to_dict() != self._manifest["policy"]):
            raise EvidenceUnavailable("invalid_stock_evidence_start")
        self._record = {"execution_id": str(uuid4()), "action": action.to_dict(), "session_id": session_id,
                        "session_step": session_step, "backend": backend}
        self._write_new("intent.json", spec.encode(self._record), MAX_BYTES)
        return self._record["execution_id"]

    def finish(self, execution_id, result, *, execution_status):
        self._check()
        if (self._record is None or execution_id != self._record["execution_id"] or self._result is not None
                or result.get("status") != execution_status):
            raise EvidenceUnavailable("invalid_stock_evidence_completion")
        validate_result(result, self._manifest, deadline=self._deadline)
        self._write_new("result.json", spec.encode(result), MAX_BYTES)
        self._result = deepcopy(result)

    def finalize(self, outcome, *, elapsed_ms):
        self._check()
        safe = {key: item for key, item in outcome.items() if key != "untrusted_result"}
        if (self._record is not None and (self._result is None or safe.get("execution_id") != self._record["execution_id"])):
            raise EvidenceUnavailable("stock_evidence_incomplete")
        report = report_for(self._manifest, self._result, safe, elapsed_ms, deadline=self._deadline)
        self._write_new("outcome.json", spec.encode({"outcome": safe, "elapsed_ms": elapsed_ms}), MAX_BYTES)
        self._write_new("report.json", spec.encode(report), MAX_BYTES)
        self._finalized = True
        return report


def _validate_audit(events, manifest, outcome, result):
    validate_outcome(outcome, manifest, result)
    action = parse_action(contract.action(manifest["selection"]))
    policy = contract.validate_policy(manifest["policy"], manifest["selection"])
    initial = {key: outcome[key] for key in ("action_id", "action_digest", "policy_version", "policy_digest",
        "session_id", "session_step", "tool_id", "target", "decision")}
    initial.update(approval_reference=None, reasons=list(policy.evaluate(action).reasons), execution_status="not_started")
    expected = [{**initial, "event_type": "policy_decision",
        "untrusted_agent_context": {"rationale": "[REDACTED]", "rationale_length": len(action.rationale)}}]
    if policy.require_approval and outcome["approval_reference"] is not None:
        initial["approval_reference"] = outcome["approval_reference"]
        expected.append({**initial, "event_type": "approval_consumed"})
    if result is not None:
        expected.extend([{**initial, "event_type": "execution_started", "execution_status": "started",
                          "execution_id": outcome["execution_id"], "backend": contract.BACKEND},
                         {**outcome, "event_type": "execution_finished", "backend": contract.BACKEND}])
    elif outcome["execution_status"] == "blocked":
        kind = "approval_rejected" if policy.require_approval and outcome["approval_reference"] is None else "execution_blocked"
        expected.append({**outcome, "event_type": kind})
    if len(events) != len(expected):
        raise ValueError("stock_audit_sequence_mismatch")
    envelope = {"event_schema_version", "event_id", "timestamp", "source"}
    identifiers = set()
    for event, payload in zip(events, expected, strict=True):
        if (type(event) is not dict or set(event) != set(payload) | envelope
                or event["event_schema_version"] != "1" or event["source"] != "recon-cockpit.secure-agent"
                or not _uuid(event["event_id"]) or event["event_id"] in identifiers
                or type(event["timestamp"]) is not str or not 1 <= len(event["timestamp"]) <= 64):
            raise ValueError("invalid_stock_audit_event")
        identifiers.add(event["event_id"])
        try:
            stamp = datetime.fromisoformat(event["timestamp"])
        except ValueError:
            raise ValueError("invalid_stock_audit_timestamp") from None
        if stamp.utcoffset() != timedelta(0):
            raise ValueError("invalid_stock_audit_timestamp")
        if spec.encode({key: event[key] for key in payload}) != spec.encode(payload):
            raise ValueError("stock_audit_binding_mismatch")


def inspect_trial(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("invalid_stock_evidence_directory")
        names, _ = _directory_contents(fd)
        expected = {"manifest.json", "outcome.json", "report.json", "audit.jsonl"}
        executed = "intent.json" in names
        if names != expected | ({"intent.json", "result.json"} if executed else set()):
            raise ValueError("invalid_stock_evidence_files")
        read = lambda name: _decode(_read_private(fd, name, MAX_JSON_BYTES))
        manifest, saved = validate_manifest(read("manifest.json")), read("outcome.json")
        if type(saved) is not dict or set(saved) != {"outcome", "elapsed_ms"}:
            raise ValueError("invalid_stock_saved_outcome")
        outcome = saved["outcome"]
        if executed:
            intent = read("intent.json")
            if intent != {"execution_id": outcome.get("execution_id"), "action": contract.action(manifest["selection"]),
                          "session_id": manifest["session_id"], "session_step": 1, "backend": contract.BACKEND} or not _uuid(intent["execution_id"]):
                raise ValueError("invalid_stock_saved_intent")
        audit = _read_private(fd, "audit.jsonl", MAX_BYTES)
        if not audit.endswith(b"\n") or len(audit.splitlines()) > 8:
            raise ValueError("invalid_stock_audit")
        events = [_decode(line) for line in audit.splitlines()]
        result = read("result.json") if executed else None
        _validate_audit(events, manifest, outcome, result)
        recomputed = report_for(manifest, result, outcome, saved["elapsed_ms"])
        if spec.encode(recomputed) != spec.encode(read("report.json")):
            raise ValueError("stock_report_replay_mismatch")
        return recomputed
    finally:
        os.close(fd)
