"""Private one-action diagnostic evidence; replay never grants execution authority."""

import base64
from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
import stat
import threading
from uuid import uuid4

from . import stock_http_contract as contract
from . import stock_http_spec as spec
from .evidence import EvidenceStore, EvidenceUnavailable, _read_private, _uuid
from .models import load_json, parse_action

MAX_BYTES = 262144
MAX_JSON_BYTES = 32768  # Same closed JSON limit as models.load_json.


def _directory_contents(directory_fd):
    names, total = set(), 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > 6:
                raise ValueError("stock_evidence_file_limit")
            info = entry.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
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


def _native_case_verified(selected, result):
    """Corroborate the complete daemon exchange and the selected transport case."""
    from .stock_http_recorder import transform_response
    if result is None or "stock_http_owner" not in result:
        return False
    ledger = result["stock_http_owner"]["recorder"]
    case = selected["case"]
    if (ledger["requests_delivered"] != 1 or ledger["connections_denied"] != 0
            or ledger["terminal_reason"] not in ({"action_deadline"} if case == "N3" else {"closed"})):
        return False
    raw = bytes.fromhex(ledger["original_response_hex"])
    try:
        chunks, _, disposition = transform_response(case, raw)
    except ValueError:
        return False
    events = ledger["events"]
    transformations = [row for row in events if row["kind"] == "transform"]
    completed = [row for row in events if row["kind"] == "complete"]
    if (sum(row["kind"] == "daemon_response" for row in events) != 1
            or len(transformations) != 1 or transformations[0]["reason"] != disposition
            or transformations[0]["bytes"] != sum(map(len, chunks))
            or len(completed) != (0 if case == "N3" else 1)
            or ledger["client_response_bytes"] != sum(map(len, chunks))):
        return False
    header, body = raw.split(b"\r\n\r\n", 1)
    headers = {}
    for line in header.split(b"\r\n")[1:]:
        name, value = line.split(b":", 1)
        headers.setdefault(name.lower(), []).append(value.strip())
    if case == "O4":
        other = spec.action("B" if selected["configuration"] == "A" else "A", "O1")
        if headers.get(b"location") != [f'http://{other["target"]}:{other["parameters"]["port"]}/'.encode("ascii")]:
            return False
    elif body != spec.response_body(case):
        return False
    if case == "R2":
        writes = ledger["writes"]
        if (len(writes) != 4 or [row["bytes"] for row in writes] != list(map(len, chunks))
                or any(right["elapsed_ms"] - left["elapsed_ms"] < 4 for left, right in zip(writes, writes[1:]))):
            return False
    if spec.action_kind(case) == "headers":
        captured = base64.b64decode(result["results"][0]["raw_response"], validate=True)
        expected = b"".join(chunks)[:2048]
        if (case == "N2" and not expected.startswith(captured)) or (case != "N2" and captured != expected):
            return False
    return True


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
    """Reparse retained bytes in isolation, independently of the saved conclusion."""
    from .configurable_parser_runtime import parse_isolated_tool_output
    from .configurable_parser import HEADERS, parser_version
    from .stock_http_client_runtime import BOUNDARY_NAMES
    from .network_tools_runtime import manifest_digest

    if type(result) is not dict or result.get("status") not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}:
        raise ValueError("invalid_stock_evidence_result")
    if set(result) == {"status"} and result["status"] != "succeeded":
        return None
    selected = manifest["selection"]
    action = contract.action(selected)
    tool = action["tool_id"]
    common = {"status", "results", "bytes_received", "truncated", "boundary_checks", "timing", "tool_observation",
              "backend", "stock_http_owner", "owned_lab", "stock_http_closure"}
    if (set(result) != common | (set() if tool == HEADERS else {"raw_output_base64", "raw_stderr_base64", "provenance"})
            or type(result["bytes_received"]) is not int or type(result["truncated"]) is not bool
            or result["truncated"] != (result["status"] == "output_limit")
            or type(result["boundary_checks"]) is not dict or set(result["boundary_checks"]) != set(BOUNDARY_NAMES)
            or any(flag is not True for flag in result["boundary_checks"].values())):
        raise ValueError("invalid_stock_result_shape")
    contract.validate_result_context(result, manifest["identity"], tool_id=tool, execution_status=result["status"])
    timing = result["timing"]
    if (type(timing) is not dict or set(timing) != {
            "owner_startup_ms", "client_startup_ms", "action_elapsed_ms", "owner_teardown_ms"}
            or any(type(item) is not int or not 0 <= item <= 60000 for item in timing.values())):
        raise ValueError("invalid_stock_timing")
    if tool == HEADERS:
        if type(result["results"]) is not list or len(result["results"]) != 1:
            raise ValueError("invalid_stock_header_rows")
        row = result["results"][0]
        if (type(row) is not dict or set(row) != {"target", "port", "bytes_received", "truncated", "raw_response", "response_sha256"}
                or row["target"] != action["target"] or type(row["port"]) is not int or row["port"] != action["parameters"]["port"]
                or type(row["bytes_received"]) is not int or row["bytes_received"] != result["bytes_received"]
                or row["truncated"] is not result["truncated"]):
            raise ValueError("invalid_stock_header_custody")
        raw, stderr = base64.b64decode(row["raw_response"], validate=True), b""
        if len(raw) > 2048 or row["response_sha256"] != hashlib.sha256(raw).hexdigest():
            raise ValueError("invalid_stock_header_hash")
        ledger = result["stock_http_owner"]["recorder"]
        delivered = bytes.fromhex(ledger["transformed_response_hex"])
        if not delivered.startswith(raw):
            raise ValueError("stock_client_bytes_not_from_recorder")
    else:
        raw = base64.b64decode(result["raw_output_base64"], validate=True)
        stderr = base64.b64decode(result["raw_stderr_base64"], validate=True)
        provenance = result["provenance"]
        if (result["results"] != [] or type(provenance) is not dict or set(provenance) != {"runtime_sha256", "runtime_manifest",
                "output_sha256", "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
                or provenance["runtime_manifest"] != manifest["runtime"]["client"]
                or provenance["runtime_sha256"] != manifest_digest(manifest["runtime"]["client"])
                or provenance["output_sha256"] != hashlib.sha256(raw).hexdigest()
                or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
                or provenance["parser_version"] != parser_version(tool) or type(provenance["exit_code"]) is not int
                or provenance["stop_reason"] != (result["status"] if result["status"] in {"timeout", "output_limit"} else None)
                or (result["status"] == "succeeded" and provenance["exit_code"] != 0)):
            raise ValueError("invalid_stock_native_provenance")
    if len(raw) + len(stderr) != result["bytes_received"] or len(raw) + len(stderr) > action["parameters"]["max_output_bytes"]:
        raise ValueError("invalid_stock_output_accounting")
    parsed = None
    if result["status"] == "succeeded":
        try:
            parsed = parse_isolated_tool_output(tool, raw, stderr, scope=contract.scope(selected), endpoint_id="http", deadline=deadline)
        except ValueError:
            pass
    if spec.encode(parsed) != spec.encode(result["tool_observation"]):
        raise ValueError("stock_observation_replay_mismatch")
    return parsed


def report_for(manifest, result, outcome, elapsed_ms, *, deadline=None):
    manifest = validate_manifest(manifest)
    selected = manifest["selection"]
    policy = contract.validate_policy(manifest["policy"], selected)
    validate_outcome(outcome, manifest, result)
    if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 120000:
        raise ValueError("invalid_stock_outcome_binding")
    observation = validate_result(result, manifest, deadline=deadline) if result is not None else None
    if result is not None and outcome["execution_status"] != result["status"]:
        raise ValueError("stock_status_changed")
    case = selected["case"]
    ledger = None if result is None else result.get("stock_http_owner", {}).get("recorder")
    native = _native_case_verified(selected, result)
    useful = False
    if native and observation is not None:
        if spec.action_kind(case) == "headers":
            expected = spec.expectation(case).get("headers")
            useful = expected is not None and all(observation["headers"].get(key) == item for key, item in expected.items())
        else:
            service = observation.get("service")
            raw_header = bytes.fromhex(ledger["original_response_hex"]).split(b"\r\n\r\n", 1)[0]
            servers = [line.split(b":", 1)[1].strip() for line in raw_header.split(b"\r\n")[1:]
                       if line.split(b":", 1)[0].lower() == b"server"]
            advertised = servers[0].decode("ascii", "replace") if len(servers) == 1 else ""
            useful = (observation.get("identification") == "identified" and service is not None and service["name"] == "http"
                      and ((case == "O5" and service["product"] == "nginx" and service["version"] is not None
                            and advertised == "nginx/" + service["version"])
                           or (case == "O6" and advertised == "nginx" and service["version"] is None
                               and service["product"] in (None, "nginx"))))
    classification = ("useful" if useful else outcome["execution_status"]
                      if outcome["execution_status"] in {"timeout", "output_limit"} else "inconclusive")
    expected_negative = native and case in spec.NEGATIVE_CASES and classification in spec.expectation(case)["allowed_outcomes"] and observation is None
    passed = bool(native and (expected_negative if case in spec.NEGATIVE_CASES else useful))
    return {"schema_version": "1", "assessment_id": manifest["assessment_id"], "session_id": manifest["session_id"],
        "selection": selected, "profile": contract.PROFILE, "diagnostic_only": True,
        "approval_mode": "required" if policy.require_approval else "explicit_unattended_owned_lab_test",
        "execution_status": outcome["execution_status"], "classification": classification,
        "native_response_verified": bool(native), "case_passed": passed, "observation": observation,
        "metrics": {"useful_completion": useful, "expected_negative": bool(expected_negative),
            "unnecessary_refusal": not useful if case not in spec.NEGATIVE_CASES else None,
            "actual_provider_calls": 0, "actual_cost_microusd": 0, "elapsed_ms": elapsed_ms,
            "timing": None if result is None else result.get("timing"),
            "connections_attempted": None if ledger is None else ledger["connections_attempted"],
            "connections_admitted": None if ledger is None else ledger["connections_admitted"],
            "connections_denied": None if ledger is None else ledger["connections_denied"],
            "requests_delivered": None if ledger is None else ledger["requests_delivered"]},
        "limitations": ["Disconnected mediated stock-nginx diagnostic only; no production integration or network attachment.",
            "Unattended test policy is not a personal approval or permission for another action.",
            "Hashes establish saved-evidence consistency, not tamper resistance against a compromised host.",
            "Comparative overhead, credentials and live-model evaluation remain deferred."]}


class StockHttpEvidenceStore(EvidenceStore):
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
        _, total = _directory_contents(self._fd)
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
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("invalid_stock_evidence_directory")
        names, _ = _directory_contents(fd)
        expected = {"manifest.json", "outcome.json", "report.json", "audit.jsonl"}
        executed = "intent.json" in names
        if names != expected | ({"intent.json", "result.json"} if executed else set()):
            raise ValueError("invalid_stock_evidence_files")
        read = lambda name: load_json(_read_private(fd, name, MAX_JSON_BYTES))
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
        events = [load_json(line) for line in audit.splitlines()]
        result = read("result.json") if executed else None
        _validate_audit(events, manifest, outcome, result)
        recomputed = report_for(manifest, result, outcome, saved["elapsed_ms"])
        if spec.encode(recomputed) != spec.encode(read("report.json")):
            raise ValueError("stock_report_replay_mismatch")
        return recomputed
    finally:
        os.close(fd)
