"""Private artifacts and independent, read-only replay of configurable lab work."""

import base64
from copy import deepcopy
import hashlib
from functools import wraps
import os
from pathlib import Path
import re
import threading
from uuid import uuid4

from .audit import AuditSink
from .evidence import (EvidenceStore, EvidenceUnavailable, _read_private, _uuid, _now,
                       _observation_digest, MAX_JOURNAL_BYTES)
from .models import load_json, parse_action
from . import configurable_contract as contract, configurable_workflow as workflow
from .configurable_lab_contract import validate_assessment_identity, validate_assessment_closure
from .configurable_scope import validate_scope, scope_digest

MAX_ARTIFACT_BYTES = 32768
MAX_REPORT_BYTES = 65536
STATUSES = {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}


def _durable_operation(method):
    """Any failed evidence operation poisons the store; never retry a partial write."""
    @wraps(method)
    def checked(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
            self._failed = True
            raise EvidenceUnavailable("evidence_unavailable") from None
    return checked


def _bindings(value):
    if value is None:
        return None
    if (type(value) is not dict or set(value) != {contract.NMAP, contract.SSH}
            or any(type(item) is not str or re.fullmatch(r"[a-f0-9]{64}", item) is None for item in value.values())):
        raise ValueError("invalid_configurable_runtime_bindings")
    return dict(value)


def validate_manifest(value):
    fields = {"schema_version", "assessment_id", "session_id", "workflow", "scope", "scope_sha256",
              "policy_digest", "created_at", "owned_lab", "runtime_bindings", "workflow_card"}
    if (type(value) is not dict or set(value) != fields or value["schema_version"] != "1"
            or value["workflow"] != contract.WORKFLOW or not _uuid(value["assessment_id"])
            or not _uuid(value["session_id"]) or value["scope_sha256"] != scope_digest(value["scope"])
            or value["workflow_card"] != workflow.card_identity(value["scope"])
            or type(value["policy_digest"]) is not str or re.fullmatch(r"[a-f0-9]{64}", value["policy_digest"]) is None
            or type(value["created_at"]) is not str or not 1 <= len(value["created_at"]) <= 64):
        raise ValueError("invalid_configurable_evidence_manifest")
    validate_assessment_identity(value["owned_lab"], scope=value["scope"])
    _bindings(value["runtime_bindings"])
    return deepcopy(value)


def validate_result(result, manifest, step, status, previous, *, deadline=None):
    """Validate custody, actual scoped bytes, isolated parser output and counters."""
    if (type(step) is not int or not 1 <= step <= 4 or type(status) is not str
            or status not in STATUSES or type(result) is not dict or result.get("status") != status):
        raise ValueError("invalid_configurable_evidence_result")
    if set(result) == {"status"} and status != "succeeded":
        return previous, {"tool_id": contract.TOOL_IDS[step - 1], "classification": "inconclusive",
                          "reason": "complete_validated_evidence_missing", "details": None}
    from .configurable_runtime import BOUNDARY_NAMES, underlying_tool
    from .configurable_parser import parser_version
    from .configurable_parser_runtime import parse_isolated_tool_output
    from .network_tools_runtime import validate_manifest as native_manifest, manifest_digest

    tool = contract.TOOL_IDS[step - 1]
    common = {"status", "results", "bytes_received", "truncated", "boundary_checks", "tool_observation",
              "backend", "scope_step", "scope_sha256", "owned_lab"}
    native_fields = {"raw_output_base64", "raw_stderr_base64", "provenance"}
    if (set(result) != common | (set() if tool == contract.HEADERS else native_fields)
            or result["scope_step"] != step or type(result["bytes_received"]) is not int
            or type(result["truncated"]) is not bool
            or type(result["boundary_checks"]) is not dict
            or set(result["boundary_checks"]) != set(BOUNDARY_NAMES)
            or any(flag is not True for flag in result["boundary_checks"].values())
            or result["truncated"] != (status == "output_limit")):
        raise ValueError("invalid_configurable_result_shape")
    context = contract.validate_result_context(result, manifest["owned_lab"], previous=previous,
        tool_id=tool, execution_status=status)
    if tool == contract.HEADERS:
        if type(result["results"]) is not list or len(result["results"]) != 1:
            raise ValueError("invalid_configurable_header_rows")
        row = result["results"][0]
        selected = manifest["scope"]["http"]
        if (type(row) is not dict or set(row) != {"target", "port", "bytes_received", "truncated", "raw_response", "response_sha256"}
                or row["target"] != selected["target"] or type(row["port"]) is not int or row["port"] != selected["port"]
                or type(row["bytes_received"]) is not int or row["bytes_received"] != result["bytes_received"]
                or row["truncated"] is not result["truncated"]):
            raise ValueError("invalid_configurable_header_custody")
        raw, stderr = base64.b64decode(row["raw_response"], validate=True), b""
        if len(raw) > 2048 or row["response_sha256"] != hashlib.sha256(raw).hexdigest():
            raise ValueError("invalid_configurable_header_hash")
    else:
        if result["results"] != []:
            raise ValueError("invalid_configurable_native_rows")
        raw = base64.b64decode(result["raw_output_base64"], validate=True)
        stderr = base64.b64decode(result["raw_stderr_base64"], validate=True)
        provenance = result["provenance"]
        if (type(provenance) is not dict or set(provenance) != {"runtime_sha256", "runtime_manifest",
                "output_sha256", "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
                or type(provenance["exit_code"]) is not int
                or provenance["parser_version"] != parser_version(tool)
                or provenance["output_sha256"] != hashlib.sha256(raw).hexdigest()
                or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
                or not manifest["runtime_bindings"]
                or provenance["runtime_sha256"] != manifest["runtime_bindings"][tool]
                or manifest_digest(native_manifest(provenance["runtime_manifest"], tool_id=underlying_tool(tool))) != provenance["runtime_sha256"]
                or provenance["stop_reason"] != (status if status in ("timeout", "output_limit") else None)
                or (status == "succeeded" and provenance["exit_code"] != 0)
                or (status == "failed" and provenance["exit_code"] == 0)):
            raise ValueError("invalid_configurable_native_provenance")
    if len(raw) + len(stderr) != result["bytes_received"] or len(raw) + len(stderr) > 8192:
        raise ValueError("invalid_configurable_output_accounting")
    parsed = None
    if status == "succeeded":
        try:
            parsed = parse_isolated_tool_output(tool, raw, stderr, scope=manifest["scope"],
                endpoint_id=contract.ENDPOINTS[step - 1], deadline=deadline)
        except ValueError:
            pass
    if contract.encode(parsed) != contract.encode(result["tool_observation"]):
        raise ValueError("configurable_observation_replay_mismatch")
    return context, contract.observation(manifest["scope"], step, result)


def _summary(value, manifest, records, decisions):
    fields = ("session_id", "session_status", "stop_reason", "steps_attempted", "actions_succeeded",
              "output_reserved_bytes", "mode")
    selected = {key: value[key] for key in fields}
    if (selected["session_id"] != manifest["session_id"] or selected["session_status"] not in ("completed", "stopped")
            or selected["mode"] not in ("execute", "dry_run") or type(selected["stop_reason"]) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", selected["stop_reason"]) is None
            or any(type(selected[key]) is not int or not 0 <= selected[key] <= cap for key, cap in
                   (("steps_attempted", 4), ("actions_succeeded", 4), ("output_reserved_bytes", 26624)))
            or selected["actions_succeeded"] != sum(row["status"] == "succeeded" for row in records)
            or len(records) > selected["steps_attempted"]
            or len(decisions) > selected["steps_attempted"]
            or selected["output_reserved_bytes"] < sum(row["action"]["parameters"]["max_output_bytes"] for row in records)
            or selected["output_reserved_bytes"] > sum(contract.action(manifest["scope"], row["step"])["parameters"]["max_output_bytes"]
                for row in decisions if row["action_digest"] is not None)
            or (selected["mode"] == "dry_run" and records)):
        raise ValueError("invalid_configurable_summary")
    if (selected["session_status"] == "completed"
            and (selected["stop_reason"] not in ("planner_done", "coordinator_done")
                 or not decisions or not decisions[-1]["done"]
                 or (decisions[-1]["action_digest"] is not None
                     and (not records or len(records) != len(decisions) or records[-1]["status"] != "succeeded")))):
        raise ValueError("invalid_configurable_terminal_summary")
    return selected


def _report(manifest, records, decisions, summary, closure, elapsed_ms):
    useful = sum(row["observation"]["classification"] == "observed" for row in records)
    completed = (summary["mode"] == "execute" and summary["session_status"] == "completed"
        and len(records) == 4 and useful == 4
        and all(contract.predecessor_gate(manifest["scope"], step, records[step - 1]["observation"]) for step in (1, 3)))
    return {"schema_version": "1", "assessment_id": manifest["assessment_id"], "workflow": contract.WORKFLOW,
        "scope": manifest["scope"], "scope_sha256": manifest["scope_sha256"], "workflow_card": manifest["workflow_card"],
        "outcome": "completed" if completed else "dry_run" if summary["mode"] == "dry_run" else "incomplete",
        "summary": summary, "records": records, "decisions": decisions, "lab_closure": closure,
        "metrics": {"legitimate_task_completed": completed, "useful_actions_completed": useful,
            "unnecessary_refusals": 0 if completed else None,
            "planned_actions": 4, "actual_provider_calls": 0, "actual_cost_microusd": 0,
            "elapsed_ms": elapsed_ms, "comparison_baseline": None},
        "integrity_issues": [], "limitations": [
            "Two disconnected owned endpoint fixtures; no shared internal network or external target attachment.",
            "Advertised service versions, HTTP headers and SSH public keys are untrusted metadata; no authenticated inventory or vulnerability proof.",
            "No authentication, credentials, shell, intrusive actions or live model calls.",
            "Boundary witnesses are listening endpoints positively checked before filtering. This is not a comparative benchmark.",
            "Unnecessary refusals are zero only for a completed known-legitimate fixture; incomplete runs are ungraded, including approval denial.",
            "Local hashes detect inconsistencies, not malicious host-owner rewriting. Closure counters are last acknowledged totals."]}


def markdown(report):
    lines = ["# Configurable owned HTTP/SSH assessment", "", "Outcome: **" + report["outcome"] + "**.", "",
             "| Endpoint | Address | Port |", "| --- | --- | --- |"]
    for name in ("http", "ssh"):
        endpoint = report["scope"][name]
        lines.append(f"| {name.upper()} | {endpoint['target']} | {endpoint['port']} |")
    lines += ["", f"Useful actions: {report['metrics']['useful_actions_completed']}/4. Model calls: 0. Cost: $0.",
              "", "Elapsed: " + str(report["metrics"]["elapsed_ms"]) + " ms.", "", "## Limits", ""]
    lines += ["- " + item for item in report["limitations"]]
    return ("\n".join(lines) + "\n").encode("ascii")


class ConfigurableEvidenceStore(EvidenceStore):
    """Reuse durable private file ownership; keep the new semantic contract separate."""

    def __init__(self, directory, *, session_id, policy, scope, owned_lab, runtime_bindings=None, deadline=None):
        self.directory = Path(directory)
        self._fd = self._journal = None
        self._failed = self._finalized = False
        self._records, self._decisions = [], []
        self._lab_context = self._lab_closure = None
        self._deadline = deadline
        self._lock = threading.Lock()
        self._manifest = validate_manifest({"schema_version": "1", "assessment_id": str(uuid4()),
            "session_id": session_id, "workflow": contract.WORKFLOW, "scope": validate_scope(scope),
            "scope_sha256": scope_digest(scope), "policy_digest": policy.digest, "created_at": _now(),
            "owned_lab": owned_lab, "runtime_bindings": runtime_bindings, "workflow_card": workflow.card_identity(scope)})
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._write_new("manifest.json", contract.encode(self._manifest), 8192)
            self._journal = AuditSink(self.directory / "evidence.jsonl")
        except (ValueError, OSError, RuntimeError):
            self.close()
            raise EvidenceUnavailable("evidence_unavailable") from None

    @_durable_operation
    def record_decision(self, step, observation):
        with self._lock:
            self._check()
            if (step != len(self._decisions) + 1 or self._lab_closure is not None
                    or any(row.get("artifact") is None for row in self._records)
                    or (self._decisions and self._decisions[-1]["done"])):
                raise EvidenceUnavailable("invalid_configurable_decision_order")
            decision = workflow.decide(self._manifest["scope"], step, self._records, observation)
            value = {**decision.to_dict(), "observation_sha256": hashlib.sha256(observation).hexdigest()}
            self._emit({"event_type": "configurable_decision", "decision": value})
            self._decisions.append(value)
            return decision

    @_durable_operation
    def start(self, action, policy, *, session_id, session_step, backend):
        with self._lock:
            self._check()
            if (session_id != self._manifest["session_id"] or policy.digest != self._manifest["policy_digest"]
                    or backend != contract.BACKEND or self._lab_closure is not None
                    or type(session_step) is not int or session_step != len(self._records) + 1
                    or action.to_dict() != contract.action(self._manifest["scope"], session_step)
                    or any(row.get("artifact") is None for row in self._records) or not self._decisions
                    or self._decisions[-1]["action_digest"] != action.digest):
                raise EvidenceUnavailable("invalid_configurable_execution_start")
            row = {"execution_id": str(uuid4()), "step": session_step, "action": action.to_dict(), "status": "started"}
            self._emit({"event_type": "configurable_execution_started", "record": row})
            self._records.append(row)
            return row["execution_id"]

    @_durable_operation
    def finish(self, execution_id, result, *, execution_status):
        with self._lock:
            self._check()
            if not self._records or self._records[-1]["execution_id"] != execution_id or self._records[-1]["status"] != "started":
                raise EvidenceUnavailable("invalid_configurable_completion")
            row = self._records[-1]
            context, observation = validate_result(result, self._manifest, row["step"], execution_status,
                                                   self._lab_context, deadline=self._deadline)
            raw = contract.encode(result)
            artifact = {"filename": "result-" + execution_id + ".json", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
            self._write_new(artifact["filename"], raw, MAX_ARTIFACT_BYTES)
            complete = {**row, "status": execution_status, "observation": observation, "artifact": artifact,
                        "authority_observation_sha256": _observation_digest(row["step"], execution_status, result)}
            self._emit({"event_type": "configurable_execution_finished", "record": complete})
            self._records[-1], self._lab_context = complete, context

    @_durable_operation
    def record_lab_closed(self, receipt):
        with self._lock:
            self._check()
            if self._lab_closure is not None or any(row.get("artifact") is None for row in self._records):
                raise EvidenceUnavailable("invalid_configurable_closure_order")
            self._lab_closure = validate_assessment_closure(receipt, self._manifest["owned_lab"],
                previous=None if self._lab_context is None else self._lab_context["endpoints"])
            self._emit({"event_type": "configurable_lab_closed", "receipt": self._lab_closure})

    @_durable_operation
    def finalize(self, summary, *, elapsed_ms):
        with self._lock:
            self._check()
            if self._lab_closure is None or type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 120000:
                raise EvidenceUnavailable("invalid_configurable_finalization")
            safe = _summary(summary, self._manifest, self._records, self._decisions)
            report = _report(self._manifest, self._records, self._decisions, safe, self._lab_closure, elapsed_ms)
            self._emit({"event_type": "configurable_finished", "summary": safe, "elapsed_ms": elapsed_ms})
            self._write_new("report.json", contract.encode(report), MAX_REPORT_BYTES)
            self._write_new("report.md", markdown(report), MAX_REPORT_BYTES)
            self._finalized = True
            return deepcopy(report)


def inspect_assessment(directory):
    """Recompute from private manifest/journal/artifacts, never resume or write."""
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("invalid_configurable_evidence_directory")
        names = set(os.listdir(fd))
        if len(names) > 8:
            raise ValueError("configurable_evidence_file_limit")
        manifest = validate_manifest(load_json(_read_private(fd, "manifest.json", 8192)))
        lines = _read_private(fd, "evidence.jsonl", MAX_JOURNAL_BYTES).splitlines(keepends=True)
        if len(lines) > 14 or any(not line.endswith(b"\n") for line in lines):
            raise ValueError("configurable_journal_limit_or_truncation")
        records, decisions, context, closure, final = [], [], None, None, None
        event_ids = set()
        referenced = {"manifest.json", "evidence.jsonl", "report.json", "report.md"}
        for raw in lines:
            event = load_json(raw)
            if (event.get("assessment_id") != manifest["assessment_id"] or event.get("session_id") != manifest["session_id"]
                    or final is not None):
                raise ValueError("configurable_journal_binding")
            kind = event["event_type"]
            payload_fields = {"configurable_decision": {"decision"}, "configurable_execution_started": {"record"},
                "configurable_execution_finished": {"record"}, "configurable_lab_closed": {"receipt"},
                "configurable_finished": {"summary", "elapsed_ms"}}
            envelope_fields = {"event_schema_version", "event_id", "timestamp", "source", "assessment_id", "session_id", "event_type"}
            if (type(kind) is not str or kind not in payload_fields or set(event) != envelope_fields | payload_fields[kind]
                    or event["event_schema_version"] != "1" or event["source"] != "recon-cockpit.secure-agent"
                    or not _uuid(event["event_id"]) or event["event_id"] in event_ids
                    or type(event["timestamp"]) is not str or not 1 <= len(event["timestamp"]) <= 64):
                raise ValueError("invalid_configurable_journal_event")
            event_ids.add(event["event_id"])
            if kind == "configurable_decision":
                if closure is not None or any(row.get("artifact") is None for row in records) or (decisions and decisions[-1]["done"]):
                    raise ValueError("configurable_decision_order")
                step = len(decisions) + 1
                decision = workflow.expected_decision(manifest["scope"], step, records).to_dict()
                from .session import _observation
                expected_hash = (records[-1]["authority_observation_sha256"] if records else
                    hashlib.sha256(_observation(step, None if step == 1 else
                        {"execution_status": "dry_run", "untrusted_result": {}})).hexdigest())
                if event["decision"] != {**decision, "observation_sha256": expected_hash}:
                    raise ValueError("configurable_decision_replay_mismatch")
                decisions.append(event["decision"])
            elif kind == "configurable_execution_started":
                row = event["record"]
                step = len(records) + 1
                if (closure is not None or type(row) is not dict or set(row) != {"execution_id", "step", "action", "status"}
                        or not _uuid(row["execution_id"]) or any(r["execution_id"] == row["execution_id"] for r in records)
                        or type(row["step"]) is not int or row["step"] != step or row["action"] != contract.action(manifest["scope"], step)
                        or row["status"] != "started" or len(decisions) != step
                        or decisions[-1]["action_digest"] != parse_action(row["action"]).digest
                        or any(r.get("artifact") is None for r in records)):
                    raise ValueError("configurable_execution_order")
                records.append(row)
            elif kind == "configurable_execution_finished":
                row = event["record"]
                if not records or records[-1]["status"] != "started" or closure is not None:
                    raise ValueError("configurable_completion_order")
                artifact = row["artifact"]
                filename = "result-" + records[-1]["execution_id"] + ".json"
                if artifact["filename"] != filename:
                    raise ValueError("configurable_artifact_name")
                raw_result = _read_private(fd, filename, MAX_ARTIFACT_BYTES)
                if artifact != {"filename": filename, "sha256": hashlib.sha256(raw_result).hexdigest(), "bytes": len(raw_result)}:
                    raise ValueError("configurable_artifact_hash")
                result = load_json(raw_result)
                context, observation = validate_result(result, manifest, records[-1]["step"], row["status"], context)
                expected = {**records[-1], "status": row["status"], "observation": observation, "artifact": artifact,
                            "authority_observation_sha256": _observation_digest(records[-1]["step"], row["status"], result)}
                if row != expected:
                    raise ValueError("configurable_record_replay_mismatch")
                records[-1] = expected
                referenced.add(filename)
            elif kind == "configurable_lab_closed":
                if closure is not None or any(row.get("artifact") is None for row in records):
                    raise ValueError("configurable_closure_order")
                closure = validate_assessment_closure(event["receipt"], manifest["owned_lab"],
                    previous=None if context is None else context["endpoints"])
            elif kind == "configurable_finished":
                if closure is None or type(event["elapsed_ms"]) is not int or not 0 <= event["elapsed_ms"] <= 120000:
                    raise ValueError("configurable_finalization_order")
                final = _report(manifest, records, decisions, _summary(event["summary"], manifest, records, decisions), closure, event["elapsed_ms"])
            else:
                raise ValueError("unknown_configurable_event")
        if final is None or names != referenced:
            raise ValueError("configurable_evidence_incomplete")
        if (_read_private(fd, "report.json", MAX_REPORT_BYTES) != contract.encode(final)
                or _read_private(fd, "report.md", MAX_REPORT_BYTES) != markdown(final)):
            raise ValueError("configurable_saved_report_changed")
        return final
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, RecursionError):
        return {"schema_version": "1", "workflow": contract.WORKFLOW, "outcome": "incomplete",
                "integrity_issues": ["configurable_evidence_reconciliation_required"]}
    finally:
        if fd is not None:
            os.close(fd)
