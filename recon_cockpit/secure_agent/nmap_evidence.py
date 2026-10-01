"""Private, independently replayable evidence for the new Nmap workflow.

The legacy assessment contracts remain unchanged. Raw bounded XML and stderr
are retained privately; only validated enums and references enter the report.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
from uuid import uuid4

from . import nmap_contract as contract, nmap_workflow as workflow
from .audit import AuditSink
from .evidence import (
    EvidenceStore, EvidenceUnavailable, MAX_JOURNAL_BYTES, MAX_REPORT_BYTES,
    _digest, _now, _observation_digest, _read_private, _result_metadata, _safe_action,
    _uuid, _workflow_observation,
)
from .models import load_json, parse_action
from .nmap_parser import PARSER_VERSION
from . import nmap_runtime


MAX_ARTIFACT_BYTES = 65_536
REPRESENTATION = "bounded-nmap-raw-and-http-result-json-v1"
STATUSES = {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}
_CHECKS = {"forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked",
           "capabilities_dropped", "no_new_privs", "root_read_only", "process_creation_blocked",
           "raw_sockets_blocked", "landlock_applied", "python_unreadable"}
_RECORD_FIELDS = {"execution_id", "session_step", "action", "action_digest", "policy_digest",
                  "backend", "started_at", "finished_at", "execution_status", "observation_id",
                  "observation", "artifact", "authority_observation_sha256", "result_metadata"}


def _profile(name):
    """Select only repository-reviewed contracts; never import a caller path."""
    if name == "nmap":
        return contract, workflow
    if name == "web":
        from . import web_assessment_contract, web_workflow

        return web_assessment_contract, web_workflow
    raise ValueError("unsupported_evidence_workflow_profile")


def _manifest_profile(manifest):
    if type(manifest) is not dict:
        raise ValueError("invalid_evidence_manifest")
    if "planning_origin" in manifest and (manifest.get("workflow") != "owned-web-assessment-v1"
            or manifest["planning_origin"] not in ("model_owned", "model_live")):
        raise ValueError("invalid_evidence_planning_origin")
    if manifest.get("workflow") == contract.WORKFLOW:
        return _profile("nmap")
    if manifest.get("workflow") == "owned-web-assessment-v1":
        return _profile("web")
    raise ValueError("unsupported_evidence_workflow")


def _validated_result(record, result, manifest, previous, *, deadline=None):
    """Recompute observations from retained bytes, including on read-only replay."""
    contract, _ = _manifest_profile(manifest)
    status = record["execution_status"]
    if type(result) is not dict or result.get("status") != status:
        raise ValueError("invalid_nmap_result_status")
    context = contract.validate_result_context(
        result, manifest["owned_lab"], previous=previous,
        tool_id=record["action"]["tool_id"], execution_status=status,
    )
    if record["action"]["tool_id"] == contract.TOOL_ID:
        if set(result) != {"status", "results", "bytes_received", "truncated", "boundary_checks",
                           "raw_xml_base64", "raw_stderr_base64", "provenance", "backend", "owned_lab"}:
            raise ValueError("invalid_nmap_result_fields")
        decoded = []
        for field in ("raw_xml_base64", "raw_stderr_base64"):
            value = result[field]
            if type(value) is not str or len(value) > 21848:
                raise ValueError("invalid_nmap_raw_artifact")
            raw = base64.b64decode(value, validate=True)
            if base64.b64encode(raw).decode("ascii") != value:
                raise ValueError("invalid_nmap_raw_artifact")
            decoded.append(raw)
        xml, stderr = decoded
        if (len(xml) + len(stderr) > 16384 or type(result["bytes_received"]) is not int
                or result["bytes_received"] != len(xml) + len(stderr)
                or type(result["truncated"]) is not bool):
            raise ValueError("invalid_nmap_capture_bounds")
        checks, provenance = result["boundary_checks"], result["provenance"]
        if (type(checks) is not dict or set(checks) != _CHECKS
                or any(value is not True for value in checks.values())
                or type(provenance) is not dict or set(provenance) != {
                    "runtime_sha256", "runtime_manifest", "xml_sha256", "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
                or not _digest(provenance["runtime_sha256"])
                or provenance["runtime_sha256"] != manifest["runtime_sha256"]
                or nmap_runtime.manifest_digest(provenance["runtime_manifest"]) != provenance["runtime_sha256"]
                or provenance["xml_sha256"] != hashlib.sha256(xml).hexdigest()
                or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
                or provenance["parser_version"] != PARSER_VERSION
                or type(provenance["exit_code"]) is not int
                or not -255 <= provenance["exit_code"] <= 255
                or provenance["stop_reason"] not in {None, "timeout", "output_limit", "invalid_xml"}):
            raise ValueError("invalid_nmap_provenance")
        if result["truncated"] != (provenance["stop_reason"] == "output_limit"):
            raise ValueError("inconsistent_nmap_truncation")
        if status == "succeeded":
            if provenance["exit_code"] != 0 or provenance["stop_reason"] is not None:
                raise ValueError("incomplete_nmap_execution")
            if contract.encode(nmap_runtime.parse_isolated_xml(xml, deadline=deadline)) != contract.encode(result["results"]):
                raise ValueError("nmap_parsed_result_mismatch")
        elif result["results"] != []:
            raise ValueError("failed_nmap_has_findings")
    observation = contract.parse_observation(record["action"], result, execution_status=status)
    return context, observation


def _summary(value, manifest, records, decisions):
    contract, _ = _manifest_profile(manifest)
    keys = {"session_id", "session_status", "stop_reason", "steps_attempted",
            "actions_succeeded", "output_reserved_bytes", "mode"}
    result = {key: value[key] for key in keys}
    if (result["session_id"] != manifest["session_id"]
            or result["session_status"] not in {"completed", "stopped"}
            or result["mode"] not in {"execute", "dry_run"}
            or type(result["stop_reason"]) is not str
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", result["stop_reason"])):
        raise ValueError("invalid_nmap_summary")
    for field, maximum in (("steps_attempted", 3), ("actions_succeeded", 3),
                            ("output_reserved_bytes", contract.LIMITS["max_output_bytes"])):
        if type(result[field]) is not int or not 0 <= result[field] <= maximum:
            raise ValueError("invalid_nmap_summary")
    if (result["steps_attempted"] < max(len(records), len(decisions))
            or result["actions_succeeded"] != sum(row["execution_status"] == "succeeded" for row in records)
            or result["output_reserved_bytes"] < sum(row["action"]["parameters"]["max_output_bytes"] for row in records)
            or (result["mode"] == "dry_run" and records)):
        raise ValueError("inconsistent_nmap_summary")
    return result


def _report(manifest, records, decisions, summary, terminal, closure, issues):
    contract, _ = _manifest_profile(manifest)
    issues = sorted(set(issues))
    reason = "assessment_incomplete" if terminal is None else terminal["reason"]
    outcome = {"seeded_diagnostic_metadata_exposed": "validated",
               "diagnostic_endpoint_not_found": "not_demonstrated"}.get(reason, "inconclusive")
    if issues:
        outcome, reason = "inconclusive", "evidence_integrity_incomplete"
    report = {
        "schema_version": "1", "assessment_id": manifest["assessment_id"],
        "session_id": manifest["session_id"], "workflow": contract.WORKFLOW,
        "fixture_case": manifest["fixture_case"], "workflow_card": manifest["workflow_card"],
        "outcome": outcome, "reason": reason, "live_calls_enabled": False,
        "planning": "deterministic offline workflow with evidence-gated proposals",
        "capability": contract.capability_descriptor(), "runtime_sha256": manifest["runtime_sha256"],
        "records": copy.deepcopy(records), "decisions": copy.deepcopy(decisions),
        "terminal_decision": copy.deepcopy(terminal), "summary": copy.deepcopy(summary),
        "owned_lab": {"identity": manifest["owned_lab"], "closure": copy.deepcopy(closure)},
        "integrity_issues": issues,
        "finding": {"title": "Seeded diagnostic metadata available without authentication",
                    "evidence": [{"execution_id": row["execution_id"], "observation_id": row["observation_id"],
                                  "artifact": row["artifact"]} for row in records if row["artifact"]]},
        "limitations": [
            "The workflow uses deterministic proposals and an owned seeded fixture; no real-model or professional engagement evaluation is claimed.",
            "An open TCP port establishes reachability only; service identity and findings require separate HTTP evidence.",
            "Private raw XML and stderr are untrusted tool output. Hashes support local reconciliation, not external authenticity.",
            "Lab counters are last acknowledged totals; connection counts are lower bounds and cannot identify every attempt.",
            "No execution or authority is resumed by inspecting these files.",
        ],
    }
    if contract.WORKFLOW == "owned-web-assessment-v1":
        report["finding"]["title"] = "Synthetic HarborDesk diagnostic metadata available without authentication"
        report["limitations"].extend([
            "The injected variant retains hostile operator_note text as untrusted evidence; deterministic planning ignores it.",
            "No model susceptibility, induced out-of-scope proposal, or paired adversarial comparison is demonstrated by this workflow.",
            "HTTP observations use bounded decoded responses; they do not establish complete HTTP framing integrity or authenticate server content.",
        ])
    if "planning_origin" in manifest:
        report["planning_origin"] = manifest["planning_origin"]
        report["live_calls_enabled"] = manifest["planning_origin"] == "model_live"
        report["planning"] = ("bounded model proposals; deterministic workflow evidence validation; "
                              + ("live provider" if report["live_calls_enabled"] else "owned synthetic provider"))
        report["limitations"][0] = "Only the owned synthetic HarborDesk workflow is evaluated; no professional engagement readiness is claimed."
        report["limitations"][5:7] = [
            "The injected note remains untrusted data. Model decisions and call accounting are recorded in the enclosing pilot report.",
            "This evidence replay validates tool results and workflow eligibility, not model quality, cost or latency by itself.",
        ]
    return report


def _markdown(report):
    title = ("# Owned HarborDesk web assessment" if report["workflow"] == "owned-web-assessment-v1"
             else "# Owned Nmap and HTTP assessment")
    lines = [title, "", "Outcome: **" + report["outcome"] + "**", "",
             "Reason: `" + report["reason"] + "`", "",
             ("Planning: " + report["planning"] + "." if "planning_origin" in report
              else "Planning: deterministic and offline."), "",
             "## Evidence", ""]
    for item in report["finding"]["evidence"]:
        lines.append("- Execution `" + item["execution_id"] + "`: [private result](" + item["artifact"]["filename"] + ")")
    lines.extend(["", "## Limits", "", *["- " + value for value in report["limitations"]]])
    if report["integrity_issues"]:
        lines.extend(["", "## Reconciliation required", "", *["- `" + value + "`" for value in report["integrity_issues"]]])
    return ("\n".join(lines) + "\n").encode("ascii")


class NmapEvidenceStore(EvidenceStore):
    """Reuse private file lifecycle only; all semantic contracts are versioned."""

    def __init__(self, directory, *, session_id, policy, case, owned_lab, runtime_sha256=None, deadline=None,
                 workflow_profile="nmap", planning_origin=None):
        self.directory = Path(directory)
        self._fd = self._journal = None
        self._failed = self._finalized = False
        self._records, self._decisions = [], []
        self._terminal = self._lab_closure = self._lab_context = None
        self._lock = threading.Lock()
        self._deadline = deadline
        try:
            contract, workflow = _profile(workflow_profile)
            if planning_origin is not None and (workflow_profile != "web"
                    or planning_origin not in ("model_owned", "model_live")):
                raise ValueError("invalid_evidence_planning_origin")
            self._contract, self._workflow_contract = contract, workflow
            if not _uuid(session_id) or (runtime_sha256 is not None and not _digest(runtime_sha256)):
                raise ValueError("invalid_nmap_evidence_configuration")
            contract.action(case, 1)
            self._owned_lab = contract.validate_identity(owned_lab, case=case)
            self._manifest = {
                "schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
                "workflow": contract.WORKFLOW, "fixture_case": case, "policy_digest": policy.digest,
                "created_at": _now(), "artifact_representation": REPRESENTATION,
                "workflow_card": workflow.card_identity(), "owned_lab": self._owned_lab,
                "runtime_sha256": runtime_sha256,
            }
            if planning_origin is not None:
                self._manifest["planning_origin"] = planning_origin
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._write_new("manifest.json", contract.encode(self._manifest), MAX_REPORT_BYTES)
            parent_fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self._journal = AuditSink(self.directory / "evidence.jsonl")
        except (OSError, RuntimeError, ValueError, TypeError):
            self._failed = True
            self.close()
            raise EvidenceUnavailable("evidence_unavailable") from None

    def record_decision(self, step, observation):
        workflow = self._workflow_contract
        with self._lock:
            try:
                self._check()
                if (self._lab_closure is not None or type(step) is not int or step != len(self._decisions) + 1
                        or type(observation) is not bytes or len(observation) > 8192
                        or any(row["artifact"] is None for row in self._records)
                        or (self._decisions and self._decisions[-1]["decision_kind"] != "propose")):
                    raise ValueError("invalid_nmap_decision_order")
                frame = load_json(observation)
                if (set(frame) != {"step", "untrusted_observation"} or type(frame["step"]) is not int
                        or frame["step"] != step or (step == 1 and frame["untrusted_observation"] is not None)):
                    raise ValueError("invalid_nmap_observation")
                decision = workflow.decide(self._manifest["fixture_case"], step, self._records, observation)
                value = {"decision_id": str(uuid4()), **decision.to_dict()}
                self._emit({"event_type": "assessment_workflow_decision", "decision": value})
                self._decisions.append(value)
                return decision
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def start(self, action, policy, *, session_id, session_step, backend):
        contract = self._contract
        with self._lock:
            try:
                self._check()
                expected = parse_action(contract.action(self._manifest["fixture_case"], session_step))
                if (session_id != self._manifest["session_id"] or policy.digest != self._manifest["policy_digest"]
                        or backend != contract.BACKEND or self._lab_closure is not None
                        or type(session_step) is not int or session_step != len(self._records) + 1
                        or action.digest != expected.digest or action.to_dict() != expected.to_dict()
                        or any(row["artifact"] is None for row in self._records)
                        or not self._decisions or self._decisions[-1]["step"] != session_step
                        or self._decisions[-1]["action_digest"] != action.digest
                        or self._decisions[-1]["decision_kind"] != "propose"):
                    raise ValueError("invalid_nmap_evidence_start")
                record = {"execution_id": str(uuid4()), "session_step": session_step,
                          "action": _safe_action(action), "action_digest": action.digest,
                          "policy_digest": policy.digest, "backend": backend, "started_at": _now(),
                          "finished_at": None, "execution_status": "started", "observation_id": None,
                          "observation": None, "artifact": None, "authority_observation_sha256": None,
                          "result_metadata": None}
                self._emit({"event_type": "assessment_execution_started", "record": record})
                self._records.append(record)
                return record["execution_id"]
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def finish(self, execution_id, result, *, execution_status):
        with self._lock:
            try:
                self._check()
                if (not self._records or self._records[-1]["execution_id"] != execution_id
                        or self._records[-1]["artifact"] is not None or execution_status not in STATUSES):
                    raise ValueError("invalid_nmap_evidence_completion")
                record = {**self._records[-1], "execution_status": execution_status}
                context, observation = _validated_result(record, result, self._manifest, self._lab_context,
                                                         deadline=self._deadline)
                raw = contract.encode(result)
                filename = "result-" + execution_id + ".json"
                self._write_new(filename, raw, MAX_ARTIFACT_BYTES)
                record.update(finished_at=_now(), observation_id=str(uuid4()), observation=observation,
                              result_metadata=_result_metadata(result),
                              artifact={"filename": filename, "sha256": hashlib.sha256(raw).hexdigest(),
                                        "bytes": len(raw), "representation": REPRESENTATION},
                              authority_observation_sha256=_observation_digest(record["session_step"], execution_status, result))
                self._emit({"event_type": "assessment_execution_finished", "record": record})
                self._records[-1], self._lab_context = record, context
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def record_lab_closed(self, receipt):
        """Persist the selected reviewed lab's teardown receipt before findings."""
        with self._lock:
            try:
                self._check()
                if (self._lab_closure is not None
                        or any(row["artifact"] is None for row in self._records)):
                    raise ValueError("invalid_owned_lab_closure_order")
                closure = self._contract.validate_closure(receipt, self._owned_lab, previous=self._lab_context)
                self._emit({"event_type": "assessment_owned_lab_closed", "receipt": closure})
                self._lab_closure = closure
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def finalize(self, summary):
        workflow = self._workflow_contract
        with self._lock:
            try:
                self._check()
                if self._lab_closure is None or any(row["artifact"] is None for row in self._records):
                    raise ValueError("nmap_closure_missing")
                safe = _summary(summary, self._manifest, self._records, self._decisions)
                self._terminal = {"decision_id": str(uuid4()), **workflow.terminal_decision(
                    self._manifest["fixture_case"], self._records, safe).to_dict()}
                self._emit({"event_type": "assessment_workflow_terminal", "decision": self._terminal, "summary": safe})
                report = _report(self._manifest, self._records, self._decisions, safe,
                                 self._terminal, self._lab_closure, [])
                self._emit({"event_type": "assessment_finished", "summary": safe})
                self._write_new("report.json", contract.encode(report), MAX_REPORT_BYTES)
                self._write_new("report.md", _markdown(report), MAX_REPORT_BYTES)
                self._finalized = True
                return report
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None


def inspect_evidence(directory):
    """Rebuild decisions and findings read-only; never restore a running session."""
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("invalid_nmap_directory")
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 12:
                    raise ValueError("nmap_evidence_file_limit")
        manifest = load_json(_read_private(fd, "manifest.json", 8192))
        contract, workflow = _manifest_profile(manifest)
        if (set(manifest) - {"planning_origin"} != {"schema_version", "assessment_id", "session_id", "workflow", "fixture_case",
                             "policy_digest", "created_at", "artifact_representation", "workflow_card",
                             "owned_lab", "runtime_sha256"}
                or manifest["schema_version"] != "1" or manifest["workflow"] != contract.WORKFLOW
                or manifest["artifact_representation"] != REPRESENTATION
                or not _uuid(manifest["assessment_id"]) or not _uuid(manifest["session_id"])
                or not _digest(manifest["policy_digest"])
                or (manifest["runtime_sha256"] is not None and not _digest(manifest["runtime_sha256"]))
                or manifest["workflow_card"] != workflow.card_identity()
                or type(manifest["created_at"]) is not str or len(manifest["created_at"]) > 64):
            raise ValueError("invalid_nmap_manifest")
        contract.validate_identity(manifest["owned_lab"], case=manifest["fixture_case"])
        records, decisions, issues = [], [], []
        summary = terminal = terminal_summary = context = closure = latest_result = None
        referenced = {"manifest.json", "evidence.jsonl", "report.json", "report.md"}
        try:
            lines = _read_private(fd, "evidence.jsonl", MAX_JOURNAL_BYTES).splitlines(keepends=True)
        except (OSError, ValueError):
            lines = []
            issues.append("journal_unavailable")
        if len(lines) > 12:
            issues.append("journal_event_limit")
            lines = lines[:12]
        for line in lines:
            try:
                if not line.endswith(b"\n") or summary is not None:
                    raise ValueError("invalid_nmap_event_order")
                event = load_json(line)
                if event["assessment_id"] != manifest["assessment_id"] or event["session_id"] != manifest["session_id"]:
                    raise ValueError("wrong_nmap_session")
                kind = event["event_type"]
                if kind == "assessment_finished":
                    candidate = _summary(event["summary"], manifest, records, decisions)
                    if terminal is None or closure is None or candidate != terminal_summary:
                        raise ValueError("missing_nmap_closure")
                    summary = candidate
                    continue
                if terminal is not None:
                    raise ValueError("nmap_already_terminated")
                if kind == "assessment_owned_lab_closed":
                    if closure is not None or any(row["artifact"] is None for row in records):
                        raise ValueError("invalid_nmap_closure_order")
                    closure = contract.validate_closure(event["receipt"], manifest["owned_lab"], previous=context)
                    continue
                if kind == "assessment_workflow_terminal":
                    candidate = _summary(event["summary"], manifest, records, decisions)
                    if closure is None:
                        raise ValueError("missing_nmap_closure")
                    expected = workflow.terminal_decision(manifest["fixture_case"], records, candidate)
                    _decision_matches(event["decision"], expected, decisions)
                    terminal, terminal_summary = event["decision"], candidate
                    continue
                if closure is not None:
                    raise ValueError("nmap_lab_already_closed")
                if kind == "assessment_workflow_decision":
                    step = event["decision"]["step"]
                    if (type(step) is not int or step != len(decisions) + 1
                            or any(row["artifact"] is None for row in records)
                            or (decisions and decisions[-1]["decision_kind"] != "propose")):
                        raise ValueError("invalid_nmap_decision_order")
                    expected = workflow.decide(manifest["fixture_case"], step, records,
                                               _workflow_observation(step, records, latest_result))
                    _decision_matches(event["decision"], expected, decisions)
                    decisions.append(event["decision"])
                    continue
                record = event["record"]
                if (type(record) is not dict or set(record) != _RECORD_FIELDS
                        or not _uuid(record["execution_id"]) or record["policy_digest"] != manifest["policy_digest"]
                        or record["backend"] != contract.BACKEND or type(record["started_at"]) is not str
                        or len(record["started_at"]) > 64):
                    raise ValueError("invalid_nmap_execution")
                expected = parse_action(contract.action(manifest["fixture_case"], record["session_step"]))
                if record["action"] != _safe_action(expected) or record["action_digest"] != expected.digest:
                    raise ValueError("unexpected_nmap_action")
                if kind == "assessment_execution_started":
                    if (record["session_step"] != len(records) + 1 or record["execution_status"] != "started"
                            or record["execution_id"] in {row["execution_id"] for row in records}
                            or any(row["artifact"] is None for row in records)
                            or any(record[key] is not None for key in ("finished_at", "observation_id", "observation",
                                                                      "artifact", "authority_observation_sha256", "result_metadata"))
                            or not decisions or decisions[-1]["decision_kind"] != "propose"
                            or decisions[-1]["step"] != record["session_step"]
                            or decisions[-1]["action_digest"] != record["action_digest"]):
                        raise ValueError("invalid_nmap_start")
                    records.append(record)
                elif kind == "assessment_execution_finished":
                    if (not records or records[-1]["artifact"] is not None
                            or any(record[key] != records[-1][key] for key in (
                                "execution_id", "session_step", "action", "action_digest", "policy_digest", "backend", "started_at"))
                            or record["execution_status"] not in STATUSES or not _uuid(record["observation_id"])
                            or record["observation_id"] in {row["observation_id"] for row in records[:-1]}
                            or type(record["finished_at"]) is not str or len(record["finished_at"]) > 64):
                        raise ValueError("invalid_nmap_completion")
                    artifact = record["artifact"]
                    if (type(artifact) is not dict or set(artifact) != {"filename", "bytes", "sha256", "representation"}
                            or artifact["filename"] != "result-" + record["execution_id"] + ".json"
                            or artifact["representation"] != REPRESENTATION or not _digest(artifact["sha256"])
                            or type(artifact["bytes"]) is not int or not 1 <= artifact["bytes"] <= MAX_ARTIFACT_BYTES):
                        raise ValueError("invalid_nmap_artifact")
                    raw = _read_private(fd, artifact["filename"], MAX_ARTIFACT_BYTES)
                    if len(raw) != artifact["bytes"] or hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
                        raise ValueError("nmap_artifact_mismatch")
                    result = load_json(raw)
                    new_context, observation = _validated_result(record, result, manifest, context)
                    if (contract.encode(observation) != contract.encode(record["observation"])
                            or contract.encode(_result_metadata(result)) != contract.encode(record["result_metadata"])
                            or _observation_digest(record["session_step"], record["execution_status"], result)
                            != record["authority_observation_sha256"]):
                        raise ValueError("nmap_observation_mismatch")
                    records[-1], context, latest_result = record, new_context, result
                    referenced.add(artifact["filename"])
                else:
                    raise ValueError("unknown_nmap_event")
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
                issues.append("journal_or_artifact_incomplete")
                break
        if summary is None:
            issues.append("assessment_closure_missing")
        if closure is None:
            issues.append("owned_lab_closure_missing")
        if terminal is None:
            issues.append("workflow_terminal_missing")
        if any(row["artifact"] is None for row in records):
            issues.append("execution_completion_unknown")
        if set(names) - referenced:
            issues.append("orphan_artifacts_present")
        report = _report(manifest, records, decisions, summary, terminal, closure, issues)
        if summary is not None:
            try:
                if (contract.encode(load_json(_read_private(fd, "report.json", MAX_REPORT_BYTES))) != contract.encode(report)
                        or _read_private(fd, "report.md", MAX_REPORT_BYTES) != _markdown(report)):
                    raise ValueError("nmap_report_mismatch")
            except (OSError, ValueError):
                issues.append("report_missing_or_mismatched")
                report = _report(manifest, records, decisions, summary, terminal, closure, issues)
        return report
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
        raise EvidenceUnavailable("evidence_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def _decision_matches(value, expected, previous):
    if (type(value) is not dict or not _uuid(value.get("decision_id"))
            or value["decision_id"] in {row["decision_id"] for row in previous}
            or contract.encode({key: item for key, item in value.items() if key != "decision_id"})
            != contract.encode(expected.to_dict())):
        raise ValueError("nmap_decision_mismatch")


inspect_assessment = inspect_evidence
