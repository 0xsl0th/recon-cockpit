"""Private, bounded evidence for fixed owned HTTP assessment workflows.

Trusted Controller code owns this store. No pathname or handle crosses an agent
boundary. Artifacts contain decoded results, not original HTTP wire bytes.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from uuid import UUID, uuid4

from .audit import AuditSink, AuditUnavailable
from .models import load_json, parse_action


MAX_ARTIFACT_BYTES = 16384
MAX_JOURNAL_BYTES = 65536
MAX_REPORT_BYTES = 32768
MAX_EXECUTIONS = 2
REPRESENTATION = "canonical-decoded-http-result-json-v1"
WORKFLOW = "owned-http-assessment-v1"
DISCOVERY_REPRESENTATION = "canonical-decoded-discovery-http-result-json-v1"
DISCOVERY_WORKFLOW = "owned-discovery-http-assessment-v1"
VERSIONED_WORKFLOW = "owned-workflow-assessment-v1"
OWNED_LAB_WORKFLOW = "owned-lab-workflow-assessment-v1"
_DISCOVERY_WORKFLOWS = {DISCOVERY_WORKFLOW, VERSIONED_WORKFLOW, OWNED_LAB_WORKFLOW}
_VERSIONED_WORKFLOWS = {VERSIONED_WORKFLOW, OWNED_LAB_WORKFLOW}


class EvidenceUnavailable(AuditUnavailable):
    code = "evidence_unavailable"


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def _uuid(value):
    return type(value) is str and str(UUID(value)) == value


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_action(action):
    value = action.to_dict()
    value.pop("rationale")
    return value


def _check_action(action, case, step, *, discovery=False):
    if discovery:
        from .discovery_contract import discovery_action as expected_action
    else:
        from .assessment_contract import assessment_action as expected_action

    if type(step) is not int or not 1 <= step <= (3 if discovery else MAX_EXECUTIONS):
        raise ValueError("invalid_evidence_step")
    parsed = parse_action({**action, "rationale": "Evidence excludes planner rationale."})
    expected = expected_action(case, step)
    # Action IDs are planner data. The store generates its own execution IDs.
    if any(parsed.to_dict()[key] != expected[key] for key in ("tool_id", "target", "parameters")):
        raise ValueError("unexpected_assessment_action")
    if set(action) != {"schema_version", "action_id", "tool_id", "target", "parameters"}:
        raise ValueError("invalid_evidence_action")


def _summary(value, session_id, *, discovery=False, workflow=False):
    keys = ("session_id", "session_status", "stop_reason", "steps_attempted",
            "actions_succeeded", "output_reserved_bytes", "mode")
    result = {key: value[key] for key in keys}
    if (result["session_id"] != session_id or result["session_status"] not in {"completed", "stopped"}
            or result["mode"] not in {"execute", "dry_run"}
            or type(result["stop_reason"]) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", result["stop_reason"]) is None):
        raise ValueError("invalid_assessment_summary")
    for key, maximum in (("steps_attempted", 3 if discovery else 16),
                         ("actions_succeeded", 3 if discovery else MAX_EXECUTIONS),
                         ("output_reserved_bytes", 3072 if discovery else 1048576)):
        if type(result[key]) is not int or not 0 <= result[key] <= maximum:
            raise ValueError("invalid_assessment_summary")
    if discovery and result["actions_succeeded"] > result["steps_attempted"]:
        raise ValueError("invalid_assessment_summary")
    if workflow:
        from .workflow import BLOCKED_REASONS

        blocked = None
        is_blocked = (result["mode"] == "execute" and result["session_status"] == "stopped"
                      and result["stop_reason"] == "action_blocked")
        if "blocked_reason" in value:
            # Inspection sees only this bounded persisted field, never raw
            # callback text or a copied authority step object.
            blocked = value["blocked_reason"]
            if blocked is not None and (not is_blocked or type(blocked) is not str
                                        or blocked not in BLOCKED_REASONS):
                raise ValueError("invalid_workflow_blocked_reason")
        elif is_blocked:
            steps = value.get("steps")
            if type(steps) is list and 1 <= len(steps) <= 3:
                last = steps[-1]
                if (type(last) is dict and type(last.get("step")) is int
                        and last["step"] == result["steps_attempted"]
                        and last.get("execution_status") == "blocked"):
                    reasons = last.get("reasons")
                    if (type(reasons) is list and len(reasons) == 1
                            and type(reasons[0]) is str and reasons[0] in BLOCKED_REASONS):
                        blocked = reasons[0]
        result["blocked_reason"] = blocked
    return result


def _parse_observation(action, result, *, execution_status, discovery=False, owned_lab=None):
    if discovery:
        from .discovery_contract import parse_observation
    else:
        from .assessment_contract import parse_observation

    if owned_lab is not None:
        # Context continuity is validated separately against preceding artifacts.
        # Do not widen either legacy observation parser's accepted result schema.
        from .owned_lab_contract import BACKEND, validate_context

        if result.get("backend") != BACKEND:
            raise ValueError("invalid_owned_lab_backend")
        validate_context(result.get("owned_lab"), owned_lab)
        result = {key: value for key, value in result.items() if key != "owned_lab"}
        result["backend"] = "linux-authorized-discovery-fixture-executor-v1"
    return parse_observation(action, result, execution_status=execution_status)


def _reconcile_summary(summary, records, *, discovery=False):
    if summary["actions_succeeded"] != sum(row["execution_status"] == "succeeded" for row in records):
        raise ValueError("inconsistent_assessment_summary")
    if discovery and (summary["steps_attempted"] < max((row["session_step"] for row in records), default=0)
                      or summary["output_reserved_bytes"] < sum(
                          row["action"]["parameters"]["max_output_bytes"] for row in records)):
        raise ValueError("inconsistent_assessment_summary")


def _observation_digest(step, status, result):
    # Local import avoids a Controller -> evidence -> session -> Controller cycle.
    from .session import _observation

    return hashlib.sha256(_observation(step + 1, {
        "execution_status": status, "untrusted_result": result,
    })).hexdigest()


def _result_metadata(result):
    from .controller import result_metadata

    return result_metadata(result)


def _workflow_observation(step, records, result=None):
    """Rebuild authority feedback from validated artifacts, never journal prose."""
    from .session import _observation

    if step == 1:
        return _observation(1, None)
    if records and records[-1]["session_step"] == step - 1:
        return _observation(step, {"execution_status": records[-1]["execution_status"],
                                   "untrusted_result": result})
    # A dry-run proposal has no execution record. It must stop at the next
    # prerequisite check; this canonical frame permits read-only replay.
    return _observation(step, {"execution_status": "dry_run", "untrusted_result": {}})


def _check_decision_order(decisions, records, step):
    if (type(step) is not int or step != len(decisions) + 1 or not 1 <= step <= 3
            or (decisions and decisions[-1]["decision_kind"] != "propose")
            or any(row["artifact"] is None for row in records)):
        raise ValueError("invalid_workflow_decision_order")


def _require_proposed(decisions, step, action_digest):
    if (not decisions or decisions[-1]["decision_kind"] != "propose"
            or decisions[-1]["step"] != step or decisions[-1]["action_digest"] != action_digest):
        raise ValueError("workflow_proposal_missing")


def _reconcile_workflow_summary(summary, decisions, records):
    if (summary["steps_attempted"] < len(decisions)
            or (summary["mode"] == "dry_run" and records)):
        raise ValueError("inconsistent_workflow_summary")


def _validate_decision(value, expected, previous):
    if (type(value) is not dict or not _uuid(value.get("decision_id"))
            or value["decision_id"] in {row["decision_id"] for row in previous}
            or _encode({key: item for key, item in value.items() if key != "decision_id"}) != _encode(expected.to_dict())):
        raise ValueError("workflow_decision_mismatch")


def _decision_trace(decisions, records):
    trace = []
    for decision in decisions:
        execution = next((row for row in records if row["session_step"] == decision["step"]
                          and row["action_digest"] == decision["action_digest"]), None)
        status = "not_executed" if decision["decision_kind"] == "propose" else "not_proposed"
        if execution is not None:
            status = "completion_unknown" if execution["artifact"] is None else execution["execution_status"]
        trace.append({**copy.deepcopy(decision), "execution_id": execution["execution_id"] if execution else None,
                      "execution_status": status})
    return trace


def _report(manifest, records, summary, issues, decisions=None, terminal=None, lab_closure=None):
    from .assessment_contract import capability_descriptor, discovery_path, diagnostics_path

    discovery = manifest["workflow"] in _DISCOVERY_WORKFLOWS
    if discovery:
        from .discovery_contract import capability_descriptor

    if manifest["workflow"] == OWNED_LAB_WORKFLOW:
        from .owned_lab_contract import capability_descriptor

        if lab_closure is None:
            issues = [*issues, "owned_lab_closure_missing"]
    issues = sorted(set(issues))
    outcome, reason = "inconclusive", "assessment_incomplete"
    completed = [row for row in records if row.get("artifact") is not None]
    expected_steps = [1, 2, 3] if discovery else [1, 2]
    preceding_classifications = ["reachable", "discovered"] if discovery else ["discovered"]
    if summary is not None and not issues:
        if summary["mode"] == "dry_run":
            reason = "dry_run_has_no_execution_evidence"
        elif summary["session_status"] != "completed":
            reason = "session_stopped"
        elif (len(completed) == len(expected_steps)
              and [row["session_step"] for row in completed] == expected_steps
              and all(row["execution_status"] == "succeeded" for row in completed)
              and [row["observation"]["classification"] for row in completed[:-1]] == preceding_classifications):
            classification = completed[-1]["observation"]["classification"]
            if classification == "exposed":
                outcome, reason = "validated", "seeded_diagnostic_metadata_exposed"
            elif classification == "absent":
                outcome, reason = "not_demonstrated", "diagnostic_endpoint_not_found"
            else:
                reason = "diagnostic_evidence_invalid"
        else:
            reason = "discovery_or_execution_evidence_missing"
    if issues:
        reason = "evidence_integrity_incomplete"
    references = [{"execution_id": row["execution_id"], "observation_id": row["observation_id"],
                   "artifact": copy.deepcopy(row["artifact"])} for row in completed]
    report = {
        "schema_version": "1", "assessment_id": manifest["assessment_id"],
        "session_id": manifest["session_id"], "workflow": manifest["workflow"],
        "fixture_case": manifest["fixture_case"], "outcome": outcome, "reason": reason,
        "planning": "deterministic fixture workflow with gated synthetic provider replies",
        "live_calls_enabled": False, "capability": capability_descriptor(),
        "scope": {"target": "127.0.0.1", "port": 8080, "method": "GET",
                  "paths": [discovery_path(manifest["fixture_case"]), diagnostics_path(manifest["fixture_case"])]},
        "finding": {
            "title": "Seeded diagnostic metadata available without authentication",
            "validation_status": outcome, "review_status": "pending_operator_review",
            "impact": "The owned fixture exposes synthetic internal diagnostic metadata when the seeded condition is validated.",
            "remediation": "Restrict diagnostic endpoints to authorized users and omit internal metadata from public responses.",
            "evidence": references,
        },
        "execution": copy.deepcopy(summary), "records": copy.deepcopy(records),
        "integrity_issues": issues,
        "limitations": [
            "Owned fixture only; no general vulnerability, authentication bypass, CVE or live-model performance claim.",
            "A not-demonstrated result applies only to the inspected endpoint and fixed condition.",
            "Artifacts hold decoded result JSON, not exact HTTP wire bytes; response and artifact digests identify different representations.",
            "Local hashes do not prevent a host owner from modifying evidence. Raw artifacts are private and retained until operator cleanup.",
            "Inspection never resumes execution or restores approvals, deadlines or budgets.",
        ] + (["TCP evidence establishes a completed connection only, not HTTP service identity or a finding.",
              "Each action recreates the owned topology in a fresh namespace; this does not track a persistent remote service."]
             if discovery else []),
    }

    if manifest["workflow"] in _VERSIONED_WORKFLOWS:
        report["workflow_card"] = copy.deepcopy(manifest["workflow_card"])
        report["planning"] = "versioned deterministic workflow with durable evidence-backed decisions"
        report["decision_trace"] = _decision_trace(decisions or [], records)
        report["terminal_decision"] = copy.deepcopy(terminal)
        report["limitations"].append(
            "A workflow proposal grants no authority. Execution still requires current policy, approval, budgets and controller checks.")
    if manifest["workflow"] == OWNED_LAB_WORKFLOW:
        report["owned_lab"] = {"identity": copy.deepcopy(manifest["owned_lab"]),
                               "closure": copy.deepcopy(lab_closure)}
        report["limitations"].remove(
            "Each action recreates the owned topology in a fresh namespace; this does not track a persistent remote service.")
        report["limitations"].append(
            "One owned service persists only within this authority session. Reset destroys it and creates a new instance; no runtime or authority is resumed.")
    return report


def _markdown(report):
    # Only validated enums, UUIDs, generated artifact filenames/digests and fixed
    # text are rendered. No response body, rationale or model prose is included.
    title = "# Owned discovery and HTTP assessment" if report["workflow"] in _DISCOVERY_WORKFLOWS else "# Owned HTTP assessment"
    lines = [title, "", "Outcome: **" + report["outcome"] + "**", "",
             report["finding"]["title"], "", "Review: pending operator review.", "",
             "Assessment: `" + report["assessment_id"] + "`", "",
             "Session: `" + report["session_id"] + "`", "",
             "Reason: `" + report["reason"] + "`", "",
             "## Evidence", ""]
    if not report["finding"]["evidence"]:
        lines.append("No completed execution evidence is available.")
    for item in report["finding"]["evidence"]:
        artifact = item["artifact"]
        lines.extend(["- Execution `" + item["execution_id"] + "`: [decoded result](" + artifact["filename"] + ")",
                      "  SHA-256: `" + artifact["sha256"] + "`"])
    if report["workflow"] in _VERSIONED_WORKFLOWS:
        card = report["workflow_card"]
        lines.extend(["", "## Workflow decisions", "",
                      "Card: `" + card["id"] + "` version `" + card["version"] + "`",
                      "SHA-256: `" + card["sha256"] + "`", "",
                      "Proposals require separate policy, approval, budget and controller checks before execution.", ""])
        for item in report["decision_trace"]:
            lines.append("- Step " + str(item["step"]) + ": `" + item["decision_kind"] + "` because `" + item["reason"]
                         + "`; execution `" + item["execution_status"] + "`; decision `" + item["decision_id"] + "`.")
            if item["execution_id"] is not None:
                lines.append("  Execution: `" + item["execution_id"] + "`.")
        if report["terminal_decision"] is not None:
            lines.append("- Terminal decision: `" + report["terminal_decision"]["decision_id"]
                         + "`; reason `" + report["terminal_decision"]["reason"] + "`.")
    if report["workflow"] == OWNED_LAB_WORKFLOW:
        lab = report["owned_lab"]
        lines.extend(["", "## Owned lab", "", "Instance: `" + lab["identity"]["instance_id"] + "`",
                      "Specification SHA-256: `" + lab["identity"]["spec_sha256"] + "`",
                      "Lifecycle: " + ("closed, with a recorded receipt." if lab["closure"] else "closure unconfirmed.")])
    lines.extend(["", "## Interpretation", "", report["finding"]["impact"], "",
                  report["finding"]["remediation"], "", "## Limits", ""])
    lines.extend("- " + value for value in report["limitations"])
    if report["integrity_issues"]:
        lines.extend(["", "## Evidence requiring reconciliation", ""])
        lines.extend("- `" + issue + "`" for issue in report["integrity_issues"])
    return ("\n".join(lines) + "\n").encode("ascii")


class EvidenceStore:
    """One fresh, bounded assessment. Existing directories cannot be resumed."""

    def __init__(self, directory, *, session_id, policy, case, discovery=False, workflow=False, owned_lab=None):
        from .assessment_contract import CASES

        self.directory = Path(directory)
        self._fd = None
        self._journal = None
        self._failed = False
        self._finalized = False
        self._records = []
        self._decisions = []
        self._terminal = None
        self._lab_closure = None
        self._lab_context = None
        self._lock = threading.Lock()
        try:
            if (not _uuid(session_id) or type(case) is not str or case not in CASES
                    or type(discovery) is not bool or type(workflow) is not bool
                    or (workflow and not discovery) or (owned_lab is not None and not workflow)):
                raise ValueError("invalid_assessment_configuration")
            self._discovery = discovery
            self._workflow = workflow
            self._owned_lab = None
            if owned_lab is not None:
                from .owned_lab_contract import validate_identity

                self._owned_lab = validate_identity(owned_lab, case=case)
            self._max_executions = 3 if discovery else MAX_EXECUTIONS
            self._manifest = {
                "schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
                "workflow": OWNED_LAB_WORKFLOW if owned_lab is not None else VERSIONED_WORKFLOW if workflow else DISCOVERY_WORKFLOW if discovery else WORKFLOW,
                "fixture_case": case, "policy_digest": policy.digest,
                "created_at": _now(),
                "artifact_representation": DISCOVERY_REPRESENTATION if discovery else REPRESENTATION,
            }
            if workflow:
                from .workflow import card_identity

                self._manifest["workflow_card"] = card_identity(owned_lab=owned_lab is not None)
            if owned_lab is not None:
                self._manifest["owned_lab"] = copy.deepcopy(self._owned_lab)
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._check()
            self._write_new("manifest.json", _encode(self._manifest), MAX_REPORT_BYTES)
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

    @property
    def records(self):
        with self._lock:
            return copy.deepcopy(self._records)

    def record_decision(self, step, observation):
        """Durably record a deterministic decision before a provider exchange."""
        from .workflow import decide

        with self._lock:
            try:
                self._check()
                if (not self._workflow or self._lab_closure is not None
                        or type(observation) is not bytes or len(observation) > 8192):
                    raise ValueError("invalid_workflow_observation")
                frame = load_json(observation)
                if (set(frame) != {"step", "untrusted_observation"}
                        or type(frame["step"]) is not int or frame["step"] != step
                        or (step == 1 and frame["untrusted_observation"] is not None)):
                    raise ValueError("invalid_workflow_observation")
                _check_decision_order(self._decisions, self._records, step)
                decision = decide(self._manifest["fixture_case"], step, self._records, observation,
                                  owned_lab=self._owned_lab is not None)
                durable = {"decision_id": str(uuid4()), **decision.to_dict()}
                self._emit({"event_type": "assessment_workflow_decision", "decision": durable})
                self._decisions.append(durable)
                return decision
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def _check(self):
        if self._failed or self._fd is None or self._finalized:
            raise EvidenceUnavailable("evidence_unavailable")
        info = os.fstat(self._fd)
        named = self.directory.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise EvidenceUnavailable("evidence_unavailable")

    def _write_new(self, name, raw, limit):
        self._check()
        if type(raw) is not bytes or len(raw) > limit:
            raise EvidenceUnavailable("evidence_limit")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=self._fd)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("evidence_short_write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self._fd)

    def _emit(self, value):
        self._check()
        if self._journal is None:
            raise EvidenceUnavailable("evidence_closed")
        # AuditSink adds a fixed bounded envelope (UUID, source and timestamp).
        # Reserve that envelope before appending, not after crossing the cap.
        current_bytes = (self.directory / "evidence.jsonl").stat(follow_symlinks=False).st_size
        if current_bytes + len(_encode(value)) + 512 > MAX_JOURNAL_BYTES:
            raise EvidenceUnavailable("evidence_limit")
        self._journal.emit({"assessment_id": self._manifest["assessment_id"],
                            "session_id": self._manifest["session_id"], **value})
        if (self.directory / "evidence.jsonl").stat(follow_symlinks=False).st_size > MAX_JOURNAL_BYTES:
            raise EvidenceUnavailable("evidence_limit")

    def start(self, action, policy, *, session_id, session_step, backend):
        with self._lock:
            try:
                self._check()
                safe = _safe_action(action)
                _check_action(safe, self._manifest["fixture_case"], session_step, discovery=self._discovery)
                if (session_id != self._manifest["session_id"] or policy.digest != self._manifest["policy_digest"]
                        or session_step != len(self._records) + 1 or len(self._records) >= self._max_executions
                        or any(row["artifact"] is None for row in self._records)
                        or type(backend) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,80}", backend) is None):
                    raise ValueError("invalid_evidence_start")
                if self._owned_lab is not None:
                    from .owned_lab_contract import BACKEND

                    if backend != BACKEND or self._lab_closure is not None:
                        raise ValueError("invalid_owned_lab_execution")
                if self._workflow:
                    _require_proposed(self._decisions, session_step, action.digest)
                record = {"execution_id": str(uuid4()), "session_step": session_step,
                          "action": safe, "action_digest": action.digest, "policy_digest": policy.digest,
                          "backend": backend, "started_at": _now(), "finished_at": None,
                          "execution_status": "started", "observation_id": None, "observation": None,
                          "artifact": None, "authority_observation_sha256": None, "result_metadata": None}
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
                        or self._records[-1]["artifact"] is not None
                        or execution_status not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}
                        or type(result) is not dict):
                    raise ValueError("invalid_evidence_completion")
                record = self._records[-1]
                context = None
                if self._owned_lab is not None:
                    from .owned_lab_contract import validate_result_context

                    context = validate_result_context(result, self._owned_lab, previous=self._lab_context,
                                                      tool_id=record["action"]["tool_id"],
                                                      execution_status=execution_status)
                raw = _encode(result)
                filename = "result-" + execution_id + ".json"
                self._write_new(filename, raw, MAX_ARTIFACT_BYTES)
                completed = {**record, "finished_at": _now(), "execution_status": execution_status,
                             "observation_id": str(uuid4()),
                             "result_metadata": _result_metadata(result),
                             "observation": _parse_observation(record["action"], result,
                                                               execution_status=execution_status,
                                                               discovery=self._discovery, owned_lab=self._owned_lab),
                             "artifact": {"filename": filename, "sha256": hashlib.sha256(raw).hexdigest(),
                                          "bytes": len(raw), "representation": self._manifest["artifact_representation"]},
                             "authority_observation_sha256": _observation_digest(record["session_step"], execution_status, result)}
                self._emit({"event_type": "assessment_execution_finished", "record": completed})
                self._records[-1] = completed
                self._lab_context = context
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def record_lab_closed(self, receipt):
        """Persist a trusted owner's teardown receipt before report publication."""
        from .owned_lab_contract import validate_closure

        with self._lock:
            try:
                self._check()
                if (self._owned_lab is None or self._lab_closure is not None
                        or any(row["artifact"] is None for row in self._records)):
                    raise ValueError("invalid_owned_lab_closure_order")
                closure = validate_closure(receipt, self._owned_lab, previous=self._lab_context)
                self._emit({"event_type": "assessment_owned_lab_closed", "receipt": closure})
                self._lab_closure = closure
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def finalize(self, summary):
        with self._lock:
            try:
                self._check()
                if self._owned_lab is not None and self._lab_closure is None:
                    raise ValueError("owned_lab_closure_missing")
                safe = _summary(summary, self._manifest["session_id"], discovery=self._discovery,
                                workflow=self._workflow)
                _reconcile_summary(safe, self._records, discovery=self._discovery)
                issues = ["execution_completion_unknown"] if any(row["artifact"] is None for row in self._records) else []
                if self._workflow:
                    from .workflow import terminal_decision

                    _reconcile_workflow_summary(safe, self._decisions, self._records)
                    self._terminal = {"decision_id": str(uuid4()),
                                      **terminal_decision(self._manifest["fixture_case"],
                                                          self._records, safe,
                                                          owned_lab=self._owned_lab is not None).to_dict()}
                    self._emit({"event_type": "assessment_workflow_terminal", "decision": self._terminal,
                                "summary": safe})
                report = _report(self._manifest, self._records, safe, issues,
                                 self._decisions, self._terminal, self._lab_closure)
                # Publish findings only after the evidence session is durably
                # closed. A failed closure must not leave a validated report.
                # Later export failures are reconciled as an incomplete bundle.
                self._emit({"event_type": "assessment_finished", "summary": safe})
                self._write_new("report.json", _encode(report), MAX_REPORT_BYTES)
                self._write_new("report.md", _markdown(report), MAX_REPORT_BYTES)
                self._finalized = True
                return report
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def close(self):
        if self._journal is not None:
            self._journal.close()
            self._journal = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _read_private(directory_fd, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > limit):
            raise ValueError("invalid_evidence_file")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise ValueError("evidence_limit")
    finally:
        os.close(fd)


def inspect_assessment(directory):
    """Recompute a safe report without writing files or restoring any authority."""
    from .assessment_contract import CASES

    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("invalid_evidence_directory")
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 12:
                    raise ValueError("evidence_file_limit")
        manifest = load_json(_read_private(fd, "manifest.json", 8192))
        workflow = manifest.get("workflow") in _VERSIONED_WORKFLOWS
        owned_lab = None
        manifest_fields = {"schema_version", "assessment_id", "session_id", "workflow", "fixture_case",
                           "policy_digest", "created_at", "artifact_representation"}
        if workflow:
            from .workflow import card_identity, decide, terminal_decision

            manifest_fields.add("workflow_card")
            if _encode(manifest.get("workflow_card")) != _encode(card_identity(
                    owned_lab=manifest.get("workflow") == OWNED_LAB_WORKFLOW)):
                raise ValueError("unknown_workflow_card")
        if manifest.get("workflow") == OWNED_LAB_WORKFLOW:
            from .owned_lab_contract import BACKEND, validate_identity, validate_result_context, validate_closure

            manifest_fields.add("owned_lab")
            owned_lab = validate_identity(manifest.get("owned_lab"), case=manifest.get("fixture_case"))
        if (set(manifest) != manifest_fields
                or manifest["schema_version"] != "1"
                or (manifest["workflow"], manifest["artifact_representation"]) not in (
                    (WORKFLOW, REPRESENTATION), (DISCOVERY_WORKFLOW, DISCOVERY_REPRESENTATION),
                    (VERSIONED_WORKFLOW, DISCOVERY_REPRESENTATION),
                    (OWNED_LAB_WORKFLOW, DISCOVERY_REPRESENTATION))
                or not _uuid(manifest["assessment_id"]) or not _uuid(manifest["session_id"])
                or not _digest(manifest["policy_digest"]) or manifest["fixture_case"] not in CASES
                or type(manifest["created_at"]) is not str or len(manifest["created_at"]) > 64):
            raise ValueError("invalid_assessment_manifest")
        discovery = manifest["workflow"] in _DISCOVERY_WORKFLOWS
        max_executions = 3 if discovery else MAX_EXECUTIONS
        issues, records, summary = [], [], None
        decisions, terminal, terminal_summary, latest_result = [], None, None, None
        lab_closure, lab_context = None, None
        try:
            journal = _read_private(fd, "evidence.jsonl", MAX_JOURNAL_BYTES)
        except (OSError, ValueError):
            journal = b""
            issues.append("journal_unavailable")
        lines = journal.splitlines(keepends=True)
        max_events = 12 if owned_lab is not None else 11 if workflow else 2 * max_executions + 1
        if len(lines) > max_events:
            issues.append("journal_event_limit")
            lines = lines[:max_events]
        referenced = {"manifest.json", "evidence.jsonl", "report.json", "report.md"}
        for line in lines:
            try:
                if not line.endswith(b"\n") or summary is not None:
                    raise ValueError("invalid_journal_order")
                event = load_json(line)
                if event["assessment_id"] != manifest["assessment_id"] or event["session_id"] != manifest["session_id"]:
                    raise ValueError("wrong_evidence_session")
                kind = event["event_type"]
                if kind == "assessment_finished":
                    candidate = _summary(event["summary"], manifest["session_id"], discovery=discovery,
                                         workflow=workflow)
                    _reconcile_summary(candidate, records, discovery=discovery)
                    if workflow and (terminal is None or _encode(candidate) != _encode(terminal_summary)):
                        raise ValueError("workflow_terminal_missing_or_mismatched")
                    if owned_lab is not None and lab_closure is None:
                        raise ValueError("owned_lab_closure_missing")
                    summary = candidate
                    continue
                if terminal is not None:
                    raise ValueError("workflow_already_terminated")
                if owned_lab is not None and kind == "assessment_owned_lab_closed":
                    if lab_closure is not None or any(row["artifact"] is None for row in records):
                        raise ValueError("invalid_owned_lab_closure_order")
                    lab_closure = validate_closure(event["receipt"], owned_lab, previous=lab_context)
                    continue
                if lab_closure is not None and kind != "assessment_workflow_terminal":
                    raise ValueError("owned_lab_already_closed")
                if workflow and kind == "assessment_workflow_decision":
                    decision = event["decision"]
                    step = decision["step"]
                    _check_decision_order(decisions, records, step)
                    expected = decide(manifest["fixture_case"], step, records,
                                      _workflow_observation(step, records, latest_result),
                                      owned_lab=owned_lab is not None)
                    _validate_decision(decision, expected, decisions)
                    decisions.append(decision)
                    continue
                if workflow and kind == "assessment_workflow_terminal":
                    candidate = _summary(event["summary"], manifest["session_id"], discovery=True, workflow=True)
                    _reconcile_summary(candidate, records, discovery=True)
                    _reconcile_workflow_summary(candidate, decisions, records)
                    if owned_lab is not None and lab_closure is None:
                        raise ValueError("owned_lab_closure_missing")
                    expected = terminal_decision(manifest["fixture_case"], records, candidate,
                                                 owned_lab=owned_lab is not None)
                    _validate_decision(event["decision"], expected, decisions)
                    terminal, terminal_summary = event["decision"], candidate
                    continue
                record = event["record"]
                if (type(record) is not dict or set(record) != {
                        "execution_id", "session_step", "action", "action_digest", "policy_digest", "backend",
                        "started_at", "finished_at", "execution_status", "observation_id", "observation", "artifact",
                        "authority_observation_sha256", "result_metadata"}
                        or not _uuid(record["execution_id"]) or not _digest(record["action_digest"])
                        or record["policy_digest"] != manifest["policy_digest"]
                        or type(record["backend"]) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,80}", record["backend"]) is None
                        or type(record["started_at"]) is not str or len(record["started_at"]) > 64):
                    raise ValueError("invalid_evidence_record")
                _check_action(record["action"], manifest["fixture_case"], record["session_step"], discovery=discovery)
                if owned_lab is not None and record["backend"] != BACKEND:
                    raise ValueError("invalid_owned_lab_execution")
                if kind == "assessment_execution_started":
                    if (len(records) >= max_executions or record["session_step"] != len(records) + 1
                            or record["execution_status"] != "started" or any(row["artifact"] is None for row in records)
                            or record["execution_id"] in {row["execution_id"] for row in records}
                            or any(record[key] is not None for key in ("finished_at", "observation_id", "observation", "artifact", "authority_observation_sha256", "result_metadata"))):
                        raise ValueError("invalid_evidence_start")
                    if workflow:
                        _require_proposed(decisions, record["session_step"], record["action_digest"])
                        from .discovery_contract import discovery_action

                        expected_action = parse_action(discovery_action(manifest["fixture_case"], record["session_step"]))
                        if (_encode(record["action"]) != _encode(_safe_action(expected_action))
                                or record["action_digest"] != expected_action.digest):
                            raise ValueError("workflow_action_mismatch")
                    records.append(record)
                elif kind == "assessment_execution_finished":
                    if (not records or records[-1]["artifact"] is not None
                            or any(record[key] != records[-1][key] for key in (
                                "execution_id", "session_step", "action", "action_digest", "policy_digest", "backend", "started_at"))
                            or record["execution_status"] not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}
                            or not _uuid(record["observation_id"]) or type(record["finished_at"]) is not str
                            or len(record["finished_at"]) > 64):
                        raise ValueError("invalid_evidence_completion")
                    if workflow and record["observation_id"] in {row["observation_id"] for row in records[:-1]}:
                        raise ValueError("duplicate_workflow_observation")
                    artifact = record["artifact"]
                    if (type(artifact) is not dict or set(artifact) != {"filename", "sha256", "bytes", "representation"}
                            or artifact["filename"] != "result-" + record["execution_id"] + ".json"
                            or not _digest(artifact["sha256"]) or type(artifact["bytes"]) is not int
                            or not 1 <= artifact["bytes"] <= MAX_ARTIFACT_BYTES
                            or artifact["representation"] != manifest["artifact_representation"]):
                        raise ValueError("invalid_evidence_artifact")
                    raw = _read_private(fd, artifact["filename"], MAX_ARTIFACT_BYTES)
                    referenced.add(artifact["filename"])
                    if len(raw) != artifact["bytes"] or hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
                        raise ValueError("artifact_digest_mismatch")
                    result = load_json(raw)
                    context = None
                    if owned_lab is not None:
                        context = validate_result_context(result, owned_lab, previous=lab_context,
                                                          tool_id=record["action"]["tool_id"],
                                                          execution_status=record["execution_status"])
                    if (_encode(_parse_observation(record["action"], result, execution_status=record["execution_status"], discovery=discovery, owned_lab=owned_lab)) != _encode(record["observation"])
                            or _encode(_result_metadata(result)) != _encode(record["result_metadata"])
                            or _observation_digest(record["session_step"], record["execution_status"], result) != record["authority_observation_sha256"]):
                        raise ValueError("observation_mismatch")
                    records[-1] = record
                    latest_result = result
                    lab_context = context
                else:
                    raise ValueError("unknown_evidence_event")
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
                issues.append("journal_or_artifact_incomplete")
                break
        if summary is None:
            issues.append("assessment_closure_missing")
        if workflow and terminal is None:
            issues.append("workflow_terminal_missing")
        if any(record["artifact"] is None for record in records):
            issues.append("execution_completion_unknown")
        if set(names) - referenced:
            issues.append("orphan_artifacts_present")
        report = _report(manifest, records, summary, issues, decisions, terminal, lab_closure)
        if summary is not None:
            try:
                saved = load_json(_read_private(fd, "report.json", MAX_REPORT_BYTES))
                markdown = _read_private(fd, "report.md", MAX_REPORT_BYTES)
                if _encode(saved) != _encode(report) or markdown != _markdown(report):
                    raise ValueError("report_mismatch")
            except (OSError, ValueError):
                issues.append("report_missing_or_mismatched")
                report = _report(manifest, records, summary, issues, decisions, terminal, lab_closure)
        return report
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
        raise EvidenceUnavailable("evidence_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
