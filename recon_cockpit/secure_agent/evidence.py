"""Private, bounded evidence for the fixed owned HTTP assessment.

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


def _check_action(action, case, step):
    from .assessment_contract import assessment_action

    if type(step) is not int or not 1 <= step <= MAX_EXECUTIONS:
        raise ValueError("invalid_evidence_step")
    parsed = parse_action({**action, "rationale": "Evidence excludes planner rationale."})
    expected = assessment_action(case, step)
    # Action IDs are planner data. The store generates its own execution IDs.
    if any(parsed.to_dict()[key] != expected[key] for key in ("tool_id", "target", "parameters")):
        raise ValueError("unexpected_assessment_action")
    if set(action) != {"schema_version", "action_id", "tool_id", "target", "parameters"}:
        raise ValueError("invalid_evidence_action")


def _summary(value, session_id):
    keys = ("session_id", "session_status", "stop_reason", "steps_attempted",
            "actions_succeeded", "output_reserved_bytes", "mode")
    result = {key: value[key] for key in keys}
    if (result["session_id"] != session_id or result["session_status"] not in {"completed", "stopped"}
            or result["mode"] not in {"execute", "dry_run"}
            or type(result["stop_reason"]) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", result["stop_reason"]) is None):
        raise ValueError("invalid_assessment_summary")
    for key, maximum in (("steps_attempted", 16), ("actions_succeeded", 2), ("output_reserved_bytes", 1048576)):
        if type(result[key]) is not int or not 0 <= result[key] <= maximum:
            raise ValueError("invalid_assessment_summary")
    return result


def _observation_digest(step, status, result):
    # Local import avoids a Controller -> evidence -> session -> Controller cycle.
    from .session import _observation

    return hashlib.sha256(_observation(step + 1, {
        "execution_status": status, "untrusted_result": result,
    })).hexdigest()


def _result_metadata(result):
    from .controller import result_metadata

    return result_metadata(result)


def _report(manifest, records, summary, issues):
    from .assessment_contract import capability_descriptor, discovery_path, diagnostics_path

    issues = sorted(set(issues))
    outcome, reason = "inconclusive", "assessment_incomplete"
    completed = [row for row in records if row.get("artifact") is not None]
    if summary is not None and not issues:
        if summary["mode"] == "dry_run":
            reason = "dry_run_has_no_execution_evidence"
        elif summary["session_status"] != "completed":
            reason = "session_stopped"
        elif (len(completed) == 2 and [row["session_step"] for row in completed] == [1, 2]
              and all(row["execution_status"] == "succeeded" for row in completed)
              and completed[0]["observation"]["classification"] == "discovered"):
            classification = completed[1]["observation"]["classification"]
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
    return {
        "schema_version": "1", "assessment_id": manifest["assessment_id"],
        "session_id": manifest["session_id"], "workflow": WORKFLOW,
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
        ],
    }


def _markdown(report):
    # Only validated enums, UUIDs, generated artifact filenames/digests and fixed
    # text are rendered. No response body, rationale or model prose is included.
    lines = ["# Owned HTTP assessment", "", "Outcome: **" + report["outcome"] + "**", "",
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
    lines.extend(["", "## Interpretation", "", report["finding"]["impact"], "",
                  report["finding"]["remediation"], "", "## Limits", ""])
    lines.extend("- " + value for value in report["limitations"])
    if report["integrity_issues"]:
        lines.extend(["", "## Evidence requiring reconciliation", ""])
        lines.extend("- `" + issue + "`" for issue in report["integrity_issues"])
    return ("\n".join(lines) + "\n").encode("ascii")


class EvidenceStore:
    """One fresh, bounded assessment. Existing directories cannot be resumed."""

    def __init__(self, directory, *, session_id, policy, case):
        from .assessment_contract import CASES

        self.directory = Path(directory)
        self._fd = None
        self._journal = None
        self._failed = False
        self._finalized = False
        self._records = []
        self._lock = threading.Lock()
        try:
            if not _uuid(session_id) or type(case) is not str or case not in CASES:
                raise ValueError("invalid_assessment_configuration")
            self._manifest = {
                "schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
                "workflow": WORKFLOW, "fixture_case": case, "policy_digest": policy.digest,
                "created_at": _now(), "artifact_representation": REPRESENTATION,
            }
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
                _check_action(safe, self._manifest["fixture_case"], session_step)
                if (session_id != self._manifest["session_id"] or policy.digest != self._manifest["policy_digest"]
                        or session_step != len(self._records) + 1 or len(self._records) >= MAX_EXECUTIONS
                        or any(row["artifact"] is None for row in self._records)
                        or type(backend) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,80}", backend) is None):
                    raise ValueError("invalid_evidence_start")
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
        from .assessment_contract import parse_observation

        with self._lock:
            try:
                self._check()
                if (not self._records or self._records[-1]["execution_id"] != execution_id
                        or self._records[-1]["artifact"] is not None
                        or execution_status not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}
                        or type(result) is not dict):
                    raise ValueError("invalid_evidence_completion")
                record = self._records[-1]
                raw = _encode(result)
                filename = "result-" + execution_id + ".json"
                self._write_new(filename, raw, MAX_ARTIFACT_BYTES)
                completed = {**record, "finished_at": _now(), "execution_status": execution_status,
                             "observation_id": str(uuid4()),
                             "result_metadata": _result_metadata(result),
                             "observation": parse_observation(record["action"], result,
                                                              execution_status=execution_status),
                             "artifact": {"filename": filename, "sha256": hashlib.sha256(raw).hexdigest(),
                                          "bytes": len(raw), "representation": REPRESENTATION},
                             "authority_observation_sha256": _observation_digest(record["session_step"], execution_status, result)}
                self._emit({"event_type": "assessment_execution_finished", "record": completed})
                self._records[-1] = completed
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def finalize(self, summary):
        with self._lock:
            try:
                self._check()
                safe = _summary(summary, self._manifest["session_id"])
                succeeded = sum(row["execution_status"] == "succeeded" for row in self._records)
                if safe["actions_succeeded"] != succeeded:
                    raise ValueError("inconsistent_assessment_summary")
                issues = ["execution_completion_unknown"] if any(row["artifact"] is None for row in self._records) else []
                report = _report(self._manifest, self._records, safe, issues)
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
    from .assessment_contract import CASES, parse_observation

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
        if (set(manifest) != {"schema_version", "assessment_id", "session_id", "workflow", "fixture_case",
                             "policy_digest", "created_at", "artifact_representation"}
                or manifest["schema_version"] != "1" or manifest["workflow"] != WORKFLOW
                or manifest["artifact_representation"] != REPRESENTATION
                or not _uuid(manifest["assessment_id"]) or not _uuid(manifest["session_id"])
                or not _digest(manifest["policy_digest"]) or manifest["fixture_case"] not in CASES
                or type(manifest["created_at"]) is not str or len(manifest["created_at"]) > 64):
            raise ValueError("invalid_assessment_manifest")
        issues, records, summary = [], [], None
        try:
            journal = _read_private(fd, "evidence.jsonl", MAX_JOURNAL_BYTES)
        except (OSError, ValueError):
            journal = b""
            issues.append("journal_unavailable")
        lines = journal.splitlines(keepends=True)
        if len(lines) > 5:
            issues.append("journal_event_limit")
            lines = lines[:5]
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
                    summary = _summary(event["summary"], manifest["session_id"])
                    if summary["actions_succeeded"] != sum(row["execution_status"] == "succeeded" for row in records):
                        raise ValueError("inconsistent_assessment_summary")
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
                _check_action(record["action"], manifest["fixture_case"], record["session_step"])
                if kind == "assessment_execution_started":
                    if (len(records) >= 2 or record["session_step"] != len(records) + 1
                            or record["execution_status"] != "started" or any(row["artifact"] is None for row in records)
                            or record["execution_id"] in {row["execution_id"] for row in records}
                            or any(record[key] is not None for key in ("finished_at", "observation_id", "observation", "artifact", "authority_observation_sha256", "result_metadata"))):
                        raise ValueError("invalid_evidence_start")
                    records.append(record)
                elif kind == "assessment_execution_finished":
                    if (not records or records[-1]["artifact"] is not None
                            or any(record[key] != records[-1][key] for key in (
                                "execution_id", "session_step", "action", "action_digest", "policy_digest", "backend", "started_at"))
                            or record["execution_status"] not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}
                            or not _uuid(record["observation_id"]) or type(record["finished_at"]) is not str
                            or len(record["finished_at"]) > 64):
                        raise ValueError("invalid_evidence_completion")
                    artifact = record["artifact"]
                    if (type(artifact) is not dict or set(artifact) != {"filename", "sha256", "bytes", "representation"}
                            or artifact["filename"] != "result-" + record["execution_id"] + ".json"
                            or not _digest(artifact["sha256"]) or type(artifact["bytes"]) is not int
                            or not 1 <= artifact["bytes"] <= MAX_ARTIFACT_BYTES or artifact["representation"] != REPRESENTATION):
                        raise ValueError("invalid_evidence_artifact")
                    raw = _read_private(fd, artifact["filename"], MAX_ARTIFACT_BYTES)
                    referenced.add(artifact["filename"])
                    if len(raw) != artifact["bytes"] or hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
                        raise ValueError("artifact_digest_mismatch")
                    result = load_json(raw)
                    if (_encode(parse_observation(record["action"], result, execution_status=record["execution_status"])) != _encode(record["observation"])
                            or _encode(_result_metadata(result)) != _encode(record["result_metadata"])
                            or _observation_digest(record["session_step"], record["execution_status"], result) != record["authority_observation_sha256"]):
                        raise ValueError("observation_mismatch")
                    records[-1] = record
                else:
                    raise ValueError("unknown_evidence_event")
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
                issues.append("journal_or_artifact_incomplete")
                break
        if summary is None:
            issues.append("assessment_closure_missing")
        if any(record["artifact"] is None for record in records):
            issues.append("execution_completion_unknown")
        if set(names) - referenced:
            issues.append("orphan_artifacts_present")
        report = _report(manifest, records, summary, issues)
        if summary is not None:
            try:
                saved = load_json(_read_private(fd, "report.json", MAX_REPORT_BYTES))
                markdown = _read_private(fd, "report.md", MAX_REPORT_BYTES)
                if _encode(saved) != _encode(report) or markdown != _markdown(report):
                    raise ValueError("report_mismatch")
            except (OSError, ValueError):
                issues.append("report_missing_or_mismatched")
                report = _report(manifest, records, summary, issues)
        return report
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
        raise EvidenceUnavailable("evidence_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
