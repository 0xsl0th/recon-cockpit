"""Bounded sequential owned-lab evaluations and read-only aggregate replay.

The host scheduler supplies no new execution authority. Each trial constructs a
fresh existing authority, lab, coordinator and synthetic provider. Grades come
only from saved evidence; neither returned workflow outcomes nor cached grades
are authoritative. This module never resumes a batch or an assessment.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import errno
import hashlib
import os
from pathlib import Path
import stat
import threading
import time
from uuid import UUID, uuid4

from .audit import AuditSink, AuditUnavailable
from .evidence import _encode, _read_private
from .models import load_json, parse_policy


MAX_MANIFEST_BYTES = 32768
MAX_BATCH_JOURNAL_BYTES = 131072
MAX_AGGREGATE_BYTES = 262144
RESERVATION = {"trials": 1, "steps": 3, "tool_output_bytes": 3072,
               "broker_calls": 3, "broker_output_tokens": 3072,
               "broker_request_bytes": 49152}
_END_REASONS = {"completed", "cancelled", "deadline", "trial_failed", "dry_run", "component_failed"}
_ENVELOPE = {"event_schema_version", "event_id", "timestamp", "source", "evaluation_id", "event_type"}


class EvaluationUnavailable(AuditUnavailable):
    code = "evaluation_unavailable"


@dataclass(frozen=True, slots=True)
class EvaluationLimits:
    repeats: int = 3
    max_runtime_seconds: int = 600

    def __post_init__(self):
        for name, maximum in (("repeats", 10), ("max_runtime_seconds", 3600)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid_evaluation_" + name)


def _plan(limits):
    return [{"trial_id": f"trial-{(repeat - 1) * 6 + offset:03d}-{case}",
             "repeat": repeat, "case": case}
            for repeat in range(1, limits.repeats + 1)
            for offset, case in enumerate("abcdef", 1)]


def _totals(count):
    return {key: value * count for key, value in RESERVATION.items()}


def _uuid(value):
    return type(value) is str and str(UUID(value)) == value


def _open_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise EvaluationUnavailable("evaluation_directory_must_be_private")
        return fd
    except BaseException:
        os.close(fd)
        raise


class _Directory:
    """Fresh private files, exclusive writes, directory identity and durable names."""

    def __init__(self, path):
        self.path = Path(path)
        self.fd = None
        try:
            # The caller supplies an existing parent; never replace or resume a
            # directory, and do not silently create public ancestor directories.
            self.path.mkdir(mode=0o700)
            self.fd = _open_directory(self.path)
            parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except (OSError, RuntimeError):
            self.close()
            raise EvaluationUnavailable("evaluation_directory_unavailable") from None

    def check(self):
        if self.fd is None:
            raise EvaluationUnavailable("evaluation_directory_closed")
        current = os.fstat(self.fd)
        named = self.path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino) or named.st_mode & 0o077:
            raise EvaluationUnavailable("evaluation_directory_changed")

    def write(self, name, value, maximum):
        self.check()
        raw = value if type(value) is bytes else _encode(value)
        if len(raw) > maximum:
            raise EvaluationUnavailable("evaluation_file_limit")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=self.fd)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    raise EvaluationUnavailable("evaluation_short_write")
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _validate_policy(policy):
    from .discovery_contract import discovery_action

    policy = parse_policy(policy.to_dict())
    # Automation must be explicitly permitted by the operator's policy. Never
    # rewrite require_approval or manufacture approval grants for the baseline.
    if policy.require_approval:
        raise ValueError("evaluation_requires_explicit_unattended_owned_policy")
    from .models import parse_action

    if any(policy.evaluate(parse_action(discovery_action(case, step))).decision != "allow"
           for case in "abcdef" for step in (1, 2, 3)):
        raise ValueError("evaluation_policy_does_not_allow_fixed_workflow")
    return policy


class EvaluationRunner:
    """Single-use, sequential scheduler with fixed per-trial authority limits."""

    def __init__(self, directory, policy, limits=None):
        self.directory = Path(directory)
        self.policy = _validate_policy(policy)
        self.limits = EvaluationLimits() if limits is None else limits
        if type(self.limits) is not EvaluationLimits:
            raise ValueError("invalid_evaluation_limits")
        self.evaluation_id = str(uuid4())
        self._lock = threading.RLock()
        self._used = False
        self._active = None
        self._stop_reason = None
        self._deadline = None

    def cancel(self):
        self._stop("cancelled")

    def _stop(self, reason):
        with self._lock:
            if self._stop_reason is None:
                self._stop_reason = reason
            if self._active is not None:
                self._active.cancel()

    def _stopped(self):
        with self._lock:
            if self._deadline is not None and time.monotonic() >= self._deadline:
                self._stop("deadline")
            return self._stop_reason

    def _install(self, runner):
        with self._lock:
            if self._stopped() is not None:
                runner.cancel()
            self._active = runner

    def _run_trial(self, path, case):
        from .assessment import WorkflowAssessmentProvider
        from .control_plane import AuthoritySession
        from .coordinator_isolation import LinuxOfflineCoordinator
        from .evidence import EvidenceStore, EvidenceUnavailable
        from .evaluation_contract import FIXED_LIMITS
        from .isolation import IsolationUnavailable
        from .owned_lab import OwnedLab, AuthorizedOwnedLabBackend
        from .session import SessionLimits

        started = time.monotonic()
        limits = SessionLimits(**FIXED_LIMITS)
        session_id = str(uuid4())
        lab = OwnedLab(case, session_id, limits, execute=True)
        backend = AuthorizedOwnedLabBackend(self.policy, session_id, limits, lab, execute=True)
        coordinator = LinuxOfflineCoordinator()
        provider = None
        closure = None
        error = None
        cleanup = {"owner_reaped": False, "namespace_fds_closed": False}
        with _Directory(path) as directory:
            try:
                with AuditSink(path / "audit.jsonl") as audit, EvidenceStore(
                        path / "evidence", session_id=session_id, policy=self.policy,
                        case=case, discovery=True, workflow=True, owned_lab=lab.identity) as evidence:
                    provider = WorkflowAssessmentProvider(case, audit, evidence)
                    authority = AuthoritySession(self.policy, audit, backend, coordinator, limits,
                        session_id=session_id, provider=provider, evidence=evidence, deadline=self._deadline)
                    self._install(authority)
                    summary = authority.run(execute=True)
                    closure = lab.close()
                    evidence.record_lab_closed(closure)
                    evidence.finalize(summary)
            except EvidenceUnavailable:
                error = "evidence_unavailable"
            except AuditUnavailable:
                error = "audit_unavailable"
            except IsolationUnavailable:
                error = "isolation_unavailable"
            except (OSError, ValueError, RuntimeError, TypeError):
                error = "trial_component_failed"
            finally:
                # These are trusted supervisor observations, not agent claims.
                # Full coordinator/parser/owner descendant cleanup is also
                # independently exercised by the real Linux integration tests.
                pins = tuple(lab._namespace_fds)
                try:
                    closure = lab.close()
                    supervisor = lab._supervisor
                    cleanup["owner_reaped"] = supervisor is None or all(
                        proc.poll() is not None for proc in supervisor.processes.values())
                    closed = True
                    for fd in pins:
                        try:
                            os.fstat(fd)
                            closed = False
                        except OSError as exc:
                            if exc.errno != errno.EBADF:
                                closed = False
                    cleanup["namespace_fds_closed"] = closed
                except (OSError, RuntimeError):
                    error = "cleanup_unconfirmed"
                with self._lock:
                    self._active = None
            directory.write("runtime.json", {
                "schema_version": "1", "case": case, "session_id": session_id,
                "lab_identity": lab.identity, "backend": dict(backend.snapshot),
                "broker_id": provider.broker.broker_id if provider else None,
                "broker": dict(provider.broker.snapshot) if provider else None,
                "coordinator_boundary_checks": coordinator.boundary_checks,
                "parser_boundary_checks": provider.boundary_checks if provider else None,
                "lab_closure": closure, "cleanup": cleanup, "error": error,
                "elapsed_ms": min(10**9, max(0, int((time.monotonic() - started) * 1000))),
            }, 16384)

    def run(self, *, execute=False, on_trial=None):
        from .evaluation_contract import FIXED_LIMITS, evaluation_identity
        from .evaluation_grading import grade_trial

        if type(execute) is not bool:
            raise ValueError("invalid_evaluation_mode")
        with self._lock:
            if self._used:
                raise RuntimeError("evaluation_already_used")
            self._used = True
            started = time.monotonic()
            self._deadline = started + self.limits.max_runtime_seconds
        plan = _plan(self.limits)
        timer = threading.Timer(self.limits.max_runtime_seconds, lambda: self._stop("deadline"))
        timer.daemon = True
        timer.start()
        try:
            with _Directory(self.directory) as directory:
                directory.write("manifest.json", {
                    "schema_version": "1", "evaluation_id": self.evaluation_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "evaluation": evaluation_identity(), "limits": asdict(self.limits),
                    "trial_limits": FIXED_LIMITS, "policy": self.policy.to_dict(),
                    "policy_digest": self.policy.digest, "plan": plan,
                    "reservation_per_trial": RESERVATION, "batch_allowances": _totals(len(plan)),
                    "mode": "execute" if execute else "dry_run", "live_calls_enabled": False,
                }, MAX_MANIFEST_BYTES)
                with AuditSink(self.directory / "evaluation.jsonl") as audit:
                    def emit(kind, **fields):
                        directory.check()
                        event = {"evaluation_id": self.evaluation_id, "event_type": kind, **fields}
                        if os.stat("evaluation.jsonl", dir_fd=directory.fd).st_size + len(_encode(event)) + 512 > MAX_BATCH_JOURNAL_BYTES:
                            raise EvaluationUnavailable("evaluation_journal_limit")
                        audit.emit(event)

                    reason = "dry_run" if not execute else "completed"
                    if execute:
                        for index, trial in enumerate(plan, 1):
                            if self._stopped() is not None:
                                reason = self._stopped()
                                break
                            # Full per-trial allowances are reserved durably
                            # before constructing authority; never refunded.
                            emit("evaluation_trial_started", **trial, reserved_totals=_totals(index))
                            try:
                                directory.check()
                                self._run_trial(self.directory / trial["trial_id"], trial["case"])
                            except (OSError, AuditUnavailable, ValueError, RuntimeError):
                                # Preserve the durable start and independently
                                # grade whatever was actually saved; no retry.
                                reason = "component_failed"
                            grade = grade_trial(self.directory / trial["trial_id"], case=trial["case"],
                                                policy_digest=self.policy.digest, limits=FIXED_LIMITS)
                            emit("evaluation_trial_finished", trial_id=trial["trial_id"],
                                 grade_sha256=hashlib.sha256(_encode(grade)).hexdigest())
                            if on_trial is not None:
                                on_trial({**trial, "grade": grade, "evidence": trial["trial_id"] + "/evidence"})
                            if self._stopped() is not None:
                                reason = self._stopped()
                                break
                            if grade["verdict"] != "passed" or reason == "component_failed":
                                reason = "trial_failed" if reason == "completed" else reason
                                break
                    emit("evaluation_finished", stop_reason=reason,
                         elapsed_ms=min(10**9, max(0, int((time.monotonic() - started) * 1000))))
                report = _inspect_evaluation(self.directory, check_reports=False)
                directory.write("report.json", report, MAX_AGGREGATE_BYTES)
                directory.write("report.md", _markdown(report), MAX_AGGREGATE_BYTES)
                return report
        finally:
            timer.cancel()
            timer.join()


def _validate_manifest(value):
    from .evaluation_contract import FIXED_LIMITS, evaluation_identity

    fields = {"schema_version", "evaluation_id", "created_at", "evaluation", "limits", "trial_limits",
              "policy", "policy_digest", "plan", "reservation_per_trial", "batch_allowances", "mode", "live_calls_enabled"}
    if type(value) is not dict or set(value) != fields or not _uuid(value["evaluation_id"]):
        raise ValueError("invalid_evaluation_manifest")
    limits = EvaluationLimits(**value["limits"])
    policy = _validate_policy(parse_policy(value["policy"]))
    if (value["schema_version"] != "1" or value["evaluation"] != evaluation_identity()
            or _encode(value["trial_limits"]) != _encode(FIXED_LIMITS)
            or value["policy_digest"] != policy.digest or value["policy"] != policy.to_dict()
            or _encode(value["plan"]) != _encode(_plan(limits))
            or _encode(value["reservation_per_trial"]) != _encode(RESERVATION)
            or _encode(value["batch_allowances"]) != _encode(_totals(len(value["plan"])))
            or value["mode"] not in {"execute", "dry_run"} or value["live_calls_enabled"] is not False
            or type(value["created_at"]) is not str or len(value["created_at"]) > 64):
        raise ValueError("invalid_evaluation_manifest")
    return value


def _journal(fd, manifest):
    raw = _read_private(fd, "evaluation.jsonl", MAX_BATCH_JOURNAL_BYTES)
    lines = raw.splitlines()
    issues = []
    if raw and not raw.endswith(b"\n"):
        lines = lines[:-1]
        issues.append("evaluation_journal_torn")
    starts, finishes, terminal, ids = [], {}, None, set()

    def accept(line):
        nonlocal terminal
        event = load_json(line)
        if type(event) is not dict:
            raise ValueError("invalid_evaluation_event")
        kind = event.get("event_type")
        keys = {"evaluation_trial_started": {"trial_id", "repeat", "case", "reserved_totals"},
                "evaluation_trial_finished": {"trial_id", "grade_sha256"},
                "evaluation_finished": {"stop_reason", "elapsed_ms"}}
        if (kind not in keys or set(event) != _ENVELOPE | keys[kind]
                or event["evaluation_id"] != manifest["evaluation_id"]
                or event["event_schema_version"] != "1" or event["source"] != "recon-cockpit.secure-agent"
                or not _uuid(event["event_id"]) or event["event_id"] in ids or terminal is not None):
            raise ValueError("invalid_evaluation_journal")
        ids.add(event["event_id"])
        if kind == "evaluation_trial_started":
            if manifest["mode"] != "execute" or len(starts) != len(finishes) or len(starts) >= len(manifest["plan"]):
                raise ValueError("invalid_evaluation_trial_order")
            expected = manifest["plan"][len(starts)]
            if (_encode({key: event[key] for key in expected}) != _encode(expected)
                    or _encode(event["reserved_totals"]) != _encode(_totals(len(starts) + 1))):
                raise ValueError("invalid_evaluation_reservation")
            starts.append(expected)
        elif kind == "evaluation_trial_finished":
            if (not starts or len(finishes) != len(starts) - 1
                    or event["trial_id"] != starts[-1]["trial_id"]
                    or type(event["grade_sha256"]) is not str or len(event["grade_sha256"]) != 64):
                raise ValueError("invalid_evaluation_trial_finish")
            finishes[event["trial_id"]] = event["grade_sha256"]
        else:
            if (event["stop_reason"] not in _END_REASONS
                    or type(event["elapsed_ms"]) is not int or not 0 <= event["elapsed_ms"] <= 10**9
                    or len(starts) != len(finishes)
                    or (event["stop_reason"] == "completed" and len(starts) != len(manifest["plan"]))
                    or (event["stop_reason"] == "dry_run") != (manifest["mode"] == "dry_run")):
                raise ValueError("invalid_evaluation_terminal")
            terminal = {"stop_reason": event["stop_reason"], "elapsed_ms": event["elapsed_ms"]}
    for line in lines:
        try:
            accept(line)
        except (ValueError, RuntimeError, TypeError, KeyError):
            issues.append("evaluation_journal_invalid")
            break
    # Retain every verified durable reservation even if a later completion was
    # torn or malformed. Inspection cannot refund or resume an unfinished trial.
    return starts, finishes, terminal, issues


def _aggregate(manifest, trials, starts, finishes, terminal, issues):
    from .evaluation_contract import CASES

    passed = sum(row["grade"]["verdict"] == "passed" for row in trials)
    reason = terminal["stop_reason"] if terminal else "completion_unknown"
    planned = len(manifest["plan"])
    status = ("dry_run" if reason == "dry_run" else
              "passed" if reason == "completed" and passed == planned else
              "failed" if reason in {"completed", "trial_failed", "component_failed"} else "incomplete")
    for key in ("session_id", "assessment_id", "lab_instance_id", "broker_id"):
        values = [row["grade"][key] for row in trials if row["grade"].get(key) is not None]
        if len(values) != len(set(values)):
            issues.append("reused_" + key)
    per_case = []
    for case in CASES:
        grades = [row["grade"] for row in trials if row["case"] == case]
        fingerprints = {row["semantic_fingerprint"] for row in grades if row["verdict"] == "passed"}
        agreement = (len(grades) == manifest["limits"]["repeats"]
                     and all(row["verdict"] == "passed" for row in grades) and len(fingerprints) == 1)
        if len(fingerprints) > 1:
            issues.append("semantic_repeat_mismatch")
        per_case.append({"case": case, "planned": manifest["limits"]["repeats"],
                         "graded": len(grades), "passed": sum(row["verdict"] == "passed" for row in grades),
                         "semantic_agreement": agreement})
    metric_names = ("executions", "steps_attempted", "actions_succeeded", "unnecessary_actions", "output_bytes_reserved",
                    "broker_calls_reserved", "broker_output_tokens_reserved", "broker_request_bytes_reserved",
                    "retained_response_bytes", "session_duration_ms", "elapsed_ms")
    metrics = {}
    for key in metric_names:
        values = [row["grade"].get("metrics", {}).get(key) for row in trials]
        metrics[key] = sum(values) if all(type(value) is int and value >= 0 for value in values) else None
    if issues:
        status = "incomplete" if terminal is None else "failed"
    outcomes = {key: sum(row["grade"].get("outcome") == key for row in trials)
                for key in ("validated", "not_demonstrated", "inconclusive")}
    return {"schema_version": "1", "evaluation_id": manifest["evaluation_id"],
            "evaluation": manifest["evaluation"], "limits": manifest["limits"], "policy_digest": manifest["policy_digest"],
            "status": status, "stop_reason": reason, "live_calls_enabled": False,
            "planned_trials": planned, "started_trials": len(starts), "completed_trials": len(finishes),
            "passed_trials": passed, "failed_trials": len(trials) - passed,
            "not_run_trials": planned - len(starts), "trials": trials, "per_case": per_case,
            "outcomes": outcomes, "correct_abstentions": sum(row["grade"].get("classification") == "correct_abstention" for row in trials),
            "cleanup_verified_trials": sum(row["grade"].get("checks", {}).get("cleanup") is True for row in trials),
            "isolation_verified_trials": sum(row["grade"].get("checks", {}).get("isolation") is True for row in trials),
            "batch_allowances": manifest["batch_allowances"], "reservations": _totals(len(starts)),
            "aggregate_metrics": metrics, "resource_accounting_complete": not issues and passed == len(starts) and len(finishes) == len(starts),
            "elapsed_ms": terminal["elapsed_ms"] if terminal else None,
            "integrity_issues": sorted(set(issues)),
            "limitations": [
                "Synthetic owned cases only; expected-decision agreement is not live-model or general vulnerability accuracy.",
                "Correct abstentions are distinct from a negative finding and from infrastructure or evidence failures.",
                "Reservations are ceilings, not measured token use, network traffic or monetary spending; failed work is never refunded.",
                "Cleanup and isolation receipts are trusted host observations; Linux tests additionally check real child processes.",
                "Local evidence hashes do not authenticate against a malicious host owner. Inspection never resumes execution.",
                "Batch cancellation stops future trials and cancels current authority; kernel stalls and durable storage may delay teardown.",
            ]}


def _inspect_evaluation(directory, *, check_reports=True):
    from .evaluation_grading import grade_trial

    path = Path(directory)
    fd = None
    try:
        fd = _open_directory(path)
        manifest = _validate_manifest(load_json(_read_private(fd, "manifest.json", MAX_MANIFEST_BYTES)))
        issues = []
        try:
            starts, finishes, terminal, journal_issues = _journal(fd, manifest)
            issues.extend(journal_issues)
        except (OSError, ValueError, RuntimeError, TypeError, KeyError):
            starts, finishes, terminal = [], {}, None
            issues.append("evaluation_journal_invalid")
        if terminal is None:
            issues.append("evaluation_completion_unknown")
        expected_names = {"manifest.json", "evaluation.jsonl", "report.json", "report.md", *[row["trial_id"] for row in starts]}
        if set(os.listdir(fd)) - expected_names:
            issues.append("unexpected_evaluation_entry")
        trials = []
        for trial in starts:
            grade = grade_trial(path / trial["trial_id"], case=trial["case"],
                                policy_digest=manifest["policy_digest"], limits=manifest["trial_limits"])
            if trial["trial_id"] not in finishes:
                issues.append("trial_completion_unknown")
            elif hashlib.sha256(_encode(grade)).hexdigest() != finishes[trial["trial_id"]]:
                issues.append("saved_trial_grade_mismatch")
            trials.append({**trial, "grade": grade, "evidence": trial["trial_id"] + "/evidence"})
        report = _aggregate(manifest, trials, starts, finishes, terminal, issues)
        if check_reports:
            try:
                saved = load_json(_read_private(fd, "report.json", MAX_AGGREGATE_BYTES))
                markdown = _read_private(fd, "report.md", MAX_AGGREGATE_BYTES)
                if _encode(saved) != _encode(report) or markdown != _markdown(report):
                    issues.append("aggregate_report_mismatch")
            except (OSError, ValueError, RuntimeError, TypeError):
                issues.append("aggregate_report_unavailable")
            report = _aggregate(manifest, trials, starts, finishes, terminal, issues)
        return report
    except (OSError, ValueError, RuntimeError, TypeError, KeyError):
        raise EvaluationUnavailable("evaluation_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def inspect_evaluation(directory):
    """Regrade every started trial from disk; do not execute or write anything."""
    return _inspect_evaluation(directory)


def _markdown(report):
    lines = ["# Repeated owned lab evaluation", "", "Status: **" + report["status"] + "**", "",
             "Evaluation: `" + report["evaluation_id"] + "`", "",
             f"Trials: {report['passed_trials']} passed; {report['failed_trials']} failed; {report['not_run_trials']} not run.", "",
             "Stop reason: `" + report["stop_reason"] + "`", "",
             "Expected decision agreement is measured against the versioned synthetic case specification.", "",
             "| Trial | Case | Grade | Expected | Observed | Evidence |", "| --- | --- | --- | --- | --- | --- |"]
    for trial in report["trials"]:
        grade = trial["grade"]
        lines.append(f"| {trial['trial_id']} | {trial['case']} | {grade['verdict']} | {grade['expected_outcome']} | {grade['outcome'] or 'unknown'} | [inspect bundle]({trial['evidence']}/report.md) |")
    for trial in report["trials"]:
        grade = trial["grade"]
        if grade["issues"]:
            lines.append("")
            lines.append("Trial `" + trial["trial_id"] + "`: " + ", ".join("`" + value + "`" for value in grade["issues"]) + ".")
            lines.append("")
    lines.extend(["", "## Resource accounting", "",
                  "Batch reservations admit full per-trial allowances before starting; they are never refunded.", "",
                  "| Reservation | Admitted | Batch ceiling |", "| --- | --- | --- |"])
    for key, value in report["reservations"].items():
        lines.append(f"| {key} | {value} | {report['batch_allowances'][key]} |")
    lines.extend(["", "| Observed metric | Total |", "| --- | --- |"])
    for key, value in report["aggregate_metrics"].items():
        lines.append(f"| {key} | {value if value is not None else 'unknown'} |")
    lines.extend(["", "## Limits", ""])
    lines.extend("- " + value for value in report["limitations"])
    if report["integrity_issues"]:
        lines.extend(["", "## Integrity issues", ""])
        lines.extend("- `" + value + "`" for value in report["integrity_issues"])
    return ("\n".join(lines) + "\n").encode("ascii")
