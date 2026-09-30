"""Bounded owned TLS planning evaluations; saved artifacts never restore authority.

The old deterministic baseline and its strict grader remain a separate profile.
One private simulation ledger enforces the whole batch cap. The writer is closed
before read-only replay opens it; no second descriptor may release SQLite locks.
"""

from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime, timezone, timedelta
import hashlib
import os
from pathlib import Path
import threading
import time

from .audit import AuditSink, AuditUnavailable
from .cost_contract import CostError
from .cost_ledger import CostLedger
from .evaluation import (EvaluationRunner, EvaluationLimits, EvaluationUnavailable,
    MAX_MANIFEST_BYTES, MAX_BATCH_JOURNAL_BYTES, _Directory,
    _plan, _uuid, _open_directory, _validate_policy, _END_REASONS, _ENVELOPE,
    _aggregate as _baseline_aggregate, _markdown as _baseline_markdown)
from .evidence import _encode, _read_private
from .models import load_json, parse_policy
from .planning_evaluation_contract import (FIXED_LIMITS, RESERVATION, TRIAL_BUDGET,
    PLANNING_METRICS, evaluation_identity, scope_ids, totals as _totals)


# Up to 60 trials include immutable per-attempt quotes and settlements in grades.
MAX_AGGREGATE_BYTES = 2 * 1024 * 1024


def _timestamp(value):
    if type(value) is not str or not 20 <= len(value) <= 32:
        raise ValueError("invalid_planning_evaluation_timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timedelta(0) or parsed.isoformat() != value:
        raise ValueError("invalid_planning_evaluation_timestamp")


class PlanningEvaluationRunner(EvaluationRunner):
    """Single-use sequential scheduler for fixed, disconnected planning trials."""

    def _run_trial(self, path, case):
        from .planning_evaluation_runtime import run_trial
        run_trial(self, path, case, ledger=self._ledger, **scope_ids(self.evaluation_id))

    def run(self, *, execute=False, on_trial=None):
        from .planning_evaluation_grading import grade_trial

        if type(execute) is not bool:
            raise ValueError("invalid_evaluation_mode")
        with self._lock:
            if self._used:
                raise RuntimeError("evaluation_already_used")
            self._used = True
            started = time.monotonic()
            self._deadline = started + self.limits.max_runtime_seconds
        plan = _plan(self.limits)
        scopes = scope_ids(self.evaluation_id)
        timer = threading.Timer(self.limits.max_runtime_seconds, lambda: self._stop("deadline"))
        timer.daemon = True
        timer.start()
        self._ledger = None
        try:
            with _Directory(self.directory) as directory:
                with ExitStack() as resources:
                    if execute:
                        self._ledger = resources.enter_context(CostLedger.create(
                            self.directory / "planning-ledger", account_id=scopes["account_scope_id"],
                            limit_microusd=len(plan) * TRIAL_BUDGET, mode="simulation"))
                        self._ledger.add_scope(scopes["engagement_scope_id"],
                            parent_id=scopes["account_scope_id"], kind="engagement",
                            limit_microusd=len(plan) * TRIAL_BUDGET)
                    directory.write("manifest.json", {
                        "schema_version": "1", "evaluation_id": self.evaluation_id,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "evaluation": evaluation_identity(), "limits": asdict(self.limits),
                        "trial_limits": FIXED_LIMITS, "policy": self.policy.to_dict(),
                        "policy_digest": self.policy.digest, "plan": plan,
                        "reservation_per_trial": RESERVATION, "batch_allowances": _totals(len(plan)),
                        "mode": "execute" if execute else "dry_run", "live_calls_enabled": False,
                        "planning_ledger": {**scopes,
                            "ledger_id": self._ledger.ledger_id if self._ledger else None,
                            "directory": "planning-ledger", "mode": "simulation",
                            "period": "lifetime", "limit_microusd": len(plan) * TRIAL_BUDGET},
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
                                # Durable full ceilings precede constructing any trial authority.
                                emit("evaluation_trial_started", **trial, reserved_totals=_totals(index))
                                try:
                                    directory.check()
                                    self._run_trial(self.directory / trial["trial_id"], trial["case"])
                                except (OSError, AuditUnavailable, ValueError, RuntimeError):
                                    reason = "component_failed"
                                grade = grade_trial(self.directory / trial["trial_id"], case=trial["case"],
                                    policy_digest=self.policy.digest, limits=FIXED_LIMITS,
                                    ledger=self._ledger, evaluation_id=self.evaluation_id, **scopes)
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
                # Closing a second SQLite descriptor can unlock an active writer.
                # All subsequent inspection happens after ExitStack closed ours.
                self._ledger = None
                report = _inspect_planning_evaluation(self.directory, check_reports=False)
                directory.write("report.json", report, MAX_AGGREGATE_BYTES)
                directory.write("report.md", _markdown(report), MAX_AGGREGATE_BYTES)
                return report
        finally:
            self._ledger = None
            timer.cancel()
            timer.join()


def _validate_manifest(value):
    fields = {"schema_version", "evaluation_id", "created_at", "evaluation", "limits", "trial_limits",
              "policy", "policy_digest", "plan", "reservation_per_trial", "batch_allowances", "mode",
              "live_calls_enabled", "planning_ledger"}
    if type(value) is not dict or set(value) != fields or not _uuid(value["evaluation_id"]):
        raise ValueError("invalid_planning_evaluation_manifest")
    _timestamp(value["created_at"])
    limits = EvaluationLimits(**value["limits"])
    policy = _validate_policy(parse_policy(value["policy"]))
    binding = value["planning_ledger"]
    if type(binding) is not dict:
        raise ValueError("invalid_planning_evaluation_manifest")
    expected = {**scope_ids(value["evaluation_id"]), "ledger_id": binding.get("ledger_id"),
                "directory": "planning-ledger", "mode": "simulation", "period": "lifetime",
                "limit_microusd": len(_plan(limits)) * TRIAL_BUDGET}
    if (value["schema_version"] != "1" or value["evaluation"] != evaluation_identity()
            or _encode(value["trial_limits"]) != _encode(FIXED_LIMITS)
            or value["policy_digest"] != policy.digest or value["policy"] != policy.to_dict()
            or _encode(value["plan"]) != _encode(_plan(limits))
            or _encode(value["reservation_per_trial"]) != _encode(RESERVATION)
            or _encode(value["batch_allowances"]) != _encode(_totals(len(value["plan"])))
            or _encode(binding) != _encode(expected)
            or (value["mode"] == "execute" and not _uuid(binding["ledger_id"]))
            or (value["mode"] == "dry_run" and binding["ledger_id"] is not None)
            or value["mode"] not in {"execute", "dry_run"} or value["live_calls_enabled"] is not False):
        raise ValueError("invalid_planning_evaluation_manifest")
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
        _timestamp(event["timestamp"])
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



def _ledger_report(ledger, manifest, trials, issues):
    if manifest["mode"] == "dry_run":
        return None
    if ledger is None:
        issues.append("planning_ledger_unavailable")
        return None
    try:
        binding = manifest["planning_ledger"]
        report = ledger.report()
        if (ledger.mode != "simulation" or ledger.period != "lifetime"
                or ledger.ledger_id != binding["ledger_id"]
                or ledger.account_id != binding["account_scope_id"]
                or report["summary"]["limit_microusd"] != binding["limit_microusd"]):
            raise ValueError("planning_ledger_binding_mismatch")
        engagement = ledger.report(binding["engagement_scope_id"])
        if (engagement["summary"]["parent_id"] != ledger.account_id
                or engagement["summary"]["kind"] != "engagement"
                or engagement["summary"]["limit_microusd"] != binding["limit_microusd"]):
            raise ValueError("planning_ledger_binding_mismatch")
        # At most 60 trials / 180 attempts are possible in this closed profile.
        attempts = ledger.attempts(limit=1000)
        if len(attempts) > len(trials) * 3:
            raise ValueError("unexpected_planning_attempt")
        action_scopes = {row["grade"].get("action_scope_id") for row in trials}
        if any(row["scope_id"] not in action_scopes for row in attempts):
            raise ValueError("unexpected_planning_attempt")
        allowed_scopes = {binding["account_scope_id"], binding["engagement_scope_id"]}
        for row in trials:
            allowed_scopes.update(row["grade"].get(key) for key in
                                  ("session_scope_id", "agent_scope_id", "action_scope_id"))
        events = ledger.events(limit=1000)
        if (len(events) == 1000 or any(event["scope_id"] not in allowed_scopes for event in events)
                or report["last_event_sequence"] != len(events)):
            raise ValueError("unexpected_planning_ledger_event")
        # Per-trial grading verifies child scope and attempt journals. Bind the
        # two immutable ancestors here, including their original durable caps.
        if len(events) < 2:
            raise ValueError("planning_ledger_roots_missing")
        root_ids = {binding["account_scope_id"], binding["engagement_scope_id"]}
        for index, kind in enumerate(("account", "engagement")):
            event = events[index]
            payload = {"parent_id": None if index == 0 else binding["account_scope_id"],
                       "kind": kind, "limit_microusd": binding["limit_microusd"]}
            if index == 1:
                payload["scope_id"] = binding["engagement_scope_id"]
            _timestamp(event["timestamp"])
            if (set(event) != {"sequence", "event_id", "timestamp", "kind", "scope_id", "attempt_id", "payload"}
                    or type(event["sequence"]) is not int or event["sequence"] != index + 1
                    or not _uuid(event["event_id"]) or event["kind"] != "scope_created"
                    or event["scope_id"] != binding[kind + "_scope_id"] or event["attempt_id"] is not None
                    or _encode(event["payload"]) != _encode(payload)):
                raise ValueError("planning_ledger_root_mismatch")
        if any(event["scope_id"] in root_ids for event in events[2:]):
            raise ValueError("unexpected_planning_ledger_root_event")
        if any(event["kind"] not in {"scope_created", "cost_estimated", "cost_reserved", "dispatch_started",
                                     "cost_settled", "cost_uncertain", "reservation_released", "reservation_denied",
                                     "dispatch_denied"} for event in events):
            raise ValueError("unexpected_planning_ledger_event")
        return report
    except (OSError, CostError, ValueError, TypeError, KeyError):
        issues.append("planning_ledger_invalid")
        return None


def _aggregate(manifest, trials, starts, finishes, terminal, issues, cost):
    # The baseline aggregates outcome/semantic agreement; this profile supplies
    # its own strict trial grades, money totals, identity and trust limitations.
    for key in ("session_scope_id", "agent_scope_id", "action_scope_id"):
        values = [row["grade"].get(key) for row in trials if row["grade"].get(key) is not None]
        if len(values) != len(set(values)):
            issues.append("reused_" + key)
    result = _baseline_aggregate(manifest, trials, starts, finishes, terminal, issues)
    result["reservations"] = _totals(len(starts))
    for key in PLANNING_METRICS:
        values = [row["grade"].get("metrics", {}).get(key) for row in trials]
        result["aggregate_metrics"][key] = sum(values) if all(type(v) is int and v >= 0 for v in values) else None
    result.update(planning_cost=cost, actual_provider_calls=0, human_acceptance=False,
                  approval_mode="unattended_owned_policy")
    result["limitations"] = [
        "Synthetic owned cases only; matching the preserved oracle is not live-model or general vulnerability accuracy.",
        "Correct abstentions require valid evidence, TLS receipts, accounting, isolation and cleanup; infrastructure failures receive no credit.",
        "Token use and microUSD amounts come from fixed simulation fixtures; actual provider calls and spend are zero.",
        "The selected policy explicitly allows unattended owned actions; no human approval or operator acceptance is demonstrated.",
        "Cleanup and isolation receipts are trusted supervisor observations, supplemented by real Linux process tests.",
        "Local evidence hashes do not authenticate against a malicious host owner. Read-only inspection never restores execution authority.",
        "Batch cancellation stops later trials and cancels current authority; kernel stalls and durable storage may delay teardown.",
        "Elapsed time includes local TLS, namespace and accounting overhead; it is not live model latency.",
    ]
    return result


def _inspect_planning_evaluation(directory, *, check_reports=True):
    from .planning_evaluation_grading import grade_trial

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
        expected_names = {"manifest.json", "evaluation.jsonl", "report.json", "report.md",
                          *[row["trial_id"] for row in starts]}
        if manifest["mode"] == "execute":
            expected_names.add("planning-ledger")
        if set(os.listdir(fd)) - expected_names:
            issues.append("unexpected_evaluation_entry")
        with ExitStack() as resources:
            ledger = None
            if manifest["mode"] == "execute":
                try:
                    ledger = resources.enter_context(CostLedger(path / "planning-ledger", read_only=True))
                except CostError:
                    issues.append("planning_ledger_unavailable")
            trials = []
            for trial in starts:
                grade = grade_trial(path / trial["trial_id"], case=trial["case"],
                    policy_digest=manifest["policy_digest"], limits=manifest["trial_limits"],
                    ledger=ledger, evaluation_id=manifest["evaluation_id"], **scope_ids(manifest["evaluation_id"]))
                if trial["trial_id"] not in finishes:
                    issues.append("trial_completion_unknown")
                elif hashlib.sha256(_encode(grade)).hexdigest() != finishes[trial["trial_id"]]:
                    issues.append("saved_trial_grade_mismatch")
                trials.append({**trial, "grade": grade, "evidence": trial["trial_id"] + "/evidence"})
            cost = _ledger_report(ledger, manifest, trials, issues)
        report = _aggregate(manifest, trials, starts, finishes, terminal, issues, cost)
        if check_reports:
            try:
                # This aggregate is larger than the proposal JSON parser's
                # 32 KiB limit. Compare bounded canonical bytes with freshly
                # regraded evidence instead of parsing cached claims.
                saved = _read_private(fd, "report.json", MAX_AGGREGATE_BYTES)
                markdown = _read_private(fd, "report.md", MAX_AGGREGATE_BYTES)
                if saved != _encode(report) or markdown != _markdown(report):
                    issues.append("aggregate_report_mismatch")
            except (OSError, ValueError, RuntimeError, TypeError):
                issues.append("aggregate_report_unavailable")
            report = _aggregate(manifest, trials, starts, finishes, terminal, issues, cost)
        return report
    except (OSError, ValueError, RuntimeError, TypeError, KeyError):
        raise EvaluationUnavailable("evaluation_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def inspect_planning_evaluation(directory):
    """Independently regrade saved evidence, audit and costs without writes."""
    return _inspect_planning_evaluation(directory)


def _markdown(report):
    raw = _baseline_markdown(report).replace(b"# Repeated owned lab evaluation", b"# Offline owned TLS planning evaluation", 1)
    cost = report["planning_cost"]
    lines = ["", "## Simulation accounting", "",
             "Actual provider calls: 0. Human acceptance: pending. Approval: not required by the selected owned policy.", ""]
    if cost is not None:
        summary = cost["summary"]
        lines += [f"Batch cap: {summary['limit_microusd']} microUSD; simulated usage: {summary['actual_microusd']} microUSD; retained holds: {summary['reserved_microusd']} microUSD; unresolved attempts: {summary['unresolved_attempts']}.", ""]
    else:
        lines += ["No verified ledger summary is available (dry run or accounting failure).", ""]
    return raw + ("\n".join(lines) + "\n").encode("ascii")
