"""Read-only replay of the owned TLS planning evaluation profile.

Evidence, audit, transport receipts and the durable simulation ledger must agree.
These are trusted host records, not authenticated attestations or live-model
performance evidence. Failed or incomplete accounting never earns abstention
credit. Local trial costs exclude later-changing ancestor budget availability.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
import hashlib
import math
import os
from pathlib import Path
import re

from . import assessment_planning_contract as planning
from .assessment_planning_tls_contract import canonical_request
from .audit_protocol import CHECKS as AUDIT_CHECKS
from .cost_contract import TokenUsage, quote
from .cost_ledger import CostLedger
from .discovery_contract import discovery_action
from .evidence import (MAX_ARTIFACT_BYTES, MAX_REPORT_BYTES, OWNED_LAB_WORKFLOW,
                       _encode, _read_private, inspect_assessment)
from .evaluation_contract import FIXED_LIMITS, oracle
from .evaluation_grading import (_AUDIT_FIELDS as BASE_AUDIT_FIELDS, _ENVELOPE,
                                 _EXECUTOR, _ISOLATION, _assert, _checks,
                                 _directory, _trace, _uuid, METRICS as BASE_METRICS)
from .launcher_protocol import CHECKS as LAUNCHER_CHECKS
from .models import load_json
from .planning_evaluation_contract import PROFILE, TRIAL_BUDGET
from .provider_broker import _receipt
from .provider_contract import BOUNDARY_NAMES as TLS_CHECKS
from .session import SessionLimits


METRICS = BASE_METRICS + ("planning_actual_microusd", "planning_reserved_microusd",
    "planning_unresolved_attempts", "planning_input_tokens", "planning_output_tokens",
    "planning_cached_input_tokens", "actual_provider_calls", "owned_tls_exchanges")
_RUNTIME_FIELDS = {"schema_version", "profile", "case", "session_id", "lab_identity", "backend",
    "broker_id", "broker", "coordinator_boundary_checks", "parser_boundary_checks",
    "lab_closure", "cleanup", "error", "elapsed_ms", "services", "planning"}
_PLANNING_FIELDS = {"ledger_id", "account_scope_id", "engagement_scope_id", "session_scope_id",
    "agent_scope_id", "action_scope_id", "provider", "broker_config_digest", "control_deadline",
    "mode", "actual_provider_calls", "cost", "transport_receipts"}
_SERVICES_FIELDS = {"audit_boundary_checks", "launcher_boundary_checks", "audit_gate", "approval_gate",
    "approval_mode", "approval_worker_started"}
_PROVIDER = "owned-tls-assessment-planning-v1"
_PLAN_BASE = {"session_id", "broker_id", "config_digest", "provider"}
_TLS_BASE = {"broker_id", "config_digest", "broker_sequence", "request_digest", "calls_reserved",
             "output_tokens_reserved", "request_bytes_reserved", "context_digest"}
_AUDIT_FIELDS = {**BASE_AUDIT_FIELDS,
    "assessment_planning_session_bound": _PLAN_BASE | {"mode", "live_calls_enabled", "ledger_id", "scope_id"},
    "assessment_planning_reserved": _PLAN_BASE | {"step", "attempt_id", "request_digest", "mode"},
    "assessment_planning_dispatch_started": _PLAN_BASE | {"step", "attempt_id"},
    "assessment_planning_tls_reserved": _TLS_BASE,
    "assessment_planning_tls_finished": _TLS_BASE | {"exchange_status", "receipt"},
    "assessment_planning_settled": _PLAN_BASE | {"step", "attempt_id", "within_token_limits",
        "actual_microusd", "actual_source", "mode"},
    "assessment_planning_proposal_released": _PLAN_BASE | {"step", "action_digest", "workflow_digest"},
}
_BLOCK = ["session_step_started", "assessment_planning_reserved", "assessment_planning_dispatch_started",
    "assessment_planning_tls_reserved", "assessment_planning_tls_finished", "assessment_planning_settled",
    "assessment_planning_proposal_released", "session_plan_received", "policy_decision", "session_output_reserved",
    "policy_decision", "execution_started", "execution_finished", "session_step_finished"]


def _timestamp(value):
    _assert(type(value) is str and 20 <= len(value) <= 32, "invalid_timestamp")
    parsed = datetime.fromisoformat(value)
    _assert(parsed.utcoffset() == timedelta(0) and parsed.isoformat() == value, "invalid_timestamp")


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


def _scope_binding(ledger, runtime, *, evaluation_id, account_scope_id, engagement_scope_id):
    """Identify actual trial scopes even when execution stopped before grading."""
    context = runtime["planning"]
    session_id = runtime["session_id"]
    _assert(type(ledger) is CostLedger and ledger.mode == "simulation" and ledger.period == "lifetime"
            and _uuid(session_id) and _uuid(evaluation_id) and account_scope_id == "planning-evaluation-" + evaluation_id
            and engagement_scope_id == "planning-engagement-" + evaluation_id
            and ledger.account_id == account_scope_id and _uuid(ledger.ledger_id), "ledger_binding_mismatch")
    ids = {"ledger_id": ledger.ledger_id, "account_scope_id": account_scope_id,
           "engagement_scope_id": engagement_scope_id,
           **{kind + "_scope_id": "planning-" + kind + "-" + session_id for kind in ("session", "agent", "action")}}
    _assert(all(context[key] == expected for key, expected in ids.items()), "ledger_binding_mismatch")
    local = ledger.report(ids["action_scope_id"])
    chain = local["budget_chain"]
    _assert(len(chain) == 5, "ledger_scope_mismatch")
    parent = None
    for index, kind in enumerate(("account", "engagement", "session", "agent", "action")):
        scope = chain[index]
        _assert(scope["kind"] == kind and scope["scope_id"] == ids[kind + "_scope_id"]
                and scope["parent_id"] == parent and scope["ledger_id"] == ledger.ledger_id
                and scope["mode"] == "simulation" and scope["period"] == "lifetime"
                and type(scope["limit_microusd"]) is int, "ledger_scope_mismatch")
        if index < 2:
            _assert(TRIAL_BUDGET <= scope["limit_microusd"] <= 60 * TRIAL_BUDGET
                    and scope["limit_microusd"] % (6 * TRIAL_BUDGET) == 0
                    and scope["limit_microusd"] == chain[0]["limit_microusd"], "ledger_scope_limit_mismatch")
        else:
            _assert(scope["limit_microusd"] == TRIAL_BUDGET, "ledger_scope_limit_mismatch")
        parent = scope["scope_id"]
    return ids, local


def _cost(ledger, runtime, *, evaluation_id, account_scope_id, engagement_scope_id, requests):
    """Bind one immutable trial subtree to its actual attempts and journal."""
    context = runtime["planning"]
    ids, local = _scope_binding(ledger, runtime, evaluation_id=evaluation_id,
        account_scope_id=account_scope_id, engagement_scope_id=engagement_scope_id)
    chain = local["budget_chain"]

    all_attempts = ledger.attempts(limit=1000)
    _assert(len(all_attempts) <= 180, "ledger_attempt_limit")
    attempts = [row for row in all_attempts if row["scope_id"] == ids["action_scope_id"]]
    _assert(len(attempts) == len(requests), "ledger_attempt_count_mismatch")
    match = re.fullmatch(r"planning-([a-f0-9]{32})-1", attempts[0]["attempt_id"])
    _assert(match is not None, "ledger_attempt_identity_mismatch")
    run_id = match[1]
    expected_attempts = []
    expected_events = []
    for index, request in enumerate(requests, 1):
        attempt_id = f"planning-{run_id}-{index}"
        request_digest = hashlib.sha256(request).hexdigest()
        usage = TokenUsage(512, 128)
        quotation = quote(planning.PRICE, TokenUsage(len(request), planning.OUTPUT_LIMIT),
                          planning.INPUT_LIMIT, planning.OUTPUT_LIMIT)
        reference = "simulation-response-" + hashlib.sha256(
            f"resp_owned_{run_id}_{runtime['case']}_{index}".encode("ascii")).hexdigest()
        actual = planning.PRICE.cost(usage)
        expected_attempts.append({"attempt_id": attempt_id, "scope_id": ids["action_scope_id"],
            "request_digest": request_digest, "quote": quotation, "state": "settled", "reserved_microusd": 0,
            "actual_microusd": actual, "actual_source": "usage_derived", "usage": asdict(usage),
            "receipt_reference": reference, "reservation_overrun_microusd": 0})
        expected_events.extend((kind, attempt_id, payload) for kind, payload in (
            ("cost_estimated", {"request_digest": request_digest, **quotation}),
            ("cost_reserved", {"reserved_microusd": quotation["ceiling_microusd"]}),
            ("dispatch_started", {"request_digest": request_digest}),
            ("cost_settled", {"actual_microusd": actual, "source": "usage_derived",
                               "reference": reference, "usage": asdict(usage)})))
    _assert(_encode(attempts) == _encode(expected_attempts), "ledger_attempt_mismatch")
    events = ledger.events(limit=1000)
    _assert(len(events) < 1000, "ledger_event_limit")
    local_scopes = {ids[kind + "_scope_id"] for kind in ("session", "agent", "action")}
    events = [event for event in events if event["scope_id"] in local_scopes]
    _assert(len(events) == 3 + len(expected_events), "ledger_journal_mismatch")
    event_ids = set()
    previous_sequence = 0
    for event in events:
        _assert(set(event) == {"sequence", "event_id", "timestamp", "kind", "scope_id", "attempt_id", "payload"}
                and type(event["sequence"]) is int and event["sequence"] > previous_sequence
                and type(event["event_id"]) is str and event["event_id"] not in event_ids,
                "ledger_event_invalid")
        previous_sequence = event["sequence"]
        event_ids.add(event["event_id"])
        _timestamp(event["timestamp"])
    for event, scope in zip(events[:3], chain[2:]):
        expected = {key: scope[key] for key in ("scope_id", "parent_id", "kind", "limit_microusd")}
        _assert(event["kind"] == "scope_created" and event["scope_id"] == scope["scope_id"]
                and event["attempt_id"] is None and _uuid(event["event_id"])
                and _encode(event["payload"]) == _encode(expected), "ledger_scope_journal_mismatch")
    for event, (kind, attempt_id, payload) in zip(events[3:], expected_events):
        _assert(event["kind"] == kind and event["scope_id"] == ids["action_scope_id"]
                and event["attempt_id"] == attempt_id and _encode(event["payload"]) == _encode(payload)
                and (event["event_id"] == attempt_id + "-usage" if kind == "cost_settled"
                     else _uuid(event["event_id"])), "ledger_attempt_journal_mismatch")

    summary = {key: value for key, value in local["summary"].items()
               if key not in {"effective_available_microusd", "limiting_scope_id"}}
    cost = {"summary": summary, "by_model": local["by_model"], "attempts": attempts}
    _assert(_encode(context["cost"]) == _encode(cost), "runtime_cost_mismatch")
    count = len(attempts)
    _assert(summary["actual_complete"] is True and summary["attempt_count"] == count
            and summary["actual_microusd"] == summary["usage_derived_microusd"] == 778 * count
            and summary["reserved_microusd"] == summary["unresolved_attempts"] == 0,
            "ledger_summary_mismatch")
    return cost, run_id, {"planning_actual_microusd": count * 778, "planning_reserved_microusd": 0,
        "planning_unresolved_attempts": 0, "planning_input_tokens": count * 512,
        "planning_output_tokens": count * 128, "planning_cached_input_tokens": 0,
        "actual_provider_calls": 0, "owned_tls_exchanges": count}


def _audit(raw, report, runtime, policy_digest, limits, requests, run_id):
    """One closed success trace; no refunds, retries, grants or extra events."""
    _assert(raw.endswith(b"\n"), "audit_incomplete")
    events = [load_json(line) for line in raw.splitlines()]
    records = report["records"]
    types = ["session_started", "assessment_planning_session_bound"] + _BLOCK * len(records)
    if len(records) == 2:
        types += ["session_step_started", "session_plan_received"]
    types += ["session_finished"]
    _assert([event["event_type"] for event in events] == types, "audit_trace_mismatch")
    context = runtime["planning"]
    config_digest = _digest({"profile": planning.PROFILE, "model": planning.MODEL,
        "transport": "disconnected_owned_tls", "case": runtime["case"], "scenario": "success", "run_id": run_id,
        "max_calls": 3, "input_limit": planning.INPUT_LIMIT, "output_limit": planning.OUTPUT_LIMIT, "retries": 0})
    _assert(context["broker_config_digest"] == config_digest, "broker_configuration_mismatch")
    deadline = context["control_deadline"]
    _assert(type(deadline) in {int, float} and math.isfinite(deadline) and deadline > 0, "invalid_control_deadline")
    identities = {"session_id": report["session_id"], "policy_digest": policy_digest,
        "limits_digest": SessionLimits(**limits).digest, "broker_id": runtime["broker_id"],
        "config_digest": config_digest, "control_plane": "privsep-offline-v2", "provider": _PROVIDER}
    event_ids, policy_versions = set(), set()
    for event in events:
        fields = _AUDIT_FIELDS[event["event_type"]]
        _assert(set(event) == _ENVELOPE | fields and event["event_schema_version"] == "1"
                and event["source"] == "recon-cockpit.secure-agent" and _uuid(event["event_id"])
                and event["event_id"] not in event_ids, "audit_envelope_mismatch")
        event_ids.add(event["event_id"])
        _timestamp(event["timestamp"])
        _assert(all(event[key] == value for key, value in identities.items() if key in fields), "audit_identity_mismatch")
        if "policy_version" in fields:
            version = event["policy_version"]
            _assert(type(version) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", version),
                    "audit_policy_version_invalid")
            policy_versions.add(version)
    _assert(len(policy_versions) == 1, "audit_policy_version_mismatch")
    _assert(_encode(events[0]["limits"]) == _encode(limits) and events[0]["mode"] == "execute", "audit_session_mismatch")
    bound = events[1]
    _assert(bound["mode"] == "simulation" and bound["live_calls_enabled"] is False
            and bound["ledger_id"] == context["ledger_id"] and bound["scope_id"] == context["action_scope_id"],
            "audit_ledger_binding_mismatch")
    request_bytes, transport_receipts = 0, []
    for index, (record, request) in enumerate(zip(records, requests), 1):
        rows = events[2 + (index - 1) * len(_BLOCK):2 + index * len(_BLOCK)]
        for row in rows:
            for key in ("step", "session_step"):
                if key in row:
                    _assert(type(row[key]) is int and row[key] == index, "audit_step_mismatch")
        attempt_id = f"planning-{run_id}-{index}"
        request_digest = hashlib.sha256(request).hexdigest()
        for row in (rows[1], rows[2], rows[5]):
            _assert(row["attempt_id"] == attempt_id, "audit_attempt_mismatch")
        _assert(rows[1]["request_digest"] == request_digest and rows[1]["mode"] == "simulation", "audit_request_mismatch")
        request_bytes += len(request)
        counters = {"calls_reserved": index, "output_tokens_reserved": index * planning.OUTPUT_LIMIT,
                    "request_bytes_reserved": request_bytes}
        base = {"broker_sequence": index, "request_digest": request_digest, **counters}
        digest = _digest({"broker_id": runtime["broker_id"], "config_digest": config_digest,
                          "deadline": deadline, **base})
        for row in rows[3:5]:
            _assert(_encode({key: row[key] for key in base}) == _encode(base)
                    and row["context_digest"] == digest, "broker_accounting_mismatch")
        transport = _receipt(rows[4]["receipt"], digest)
        _assert(rows[4]["exchange_status"] == "succeeded" and transport["status"] == "ok"
                and _checks(transport["boundary_checks"], TLS_CHECKS)
                and _checks(transport["cleanup"], {"worker_reaped", "owner_reaped"}), "tls_boundary_unconfirmed")
        transport_receipts.append({key: rows[4][key] for key in (
            "broker_sequence", "request_digest", "context_digest", "exchange_status", "receipt")})
        _assert(_encode({key: rows[5][key] for key in (
            "within_token_limits", "actual_microusd", "actual_source", "mode")}) == _encode({
                "within_token_limits": True, "actual_microusd": 778, "actual_source": "usage_derived", "mode": "simulation"}),
                "audit_settlement_mismatch")
        _assert(rows[6]["action_digest"] == record["action_digest"]
                and rows[6]["workflow_digest"] == report["decision_trace"][index - 1]["workflow_digest"],
                "audit_planning_decision_mismatch")
        for row in rows[8:]:
            _assert(row["action_digest"] == record["action_digest"], "audit_action_mismatch")
            for key in ("action_id", "tool_id", "target"):
                if key in row:
                    _assert(row[key] == record["action"][key], "audit_action_mismatch")
            if "decision" in row:
                _assert(row["decision"] == "allow" and row["reasons"] == ["policy_allows_action"],
                        "audit_authorization_mismatch")
            if "approval_reference" in row:
                _assert(row["approval_reference"] is None, "audit_authorization_mismatch")
        for row in (rows[8], rows[10]):
            _assert(row["execution_status"] == "not_started"
                    and _encode(row["untrusted_agent_context"]) == _encode({
                        "rationale": "[REDACTED]", "rationale_length": len(discovery_action(runtime["case"], index)["rationale"])}),
                    "audit_policy_context_mismatch")
        _assert(_encode({key: rows[9][key] for key in ("action_output_allowance", "output_reserved_bytes")}) ==
                _encode({"action_output_allowance": 1024, "output_reserved_bytes": index * 1024}), "tool_accounting_mismatch")
        for event, status in ((rows[11], "started"), (rows[12], record["execution_status"])):
            _assert(event["execution_id"] == record["execution_id"] and event["execution_status"] == status
                    and event["backend"] == record["backend"], "audit_execution_mismatch")
        _assert(_encode(rows[12]["result_metadata"]) == _encode(record["result_metadata"])
                and _encode(rows[13]["result_metadata"]) == _encode(record["result_metadata"])
                and rows[13]["execution_id"] == record["execution_id"]
                and rows[13]["execution_status"] == record["execution_status"]
                and type(rows[13]["output_reserved_bytes"]) is int and rows[13]["output_reserved_bytes"] == index * 1024,
                "audit_result_mismatch")
    if len(records) == 2:
        _assert(all(type(event["step"]) is int and event["step"] == 3 for event in events[-3:-1]), "audit_stop_step_mismatch")
    last = events[-1]
    _assert(all(_encode(last[key]) == _encode(value) for key, value in report["execution"].items()
                if key != "blocked_reason"), "audit_summary_mismatch")
    _assert(type(last["duration_ms"]) is int and 0 <= last["duration_ms"] <= 10**9, "audit_duration_invalid")
    _assert(_encode(runtime["broker"]) == _encode({"calls_reserved": len(records),
        "output_tokens_reserved": len(records) * planning.OUTPUT_LIMIT, "request_bytes_reserved": request_bytes}),
        "broker_snapshot_mismatch")
    _assert(_encode(context["transport_receipts"]) == _encode(transport_receipts), "runtime_tls_receipts_mismatch")
    return {"broker_calls_reserved": len(records), "broker_output_tokens_reserved": len(records) * planning.OUTPUT_LIMIT,
            "broker_request_bytes_reserved": request_bytes, "session_duration_ms": last["duration_ms"]}


def grade_trial(directory, *, case, policy_digest, limits, ledger, evaluation_id,
                account_scope_id, engagement_scope_id):
    expected = oracle(case)
    value = {"schema_version": "1", "profile": PROFILE, "case": case, "verdict": "failed", "issues": [],
        "evaluation_id": evaluation_id, "assessment_id": None, "session_id": None, "lab_instance_id": None,
        "broker_id": None, "ledger_id": None, "session_scope_id": None, "agent_scope_id": None, "action_scope_id": None,
        "outcome": None, "classification": "failed", "metrics": dict.fromkeys(METRICS), "cost": None,
        "expected_outcome": expected["outcome"], "expected_terminal_reason": expected["terminal_reason"],
        "observed_terminal_reason": None, "checks": dict.fromkeys(("saved_evidence", "expected_trace", "cleanup",
            "isolation", "resource_accounting", "planning_accounting", "launch_preconditions"), False),
        "semantic_fingerprint": None}
    fd = evidence_fd = None
    stage = "trial_evidence_unavailable"
    try:
        _assert(_encode(limits) == _encode(FIXED_LIMITS) and type(policy_digest) is str
                and re.fullmatch(r"[0-9a-f]{64}", policy_digest) is not None, "invalid_grading_context")
        path = Path(directory)
        fd = _directory(path)
        runtime = load_json(_read_private(fd, "runtime.json", 65536))
        _assert(type(runtime) is dict and set(runtime) == _RUNTIME_FIELDS and runtime["schema_version"] == "1"
                and runtime["profile"] == PROFILE and runtime["case"] == case, "runtime_receipt_invalid")
        context = runtime["planning"]
        _assert(type(context) is dict and set(context) == _PLANNING_FIELDS, "planning_receipt_invalid")
        stage = "planning_accounting_failed"
        ids, _ = _scope_binding(ledger, runtime, evaluation_id=evaluation_id,
            account_scope_id=account_scope_id, engagement_scope_id=engagement_scope_id)
        value.update(session_id=runtime["session_id"], **{key: ids[key] for key in (
            "ledger_id", "session_scope_id", "agent_scope_id", "action_scope_id")})
        stage = "trial_evidence_unavailable"
        _assert(set(os.listdir(fd)) == {"runtime.json", "audit.jsonl", "evidence"}, "trial_files_incomplete")
        stage = "assessment_replay_failed"
        report = inspect_assessment(path / "evidence")
        _assert(not report["integrity_issues"] and report["workflow"] == OWNED_LAB_WORKFLOW
                and report["fixture_case"] == case and report["live_calls_enabled"] is False, "assessment_profile_mismatch")
        value.update({key: report[key] for key in ("assessment_id", "session_id", "outcome")})
        value["lab_instance_id"] = report["owned_lab"]["identity"]["instance_id"]
        value["observed_terminal_reason"] = report["terminal_decision"]["reason"]
        value["checks"]["saved_evidence"] = True
        stage = "expected_trace_failed"
        records = _trace(report, expected)
        _assert(all(record["policy_digest"] == policy_digest for record in records), "assessment_policy_mismatch")
        value["checks"]["expected_trace"] = True
        stage = "runtime_receipt_failed"
        _assert(runtime["error"] is None and runtime["session_id"] == report["session_id"]
                and _uuid(runtime["broker_id"]), "runtime_failed")
        value["broker_id"] = runtime["broker_id"]
        _assert(_encode(runtime["lab_identity"]) == _encode(report["owned_lab"]["identity"])
                and _encode(runtime["lab_closure"]) == _encode(report["owned_lab"]["closure"]), "runtime_lab_mismatch")
        _assert(_checks(runtime["cleanup"], {"audit_reaped", "launcher_reaped", "approval_unstarted", "launcher_closed"}),
                "cleanup_unconfirmed")
        value["checks"]["cleanup"] = True
        services = runtime["services"]
        _assert(type(services) is dict and set(services) == _SERVICES_FIELDS
                and _checks(services["audit_boundary_checks"], AUDIT_CHECKS)
                and _checks(services["launcher_boundary_checks"], LAUNCHER_CHECKS)
                and services["audit_gate"] is True and services["approval_gate"] is True
                and services["approval_mode"] == "unattended_owned_policy"
                and services["approval_worker_started"] is False, "launch_preconditions_unconfirmed")
        value["checks"]["launch_preconditions"] = True
        _assert(_checks(runtime["coordinator_boundary_checks"], _ISOLATION)
                and _checks(runtime["parser_boundary_checks"], _ISOLATION), "isolation_unconfirmed")
        _assert(_encode(runtime["backend"]) == _encode({"executions_reserved": len(records),
                "output_bytes_reserved": len(records) * 1024}), "backend_accounting_mismatch")
        _assert(type(runtime["elapsed_ms"]) is int and 0 <= runtime["elapsed_ms"] <= 10**9, "runtime_duration_invalid")
        context = runtime["planning"]
        _assert(type(context) is dict and set(context) == _PLANNING_FIELDS and context["provider"] == _PROVIDER
                and context["mode"] == "simulation" and type(context["actual_provider_calls"]) is int
                and context["actual_provider_calls"] == 0, "planning_profile_mismatch")
        evidence_fd = _directory(path / "evidence")
        _assert(_encode(load_json(_read_private(evidence_fd, "report.json", MAX_REPORT_BYTES))) == _encode(report),
                "saved_assessment_mismatch")
        for index, record in enumerate(records, 1):
            raw = _read_private(evidence_fd, record["artifact"]["filename"], MAX_ARTIFACT_BYTES)
            _assert(hashlib.sha256(raw).hexdigest() == record["artifact"]["sha256"], "artifact_changed")
            artifact = load_json(raw)
            _assert(_checks(artifact["boundary_checks"], _EXECUTOR), "executor_isolation_unconfirmed")
            _assert(artifact["status"] == record["execution_status"] and type(artifact["bytes_received"]) is int
                    and 0 <= artifact["bytes_received"] <= record["action"]["parameters"]["max_output_bytes"]
                    and type(artifact["truncated"]) is bool, "retained_response_accounting_invalid")
            _assert(_encode(artifact["owned_lab"]) == _encode({"identity": runtime["lab_identity"],
                    "connection_count": index, "request_count": index - 1}), "service_continuity_mismatch")
        value["checks"]["isolation"] = True
        requests = [canonical_request(case, index, owned_lab=True) for index in range(1, len(records) + 1)]
        stage = "planning_accounting_failed"
        cost, run_id, planning_metrics = _cost(ledger, runtime, evaluation_id=evaluation_id,
            account_scope_id=account_scope_id, engagement_scope_id=engagement_scope_id, requests=requests)
        value["checks"]["planning_accounting"] = True
        stage = "audit_accounting_failed"
        metrics = _audit(_read_private(fd, "audit.jsonl", 262144), report, runtime,
                         policy_digest, limits, requests, run_id)
        _assert(runtime["elapsed_ms"] >= metrics["session_duration_ms"], "elapsed_duration_mismatch")
        value["checks"]["resource_accounting"] = True
        metrics.update(planning_metrics, executions=len(records), steps_attempted=report["execution"]["steps_attempted"],
            actions_succeeded=expected["statuses"].count("succeeded"), unnecessary_actions=0,
            output_bytes_reserved=len(records) * 1024,
            retained_response_bytes=sum(row["result_metadata"]["bytes_received"] for row in records),
            elapsed_ms=runtime["elapsed_ms"])
        semantic = {"case": case, "outcome": report["outcome"], "statuses": expected["statuses"],
            "observations": [row["observation"] for row in records], "actions": [row["action"] for row in records],
            "terminal_reason": report["terminal_decision"]["reason"],
            "closure_counts": {key: runtime["lab_closure"][key] for key in ("connection_count", "request_count")}}
        value.update(verdict="passed", classification=expected["classification"], metrics=metrics,
                     cost=cost, semantic_fingerprint=_digest(semantic))
        value.update({key: context[key] for key in ("ledger_id", "session_scope_id", "agent_scope_id", "action_scope_id")})
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, IndexError, RecursionError):
        value["issues"] = [stage]
    finally:
        for opened in (evidence_fd, fd):
            if opened is not None:
                os.close(opened)
    return value
