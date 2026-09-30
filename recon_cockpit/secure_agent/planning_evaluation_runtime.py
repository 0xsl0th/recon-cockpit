"""One owned planning evaluation trial through the completed isolated services.

The scheduler owns the shared simulation account and absolute batch deadline.
This module starts fresh trial scopes and authority; it never resumes execution,
rewrites approval policy, reads real credentials or supplies terminal answers.
"""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import time
from uuid import uuid4

from .assessment_planning_tls import OwnedTLSAssessmentPlanningProvider
from .audit import AuditUnavailable
from .audit_isolation import LinuxAuditSink
from .approval_isolation import LinuxApprovalService
from .control_plane import AuthoritySession
from .coordinator_isolation import LinuxOfflineCoordinator
from .cost_ledger import CostLedger
from .evaluation import _Directory, _validate_policy
from .evaluation_contract import FIXED_LIMITS
from .evidence import EvidenceStore, EvidenceUnavailable, _read_private
from .isolation import IsolationUnavailable
from .launcher_isolation import LinuxFixtureLauncher
from .models import load_json
from .owned_lab import OwnedLab, AuthorizedOwnedLabBackend
from .session import SessionLimits


def _reaped(service):
    if service is None:
        return False
    supervisor = service._supervisor
    return supervisor is None or all(process.poll() is not None for process in supervisor.processes.values())


def _cost_snapshot(ledger, scope_id):
    """Only immutable trial-local totals; later siblings cannot change a grade."""
    report = ledger.report(scope_id)
    summary = {key: value for key, value in report["summary"].items()
               if key not in {"effective_available_microusd", "limiting_scope_id"}}
    return {"summary": summary, "by_model": report["by_model"],
            "attempts": [row for row in ledger.attempts(limit=1000) if row["scope_id"] == scope_id]}


def _transport_receipts(directory):
    raw = _read_private(directory.fd, "audit.jsonl", 262144)
    if not raw.endswith(b"\n"):
        raise ValueError("planning_evaluation_audit_incomplete")
    receipts = []
    for line in raw.splitlines():
        event = load_json(line)
        if event.get("event_type") == "assessment_planning_tls_finished":
            receipts.append({key: event[key] for key in (
                "broker_sequence", "request_digest", "context_digest", "exchange_status", "receipt")})
    return receipts


def run_trial(runner, path, case, *, ledger, account_scope_id, engagement_scope_id):
    """Write one fresh trial; all live services close before runtime evidence."""
    from .planning_evaluation_contract import PROFILE, TRIAL_BUDGET

    path = Path(path)
    policy = _validate_policy(runner.policy)
    if (type(ledger) is not CostLedger or ledger.mode != "simulation"
            or ledger.account_id != account_scope_id):
        raise ValueError("planning_evaluation_ledger_mismatch")
    engagement = ledger.snapshot(engagement_scope_id)
    if engagement["kind"] != "engagement" or engagement["parent_id"] != account_scope_id:
        raise ValueError("planning_evaluation_ledger_mismatch")
    started = time.monotonic()
    limits = SessionLimits(**FIXED_LIMITS)
    session_id = str(uuid4())
    lab = OwnedLab(case, session_id, limits, execute=True)
    backend = AuthorizedOwnedLabBackend(policy, session_id, limits, lab, execute=True)
    coordinator = LinuxOfflineCoordinator()
    audit = approvals = launcher = provider = closure = None
    error = None
    scopes = {kind: "planning-" + kind + "-" + session_id for kind in ("session", "agent", "action")}
    services = {"audit_boundary_checks": None, "launcher_boundary_checks": None,
                "audit_gate": False, "approval_gate": False,
                "approval_mode": "unattended_owned_policy", "approval_worker_started": False}
    cleanup = dict.fromkeys(("audit_reaped", "launcher_reaped", "approval_unstarted", "launcher_closed"), False)
    cost = None
    receipts = []
    with _Directory(path) as directory:
        try:
            parent = engagement_scope_id
            for kind, scope_id in scopes.items():
                ledger.add_scope(scope_id, parent_id=parent, kind=kind, limit_microusd=TRIAL_BUDGET)
                parent = scope_id
            if runner._stopped() is not None:
                raise RuntimeError("planning_evaluation_stopped")
            with ExitStack() as stack:
                audit = stack.enter_context(LinuxAuditSink(path / "audit.jsonl", launch_witness=True))
                approvals = stack.enter_context(LinuxApprovalService(policy, session_id, launch_witness=True))
                launcher = stack.enter_context(LinuxFixtureLauncher(backend, audit=audit, approvals=approvals))
                services.update(audit_gate=launcher._witness_source is not None,
                                approval_gate=launcher._approval_source is not None)
                try:
                    evidence = stack.enter_context(EvidenceStore(path / "evidence", session_id=session_id,
                        policy=policy, case=case, discovery=True, workflow=True, owned_lab=lab.identity))
                    provider = OwnedTLSAssessmentPlanningProvider(case, audit, evidence, ledger,
                                                                  scope_id=scopes["action"])
                    authority = AuthoritySession(policy, audit, launcher, coordinator, limits,
                        session_id=session_id, provider=provider, evidence=evidence,
                        approvals=approvals, deadline=runner._deadline)
                    runner._install(authority)
                    summary = authority.run(execute=True)
                    services["launcher_boundary_checks"] = launcher.boundary_checks
                    closure = launcher.close()
                    evidence.record_lab_closed(closure)
                    evidence.finalize(summary)
                finally:
                    services["audit_boundary_checks"] = audit.boundary_checks
                    if services["launcher_boundary_checks"] is None:
                        services["launcher_boundary_checks"] = launcher.boundary_checks
                    services["approval_worker_started"] = approvals._supervisor is not None
        except EvidenceUnavailable:
            error = "evidence_unavailable"
        except AuditUnavailable:
            error = "audit_unavailable"
        except IsolationUnavailable:
            error = "isolation_unavailable"
        except (OSError, ValueError, RuntimeError, TypeError):
            error = "trial_component_failed"
        finally:
            # No second ledger connection is opened while the scheduler owns
            # its writer. Cleanup observations refer to these host handles;
            # nested owner lifetimes are separately observed by Linux tests.
            cleanup.update(audit_reaped=_reaped(audit), launcher_reaped=_reaped(launcher),
                approval_unstarted=approvals is not None and approvals._supervisor is None,
                launcher_closed=launcher is not None and launcher._closed and launcher._cleanup_verified)
            if not all(cleanup.values()) and error is None:
                error = "cleanup_unconfirmed"
            if launcher is not None and closure is None:
                try:
                    closure = launcher.close()
                except (OSError, RuntimeError):
                    error = "cleanup_unconfirmed"
            with runner._lock:
                runner._active = None
        try:
            cost = _cost_snapshot(ledger, scopes["action"])
        except (OSError, ValueError, RuntimeError, TypeError):
            error = error or "planning_accounting_unavailable"
        try:
            receipts = _transport_receipts(directory)
        except (OSError, ValueError, RuntimeError, TypeError, KeyError):
            error = error or "audit_unavailable"
        broker = None if provider is None else provider.broker
        control = None if broker is None else broker._control
        directory.write("runtime.json", {
            "schema_version": "1", "profile": PROFILE, "case": case, "session_id": session_id,
            "lab_identity": lab.identity, "backend": dict(launcher.snapshot) if launcher is not None else None,
            "broker_id": broker.broker_id if broker is not None else None,
            "broker": dict(broker.snapshot) if broker is not None else None,
            "coordinator_boundary_checks": coordinator.boundary_checks,
            "parser_boundary_checks": provider.boundary_checks if provider is not None else None,
            "lab_closure": closure, "cleanup": cleanup, "services": services, "error": error,
            "elapsed_ms": min(10**9, max(0, int((time.monotonic() - started) * 1000))),
            "planning": {"ledger_id": ledger.ledger_id, "account_scope_id": account_scope_id,
                "engagement_scope_id": engagement_scope_id, "session_scope_id": scopes["session"],
                "agent_scope_id": scopes["agent"], "action_scope_id": scopes["action"],
                "provider": provider.name if provider is not None else None,
                "broker_config_digest": broker.config_digest if broker is not None else None,
                "control_deadline": control.deadline if control is not None else None,
                "mode": "simulation", "actual_provider_calls": 0, "cost": cost,
                "transport_receipts": receipts},
        }, 65536)
