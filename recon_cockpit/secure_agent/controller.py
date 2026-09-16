"""The single proposal-to-execution control path, independent of the provider."""

from __future__ import annotations

import threading
from typing import Protocol
from uuid import UUID

from .approvals import ApprovalStore
from .audit import AuditSink, AuditUnavailable
from .evidence import EvidenceUnavailable
from .execution import ExecutionControl, ExecutionStopped
from .models import Action, Policy, ValidationError, parse_action, parse_policy


class IsolationUnavailable(RuntimeError):
    code = "isolation_unavailable"


class Backend(Protocol):
    name: str

    def check_available(self, action: Action | None = None) -> None: ...

    def run(self, action: Action, policy: Policy, *, control: ExecutionControl | None = None) -> dict: ...


class UnavailableBackend:
    name = "unavailable"

    def check_available(self, action=None):
        raise IsolationUnavailable("No isolated execution backend selected")

    def run(self, action, policy):
        self.check_available(action)


def result_metadata(result: dict) -> dict:
    """Allowlist bounded numbers/booleans only; tool output is not audit text."""
    metadata = {}
    for key in ("bytes_received", "truncated", "http_status", "duration_ms"):
        value = result.get(key)
        if type(value) is bool or type(value) is int and 0 <= value <= 10**9:
            metadata[key] = value
    rows = result.get("results")
    if isinstance(rows, list):
        metadata["results"] = [result_metadata(row) for row in rows[:16]
                               if isinstance(row, dict)]
    return metadata


class Controller:
    def __init__(self, policy: Policy, audit: AuditSink, backend: Backend | None = None,
                 approvals: ApprovalStore | None = None, *, session_id: str | None = None,
                 evidence=None):
        self.policy = parse_policy(policy.to_dict())
        self.audit = audit
        self.backend = backend if backend is not None else UnavailableBackend()
        self.approvals = approvals if approvals is not None else ApprovalStore()
        # Optional trusted host sink; no proposal field can select or replace it.
        self.evidence = evidence
        self._lock = threading.Lock()
        self._audit_failed = False
        if session_id is not None:
            if type(session_id) is not str or str(UUID(session_id)) != session_id:
                raise ValueError("invalid_session_id")
        self.session_id = session_id

    def _emit(self, event: dict) -> None:
        if self._audit_failed:
            raise AuditUnavailable("audit_previously_failed")
        try:
            self.audit.emit(event)
        except AuditUnavailable:
            self._audit_failed = True
            raise

    def _evidence_call(self, operation, *args, **kwargs):
        if self._audit_failed:
            raise EvidenceUnavailable("evidence_previously_failed")
        try:
            result = getattr(self.evidence, operation)(*args, **kwargs)
            if operation == "start" and (type(result) is not str or str(UUID(result)) != result):
                raise ValueError("invalid_execution_id")
            return result
        except EvidenceUnavailable:
            self._audit_failed = True
            raise
        except (RuntimeError, OSError, ValueError, TypeError):
            self._audit_failed = True
            raise EvidenceUnavailable("evidence_unavailable") from None

    def submit(self, proposal: dict | str | bytes, *, execute: bool = False,
               approval_reference: str | None = None, interactive: bool = False,
               execution_control: ExecutionControl | None = None,
               session_step: int | None = None) -> dict:
        """Trusted controller API. IPC accepts proposal data only, never kwargs.

        `interactive` is set by the trusted TTY UI, not a proposal field. The UI
        owns the ApprovalStore. Dry-run still validates and audits the decision.
        """
        with self._lock:
            if session_step is not None and (self.session_id is None or type(session_step) is not int
                                             or not 1 <= session_step <= 16):
                raise ValueError("invalid_session_step")
            if execution_control is not None:
                execution_control.check()
            return self._submit(proposal, execute, approval_reference, interactive,
                                execution_control, session_step)

    def _submit(self, proposal, execute, approval_reference, interactive, control, session_step):
        base = {
            "action_id": None, "action_digest": None,
            "policy_version": self.policy.policy_version,
            "policy_digest": self.policy.digest,
            "approval_reference": None,
        }
        if self.session_id is not None:
            base.update(session_id=self.session_id, session_step=session_step)
        try:
            action = parse_action(proposal)
        except ValidationError as exc:
            outcome = {**base, "decision": "deny", "reasons": [exc.code],
                       "execution_status": "rejected"}
            self._emit({**outcome, "event_type": "validation_rejected"})
            return outcome
        base.update(action_id=action.action_id, action_digest=action.digest,
                    tool_id=action.tool_id, target=action.target)
        decision = self.policy.evaluate(action)
        outcome = {**base, "decision": decision.decision,
                   "reasons": list(decision.reasons), "execution_status": "not_started"}
        self._emit({**outcome, "event_type": "policy_decision",
                    "untrusted_agent_context": {"rationale": "[REDACTED]",
                                                "rationale_length": len(action.rationale)}})
        if decision.decision == "deny":
            outcome["execution_status"] = "blocked"
            return outcome
        if not execute:
            outcome["execution_status"] = "dry_run"
            return outcome
        if control is not None:
            control.check()
        if decision.decision == "approval_required":
            reason = ("noninteractive_approval_required" if not interactive else
                      self.approvals.consume(approval_reference, action, self.policy))
            if reason:
                outcome.update(execution_status="blocked", reasons=[reason])
                self._emit({**outcome, "event_type": "approval_rejected"})
                return outcome
            outcome["approval_reference"] = approval_reference
            self._emit({**outcome, "event_type": "approval_consumed"})
        try:
            self.backend.check_available(action)
        except RuntimeError:
            outcome.update(execution_status="blocked", reasons=["isolation_unavailable"])
            self._emit({**outcome, "event_type": "execution_blocked"})
            return outcome
        if self.evidence is not None:
            outcome["execution_id"] = self._evidence_call(
                "start", action, self.policy, session_id=self.session_id,
                session_step=session_step, backend=self.backend.name)
        # This synchronous, durable event is a hard precondition to tool launch.
        self._emit({**outcome, "event_type": "execution_started",
                    "execution_status": "started", "backend": self.backend.name})
        try:
            # A durable write or availability check may have used the remaining
            # session time. Never launch after that deadline/cancellation.
            if control is not None:
                control.check()
                result = self.backend.run(action, self.policy, control=control)
            else:
                result = self.backend.run(action, self.policy)
        except ExecutionStopped as exc:
            result = {"status": "cancelled" if exc.reason == "session_cancelled" else "timeout"}
            outcome["reasons"] = [exc.reason]
        except (RuntimeError, OSError, ValueError) as exc:
            if getattr(exc, "code", None) == "isolation_unavailable":
                result = {"status": "blocked"}
                outcome["reasons"] = ["isolation_unavailable"]
            else:
                result = {"status": "failed"}
        status = result.get("status", "failed")
        if status not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}:
            status = "failed"
        outcome["execution_status"] = status
        if self.evidence is not None:
            # Artifact/completion failures must escape, not become a fabricated
            # backend failure or a successful audit completion.
            self._evidence_call("finish", outcome["execution_id"], result, execution_status=status)
        self._emit({**outcome, "event_type": "execution_finished",
                    "backend": self.backend.name, "result_metadata": result_metadata(result)})
        # The caller receives bounded tool data separately from trusted decisions.
        # CLI emits only result_metadata; it never renders arbitrary tool strings.
        outcome["result_metadata"] = result_metadata(result)
        outcome["untrusted_result"] = result
        return outcome
