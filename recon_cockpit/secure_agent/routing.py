"""Explicit independent selections through the witnessed disconnected launcher."""

from pathlib import Path
import threading
import time
from uuid import uuid4

from . import routing_contract as contract
from .audit_isolation import LinuxAuditSink
from .approval_isolation import LinuxApprovalService
from .controller import Controller
from .execution import ExecutionControl
from .launcher_isolation import LinuxFixtureLauncher
from .session_limits import SessionLimits
from .routing_backend import AuthorizedRoutingBackend
from .routing_evidence import RoutingEvidenceStore
from .routing_lab import RoutingLab


def run_trial(directory, *, selectors, budget_case="ordinary", deployment=None, execute=False,
              unattended_owned_lab_test=False, cancelled=None):
    if type(execute) is not bool or type(unattended_owned_lab_test) is not bool:
        raise ValueError("invalid_routing_mode")
    if cancelled is not None and not isinstance(cancelled, threading.Event):
        raise ValueError("invalid_routing_cancellation")
    if (type(selectors) is not list or not 1 <= len(selectors) <= 4
            or any(type(value) is not str or value not in contract.SELECTORS for value in selectors)
            or len(set(selectors)) != len(selectors)):
        raise ValueError("invalid_routing_selectors")
    selected = contract.selection(budget_case, deployment=deployment)
    trial_started = time.monotonic()
    preflight = ExecutionControl(trial_started + 60, cancelled=cancelled)
    runtime = contract.inspect_runtime(selected, preflight)
    session_id = str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=not unattended_owned_lab_test)
    lab = RoutingLab(selected, session_id, limits, execute=execute, runtime=runtime)
    original = AuthorizedRoutingBackend(policy, session_id, limits, lab, execute=execute)
    manifest = {"schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
        "selection": selected, "selectors": list(selectors), "policy": policy.to_dict(),
        "limits": contract.limits(selected), "runtime": runtime, "identity": lab.identity}
    control = ExecutionControl(time.monotonic() + limits.max_runtime_seconds, cancelled=cancelled)
    outcomes = []
    with RoutingEvidenceStore(directory, manifest, deadline=control.deadline) as evidence:
        with LinuxAuditSink(Path(directory) / "audit.jsonl", launch_witness=True) as audit:
            with LinuxApprovalService(policy, session_id, launch_witness=True) as approvals:
                with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as backend:
                    controller = Controller(policy, audit, backend, approvals, session_id=session_id, evidence=evidence)
                    for step, selector in enumerate(selectors, 1):
                        control.check()
                        outcome = controller.submit(contract.action(selected, selector), execute=execute,
                            execution_control=control, session_step=step)
                        outcomes.append(outcome)
                        result = outcome.get("untrusted_result") or {}
                        if (outcome.get("execution_status") not in {"succeeded", "not_started"}
                                or result.get("routing_ledger", {}).get("terminal")):
                            break
                closure = backend.close()
        return evidence.finalize(outcomes, closure=closure,
                                 elapsed_ms=round((time.monotonic() - trial_started) * 1000))
