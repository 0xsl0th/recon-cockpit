"""Explicit one-action diagnostic through existing witnessed authority services."""

from pathlib import Path
import threading
import time
from uuid import uuid4

from . import stock_http_contract as contract
from .audit_isolation import LinuxAuditSink
from .approval_isolation import LinuxApprovalService
from .controller import Controller
from .execution import ExecutionControl
from .launcher_isolation import LinuxFixtureLauncher
from .session_limits import SessionLimits
from .stock_http_backend import AuthorizedStockHttpBackend
from .stock_http_client_runtime import inspect_client_runtime
from .stock_http_evidence import StockHttpEvidenceStore
from .stock_http_lab import StockHttpLab
from .stock_http_runtime import inspect_runtime


def run_trial(directory, *, configuration, case, execute=False, unattended_owned_lab_test=False, cancelled=None):
    """No arbitrary endpoint, command, credential or network attachment input.

    Default policy requires approval and unattended execution is blocked. The
    explicit test policy exercises the already-authorized disconnected corpus;
    it neither manufactures a human approval nor weakens launcher witnesses.
    """
    if type(execute) is not bool or type(unattended_owned_lab_test) is not bool:
        raise ValueError("invalid_stock_diagnostic_mode")
    if cancelled is not None and not isinstance(cancelled, threading.Event):
        raise ValueError("invalid_stock_diagnostic_cancellation")
    selected = contract.selection(configuration, case)
    preflight = ExecutionControl(time.monotonic() + 60, cancelled=cancelled)
    runtime = {"daemon": inspect_runtime(configuration, case, preflight),
               "client": inspect_client_runtime(selected, preflight)}
    session_id = str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=not unattended_owned_lab_test)
    lab = StockHttpLab(selected, session_id, limits, execute=execute, runtime=runtime)
    original = AuthorizedStockHttpBackend(policy, session_id, limits, lab, execute=execute)
    manifest = {"schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
        "selection": selected, "policy": policy.to_dict(), "limits": contract.limits(selected),
        "runtime": runtime, "identity": lab.identity}
    started = time.monotonic()
    control = ExecutionControl(started + limits.max_runtime_seconds, cancelled=cancelled)
    with StockHttpEvidenceStore(directory, manifest, deadline=control.deadline) as evidence:
        with LinuxAuditSink(Path(directory) / "audit.jsonl", launch_witness=True) as audit:
            with LinuxApprovalService(policy, session_id, launch_witness=True) as approvals:
                with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as backend:
                    controller = Controller(policy, audit, backend, approvals, session_id=session_id, evidence=evidence)
                    outcome = controller.submit(contract.action(selected), execute=execute,
                        execution_control=control, session_step=1)
        return evidence.finalize(outcome, elapsed_ms=round((time.monotonic() - started) * 1000))
