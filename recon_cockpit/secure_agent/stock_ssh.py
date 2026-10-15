"""One stock SSH operation through independently witnessed authority."""

from pathlib import Path
import threading
import time
from uuid import uuid4

from . import stock_ssh_contract as contract
from .audit_isolation import LinuxAuditSink
from .approval_isolation import LinuxApprovalService
from .controller import Controller
from .execution import ExecutionControl
from .launcher_isolation import LinuxFixtureLauncher
from .session_limits import SessionLimits
from .stock_ssh_backend import AuthorizedStockSshBackend
from .stock_ssh_client_runtime import inspect_client_runtime
from .stock_ssh_evidence import StockSshEvidenceStore
from .stock_ssh_lab import StockSshLab
from .stock_ssh_runtime import inspect_runtime


def run_trial(directory, *, configuration, case, execute=False, unattended_owned_lab_test=False, cancelled=None):
    """No arbitrary endpoint, command, credential or network attachment input.

    Default policy requires approval and unattended execution is blocked. The
    explicit test policy exercises the already-authorized disconnected corpus;
    it neither manufactures a human approval nor weakens launcher witnesses.
    """
    if type(execute) is not bool or type(unattended_owned_lab_test) is not bool:
        raise ValueError("invalid_stock_ssh_mode")
    if cancelled is not None and not isinstance(cancelled, threading.Event):
        raise ValueError("invalid_stock_ssh_cancellation")
    selected = contract.selection(configuration, case)
    trial_started = time.monotonic()
    preflight = ExecutionControl(trial_started + 60, cancelled=cancelled)
    preflight.check()
    runtime = {"daemon": inspect_runtime(configuration, case, preflight),
               "client": inspect_client_runtime(selected, preflight)}
    session_id = str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=not unattended_owned_lab_test)
    lab = StockSshLab(selected, session_id, limits, execute=execute, runtime=runtime)
    original = AuthorizedStockSshBackend(policy, session_id, limits, lab, execute=execute)
    manifest = {"schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
        "selection": selected, "policy": policy.to_dict(), "limits": contract.limits(selected),
        "runtime": runtime, "identity": lab.identity}
    # Read-only preflight contributes to wall time, not the execution session.
    session_started = time.monotonic()
    control = ExecutionControl(session_started + limits.max_runtime_seconds, cancelled=cancelled)
    with StockSshEvidenceStore(directory, manifest, deadline=control.deadline) as evidence:
        with LinuxAuditSink(Path(directory) / "audit.jsonl", launch_witness=True) as audit:
            with LinuxApprovalService(policy, session_id, launch_witness=True) as approvals:
                with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as backend:
                    controller = Controller(policy, audit, backend, approvals, session_id=session_id, evidence=evidence)
                    outcome = controller.submit(contract.action(selected), execute=execute,
                        execution_control=control, session_step=1)
        return evidence.finalize(outcome, elapsed_ms=round((time.monotonic() - trial_started) * 1000))
