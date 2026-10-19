"""Finite name-bound assessment through independent audit and approval gates."""

from pathlib import Path
import threading
import time
from uuid import uuid4

from . import name_tls_contract as contract, name_tls_native_runtime as native
from .audit_isolation import LinuxAuditSink
from .approval_isolation import LinuxApprovalService
from .controller import Controller
from .execution import ExecutionControl
from .launcher_isolation import LinuxFixtureLauncher
from .session_limits import SessionLimits
from .name_tls_backend import AuthorizedNameTLSBackend
from .name_tls_lab import NameTLSLab


def run_trial(directory, *, configuration="A", case="O4", order="default", execute=False,
              unattended_owned_lab_test=False, cancelled=None):
    if type(execute) is not bool or type(unattended_owned_lab_test) is not bool:
        raise ValueError("invalid_name_tls_mode")
    if cancelled is not None and not isinstance(cancelled, threading.Event):
        raise ValueError("invalid_name_tls_cancellation")
    selected = contract.selection(configuration, case, order)
    started = time.monotonic()
    inspection = ExecutionControl(started + 15, cancelled=cancelled)
    runtime = native.inspect_runtime(configuration, case, inspection)
    session_id = str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=not unattended_owned_lab_test)
    lab = NameTLSLab(selected, session_id, limits, execute=execute, runtime=runtime)
    original = AuthorizedNameTLSBackend(policy, session_id, limits, lab, execute=execute)
    slots = list(contract.operation_plan(selected))
    attempts = list(contract.attempt_slots(selected))
    manifest = {"schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
        "selection": selected, "slots": [*slots, *attempts], "policy": policy.to_dict(), "limits": contract.limits(selected),
        "runtime": runtime, "identity": lab.identity, "execute": execute,
        "unattended_owned_lab_test": unattended_owned_lab_test}
    control = ExecutionControl(min(started + 75, time.monotonic() + 60), cancelled=cancelled)
    outcomes, binding, probes = [], None, None
    from .name_tls_evidence import NameTLSEvidenceStore
    with NameTLSEvidenceStore(directory, manifest, deadline=min(started + 80, control.deadline + 5)) as evidence:
        with LinuxAuditSink(Path(directory) / "audit.jsonl", launch_witness=True) as audit:
            with LinuxApprovalService(policy, session_id, launch_witness=True) as approvals:
                with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as backend:
                    controller = Controller(policy, audit, backend, approvals, session_id=session_id, evidence=evidence)
                    for step, slot in enumerate(slots, 1):
                        control.check()
                        if contract.operation(slot) == "dns":
                            action = contract.dns_action(selected, lab.identity, slot)
                        else:
                            if binding is None:
                                break
                            action = contract.service_action(selected, lab.identity, slot, binding)
                        outcome = controller.submit(action, execute=execute, execution_control=control, session_step=step)
                        outcomes.append(outcome)
                        result = outcome.get("untrusted_result") or {}
                        ledger = result.get("name_tls_ledger", {})
                        binding = ledger.get("binding")
                        if (outcome.get("execution_status") not in {"succeeded", "not_started"}
                                or ledger.get("terminal")):
                            break
                    if execute and unattended_owned_lab_test and case in contract.PROBE_CASES:
                        from .name_tls_probes import run_probe_cases
                        probes = run_probe_cases(controller, backend, selected=selected, identity=lab.identity,
                            control=control, outcomes=outcomes, execute=execute)
                        if case == "N14":
                            outcomes.extend(attempt["outcome"] for attempt in probes["attempts"])
                closure = backend.close()
        return evidence.finalize(outcomes, closure=closure,
                                 elapsed_ms=round((time.monotonic() - started) * 1000), probes=probes)
