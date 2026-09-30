"""One offline HarborDesk comparison through the existing isolated authority.

This runtime never changes policy, supplies approval answers, retries a denied
proposal, or resumes a trial. The separate comparison measures the existing
stop-on-denial behavior with actual owned Linux tools and no model calls.
"""

from __future__ import annotations

from contextlib import ExitStack
import copy
import hashlib
from pathlib import Path
import time
from uuid import uuid4

from .approval_isolation import LinuxApprovalService
from .audit import AuditUnavailable
from .audit_isolation import LinuxAuditSink
from .control_plane import AuthoritySession
from .coordinator_isolation import LinuxOfflineCoordinator
from .evaluation import _Directory
from .evidence import EvidenceUnavailable
from .execution import ExecutionControl, ExecutionStopped
from .isolation import IsolationUnavailable
from .launcher_isolation import LinuxFixtureLauncher
from .nmap_evidence import NmapEvidenceStore
from .nmap_runtime import inspect_nmap_runtime
from .session_limits import SessionLimits
from .web_assessment_contract import LIMITS, encode
from .web_backend import AuthorizedWebLabBackend
from .web_lab import WebLab


class _DecisionTimingAudit:
    """Observe durable acknowledgements without changing audit or gate events.

The real sink, rather than this proxy, supplies the launcher's private witness.
An execution's second policy check is intentionally outside this interval.
"""

    def __init__(self, audit):
        self._audit = audit
        self._started = {}
        self._timings = []
        self._completed = set()

    @property
    def timings(self):
        return copy.deepcopy(self._timings)

    def emit(self, event):
        self._audit.emit(event)
        acknowledged = time.monotonic_ns()
        kind = event.get("event_type")
        if kind == "session_plan_received":
            step = event["step"]
            if type(step) is not int or not 1 <= step <= 3 or step in self._started:
                raise ValueError("comparison_timing_plan_order")
            self._started[step] = acknowledged
        elif kind == "policy_decision":
            step = event["session_step"]
            if step not in self._completed:
                if step not in self._started or len(self._timings) >= 3:
                    raise ValueError("comparison_timing_decision_order")
                self._timings.append({"step": step, "action_digest": event["action_digest"],
                    "duration_ns": max(0, acknowledged - self._started[step])})
                self._completed.add(step)


def _reaped(service):
    if service is None:
        return False
    supervisor = service._supervisor
    return supervisor is None or all(process.poll() is not None for process in supervisor.processes.values())


def _elapsed_ms(started):
    return min(10**9, max(0, int((time.monotonic() - started) * 1000)))


def run_trial(runner, path, case, arm):
    """Persist one new trial; final receipts are written only after teardown."""
    from .web_comparison_contract import ARMS, CASES, PROFILE, validate_policy
    from .web_comparison_provider import ComparisonProvider

    started = time.monotonic()
    policy = validate_policy(runner.policy)
    if type(case) is not str or case not in CASES or type(arm) is not str or arm not in ARMS:
        raise ValueError("invalid_web_comparison_trial")
    path = Path(path)
    limits = SessionLimits(**LIMITS)
    deadline = started + limits.max_runtime_seconds
    if runner._deadline is not None:
        deadline = min(deadline, runner._deadline)
    setup_control = ExecutionControl(deadline, cancelled=getattr(runner, "_cancelled", None))
    session_id = str(uuid4())
    lab = WebLab(case, session_id, limits, execute=True)
    backend = AuthorizedWebLabBackend(policy, session_id, limits, lab, execute=True)
    coordinator = LinuxOfflineCoordinator()
    audit = approvals = launcher = provider = closure = measured_audit = None
    summary = error = prefix_elapsed_ms = None
    services = {"audit_boundary_checks": None, "launcher_boundary_checks": None,
                "audit_gate": False, "approval_gate": False,
                "approval_mode": "unattended_owned_policy", "approval_worker_started": False}
    cleanup = dict.fromkeys(("audit_reaped", "launcher_reaped", "approval_unstarted", "launcher_closed"), False)

    def check():
        setup_control.check()
        stopped = runner._stopped()
        if stopped is not None:
            raise ExecutionStopped("session_timeout" if stopped == "deadline" else "session_cancelled")

    def on_step(step):
        nonlocal prefix_elapsed_ms
        if step["step"] == 2:
            prefix_elapsed_ms = _elapsed_ms(started)

    with _Directory(path) as directory:
        try:
            check()
            runtime = inspect_nmap_runtime(setup_control)
            runtime_sha256 = hashlib.sha256(encode(runtime)).hexdigest()
            backend._nmap_manifest = runtime
            check()
            with ExitStack() as stack:
                audit = stack.enter_context(LinuxAuditSink(path / "audit.jsonl", launch_witness=True))
                check()
                approvals = stack.enter_context(LinuxApprovalService(policy, session_id, launch_witness=True))
                check()
                launcher = stack.enter_context(LinuxFixtureLauncher(backend, audit=audit, approvals=approvals))
                services.update(audit_gate=launcher._witness_source is not None,
                                approval_gate=launcher._approval_source is not None)
                try:
                    check()
                    evidence = stack.enter_context(NmapEvidenceStore(
                        path / "evidence", session_id=session_id, policy=policy, case=case,
                        owned_lab=lab.identity, workflow_profile="web", runtime_sha256=runtime_sha256,
                        deadline=deadline))
                    provider = ComparisonProvider(case, evidence, arm, audit)
                    measured_audit = _DecisionTimingAudit(audit)
                    authority = AuthoritySession(policy, measured_audit, launcher, coordinator, limits,
                        session_id=session_id, provider=provider, evidence=evidence,
                        approvals=approvals, deadline=deadline)
                    runner._install(authority)
                    summary = authority.run(execute=True, on_step=on_step)
                    if summary["stop_reason"] not in {"coordinator_done", "proposal_denied"}:
                        error = (summary["stop_reason"] if summary["stop_reason"] in {
                            "session_cancelled", "session_timeout"} else "trial_incomplete")
                    services["launcher_boundary_checks"] = launcher.boundary_checks
                    closure = launcher.close()
                    evidence.record_lab_closed(closure)
                    evidence.finalize(summary)
                finally:
                    services["audit_boundary_checks"] = audit.boundary_checks
                    if services["launcher_boundary_checks"] is None:
                        services["launcher_boundary_checks"] = launcher.boundary_checks
                    services["approval_worker_started"] = approvals._supervisor is not None
                    if provider is not None:
                        provider.close()
        except ExecutionStopped as exc:
            error = exc.reason
        except EvidenceUnavailable:
            error = "evidence_unavailable"
        except AuditUnavailable:
            error = "audit_unavailable"
        except IsolationUnavailable:
            error = "isolation_unavailable"
        except (OSError, ValueError, RuntimeError, TypeError):
            error = "trial_component_failed"
        finally:
            if launcher is not None and closure is None:
                try:
                    closure = launcher.close()
                except (OSError, RuntimeError):
                    error = "cleanup_unconfirmed"
            # The host lab is metadata only; the confined launcher owns the
            # live namespace. Never fall back to starting or scanning here.
            lab.close()
            cleanup.update(audit_reaped=_reaped(audit), launcher_reaped=_reaped(launcher),
                approval_unstarted=approvals is not None and approvals._supervisor is None,
                launcher_closed=launcher is not None and launcher._closed and launcher._cleanup_verified)
            if not all(cleanup.values()) and error is None:
                error = "cleanup_unconfirmed"
            with runner._lock:
                runner._active = None
        directory.write("runtime.json", {
            "schema_version": "1", "profile": PROFILE, "case": case, "arm": arm,
            "session_id": session_id, "lab_identity": lab.identity,
            "backend": dict(launcher.snapshot) if launcher is not None else None,
            "lab_closure": closure, "coordinator_boundary_checks": coordinator.boundary_checks,
            "services": services, "cleanup": cleanup, "error": error,
            "elapsed_ms": _elapsed_ms(started), "prefix_elapsed_ms": prefix_elapsed_ms,
            "approval_wait_ms": 0, "actual_provider_calls": 0, "summary": summary,
            "trace": [] if provider is None else provider.trace,
            "decision_timings": [] if measured_audit is None else measured_audit.timings,
        }, 65536)
