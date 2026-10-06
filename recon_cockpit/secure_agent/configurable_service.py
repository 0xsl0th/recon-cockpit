"""Shared, process-local service for the reviewed configurable owned assessment.

This is trusted application code, not a network API or a Python plugin boundary.
Every run creates fresh authority and uses the existing isolated audit, approval,
admission and launcher path. Views contain data only; they cannot resume work or
restore approval. The selected isolated reviewer owns its own approval input.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import sys
import threading
import time
from uuid import uuid4

from . import configurable_contract as contract
from .configurable_scope import load_scope, scope_digest
from .execution import ExecutionControl, ExecutionStopped
from .models import parse_action, parse_policy
from .session_limits import SessionLimits


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigurableAssessmentRequest:
    """Validated immutable inputs; construction performs no filesystem I/O."""

    scope_json: bytes
    policy_json: bytes
    assessment_dir: Path
    audit_path: Path
    execute: bool = False
    limits: SessionLimits | None = None
    approval_frontend: str = "terminal"

    def __post_init__(self):
        if type(self.scope_json) is not bytes:
            raise ValueError("invalid_assessment_scope_bytes")
        if type(self.policy_json) is not bytes or len(self.policy_json) > 16384:
            raise ValueError("invalid_assessment_policy_bytes")
        if type(self.execute) is not bool:
            raise ValueError("invalid_assessment_mode")
        if (type(self.approval_frontend) is not str
                or self.approval_frontend not in {"terminal", "graphical_v1"}):
            raise ValueError("invalid_assessment_approval_frontend")
        if not isinstance(self.assessment_dir, Path) or not isinstance(self.audit_path, Path):
            raise ValueError("invalid_assessment_paths")
        limits = SessionLimits(**contract.LIMITS) if self.limits is None else self.limits
        if type(limits) is not SessionLimits:
            raise ValueError("invalid_assessment_limits")
        limits = SessionLimits(**asdict(limits))
        if any(asdict(limits)[name] > ceiling for name, ceiling in contract.LIMITS.items()):
            raise ValueError("assessment_limits_exceed_profile")
        scope = load_scope(self.scope_json)
        policy = parse_policy(self.policy_json)
        if self.approval_frontend == "graphical_v1" and (not self.execute or not policy.require_approval):
            raise ValueError("graphical_assessment_requires_execution_and_approval")
        object.__setattr__(self, "scope_json", contract.encode(scope))
        object.__setattr__(self, "policy_json", contract.encode(policy.to_dict()))
        object.__setattr__(self, "assessment_dir", Path(self.assessment_dir))
        object.__setattr__(self, "audit_path", Path(self.audit_path))
        object.__setattr__(self, "limits", limits)


class ConfigurableAssessmentService:
    """Single-use owned assessment with detached views and cooperative cancellation.

    Run may execute on a caller-owned worker thread. There are no signal handlers,
    background threads, injected services, restored state or configurable providers.
    Cancellation cannot interrupt host filesystem/kernel stalls; existing supervisors
    stop and reap their processes when control returns. Observer callbacks are trusted
    application code and receive detached public data, never approval authority. An
    observer exception cancels the run, closes services and leaves incomplete evidence
    without a finalized report; the original exception is propagated to its caller.
    """

    def __init__(self, request):
        if type(request) is not ConfigurableAssessmentRequest:
            raise ValueError("invalid_assessment_request")
        self._request = request
        self._scope = load_scope(request.scope_json)
        self._session_id = str(uuid4())
        self._cancelled = threading.Event()
        self._lock = threading.RLock()
        self._run_lock = threading.Lock()
        self._used = False
        self._runner = None
        self._state = "ready"
        self._stop_reason = None
        self._steps = []
        self._result = None

    def cancel(self):
        """Irreversibly request cancellation, including before authority exists."""
        self._cancelled.set()
        with self._lock:
            runner = self._runner
        if runner is not None:
            runner.cancel()

    def snapshot(self):
        """A bounded data projection, never a serialization of authority state."""
        with self._lock:
            return deepcopy({"state": self._state, "session_id": self._session_id,
                "scope": self._scope, "scope_sha256": scope_digest(self._scope),
                "steps": self._steps, "result": self._result,
                "stop_reason": self._stop_reason, "live_calls_enabled": False})

    def run(self, *, interactive_terminal=False, on_step=None):
        if type(interactive_terminal) is not bool:
            raise ValueError("invalid_assessment_interactivity")
        if on_step is not None and not callable(on_step):
            raise ValueError("invalid_assessment_observer")
        if interactive_terminal and self._request.approval_frontend == "graphical_v1":
            raise ValueError("assessment_approval_frontends_conflict")
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("assessment_already_running")
        try:
            with self._lock:
                if self._used:
                    raise RuntimeError("assessment_already_used")
                self._used = True
                self._state = "running"
            try:
                result = self._run(interactive_terminal, on_step)
            except ExecutionStopped as exc:
                with self._lock:
                    self._state, self._stop_reason = "stopped", exc.reason
                raise
            except BaseException:
                with self._lock:
                    self._state, self._stop_reason = "failed", "assessment_failed"
                raise
            else:
                with self._lock:
                    self._result = deepcopy(result)
                    self._state, self._stop_reason = "finished", result["stop_reason"]
                return deepcopy(result)
            finally:
                with self._lock:
                    self._runner = None
        finally:
            self._run_lock.release()

    def _run(self, interactive_terminal, on_step):
        from .audit_isolation import LinuxAuditSink
        from .approval_isolation import LinuxApprovalService
        from .launcher_isolation import LinuxFixtureLauncher
        from .control_plane import AuthoritySession
        from .coordinator_isolation import LinuxOfflineCoordinator
        from .configurable_backend import AuthorizedConfigurableBackend
        from .configurable_evidence import ConfigurableEvidenceStore
        from .configurable_lab import ConfigurableLab
        from .configurable_workflow import ConfigurableProvider
        from .configurable_runtime import inspect_configurable_runtime

        request = self._request
        graphical_review = request.approval_frontend == "graphical_v1"
        scope, policy = load_scope(request.scope_json), parse_policy(request.policy_json)
        started = time.monotonic()
        deadline = started + request.limits.max_runtime_seconds
        control = ExecutionControl(deadline, cancelled=self._cancelled)
        control.check()
        manifests = inspect_configurable_runtime(control) if request.execute else None
        control.check()
        bindings = None if manifests is None else {
            tool: hashlib.sha256(contract.encode(value)).hexdigest() for tool, value in manifests.items()}
        coordinator = LinuxOfflineCoordinator()
        lab = ConfigurableLab(scope, self._session_id, request.limits, execute=request.execute)
        original = AuthorizedConfigurableBackend(policy, self._session_id, request.limits, lab,
                                                execute=request.execute)
        original._configurable_manifests = manifests
        # These controls are mandatory for direct application callers as well as
        # CLI callers. No flags or alternate service implementations are exposed.
        with LinuxAuditSink(request.audit_path, launch_witness=True) as audit:
            control.check()
            approval_options = {"launch_witness": True}
            if graphical_review:
                approval_options["frontend"] = "graphical_v1"
            with LinuxApprovalService(policy, self._session_id, **approval_options) as approvals:
                control.check()
                with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as backend:
                    control.check()
                    with ConfigurableEvidenceStore(request.assessment_dir, session_id=self._session_id,
                            policy=policy, scope=scope, owned_lab=lab.identity,
                            runtime_bindings=bindings, deadline=deadline) as evidence:
                        provider = ConfigurableProvider(scope, evidence)
                        runner = AuthoritySession(policy, audit, backend, coordinator, request.limits,
                            session_id=self._session_id, provider=provider, evidence=evidence,
                            approvals=approvals, deadline=deadline)
                        with self._lock:
                            self._runner = runner
                            if self._cancelled.is_set():
                                runner.cancel()
                        observer_error = None

                        def record(step):
                            nonlocal observer_error
                            safe = deepcopy(step)
                            with self._lock:
                                if len(self._steps) >= contract.LIMITS["max_steps"]:
                                    raise ValueError("assessment_step_limit")
                                self._steps.append(safe)
                            if on_step is not None:
                                try:
                                    on_step(deepcopy(safe))
                                except BaseException as exc:
                                    observer_error = exc
                                    self.cancel()
                                    raise

                        def isolated_approval(controller, raw, *, control):
                            if not graphical_review and (not sys.stdin.isatty() or not sys.stdout.isatty()):
                                return None
                            proposed = parse_action(raw)
                            if not graphical_review:
                                return controller.approvals.review(proposed, controller.policy, control=control)
                            context = {"session_id": self._session_id, "action_id": proposed.action_id,
                                "action_digest": proposed.digest, "policy_digest": policy.digest,
                                "policy_version": policy.policy_version, "frontend": "graphical_v1"}
                            # Record intent before opening the reviewer. The audit
                            # stores bindings/outcome, never its phrase or grant.
                            audit.emit({**context, "event_type": "graphical_review_requested"})
                            try:
                                reference = controller.approvals.review(proposed, controller.policy, control=control)
                            except ExecutionStopped as exc:
                                audit.emit({**context, "event_type": "graphical_review_finished", "outcome": exc.reason})
                                raise
                            except Exception:
                                audit.emit({**context, "event_type": "graphical_review_finished", "outcome": "unavailable"})
                                raise
                            audit.emit({**context, "event_type": "graphical_review_finished",
                                        "outcome": "grant_issued" if reference is not None else "denied"})
                            return reference

                        summary = runner.run(execute=request.execute,
                            interactive=(graphical_review or (interactive_terminal and sys.stdin.isatty() and sys.stdout.isatty())),
                            approval=isolated_approval, on_step=record)
                        # AuthoritySession converts some callback exceptions into
                        # a stopped summary. A failed application observer must
                        # never become a normal, finalized service result.
                        if observer_error is not None:
                            raise observer_error
                        evidence.record_lab_closed(backend.close())
                        report = evidence.finalize(summary, elapsed_ms=round((time.monotonic() - started) * 1000))
        return {**summary, "provider": provider.name, "scope_sha256": report["scope_sha256"],
            "assessment_outcome": report["outcome"], "assessment_id": report["assessment_id"],
            "report_paths": {"json": str(request.assessment_dir / "report.json"),
                             "markdown": str(request.assessment_dir / "report.md")},
            "capability": contract.capability_descriptor(scope), "live_calls_enabled": False,
            "metrics": report["metrics"], "coordinator_boundary_checks": coordinator.boundary_checks}
