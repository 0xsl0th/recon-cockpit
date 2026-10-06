"""Operator entry point for four scoped actions in disconnected owned fixtures."""

import hashlib
import json
import signal
import sys
import time
from uuid import uuid4

from . import configurable_contract as contract
from .configurable_scope import load_scope


def run_assessment(args, policy, audit):
    from .cli import _approval_context, _admission_context, _isolated_human_approval, _print, _read_bounded
    from .control_plane import AuthoritySession
    from .coordinator_isolation import LinuxOfflineCoordinator
    from .configurable_backend import AuthorizedConfigurableBackend
    from .configurable_evidence import ConfigurableEvidenceStore
    from .configurable_lab import ConfigurableLab
    from .configurable_workflow import ConfigurableProvider
    from .configurable_runtime import inspect_configurable_runtime
    from .execution import ExecutionControl
    from .session_limits import SessionLimits

    scope = load_scope(_read_bounded(args.configurable_assessment))
    overrides = {key: value for key, value in zip(contract.LIMITS,
        (args.session_max_steps, args.session_max_seconds, args.session_max_output_bytes)) if value is not None}
    limits = SessionLimits(**{**contract.LIMITS, **overrides})
    session_id = str(uuid4())
    started = time.monotonic()
    deadline = started + limits.max_runtime_seconds
    manifests = inspect_configurable_runtime(ExecutionControl(deadline)) if args.execute else None
    bindings = None if manifests is None else {tool: hashlib.sha256(contract.encode(value)).hexdigest()
                                               for tool, value in manifests.items()}
    coordinator = LinuxOfflineCoordinator()
    lab = ConfigurableLab(scope, session_id, limits, execute=args.execute)
    original = AuthorizedConfigurableBackend(policy, session_id, limits, lab, execute=args.execute)
    original._configurable_manifests = manifests
    with (_approval_context(args, policy, session_id) as approvals,
          _admission_context(args, original, audit, approvals) as backend,
          ConfigurableEvidenceStore(args.assessment_dir, session_id=session_id, policy=policy,
              scope=scope, owned_lab=lab.identity, runtime_bindings=bindings, deadline=deadline) as evidence):
        provider = ConfigurableProvider(scope, evidence)
        runner = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
            provider=provider, evidence=evidence, approvals=approvals, deadline=deadline)
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        try:
            for number in previous:
                signal.signal(number, lambda *_: runner.cancel())
            summary = runner.run(execute=args.execute, interactive=sys.stdin.isatty() and sys.stdout.isatty(),
                approval=_isolated_human_approval, on_step=lambda step: print(json.dumps({
                    "event_type": "session_step_finished", "session_id": session_id, **step},
                    sort_keys=True, ensure_ascii=True), file=sys.stderr, flush=True))
            evidence.record_lab_closed(backend.close())
            report = evidence.finalize(summary, elapsed_ms=round((time.monotonic() - started) * 1000))
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    _print({**summary, "provider": provider.name, "scope_sha256": report["scope_sha256"],
        "assessment_outcome": report["outcome"], "assessment_id": report["assessment_id"],
        "report_paths": {"json": str(args.assessment_dir / "report.json"), "markdown": str(args.assessment_dir / "report.md")},
        "capability": contract.capability_descriptor(scope), "live_calls_enabled": False,
        "metrics": report["metrics"], "coordinator_boundary_checks": coordinator.boundary_checks})
    return 0 if report["outcome"] in ("completed", "dry_run") else 2
