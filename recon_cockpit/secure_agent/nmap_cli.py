"""Owned Nmap assessment orchestration; no host execution or live planner."""
import json
import hashlib
import time
import signal
import sys
from uuid import uuid4

from .nmap_contract import LIMITS, capability_descriptor


def run_assessment(args, policy, audit):
    from .cli import _approval_context, _admission_context, _isolated_human_approval, _print
    from .control_plane import AuthoritySession
    from .coordinator_isolation import LinuxOfflineCoordinator
    from .nmap_backend import AuthorizedNmapOwnedBackend
    from .nmap_evidence import NmapEvidenceStore
    from .nmap_workflow import NmapProvider
    from .owned_lab import OwnedLab
    from .session_limits import SessionLimits

    case = args.nmap_assessment
    lab_type, backend_type, provider_type = OwnedLab, AuthorizedNmapOwnedBackend, NmapProvider
    capability = capability_descriptor
    workflow_profile = 'nmap'
    if args.web_assessment:
        from .web_lab import WebLab
        from .web_backend import AuthorizedWebLabBackend
        from .web_workflow import WebProvider
        from .web_assessment_contract import capability_descriptor as capability
        case = args.web_assessment
        lab_type, backend_type, provider_type = WebLab, AuthorizedWebLabBackend, WebProvider
        workflow_profile = 'web'

    overrides = {key: value for key, value in zip(
        ('max_steps', 'max_runtime_seconds', 'max_output_bytes'),
        (args.session_max_steps, args.session_max_seconds, args.session_max_output_bytes)) if value is not None}
    limits = SessionLimits(**{**LIMITS, **overrides})
    session_id = str(uuid4())
    from .execution import ExecutionControl
    from .nmap_contract import encode
    deadline = time.monotonic() + limits.max_runtime_seconds
    runtime_manifest = None
    if args.execute:
        from .nmap_runtime import inspect_nmap_runtime
        runtime_manifest = inspect_nmap_runtime(ExecutionControl(deadline))
    runtime_sha256 = None if runtime_manifest is None else hashlib.sha256(encode(runtime_manifest)).hexdigest()
    coordinator = LinuxOfflineCoordinator()
    lab = lab_type(case, session_id, limits, execute=args.execute)
    original_backend = backend_type(policy, session_id, limits, lab, execute=args.execute)
    original_backend._nmap_manifest = runtime_manifest
    with (_approval_context(args, policy, session_id) as approvals,
          _admission_context(args, original_backend, audit, approvals) as backend,
          NmapEvidenceStore(args.assessment_dir, session_id=session_id, policy=policy,
                           case=case, owned_lab=lab.identity, workflow_profile=workflow_profile,
                           runtime_sha256=runtime_sha256, deadline=deadline) as evidence):
        provider = provider_type(case, evidence)
        runner = AuthoritySession(policy, audit, backend, coordinator, limits,
            session_id=session_id, provider=provider, evidence=evidence, approvals=approvals, deadline=deadline)
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        try:
            for number in previous:
                signal.signal(number, lambda *_: runner.cancel())
            summary = runner.run(execute=args.execute,
                interactive=sys.stdin.isatty() and sys.stdout.isatty(), approval=_isolated_human_approval,
                on_step=lambda step: print(json.dumps({'event_type': 'session_step_finished',
                    'session_id': session_id, **step}, sort_keys=True, ensure_ascii=True), file=sys.stderr, flush=True))
            evidence.record_lab_closed(backend.close())
            report = evidence.finalize(summary)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    _print({**summary, 'provider': provider.name, 'fixture_case': case,
        'assessment_outcome': report['outcome'], 'assessment_id': report['assessment_id'],
        'report_paths': {'json': str(args.assessment_dir / 'report.json'),
                         'markdown': str(args.assessment_dir / 'report.md')},
        'capability': capability(), 'live_calls_enabled': False,
        'actual_provider_calls': 0, 'workflow_card': report['workflow_card'],
        'coordinator_boundary_checks': coordinator.boundary_checks})
    return 0 if summary['session_status'] == 'completed' else 2
