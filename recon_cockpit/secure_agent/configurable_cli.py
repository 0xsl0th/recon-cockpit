"""Terminal adapter for the shared configurable owned-assessment service."""

import json
import signal
import sys

from . import configurable_contract as contract
from .configurable_service import ConfigurableAssessmentRequest, ConfigurableAssessmentService
from .execution import ExecutionStopped
from .session_limits import SessionLimits


def run_assessment(args):
    from .cli import _print, _read_bounded

    overrides = {key: value for key, value in zip(contract.LIMITS,
        (args.session_max_steps, args.session_max_seconds, args.session_max_output_bytes)) if value is not None}
    request = ConfigurableAssessmentRequest(
        scope_json=_read_bounded(args.configurable_assessment),
        policy_json=_read_bounded(args.policy),
        assessment_dir=args.assessment_dir, audit_path=args.audit,
        execute=args.execute, limits=SessionLimits(**{**contract.LIMITS, **overrides}))
    service = ConfigurableAssessmentService(request)
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, lambda *_: service.cancel())
        result = service.run(
            interactive_terminal=sys.stdin.isatty() and sys.stdout.isatty(),
            on_step=lambda step: print(json.dumps({
                "event_type": "session_step_finished", "session_id": service.snapshot()["session_id"], **step},
                sort_keys=True, ensure_ascii=True), file=sys.stderr, flush=True))
    except ExecutionStopped as exc:
        _print({"decision": "deny", "execution_status": "blocked", "reasons": [exc.reason],
                "live_calls_enabled": False})
        return 2
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    _print(result)
    return 0 if result["assessment_outcome"] in ("completed", "dry_run") else 2
