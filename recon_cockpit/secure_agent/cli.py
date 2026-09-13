"""Dedicated secure-agent entry point. No imports from the legacy host runner."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

from .audit import AuditSink, AuditUnavailable
from .controller import Controller
from .models import ValidationError, parse_action, parse_policy
from .providers import MockProvider


def _read_bounded(path: Path, limit: int = 16384) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input_too_large")
    return data


def _print(outcome: dict) -> None:
    # ASCII JSON escapes terminal controls. Raw responses and rationale are never
    # printed: their content has no role in the trusted decision or approval UI.
    print(json.dumps({key: value for key, value in outcome.items()
                      if key != "untrusted_result"}, sort_keys=True, ensure_ascii=True))


def _human_approval(controller: Controller, raw: bytes | str, *, control=None) -> str | None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return None
    action = parse_action(raw)
    review = action.to_dict()
    review.pop("rationale")
    print(json.dumps({"review_exact_action": review,
                      "action_digest": action.digest,
                      "policy_version": controller.policy.policy_version,
                      "policy_digest": controller.policy.digest},
                     sort_keys=True, ensure_ascii=True), file=sys.stderr)
    # Read from the controlling terminal, never the proposal input channel.
    challenge = "approve " + action.digest[:16]
    try:
        # A terminal is not seekable: buffered text update mode (r+) cannot
        # open it. Keep both directions on the controlling terminal with
        # separate streams, never falling back to proposal/stdin input.
        with (open("/dev/tty", "r", encoding="utf-8") as terminal_input,
              open("/dev/tty", "w", encoding="utf-8") as terminal_output):
            terminal_output.write(f"Type '{challenge}' to approve once (blank denies): ")
            terminal_output.flush()
            if control is None:
                answer = terminal_input.readline(128).strip()
            else:
                # Deadline/cancellation cover time spent waiting for the human.
                # Read only the controlling terminal, never provider/stdin data.
                received = bytearray()
                while len(received) < 128:
                    control.check()
                    ready, _, _ = select.select([terminal_input.fileno()], [], [], min(0.1, control.remaining()))
                    if not ready:
                        continue
                    byte = os.read(terminal_input.fileno(), 1)
                    if not byte or byte == b"\n":
                        break
                    received.extend(byte)
                control.check()
                answer = received.decode("utf-8", "replace").strip()
    except OSError:
        return None
    if answer != challenge:
        print("Approval not granted: expected the displayed challenge with its 16-character digest prefix; "
              "blank input denies.", file=sys.stderr)
        return None
    grant = controller.approvals.issue(action, controller.policy)
    return grant.reference


def main(argv: list[str] | None = None) -> int:
    from .session_provider import SCENARIOS
    from .openai_broker import BrokerError
    from .openai_fixtures import SCENARIOS as OPENAI_SCENARIOS

    parser = argparse.ArgumentParser(description="Secure Agent Mode: isolated actions and bounded mock sessions")
    parser.add_argument("--policy", type=Path, default=Path("examples/secure-agent-policy.json"))
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--mock", action="store_true", help="use the deterministic mock (default)")
    source.add_argument("--proposal", type=Path, help="read strictly bounded untrusted action JSON")
    source.add_argument("--session-mock", choices=SCENARIOS,
                        help="run a bounded deterministic fixture planning session (no real model)")
    source.add_argument("--isolated-session-mock", choices=SCENARIOS,
                        help="run the fixed session mock in a network-disabled Linux planner sandbox")
    source.add_argument("--openai-offline", choices=OPENAI_SCENARIOS,
                        help="run synthetic OpenAI responses through the isolated parser; no API calls")
    parser.add_argument("--openai-model", help="explicit model identifier for the offline request contract")
    parser.add_argument("--openai-max-output-tokens", type=int,
                        help="output token allowance per simulated request: 16–4096 (default: 1024)")
    parser.add_argument("--broker-max-calls", type=int,
                        help="simulated request allowance: 1–16 (default: 3)")
    parser.add_argument("--broker-max-output-tokens", type=int,
                        help="total reserved output tokens: 1–65536 (default: 3072)")
    parser.add_argument("--broker-max-request-bytes", type=int,
                        help="total request bytes: 1–262144 (default: 49152)")
    parser.add_argument("--session-max-steps", type=int, help="planner attempt limit: 1–16 (default: 3)")
    parser.add_argument("--session-max-seconds", type=int, help="total session deadline: 1–600 seconds (default: 60)")
    parser.add_argument("--session-max-output-bytes", type=int,
                        help="total reserved response allowance: 1–1048576 bytes (default: 3072)")
    parser.add_argument("--audit", type=Path, default=Path(".secure-agent/audit.jsonl"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="execute only with policy, audit and isolation")
    mode.add_argument("--dry-run", action="store_true", help="validate and audit only (default)")
    backend_selection = parser.add_mutually_exclusive_group()
    backend_selection.add_argument("--fixture", action="store_true", help="select the owned Linux in-namespace fixture backend")
    backend_selection.add_argument("--routed", action="store_true", help="select isolated HTTP to one authorized IPv4 literal")
    args = parser.parse_args(argv)
    session_scenario = args.session_mock or args.isolated_session_mock or args.openai_offline
    session_options = (args.session_max_steps, args.session_max_seconds, args.session_max_output_bytes)
    broker_options = (args.broker_max_calls, args.broker_max_output_tokens, args.broker_max_request_bytes)
    if not args.openai_offline and any(value is not None for value in (
            args.openai_model, args.openai_max_output_tokens, *broker_options)):
        parser.error("OpenAI and broker options require --openai-offline")
    if args.openai_offline and args.openai_model is None:
        parser.error("--openai-offline requires an explicit --openai-model")
    if not session_scenario and any(value is not None for value in session_options):
        parser.error("session limits require a session source")
    if session_scenario and args.routed:
        parser.error("this mock session slice supports owned fixtures only, not routed targets")
    try:
        policy = parse_policy(_read_bounded(args.policy))
        backend = None
        if args.fixture:
            from .isolation import LinuxFixtureBackend
            backend = LinuxFixtureBackend()
        elif args.routed:
            from .routed import LinuxRoutedBackend
            backend = LinuxRoutedBackend()
        with AuditSink(args.audit) as audit:
            if session_scenario:
                from .session import SessionLimits, SessionRunner
                from .session_provider import SessionMockProvider

                limits = SessionLimits(**{key: value for key, value in zip(
                    ("max_steps", "max_runtime_seconds", "max_output_bytes"), session_options)
                    if value is not None})
                if args.openai_offline:
                    from .openai_broker import BrokerLimits, OfflineTransport
                    from .openai_fixtures import scenario_responses
                    from .openai_protocol import OpenAIConfig
                    from .openai_provider import OfflineOpenAIProvider

                    config = OpenAIConfig(args.openai_model, max_output_tokens=(
                        args.openai_max_output_tokens if args.openai_max_output_tokens is not None else 1024))
                    broker_limits = BrokerLimits(**{key: value for key, value in zip(
                        ("max_calls", "max_reserved_output_tokens", "max_request_bytes"), broker_options)
                        if value is not None})
                    provider = OfflineOpenAIProvider(config, audit,
                        OfflineTransport(scenario_responses(args.openai_offline)), broker_limits)
                elif args.isolated_session_mock:
                    from .planner_isolation import LinuxIsolatedMockProvider
                    provider = LinuxIsolatedMockProvider(session_scenario)
                else:
                    provider = SessionMockProvider(session_scenario)
                runner = SessionRunner(policy, audit, backend, provider, limits)
                if args.openai_offline:
                    provider.bind_session(runner.session_id)
                previous_handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
                try:
                    for number in previous_handlers:
                        signal.signal(number, lambda *_: runner.cancel())
                    summary = runner.run(execute=args.execute,
                                         interactive=sys.stdin.isatty() and sys.stdout.isatty(),
                                         approval=_human_approval,
                                         on_step=lambda step: print(json.dumps({
                                             "event_type": "session_step_finished", "session_id": runner.session_id,
                                             **step,
                                         }, sort_keys=True, ensure_ascii=True), file=sys.stderr, flush=True))
                finally:
                    for number, handler in previous_handlers.items():
                        signal.signal(number, handler)
                extra = ({"broker_id": provider.broker.broker_id,
                          "broker": dict(provider.broker.snapshot),
                          "broker_error": provider.broker.last_error,
                          "live_calls_enabled": False} if args.openai_offline else {})
                _print({**summary, "provider": provider.name, **extra})
                return 0 if summary["session_status"] == "completed" else 2
            raw = _read_bounded(args.proposal) if args.proposal else MockProvider().propose()
            controller = Controller(policy, audit, backend)
            preview = controller.submit(raw)
            preview["provider"] = "imported-untrusted-json" if args.proposal else MockProvider.name
            if not args.execute or preview["decision"] == "deny":
                _print(preview)
                return 2 if preview["decision"] == "deny" else 0
            interactive = sys.stdin.isatty() and sys.stdout.isatty()
            reference = None
            if preview["decision"] == "approval_required" and interactive:
                reference = _human_approval(controller, raw)
            outcome = controller.submit(raw, execute=True, approval_reference=reference,
                                        interactive=interactive)
            outcome["provider"] = preview["provider"]
            _print(outcome)
            return 0 if outcome["execution_status"] == "succeeded" else 2
    except AuditUnavailable:
        _print({"decision": "deny", "execution_status": "audit_error",
                "reasons": ["audit_unavailable"],
                "note": "No new execution is permitted; check for an unmatched execution_started event."})
        return 3
    except (ValidationError, ValueError, BrokerError, OSError, subprocess.SubprocessError) as exc:
        _print({"decision": "deny", "execution_status": "blocked",
                "reasons": [exc.code if isinstance(exc, ValidationError) else "configuration_or_input_error"]})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
