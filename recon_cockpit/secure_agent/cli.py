"""Dedicated secure-agent entry point. No imports from the legacy host runner."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, nullcontext
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

from .audit import AuditSink, AuditUnavailable
from .approvals import ApprovalUnavailable
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


def _isolated_human_approval(controller, raw, *, control):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return None
    return controller.approvals.review(parse_action(raw), controller.policy, control=control)


def _approval_context(args, policy, session_id):
    if not args.isolated_approvals:
        return nullcontext(None)
    from .approval_isolation import LinuxApprovalService
    return LinuxApprovalService(policy, session_id)


def _run_http_assessment(args, policy, audit):
    """Construct one fresh fixture authority with privately persisted evidence."""
    from uuid import uuid4

    from .assessment import AssessmentProvider, DiscoveryAssessmentProvider, WorkflowAssessmentProvider
    from .assessment_contract import capability_descriptor
    from .authorized_execution import AuthorizedFixtureBackend, AuthorizedDiscoveryFixtureBackend
    from .control_plane import AuthoritySession
    from .coordinator_isolation import LinuxOfflineCoordinator
    from .evidence import EvidenceStore
    from .session import SessionLimits

    workflow = args.workflow_assessment is not None
    discovery = workflow or args.discovery_assessment is not None
    case = args.workflow_assessment or args.discovery_assessment or args.http_assessment
    steps = 3 if discovery else 2
    provider_type = DiscoveryAssessmentProvider if discovery else AssessmentProvider
    if workflow:
        provider_type = WorkflowAssessmentProvider
    backend_type = AuthorizedDiscoveryFixtureBackend if discovery else AuthorizedFixtureBackend
    if discovery:
        from .discovery_contract import capability_descriptor
    limits = SessionLimits(**{"max_steps": steps, "max_output_bytes": steps * 1024, **{key: value for key, value in zip(
        ("max_steps", "max_runtime_seconds", "max_output_bytes"),
        (args.session_max_steps, args.session_max_seconds, args.session_max_output_bytes))
        if value is not None}})
    session_id = str(uuid4())
    coordinator = LinuxOfflineCoordinator()
    lab = None
    backend = (backend_type(policy, session_id, limits, execute=args.execute)
               if args.fixture else None)
    evidence_options = {}
    if args.owned_lab:
        from .owned_lab import OwnedLab, AuthorizedOwnedLabBackend
        from .owned_lab_contract import capability_descriptor

        # Construction is inert. The first authorized, audited action starts
        # the lab; dry runs and denied approvals never create its services.
        lab = OwnedLab(case, session_id, limits, execute=args.execute)
        backend = AuthorizedOwnedLabBackend(policy, session_id, limits, lab, execute=args.execute)
        evidence_options["owned_lab"] = lab.identity
    with (_approval_context(args, policy, session_id) as approvals,
          (lab if lab is not None else nullcontext()), EvidenceStore(
            args.assessment_dir, session_id=session_id, policy=policy,
            case=case, discovery=discovery, workflow=workflow, **evidence_options) as evidence):
        provider = provider_type(case, audit, evidence)
        runner = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                  provider=provider, evidence=evidence, approvals=approvals)
        previous_handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        try:
            for number in previous_handlers:
                signal.signal(number, lambda *_: runner.cancel())
            summary = runner.run(execute=args.execute,
                                 interactive=sys.stdin.isatty() and sys.stdout.isatty(),
                                 approval=_isolated_human_approval if args.isolated_approvals else _human_approval,
                                 on_step=lambda step: print(json.dumps({
                                     "event_type": "session_step_finished", "session_id": runner.session_id,
                                     **step,
                                 }, sort_keys=True, ensure_ascii=True), file=sys.stderr, flush=True))
            if lab is not None:
                evidence.record_lab_closed(lab.close())
            report = evidence.finalize(summary)
        finally:
            for number, handler in previous_handlers.items():
                signal.signal(number, handler)
    _print({**summary, "provider": provider.name, "fixture_case": case,
            "assessment_outcome": report["outcome"], "assessment_id": report.get("assessment_id"),
            "report_paths": {"json": str(args.assessment_dir / "report.json"),
                             "markdown": str(args.assessment_dir / "report.md")},
            "capability": capability_descriptor(), "live_calls_enabled": False,
            **({"workflow_card": report["workflow_card"]} if workflow else {}),
            **({"owned_lab": report["owned_lab"]} if lab is not None else {}),
            "broker_id": provider.broker.broker_id, "broker": dict(provider.broker.snapshot),
            "broker_error": provider.broker.last_error,
            "coordinator_boundary_checks": coordinator.boundary_checks,
            "parser_boundary_checks": provider.boundary_checks})
    return 0 if summary["session_status"] == "completed" else 2


def main(argv: list[str] | None = None) -> int:
    from .session_provider import SCENARIOS
    from .openai_broker import BrokerError
    from .openai_fixtures import SCENARIOS as OPENAI_SCENARIOS
    from .coordinator_isolation import SCENARIOS as COORDINATOR_SCENARIOS
    from .isolation import IsolationUnavailable

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
    source.add_argument("--control-plane-mock", choices=COORDINATOR_SCENARIOS,
                        help="run a persistent Linux-isolated coordinator through the authority service")
    source.add_argument("--control-plane-openai-offline", choices=OPENAI_SCENARIOS,
                        help="run synthetic responses through the isolated coordinator, parser and authority")
    source.add_argument("--http-assessment", choices=tuple("abcdef"),
                        help="run the fixed owned HTTP assessment with private evidence; no live model")
    source.add_argument("--discovery-assessment", choices=tuple("abcdef"),
                        help="gate owned HTTP assessment on one TCP connection; policy must allow tcp_connect")
    source.add_argument("--workflow-assessment", choices=tuple("abcdef"),
                        help="run the reviewed TCP-to-HTTP workflow card and record each decision")
    source.add_argument("--inspect-assessment", type=Path,
                        help="inspect existing assessment evidence without resuming execution")
    source.add_argument("--evaluate-owned-lab", action="store_true",
                        help="repeat all six owned cases and independently grade saved evidence")
    source.add_argument("--inspect-evaluation", type=Path,
                        help="regrade an existing owned evaluation without execution or writes")
    parser.add_argument("--evaluation-dir", type=Path, help="fresh private batch directory; parent must exist")
    parser.add_argument("--evaluation-repeats", type=int, help="repetitions of cases a-f: 1-10 (default: 3, 18 trials)")
    parser.add_argument("--evaluation-max-seconds", type=int, help="absolute batch lifetime: 1-3600 seconds (default: 600)")
    parser.add_argument("--assessment-dir", type=Path,
                        help="new private directory for assessment artifacts, decisions and reports")
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
    parser.add_argument("--isolated-audit", action="store_true",
                        help="use the confined Linux audit writer for an authority session or owned assessment")
    parser.add_argument("--isolated-approvals", action="store_true",
                        help="confine terminal review and grants for an authority session or owned assessment")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="execute only with policy, audit and isolation")
    mode.add_argument("--dry-run", action="store_true", help="validate and audit only (default)")
    backend_selection = parser.add_mutually_exclusive_group()
    backend_selection.add_argument("--fixture", action="store_true", help="select the owned Linux in-namespace fixture backend")
    backend_selection.add_argument("--routed", action="store_true", help="select isolated HTTP to one authorized IPv4 literal")
    backend_selection.add_argument("--owned-lab", action="store_true",
                                   help="keep one owned fixture alive across a workflow; reset on each run")
    args = parser.parse_args(argv)
    offline_scenario = args.openai_offline or args.control_plane_openai_offline
    assessment_case = args.http_assessment or args.discovery_assessment or args.workflow_assessment
    authority_mode = args.control_plane_mock or args.control_plane_openai_offline or assessment_case
    if args.isolated_audit and not authority_mode:
        parser.error("--isolated-audit requires an authority session or owned assessment")
    if args.isolated_approvals and not authority_mode:
        parser.error("--isolated-approvals requires an authority session or owned assessment")
    session_scenario = (args.session_mock or args.isolated_session_mock or offline_scenario
                        or args.control_plane_mock or assessment_case)
    session_options = (args.session_max_steps, args.session_max_seconds, args.session_max_output_bytes)
    broker_options = (args.broker_max_calls, args.broker_max_output_tokens, args.broker_max_request_bytes)
    evaluation_options = (args.evaluation_dir, args.evaluation_repeats, args.evaluation_max_seconds)
    if not args.evaluate_owned_lab and any(value is not None for value in evaluation_options):
        parser.error("evaluation options require --evaluate-owned-lab")
    if args.evaluate_owned_lab and args.evaluation_dir is None:
        parser.error("--evaluate-owned-lab requires --evaluation-dir")
    if (args.evaluate_owned_lab or args.inspect_evaluation) and (args.fixture or args.routed or args.owned_lab):
        parser.error("evaluation fixes the owned lab backend and cannot select another backend")
    if args.inspect_evaluation and (args.execute or args.dry_run):
        parser.error("--inspect-evaluation cannot select an execution mode")
    if not offline_scenario and any(value is not None for value in (
            args.openai_model, args.openai_max_output_tokens, *broker_options)):
        parser.error("OpenAI and broker options require --openai-offline or --control-plane-openai-offline")
    if offline_scenario and args.openai_model is None:
        option = "--control-plane-openai-offline" if args.control_plane_openai_offline else "--openai-offline"
        parser.error(option + " requires an explicit --openai-model")
    if not session_scenario and any(value is not None for value in session_options):
        parser.error("session limits require a session source")
    if session_scenario and args.routed:
        parser.error("this mock session slice supports owned fixtures only, not routed targets")
    if assessment_case and args.assessment_dir is None:
        parser.error("assessment requires --assessment-dir")
    if args.assessment_dir is not None and not assessment_case:
        parser.error("--assessment-dir requires --http-assessment, --discovery-assessment or --workflow-assessment")
    if args.owned_lab and not args.workflow_assessment:
        parser.error("--owned-lab requires --workflow-assessment")
    if assessment_case and args.execute and not (args.fixture or args.owned_lab):
        parser.error("executing an assessment requires --fixture or --owned-lab")
    if args.inspect_assessment and (args.execute or args.dry_run or args.fixture or args.routed or args.owned_lab):
        parser.error("--inspect-assessment cannot select an execution mode or backend")
    try:
        if args.inspect_evaluation is not None:
            from .evaluation import inspect_evaluation

            report = inspect_evaluation(args.inspect_evaluation)
            _print(report)
            return 0 if report["status"] in {"passed", "dry_run"} and not report["integrity_issues"] else 2
        if args.evaluate_owned_lab:
            from .evaluation import EvaluationRunner, EvaluationLimits

            limits = EvaluationLimits(**{key: value for key, value in zip(
                ("repeats", "max_runtime_seconds"),
                (args.evaluation_repeats, args.evaluation_max_seconds)) if value is not None})
            runner = EvaluationRunner(args.evaluation_dir, parse_policy(_read_bounded(args.policy)), limits)
            previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
            try:
                for number in previous:
                    signal.signal(number, lambda *_: runner.cancel())
                report = runner.run(execute=args.execute, on_trial=lambda trial: print(json.dumps({
                    "event_type": "evaluation_trial_graded", "trial_id": trial["trial_id"],
                    "verdict": trial["grade"]["verdict"], "issues": trial["grade"]["issues"],
                }, sort_keys=True, ensure_ascii=True), file=sys.stderr, flush=True))
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
            _print(report)
            return 0 if report["status"] in {"passed", "dry_run"} else 2
        if args.inspect_assessment is not None:
            from .evidence import inspect_assessment

            report = inspect_assessment(args.inspect_assessment)
            _print(report)
            return 0 if not report["integrity_issues"] else 2
        policy = parse_policy(_read_bounded(args.policy))
        backend = None
        if args.fixture and not authority_mode:
            from .isolation import LinuxFixtureBackend
            backend = LinuxFixtureBackend()
        elif args.routed:
            from .routed import LinuxRoutedBackend
            backend = LinuxRoutedBackend()
        audit_type = AuditSink
        if args.isolated_audit:
            from .audit_isolation import LinuxAuditSink
            audit_type = LinuxAuditSink
        with audit_type(args.audit) as audit, ExitStack() as services:
            if assessment_case:
                return _run_http_assessment(args, policy, audit)
            if session_scenario:
                from .session import SessionLimits, SessionRunner
                from .session_provider import SessionMockProvider

                limits = SessionLimits(**{key: value for key, value in zip(
                    ("max_steps", "max_runtime_seconds", "max_output_bytes"), session_options)
                    if value is not None})
                if offline_scenario:
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
                        OfflineTransport(scenario_responses(offline_scenario)), broker_limits)
                if authority_mode:
                    from uuid import uuid4
                    from .authorized_execution import AuthorizedFixtureBackend
                    from .control_plane import AuthoritySession
                    from .coordinator_isolation import LinuxCoordinator, LinuxOfflineCoordinator

                    session_id = str(uuid4())
                    coordinator = (LinuxOfflineCoordinator() if args.control_plane_openai_offline
                                   else LinuxCoordinator(args.control_plane_mock))
                    backend = (AuthorizedFixtureBackend(policy, session_id, limits, execute=args.execute)
                               if args.fixture else None)
                    provider_kwargs = {"provider": provider} if args.control_plane_openai_offline else {}
                    approvals = services.enter_context(_approval_context(args, policy, session_id))
                    runner = AuthoritySession(policy, audit, backend, coordinator, limits,
                                              session_id=session_id, approvals=approvals, **provider_kwargs)
                    if args.control_plane_mock:
                        provider = coordinator
                elif args.isolated_session_mock:
                    from .planner_isolation import LinuxIsolatedMockProvider
                    provider = LinuxIsolatedMockProvider(session_scenario)
                elif not offline_scenario:
                    provider = SessionMockProvider(session_scenario)
                if not authority_mode:
                    runner = SessionRunner(policy, audit, backend, provider, limits)
                if args.openai_offline:
                    provider.bind_session(runner.session_id)
                previous_handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
                try:
                    for number in previous_handlers:
                        signal.signal(number, lambda *_: runner.cancel())
                    summary = runner.run(execute=args.execute,
                                         interactive=sys.stdin.isatty() and sys.stdout.isatty(),
                                         approval=_isolated_human_approval if args.isolated_approvals else _human_approval,
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
                          "live_calls_enabled": False} if offline_scenario else {})
                if args.control_plane_mock:
                    extra = {"boundary_checks": provider.boundary_checks, "live_calls_enabled": False}
                if args.control_plane_openai_offline:
                    extra.update(coordinator_boundary_checks=coordinator.boundary_checks,
                                 parser_boundary_checks=provider.boundary_checks)
                provider_name = ("linux-isolated-coordinator-openai-offline" if args.control_plane_openai_offline
                                 else provider.name)
                _print({**summary, "provider": provider_name, **extra})
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
    except AuditUnavailable as exc:
        if getattr(exc, "code", None) == "evidence_unavailable":
            _print({"decision": "deny", "execution_status": "evidence_error",
                    "reasons": ["evidence_unavailable"],
                    "note": "No new execution is permitted; inspect the private assessment directory for incomplete evidence."})
            return 3
        _print({"decision": "deny", "execution_status": "audit_error",
                "reasons": ["audit_unavailable"],
                "note": "No new execution is permitted; check for an unmatched execution_started event."})
        return 3
    except ApprovalUnavailable:
        _print({"decision": "deny", "execution_status": "blocked", "reasons": ["approval_unavailable"]})
        return 2
    except IsolationUnavailable:
        _print({"decision": "deny", "execution_status": "blocked", "reasons": ["isolation_unavailable"]})
        return 2
    except (ValidationError, ValueError, BrokerError, OSError, subprocess.SubprocessError) as exc:
        _print({"decision": "deny", "execution_status": "blocked",
                "reasons": [exc.code if isinstance(exc, ValidationError) else "configuration_or_input_error"]})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
