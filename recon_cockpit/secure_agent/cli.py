"""Dedicated secure-agent entry point. No imports from the legacy host runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
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


def _human_approval(controller: Controller, raw: bytes | str) -> str | None:
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
        with open("/dev/tty", "r+", encoding="utf-8") as terminal:
            terminal.write(f"Type '{challenge}' to approve once (blank denies): ")
            terminal.flush()
            answer = terminal.readline(128).strip()
    except OSError:
        return None
    if answer != challenge:
        return None
    grant = controller.approvals.issue(action, controller.policy)
    return grant.reference


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Secure Agent Mode, milestone 1 (deterministic mock)")
    parser.add_argument("--policy", type=Path, default=Path("examples/secure-agent-policy.json"))
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--mock", action="store_true", help="use the deterministic mock (default)")
    source.add_argument("--proposal", type=Path, help="read strictly bounded untrusted action JSON")
    parser.add_argument("--audit", type=Path, default=Path(".secure-agent/audit.jsonl"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="execute only with policy, audit and isolation")
    mode.add_argument("--dry-run", action="store_true", help="validate and audit only (default)")
    parser.add_argument("--fixture", action="store_true", help="select the owned Linux in-namespace fixture backend")
    args = parser.parse_args(argv)
    try:
        policy = parse_policy(_read_bounded(args.policy))
        raw = _read_bounded(args.proposal) if args.proposal else MockProvider().propose()
        backend = None
        if args.fixture:
            from .isolation import LinuxFixtureBackend
            backend = LinuxFixtureBackend()
        with AuditSink(args.audit) as audit:
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
    except (ValidationError, ValueError, OSError, subprocess.SubprocessError) as exc:
        _print({"decision": "deny", "execution_status": "blocked",
                "reasons": [exc.code if isinstance(exc, ValidationError) else "configuration_or_input_error"]})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
