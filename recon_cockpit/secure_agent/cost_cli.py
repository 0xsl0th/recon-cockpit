"""Operator controls and read-only JSON views for the provider cost ledger."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .cost_contract import CostError
from .cost_ledger import CostLedger


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True, help="private ledger directory")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create a new account ledger; never replace one")
    create.add_argument("--account", required=True)
    create.add_argument("--limit-microusd", type=int, required=True)
    create.add_argument("--period", default="lifetime", help="explicit accounting period label; no automatic reset")
    create.add_argument("--mode", choices=("provider", "simulation"), default="provider")
    scope = commands.add_parser("add-scope", help="add an engagement, session, agent or action budget")
    scope.add_argument("--scope", required=True)
    scope.add_argument("--parent", required=True)
    scope.add_argument("--kind", choices=("engagement", "session", "agent", "action"), required=True)
    scope.add_argument("--limit-microusd", type=int, help="omitted means inherit parent constraints")
    limit = commands.add_parser("set-limit", help="record an explicit operator budget change")
    limit.add_argument("--scope", required=True)
    limit.add_argument("--limit-microusd", type=int, required=True)
    limit.add_argument("--event-id", required=True, help="stable identifier for this change")
    inspect = commands.add_parser("inspect", help="read costs without writes or execution")
    inspect.add_argument("--scope")
    events = commands.add_parser("events", help="read a bounded audit page")
    events.add_argument("--after-sequence", type=int, default=0)
    events.add_argument("--limit", type=int, default=100)
    attempts = commands.add_parser("attempts", help="read estimates, holds and unresolved attempts")
    attempts.add_argument("--after-id", default="")
    attempts.add_argument("--limit", type=int, default=100)
    cancel = commands.add_parser("cancel", help="release an attempt only if dispatch never started")
    cancel.add_argument("--attempt", required=True)
    reconcile = commands.add_parser("reconcile", help="record retained billing evidence for an incurred charge")
    reconcile.add_argument("--attempt", required=True)
    reconcile.add_argument("--actual-microusd", type=int, required=True)
    reconcile.add_argument("--billing-reference", required=True, help="unique billing line/revision evidence reference")
    reconcile.add_argument("--event-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            with CostLedger.create(args.ledger, account_id=args.account, limit_microusd=args.limit_microusd,
                                   period=args.period, mode=args.mode) as ledger:
                result = ledger.report()
        else:
            with CostLedger(args.ledger, read_only=args.command in {"inspect", "events", "attempts"}) as ledger:
                if args.command == "add-scope":
                    result = ledger.add_scope(args.scope, parent_id=args.parent, kind=args.kind,
                                              limit_microusd=args.limit_microusd)
                elif args.command == "set-limit":
                    result = ledger.set_limit(args.scope, args.limit_microusd, event_id=args.event_id)
                elif args.command == "inspect":
                    result = ledger.report(args.scope)
                elif args.command == "events":
                    result = {"events": ledger.events(after_sequence=args.after_sequence, limit=args.limit)}
                elif args.command == "attempts":
                    result = {"attempts": ledger.attempts(after_id=args.after_id, limit=args.limit)}
                elif args.command == "cancel":
                    result = ledger.cancel(args.attempt)
                else:
                    result = ledger.reconcile(args.attempt, args.actual_microusd,
                                              billing_reference=args.billing_reference, event_id=args.event_id)
        print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False))
        return 0
    except CostError as exc:
        print(json.dumps({"status": "failed", "reason": exc.code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
