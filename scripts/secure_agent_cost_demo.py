"""Exercise monetary accounting locally using fictional prices and receipts.

With no --ledger, print a plan without writing files. Supplying a fresh directory
creates an explicitly simulation-only ledger. There is no provider connection,
credential lookup, tool execution or actual bill in either mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from recon_cockpit.secure_agent.cost_contract import CostError, PriceCard, TokenUsage
from recon_cockpit.secure_agent.cost_ledger import BudgetExceeded, CostLedger


def run_demo(directory=None):
    result = {"demo": "provider-cost-ledger", "mode": "dry_run" if directory is None else "simulation",
              "live_calls_enabled": False, "actual_provider_calls": 0, "status": "dry_run"}
    if directory is None:
        return result
    try:
        with CostLedger.create(directory, account_id="demo-account", limit_microusd=1000,
                               mode="simulation") as ledger:
            parent = "demo-account"
            for kind in ("engagement", "session", "agent", "action"):
                scope = "demo-" + kind
                ledger.add_scope(scope, parent_id=parent, kind=kind,
                                 limit_microusd=500 if kind == "engagement" else None)
                parent = scope
            price = PriceCard("fictional-provider", "fictional-model", "demo-v1", 1_000_000, 500_000, 2_000_000)
            for attempt in ("completed", "interrupted", "unaffordable"):
                digest = hashlib.sha256(attempt.encode("ascii")).hexdigest()
                ledger.estimate(attempt, scope_id=parent, request_digest=digest, price=price,
                                usage=TokenUsage(10, 10), input_token_limit=100, output_token_limit=100)
                try:
                    ledger.reserve(attempt)
                except BudgetExceeded as exc:
                    result["denied_by"] = exc.scope_id
                    continue
                ledger.begin_dispatch(attempt, request_digest=digest)
                if attempt == "completed":
                    ledger.settle_usage(attempt, TokenUsage(10, 10), receipt_reference="demo-usage", event_id="demo-settle")
                    ledger.reconcile(attempt, 25, billing_reference="demo-bill-line", event_id="demo-reconcile")
                else:
                    ledger.mark_uncertain(attempt, reason="timeout")
            result.update(status="passed", report=ledger.report("demo-engagement"))
    except CostError as exc:
        result.update(status="failed", reason=exc.code)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, help="new private directory for simulated accounting")
    args = parser.parse_args(argv)
    result = run_demo(args.ledger)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0 if result["status"] in {"passed", "dry_run"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
