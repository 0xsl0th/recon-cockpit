"""Exercise the owned TLS provider foundation, with no real model or tool calls.

The default prints a plan without starting any process or reading credentials.
--execute starts an owned TLS fixture and fresh isolated broker/parser processes.
Only synthetic credentials, the fixed model and the status-only release profile
are supported. Failure reports contain static codes and safe receipts only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import tempfile
import threading
import time

from recon_cockpit.secure_agent.audit import AuditSink, AuditUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import load_json
from recon_cockpit.secure_agent.provider_adapter import OwnedTLSProvider
from recon_cockpit.secure_agent.provider_contract import ERROR_CODES, ProviderError, SCENARIOS


def run_demo(audit_path=None, *, scenario="success", execute=False, max_seconds=30, cancelled=None):
    if (type(scenario) is not str or scenario not in SCENARIOS or type(execute) is not bool
            or type(max_seconds) is not int or not 1 <= max_seconds <= 120):
        raise ValueError("invalid_provider_demo_configuration")
    result = {"schema_version": "1", "demo": "owned-tls-provider-foundation", "scenario": scenario,
              "mode": "execute_owned_tls" if execute else "dry_run", "status": "dry_run", "reason": None,
              "live_calls_enabled": False, "tool_executions": 0, "billing": "synthetic_units_only",
              "broker_id": None, "reservations": None, "receipt": None, "parser_boundary_checks": None,
              "proposal_parsed": False}
    if not execute:
        return result
    provider = None
    try:
        control = ExecutionControl(time.monotonic() + max_seconds, cancelled=cancelled)
        path = Path(audit_path) if audit_path is not None else Path(tempfile.mkdtemp(prefix="recon-provider-demo-")) / "audit.jsonl"
        with AuditSink(path) as audit:
            provider = OwnedTLSProvider(audit, scenario=scenario)
            proposal = load_json(provider.propose(b'{"step":1,"untrusted_observation":null}', control=control))
            if proposal != {"schema_version": "1", "action": None, "done": True}:
                raise ValueError("unexpected_owned_provider_proposal")
            result.update(status="passed", proposal_parsed=True)
    except ExecutionStopped as exc:
        result.update(status="stopped", reason=exc.reason)
    except (ProviderError, IsolationUnavailable, AuditUnavailable) as exc:
        # The isolated parser deliberately wraps callback failures. Preserve a
        # known broker code without exposing callback/peer exception messages.
        broker_reason = getattr(provider.broker, "last_error", None) if provider is not None else None
        reason = broker_reason if type(broker_reason) is str and broker_reason in ERROR_CODES else exc.code
        result.update(status="failed", reason=reason)
    except (OSError, RuntimeError, ValueError, TypeError):
        result.update(status="failed", reason="provider_demo_failed")
    if provider is not None:
        result.update(broker_id=provider.broker.broker_id, reservations=dict(provider.broker.snapshot),
                      receipt=provider.broker.last_receipt, parser_boundary_checks=provider.boundary_checks)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="run the owned TLS fixture and isolated broker")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="success")
    parser.add_argument("--audit", type=Path, help="private JSONL audit path; temporary by default")
    parser.add_argument("--max-seconds", type=int, default=30, choices=range(1, 121), metavar="1..120")
    args = parser.parse_args(argv)
    cancelled = threading.Event()
    handlers = {}
    try:
        if args.execute:
            for number in (signal.SIGINT, signal.SIGTERM):
                handlers[number] = signal.signal(number, lambda *_: cancelled.set())
        result = run_demo(args.audit, scenario=args.scenario, execute=args.execute,
                          max_seconds=args.max_seconds, cancelled=cancelled)
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"passed", "dry_run"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
