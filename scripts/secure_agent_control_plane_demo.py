"""Exercise the real coordinator boundary against fixed adversarial scenarios.

No model, credentials or routed targets. Tools are dry-run by default; the
explicit --execute-fixtures mode uses an automatic policy for owned fixtures.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
from uuid import uuid4

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.session import SessionLimits


def demo_policy(*, approval=False):
    return parse_policy({
        "schema_version": "1", "policy_version": "control-plane-owned-fixtures-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET", "HEAD"],
        "max_timeout_seconds": 3, "max_output_bytes": 2048, "max_targets": 1,
        "require_approval": approval, "approval_ttl_seconds": 5,
    })


def run_demo(audit_path: Path, *, execute_fixtures=False, on_case=None):
    # label, scenario, limits, stop reason, attempted steps, reserved allowances.
    cases = [
        ("three_step", "three_step", SessionLimits(), "coordinator_done", 3, 3),
        ("step_budget", "endless", SessionLimits(max_steps=2), "step_limit", 2, 2),
        ("output_budget", "endless", SessionLimits(max_output_bytes=1024), "output_limit", 2, 1),
        ("replay", "replay", SessionLimits(), "coordinator_protocol_error", 1, 1),
        ("wrong_session", "wrong_session", SessionLimits(), "coordinator_protocol_error", 0, 0),
        ("forge_approval", "forge_approval", SessionLimits(), "coordinator_protocol_error", 0, 0),
        ("oversized", "oversized", SessionLimits(), "coordinator_failed", 0, 0),
        ("early_exit", "early_exit", SessionLimits(), "coordinator_failed", 0, 0),
        ("approval_required", "three_step", SessionLimits(), "action_blocked", 1, 1),
    ]
    if execute_fixtures:
        cases.extend((
            ("injection_target", "injection_target", SessionLimits(), "proposal_denied", 2, 1),
            ("injection_authority", "injection_authority", SessionLimits(), "proposal_denied", 2, 1),
        ))
    evidence = []
    with AuditSink(audit_path) as audit:
        for label, scenario, limits, stop, attempts, reserved in cases:
            required = label == "approval_required"
            policy = demo_policy(approval=required)
            session_id = str(uuid4())
            execute = execute_fixtures or required
            coordinator = LinuxCoordinator(scenario)
            backend = AuthorizedFixtureBackend(policy, session_id, limits, execute=execute)
            authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id)
            summary = authority.run(execute=execute, interactive=False)
            expected_success = reserved if execute_fixtures and not required else 0
            if (summary["stop_reason"] != stop or summary["steps_attempted"] != attempts
                    or summary["output_reserved_bytes"] != reserved * 1024
                    or summary["actions_succeeded"] != expected_success
                    or authority.controller.policy.digest != policy.digest):
                raise RuntimeError("control_plane_demo_case_failed: " + label)
            result = {"case": label, **summary, "boundary_checks": coordinator.boundary_checks,
                      "live_calls_enabled": False}
            evidence.append(result)
            if on_case is not None:
                on_case(result)
    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    for case in evidence:
        session_events = [row for row in records if row.get("session_id") == case["session_id"]]
        starts = [row for row in session_events if row["event_type"] == "execution_started"]
        finishes = [row for row in session_events if row["event_type"] == "execution_finished"]
        if len(starts) != case["actions_succeeded"] or len(finishes) != len(starts):
            raise RuntimeError("control_plane_demo_audit_mismatch")
        if sum(row["event_type"] == "session_finished" for row in session_events) != 1:
            raise RuntimeError("control_plane_demo_session_not_closed")
    return {"demo": "passed", "mode": "execute_owned_fixtures" if execute_fixtures else "dry_run_tools",
            "audit": str(audit_path), "live_calls_enabled": False, "cases": evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="private path for durable JSONL evidence")
    parser.add_argument("--execute-fixtures", action="store_true", help="execute owned isolated HTTP fixtures")
    args = parser.parse_args()
    path = args.audit or Path(tempfile.mkdtemp(prefix="recon-control-plane-demo-")) / "audit.jsonl"
    try:
        report = run_demo(path, execute_fixtures=args.execute_fixtures,
                          on_case=lambda case: print(json.dumps(case, sort_keys=True), flush=True))
    except (RuntimeError, OSError, ValueError):
        print(json.dumps({"demo": "failed", "reason": "control_plane_demo_validation_failed"}))
        return 1
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
