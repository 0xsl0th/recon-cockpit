"""Validate bounded mock sessions against owned, isolated Linux HTTP fixtures.

This unattended demo uses an explicit fixture-only automatic policy. It does
not issue human grants, contact a model, or enable host/routed destinations.
Run from an installed checkout: python scripts/secure_agent_session_demo.py
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.isolation import IsolationUnavailable, LinuxFixtureBackend
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.session import SessionLimits, SessionRunner
from recon_cockpit.secure_agent.session_provider import SessionMockProvider
from recon_cockpit.secure_agent.worker import INJECTION_FIXTURE

if __package__:
    from .secure_agent_linux_demo import _require_boundary_checks
else:
    from secure_agent_linux_demo import _require_boundary_checks


def demo_policy():
    return parse_policy({
        "schema_version": "1", "policy_version": "owned-session-demo-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET", "HEAD"],
        "max_timeout_seconds": 3, "max_output_bytes": 1024, "max_targets": 1,
        "require_approval": False, "approval_ttl_seconds": 60,
    })


class VerifiedFixtureBackend(LinuxFixtureBackend):
    """Retain only checked boundary evidence; response bodies stay internal."""

    def __init__(self):
        super().__init__(verify_boundary=True)
        self.calls = 0
        self.evidence = []

    def run(self, action, policy, *, control=None):
        self.calls += 1
        result = super().run(action, policy, control=control)
        checks = result.get("boundary_checks")
        _require_boundary_checks(checks)
        injected = action.parameters.path == "/injection"
        if injected:
            rows = result.get("results")
            if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                    or rows[0].get("body") != INJECTION_FIXTURE.decode("ascii")):
                raise RuntimeError("owned injection fixture was not received intact")
        self.evidence.append({
            "action_digest": action.digest, "path": action.parameters.path,
            "boundary_checks": dict(checks), "injection_fixture_received": injected,
        })
        return result


def run_demo(audit_path: Path, *, on_case=None) -> dict:
    """Execute and verify six real-kernel cases, returning safe summary data."""
    policy = demo_policy()
    LinuxFixtureBackend(verify_boundary=True).check_available()
    cases = (
        ("three_step", "three_step", SessionLimits(), "planner_done", 3, 3),
        ("injection_target", "injection_target", SessionLimits(), "proposal_denied", 2, 1),
        ("injection_authority", "injection_authority", SessionLimits(), "proposal_denied", 2, 1),
        ("step_limit", "endless", SessionLimits(max_steps=2), "step_limit", 2, 2),
        ("output_limit", "endless", SessionLimits(max_output_bytes=1024), "output_limit", 2, 1),
        ("cancel_after_first", "endless", SessionLimits(), "session_cancelled", 1, 1),
    )
    evidence = []
    with AuditSink(audit_path) as audit:
        for label, scenario, limits, reason, attempts, successes in cases:
            backend = VerifiedFixtureBackend()
            runner = SessionRunner(policy, audit, backend, SessionMockProvider(scenario), limits)

            def cancel_after_first(_step):
                runner.cancel()

            summary = runner.run(
                execute=True, on_step=cancel_after_first if label == "cancel_after_first" else None,
            )
            if (summary["stop_reason"] != reason or summary["steps_attempted"] != attempts
                    or summary["actions_succeeded"] != successes or backend.calls != successes
                    or len(backend.evidence) != successes):
                raise RuntimeError("session demonstration outcome mismatch: " + label)
            if (runner.controller.policy.digest != policy.digest
                    or summary["output_reserved_bytes"] != successes * 1024):
                raise RuntimeError("session authority or budget invariant failed: " + label)
            if label.startswith("injection_"):
                expected = "target_out_of_scope" if label == "injection_target" else "unknown_action_fields"
                if summary["steps"][-1]["reasons"] != [expected]:
                    raise RuntimeError("injected proposal failed at the wrong boundary: " + label)
            result = {"case": label, **summary, "executions": backend.evidence,
                      "policy_unchanged": True}
            evidence.append(result)
            if on_case is not None:
                on_case(result)
    return {
        "demo": "passed", "provider": SessionMockProvider.name,
        "policy_version": policy.policy_version, "audit": str(audit_path), "cases": evidence,
        "limits": "Owned fixture mock sessions only; no model or routed-session validation.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="retain JSONL evidence at this private operator path")
    args = parser.parse_args()
    audit_path = args.audit
    if audit_path is None:
        audit_path = Path(tempfile.mkdtemp(prefix="recon-session-demo-")) / "audit.jsonl"
    print(json.dumps({
        "provider": SessionMockProvider.name, "audit": str(audit_path),
        "note": "Explicit automatic policy for owned isolated fixtures; no human approvals or model.",
    }))
    try:
        result = run_demo(audit_path, on_case=lambda case: print(json.dumps(case, sort_keys=True)))
    except IsolationUnavailable as exc:
        print(json.dumps({"demo": "blocked", "reason": exc.code}))
        return 2
    except (RuntimeError, OSError, ValueError):
        print(json.dumps({"demo": "failed", "reason": "session_demo_validation_failed"}))
        return 1
    print(json.dumps({key: value for key, value in result.items() if key != "cases"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
