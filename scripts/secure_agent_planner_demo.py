"""Verify the isolated deterministic planner with safe, bounded session output.

The default runs three planner steps in real Linux isolation without launching
tools. --execute-fixtures also probes owned in-namespace fixtures under an
explicit automatic policy. Neither mode contacts a model or issues human grants.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import UnavailableBackend
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.planner_isolation import LinuxIsolatedMockProvider
from recon_cockpit.secure_agent.session import SessionRunner

if __package__:
    from .secure_agent_session_demo import VerifiedFixtureBackend, demo_policy
else:
    from secure_agent_session_demo import VerifiedFixtureBackend, demo_policy


BOUNDARY_NAMES = {
    "namespaces_private", "capabilities_dropped", "no_new_privs",
    "socket_creation_blocked", "process_creation_blocked",
    "namespace_creation_blocked", "root_read_only",
}


class VerifiedPlanner(LinuxIsolatedMockProvider):
    """Expose checked booleans only, never planner or response text."""

    def __init__(self, scenario="three_step"):
        super().__init__(scenario)
        self.evidence = []

    def propose(self, observation, *, control):
        proposal = super().propose(observation, control=control)
        checks = self.boundary_checks
        if (type(checks) is not dict or set(checks) != BOUNDARY_NAMES
                or any(checks[name] is not True for name in BOUNDARY_NAMES)):
            raise RuntimeError("planner boundary verification failed")
        self.evidence.append({"step": len(self.evidence) + 1, "boundary_checks": checks})
        return proposal


def run_demo(audit_path: Path, *, execute_fixtures=False, on_case=None) -> dict:
    """Return verified planner/session evidence without raw proposals or bodies."""
    policy = demo_policy()
    LinuxIsolatedMockProvider().check_available()
    scenarios = ("three_step", "injection_target", "injection_authority") if execute_fixtures else ("three_step",)
    evidence = []
    with AuditSink(audit_path) as audit:
        for scenario in scenarios:
            provider = VerifiedPlanner(scenario)
            backend = VerifiedFixtureBackend() if execute_fixtures else UnavailableBackend()
            runner = SessionRunner(policy, audit, backend, provider)
            summary = runner.run(execute=execute_fixtures)
            attempts = 3 if scenario == "three_step" else 2
            successes = (3 if scenario == "three_step" else 1) if execute_fixtures else 0
            reason = "planner_done" if scenario == "three_step" else "proposal_denied"
            if (summary["stop_reason"] != reason or summary["steps_attempted"] != attempts
                    or summary["actions_succeeded"] != successes or len(provider.evidence) != attempts
                    or runner.controller.policy.digest != policy.digest):
                raise RuntimeError("isolated planner demonstration outcome mismatch")
            if execute_fixtures and (backend.calls != successes or len(backend.evidence) != successes):
                raise RuntimeError("isolated planner tool execution count mismatch")
            if scenario.startswith("injection_"):
                expected = "target_out_of_scope" if scenario == "injection_target" else "unknown_action_fields"
                if summary["steps"][-1]["reasons"] != [expected]:
                    raise RuntimeError("injected isolated proposal failed at the wrong boundary")
            result = {
                "case": scenario, **summary, "planner_executions": provider.evidence,
                "tool_executions": backend.evidence if execute_fixtures else [], "policy_unchanged": True,
            }
            evidence.append(result)
            if on_case is not None:
                on_case(result)
    return {
        "demo": "passed", "provider": LinuxIsolatedMockProvider.name,
        "mode": "execute_owned_fixtures" if execute_fixtures else "dry_run_tools",
        "policy_version": policy.policy_version, "audit": str(audit_path), "cases": evidence,
        "limits": "Fixed isolated mock only; no live model/API calls or arbitrary plugins.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="retain JSONL evidence at this private operator path")
    parser.add_argument("--execute-fixtures", action="store_true", help="execute owned isolated HTTP fixtures")
    args = parser.parse_args()
    audit_path = args.audit or Path(tempfile.mkdtemp(prefix="recon-planner-demo-")) / "audit.jsonl"
    print(json.dumps({
        "provider": LinuxIsolatedMockProvider.name, "audit": str(audit_path),
        "note": "Fixed isolated mock; explicit automatic fixture policy; no model or human approvals.",
    }))
    try:
        report = run_demo(audit_path, execute_fixtures=args.execute_fixtures,
                          on_case=lambda case: print(json.dumps(case, sort_keys=True)))
    except IsolationUnavailable as exc:
        print(json.dumps({"demo": "blocked", "reason": exc.code}))
        return 2
    except (RuntimeError, OSError, ValueError):
        print(json.dumps({"demo": "failed", "reason": "planner_demo_validation_failed"}))
        return 1
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
