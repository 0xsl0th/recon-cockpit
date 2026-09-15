"""Verify the isolated coordinator and parser with fixed offline responses.

No API call, credential, routed target or human approval is involved. Tools are
dry-run by default. --execute-fixtures selects an explicit automatic policy for
owned isolated HTTP fixtures and the independently checked authority executor.
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
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES, LinuxOfflineCoordinator
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.openai_broker import BrokerLimits, OfflineTransport
from recon_cockpit.secure_agent.openai_fixtures import scenario_responses
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig
from recon_cockpit.secure_agent.openai_provider import OfflineOpenAIProvider
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES as PARSER_BOUNDARY_NAMES
from recon_cockpit.secure_agent.session import SessionLimits
from recon_cockpit.secure_agent.worker import INJECTION_FIXTURE


PROVIDER_NAME = "linux-isolated-coordinator-openai-offline"
EXECUTOR_BOUNDARY_NAMES = frozenset({
    "forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked", "capabilities_dropped",
})


def _require_checks(checks, names):
    if (type(checks) is not dict or set(checks) != names
            or any(checks[name] is not True for name in names)):
        raise RuntimeError("offline_authority_boundary_verification_failed")


def demo_policy():
    return parse_policy({
        "schema_version": "1", "policy_version": "offline-authority-owned-fixtures-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET", "HEAD"],
        "max_timeout_seconds": 3, "max_output_bytes": 1024, "max_targets": 1,
        "require_approval": False, "approval_ttl_seconds": 60,
    })


class VerifiedOfflineProvider(OfflineOpenAIProvider):
    """Retain checked booleans for successful parser runs, without plan text."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.evidence = []

    def propose(self, observation, *, control):
        proposal = super().propose(observation, control=control)
        checks = self.boundary_checks
        _require_checks(checks, PARSER_BOUNDARY_NAMES)
        self.evidence.append({"step": len(self.evidence) + 1, "parser_boundary_checks": dict(checks)})
        return proposal


class VerifiedAuthorizedFixtureBackend(AuthorizedFixtureBackend):
    """Check evidence returned by the authority-bound executor before recording it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.evidence = []

    def run(self, action, policy, *, control=None):
        result = super().run(action, policy, control=control)
        checks = result.get("boundary_checks")
        _require_checks(checks, EXECUTOR_BOUNDARY_NAMES)
        injected = action.parameters.path == "/injection"
        if injected:
            rows = result.get("results")
            if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                    or rows[0].get("body") != INJECTION_FIXTURE.decode("ascii")):
                raise RuntimeError("offline_authority_injection_fixture_missing")
        self.evidence.append({
            "action_digest": action.digest, "path": action.parameters.path,
            "executor_boundary_checks": dict(checks), "injection_fixture_received": injected,
        })
        return result


def run_demo(audit_path: Path, *, execute_fixtures=False, on_case=None) -> dict:
    """Run twelve synthetic scenarios through the real Linux process boundaries."""
    config = OpenAIConfig(model="offline-fixture-model", max_output_tokens=1024)
    policy = demo_policy()
    # label, response scenario, broker bounds, session bounds, stop, attempts,
    # successful parser runs, accepted actions, reserved broker calls.
    cases = (
        ("three_step", "three_step", BrokerLimits(), SessionLimits(), "coordinator_done", 3, 3, 3, 3),
        ("injection_target", "injection_target", BrokerLimits(), SessionLimits(), "proposal_denied", 2, 2, 1, 2),
        ("injection_authority", "injection_authority", BrokerLimits(), SessionLimits(), "provider_failed", 2, 1, 1, 2),
        ("refusal", "refusal", BrokerLimits(), SessionLimits(), "provider_failed", 1, 0, 0, 1),
        ("malformed", "malformed", BrokerLimits(), SessionLimits(), "provider_failed", 1, 0, 0, 1),
        ("incomplete", "incomplete", BrokerLimits(), SessionLimits(), "provider_failed", 1, 0, 0, 1),
        ("call_budget", "endless", BrokerLimits(max_calls=2), SessionLimits(), "broker_call_limit", 3, 2, 2, 2),
        ("token_budget", "endless", BrokerLimits(max_reserved_output_tokens=2048), SessionLimits(),
         "broker_token_limit", 3, 2, 2, 2),
        ("request_budget", "endless", BrokerLimits(max_request_bytes=1), SessionLimits(),
         "broker_request_limit", 1, 0, 0, 0),
        ("step_budget", "endless", BrokerLimits(), SessionLimits(max_steps=2), "step_limit", 2, 2, 2, 2),
        ("output_budget", "endless", BrokerLimits(), SessionLimits(max_output_bytes=1024), "output_limit", 2, 2, 1, 2),
        # Real coordinator/parser bootstrap can spend the deadline before the
        # first broker reservation. Either outcome must prevent all execution.
        ("timeout", "timeout", BrokerLimits(), SessionLimits(max_runtime_seconds=1),
         "session_timeout", None, 0, 0, None),
    )
    evidence = []
    with AuditSink(audit_path) as audit:
        for label, scenario, broker_limits, limits, stop, attempts, parsed, accepted, calls in cases:
            provider = VerifiedOfflineProvider(config, audit, OfflineTransport(scenario_responses(scenario)),
                                               limits=broker_limits)
            coordinator = LinuxOfflineCoordinator()
            session_id = str(uuid4())
            backend = (VerifiedAuthorizedFixtureBackend(policy, session_id, limits, execute=True)
                       if execute_fixtures else None)
            authority = AuthoritySession(policy, audit, backend, coordinator, limits,
                                         session_id=session_id, provider=provider)
            summary = authority.run(execute=execute_fixtures, interactive=False)
            counters = dict(provider.broker.snapshot)
            succeeded = accepted if execute_fixtures else 0
            if (summary["control_plane"] != "privsep-offline-v2" or summary["stop_reason"] != stop
                    or (attempts is not None and summary["steps_attempted"] != attempts)
                    or (attempts is None and summary["steps_attempted"] not in (0, 1))
                    or summary["actions_succeeded"] != succeeded or len(provider.evidence) != parsed
                    or authority.controller.policy.digest != policy.digest
                    or summary["output_reserved_bytes"] != accepted * 1024):
                raise RuntimeError("offline_authority_outcome_mismatch: " + label)
            if (set(counters) != {"calls_reserved", "output_tokens_reserved", "request_bytes_reserved"}
                    or any(type(value) is not int or value < 0 for value in counters.values())
                    or (calls is not None and counters["calls_reserved"] != calls)
                    or (calls is None and counters["calls_reserved"] not in (0, 1))
                    or counters["output_tokens_reserved"] != counters["calls_reserved"] * 1024):
                raise RuntimeError("offline_authority_broker_reservation_mismatch: " + label)
            # Timeout and broker budget exceptions terminate the supervisor;
            # no coordinator boundary success is asserted for those outcomes.
            coordinator_checks = coordinator.boundary_checks
            if label not in {"timeout", "call_budget", "token_budget", "request_budget"}:
                _require_checks(coordinator_checks, BOUNDARY_NAMES)
            elif coordinator_checks is not None:
                _require_checks(coordinator_checks, BOUNDARY_NAMES)
            if execute_fixtures and (len(backend.evidence) != succeeded
                    or backend.snapshot["executions_reserved"] != succeeded
                    or backend.snapshot["output_bytes_reserved"] != succeeded * 1024):
                raise RuntimeError("offline_authority_executor_reservation_mismatch: " + label)
            if label == "injection_target" and summary["steps"][-1]["reasons"] != ["target_out_of_scope"]:
                raise RuntimeError("offline_authority_target_denial_mismatch")
            if label in {"call_budget", "token_budget", "request_budget"} and provider.broker.last_error != stop:
                raise RuntimeError("offline_authority_broker_failure_missing")
            result = {
                "case": label, **summary, "provider": PROVIDER_NAME, "live_calls_enabled": False,
                "broker_id": provider.broker.broker_id, "broker": counters,
                "broker_error": provider.broker.last_error,
                "coordinator_boundary_checks": coordinator_checks, "parser_executions": provider.evidence,
                "tool_executions": backend.evidence if execute_fixtures else [], "policy_unchanged": True,
            }
            evidence.append(result)
            if on_case is not None:
                on_case(result)
    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    for case in evidence:
        events = [row for row in records if row.get("session_id") == case["session_id"]]
        starts = [row for row in events if row["event_type"] == "execution_started"]
        finishes = [row for row in events if row["event_type"] == "execution_finished"]
        bindings = [row for row in events if row["event_type"] == "offline_provider_session_bound"]
        if (len(starts) != case["actions_succeeded"] or len(finishes) != len(starts)
                or sum(row["event_type"] == "session_finished" for row in events) != 1
                or len(bindings) != 1 or bindings[0]["broker_id"] != case["broker_id"]
                or any(row["event_type"].startswith("approval_") or row.get("approval_reference") is not None
                       for row in events)):
            raise RuntimeError("offline_authority_audit_mismatch")
    return {
        "demo": "passed", "provider": PROVIDER_NAME, "live_calls_enabled": False,
        "mode": "execute_owned_fixtures" if execute_fixtures else "dry_run_tools",
        "policy_version": policy.policy_version, "audit": str(audit_path), "cases": evidence,
        "limits": "Fixed synthetic responses; token counts are reservations. No API, model or human approval validation.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="retain durable JSONL evidence at this private operator path")
    parser.add_argument("--execute-fixtures", action="store_true", help="execute owned isolated HTTP fixtures")
    args = parser.parse_args()
    path = args.audit or Path(tempfile.mkdtemp(prefix="recon-offline-authority-demo-")) / "audit.jsonl"
    print(json.dumps({
        "provider": PROVIDER_NAME, "audit": str(path), "live_calls_enabled": False,
        "note": "Fixed synthetic responses; isolated coordinator and parser; automatic owned fixture policy; no human grants.",
    }), flush=True)
    try:
        report = run_demo(path, execute_fixtures=args.execute_fixtures,
                          on_case=lambda case: print(json.dumps(case, sort_keys=True), flush=True))
    except IsolationUnavailable as exc:
        print(json.dumps({"demo": "blocked", "reason": exc.code}))
        return 2
    except (RuntimeError, OSError, ValueError):
        print(json.dumps({"demo": "failed", "reason": "offline_authority_demo_validation_failed"}))
        return 1
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
