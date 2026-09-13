"""Verify offline OpenAI-format sessions through the real Linux planner sandbox.

All provider responses are fixed local fixtures. No API call, credential, model
access, or human approval is involved. Tools are dry-run by default;
--execute-fixtures uses an explicit automatic policy for owned isolated HTTP.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import UnavailableBackend
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_broker import BrokerLimits, OfflineTransport
from recon_cockpit.secure_agent.openai_fixtures import scenario_responses
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig
from recon_cockpit.secure_agent.openai_provider import OfflineOpenAIProvider
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES
from recon_cockpit.secure_agent.session import SessionLimits, SessionRunner

if __package__:
    from .secure_agent_session_demo import VerifiedFixtureBackend, demo_policy
else:
    from secure_agent_session_demo import VerifiedFixtureBackend, demo_policy


def _require_planner_checks(checks):
    if (type(checks) is not dict or set(checks) != BOUNDARY_NAMES
            or any(checks[name] is not True for name in BOUNDARY_NAMES)):
        raise RuntimeError("offline planner boundary verification failed")


class VerifiedOfflineProvider(OfflineOpenAIProvider):
    """Record checked booleans after successful isolated proposal parsing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.evidence = []

    def propose(self, observation, *, control):
        proposal = super().propose(observation, control=control)
        checks = self.boundary_checks
        _require_planner_checks(checks)
        self.evidence.append({"step": len(self.evidence) + 1, "boundary_checks": checks})
        return proposal


def run_demo(audit_path: Path, *, execute_fixtures=False, on_case=None) -> dict:
    """Run nine offline cases and return safe summaries and reserved budgets."""
    config = OpenAIConfig(model="offline-fixture-model", max_output_tokens=1024)
    policy = demo_policy()
    cases = (
        # label, response scenario, broker bounds, session bounds, stop, attempts,
        # successfully parsed proposals, accepted tool actions, reserved calls.
        ("three_step", "three_step", BrokerLimits(), SessionLimits(), "planner_done", 3, 3, 3, 3),
        ("injection_target", "injection_target", BrokerLimits(), SessionLimits(), "proposal_denied", 2, 2, 1, 2),
        ("injection_authority", "injection_authority", BrokerLimits(), SessionLimits(),
         "session_component_failed", 2, 1, 1, 2),
        ("refusal", "refusal", BrokerLimits(), SessionLimits(), "session_component_failed", 1, 0, 0, 1),
        ("malformed", "malformed", BrokerLimits(), SessionLimits(), "session_component_failed", 1, 0, 0, 1),
        ("incomplete", "incomplete", BrokerLimits(), SessionLimits(), "session_component_failed", 1, 0, 0, 1),
        ("call_budget", "endless", BrokerLimits(max_calls=2), SessionLimits(), "broker_call_limit", 3, 2, 2, 2),
        ("token_budget", "endless", BrokerLimits(max_reserved_output_tokens=2048), SessionLimits(),
         "broker_token_limit", 3, 2, 2, 2),
        ("timeout", "timeout", BrokerLimits(), SessionLimits(max_runtime_seconds=1),
         "session_timeout", 1, 0, 0, None),
    )
    evidence = []
    with AuditSink(audit_path) as audit:
        for label, scenario, broker_limits, session_limits, stop, attempts, parsed, accepted, calls in cases:
            provider = VerifiedOfflineProvider(config, audit, OfflineTransport(scenario_responses(scenario)),
                                               limits=broker_limits)
            backend = VerifiedFixtureBackend() if execute_fixtures else UnavailableBackend()
            runner = SessionRunner(policy, audit, backend, provider, session_limits)
            provider.bind_session(runner.session_id)
            summary = runner.run(execute=execute_fixtures)
            counters = dict(provider.broker.snapshot)
            succeeded = accepted if execute_fixtures else 0
            if (summary["stop_reason"] != stop or summary["steps_attempted"] != attempts
                    or summary["actions_succeeded"] != succeeded or len(provider.evidence) != parsed
                    or runner.controller.policy.digest != policy.digest
                    or summary["output_reserved_bytes"] != accepted * 1024):
                raise RuntimeError("offline session outcome mismatch: " + label)
            if (set(counters) != {"calls_reserved", "output_tokens_reserved", "request_bytes_reserved"}
                    or any(type(value) is not int or value < 0 for value in counters.values())
                    or (calls is not None and counters["calls_reserved"] != calls)
                    or (calls is None and counters["calls_reserved"] not in (0, 1))
                    or counters["output_tokens_reserved"] != counters["calls_reserved"] * 1024):
                raise RuntimeError("offline broker reservation mismatch: " + label)
            if execute_fixtures and (backend.calls != succeeded or len(backend.evidence) != succeeded):
                raise RuntimeError("offline session executed unexpected tools: " + label)
            if label == "injection_target" and summary["steps"][-1]["reasons"] != ["target_out_of_scope"]:
                raise RuntimeError("offline target escalation was not policy-denied")
            if label.endswith("_budget") and provider.broker.last_error != stop:
                raise RuntimeError("offline broker budget failure was not retained")
            result = {
                "case": label, **summary, "broker_id": provider.broker.broker_id,
                "broker_counters": counters, "broker_last_error": provider.broker.last_error,
                "planner_executions": provider.evidence,
                "tool_executions": backend.evidence if execute_fixtures else [], "policy_unchanged": True,
            }
            evidence.append(result)
            if on_case is not None:
                on_case(result)
    return {
        "demo": "passed", "provider": OfflineOpenAIProvider.name,
        "mode": "execute_owned_fixtures" if execute_fixtures else "dry_run_tools",
        "policy_version": policy.policy_version, "audit": str(audit_path), "cases": evidence,
        "limits": "Scripted offline Responses-format replies; no API or model validation. Token counts are reservations.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="retain JSONL evidence at this private operator path")
    parser.add_argument("--execute-fixtures", action="store_true", help="execute owned isolated HTTP fixtures")
    args = parser.parse_args()
    audit_path = args.audit or Path(tempfile.mkdtemp(prefix="recon-openai-demo-")) / "audit.jsonl"
    print(json.dumps({
        "provider": OfflineOpenAIProvider.name, "audit": str(audit_path),
        "note": "Fixed local responses and isolated parser; explicit automatic fixture policy; no API or human grants.",
    }))
    try:
        report = run_demo(audit_path, execute_fixtures=args.execute_fixtures,
                          on_case=lambda case: print(json.dumps(case, sort_keys=True)))
    except IsolationUnavailable as exc:
        print(json.dumps({"demo": "blocked", "reason": exc.code}))
        return 2
    except (RuntimeError, OSError, ValueError):
        print(json.dumps({"demo": "failed", "reason": "offline_openai_demo_validation_failed"}))
        return 1
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
