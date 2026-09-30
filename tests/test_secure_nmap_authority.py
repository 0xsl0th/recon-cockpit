"""Nmap proposals retain the existing independent approval/audit boundaries."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent.audit import AuditSink, AuditUnavailable
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.nmap_contract import action


class NeverBackend:
    name = "TEST-NEVER-LAUNCH"

    def check_available(self, *_):
        pytest.fail("Nmap backend inspected before approval")

    def run(self, *_a, **_k):
        pytest.fail("Nmap backend launched without authority")


def policy():
    return parse_policy(json.loads(Path("examples/secure-agent-nmap-policy.json").read_text()))


@pytest.mark.parametrize("interactive,expected", [
    (False, "noninteractive_approval_required"), (True, "approval_missing"),
])
def test_nmap_fresh_approval_is_required_before_backend_availability(tmp_path, interactive, expected):
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        result = Controller(policy(), audit, NeverBackend()).submit(
            action("a", 1), execute=True, interactive=interactive,
        )
    assert result["execution_status"] == "blocked" and result["reasons"] == [expected]
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert not any(row["event_type"] == "execution_started" for row in records)


def test_unavailable_durable_audit_prevents_nmap_launch_and_poison_controller(tmp_path):
    class AvailabilityOnly:
        name = "TEST-NEVER-LAUNCH"

        def check_available(self, *_):
            pass

        def run(self, *_a, **_k):
            pytest.fail("Nmap launched without durable execution_started")

    class FailingAudit:
        def emit(self, event):
            if event["event_type"] == "execution_started":
                raise AuditUnavailable("audit_unavailable")

    # This unit policy explicitly avoids impersonating a human grant. The test
    # exercises the separate durable audit precondition without any tool call.
    controller = Controller(replace(policy(), require_approval=False), FailingAudit(), AvailabilityOnly())
    with pytest.raises(AuditUnavailable):
        controller.submit(action("a", 1), execute=True)
    with pytest.raises(AuditUnavailable):
        controller.submit(action("a", 1), execute=True)


@pytest.mark.parametrize("changes,reason", [
    ({"target": "127.0.0.2"}, "target_out_of_scope"),
    ({"parameters": {"port": 8081, "timeout_seconds": 5, "max_output_bytes": 16384}}, "port_not_allowed"),
])
def test_out_of_scope_nmap_proposals_are_recorded_before_execution(tmp_path, changes, reason):
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        result = Controller(policy(), audit, NeverBackend()).submit({**action("a", 1), **changes}, execute=True)
    assert result["execution_status"] == "blocked" and reason in result["reasons"]
    event = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert event["event_type"] == "policy_decision" and event["decision"] == "deny"
    assert event["action_digest"] == result["action_digest"]
