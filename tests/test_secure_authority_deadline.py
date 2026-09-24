"""Absolute enclosing deadlines cannot be extended by delayed session setup."""

import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.session import SessionLimits


def policy():
    return parse_policy((Path(__file__).resolve().parents[1] / "examples/secure-agent-evaluation-policy.json").read_bytes())


class Coordinator:
    def __init__(self, clock, advance=0):
        self.clock = clock
        self.advance = advance
        self.deadlines = []

    def run(self, init, exchange, *, control):
        self.deadlines.append(control.deadline)
        self.clock[0] += self.advance
        control.check()
        value = json.loads(init)
        exchange(json.dumps({**value, "sequence": 1, "plan": {
            "schema_version": "1", "action": None, "done": True}}).encode(), control=control)
        return json.dumps({**value, "status": "closed"}).encode()


@pytest.mark.parametrize("deadline,expected", [(None, 105), (500, 105), (101, 101)])
def test_outer_deadline_only_shortens_current_session(tmp_path, deadline, expected):
    clock = [100]
    coordinator = Coordinator(clock)
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        runner = AuthoritySession(policy(), audit, None, coordinator, SessionLimits(max_runtime_seconds=5),
                                  clock=lambda: clock[0], deadline=deadline)
        result = runner.run()
    assert coordinator.deadlines == [expected] and result["session_status"] == "completed"


def test_setup_delay_does_not_renew_enclosing_deadline(tmp_path):
    clock = [100]
    coordinator = Coordinator(clock)
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        runner = AuthoritySession(policy(), audit, None, coordinator, clock=lambda: clock[0], deadline=102)
        clock[0] = 103
        result = runner.run(execute=True)
    assert result["stop_reason"] == "session_timeout" and coordinator.deadlines == []


def test_active_session_obeys_outer_deadline(tmp_path):
    clock = [100]
    coordinator = Coordinator(clock, advance=3)
    with AuditSink(tmp_path / "audit.jsonl") as audit:
        result = AuthoritySession(policy(), audit, None, coordinator, clock=lambda: clock[0], deadline=102).run()
    assert result["stop_reason"] == "session_timeout" and coordinator.deadlines == [102]


@pytest.mark.parametrize("deadline", [True, "100", float("nan"), float("inf"), float("-inf")])
def test_invalid_deadline_rejected(tmp_path, deadline):
    with AuditSink(tmp_path / "audit.jsonl") as audit, pytest.raises(ValueError, match="invalid_authority_deadline"):
        AuthoritySession(policy(), audit, None, None, deadline=deadline)
