"""Portable negative proposal checks; native proof belongs to the Linux suite."""

from copy import deepcopy
import time

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent import name_tls_probes as probes
from recon_cockpit.secure_agent.controller import Controller, IsolationUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action
from test_name_tls_authority import Harness, setup


class Audit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(deepcopy(event))


class StaticBackend:
    name = contract.BACKEND

    def __init__(self, selected, owner):
        self.selected, self.owner = selected, owner
        self.checks = []

    def check_available(self, action):
        self.checks.append(action.to_dict())
        if not contract.profile_allows(action, self.selected, session_id=self.owner["session_id"]):
            raise IsolationUnavailable("outside selected plan")

    def run(self, *args, **kwargs):
        pytest.fail("a portable mutation check must not execute a service")


def outcomes(h):
    return [{"untrusted_result": {"name_tls_ledger": h.ledger.snapshot()}}]


@pytest.mark.parametrize("case,count", [("N4", 3), ("N9", 1), ("N10", 1)])
def test_name_mutations_stop_at_typed_validation_before_backend(case, count):
    h = Harness(case=case)
    if case != "N4":
        h.dns()
    audit = Audit()
    backend = StaticBackend(h.selected, h.identity)
    controller = Controller(contract.policy_for_selection(h.selected, require_approval=False), audit,
                            backend, session_id=h.identity["session_id"])
    receipt = probes.run_probe_cases(controller, backend, selected=h.selected, identity=h.identity,
                                    control=ExecutionControl(time.monotonic() + 5),
                                    outcomes=[] if case == "N4" else outcomes(h))
    assert receipt["status"] == "attempted" and len(receipt["attempts"]) == count
    assert backend.checks == []
    assert all(row["outcome"]["execution_status"] == "rejected" for row in receipt["attempts"])
    assert all(row["expected_guard"] == "typed_validation" for row in receipt["attempts"])
    assert all(row["event_type"] == "validation_rejected" for row in audit.events)


def test_changed_dns_replay_uses_actual_old_binding_and_reports_static_guard():
    h = Harness(case="N1")
    h.dns()
    saved = outcomes(h)
    h.clock = .3
    h.dns("dns_2")
    saved.extend(outcomes(h))
    backend, audit = StaticBackend(h.selected, h.identity), Audit()
    controller = Controller(contract.policy_for_selection(h.selected, require_approval=False), audit,
                            backend, session_id=h.identity["session_id"])
    receipt = probes.run_probe_cases(controller, backend, selected=h.selected, identity=h.identity,
        control=ExecutionControl(time.monotonic() + 5), outcomes=saved)
    attempt = receipt["attempts"][0]
    assert attempt["proposal"]["parameters"]["observation_generation"] == 1
    assert attempt["outcome"]["reasons"] == ["isolation_unavailable"]
    assert attempt["expected_guard"] == "static_profile" and len(backend.checks) == 1
    assert not any(event["event_type"] == "execution_started" for event in audit.events)


def test_n14_attempt_admission_does_not_expand_owner_execution_plan():
    h = Harness(case="N14")
    h.dns()
    assert contract.operation_plan(h.selected) == ("dns_1",)
    assert contract.attempt_slots(h.selected) == ("http", "tls")
    attempts = probes.proposals(h.selected, h.identity, outcomes(h))
    assert [row[2] for row in attempts] == ["owner_expiry", "owner_terminal"]
    for _, raw, _ in attempts:
        assert contract.profile_allows(parse_action(raw), h.selected, session_id=h.identity["session_id"])
    h.clock = 1.01
    assert h.arm("http")["reason"] == "binding_expired"
    assert h.ledger.snapshot()["counters"]["actions"] == 1
    assert h.ledger.snapshot()["counters"]["connections"] == 1


@pytest.mark.parametrize("case,expected", [("O1", "not_required"), ("N15", "incomplete"), ("N14", "incomplete")])
def test_missing_native_or_real_grant_proof_never_becomes_a_pass(case, expected):
    selected, owner = setup(case)
    backend, audit = StaticBackend(selected, owner), Audit()
    controller = Controller(contract.policy_for_selection(selected, require_approval=False), audit,
                            backend, session_id=owner["session_id"])
    receipt = probes.run_probe_cases(controller, backend, selected=selected, identity=owner,
        control=ExecutionControl(time.monotonic() + 5), outcomes=[])
    assert receipt["status"] == expected and receipt["attempts"] == []
    assert "passed" not in receipt and audit.events == [] and backend.checks == []


def test_fake_clock_cannot_schedule_a_native_expiry_probe():
    selected, owner = setup("N14")
    backend = StaticBackend(selected, owner)
    controller = Controller(contract.policy_for_selection(selected, require_approval=False), Audit(),
                            backend, session_id=owner["session_id"])
    with pytest.raises(ValueError, match="invalid_name_tls_probe_context"):
        probes.run_probe_cases(controller, backend, selected=selected, identity=owner,
                               control=ExecutionControl(10, clock=lambda: 0), outcomes=[])
