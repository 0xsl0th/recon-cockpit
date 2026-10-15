"""Direct confined calls cannot continue after a v3 declared-negative attempt."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import time

import pytest

from recon_cockpit.secure_agent import routing_contract as contract
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.routing_backend import ConfinedRoutingBackend
from test_routing_authority import initial
from test_routing_matrix_contract import identity, runtime


def backend_with_prior_attempt(selected, selector):
    value = initial()
    value["configuration"].update(case=selected, owned_lab=identity(selected),
        policy=contract.policy_for_selection(selected, require_approval=False).to_dict())
    value["runtime"]["routing_runtime"] = runtime(selected)
    backend = ConfinedRoutingBackend(value["configuration"], value["runtime"])
    backend._used = {selector}
    backend._sequence = 1
    backend._output = contract.action_bounds(selector)["output_bytes"]
    return backend


NEGATIVES = tuple(profile for profile in contract.CASE_PROFILES if "_N" in profile)


@pytest.mark.parametrize("deployment", ("nginx-A", "apache-B"))
@pytest.mark.parametrize("profile", NEGATIVES)
def test_direct_negative_continuation_refuses_before_reservation_start_or_service(monkeypatch, deployment, profile):
    selected = contract.selection(deployment=deployment, case_profile=profile)
    first, _ = profile.rsplit("_", 1)
    later = next(name for name in contract.SELECTORS if name != first)
    backend = backend_with_prior_attempt(selected, first)
    calls = []
    monkeypatch.setattr(backend, "check_available", lambda *_: calls.append("availability"))
    monkeypatch.setattr(backend.lab, "start", lambda *_: calls.append("startup"))
    backend.lab.services = SimpleNamespace(
        run_action=lambda *_: calls.append("service"), close=lambda: calls.append("cleanup"))
    before = dict(backend.snapshot), deepcopy(backend._used)
    with pytest.raises(IsolationUnavailable, match="declared negative already attempted"):
        backend.run(parse_action(contract.action(selected, later)), backend._policy,
                    control=ExecutionControl(time.monotonic() + 30))
    assert (dict(backend.snapshot), backend._used) == before
    assert calls == ["cleanup"] and backend.lab._closed
    assert backend._control is None and not backend._lock.locked()


@pytest.mark.parametrize("deployment,profile", ((None, None), ("apache-B", None),
    ("nginx-A", "baseline"), ("apache-B", "http_headers_R1"), ("nginx-B", "ssh_keys_N3")))
def test_legacy_and_nonnegative_prior_slots_still_reach_startup(monkeypatch, deployment, profile):
    selected = contract.selection(deployment=deployment, case_profile=profile)
    backend = backend_with_prior_attempt(selected, "http_headers")
    calls = []
    class ReachedStartup(Exception): pass
    def start(_):
        calls.append("startup")
        raise ReachedStartup
    monkeypatch.setattr(backend.lab, "start", start)
    with pytest.raises(ReachedStartup):
        backend.run(parse_action(contract.action(selected, "ssh_keys")), backend._policy,
                    control=ExecutionControl(time.monotonic() + 30))
    assert calls == ["startup"]
    assert dict(backend.snapshot) == {"executions_reserved": 2, "output_bytes_reserved": 10240}
    assert backend._used == {"http_headers", "ssh_keys"}


def test_direct_native_stop_observer_pins_existing_gate_and_prestartup_tripwire():
    from recon_cockpit.secure_agent import routing_backend
    from test_routing_matrix_direct_linux import _observe_stop_before_second_start
    source = Path(routing_backend.__file__).read_text()
    observed = _observe_stop_before_second_start(source)
    assert "EXPECTED-ROUTING-DECLARED-NEGATIVE-STOP" in observed
    assert "UNEXPECTED-ROUTING-LATER-LAB-START" in observed
    assert source == Path(routing_backend.__file__).read_text()
