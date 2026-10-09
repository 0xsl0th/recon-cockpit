"""Authority state and failure behavior with native transport replaced by a fake."""

import base64
from copy import deepcopy
import time
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import configurable_backend as backend_module, configurable_contract as contract
from recon_cockpit.secure_agent import configurable_runtime as runtime, configurable_parser_runtime as parser_runtime
from recon_cockpit.secure_agent.configurable_lab import ConfigurableLab
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_configurable_parser import scope
from test_secure_configurable_contract import observation, result
from test_secure_configurable_runtime import manifests


HOST_NAMESPACES = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}


def setup_backend(monkeypatch, *, limits=None, execute=True):
    limits = limits or SessionLimits(**contract.LIMITS)
    policy = contract.policy_for_scope(scope(), require_approval=False)
    lab = ConfigurableLab(scope(), str(UUID(int=999)), limits, execute=execute)
    backend = backend_module.AuthorizedConfigurableBackend(policy, lab.session_id, limits, lab, execute=execute)
    backend._configurable_manifests = manifests()
    calls, snapshots = [], []
    # The transport is fake, so this portable fixture must not inspect /proc.
    monkeypatch.setattr(backend_module, "_namespaces", lambda: dict(HOST_NAMESPACES))
    monkeypatch.setattr(backend, "check_available", lambda *_: [lab.endpoint_lab(name) for name in ("http", "ssh")])
    for name in ("http", "ssh"):
        selected = lab.endpoint_lab(name)
        def start(control, owner=selected):
            if owner._closed:
                raise IsolationUnavailable("owner closed")
            owner._started, owner._control = True, control
        def snapshot(control, *, minimum_connections, minimum_requests, owner=selected):
            snapshots.append((owner.endpoint_name, minimum_connections, minimum_requests))
            return dict(owner._counts)
        monkeypatch.setattr(selected, "start", start)
        monkeypatch.setattr(selected, "snapshot", snapshot)
    def runner(**kwargs):
        calls.append(kwargs)
        step = kwargs["launch"]["launch"]["sequence"]
        name = contract.ENDPOINTS[step - 1]
        counts = result(step, lab.identity)["owned_lab"]["endpoints"][name]
        kwargs["lab"]._counts = {key: counts[key] for key in ("connection_count", "request_count")}
        raw = base64.b64encode(b"raw evidence").decode()
        return {"status": "succeeded", "truncated": False, "raw_output_base64": raw,
                "raw_stderr_base64": "", "results": [{"raw_response": raw}] if step == 2 else []}
    monkeypatch.setattr(runtime, "run_configurable_tool_owned", runner)
    def parse(tool, raw, stderr, *, scope, endpoint_id, **kwargs):
        step = 2 if tool == contract.HEADERS else 4 if tool == contract.SSH else 1 if endpoint_id == "http" else 3
        return observation(step)
    monkeypatch.setattr(parser_runtime, "parse_isolated_tool_output", parse)
    return backend, policy, calls, snapshots


def run(backend, policy, step, control):
    return backend.run(parse_action(contract.action(scope(), step)), policy, control=control)


def test_complete_useful_work_preserves_owner_selection_scope_and_each_runtime(monkeypatch):
    backend, policy, calls, snapshots = setup_backend(monkeypatch)
    backend._closure = {"stdlib": "/stdlib", "files": ["/lib/libc.so"], "configurable_runtime": manifests()}
    control = ExecutionControl(time.monotonic() + 55)
    previous = None
    for step in range(1, 5):
        value = run(backend, policy, step, control)
        previous = contract.validate_result_context(value, backend.lab.identity, previous=previous,
            tool_id=contract.TOOL_IDS[step - 1], execution_status="succeeded")
        assert backend.snapshot["executions_reserved"] == step
        assert backend.snapshot["output_bytes_reserved"] == contract.OUTPUT_RESERVATIONS[step]
        assert calls[-1]["lab"].endpoint_name == contract.ENDPOINTS[step - 1]
        assert calls[-1]["launch"]["launch"]["host_namespaces"] == HOST_NAMESPACES
        assert calls[-1]["launch"]["launch"]["host_namespaces"] is not HOST_NAMESPACES
        assert calls[-1]["closure"]["configurable_runtime"] == (None if step == 2 else manifests()[contract.TOOL_IDS[step - 1]])
    assert snapshots == [("http", 2, 1), ("http", 3, 2), ("ssh", 2, 1), ("ssh", 3, 2)]
    receipt = backend.close()
    assert all(row["request_count"] == 2 for row in receipt["endpoints"].values())


@pytest.mark.parametrize("step", [2, 3, 4])
def test_wrong_initial_step_never_starts_owner_or_reserves_budget(monkeypatch, step):
    backend, policy, calls, _ = setup_backend(monkeypatch)
    with pytest.raises(IsolationUnavailable):
        run(backend, policy, step, ExecutionControl(time.monotonic() + 55))
    assert not calls and backend.snapshot["executions_reserved"] == 0
    assert backend.lab._closed


@pytest.mark.parametrize("fault", ["scope", "lab_scope", "policy", "stored_policy", "limits", "output", "predecessor"])
def test_mutated_authority_cannot_launch_after_one_valid_result(monkeypatch, fault):
    backend, policy, calls, _ = setup_backend(monkeypatch)
    control = ExecutionControl(time.monotonic() + 55)
    run(backend, policy, 1, control)
    if fault == "scope": backend.scope["http"]["path"] = "/changed"
    elif fault == "lab_scope": backend.lab.scope["ssh"]["port"] += 1
    elif fault == "policy": policy = parse_policy({**policy.to_dict(), "require_approval": True})
    elif fault == "stored_policy": backend._policy = parse_policy({**policy.to_dict(), "require_approval": True})
    elif fault == "limits": backend._limits = SessionLimits(4, 59, 26624)
    elif fault == "output": backend._output += 1
    else: backend._completed_step = 0
    with pytest.raises((IsolationUnavailable, ValueError)):
        run(backend, policy, 2, control)
    assert len(calls) == 1 and backend.lab._closed
    assert backend.snapshot["executions_reserved"] == 1


def test_replacing_session_control_closes_both_owners_and_preserves_reservation(monkeypatch):
    backend, policy, calls, _ = setup_backend(monkeypatch)
    control = ExecutionControl(time.monotonic() + 55)
    run(backend, policy, 1, control)
    with pytest.raises(IsolationUnavailable, match="cannot be replaced"):
        run(backend, policy, 2, ExecutionControl(time.monotonic() + 55))
    assert len(calls) == 1 and backend.snapshot["output_bytes_reserved"] == 8192
    assert all(owner._closed for owner in backend.lab._endpoints.values())


@pytest.mark.parametrize("fault", ["timeout", "truncated", "parse_rejected", "wrong_protocol"])
def test_incomplete_or_wrong_protocol_cannot_unlock_followup(monkeypatch, fault):
    backend, policy, calls, _ = setup_backend(monkeypatch)
    original = runtime.run_configurable_tool_owned
    def runner(**kwargs):
        value = original(**kwargs)
        if fault == "timeout": value["status"] = "timeout"
        elif fault == "truncated": value["truncated"] = True
        return value
    monkeypatch.setattr(runtime, "run_configurable_tool_owned", runner)
    if fault == "parse_rejected":
        def reject(*a, **k): raise ValueError("untrusted parser output")
        monkeypatch.setattr(parser_runtime, "parse_isolated_tool_output", reject)
    elif fault == "wrong_protocol":
        observed = observation(1)
        observed["service"].update(name="ssh", product="OpenSSH")
        monkeypatch.setattr(parser_runtime, "parse_isolated_tool_output", lambda *a, **k: observed)
    control = ExecutionControl(time.monotonic() + 55)
    first = run(backend, policy, 1, control)
    assert backend._completed_step == 0
    with pytest.raises(IsolationUnavailable): run(backend, policy, 2, control)
    assert len(calls) == 1 and backend.snapshot["executions_reserved"] == 1
    assert backend.lab._closed


def test_native_setup_failure_consumes_reservation_without_restart(monkeypatch):
    backend, policy, calls, _ = setup_backend(monkeypatch)
    attempts = []
    def refuse(**kwargs):
        attempts.append(kwargs)
        raise IsolationUnavailable("native confinement failed")
    monkeypatch.setattr(runtime, "run_configurable_tool_owned", refuse)
    control = ExecutionControl(time.monotonic() + 55)
    with pytest.raises(IsolationUnavailable, match="confinement failed"):
        run(backend, policy, 1, control)
    assert backend.snapshot == {"executions_reserved": 1, "output_bytes_reserved": 8192}
    with pytest.raises(IsolationUnavailable): run(backend, policy, 1, control)
    assert len(attempts) == 1 and all(owner._closed for owner in backend.lab._endpoints.values())


@pytest.mark.parametrize("limits", [SessionLimits(1, 60, 26624), SessionLimits(4, 60, 8192)])
def test_shortened_ceilings_allow_first_action_and_refuse_second_without_refund(monkeypatch, limits):
    backend, policy, calls, _ = setup_backend(monkeypatch, limits=limits)
    control = ExecutionControl(time.monotonic() + 55)
    run(backend, policy, 1, control)
    with pytest.raises(IsolationUnavailable, match="exhausted"):
        run(backend, policy, 2, control)
    assert len(calls) == 1 and backend.snapshot["executions_reserved"] == 1


def test_cancelled_control_never_reserves_or_starts_an_owner(monkeypatch):
    backend, policy, calls, _ = setup_backend(monkeypatch)
    with pytest.raises(ExecutionStopped):
        run(backend, policy, 1, ExecutionControl(time.monotonic() - 1))
    assert not calls and backend.snapshot["executions_reserved"] == 0
    assert backend.lab._closed


def test_dry_run_backend_cannot_be_promoted_to_execution_by_a_valid_action(monkeypatch):
    backend, policy, calls, _ = setup_backend(monkeypatch, execute=False)
    with pytest.raises(IsolationUnavailable):
        run(backend, policy, 1, ExecutionControl(time.monotonic() + 55))
    assert not calls and backend.snapshot["executions_reserved"] == 0


def test_runtime_pin_change_prevents_owner_start_and_any_budget_reservation(monkeypatch):
    backend, policy, calls, _ = setup_backend(monkeypatch)
    backend._closure = {"stdlib": "/stdlib", "files": ["/lib/libc.so"], "configurable_runtime": manifests()}
    backend._closure["configurable_runtime"][contract.NMAP]["files"][0]["sha256"] = "c" * 64
    with pytest.raises(IsolationUnavailable, match="runtime pin changed"):
        run(backend, policy, 1, ExecutionControl(time.monotonic() + 55))
    assert not calls and backend.snapshot["executions_reserved"] == 0
