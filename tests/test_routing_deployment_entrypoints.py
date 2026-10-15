"""Closed deployment inputs must fail before runtime inspection or authority."""
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import routing, routing_contract as contract


@pytest.mark.parametrize("deployment", ("apache-C", "nginx-b", "nginx", "http://127.0.0.1", True, {}, []))
def test_invalid_deployment_never_reaches_preflight(tmp_path, monkeypatch, deployment):
    monkeypatch.setattr(contract, "inspect_runtime", lambda *_: pytest.fail("invalid deployment reached runtime"))
    directory = tmp_path / "evidence"
    with pytest.raises(ValueError):
        routing.run_trial(directory, selectors=["http_headers"], deployment=deployment, execute=True)
    assert not directory.exists()


@pytest.mark.parametrize("deployment", (None, *contract.DEPLOYMENTS))
def test_runner_binds_selected_deployment_before_preflight(tmp_path, monkeypatch, deployment):
    class PreflightReached(Exception):
        pass
    def inspect(selected, control):
        assert selected == contract.selection(deployment=deployment)
        control.check()
        raise PreflightReached
    monkeypatch.setattr(contract, "inspect_runtime", inspect)
    with pytest.raises(PreflightReached):
        routing.run_trial(tmp_path / "evidence", selectors=["http_headers"], deployment=deployment)


def test_cli_rejects_arbitrary_deployment_before_runtime(tmp_path):
    directory = tmp_path / "evidence"
    result = subprocess.run([sys.executable, "scripts/disconnected_routing.py", "run",
        "--action", "http_headers", "--directory", str(directory), "--deployment", "apache-C"],
        capture_output=True, timeout=10)
    assert result.returncode == 2 and b"invalid choice" in result.stderr
    assert not directory.exists()


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
def test_launcher_initial_binds_deployment_and_runtime_before_witnessed_launch(deployment):
    from copy import deepcopy
    from recon_cockpit.secure_agent import launcher_protocol as protocol
    from test_routing_authority import initial
    from test_routing_contract import identity, runtime
    value = initial()
    selected = contract.selection(deployment=deployment)
    value["configuration"].update(case=selected, owned_lab=identity(deployment=deployment),
        policy=contract.policy_for_selection(selected).to_dict())
    value["runtime"]["routing_runtime"] = runtime(deployment)
    assert protocol.initial(value, 100) == value["configuration"]
    for other in contract.DEPLOYMENTS:
        if other == deployment:
            continue
        changed = deepcopy(value)
        changed["runtime"]["routing_runtime"] = runtime(other)
        with pytest.raises(ValueError):
            protocol.initial(changed, 100)
    for field in ("audit_witness", "approval_witness"):
        changed = deepcopy(value)
        del changed[field]
        with pytest.raises(ValueError):
            protocol.initial(changed, 100)
