"""Matrix inputs are validated before preflight; a negative never launches a later slot."""

from contextlib import nullcontext
from copy import deepcopy
import runpy
import subprocess
import sys
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import routing, routing_contract as contract


@pytest.mark.parametrize("deployment,profile,budget", (
    (None, "baseline", "ordinary"), (None, "http_headers_N1", "ordinary"),
    ("apache-C", "baseline", "ordinary"), ("nginx-A", "ssh_keys_N7", "ordinary"),
    ("apache-A", "http_headers_R2", "http_one"), ("nginx-B", "ssh_keys_N3", "ssh_zero"),
    ("nginx-A", True, "ordinary"), ("nginx-A", {}, "ordinary"),
))
def test_invalid_matrix_combination_never_reaches_runtime_or_creates_evidence(tmp_path, monkeypatch, deployment, profile, budget):
    monkeypatch.setattr(contract, "inspect_runtime", lambda *_: pytest.fail("invalid profile reached runtime"))
    directory = tmp_path / "evidence"
    with pytest.raises(ValueError):
        routing.run_trial(directory, selectors=["http_headers"], deployment=deployment,
                          case_profile=profile, budget_case=budget, execute=True)
    assert not directory.exists()


@pytest.mark.parametrize("profile", contract.CASE_PROFILES)
def test_runner_binds_the_matrix_before_preflight(tmp_path, monkeypatch, profile):
    class PreflightReached(Exception): pass
    def inspect(selected, control):
        assert selected == contract.selection(deployment="apache-B", case_profile=profile)
        control.check()
        raise PreflightReached
    monkeypatch.setattr(contract, "inspect_runtime", inspect)
    with pytest.raises(PreflightReached):
        routing.run_trial(tmp_path / "evidence", selectors=["http_headers"],
                          deployment="apache-B", case_profile=profile)


@pytest.fixture
def runner(monkeypatch, tmp_path):
    """Exercise the actual sequence loop without creating owners or sockets."""
    observed = []
    replies = []
    monkeypatch.setattr(contract, "inspect_runtime", lambda *_: {})
    monkeypatch.setattr(routing, "RoutingLab", lambda *_a, **_kw: SimpleNamespace(identity={}))
    monkeypatch.setattr(routing, "AuthorizedRoutingBackend", lambda *_a, **_kw: object())
    class Evidence:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def finalize(self, outcomes, **kwargs): return deepcopy(outcomes)
    monkeypatch.setattr(routing, "RoutingEvidenceStore", Evidence)
    monkeypatch.setattr(routing, "LinuxAuditSink", lambda *_a, **_kw: nullcontext(object()))
    monkeypatch.setattr(routing, "LinuxApprovalService", lambda *_a, **_kw: nullcontext(object()))
    monkeypatch.setattr(routing, "LinuxFixtureLauncher", lambda *_a, **_kw: nullcontext(SimpleNamespace(close=lambda: {})))
    class Controller:
        def __init__(self, *args, **kwargs): pass
        def submit(self, action, **kwargs):
            observed.append(action)
            return replies[len(observed) - 1]
    monkeypatch.setattr(routing, "Controller", Controller)
    def run(outcomes, selectors, *, profile=None, execute=True):
        replies[:] = deepcopy(outcomes)
        observed.clear()
        result = routing.run_trial(tmp_path / "evidence", selectors=selectors, deployment="apache-A",
                                   case_profile=profile, execute=execute)
        return result, list(observed)
    return run


def success(number, *, native=True):
    return {"execution_status": "succeeded", **({"execution_id": str(number)} if native else {}),
            "untrusted_result": {"status": "succeeded", "routing_ledger": {"terminal": False}}}


@pytest.mark.parametrize("profile,selector", (("http_headers_N1", "http_headers"), ("http_headers_N4", "http_headers"),
                                             ("ssh_nmap_N1", "ssh_nmap"), ("ssh_keys_N3", "ssh_keys")))
def test_successful_native_negative_stops_after_prior_useful_action(runner, profile, selector):
    prior = "http_nmap" if selector.startswith("ssh_") else "ssh_nmap"
    later = "ssh_keys" if selector != "ssh_keys" else "http_headers"
    outcomes = [success(1), success(2), success(3)]
    result, calls = runner(outcomes, [prior, selector, later], profile=profile)
    assert result == outcomes[:2] and len(calls) == 2
    assert result[-1]["execution_status"] == "succeeded"


@pytest.mark.parametrize("profile", (None, "baseline", "http_headers_R1"))
def test_ordinary_and_legacy_successes_keep_the_explicit_order(runner, profile):
    outcomes = [success(1), success(2)]
    result, calls = runner(outcomes, ["http_headers", "ssh_keys"], profile=profile)
    assert result == outcomes and len(calls) == 2


@pytest.mark.parametrize("execute,native", ((False, False), (True, False)))
def test_declared_negative_stop_requires_an_actual_execution(runner, execute, native):
    outcomes = [success(1, native=native), success(2, native=native)]
    result, calls = runner(outcomes, ["http_headers", "ssh_keys"], profile="http_headers_N1", execute=execute)
    assert result == outcomes and len(calls) == 2


@pytest.mark.parametrize("status", ("blocked", "dry_run", "failed", "timeout", "output_limit", "cancelled"))
def test_existing_non_success_stopping_is_unchanged(runner, status):
    first = {"execution_status": status}
    result, calls = runner([first, success(2)], ["http_headers", "ssh_keys"], profile="http_headers_N1")
    assert result == [first] and len(calls) == 1


def test_cli_exposes_closed_case_profile_and_forwards_selection(tmp_path, monkeypatch, capsys):
    namespace = runpy.run_path("scripts/disconnected_routing.py", run_name="routing_matrix_cli")
    calls = []
    monkeypatch.setattr(routing, "run_trial", lambda *a, **kw: calls.append((a, kw)) or {"case_passed": True})
    monkeypatch.setattr(sys, "argv", ["disconnected_routing.py", "run", "--action", "http_headers",
        "--directory", str(tmp_path / "evidence"), "--deployment", "apache-B", "--case-profile", "http_headers_O4"])
    assert namespace["main"]() == 0
    assert calls[0][1]["deployment"] == "apache-B" and calls[0][1]["case_profile"] == "http_headers_O4"
    assert '"case_passed": true' in capsys.readouterr().out


def test_cli_rejects_an_arbitrary_profile_before_runtime(tmp_path):
    directory = tmp_path / "evidence"
    result = subprocess.run([sys.executable, "scripts/disconnected_routing.py", "run", "--action", "http_headers",
        "--directory", str(directory), "--deployment", "nginx-A", "--case-profile", "http_headers_O7"],
        capture_output=True, timeout=10)
    assert result.returncode == 2 and b"invalid choice" in result.stderr
    assert not directory.exists()


@pytest.mark.parametrize("arguments", (("--case-profile", "baseline"),
    ("--case-profile", "http_headers_N1", "--deployment", "apache-A", "--budget-case", "http_one")))
def test_cli_rejects_invalid_profile_combinations_without_preflight(tmp_path, arguments):
    directory = tmp_path / "evidence"
    result = subprocess.run([sys.executable, "scripts/disconnected_routing.py", "run", "--action", "http_headers",
        "--directory", str(directory), *arguments], capture_output=True, timeout=10)
    assert result.returncode == 2 and b"invalid_routing_case_profile_combination" in result.stderr
    assert b"Traceback" not in result.stderr and not directory.exists()


@pytest.mark.parametrize("profile", ("http_nmap_O6", "http_headers_N4", "ssh_nmap_N1", "ssh_keys_N3"))
def test_matrix_launcher_initial_requires_selected_runtime_and_both_witnesses(profile):
    from recon_cockpit.secure_agent import launcher_protocol as protocol
    from test_routing_authority import initial
    from test_routing_matrix_contract import identity, runtime
    selected = contract.selection(deployment="apache-B", case_profile=profile)
    value = initial()
    value["configuration"].update(case=selected, owned_lab=identity(selected),
                                  policy=contract.policy_for_selection(selected).to_dict())
    value["runtime"]["routing_runtime"] = runtime(selected)
    assert protocol.initial(value, 100) == value["configuration"]
    for field in ("audit_witness", "approval_witness"):
        changed = deepcopy(value)
        del changed[field]
        with pytest.raises(ValueError): protocol.initial(changed, 100)
    changed = deepcopy(value)
    changed["runtime"]["routing_runtime"] = runtime(contract.selection(deployment="apache-B", case_profile="baseline"))
    with pytest.raises(ValueError): protocol.initial(changed, 100)


@pytest.mark.parametrize("profile", ("http_nmap_O6", "http_headers_N4", "ssh_nmap_N1", "ssh_keys_N3"))
def test_matrix_client_launch_binds_selected_case_and_rejects_baseline_runtime(profile):
    from recon_cockpit.secure_agent.models import parse_action
    from recon_cockpit.secure_agent import routing_client_worker as worker
    from test_routing_client import envelope, consume
    from test_routing_matrix_contract import identity, runtime
    selector, case = profile.rsplit("_", 1)
    selected = contract.selection(deployment="nginx-B", case_profile=profile)
    value = envelope(selector, deployment="nginx-B")
    value.update(selection=selected, identity=identity(selected), runtime=runtime(selected)[selector])
    action, policy = parse_action(contract.action(selected, selector)), contract.policy_for_selection(selected)
    value["launch"].update(action=action.to_dict(), action_digest=action.digest,
                           policy=policy.to_dict(), policy_digest=policy.digest)
    request, _, _, runtime_digest = consume(value)
    assert request["case"] == case and request["selection"] == selected
    assert runtime_digest == value["identity"]["runtimes"][selector]["client_runtime_sha256"]
    if selector != "http_headers":
        assert request["target"] in worker.argv_for(request)
    value["runtime"] = runtime(contract.selection(deployment="nginx-B", case_profile="baseline"))[selector]
    with pytest.raises(ValueError): consume(value)
