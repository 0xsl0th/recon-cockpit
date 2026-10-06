"""Independent scope admission and launcher custody; portable, no native scans."""

from copy import deepcopy
from pathlib import Path
import json
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol as protocol
from recon_cockpit.secure_agent import launcher_isolation, admission_isolation, configurable_runtime
from recon_cockpit.secure_agent.admission_isolation import LinuxLaunchAdmission
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.configurable_backend import AuthorizedConfigurableBackend
from recon_cockpit.secure_agent.configurable_lab import ConfigurableLab
from recon_cockpit.secure_agent.configurable_scope import load_scope
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_network_tools_runtime import manifest
from test_secure_fixture_launcher import runtime as base_runtime
from scripts.secure_agent_control_plane_demo import demo_policy


def scope():
    return load_scope((Path(__file__).parents[1] / "examples/secure-agent-configurable-scope.json").read_bytes())


def configuration():
    selected = scope()
    return {"version": "1", "service_id": str(uuid4()), "session_id": str(uuid4()),
        "policy": contract.policy_for_scope(selected).to_dict(), "limits": dict(contract.LIMITS),
        "execute": True, "profile": contract.PROFILE, "case": selected}


def request(config, step, *, sequence=None, operation="execute", permit=None):
    value = {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
        "sequence": step if sequence is None else sequence, "operation": operation,
        "action": contract.action(config["case"], step), "policy_digest": admission.digest(config["policy"])}
    if operation == "redeem":
        value["permit"] = permit
    return value


def service(execute=True):
    selected, session, limits = scope(), str(uuid4()), SessionLimits(**contract.LIMITS)
    policy = contract.policy_for_scope(selected)
    lab = ConfigurableLab(selected, session, limits, execute=execute)
    return LinuxFixtureLauncher(AuthorizedConfigurableBackend(policy, session, limits, lab, execute=execute)), policy


def runtime():
    base = base_runtime()
    return {**base, "files": [*base["files"], "/usr/bin/nsenter"],
        "configurable_runtime": {tool: manifest(underlying) for tool, underlying in configurable_runtime.UNDERLYING.items()}}


def test_admission_configuration_detaches_scope_and_preloads_closed_contract():
    raw = configuration()
    fixed = admission.configuration(raw)
    raw["case"]["http"]["target"] = "10.77.0.99"
    raw["limits"]["max_steps"] = 9
    assert fixed["case"] == scope() and fixed["limits"] == contract.LIMITS


@pytest.mark.parametrize("bad_scope", [None, "vulnerable", {}, [], True])
def test_new_profile_requires_the_complete_scope_object(bad_scope):
    config = configuration()
    config["case"] = bad_scope
    with pytest.raises(ValueError):
        admission.configuration(config)


@pytest.mark.parametrize("field", contract.LIMITS)
def test_configurable_authority_has_its_own_nonexpandable_ceilings(field):
    config = configuration()
    config["limits"][field] += 1
    with pytest.raises(ValueError, match="^invalid_configurable_admission_limits$"):
        admission.configuration(config)
    config["limits"][field] = 1
    assert admission.configuration(config)["limits"][field] == 1


@pytest.mark.parametrize("profile", ["fixture", "owned_lab", "owned_nmap_lab", "owned_web_lab",
                                     "owned_http_headers_lab", "owned_web_tools_lab", "owned_network_tools_lab",
                                     "owned_service_web_lab"])
def test_existing_profiles_cannot_accept_a_configurable_scope_case(profile):
    config = configuration()
    config["profile"] = profile
    with pytest.raises(ValueError):
        admission.configuration(config)


def test_admission_requires_exact_four_step_order_and_burns_redeemed_permits():
    config = configuration()
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    for step in (2, 3, 4):
        denied = state.handle(request(config, step, sequence=state._sequence, operation="admit"))
        assert denied["reason"] == "admission_profile_denied"
        assert denied["snapshot"] == {"executions_reserved": 0, "output_bytes_reserved": 0}
    for step in range(1, 5):
        accepted = state.handle(request(config, step, sequence=state._sequence, operation="admit"))
        assert accepted["reason"] is None
        assert accepted["snapshot"] == {"executions_reserved": step,
                                         "output_bytes_reserved": contract.OUTPUT_RESERVATIONS[step]}
        for expected in (None, "admission_unknown_or_replayed"):
            redeemed = state.handle(request(config, step, sequence=state._sequence, operation="redeem",
                                            permit=accepted["permit"]))
            assert redeemed["reason"] == expected and redeemed["snapshot"] == accepted["snapshot"]
        replay = state.handle(request(config, step, sequence=state._sequence, operation="admit"))
        assert replay["reason"] == "admission_profile_denied" and replay["snapshot"] == accepted["snapshot"]


@pytest.mark.parametrize("step", range(1, 5))
@pytest.mark.parametrize("restriction", ["target", "tool", "port", "timeout", "output"])
def test_policy_remains_an_independent_narrowing_gate(step, restriction):
    config = configuration()
    selected = parse_action(contract.action(config["case"], step))
    policy = config["policy"]
    if restriction == "target": policy["allowed_targets"] = ["192.168.240.1"]
    elif restriction == "tool": policy["allowed_tools"] = []
    elif restriction == "port": policy["allowed_ports"] = [65534]
    elif restriction == "timeout":
        if step == 2:
            policy["allowed_methods"] = ["HEAD"]
        else:
            policy["max_timeout_seconds"] = 1
    else: policy["max_output_bytes"] = 1024
    assert parse_policy(policy).evaluate(selected).decision == "deny"
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    denied = state.handle(request(config, step, sequence=1, operation="admit"))
    assert denied["reason"] == "admission_policy_denied"
    assert denied["snapshot"] == {"executions_reserved": 0, "output_bytes_reserved": 0}


@pytest.mark.parametrize("step", range(1, 5))
@pytest.mark.parametrize("field", ["action_id", "rationale", "target", "port", "timeout", "output"])
def test_policy_approved_action_mutation_still_cannot_expand_fixed_scope(step, field):
    config = configuration()
    value = contract.action(config["case"], step)
    if field == "action_id": value["action_id"] = str(uuid4())
    elif field == "rationale": value["rationale"] = "changed untrusted proposal"
    elif field == "target": value["target"] = config["case"]["ssh" if step < 3 else "http"]["target"]
    elif field == "port": value["parameters"]["port"] = config["case"]["ssh" if step < 3 else "http"]["port"]
    elif field == "timeout": value["parameters"]["timeout_seconds"] = 2 if step == 2 else 1
    else: value["parameters"]["max_output_bytes"] -= 1
    candidate = parse_action(value)
    assert parse_policy(config["policy"]).evaluate(candidate).decision != "deny"
    assert not admission.profile_allows(candidate, config)
    with pytest.raises(ValueError):
        protocol.request({**request(config, step), "action": value}, config, step)


@pytest.mark.parametrize("step", range(1, 5))
def test_launcher_enforces_action_order_even_for_repeated_nmap_tool_id(step):
    config = configuration()
    assert protocol.request(request(config, step), config, step).to_dict() == contract.action(config["case"], step)
    for wrong in set(range(1, 5)) - {step}:
        with pytest.raises(ValueError):
            protocol.request(request(config, wrong, sequence=step), config, step)


@pytest.mark.parametrize("change", ["scope", "identity", "digest", "endpoint", "extra", "old_profile"])
def test_launcher_configuration_binds_both_endpoint_identities_and_full_scope(change):
    launcher, _ = service()
    config = deepcopy(launcher._config)
    if change == "scope": config["case"]["http"]["path"] = "/different"
    elif change == "identity": config["owned_lab"]["endpoints"]["ssh"]["instance_id"] = "invalid"
    elif change == "digest": config["owned_lab"]["scope_sha256"] = "a" * 64
    elif change == "endpoint": config["owned_lab"]["endpoints"]["ssh"] = config["owned_lab"]["endpoints"]["http"]
    elif change == "extra": config["owned_lab"]["approved"] = True
    else: config["profile"] = "owned_service_web_lab"
    with pytest.raises(ValueError):
        protocol.configuration(config)


def test_launcher_identity_access_cannot_mutate_its_scope_or_endpoint_commitment():
    launcher, _ = service()
    changed = launcher.identity
    changed["scope"]["http"]["target"] = "10.77.0.99"
    changed["endpoints"]["ssh"]["instance_id"] = str(uuid4())
    assert launcher.identity == launcher._config["owned_lab"]
    assert launcher.identity["scope"] == scope()


def test_runtime_and_bootstrap_tag_are_separate_from_all_existing_profiles():
    launcher, _ = service()
    closure = runtime()
    assert protocol.initial({"configuration": launcher._config, "runtime": closure, "deadline": 160}, 100) == launcher._config
    assert protocol.runtime_tag(launcher._config, closure) == "configurable-launch-preconditions"
    protocol.validate_runtime_tag("configurable-launch-preconditions", launcher._config, closure)
    for tag in (None, "launch-preconditions", "service-web-launch-preconditions", "network-tools-launch-preconditions"):
        with pytest.raises(ValueError):
            protocol.validate_runtime_tag(tag, launcher._config, closure)
    for profile in ("fixture", "owned_network_tools_lab", "owned_service_web_lab"):
        with pytest.raises(ValueError):
            protocol.validate_runtime_tag("configurable-launch-preconditions", {"profile": profile}, closure)
    for options in ({}, {"owned_lab": True}, {"owned_lab": True, "network_tools": True},
                    {"owned_lab": True, "service_web": True},
                    {"owned_lab": True, "configurable": True, "network_tools": True}):
        with pytest.raises(ValueError):
            protocol.runtime(closure, **options)


@pytest.mark.parametrize("fault", ["missing", "extra", "swapped", "wrong_tool", "nsenter"])
def test_runtime_closure_rejects_incomplete_or_substituted_native_bindings(fault):
    closure = runtime()
    if fault == "missing": del closure["configurable_runtime"][contract.SSH]
    elif fault == "extra": closure["configurable_runtime"][contract.HEADERS] = None
    elif fault == "swapped": closure["configurable_runtime"][contract.NMAP] = closure["configurable_runtime"][contract.SSH]
    elif fault == "wrong_tool": closure["configurable_runtime"][contract.NMAP]["tool_id"] = contract.NMAP
    else: closure["files"].remove("/usr/bin/nsenter")
    with pytest.raises(ValueError):
        protocol.runtime(closure, owned_lab=True, configurable=True)


def test_only_configurable_admission_and_launcher_mount_scope_modules(monkeypatch):
    namespaces = dict.fromkeys(("user", "net", "mnt", "pid"), "private")
    for module in (launcher_isolation, admission_isolation):
        monkeypatch.setattr(module, "_namespaces", lambda: namespaces)
        monkeypatch.setattr(module, "_trusted_program", lambda name: "/usr/bin/" + name)
    launcher, policy = service()
    gate = LinuxLaunchAdmission(policy, launcher._config["session_id"], SessionLimits(**contract.LIMITS),
                                execute=True, profile=contract.PROFILE, case=scope())
    mounted = gate._command("/usr/lib/python3.13", [], "a" * 64)
    assert "/app/admission_runtime/configurable_scope.py" in mounted
    assert "/app/admission_runtime/configurable_contract.py" in mounted
    old_gate = LinuxLaunchAdmission(demo_policy(), str(uuid4()), SessionLimits(), execute=True)
    assert not any("/configurable_" in arg for arg in old_gate._command("/usr/lib/python3.13", [], "a" * 64))
    launcher._approval_source = {"test": True}
    argv = launcher._command(runtime(), [], "a" * 64)
    assert argv[-1] == "configurable-launch-preconditions"
    assert "/app/recon_cockpit/secure_agent/configurable_worker.py" in argv
    assert "/app/recon_cockpit/secure_agent/configurable_parser_worker.py" in argv
    for name in launcher_isolation.CONFIGURABLE_MODULES:
        assert Path(launcher_isolation.__file__).with_name(name + ".py").is_file()
    old = LinuxFixtureLauncher(AuthorizedFixtureBackend(demo_policy(), str(uuid4()), SessionLimits(), execute=True))
    assert not any("/configurable_" in arg for arg in old._command(base_runtime(), [], "a" * 64))


def fake_result(launcher, step):
    totals = {"http": (0, 0), "ssh": (0, 0)}
    if step >= 1: totals["http"] = (2, 1)
    if step >= 2: totals["http"] = (3, 2)
    if step >= 3: totals["ssh"] = (2, 1)
    if step >= 4: totals["ssh"] = (3, 2)
    return {"backend": contract.BACKEND, "status": "succeeded", "results": [], "tool_observation": {},
        "scope_step": step, "scope_sha256": launcher.identity["scope_sha256"],
        "owned_lab": {"identity": launcher.identity, "step": step,
            "endpoints": {name: {"identity": launcher.identity["endpoints"][name],
                                  "connection_count": pair[0], "request_count": pair[1]}
                          for name, pair in totals.items()}}}


@pytest.mark.parametrize("completed", range(5))
def test_close_receipt_preserves_both_last_acknowledged_endpoint_totals(completed):
    launcher, _ = service()
    if completed:
        launcher._lab_context = fake_result(launcher, completed)["owned_lab"]
    receipt = launcher.close()
    assert set(receipt) == {"identity", "status", "endpoints"}
    assert receipt["status"] == "closed"
    for name in ("http", "ssh"):
        before = ({"identity": launcher.identity["endpoints"][name], "connection_count": 0, "request_count": 0}
                  if not completed else launcher._lab_context["endpoints"][name])
        assert receipt["endpoints"][name] == {**before, "status": "closed"}
    assert launcher.close() == receipt


@pytest.mark.parametrize("fault", ["scope", "step", "other_endpoint", "boolean", "receipt", "runtime_backend"])
def test_host_rejects_forged_scope_context_before_acknowledging_and_never_retries(monkeypatch, fault):
    launcher, policy = service()
    control = ExecutionControl(time.monotonic() + 30)
    launcher._control = control
    launcher._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
    sent = []
    monkeypatch.setattr(launcher, "check_available", lambda *_: None)
    monkeypatch.setattr(launcher, "_quiet", lambda: None)
    monkeypatch.setattr(launcher, "_send", lambda raw: sent.append(json.loads(raw)))

    def reply():
        step = len(sent)
        result = fake_result(launcher, step)
        if step == 2:
            if fault == "scope": result["scope_sha256"] = "b" * 64
            elif fault == "step": result["scope_step"] = 4
            elif fault == "other_endpoint": result["owned_lab"]["endpoints"]["ssh"]["connection_count"] = 1
            elif fault == "boolean": result["owned_lab"]["endpoints"]["http"]["request_count"] = True
            elif fault == "runtime_backend": result["backend"] = protocol.PROFILES["owned_service_web_lab"]
        receipt = protocol.receipt(sent[-1], result, {"executions_reserved": step,
                                                     "output_bytes_reserved": contract.OUTPUT_RESERVATIONS[step]})
        if step == 2 and fault == "receipt": receipt["request_digest"] = "c" * 64
        return receipt

    monkeypatch.setattr(launcher, "_reply", reply)
    first = launcher.run(parse_action(contract.action(scope(), 1)), policy, control=control)
    with pytest.raises(IsolationUnavailable):
        launcher.run(parse_action(contract.action(scope(), 2)), policy, control=control)
    assert len(sent) == 2 and launcher._closed and launcher._sequence == 1
    closed = launcher.close()
    assert closed["endpoints"]["http"]["request_count"] == first["owned_lab"]["endpoints"]["http"]["request_count"] == 1
    assert closed["endpoints"]["ssh"]["request_count"] == 0
