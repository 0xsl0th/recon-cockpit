"""Portable HarborDesk admission and independent executor boundaries."""

import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launch_admission, launcher_protocol, nmap_execution
from recon_cockpit.secure_agent import owned_lab_executor, web_assessment_contract as contract
from recon_cockpit.secure_agent.executor_worker import digest, encode
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.owned_lab_contract import identity as legacy_identity
from recon_cockpit.secure_agent.web_lab_contract import identity
from test_secure_nmap_runtime import manifest as nmap_manifest


def policy():
    return parse_policy(json.loads(Path("examples/secure-agent-web-policy.json").read_text()))


def configuration(case="vulnerable"):
    return {"version": "1", "service_id": str(uuid4()), "session_id": str(uuid4()),
            "policy": policy().to_dict(), "limits": dict(contract.LIMITS),
            "execute": True, "profile": contract.PROFILE, "case": case}


def envelope(step=2, case="vulnerable"):
    action = parse_action(contract.action(case, step))
    host = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    value = {"mode": contract.PROFILE, "identity": identity(case, str(uuid4())),
             "namespaces": {name: name + ":[200]" for name in host},
             "launch": {"schema_version": "1", "mode": "nmap_web_owned" if step == 1 else "discovery_fixture",
                "execute": True, "session_id": str(uuid4()), "nonce": "a" * 64,
                "sequence": 1, "action": action.to_dict(), "action_digest": action.digest,
                "policy": policy().to_dict(), "policy_digest": policy().digest,
                "limits": dict(contract.LIMITS), "limits_digest": digest(contract.LIMITS),
                "deadline": time.monotonic() + 30, "output_reserved_before": 0,
                "output_reserved_after": action.parameters.max_output_bytes, "host_namespaces": host}}
    if step == 1:
        value["runtime"] = nmap_manifest()
    return value


def verify(value):
    raw = encode(value)
    consume = nmap_execution.consume_launch if "runtime" in value else owned_lab_executor.validate_launch
    return consume(raw, "a" * 64, hashlib.sha256(raw).hexdigest())


def recommit(value):
    launch = value["launch"]
    for field in ("action", "policy", "limits"):
        launch[field + "_digest"] = digest(launch[field])


@pytest.mark.parametrize("case", ("vulnerable", "corrected", "injected"))
@pytest.mark.parametrize("step", (1, 2, 3))
def test_each_reviewed_action_passes_both_profile_and_independent_executor(case, step):
    action = parse_action(contract.action(case, step))
    assert launch_admission.configuration(configuration(case))["profile"] == contract.PROFILE
    assert launch_admission.profile_allows(action, configuration(case))
    request, _, namespaces, *runtime = verify(envelope(step, case))
    assert request["target"] == "127.0.0.1"
    assert request["parameters"] == action.parameters.to_dict()
    assert namespaces["net"] == "net:[200]"
    if step == 1:
        assert request["tool_id"] == contract.TOOL_ID and runtime == [digest(nmap_manifest())]


@pytest.mark.parametrize("step", (1, 2))
@pytest.mark.parametrize("fault", ("legacy_identity", "legacy_profile", "inner_profile", "scenario", "namespace"))
def test_fresh_commitment_cannot_substitute_legacy_lab_or_authority(step, fault):
    value = envelope(step)
    if fault == "legacy_identity":
        value["identity"] = legacy_identity("a", str(uuid4()))
    elif fault == "legacy_profile":
        value["mode"] = "owned_nmap_lab" if step == 1 else "owned_lab"
    elif fault == "inner_profile":
        value["launch"]["mode"] = "nmap_owned" if step == 1 else "fixture"
    elif fault == "scenario":
        value["identity"]["scenario"] = "corrected"
    else:
        value["namespaces"] = dict(value["launch"]["host_namespaces"])
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize("step", (1, 2))
@pytest.mark.parametrize("field", contract.LIMITS)
def test_admission_and_each_executor_independently_enforce_reviewed_ceilings(step, field):
    config = configuration()
    config["limits"][field] += 1
    with pytest.raises(ValueError):
        launch_admission.configuration(config)
    value = envelope(step)
    value["launch"]["limits"][field] += 1
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize("change", [
    {"target": "127.0.0.2"},
    {"port": 8081}, {"method": "HEAD"}, {"timeout_seconds": 2}, {"max_output_bytes": 2048},
    {"path": "/assessment/a/index.json"}, {"path": "/harbordesk/admin.json"},
    {"path": "/harbordesk/reset.json"},
    {"tool_id": "tcp_connect"},
])
def test_http_profile_rejects_other_targets_tools_paths_and_caps_even_with_broader_policy(change):
    value = envelope()
    launch = value["launch"]
    action = launch["action"]
    if "target" in change:
        action.update(change)
    elif "tool_id" in change:
        action.update(change)
        action["parameters"] = {"port": 8080, "timeout_seconds": 1, "max_output_bytes": 1024}
    else:
        action["parameters"].update(change)
    launch["policy"].update(allowed_targets=["127.0.0.0/8"], allowed_ports=[8080, 8081],
                            allowed_methods=["GET", "HEAD"],
                            allowed_tools=[contract.TOOL_ID, "http_probe", "tcp_connect"])
    launch["output_reserved_after"] = action["parameters"]["max_output_bytes"]
    recommit(value)
    parsed = parse_action(action)
    assert parse_policy(launch["policy"]).evaluate(parsed).decision == "approval_required"
    assert not launch_admission.profile_allows(parsed, configuration())
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize("change", [{"target": "127.0.0.2"}, {"port": 8081},
                                    {"timeout_seconds": 4}, {"max_output_bytes": 8192}])
def test_web_nmap_action_remains_the_exact_reviewed_adapter(change):
    value = envelope(1)
    action = value["launch"]["action"]
    if "target" in change:
        action.update(change)
    else:
        action["parameters"].update(change)
    recommit(value)
    assert not launch_admission.profile_allows(parse_action(action), configuration())
    with pytest.raises(ValueError):
        verify(value)


def test_three_reviewed_actions_exhaust_one_shared_reservation_budget():
    config = configuration()
    state = launch_admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    for sequence, step in enumerate((1, 2, 3, 2), 1):
        result = state.handle({"version": "1", "service_id": config["service_id"],
            "session_id": config["session_id"], "sequence": sequence, "operation": "admit",
            "action": contract.action("vulnerable", step), "policy_digest": digest(config["policy"])})
        assert result["reason"] == ("admission_step_limit" if sequence == 4 else None)
    assert result["permit"] is None
    assert result["snapshot"] == {"executions_reserved": 3, "output_bytes_reserved": 18432}


@pytest.mark.parametrize("substitution", ("old_identity", "old_profile", "wrong_case"))
def test_launcher_configuration_cannot_mix_old_and_web_lab_identity(substitution):
    config = {**configuration(), "owned_lab": identity("vulnerable", str(uuid4()))}
    assert launcher_protocol.configuration(config) == config
    if substitution == "old_identity":
        config["owned_lab"] = legacy_identity("a", str(uuid4()))
    elif substitution == "old_profile":
        config.update(profile="owned_nmap_lab", case="a")
    else:
        config["case"] = "corrected"
    with pytest.raises(ValueError):
        launcher_protocol.configuration(config)


def test_launcher_command_pins_web_bootstrap_and_keeps_new_modules_out_of_old_profiles(monkeypatch):
    from recon_cockpit.secure_agent import launcher_isolation
    monkeypatch.setattr(launcher_isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(launcher_isolation, "_namespaces", lambda: {
        name: name + ":[100]" for name in ("user", "net", "mnt", "pid")})
    closure = {"stdlib": "/usr/lib/python3.13"}
    for profile, marker in ((contract.PROFILE, "web-launch-preconditions"),
                            ("owned_nmap_lab", "nmap-launch-preconditions"),
                            ("owned_lab", "launch-preconditions")):
        client = SimpleNamespace(_config={"profile": profile}, _witness_source={}, _approval_source={})
        argv = launcher_isolation.LinuxFixtureLauncher._command(client, closure, [], "a" * 64)
        assert argv[-1] == marker
        web_modules = [item for item in argv if item.startswith("/app/") and "/web_" in item]
        assert bool(web_modules) is (profile == contract.PROFILE)
        if profile == contract.PROFILE:
            assert "/app/recon_cockpit/secure_agent/web_lab_contract.py" in web_modules
