"""Stock SSH uses the witnessed launcher without weakening older profiles."""

from copy import deepcopy
import hashlib
import shutil
import subprocess
import sys
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import stock_ssh_contract as contract, stock_ssh_spec as spec
from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol as launcher
from recon_cockpit.secure_agent.stock_ssh_execution import consume_launch
from test_stock_ssh_client import envelope, manifests, NONCE, SESSION, HOST
from test_secure_fixture_launcher import runtime as base_runtime


def configuration(config="A", case="O1"):
    selected = contract.selection(config, case)
    return {"version": "1", "service_id": str(UUID(int=1883)), "session_id": SESSION,
        "policy": contract.policy_for_selection(selected).to_dict(), "limits": contract.limits(selected),
        "execute": True, "profile": contract.PROFILE, "case": selected}


def request(config, sequence=1, *, operation="execute", permit=None):
    value = {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
        "sequence": sequence, "operation": operation, "action": contract.action(config["case"]),
        "policy_digest": admission.digest(config["policy"])}
    if operation == "redeem":
        value["permit"] = permit
    return value


def initial(config="A", case="O1"):
    value = configuration(config, case)
    value["owned_lab"] = envelope(config, case)["identity"]
    closure = base_runtime()
    closure["files"].append("/usr/bin/nsenter")
    closure["stock_ssh_runtime"] = manifests(config, case)
    return {"configuration": value, "deadline": 160, "runtime": closure,
        "audit_witness": {"version": "1", "writer_id": str(UUID(int=1990)), "device": 1, "inode": 2},
        "approval_witness": {"version": "1", "broker_id": str(UUID(int=1991)), "device": 1, "inode": 3}}


def verify(value):
    raw = spec.encode(value)
    return consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)


@pytest.mark.parametrize("config,case", spec.TRIALS)
def test_all_twenty_selections_keep_exact_one_action_authority(config, case):
    value = envelope(config, case)
    req, deadline, namespaces, client_digest = verify(value)
    assert req["selection"] == value["selection"] and req["endpoint_id"] == "ssh"
    assert req["parameters"] == contract.action(value["selection"])["parameters"]
    assert deadline == 150 and namespaces == value["namespaces"]
    assert client_digest == value["identity"]["client_runtime_sha256"]
    selected = configuration(config, case)
    assert admission.configuration(selected) == selected
    assert launcher.request(request(selected), selected, 1).to_dict() == spec.action(config, case)
    assert launcher.initial(initial(config, case), 100) == initial(config, case)["configuration"]


def test_selection_policy_and_daemon_client_runtime_are_distinct():
    selections = [contract.selection(*pair) for pair in spec.TRIALS]
    assert len({row["selection_sha256"] for row in selections}) == 20
    assert len({contract.policy_for_selection(row).digest for row in selections}) == 20
    value = configuration()
    value["policy"] = contract.policy_for_selection(contract.selection("A", "O2")).to_dict()
    with pytest.raises(ValueError, match="policy_binding_changed"):
        admission.configuration(value)


@pytest.mark.parametrize("fault", ("selection", "identity", "runtime", "profile", "preparation_selection",
    "outer_mode", "inner_mode", "runtime_hash", "owner_session", "owner_runtime", "policy", "steps",
    "deadline", "namespace", "sequence", "execute"))
def test_recommitted_launch_cannot_swap_selection_or_bypass_authority(fault):
    value = envelope()
    launch = value["launch"]
    if fault == "selection": value["selection"] = contract.selection("B", "O1")
    elif fault == "identity": value["identity"]["case"] = "O2"
    elif fault == "runtime": value["runtime"] = manifests("A", "O2")
    elif fault == "profile": value["identity"]["profile"] = "stock_http_compatibility_v1"
    elif fault == "preparation_selection": value["selection"] = contract.preparation_selection(value["selection"])
    elif fault == "outer_mode": value["mode"] = "stock_http_compatibility_v1"
    elif fault == "inner_mode": launch["mode"] = "stock_http_compatibility_v1"
    elif fault == "runtime_hash": value["runtime"]["daemon"]["files"][0]["sha256"] = "b" * 64
    elif fault == "owner_session": value["identity"]["session_id"] = str(UUID(int=1999))
    elif fault == "owner_runtime": value["identity"]["daemon_runtime_sha256"] = "b" * 64
    elif fault == "policy": launch["policy"] = contract.policy_for_selection(contract.selection("B", "O1")).to_dict()
    elif fault == "steps": launch["limits"]["max_steps"] = 2
    elif fault == "deadline": launch["deadline"] = 161
    elif fault == "namespace": value["namespaces"]["net"] = HOST["net"]
    elif fault == "sequence": launch["sequence"] = 2
    else: launch["execute"] = False
    for field in ("action", "policy", "limits"): launch[field + "_digest"] = admission.digest(launch[field])
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("case", ("O1", "O2"))
def test_independent_witnesses_and_distinct_ssh_tag_are_required(case):
    value = initial(case=case)
    for required in (True, False):
        value["configuration"]["policy"] = contract.policy_for_selection(value["configuration"]["case"], require_approval=required).to_dict()
        assert launcher.initial(value, 100) == value["configuration"]
        for key in ("audit_witness", "approval_witness"):
            changed = deepcopy(value); del changed[key]
            with pytest.raises(ValueError): launcher.initial(changed, 100)
    for tag in (None, "launch-witness", "stock-http-launch-preconditions",
                "stock-http-production-launch-preconditions", "configurable-launch-preconditions"):
        with pytest.raises(ValueError): launcher.validate_runtime_tag(tag, value["configuration"], value["runtime"])
    launcher.validate_runtime_tag("stock-ssh-launch-preconditions", value["configuration"], value["runtime"])


def test_direct_host_backend_and_unwitnessed_launcher_cannot_execute():
    from recon_cockpit.secure_agent.stock_ssh_backend import AuthorizedStockSshBackend
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    backend = object.__new__(AuthorizedStockSshBackend)
    with pytest.raises(IsolationUnavailable, match="witnessed"): backend.run(None, None)
    with pytest.raises(ValueError, match="isolated_audit_and_approval"): LinuxFixtureLauncher(backend)


@pytest.mark.parametrize("case", ("O1", "O2"))
def test_single_use_admission_never_refunds_or_replays(case):
    config = configuration(case=case)
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    granted = state.handle(request(config, operation="admit"))
    assert granted["reason"] is None
    assert granted["snapshot"] == {"executions_reserved": 1, "output_bytes_reserved": config["limits"]["max_output_bytes"]}
    assert state.handle(request(config, 2, operation="redeem", permit=granted["permit"]))["reason"] is None
    assert state.handle(request(config, 3, operation="redeem", permit=granted["permit"]))["reason"] == "admission_unknown_or_replayed"
    assert state.handle(request(config, 4, operation="admit"))["reason"] == "admission_step_limit"
    with pytest.raises(ValueError): launcher.request(request(config, 2), config, 2)


@pytest.mark.parametrize("field", ("max_steps", "max_runtime_seconds", "max_output_bytes"))
@pytest.mark.parametrize("change", (1, -1, True))
def test_exact_bounds_cannot_be_rewritten(field, change):
    value = configuration()
    value["limits"][field] = change if type(change) is bool else value["limits"][field] + change
    with pytest.raises(ValueError): admission.configuration(value)


@pytest.mark.parametrize("case", ("O1", "O2"))
@pytest.mark.parametrize("fault", ("target", "port", "tool", "action_id", "rationale", "timeout", "output"))
def test_changed_action_denied_before_reservation(case, fault):
    config = configuration(case=case)
    value = request(config, operation="admit")
    action = value["action"]
    if fault == "target": action["target"] = "10.77.0.99"
    elif fault == "port": action["parameters"]["port"] = 22
    elif fault == "tool": action["tool_id"] = ("configurable_ssh_host_keys_v1" if case == "O1" else "configurable_nmap_service_v1")
    elif fault == "action_id": action["action_id"] = str(UUID(int=1999))
    elif fault == "rationale": action["rationale"] = "different"
    elif fault == "timeout": action["parameters"]["timeout_seconds"] = 4
    else: action["parameters"]["max_output_bytes"] = 1024
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    denied = state.handle(value)
    assert denied["reason"] in ("admission_policy_denied", "admission_profile_denied")
    assert denied["snapshot"] == {"executions_reserved": 0, "output_bytes_reserved": 0}
    with pytest.raises(ValueError): launcher.request({**value, "operation": "execute"}, config, 1)


def test_runtime_closure_is_ssh_only_and_native_mounts_are_exact():
    value = initial()
    closure = value["runtime"]
    assert launcher.runtime(closure, owned_lab=True, stock_ssh=True) == closure
    for flags in ({}, {"stock_http": True}, {"stock_http_production": True}, {"stock_ssh": True, "stock_http": True}):
        with pytest.raises(ValueError): launcher.runtime(closure, owned_lab=True, **flags)
    changed = deepcopy(closure)
    changed["stock_http_runtime"] = changed.pop("stock_ssh_runtime")
    with pytest.raises(ValueError): launcher.runtime(changed, owned_lab=True, stock_ssh=True)
    selected = value["configuration"]["case"]
    mounts = contract.runtime_source_mounts(closure["stock_ssh_runtime"], selected)
    assert ("/usr/sbin/sshd", "/usr/sbin/sshd") in mounts
    assert not any(destination in ("/etc", "/usr", "/usr/lib", "/etc/ssh", "/tool/sshd", spec.HOST_KEY_PATH)
                   for _, destination in mounts)
    assert not any(source.startswith("compiled:") for source, _ in mounts)


@pytest.mark.parametrize("component", ("admission", "launcher"))
@pytest.mark.parametrize("case", ("O1", "O2"))
def test_actual_source_mount_closure_imports_without_repository(tmp_path, monkeypatch, component, case):
    if component == "admission":
        from recon_cockpit.secure_agent import admission_isolation as module
        owner = module.LinuxLaunchAdmission.__new__(module.LinuxLaunchAdmission)
        owner._config = configuration(case=case)
        argument = owner._config
        entry = """from admission_runtime import launch_admission
assert launch_admission.configuration(value)==value
assert launch_admission.__file__.startswith(sys.argv[1])
"""
    else:
        from recon_cockpit.secure_agent import launcher_isolation as module
        owner = module.LinuxFixtureLauncher.__new__(module.LinuxFixtureLauncher)
        argument = initial(case=case)
        owner._config = argument["configuration"]
        owner._witness_source = owner._approval_source = {}
        entry = """from recon_cockpit.secure_agent import launcher_worker,launcher_protocol
from recon_cockpit.secure_agent import stock_ssh_backend,stock_ssh_lab
assert launcher_protocol.initial(value,100)==value['configuration']
assert launcher_worker.__file__.startswith(sys.argv[1])
"""
    monkeypatch.setattr(module, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(module, "_namespaces", lambda: dict(HOST))
    command = owner._command("/stdlib" if component == "admission" else {"stdlib": "/stdlib"}, [], "a" * 64)
    for index, flag in enumerate(command):
        if flag == "--ro-bind" and command[index + 2].startswith("/app/"):
            destination = tmp_path / command[index + 2].removeprefix("/app/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(command[index + 1], destination)
    if component == "launcher":
        assert "stock-ssh-launch-preconditions" in command
        assert "/stock-peer" not in command and "/stock-ssh-peer" not in command
        assert [command[i + 1] for i, flag in enumerate(command) if flag == "--tmpfs"] == ["/tmp"]
        assert [command[i + 1] for i, flag in enumerate(command) if flag == "--size"] == ["1048576"]
    code = "import json,sys\nsys.path.insert(0,sys.argv[1])\nvalue=json.loads(sys.argv[2])\n" + entry + "print('closed-ssh-ok')\n"
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), spec.encode(argument).decode()],
        capture_output=True, timeout=10, env={"LC_ALL": "C"}, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout == b"closed-ssh-ok\n"
