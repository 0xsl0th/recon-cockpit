"""Routing cannot bypass launch witnesses or expand the accepted runtime profiles."""
from copy import deepcopy
import os
import shutil
import socket
import subprocess
import sys
import time
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_transport as transport
from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol as protocol
from recon_cockpit.secure_agent.routing_backend import AuthorizedRoutingBackend
from recon_cockpit.secure_agent.routing_lab import RoutingLab, ConfinedRoutingLab
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_routing_contract import runtime, identity, SESSION
from test_secure_fixture_launcher import runtime as base_runtime
from test_stock_ssh_client import HOST


def config():
    selected = contract.selection()
    return {"version": "1", "service_id": str(UUID(int=3510)), "session_id": SESSION,
        "policy": contract.policy_for_selection(selected).to_dict(), "limits": contract.limits(selected),
        "execute": True, "profile": contract.PROFILE, "case": selected}


def initial():
    value = config(); value["owned_lab"] = identity()
    closure = base_runtime(); closure["files"].append("/usr/bin/nsenter")
    closure["routing_runtime"] = runtime()
    return {"configuration": value, "deadline": 160, "runtime": closure,
        "audit_witness": {"version": "1", "writer_id": str(UUID(int=3511)), "device": 1, "inode": 2},
        "approval_witness": {"version": "1", "broker_id": str(UUID(int=3512)), "device": 1, "inode": 3}}


@pytest.mark.parametrize("require_approval", (True, False))
def test_each_routing_action_requires_both_witnesses_and_distinct_tag(require_approval):
    value = initial()
    value["configuration"]["policy"] = contract.policy_for_selection(contract.selection(), require_approval=require_approval).to_dict()
    assert protocol.initial(value, 100) == value["configuration"]
    for field in ("audit_witness", "approval_witness"):
        changed = deepcopy(value); del changed[field]
        with pytest.raises(ValueError): protocol.initial(changed, 100)
    for tag in (None, "launch-witness", "stock-ssh-launch-preconditions", "stock-http-production-launch-preconditions"):
        with pytest.raises(ValueError): protocol.validate_runtime_tag(tag, value["configuration"], value["runtime"])
    protocol.validate_runtime_tag("routing-launch-preconditions", value["configuration"], value["runtime"])


def test_host_cannot_execute_or_create_topology_even_with_metadata_closure(monkeypatch):
    value = initial(); selected = value["configuration"]["case"]
    metadata = RoutingLab(selected, SESSION, SessionLimits(**contract.limits(selected)), runtime=runtime(), closure=value["runtime"])
    with pytest.raises(IsolationUnavailable, match="witnessed"):
        metadata.start(ExecutionControl(time.monotonic() + 30))
    owner = object.__new__(AuthorizedRoutingBackend)
    with pytest.raises(IsolationUnavailable, match="witnessed"): owner.run(None, None)
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    with pytest.raises(ValueError, match="isolated_audit_and_approval"): LinuxFixtureLauncher(owner)
    assert metadata.topology is None and metadata.services is None


@pytest.mark.parametrize("fault", ("missing", "changed", "subclass", "clock", "lifetime"))
def test_confined_lab_rejects_changed_authority_before_setup(fault):
    value = initial()
    cls = type("Subclass", (ConfinedRoutingLab,), {}) if fault == "subclass" else ConfinedRoutingLab
    lab = cls(value["configuration"], value["runtime"])
    if fault == "missing": lab._closure = None
    if fault == "changed": lab._closure["routing_runtime"]["ssh_keys"]["daemon"]["files"][0]["sha256"] = "f" * 64
    control = ExecutionControl(time.monotonic() + (61 if fault == "lifetime" else 30),
        **({"clock": lambda: time.monotonic()} if fault == "clock" else {}))
    with pytest.raises((IsolationUnavailable, ValueError)): lab.start(control)
    assert lab.topology is None


@pytest.mark.parametrize("component", ("admission", "launcher"))
def test_actual_routing_source_mounts_import_without_repository(tmp_path, monkeypatch, component):
    if component == "admission":
        from recon_cockpit.secure_agent import admission_isolation as module
        owner = module.LinuxLaunchAdmission.__new__(module.LinuxLaunchAdmission)
        owner._config = argument = config()
        entry = "from admission_runtime import launch_admission; assert launch_admission.configuration(value)==value"
    else:
        from recon_cockpit.secure_agent import launcher_isolation as module
        owner = module.LinuxFixtureLauncher.__new__(module.LinuxFixtureLauncher)
        argument = initial(); owner._config = argument["configuration"]
        owner._witness_source = owner._approval_source = {}
        entry = "from recon_cockpit.secure_agent import launcher_worker,launcher_protocol,routing_backend,routing_lab,routing_context; assert launcher_protocol.initial(value,100)==value['configuration']"
    monkeypatch.setattr(module, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(module, "_namespaces", lambda: dict(HOST))
    command = owner._command("/stdlib" if component == "admission" else {"stdlib": "/stdlib"}, [], "a" * 64)
    for index, flag in enumerate(command):
        if flag == "--ro-bind" and command[index + 2].startswith("/app/"):
            destination = tmp_path / command[index + 2].removeprefix("/app/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(command[index + 1], destination)
    code = "import json,sys;sys.path.insert(0,sys.argv[1]);value=json.loads(sys.argv[2]);" + entry
    process = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), transport.encode(argument).decode()],
        capture_output=True, timeout=10, env={"LC_ALL": "C"})
    assert process.returncode == 0, process.stderr.decode()


@pytest.mark.parametrize("raw", (b'{"x":NaN}', b'{"x":1e309}', b'{"x":1,"x":2}', b'[]', b'{"x":' + b'['*65 + b'0'+b']'*65+b'}', b' '*131073))
def test_routing_bootstrap_is_finite_bounded_and_unambiguous(raw):
    with pytest.raises(ValueError): transport.decode(raw)


@pytest.mark.integration
def test_bootstrap_closes_received_descriptors_on_malformed_message():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for Linux descriptor custody")
    assert sys.platform == "linux"
    import array
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    source = os.open(os.devnull, os.O_RDONLY)
    try:
        before = set(os.listdir('/proc/self/fd'))
        left.sendmsg([b'{"x":1e309}'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [source, source]))])
        with pytest.raises(ValueError): transport.receive_bootstrap(right)
        # The sender's originals stay open; no received file description leaks.
        os.fstat(source)
        assert set(os.listdir('/proc/self/fd')) == before
    finally:
        left.close(); right.close(); os.close(source)
