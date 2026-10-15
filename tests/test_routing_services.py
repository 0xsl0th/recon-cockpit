"""Service custody/receipt validation with no daemon or namespace launch."""

from copy import deepcopy
import socket
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_services as services
from recon_cockpit.secure_agent import routing_service_contract as validation
from recon_cockpit.secure_agent import routing_frontend_worker as frontend
from recon_cockpit.secure_agent import stock_http_recorder as http, stock_ssh_recorder as ssh
from recon_cockpit.secure_agent import stock_ssh_process as process
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.stock_http_owner_worker import BOUNDS
from test_routing_contract import identity, runtime
from test_stock_ssh_owner_worker import identity as pair_identity
from test_stock_ssh_recorder import Harness as SshHarness
from test_stock_ssh_process import complete_receipt
from test_routing_frontend import budget_for


def names(number):
    return {name: name + ":[" + str(number) + "]" for name in ("user", "net", "mnt", "pid")}


def topology(configuration="A"):
    return {"owner_namespaces": names(200), "networks": {"http_client": "net:[201]", "ssh_client": "net:[202]",
        "router": "net:[203]", "http_frontend": "net:[204]", "ssh_frontend": "net:[205]"},
        "private_ssh_pairs": [{"daemon": pair_identity(index)} for index in range(4)],
        "listeners": {"http": {"netns_cookie": 789}}}


def mapping(uid):
    return {"uid_map": [[uid, 1000, 1]], "gid_map": [[uid, 1000, 1]], "launcher_uid": 1000, "launcher_gid": 1000}


def receipt(selector="http_headers", deployment=None):
    selected = contract.selection(deployment=deployment)
    owner = identity(deployment=deployment); chosen = contract.underlying_selection(selector, selected); is_ssh = selector.startswith("ssh_")
    apache = not is_ssh and contract.http_implementation(selected) == "apache"
    configuration = selected["configuration"]
    uid = 65534 if is_ssh or apache else 0
    daemon = {"namespaces": names(400), "namespace_identity": {"uid": uid, "gid": uid,
        "supplementary_groups": [uid], "setgroups_policy": "deny", "group_mutation_denied": True},
        "bounds": deepcopy(process.BOUNDS if is_ssh else BOUNDS),
        "runtime_digest": owner["runtimes"][selector]["daemon_runtime_sha256"]}
    daemon.update({"ready": True} if is_ssh else {"descriptor": {"daemon_netns_cookie": 123, "inode": 456} if apache else None})
    # No daemon is launched: accepted pure snapshot replay validates an armed,
    # empty, physically finalized local protocol instance.
    if is_ssh:
        from test_stock_ssh_recorder import PortableListener
        listener = PortableListener(); listener.bind(("127.0.0.1", 0)); listener.listen()
        old = ssh.CONFIGURATIONS[configuration]; ssh.CONFIGURATIONS[configuration] = listener.getsockname()
        try:
            service = ssh.Service(configuration, chosen["case"], listener, deadline=time.monotonic() + 60,
                connection_factory=lambda *args: None, connection_finalizer=lambda *args: None)
        finally:
            ssh.CONFIGURATIONS[configuration] = old
    else:
        listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen()
        service = http.Service(configuration, chosen["case"], listener, deadline=time.monotonic() + 60)
    service.arm(time.monotonic() + contract.action_bounds(selector)["timeout_seconds"])
    service.close()
    role = contract.selector_role(selector)
    value = {"selector": selector, "action_sequence": 1,
        "action_digest": contract.digest(contract.action(selected, selector)), "underlying_selection": chosen,
        "daemon_ready": daemon, "daemon_mapping": mapping(uid),
        "frontend_ready": {"ready": True, "role": role, "namespaces": {**names(300), "net": topology()["networks"][role]},
            "listener": list(services.endpoints(configuration)["ssh" if is_ssh else "http"]), "bounds": deepcopy(BOUNDS),
            "private_pairs": [pair_identity(index) for index in range(4)] if is_ssh else []},
        "frontend_mapping": mapping(0), "recorder": service.snapshot(), "instances": [], "reservations": [],
        "budget_denied": False, "last_budget_reply": None,
        "closure": {"daemon_processes_reaped": True, "action_connections_closed": True, "frontend_persists": True, "topology_persists": True}}
    if apache:
        value["apache_descriptor_custody"] = {"version": "1", "descriptor": deepcopy(daemon["descriptor"]),
            "frontend_netns_cookie": 789, "unconnected_at_transfer": True, "transferred_once": True,
            "frontend_consumed": False, "frontend_copy_closed": True, "listener_verified": True,
            "owner_copy_closed": True, "launcher_copy_closed": True}
    return value


def validate(value, selected=None, owner=None):
    return validation.validate_service(value, selected=selected or contract.selection(), identity=owner or identity(), topology=topology())


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_empty_finalized_service_receipt_binds_exact_case_and_separate_custody(selector):
    value = receipt(selector)
    assert validate(value) == value
    checked = validate(value); checked["closure"]["daemon_processes_reaped"] = False
    assert value["closure"]["daemon_processes_reaped"] is True


@pytest.mark.parametrize("fault", ("selector", "sequence", "action", "case", "runtime", "frontend_net", "frontend_user",
    "daemon_net", "daemon_user", "daemon_uid", "mapping_root", "mapping_owner", "bounds_bool", "pairs", "instances",
    "unarmed", "unfinished", "closure", "closure_bool", "denied", "last_reply", "extra"))
def test_rehashed_receipts_cannot_hide_changed_custody_or_false_cleanup(fault):
    value = receipt("ssh_keys")
    if fault == "selector": value["selector"] = "ssh_nmap"
    elif fault == "sequence": value["action_sequence"] = True
    elif fault == "action": value["action_digest"] = "0" * 64
    elif fault == "case": value["underlying_selection"] = contract.underlying_selection("ssh_nmap")
    elif fault == "runtime": value["daemon_ready"]["runtime_digest"] = "0" * 64
    elif fault == "frontend_net": value["frontend_ready"]["namespaces"]["net"] = "net:[201]"
    elif fault == "frontend_user": value["frontend_ready"]["namespaces"]["user"] = "user:[200]"
    elif fault == "daemon_net": value["daemon_ready"]["namespaces"]["net"] = "net:[205]"
    elif fault == "daemon_user": value["daemon_ready"]["namespaces"]["user"] = "user:[300]"
    elif fault == "daemon_uid": value["daemon_ready"]["namespace_identity"]["uid"] = 0
    elif fault == "mapping_root": value["daemon_mapping"]["launcher_uid"] = 0
    elif fault == "mapping_owner": value["daemon_mapping"]["launcher_uid"] = 1001; value["daemon_mapping"]["uid_map"][0][1] = 1001
    elif fault == "bounds_bool": value["frontend_ready"]["bounds"]["no_children"] = 1
    elif fault == "pairs": value["frontend_ready"]["private_pairs"].reverse()
    elif fault == "instances": value["instances"].append({"connection_id": 1, "receipt": complete_receipt()})
    elif fault == "unarmed": value["recorder"]["armed"] = False
    elif fault == "unfinished": value["recorder"].update(finalized=False, terminal_reason="running")
    elif fault == "closure": value["closure"]["daemon_processes_reaped"] = False
    elif fault == "closure_bool": value["closure"]["daemon_processes_reaped"] = 1
    elif fault == "denied": value["budget_denied"] = True
    elif fault == "last_reply": value["last_budget_reply"] = {}
    else: value["extra"] = True
    with pytest.raises(ValueError): validate(value)


def test_actual_protocol_receipt_checks_private_instance_and_every_reserved_byte(monkeypatch):
    h = SshHarness(monkeypatch)
    h.service.__class__ = frontend.SshService
    owner, wire, budget = budget_for(monkeypatch, h, "ssh_keys")
    try:
        h.exchange_to_reply(); h.service.close()
        value = receipt("ssh_keys")
        value.update(recorder=h.service.snapshot(), reservations=deepcopy(budget.reservations), last_budget_reply=budget.last_reply)
        instance = complete_receipt(); instance["descriptor"] = pair_identity(3)
        value["instances"] = [{"connection_id": 1, "receipt": instance}]
        assert validate(value) == value
        for field in ("instance", "missing_reservation", "sequence", "count", "lease", "extra"):
            forged = deepcopy(value)
            if field == "instance": forged["instances"][0]["receipt"]["descriptor"] = pair_identity(0)
            elif field == "missing_reservation": forged["reservations"] = [] ; forged["last_budget_reply"] = None
            elif field == "sequence": forged["reservations"][1]["message"]["sequence"] += 1
            elif field == "count":
                row = next(row for row in forged["reservations"] if row["message"]["operation"] == "RESERVE_BYTES")
                row["message"]["bytes"] = 1
            elif field == "lease": forged["reservations"][-1]["message"]["lease"] = "0" * 64
            else: forged["reservations"][0]["message"]["extra"] = True
            with pytest.raises(ValueError): validate(forged)
    finally:
        h.close()


def test_services_constructor_is_metadata_only_and_binds_runtime_control(monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError("constructor performed native work")
    monkeypatch.setattr(services.socket, "socketpair", forbidden)
    monkeypatch.setattr(services.os, "mkdir", forbidden)
    bundle = runtime(); control = ExecutionControl(time.monotonic() + 60)
    value = services.Services(object(), selection=contract.selection(), identity=identity(), runtime=bundle,
        closure={"routing_runtime": bundle}, control=control, arm_action=lambda *args: None)
    assert value.frontends == {} and value.current_daemon is None
    assert value.close() == {"closed": True, "frontends_reaped": [], "all_processes_reaped": True,
        "all_control_descriptors_closed": True, "actions_completed": 0}
    with pytest.raises(ValueError): services.Services(object(), selection=contract.selection(), identity=identity(),
        runtime=bundle, closure={"routing_runtime": {}}, control=control, arm_action=lambda *args: None)


def test_action_arm_reserves_global_budget_before_frontend_release(monkeypatch):
    events = []
    owner = SimpleNamespace(selection=contract.selection(), identity=identity(),
        topology=SimpleNamespace(namespace_fds=lambda role: (31, 32), namespaces=lambda role: names(200)),
        arm_action=lambda *args: events.append(("ledger", args)),
        _command=lambda *args, **kwargs: events.append(("frontend", kwargs)))
    view = services._ActionView(owner, object(), "http_headers", 1, "a" * 64)
    monkeypatch.setattr(view, "check", lambda control: events.append(("check", control)))
    view.arm(None, 105)
    assert [row[0] for row in events] == ["check", "ledger", "frontend"]
    assert events[-1][1] == {"deadline": 105}


@pytest.mark.parametrize("role", ("http_frontend", "ssh_frontend"))
def test_frontend_command_retains_only_received_network_and_no_setup_capabilities(monkeypatch, role):
    monkeypatch.setattr(services, "_trusted_program", lambda name: "/usr/bin/" + name)
    command = services.frontend_command(("/usr/lib/python3.13", [("/usr/bin/ip", "/usr/bin/ip")]), role, (31, 32), 33)
    assert command[:3] == ["/usr/bin/nsenter", "--user=/proc/self/fd/31", "--net=/proc/self/fd/32"]
    assert "--as-pid-1" in command and "--unshare-net" not in command
    assert "CAP_NET_ADMIN" not in command and "CAP_SYS_ADMIN" not in command and "/usr/bin/ip" not in command
    assert ("/peer" in command) == (role == "http_frontend")
    assert "routing_service_contract" in services.MODULES


@pytest.mark.parametrize("selector", ("http_nmap", "http_headers"))
def test_nginx_scratch_is_fixed_per_action_and_cannot_fall_back(monkeypatch, selector):
    monkeypatch.setattr(services.http_lab, "daemon_command", lambda *args: ["bwrap", "--bind", "/stock-peer", "/scratch"])
    assert services.daemon_command(None, None, (), selector, 10) == ["bwrap", "--bind", "/stock-peer/" + selector, "/scratch"]
    monkeypatch.setattr(services.http_lab, "daemon_command", lambda *args: ["bwrap"])
    with pytest.raises(ValueError): services.daemon_command(None, None, (), selector, 10)


def test_actual_frontend_module_mounts_import_without_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(services, "_trusted_program", lambda name: "/usr/bin/" + name)
    command = services.frontend_command(("/stdlib", []), "ssh_frontend", (31, 32), 33)
    for index, flag in enumerate(command):
        if flag == "--ro-bind" and command[index + 2].startswith("/app/"):
            path = tmp_path / command[index + 2].removeprefix("/app/")
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(command[index + 1], path)
    code = """import sys
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent import routing_frontend_worker, routing_client_worker
from recon_cockpit.secure_agent import routing_service_contract
assert routing_frontend_worker.contract.underlying_selection('ssh_keys')['case']=='O2'
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_deployment_service_receipts_bind_configuration_implementation_and_transport(deployment, selector):
    selected = contract.selection(deployment=deployment)
    owner = identity(deployment=deployment)
    value = receipt(selector, deployment)
    assert validate(value, selected, owner) == value
    assert ("apache_descriptor_custody" in value) == (deployment.startswith("apache") and selector.startswith("http_"))
    other = "nginx-A" if deployment != "nginx-A" else "nginx-B"
    with pytest.raises(ValueError):
        validate(value, contract.selection(deployment=other), identity(deployment=other))


@pytest.mark.parametrize("fault", ("identity", "same_cookie", "wrong_frontend", "connected", "reused", "owner_open", "launcher_open", "frontend_open", "unverified_listener", "unreserved_consumption", "consumed_bool", "missing", "extra", "root_uid"))
def test_apache_custody_receipt_refuses_changed_identity_or_invented_cleanup(fault):
    selected = contract.selection(deployment="apache-B")
    owner = identity(deployment="apache-B")
    value = receipt("http_headers", "apache-B")
    custody = value["apache_descriptor_custody"]
    if fault == "identity": custody["descriptor"]["inode"] += 1
    elif fault == "same_cookie": custody["frontend_netns_cookie"] = custody["descriptor"]["daemon_netns_cookie"]
    elif fault == "wrong_frontend": custody["frontend_netns_cookie"] += 1
    elif fault == "connected": custody["unconnected_at_transfer"] = False
    elif fault == "reused": custody["transferred_once"] = False
    elif fault == "owner_open": custody["owner_copy_closed"] = False
    elif fault == "launcher_open": custody["launcher_copy_closed"] = False
    elif fault == "frontend_open": custody["frontend_copy_closed"] = False
    elif fault == "unverified_listener": custody["listener_verified"] = False
    elif fault == "unreserved_consumption": custody["frontend_consumed"] = True
    elif fault == "consumed_bool": custody["frontend_consumed"] = 0
    elif fault == "missing": del value["apache_descriptor_custody"]
    elif fault == "extra": custody["extra"] = True
    else: value["daemon_ready"]["namespace_identity"]["uid"] = 0
    with pytest.raises(ValueError): validate(value, selected, owner)


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
def test_frontend_mounts_peer_only_for_selected_nginx(monkeypatch, deployment):
    monkeypatch.setattr(services, "_trusted_program", lambda name: "/usr/bin/" + name)
    selected = contract.selection(deployment=deployment)
    command = services.frontend_command(("/stdlib", []), "http_frontend", (31, 32), 33, selected)
    assert ("/peer" in command) == deployment.startswith("nginx")
    assert ("/stock-peer" in command) == deployment.startswith("nginx")
    assert command[command.index("--uid") + 1] == "0"
    assert "CAP_NET_ADMIN" not in command and "CAP_SYS_ADMIN" not in command


@pytest.mark.parametrize("deployment", ("apache-A", "apache-B"))
@pytest.mark.parametrize("selector", ("http_nmap", "http_headers"))
def test_apache_daemon_command_keeps_accepted_nonzero_mapping_and_per_action_scratch(monkeypatch, deployment, selector):
    monkeypatch.setattr(services.http_lab, "_trusted_program", lambda name: "/usr/bin/" + name)
    selected = contract.selection(deployment=deployment)
    manifest = runtime(deployment)[selector]["daemon"]
    descriptors = tuple(range(40, 40 + len(manifest["files"])))
    command = services.daemon_command(("/stdlib", []), manifest, descriptors, selector, 30, selected)
    assert command[command.index("--uid") + 1] == command[command.index("--gid") + 1] == "65534"
    index = command.index("--bind")
    assert command[index + 1:index + 3] == ["/stock-peer/" + selector, "/scratch"]
    assert "/peer" not in command and "--as-pid-1" in command
