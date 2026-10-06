"""Selected runtime custody and exact endpoint argv, without native execution."""

from copy import deepcopy
from types import SimpleNamespace
import hashlib
import time

import pytest

from recon_cockpit.secure_agent import configurable_runtime as runtime, configurable_worker as worker
from recon_cockpit.secure_agent import network_tools_runtime as accepted
from recon_cockpit.secure_agent.configurable_parser import NMAP, HEADERS, SSH
from recon_cockpit.secure_agent.configurable_contract import action
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from test_secure_configurable_parser import scope
from test_secure_network_tools_runtime import manifest


def manifests():
    return {NMAP: manifest(accepted.NMAP_SERVICE), SSH: manifest(accepted.SSH)}


def request(step):
    selected = action(scope(), step)
    return {"target": selected["target"], "parameters": selected["parameters"], "tool_id": selected["tool_id"],
            "scope": scope(), "endpoint_id": "http" if step <= 2 else "ssh"}


@pytest.mark.parametrize("step,underlying", [(1, accepted.NMAP_SERVICE), (3, accepted.NMAP_SERVICE), (4, accepted.SSH)])
def test_argv_only_changes_authorized_target_port_and_closed_probe_intensity(step, underlying):
    requested = request(step)
    args = worker.argv_for(requested)
    original = list(accepted.FIXED_ARGV[underlying])
    original[-1] = requested["target"]
    original[original.index("-p") + 1] = str(requested["parameters"]["port"])
    if underlying == accepted.NMAP_SERVICE:
        original[original.index("--version-intensity") + 1] = "1"
    assert args == tuple(original)
    assert "--version-all" not in args and "--script" not in args
    assert accepted.FIXED_ARGV[underlying][-1] == "127.0.0.1"


@pytest.mark.parametrize("step", [1, 3, 4])
@pytest.mark.parametrize("change", [lambda value: value.update(target="8.8.8.8"),
    lambda value: value["parameters"].update(port=4444),
    lambda value: value.update(endpoint_id="outside")])
def test_argv_rejects_scope_substitution(step, change):
    selected = request(step)
    change(selected)
    with pytest.raises(ValueError):
        worker.argv_for(selected)


@pytest.mark.parametrize("tool", [HEADERS, "curl", "ssh", None])
def test_unsupported_native_runtime_selection_fails(tool):
    with pytest.raises(ValueError):
        runtime.underlying_tool(tool)


def test_pin_map_uses_existing_reviewed_runtime_bytes_and_returns_copy():
    value = manifests()
    copied = runtime.validate_manifests(value)
    assert copied == value and copied is not value and copied[NMAP] is not value[NMAP]
    assert accepted.NMAP_SERVICE_PROBES.count(b"Probe TCP") == 2
    assert runtime.underlying_tool(NMAP) == accepted.NMAP_SERVICE


@pytest.mark.parametrize("change", [lambda value: value.pop(NMAP), lambda value: value.update(other=manifest()),
    lambda value: value.update({NMAP: manifest(accepted.SSH)}),
    lambda value: value[NMAP].update(executable="/usr/bin/python3"),
    lambda value: value[SSH]["files"][0].update(source="/tmp/credential")])
def test_runtime_map_rejects_missing_substituted_or_unreviewed_tool(change):
    value = manifests()
    change(value)
    with pytest.raises(ValueError):
        runtime.validate_manifests(value)


@pytest.mark.parametrize("tool", [NMAP, SSH, HEADERS])
def test_projection_contains_only_selected_runtime(tool):
    closure = {"stdlib": "/stdlib", "files": ["/lib/libc.so"], "configurable_runtime": manifests()}
    projected = runtime.project_closure(closure, tool)
    assert projected["configurable_runtime"] == (None if tool == HEADERS else manifests()[tool])
    assert projected["files"] is not closure["files"]


@pytest.mark.parametrize("tool", [NMAP, SSH, HEADERS])
def test_child_closure_never_mounts_alternate_tool_transport_or_hostfiles(monkeypatch, tool):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    selected = None if tool == HEADERS else manifests()[tool]
    entries = [] if selected is None else accepted.runtime_files(selected)
    descriptors = list(range(40, 40 + len(entries)))
    bootstrap = ("/stdlib", [(path, path) for path in ("/usr/bin/python3", "/usr/bin/nmap", "/tool/ssh-keyscan",
        "/usr/bin/nsenter", "/usr/sbin/nft", "/usr/bin/ip", "/lib/libc.so")])
    args = runtime._command(SimpleNamespace(_namespace_fds=(30, 31)), bootstrap, selected, descriptors, "a" * 64, "b" * 64)
    mounted = [args[index + 1:index + 3] for index, value in enumerate(args) if value == "--ro-bind"]
    assert ["/usr/bin/python3", "/usr/bin/python3"] in mounted
    assert ["/lib/libc.so", "/lib/libc.so"] in mounted
    assert all(source not in {"/usr/bin/nmap", "/tool/ssh-keyscan", "/usr/bin/nsenter", "/usr/sbin/nft", "/usr/bin/ip"}
               for source, destination in mounted)
    assert "--unshare-net" not in args
    assert "--unshare-user" in args and "--cap-add" in args
    assert "--net=/proc/self/fd/31" in args
    assert args.count("--ro-bind-data") == len(entries)
    # The trusted nsenter bootstrap must also accept Python-only actions that
    # have no sealed native descriptors, while closing every namespace FD.
    close_index = args.index(runtime._CLOSE_EXCEPT)
    assert args[close_index + 1] == (",".join(map(str, descriptors)) if descriptors else "0,1,2")


def test_header_operation_rejects_scope_path_drift_before_socket(monkeypatch):
    selected = request(2)
    selected["parameters"]["path"] = "/forbidden"
    monkeypatch.setattr(worker.socket, "socket", lambda *a, **k: pytest.fail("unapproved socket"))
    with pytest.raises(ValueError):
        worker.probe_headers(selected, time.monotonic() + 10)


@pytest.mark.parametrize("answer", [ConnectionRefusedError, OSError])
def test_listening_boundary_witness_requires_drop_not_unreachable_socket(monkeypatch, answer):
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def settimeout(self, value): pass
        def connect(self, address): raise answer("not a firewall drop")
    monkeypatch.setattr(worker.socket, "socket", lambda *a: Connection())
    with pytest.raises(answer):
        worker.verify_network_boundary(scope(), "http")


def test_header_worker_reply_cannot_relabel_integer_as_boundary_proof(monkeypatch):
    import json
    lab = SimpleNamespace(_check=lambda control: None, _verify_pins=lambda: None,
                          _runtime=lambda control: ("/stdlib", []), _namespace_fds=(30, 31))
    selected = action(scope(), 2)
    launch = {"launch": {"action": selected, "nonce": "a" * 64}}
    result = {"status": "succeeded", "results": [], "bytes_received": 0,
              "truncated": False, "boundary_checks": dict.fromkeys(runtime.BOUNDARY_NAMES, True)}
    result["boundary_checks"]["cross_service_blocked"] = 1
    monkeypatch.setattr(runtime, "_command", lambda *args: ["confined"])
    def capture(command, raw, *args, **kwargs):
        prefix = runtime.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n"
        return 0, json.dumps(result).encode(), prefix, None
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    with pytest.raises(IsolationUnavailable, match="Invalid configurable header reply"):
        runtime.run_configurable_tool_owned(lab=lab, launch=launch,
            control=ExecutionControl(time.monotonic() + 10))
