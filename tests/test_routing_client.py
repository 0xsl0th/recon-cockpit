"""Portable authority/command checks; these do not claim routed execution."""

from copy import deepcopy
import hashlib
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_execution as execution
from recon_cockpit.secure_agent import routing_client_runtime as runtime, routing_client_worker as worker
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.stock_http_spec import encode
from test_routing_contract import SESSION, identity, runtime as runtime_bundle
from test_stock_ssh_client import HOST, NONCE


def envelope(selector="ssh_keys"):
    selected = contract.selection()
    bundle = runtime_bundle()
    action = parse_action(contract.action(selected, selector))
    policy, limits = contract.policy_for_selection(selected), contract.limits(selected)
    return {"mode": contract.PROFILE, "selection": selected, "selector": selector,
        "identity": identity(), "runtime": bundle[selector],
        "namespaces": {name: name + ":[200]" for name in HOST},
        "launch": {"schema_version": "1", "mode": contract.PROFILE, "execute": True, "session_id": SESSION,
            "nonce": NONCE, "sequence": 1, "action": action.to_dict(), "action_digest": action.digest,
            "policy": policy.to_dict(), "policy_digest": policy.digest, "limits": limits,
            "limits_digest": contract.digest(limits), "deadline": 150,
            "output_reserved_before": 0, "output_reserved_after": action.parameters.max_output_bytes,
            "host_namespaces": HOST}}


def consume(value):
    raw = encode(value)
    return execution.consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_four_exact_envelopes_fit_bound_and_keep_selected_runtime(selector):
    value = envelope(selector)
    assert len(encode(value)) < 32768
    request, deadline, namespaces, runtime_digest = consume(value)
    assert request["selector"] == selector and request["selection"] == value["selection"]
    assert request["target"] == value["launch"]["action"]["target"]
    assert request["parameters"] == value["launch"]["action"]["parameters"]
    assert deadline == 150 and namespaces == value["namespaces"]
    assert runtime_digest == value["identity"]["runtimes"][selector]["client_runtime_sha256"]
    if selector == "http_headers":
        with pytest.raises(ValueError): worker.argv_for(request)
    else:
        argv = worker.argv_for(request)
        assert request["target"] in argv
        assert all(word not in argv for word in ("--script", "-A", "-sS", "--script-args"))
        assert argv[0] == ("/tool/ssh-keyscan" if selector == "ssh_keys" else "/tool/nmap")


@pytest.mark.parametrize("field,bad", (("nonce", "b" * 64), ("sequence", True), ("sequence", 5),
    ("mode", "stock_ssh_v1"), ("execute", False), ("deadline", 100), ("deadline", 161),
    ("output_reserved_after", 8191), ("output_reserved_before", True), ("action_digest", "b" * 64),
    ("policy_digest", "b" * 64), ("limits_digest", "b" * 64), ("session_id", "invalid")))
def test_launch_mutations_fail_closed(field, bad):
    value = envelope(); value["launch"][field] = bad
    with pytest.raises(ValueError): consume(value)


@pytest.mark.parametrize("field", ("selection", "selector", "runtime", "namespaces", "identity"))
def test_other_action_or_other_context_cannot_reuse_envelope(field):
    value = envelope()
    if field == "selection": value[field] = contract.selection("ssh_zero")
    elif field == "selector": value[field] = "ssh_nmap"
    elif field == "runtime": value[field] = runtime_bundle()["ssh_nmap"]
    elif field == "namespaces": value[field] = HOST
    else: value[field]["runtimes"]["ssh_keys"]["daemon_runtime_sha256"] = "0" * 64
    with pytest.raises(ValueError): consume(value)


def test_commitment_unknown_fields_and_duplicate_json_are_rejected():
    value = envelope(); raw = encode(value)
    with pytest.raises(ValueError): execution.consume_launch(raw, NONCE, "0" * 64, now=100)
    value["unreviewed"] = True
    with pytest.raises(ValueError): consume(value)
    raw = b'{"mode":"x","mode":"y"}'
    with pytest.raises(ValueError): execution.consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_go_is_nonce_bound_and_uses_short_action_clock(selector):
    cap = contract.action_bounds(selector)["timeout_seconds"]
    assert worker.validate_go(encode({"nonce": NONCE, "deadline": 100 + cap}), NONCE, 160, selector, now=100) == 100 + cap
    for change in ({"nonce": "b" * 64}, {"deadline": 100}, {"deadline": 100 + cap + .001}, {"extra": True}):
        with pytest.raises(ValueError):
            worker.validate_go(encode({"nonce": NONCE, "deadline": 100 + cap, **change}), NONCE, 160, selector, now=100)


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_client_command_joins_only_selected_namespace_and_has_no_private_mount(monkeypatch, selector):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    manifest = runtime_bundle()[selector]["client"]
    files = [] if manifest is None else runtime.client_runtime_module(selector).runtime_files(manifest)
    service = SimpleNamespace(selector=selector, namespace_fds=(31, 32))
    command = runtime.command(service, ("/usr/lib/python3.13", [
        ("/usr/bin/nft", "/usr/bin/nft"), ("/usr/bin/ip", "/usr/bin/ip"),
        ("/usr/bin/python3", "/usr/bin/python3")]), manifest, tuple(range(40, 40 + len(files))), NONCE, "c" * 64)
    assert command[:3] == ["/usr/bin/nsenter", "--user=/proc/self/fd/31", "--net=/proc/self/fd/32"]
    assert "--unshare-net" not in command and "--as-pid-1" not in command
    assert command[command.index("--cap-add") + 1] == "CAP_SETPCAP"
    assert "CAP_NET_ADMIN" not in command and "CAP_SYS_ADMIN" not in command
    assert not any(path in command for path in ("/peer", "/stock-peer", "/scratch", "/usr/bin/nft", "/usr/bin/ip"))
    assert "routing_topology_spec" in runtime.MODULES


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_witness_targets_are_fixed_other_service_excluded_and_wrong_port(selector):
    endpoints = worker.witness_endpoints(selector)
    assert len(endpoints) == len(set(endpoints)) == 3
    assert ("10.77.0.99", 8080) in endpoints
    action = contract.action(contract.selection(), selector)
    assert (action["target"], action["parameters"]["port"]) not in endpoints
    assert all(address.startswith("10.77.0.") for address, _ in endpoints)


@pytest.mark.parametrize("flag", (1, False, "true", None))
def test_header_result_requires_observed_routed_flags_with_exact_boolean_types(flag):
    from test_stock_http_client import header_reply
    value = header_reply()
    value["boundary_checks"] = dict.fromkeys(runtime.BOUNDARY_NAMES, True)
    assert runtime.header_reply(encode(value), "http_headers") == value
    value["boundary_checks"]["routed_namespace_verified"] = flag
    with pytest.raises(ValueError): runtime.header_reply(encode(value), "http_headers")


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_actual_client_module_mounts_import_and_verify_without_repository(tmp_path, monkeypatch, selector):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    value = envelope(selector); manifest = value["runtime"]["client"]
    files = [] if manifest is None else runtime.client_runtime_module(selector).runtime_files(manifest)
    command = runtime.command(SimpleNamespace(selector=selector, namespace_fds=(31, 32)), ("/stdlib", []),
        manifest, tuple(range(40, 40 + len(files))), NONCE, "c" * 64)
    for index, flag in enumerate(command):
        if flag == "--ro-bind" and command[index + 2].startswith("/app/"):
            path = tmp_path / command[index + 2].removeprefix("/app/")
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(command[index + 1], path)
    code = """import sys,hashlib
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent import routing_client_worker, routing_execution
raw=sys.argv[2].encode()
request,*_=routing_execution.consume_launch(raw,sys.argv[3],hashlib.sha256(raw).hexdigest(),now=100)
if request['selector']!='http_headers': routing_client_worker.argv_for(request)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), encode(value).decode(), NONCE],
        capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
