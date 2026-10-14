"""Continuity, immutable scope and two-owner lifecycle checks without sockets."""

import copy
import io
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import configurable_lab as lab_module, configurable_lab_contract as contract
from recon_cockpit.secure_agent.configurable_lab import ConfigurableLab, ConfigurableEndpointLab, ConfinedConfigurableLab
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.session_limits import SessionLimits

SCOPE = {"schema_version": "1", "scope_id": "owned-http-ssh",
         "http": {"target": "10.9.0.10", "port": 8088, "path": "/training/portal"},
         "ssh": {"target": "172.20.0.11", "port": 2222}}
SESSION = str(UUID(int=555))
LIMITS = SessionLimits(4, 60, 26624)


def test_construction_and_close_are_metadata_only_and_owner_ids_are_distinct(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("metadata started a process"))
    lab = ConfigurableLab(SCOPE, SESSION, LIMITS)
    fixed = lab.identity
    assert contract.validate_assessment_identity(fixed, scope=SCOPE) == fixed
    assert fixed["endpoints"]["http"]["instance_id"] != fixed["endpoints"]["ssh"]["instance_id"]
    assert not lab.started
    for name in ("http", "ssh"):
        assert lab.endpoint_lab(name).identity == fixed["endpoints"][name]
    receipt = lab.close()
    assert contract.validate_assessment_closure(receipt, fixed) == receipt
    receipt["status"] = "forged"
    assert lab.close()["status"] == "closed"
    with pytest.raises(IsolationUnavailable):
        lab.endpoint_lab("http")


def test_scope_and_identity_returns_do_not_alias_caller_configuration():
    scope = copy.deepcopy(SCOPE)
    lab = ConfigurableLab(scope, SESSION, LIMITS)
    scope["http"]["path"] = "/changed"
    leaked = lab.identity
    leaked["scope"]["http"]["path"] = "/changed"
    assert lab.identity["scope"] == SCOPE
    assert lab.endpoint_lab("http").scope == SCOPE


@pytest.mark.parametrize("field", ["scope_id", "http", "ssh"])
def test_whole_scope_binds_every_endpoint_identity(field):
    changed = copy.deepcopy(SCOPE)
    if field == "scope_id": changed[field] = "another-lab"
    else: changed[field]["port"] += 1
    for name in ("http", "ssh"):
        fixed = contract.identity(SCOPE, name, str(UUID(int=1)))
        with pytest.raises(ValueError):
            contract.validate_identity(fixed, scope=changed)
        assert contract.identity(changed, name, str(UUID(int=1)))["spec_sha256"] != fixed["spec_sha256"]


@pytest.mark.parametrize("field,value", [("scope_sha256", "a" * 64), ("spec_sha256", "b" * 64),
    ("endpoint", "http"), ("target", "10.9.0.12"), ("port", 8090), ("instance_id", "bad"),
    ("id", "owned-lab"), ("version", "2"), ("extra", True)])
def test_identity_cannot_be_substituted_even_with_valid_field_types(field, value):
    fixed = contract.identity(SCOPE, "ssh", str(UUID(int=2)))
    fixed[field] = value
    with pytest.raises(ValueError):
        contract.validate_identity(fixed, scope=SCOPE, endpoint_name="ssh")


@pytest.mark.parametrize("name,connections,requests", [("http", 5, 2), ("ssh", 4, 2),
    ("http", True, 1), ("ssh", 1, True), ("http", 1, 2), ("ssh", 3, 3), ("http", -1, 0)])
def test_context_rejects_expanded_or_ambiguous_counters(name, connections, requests):
    fixed = contract.identity(SCOPE, name, str(UUID(int=2)))
    with pytest.raises(ValueError):
        contract.validate_context({"identity": fixed, "connection_count": connections, "request_count": requests}, fixed)


def test_closure_acknowledges_exact_last_known_counts_and_no_new_sample():
    lab = ConfigurableLab(SCOPE, SESSION, LIMITS)
    previous = {"identity": lab.identity, "step": 4, "endpoints": {}}
    for name, count in (("http", 4), ("ssh", 3)):
        selected = lab.endpoint_lab(name)
        selected._counts = {"connection_count": count, "request_count": 2}
        previous["endpoints"][name] = {"identity": selected.identity, **selected._counts}
    receipt = lab.close()
    assert contract.validate_assessment_closure(receipt, lab.identity, previous=previous) == receipt
    receipt["endpoints"]["http"]["connection_count"] = 3
    with pytest.raises(ValueError):
        contract.validate_assessment_closure(receipt, lab.identity, previous=previous)


def test_cleanup_attempts_both_owners_even_when_first_cleanup_fails(monkeypatch):
    lab = ConfigurableLab(SCOPE, SESSION, LIMITS)
    http, ssh = lab.endpoint_lab("http"), lab.endpoint_lab("ssh")
    called = []
    def broken():
        called.append("http")
        raise IsolationUnavailable("cleanup failed")
    monkeypatch.setattr(http, "close", broken)
    monkeypatch.setattr(ssh, "close", lambda: called.append("ssh"))
    with pytest.raises(IsolationUnavailable):
        lab.close()
    assert called == ["http", "ssh"]
    with pytest.raises(IsolationUnavailable):
        lab.endpoint_lab("ssh")


@pytest.mark.parametrize("limits", [SessionLimits(5, 60, 26624), SessionLimits(4, 61, 26624),
                                     SessionLimits(4, 60, 26625)])
def test_lab_limits_may_only_shorten_fixed_ceilings(limits):
    with pytest.raises(ValueError):
        ConfigurableLab(SCOPE, SESSION, limits)


def test_expired_control_permanently_closes_selected_owner_before_runtime_inspection(monkeypatch):
    lab = ConfigurableLab(SCOPE, SESSION, LIMITS)
    selected = lab.endpoint_lab("http")
    monkeypatch.setattr(selected, "_runtime", lambda *_: pytest.fail("expired control inspected runtime"))
    with pytest.raises(ExecutionStopped):
        selected.start(ExecutionControl(time.monotonic() - 1))
    with pytest.raises(IsolationUnavailable):
        selected.start(ExecutionControl(time.monotonic() + 10))
    assert not lab.endpoint_lab("ssh").started
    lab.close()


def test_mutated_scope_cannot_start_an_owner(monkeypatch):
    lab = ConfigurableLab(SCOPE, SESSION, LIMITS)
    selected = lab.endpoint_lab("http")
    selected.scope["http"]["port"] += 1
    monkeypatch.setattr(selected, "_runtime", lambda *_: pytest.fail("mutated scope inspected runtime"))
    with pytest.raises(IsolationUnavailable, match="scope changed"):
        selected.start(ExecutionControl(time.monotonic() + 10))
    lab.close()


def test_confined_reconstruction_preserves_both_owner_identities_and_runtime_closure():
    original = ConfigurableLab(SCOPE, SESSION, LIMITS)
    config = {"owned_lab": original.identity, "session_id": SESSION, "execute": True,
              "limits": {"max_steps": 4, "max_runtime_seconds": 60, "max_output_bytes": 26624}}
    closure = {"stdlib": "/usr/lib/python3.13", "files": ["/usr/bin/python3", "/usr/sbin/nft", "/usr/bin/nsenter"]}
    lab = ConfinedConfigurableLab(config, closure)
    assert lab.identity == original.identity
    for name in ("http", "ssh"):
        selected = lab.endpoint_lab(name)
        assert selected._runtime(ExecutionControl(time.monotonic() + 10)) == (
            "/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"), ("/usr/sbin/nft", "/usr/sbin/nft")])
    assert lab.close() == original.close()


def test_owner_command_adds_only_fixed_owner_fixture_modules(monkeypatch):
    monkeypatch.setattr("recon_cockpit.secure_agent.isolation._trusted_program", lambda name: "/usr/bin/" + name)
    selected = ConfigurableEndpointLab(SCOPE, "http", SESSION, LIMITS)
    argv = selected._owner_command("/usr/lib/python3.13", [], 8)
    assert argv[-1] == "/app/configurable_lab_worker.py"
    assert "--unshare-net" in argv and "CAP_NET_ADMIN" in argv
    assert "/app/network_tools_ssh_fixture.py" in argv
    assert all("/Downloads/" not in part and "--bind" != part for part in argv)


@pytest.mark.parametrize("omit_mx", (False, True))
def test_actual_owner_module_mounts_cold_import_without_repository_fallback(tmp_path, monkeypatch, omit_mx):
    """Exercise the standalone import path that the real namespace owner uses."""
    monkeypatch.setattr("recon_cockpit.secure_agent.isolation._trusted_program", lambda name: "/usr/bin/" + name)
    selected = ConfigurableEndpointLab(SCOPE, "http", SESSION, LIMITS)
    argv = selected._owner_command("/usr/lib/python3.13", [], 8)
    staged = tmp_path / "app"
    staged.mkdir()
    for index, value in enumerate(argv):
        if value != "--ro-bind":
            continue
        source, destination = argv[index + 1:index + 3]
        target = Path(destination)
        if target.parent == Path("/app") and target.suffix == ".py":
            if omit_mx and target.name == "network_tools_dns_mx_fixture.py":
                continue
            shutil.copyfile(source, staged / target.name)
    code = """import pathlib,runpy,sys
root=pathlib.Path(sys.argv[1])
loaded={path.name:runpy.run_path(str(path),run_name='closed_owner_module')
        for path in sorted(root.glob('*.py'))}
owner=loaded['configurable_lab_worker.py']
assert pathlib.Path(owner['network']._mx_fixture.__file__).parent==root
assert pathlib.Path(owner['scope_contract'].__file__).parent==root
assert owner['header_request']({'target':'10.9.0.10','port':8088,'path':'/training/portal'}).startswith(b'GET /training/portal HTTP/1.1\\r\\n')
assert owner['header_response']().startswith(b'HTTP/1.1 ')
print('closed-owner-imports-ok')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(staged)],
                            cwd=tmp_path, env={"LC_ALL": "C"}, capture_output=True,
                            timeout=10, check=False)
    if omit_mx:
        assert result.returncode != 0 and result.stdout == b""
        assert b"FileNotFoundError" in result.stderr and b"network_tools_dns_mx_fixture.py" in result.stderr
    else:
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        assert result.stdout == b"closed-owner-imports-ok\n" and result.stderr == b""
