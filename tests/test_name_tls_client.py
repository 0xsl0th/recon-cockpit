"""Adversarial client envelopes without creating a namespace or native process."""

from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_public as public
from recon_cockpit.secure_agent import name_tls_execution as execution, name_tls_client as client
from recon_cockpit.secure_agent import name_tls_client_worker as worker
from recon_cockpit.secure_agent import name_tls_native_runtime as native
from recon_cockpit.secure_agent.models import parse_action
from test_name_tls_authority import Harness
from test_name_tls_native_runtime import prepared

NONCE = "a" * 64
HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}


def envelope(slot="dns_1", configuration="A"):
    h = Harness(configuration=configuration)
    binding = None
    if slot != "dns_1":
        h.dns()
        binding = h.ledger.snapshot()["binding"]
    selected, owner = h.selected, h.identity
    action = parse_action(contract.dns_action(selected, owner) if binding is None else
                         contract.service_action(selected, owner, slot, binding))
    op = contract.operation(slot)
    manifest = None if op == "http" else native.partition(prepared(configuration, "O4"), op + "_client")
    policy = contract.policy_for_selection(selected)
    limits = contract.limits(selected)
    return {"mode": contract.PROFILE, "selection": selected, "identity": owner, "binding": binding,
        "runtime": manifest, "namespaces": {name: name + ":[200]" for name in HOST},
        "launch": {"schema_version": "1", "mode": contract.PROFILE, "execute": True,
            "session_id": owner["session_id"], "nonce": NONCE, "sequence": 1 if binding is None else 2,
            "action": action.to_dict(), "action_digest": action.digest, "policy": policy.to_dict(),
            "policy_digest": policy.digest, "limits": limits, "limits_digest": contract.digest(limits),
            "deadline": 150, "output_reserved_before": 0,
            "output_reserved_after": action.parameters.max_output_bytes, "host_namespaces": HOST}}


def consume(value, monkeypatch):
    monkeypatch.setattr(execution.time, "monotonic", lambda: 100)
    raw = public.encode(value)
    return execution.consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("slot", ("dns_1", "http", "tls"))
@pytest.mark.parametrize("configuration", ("A", "B"))
def test_exact_client_envelope_matches_fixed_native_partition(slot, configuration, monkeypatch):
    value = envelope(slot, configuration)
    checked, action = consume(value, monkeypatch)
    assert checked == value
    assert action.to_dict() == value["launch"]["action"]
    assert len(public.encode(value)) <= 32768


@pytest.mark.parametrize("field,bad", (("nonce", "b" * 64), ("sequence", True), ("sequence", 4),
    ("mode", "disconnected_routing_v1"), ("execute", False), ("deadline", 100), ("deadline", 161),
    ("output_reserved_after", 8191), ("output_reserved_before", True), ("action_digest", "b" * 64),
    ("policy_digest", "b" * 64), ("limits_digest", "b" * 64), ("session_id", "invalid")))
def test_recommitted_launch_mutations_still_fail_closed(field, bad, monkeypatch):
    value = envelope()
    value["launch"][field] = bad
    with pytest.raises(ValueError):
        consume(value, monkeypatch)


@pytest.mark.parametrize("slot", ("http", "tls"))
@pytest.mark.parametrize("field", ("binding", "runtime", "namespaces", "identity", "selection"))
def test_foreign_binding_or_runtime_cannot_authorize_service(slot, field, monkeypatch):
    value = envelope(slot)
    other = envelope(slot, "B")
    if field == "namespaces":
        value[field] = HOST
    elif field == "runtime" and slot == "http":
        value[field] = envelope("tls")["runtime"]
    else:
        value[field] = other[field]
    with pytest.raises(ValueError):
        consume(value, monkeypatch)


@pytest.mark.parametrize("slot", ("dns_1", "http", "tls"))
def test_release_requires_exact_nonce_and_short_native_deadline(slot, monkeypatch):
    monkeypatch.setattr(worker.time, "monotonic", lambda: 100)
    cap = contract.action_bounds(slot)["timeout_seconds"]
    assert worker.validate_go(public.encode({"nonce": NONCE, "deadline": 100 + cap}), NONCE, 160, cap) == 100 + cap
    for change in ({"nonce": "b" * 64}, {"deadline": 100}, {"deadline": 100 + cap + .001}, {"extra": True}):
        with pytest.raises(ValueError):
            worker.validate_go(public.encode({"nonce": NONCE, "deadline": 100 + cap, **change}), NONCE, 160, cap)


def test_key_bearing_owner_modules_are_absent_from_client_closure():
    forbidden = {"name_tls_spec", "name_tls_runtime", "name_tls_native_runtime", "name_tls_daemon_worker",
                 "network_tools_fixture", "network_tools_tls_certificate_material"}
    assert not forbidden.intersection(client.MODULES)
    assert "name_tls_worker_common" in client.MODULES
    assert "name_tls_execution" in client.MODULES


def test_read_only_command_requires_sealed_exact_source_inventory(monkeypatch):
    from recon_cockpit.secure_agent import name_tls_python_runtime as sources
    value = envelope("http")
    service = SimpleNamespace(slot="http", selection=value["selection"], namespace_fds=(3, 4))
    monkeypatch.setattr(client, "_trusted_program", lambda name: "/usr/bin/" + name)
    with pytest.raises(ValueError, match="snapshot_inventory"):
        client.command(service, ("/usr/lib/python3.13", []), None, [], NONCE, "b" * 64,
                       source_descriptors={}, info_fd=5)
    assert set(sources.PACKAGE_FILES) <= set(client.MODULES)
