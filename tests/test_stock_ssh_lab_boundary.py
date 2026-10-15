"""Metadata cannot create owners; owner mounts retain separate commitments."""

from copy import deepcopy
import time

import pytest

from recon_cockpit.secure_agent import stock_ssh_lab as lab, stock_ssh_backend as backend
from recon_cockpit.secure_agent import stock_ssh_contract as contract, stock_ssh_spec as spec
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_stock_ssh_client import envelope


def objects():
    value = envelope("A", "O2")
    limits = SessionLimits(**contract.limits(value["selection"]))
    metadata = lab.StockSshLab(value["selection"], value["identity"]["session_id"], limits,
                              execute=True, runtime=value["runtime"], identity=value["identity"])
    return value, limits, metadata


@pytest.mark.parametrize("fault", ("metadata", "metadata_with_closure", "subclass", "missing_closure", "runtime_changed"))
def test_unwitnessed_or_changed_lab_refused_before_owner_creation(monkeypatch, fault):
    value, limits, metadata = objects()
    closure = {"stock_ssh_runtime": deepcopy(value["runtime"])}
    if fault == "metadata_with_closure":
        metadata._closure = closure
    elif fault not in ("metadata", "metadata_with_closure"):
        config = {"case": value["selection"], "session_id": value["identity"]["session_id"],
                  "limits": contract.limits(value["selection"]), "execute": True, "owned_lab": value["identity"]}
        class Subclass(lab.ConfinedStockSshLab): pass
        metadata = (Subclass if fault == "subclass" else lab.ConfinedStockSshLab)(config, closure)
        if fault == "missing_closure": metadata._closure = None
        if fault == "runtime_changed":
            next(row for row in closure["stock_ssh_runtime"]["daemon"]["files"]
                 if row["destination"] == "/tool/sshd")["sha256"] = "f" * 64
    monkeypatch.setattr(lab, "_Supervisor", lambda *a, **k: pytest.fail("owner creation before admission"))
    monkeypatch.setattr(metadata, "_check_available", lambda: pytest.fail("native checks before admission"))
    with pytest.raises(IsolationUnavailable):
        metadata.start(ExecutionControl(deadline=time.monotonic() + 5))
    assert not metadata.started


def test_metadata_backend_cannot_execute_even_with_matching_policy_and_action(monkeypatch):
    value, limits, metadata = objects()
    policy = contract.policy_for_selection(value["selection"])
    owner = backend.AuthorizedStockSshBackend(policy, metadata.session_id, limits, metadata, execute=True)
    monkeypatch.setattr(metadata, "start", lambda *a: pytest.fail("metadata started owner"))
    with pytest.raises(IsolationUnavailable, match="witnessed"):
        owner.run(parse_action(contract.action(value["selection"])), policy,
                  control=ExecutionControl(deadline=time.monotonic() + 5))


def test_custodian_mounts_only_pinned_manifest_with_private_key_mode(monkeypatch):
    monkeypatch.setattr(lab, "_trusted_program", lambda name: "/usr/bin/" + name)
    value, _, _ = objects()
    manifest = value["runtime"]["daemon"]
    descriptors = tuple(range(10, 10 + len(manifest["files"])))
    command = lab.owner_command(("/usr/lib/python3.13", [("/bin/bwrap", "/usr/bin/bwrap"),
        ("/bin/nft", "/usr/bin/nft"), ("/bin/nsenter", "/usr/bin/nsenter"), ("/bin/ip", "/usr/bin/ip")]),
        9, mode="custodian", manifest=manifest, descriptors=descriptors)
    mounted = [(command[index-1], command[index+1], command[index+2])
               for index, token in enumerate(command) if token == "--ro-bind-data"]
    assert len(mounted) == len(manifest["files"])
    for (mode, descriptor, destination), row, fd in zip(mounted, manifest["files"], descriptors, strict=True):
        assert descriptor == str(fd) and destination == row["destination"]
        assert mode == ("0400" if destination == spec.HOST_KEY_PATH else "0555"
                        if destination in manifest["executables"] or destination == manifest["interpreter"] else "0444")
    assert all(path not in command for path in ("/usr/bin/nft", "/usr/bin/nsenter", "/usr/bin/ip", "/etc"))
    assert "CAP_NET_ADMIN" not in command and command[command.index("--uid")+1] == "65534"
    assert "--clearenv" in command and "--unshare-net" in command and "--as-pid-1" in command
    assert "--bind" not in command and "--dev-bind" not in command


@pytest.mark.parametrize("fault", ("manifest", "descriptors", "missing_descriptor", "extra_descriptor", "unknown_mode"))
def test_recorder_cannot_mount_daemon_and_custodian_requires_complete_manifest(monkeypatch, fault):
    monkeypatch.setattr(lab, "_trusted_program", lambda name: "/usr/bin/" + name)
    value, _, _ = objects()
    manifest = value["runtime"]["daemon"]
    options = {"mode": "recorder"}
    if fault == "manifest": options["manifest"] = manifest
    elif fault == "descriptors": options["descriptors"] = (10,)
    elif fault == "unknown_mode": options["mode"] = "server"
    else:
        options.update(mode="custodian", manifest=manifest,
                       descriptors=tuple(range(len(manifest["files"]) + (1 if fault == "extra_descriptor" else -1))))
    with pytest.raises(ValueError): lab.owner_command(("/stdlib", []), 9, **options)
