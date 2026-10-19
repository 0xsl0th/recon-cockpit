"""Reviewed source bytes are committed and sealed before nested execution."""
from copy import deepcopy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from recon_cockpit.secure_agent import name_tls_python_runtime as source


class Control:
    def check(self):
        pass


def manifest(raw=b"public source\n"):
    return {"profile": source.PROFILE, "files": [{"module": module, "destination": destination,
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for module, destination in sorted(source.DESTINATIONS.items())]}


@pytest.mark.parametrize("change", ("missing", "duplicate", "extra", "order", "path", "hash", "size", "module"))
def test_source_inventory_is_exact_and_cannot_name_arbitrary_files(change):
    value = manifest()
    if change == "missing": value["files"].pop()
    elif change == "duplicate": value["files"][-1] = deepcopy(value["files"][0])
    elif change == "extra": value["files"].append(deepcopy(value["files"][0]))
    elif change == "order": value["files"].reverse()
    elif change == "path": value["files"][0]["destination"] = "/etc/ld.so.preload"
    elif change == "hash": value["files"][0]["sha256"] = "not a digest"
    elif change == "size": value["files"][0]["size"] = True
    else: value["files"][0]["module"] = "../secret"
    with pytest.raises(ValueError):
        source.validate_sources(value)


def test_pin_includes_all_reviewed_source_and_two_inert_package_initializers():
    value = manifest()
    assert len(value["files"]) == 43
    assert len({row["destination"] for row in value["files"]}) == 43
    assert source.source_path("recon_cockpit.__init__") == source.source_path("recon_cockpit.secure_agent.__init__")
    assert "from .models" not in source._read(source.source_path("recon_cockpit.__init__")).decode()
    copied = source.validate_sources(value)
    copied["files"][0]["sha256"] = "b" * 64
    assert value == manifest()
    assert source.source_digest(value) != source.source_digest(copied)


def test_regular_source_reader_refuses_symlinks_and_directories(tmp_path):
    path = tmp_path / "reviewed.py"
    path.write_bytes(b"pass\n")
    assert source._read(path) == b"pass\n"
    link = tmp_path / "alias.py"
    link.symlink_to(path)
    with pytest.raises(OSError):
        source._read(link)
    with pytest.raises(ValueError):
        source._read(tmp_path)


def test_sources_are_verified_before_any_descriptor_is_created(monkeypatch):
    created = []
    monkeypatch.setattr(source, "_read", lambda _: b"changed source\n")
    monkeypatch.setattr(source.os, "memfd_create", lambda *a: created.append(a), raising=False)
    with pytest.raises(ValueError, match="pin_changed"):
        source.snapshot_sources({"python_sources": manifest()}, ("name_tls_public",), Control())
    assert created == []


def test_partial_snapshot_failure_closes_every_created_descriptor(monkeypatch):
    closed, created = [], []
    raw = b"public source\n"
    monkeypatch.setattr(source, "_read", lambda _: raw)
    def create(*_):
        descriptor = 100 + len(created)
        created.append(descriptor)
        return descriptor
    monkeypatch.setattr(source.os, "memfd_create", create, raising=False)
    monkeypatch.setattr(source.os, "MFD_CLOEXEC", 1, raising=False)
    monkeypatch.setattr(source.os, "MFD_ALLOW_SEALING", 2, raising=False)
    monkeypatch.setattr(source.os, "write", lambda fd, data: len(data))
    monkeypatch.setattr(source.os, "lseek", lambda *args: 0)
    monkeypatch.setattr(source.os, "close", closed.append)
    def seal(fd, *_):
        if fd == 101:
            raise OSError("seal failed")
    fake_fcntl = SimpleNamespace(F_ADD_SEALS=1, F_SEAL_WRITE=2, F_SEAL_GROW=4,
        F_SEAL_SHRINK=8, F_SEAL_SEAL=16, fcntl=seal)
    monkeypatch.setitem(sys.modules, "fcntl", fake_fcntl)
    with pytest.raises(OSError, match="seal failed"):
        source.snapshot_sources({"python_sources": manifest(raw)}, ("name_tls_public", "name_tls_wire"), Control())
    assert created == closed == [100, 101]


@pytest.mark.parametrize("modules", ((), [], ("../../key",), ("name_tls_public", "name_tls_public"), "name_tls_public"))
def test_source_selection_cannot_expand_to_unreviewed_paths(modules):
    with pytest.raises(ValueError):
        source.checked_modules(modules)


def test_source_mounts_refuse_unsealed_or_extra_descriptors(monkeypatch):
    valid = {source.DESTINATIONS["name_tls_public"]: 10}
    fake = SimpleNamespace(F_GET_SEALS=1, F_SEAL_WRITE=2, F_SEAL_GROW=4, F_SEAL_SHRINK=8, F_SEAL_SEAL=16,
                           fcntl=lambda *args: 0)
    monkeypatch.setitem(sys.modules, "fcntl", fake)
    with pytest.raises(ValueError, match="unsealed"):
        source.mount_sources([], ("name_tls_public",), valid)
    fake.fcntl = lambda *args: 30
    argv = source.mount_sources([], ("name_tls_public",), valid)
    assert argv == ["--perms", "0444", "--ro-bind-data", "10", source.DESTINATIONS["name_tls_public"]]
    with pytest.raises(ValueError, match="inventory"):
        source.mount_sources([], ("name_tls_public",), {**valid, "/etc/shadow": 11})
