"""Finite metadata preparation does not authorize or execute DNS/TLS work."""

from copy import deepcopy
import hashlib
from itertools import product
import os
from pathlib import Path
import stat
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import name_tls_runtime as runtime
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def control():
    return ExecutionControl(time.monotonic() + 15)


def elf(*, executable=False):
    raw = bytearray(128 if executable else 64)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 3, 62, 1)
    if executable:
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        struct.pack_into("<I", raw, 64, 3)
        struct.pack_into("<Q", raw, 72, 128)
        loader = runtime.INTERPRETER.encode() + b"\0"
        struct.pack_into("<Q", raw, 96, len(loader))
        raw.extend(loader)
    return bytes(raw)


def listing(expected):
    rows = ["linux-vdso.so.1 (0x1000)"]
    for path in sorted(expected):
        rows.append((Path(path).name + " => " if path != runtime.INTERPRETER else "") + path + " (0x2000)")
    return ("\n".join(rows) + "\n").encode()


@pytest.fixture
def fake_runtime(monkeypatch):
    """Real compiled specification and ELF validation; fake installed bytes/ldd."""
    calls, reads = [], []
    aliases = {path: runtime.LIBRARY_ROOT + "ld-linux-x86-64.so.2" if path == runtime.INTERPRETER else path
               for path in runtime.DEPENDENCIES}
    raw = {source: elf() for source in aliases.values()}
    raw.update({source: elf(executable=True) for source in runtime._native_files().values()})
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.Path, "resolve", lambda path, **kwargs: Path(aliases.get(str(path), str(path))))
    def read_file(path, selected_control):
        selected_control.check()
        reads.append(path)
        return raw[path]
    monkeypatch.setattr(runtime, "_read_file", read_file)
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    by_source = {source: runtime._elf_dependencies()[destination]
                 for destination, source in runtime._native_files().items()}
    def probe(argv, timeout, maximum, selected_control):
        assert argv[0] == "/usr/bin/ldd" and len(argv) == 2 and argv[1] in by_source
        calls.append((argv, timeout, maximum, selected_control, tuple(reads)))
        return listing(by_source[argv[1]])
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    return SimpleNamespace(calls=calls, reads=reads, aliases=aliases, raw=raw)


@pytest.mark.parametrize("configuration,case", tuple(product(runtime.spec.CONFIGURATIONS, runtime.spec.CASES)))
def test_each_selection_pins_fixed_four_elf_metadata_without_execution(fake_runtime, configuration, case):
    chosen_control = control()
    manifest = runtime.inspect_runtime(configuration, case, chosen_control)
    assert [call[0] for call in fake_runtime.calls] == [["/usr/bin/ldd", source]
        for _, source in sorted(runtime._native_files().items())]
    assert len(fake_runtime.calls) == 4
    assert all(call[1:4] == (3, 32768, chosen_control) for call in fake_runtime.calls)
    assert all(len(call[4]) == 52 for call in fake_runtime.calls)
    assert len(fake_runtime.reads) == 104  # Every fixed ELF is read again after metadata.
    assert manifest["dependency_kind"] == "fixed_four_elf_linked_dependencies_only"
    assert all(manifest[name] is False for name in runtime._UNVERIFIED)
    assert manifest["selection_sha256"] == runtime.spec.selection_digest(configuration, case)
    assert len(manifest["files"]) == 52 + len(runtime.spec.compiled_files(configuration, case))
    rows = {row["destination"]: row for row in manifest["files"]}
    for source, destination, raw in runtime.spec.compiled_files(configuration, case):
        assert rows[destination] == {"source": source, "destination": destination,
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    detached = runtime.verify_current(manifest, chosen_control)
    assert detached == manifest and detached is not manifest and len(fake_runtime.calls) == 4
    assert len(runtime.manifest_digest(manifest)) == 64
    detached["files"][0]["sha256"] = "f" * 64
    assert detached != manifest


def test_linked_closure_matches_separate_installed_layout_pin():
    # Pin obtained from four bounded ldd observations before implementation.
    dependencies = runtime._elf_dependencies()
    assert hashlib.sha256(runtime.spec.encode(dependencies)).hexdigest() == "bcabe83baa65e3a65a3fe489a364411b6ed9d4d512c9ffa2ee08b6ef0d14cd00"
    assert {k: len(v) for k, v in dependencies.items()} == {
        "/tool/dnsmasq": 17, "/tool/nginx": 8, "/tool/dig": 34, "/tool/openssl": 6}
    assert len(runtime.DEPENDENCIES) == 48 and len(runtime._native_files()) == 4
    assert (runtime.MAX_FILES, runtime.MAX_FILE_BYTES, runtime.MAX_RUNTIME_BYTES, runtime.MAX_MANIFEST_BYTES) == (
        128, 16 * 1024 * 1024, 128 * 1024 * 1024, 64 * 1024)


@pytest.mark.parametrize("configuration,case", (("external", "O1"), ("A", "/etc/shadow"),
    ("A; command", "O1"), (True, "O1"), ("B", None), ("A", "N17")))
def test_invalid_selectors_cannot_read_or_probe(monkeypatch, configuration, case):
    monkeypatch.setattr(runtime, "_read_file", lambda *_: pytest.fail("invalid selector read files"))
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *_: pytest.fail("invalid selector spawned metadata"))
    with pytest.raises(ValueError): runtime.inspect_runtime(configuration, case, control())


@pytest.mark.parametrize("fault", ("none", "fake_clock", "excessive", "expired", "cancelled"))
def test_only_real_bounded_live_control_can_reach_files(monkeypatch, fault):
    selected_control = control()
    if fault == "none": selected_control = None
    elif fault == "fake_clock": selected_control = ExecutionControl(10, clock=lambda: 0)
    elif fault == "excessive": selected_control = ExecutionControl(time.monotonic() + 30)
    elif fault == "expired": selected_control = ExecutionControl(time.monotonic() - 1)
    else:
        event = threading.Event(); event.set()
        selected_control = ExecutionControl(time.monotonic() + 15, event)
    monkeypatch.setattr(runtime, "_read_file", lambda *_: pytest.fail("invalid control read files"))
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *_: pytest.fail("invalid control spawned metadata"))
    with pytest.raises((ValueError, ExecutionStopped)):
        runtime.inspect_runtime("A", "O1", selected_control)


def test_short_control_bounds_all_four_metadata_calls(fake_runtime):
    runtime.inspect_runtime("A", "O1", ExecutionControl(time.monotonic() + 1))
    assert len(fake_runtime.calls) == 4 and all(0 < row[1] <= 1 for row in fake_runtime.calls)


def test_cancellation_during_first_probe_prevents_remaining_metadata(fake_runtime, monkeypatch):
    event, calls = threading.Event(), []
    def probe(argv, *_):
        calls.append(argv)
        event.set()
        return listing(runtime._elf_dependencies()["/tool/dig"])
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        runtime.inspect_runtime("A", "O1", ExecutionControl(time.monotonic() + 15, event))
    assert calls == [["/usr/bin/ldd", "/usr/bin/dig"]]


@pytest.mark.parametrize("fault", ("platform", "inspector", "executable_alias", "missing", "library_alias"))
def test_unreviewed_runtime_cannot_reach_metadata(fake_runtime, monkeypatch, fault):
    if fault == "platform": monkeypatch.setattr(runtime.sys, "platform", "darwin")
    elif fault == "inspector": monkeypatch.setattr(runtime, "_trusted_program", lambda _: "/tmp/ldd")
    elif fault == "executable_alias": fake_runtime.aliases["/usr/bin/dig"] = "/tmp/dig"
    elif fault == "library_alias": fake_runtime.aliases[runtime.LIBRARY_ROOT + "libssl.so.3"] = "/tmp/libssl.so.3"
    else:
        original = runtime.Path.resolve
        def missing(path, **kwargs):
            if str(path) == "/usr/sbin/dnsmasq": raise FileNotFoundError("absent")
            return original(path, **kwargs)
        monkeypatch.setattr(runtime.Path, "resolve", missing)
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *_: pytest.fail("unreviewed files reached metadata"))
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime("A", "O1", control())


@pytest.mark.parametrize("fault", ("source", "traversal", "duplicate", "extra", "missing", "bool_size", "float_size",
    "oversized_file", "zero_size", "bad_hash", "reorder", "compiled_hash", "compiled_source", "selection", "flag_true",
    "flag_int", "executable", "extra_executable", "dependencies", "tuple_dependencies", "aggregate", "unknown_field", "profile"))
def test_manifest_tampering_cannot_expand_files_or_claim_runtime_readiness(fake_runtime, fault):
    value = runtime.inspect_runtime("A", "O1", control())
    row = next(r for r in value["files"] if r["destination"] == "/tool/dig")
    compiled = next(r for r in value["files"] if r["source"].startswith("compiled:"))
    if fault == "source": row["source"] = "/tmp/dig"
    elif fault == "traversal": row["source"] = "/usr/bin/../bin/dig"
    elif fault == "duplicate": value["files"][-1] = deepcopy(value["files"][0])
    elif fault == "extra": value["files"].append(deepcopy(row))
    elif fault == "missing": value["files"].pop()
    elif fault == "bool_size": row["size"] = True
    elif fault == "float_size": row["size"] = 1.0
    elif fault == "oversized_file": row["size"] = runtime.MAX_FILE_BYTES + 1
    elif fault == "zero_size": row["size"] = 0
    elif fault == "bad_hash": row["sha256"] = "G" * 64
    elif fault == "reorder": value["files"].reverse()
    elif fault == "compiled_hash": compiled["sha256"] = "f" * 64
    elif fault == "compiled_source": compiled["source"] = "compiled:outside"
    elif fault == "selection": value["case"] = "N1"
    elif fault == "flag_true": value["native_execution_performed"] = True
    elif fault == "flag_int": value["runtime_closure_verified"] = 0
    elif fault == "executable": value["executables"]["/tool/dig"] = "/tmp/dig"
    elif fault == "extra_executable": value["executables"]["/tool/helper"] = "/usr/bin/helper"
    elif fault == "dependencies": value["elf_dependencies"]["/tool/openssl"] = sorted(runtime.DEPENDENCIES)
    elif fault == "tuple_dependencies": value["elf_dependencies"]["/tool/dig"] = tuple(value["elf_dependencies"]["/tool/dig"])
    elif fault == "aggregate":
        for item in value["files"]:
            if not item["source"].startswith("compiled:"): item["size"] = runtime.MAX_FILE_BYTES
    elif fault == "unknown_field": value["execute"] = False
    else: value["profile"] = False
    with pytest.raises(ValueError): runtime.manifest_digest(value)


def test_structural_validation_is_pure_and_detached(fake_runtime, monkeypatch):
    manifest = runtime.inspect_runtime("A", "O1", control())
    monkeypatch.setattr(runtime, "_read_file", lambda *_: pytest.fail("pure validation read a file"))
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *_: pytest.fail("pure validation started metadata"))
    monkeypatch.setattr(runtime.Path, "resolve", lambda *_a, **_k: pytest.fail("pure validation resolved a path"))
    detached = runtime.validate_manifest(manifest)
    detached["elf_dependencies"]["/tool/dig"].pop()
    assert detached != manifest and len(runtime.manifest_digest(manifest)) == 64


@pytest.mark.parametrize("bound", ("MAX_FILES", "MAX_MANIFEST_BYTES"))
def test_manifest_count_and_encoded_byte_bounds_are_enforced(fake_runtime, monkeypatch, bound):
    manifest = runtime.inspect_runtime("A", "O1", control())
    size = len(manifest["files"]) if bound == "MAX_FILES" else len(runtime.spec.encode(manifest))
    monkeypatch.setattr(runtime, bound, size - 1)
    with pytest.raises(ValueError): runtime.validate_manifest(manifest)


@pytest.mark.parametrize("path", sorted(runtime.BIND_DEPENDENCIES))
def test_bind_debian_sonames_allow_only_the_four_exact_sources(path):
    assert runtime._source_allowed(path, path)
    assert not runtime._source_allowed(path + ".1", path)
    assert not runtime._source_allowed(path.replace("9.20.15-2", "9.20.16-1"), path)
    assert not runtime._source_allowed(path, path.replace("9.20.15-2", "9.20.16-1"))


@pytest.mark.parametrize("suffix,allowed", (("", True), (".0.3", True), (".1.2.3.4", True),
    (".1.2.3.4.5", False), (".12345678901", False), (".evil", False), ("/../libssl.so.3", False)))
def test_numeric_library_aliases_remain_bounded(suffix, allowed):
    path = runtime.LIBRARY_ROOT + "libssl.so.3"
    assert runtime._source_allowed(path + suffix, path) is allowed


@pytest.mark.parametrize("target", tuple(runtime._native_files().values()))
@pytest.mark.parametrize("fault", ("extra", "missing", "duplicate", "wrapper", "nonascii", "not_found",
    "soname", "duplicate_vdso", "no_vdso", "oversized", "host_config", "other_role"))
def test_each_elf_requires_its_exact_linked_dependency_set(fake_runtime, monkeypatch, target, fault):
    def probe(argv, *_):
        destination = next(k for k, v in runtime._native_files().items() if v == argv[1])
        raw = listing(runtime._elf_dependencies()[destination])
        if argv[1] != target: return raw
        if fault == "extra": raw += b"libextra.so.1 => /tmp/libextra.so.1 (0x3000)\n"
        elif fault == "missing": raw = b"\n".join(raw.splitlines()[:-1])
        elif fault == "duplicate": raw += raw.splitlines()[1] + b"\n"
        elif fault == "wrapper": raw += b"not a dynamic executable\n"
        elif fault == "nonascii": raw += b"\xff\n"
        elif fault == "not_found": raw += b"libextra.so.1 => not found\n"
        elif fault == "soname": raw = raw.replace(b"libc.so.6 =>", b"liboutside.so.6 =>")
        elif fault == "duplicate_vdso": raw += b"linux-vdso.so.1 (0x1000)\n"
        elif fault == "no_vdso": raw = b"\n".join(raw.splitlines()[1:])
        elif fault == "oversized": raw = b" " * (runtime.MAX_PROBE_BYTES + 1)
        elif fault == "host_config": raw += b"/etc/ssl/openssl.cnf (0x1000)\n"
        else:
            other = "/tool/nginx" if destination != "/tool/nginx" else "/tool/dig"
            raw = listing(runtime._elf_dependencies()[other])
        return raw
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime("A", "O1", control())


@pytest.mark.parametrize("target", tuple(runtime._native_files().values()))
@pytest.mark.parametrize("fault", ("script", "architecture", "loader", "program_headers"))
def test_four_executable_elf_images_are_checked_before_any_metadata(fake_runtime, monkeypatch, target, fault):
    raw = bytearray(fake_runtime.raw[target])
    if fault == "script": raw = bytearray(b"#!/bin/sh\ncommand\n")
    elif fault == "architecture": struct.pack_into("<H", raw, 18, 183)
    elif fault == "loader": raw[-2] = ord("9")
    else: struct.pack_into("<Q", raw, 32, 999999)
    fake_runtime.raw[target] = bytes(raw)
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *_: pytest.fail("invalid ELF reached metadata"))
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime("A", "O1", control())


def test_dependencies_must_be_shared_elf_objects_before_any_metadata(fake_runtime, monkeypatch):
    path = runtime.LIBRARY_ROOT + "libssl.so.3"
    raw = bytearray(fake_runtime.raw[path]); struct.pack_into("<H", raw, 16, 2)
    fake_runtime.raw[path] = bytes(raw)
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *_: pytest.fail("nonshared dependency reached metadata"))
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime("A", "O1", control())


@pytest.mark.parametrize("target", (*runtime._native_files().values(), runtime.LIBRARY_ROOT + "libcrypto.so.3"))
def test_changed_current_bytes_fail_without_metadata(fake_runtime, monkeypatch, target):
    manifest = runtime.inspect_runtime("A", "O1", control())
    fake_runtime.raw[target] += b"changed"
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *_: pytest.fail("reverification invoked metadata"))
    with pytest.raises(IsolationUnavailable, match="pinned manifest"): runtime.verify_current(manifest, control())


@pytest.mark.parametrize("fault", ("daemon", "client", "library", "alias"))
def test_metadata_time_mutation_cannot_yield_a_mixed_manifest(fake_runtime, monkeypatch, fault):
    original = runtime._runtime_probe
    def probe(*args):
        raw = original(*args)
        if fault == "alias": fake_runtime.aliases[runtime.LIBRARY_ROOT + "libssl.so.3"] = "/tmp/libssl.so.3"
        else:
            path = {"daemon": "/usr/sbin/dnsmasq", "client": "/usr/bin/openssl",
                    "library": runtime.LIBRARY_ROOT + "libssl.so.3"}[fault]
            fake_runtime.raw[path] += b"changed"
        return raw
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    with pytest.raises(IsolationUnavailable): runtime.inspect_runtime("A", "O1", control())


def stamp(*, uid=0, mode=stat.S_IFREG | 0o644, inode=7):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=0,
                           st_size=64, st_mtime_ns=100, st_ctime_ns=100)


@pytest.mark.parametrize("fault", ("owner", "writable", "fifo", "symlink"))
def test_reader_rejects_unsafe_ownership_or_file_kind_before_read(monkeypatch, fault):
    info = stamp(uid=1000) if fault == "owner" else stamp(mode={
        "writable": stat.S_IFREG | 0o666, "fifo": stat.S_IFIFO | 0o600,
        "symlink": stat.S_IFLNK | 0o777}[fault])
    with monkeypatch.context() as patch:
        patch.setattr(runtime.os, "stat", lambda *_a, **_k: info)
        patch.setattr(runtime.shared, "_read_file", lambda *_: pytest.fail("unsafe file reached reader"))
        with pytest.raises(IsolationUnavailable): runtime._read_file("/usr/bin/dig", control())


@pytest.mark.parametrize("fault", ("owner", "inode", "permissions"))
def test_reader_binds_root_ownership_and_identity_across_shared_read(monkeypatch, fault):
    infos = [stamp(), {"owner": stamp(uid=1000), "inode": stamp(inode=8),
                       "permissions": stamp(mode=stat.S_IFREG | 0o600)}[fault]]
    with monkeypatch.context() as patch:
        patch.setattr(runtime.os, "stat", lambda *_a, **_k: infos.pop(0))
        patch.setattr(runtime.shared, "_read_file", lambda *_: elf())
        with pytest.raises(IsolationUnavailable, match="ownership or file changed"):
            runtime._read_file("/usr/bin/dig", control())


def test_root_owned_stable_reader_preserves_shared_file_checks(monkeypatch):
    calls = []
    def read(path, selected_control):
        calls.append((path, selected_control))
        return elf()
    selected_control = control()
    with monkeypatch.context() as patch:
        patch.setattr(runtime.os, "stat", lambda *_a, **_k: stamp())
        patch.setattr(runtime.shared, "_read_file", read)
        assert runtime._read_file("/usr/bin/dig", selected_control) == elf()
    assert calls == [("/usr/bin/dig", selected_control)]
