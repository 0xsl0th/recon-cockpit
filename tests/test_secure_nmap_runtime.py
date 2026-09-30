from copy import deepcopy
import hashlib
import os
import sys
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import nmap_runtime as runtime
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.nmap_contract import action
from recon_cockpit.secure_agent.tool_adapters import compile_nmap_argv


def manifest():
    files = [("/usr/lib/nmap/nmap", "/tool/nmap"),
             ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"),
             ("/usr/share/nmap/nmap-services", "/tool/data/nmap-services"),
             ("/usr/share/nmap/nmap-protocols", "/tool/data/nmap-protocols")]
    return {"version": "1", "profile": runtime.PROFILE, "executable": "/tool/nmap",
            "interpreter": "/lib64/ld-linux-x86-64.so.2", "files": [
                {"source": source, "destination": destination, "size": 4,
                 "sha256": hashlib.sha256(b"data").hexdigest()}
                for source, destination in sorted(files, key=lambda row: row[1])]}


def test_fixed_runtime_argv_matches_the_reviewed_capability_compiler():
    assert runtime.FIXED_ARGV == compile_nmap_argv(parse_action(action("a", 1)))
    assert runtime.validate_manifest(manifest()) == manifest()
    assert runtime.runtime_source_mounts(manifest()) == sorted(
        (row["source"], row["source"]) for row in manifest()["files"])


@pytest.mark.parametrize("change", [
    {"executable": "/usr/bin/nmap"}, {"profile": "owned_lab"}, {"files": []},
    {"extra_args": "--script=all"}, {"interpreter": "/usr/bin/python3"},
])
def test_manifest_cannot_supply_executable_script_or_unknown_fields(change):
    with pytest.raises(ValueError):
        runtime.validate_manifest({**manifest(), **change})


@pytest.mark.parametrize("change", [
    {"source": "/tmp/nmap"}, {"destination": "/usr/bin/python3"}, {"size": True},
    {"size": 0}, {"sha256": "a" * 65}, {"environment": {"LD_PRELOAD": "inject.so"}},
])
def test_manifest_file_metadata_has_no_configurable_runtime_paths(change):
    value = manifest()
    value["files"][-1].update(change)
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


def test_duplicate_and_incomplete_runtime_closures_are_refused():
    value = manifest()
    value["files"].append(deepcopy(value["files"][0]))
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)
    value = manifest()
    value["files"].pop()
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.skipif(sys.platform != "linux", reason="sealed runtime snapshots require Linux")
def test_runtime_is_copied_into_sealed_fds_and_digest_mismatch_never_launches(monkeypatch):
    import fcntl
    control = ExecutionControl(time.monotonic() + 10)
    monkeypatch.setattr(runtime, "_read_regular", lambda _: b"data")
    descriptors = runtime._snapshot(manifest(), control)
    try:
        for fd in descriptors:
            assert os.read(fd, 10) == b"data"
            assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE
            with pytest.raises(PermissionError):
                os.write(fd, b"modified")
    finally:
        for fd in descriptors:
            os.close(fd)
    monkeypatch.setattr(runtime, "_read_regular", lambda _: b"evil")
    with pytest.raises(IsolationUnavailable, match="pinned"):
        runtime._snapshot(manifest(), control)


def test_command_enters_only_owned_network_and_closes_namespace_authority_fds(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    lab = SimpleNamespace(_namespace_fds=(10, 11))
    argv = runtime._command(lab, ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
                            manifest(), [20, 21, 22, 23], "a" * 64, "b" * 64)
    assert argv[:5] == ["/usr/bin/nsenter", "--user=/proc/self/fd/10", "--net=/proc/self/fd/11",
                        "--preserve-credentials", "--"]
    assert "20,21,22,23" in argv and "--unshare-net" not in argv
    assert "CAP_NET_ADMIN" not in argv and "--bind" not in argv
    assert argv.count("--ro-bind-data") == 4
    assert "--unshare-user" in argv and "--unshare-pid" in argv
    assert "--new-session" in argv and "--die-with-parent" in argv


def test_expired_session_cannot_inspect_mount_or_spawn_runtime(monkeypatch):
    from recon_cockpit.secure_agent.execution import ExecutionStopped
    monkeypatch.setattr(runtime, "inspect_nmap_runtime", lambda *_: pytest.fail("expired runtime inspected"))
    with pytest.raises((ExecutionStopped, IsolationUnavailable)):
        runtime.run_nmap_owned(lab=None, launch={}, control=ExecutionControl(time.monotonic() - 1))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux parser wrapper")
def test_evidence_reparse_preserves_original_deadline_and_avoids_tool_or_lab(monkeypatch):
    seen = []
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(runtime, "inspect_nmap_runtime", lambda *_: pytest.fail("no scanner runtime needed"))
    monkeypatch.setattr(runtime, "_runtime_files", lambda *a, **k: (seen.append(k["control"].deadline), "bootstrap"))
    monkeypatch.setattr(runtime, "_parse_isolated", lambda raw, control, bootstrap: [raw, control.deadline])
    deadline = time.monotonic() + 4
    assert runtime.parse_isolated_xml(b"bounded", deadline=deadline) == [b"bounded", deadline]
    assert seen == [deadline]
    from recon_cockpit.secure_agent.execution import ExecutionStopped
    with pytest.raises(ExecutionStopped):
        runtime.parse_isolated_xml(b"bounded", deadline=time.monotonic() - 1)
    assert seen == [deadline]
