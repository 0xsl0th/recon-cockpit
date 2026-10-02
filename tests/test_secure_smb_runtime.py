"""SMB closure expansion cannot broaden other tools or the native boundary."""

from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import launcher_protocol as protocol
from recon_cockpit.secure_agent import launcher_worker
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import tool_runtime_common as common
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def expanded(tool_id=runtime.SMB):
    entries = [(runtime.EXECUTABLES[tool_id], runtime.FIXED_ARGV[tool_id][0], b"elf"),
               ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", b"loader")]
    entries.extend(runtime.compiled_files(tool_id))
    return {"version": "1", "profile": runtime.PROFILE, "tool_id": tool_id,
        "executable": runtime.FIXED_ARGV[tool_id][0], "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "files": [{"source": src, "destination": dst, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for src, dst, data in sorted(entries, key=lambda row: row[1])]}


def library(index, size=1):
    path = f"/usr/lib/x86_64-linux-gnu/lib{index}.so"
    return {"source": path, "destination": path, "size": size, "sha256": "a" * 64}


def manifest(value=None):
    return runtime.compact_manifest(expanded() if value is None else value)


def test_smb_compact_closure_roundtrips_and_binds_the_config():
    source = expanded()
    source["files"].append(library(1))
    source["files"].sort(key=lambda row: row["destination"])
    value = manifest(source)
    assert value["profile"] == runtime.SMB_PROFILE
    assert runtime.validate_manifest(value) == value
    assert runtime.runtime_files(value) == source["files"]
    assert all(not path.startswith("compiled:") for path, _ in runtime.runtime_source_mounts(value))
    for index, replacement in ((0, "/tool/data/smb.conf"), (1, None), (2, 1), (3, "b" * 64)):
        changed = deepcopy(value)
        row = next(row for row in changed["files"] if row[0] == "compiled:smb-config")
        row[index] = replacement
        with pytest.raises(ValueError):
            runtime.validate_manifest(changed)


@pytest.mark.parametrize("fault", ["profile", "extra", "root_traversal", "root_alias", "root_duplicate",
    "root_unsorted", "root_unused", "root_missing", "expanded_row", "row_extra", "row_unsorted", "row_duplicate",
    "absolute_library", "root_index", "leading_zero", "path_traversal", "path_separator", "source_other_tool",
    "explicit_same_destination", "hash", "bool_size", "missing_loader", "missing_config", "interpreter"])
def test_smb_manifest_rejects_noncanonical_or_expanded_authority(fault):
    source = expanded()
    source["files"].append(library(1))
    source["files"].sort(key=lambda row: row["destination"])
    value = manifest(source)
    lib = next(row for row in value["files"] if row[1] is None)
    if fault == "profile": value["profile"] = runtime.PROFILE
    elif fault == "extra": value["argv"] = ["-c", "recurse"]
    elif fault == "root_traversal": value["roots"][0] = "/usr/lib/../lib"
    elif fault == "root_alias": value["roots"][0] = "/usr/lib/"
    elif fault == "root_duplicate": value["roots"].append(value["roots"][0])
    elif fault == "root_unsorted": value["roots"].reverse()
    elif fault == "root_unused": value["roots"] = sorted(value["roots"] + ["/usr/lib/aarch64-linux-gnu"])
    elif fault == "root_missing": value.pop("roots")
    elif fault == "expanded_row": value["files"] = source["files"]
    elif fault == "row_extra": lib.append("extra")
    elif fault == "row_unsorted": value["files"].reverse()
    elif fault == "row_duplicate": value["files"].append(deepcopy(lib))
    elif fault == "absolute_library": lib[0] = "/usr/lib/x86_64-linux-gnu/lib1.so"
    elif fault == "root_index": lib[0] = "99:lib1.so"
    elif fault == "leading_zero": lib[0] = "00:lib1.so"
    elif fault == "path_traversal": lib[0] = "0:..lib.so"
    elif fault == "path_separator": lib[0] = "0:x/lib1.so"
    elif fault == "source_other_tool": next(row for row in value["files"] if row[1] == "/tool/smbclient")[0] = "/usr/bin/ldapsearch"
    elif fault == "explicit_same_destination": lib[1] = lib[0]
    elif fault == "hash": lib[3] = "A" * 64
    elif fault == "bool_size": lib[2] = True
    elif fault == "missing_loader": value["files"].pop(0)
    elif fault == "missing_config": value["files"] = [row for row in value["files"] if row[0] != "compiled:smb-config"]
    elif fault == "interpreter": value["interpreter"] = "/usr/bin/python3"
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


def test_smb_closure_limits_apply_independently():
    source = expanded()
    source["files"] += [library(index) for index in range(runtime.SMB_MAX_FILES - 3)]
    source["files"].sort(key=lambda row: row["destination"])
    value = manifest(source)
    assert len(value["files"]) == 160
    assert runtime.validate_manifest(value) == value
    source["files"].append(library(999))
    source["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError): runtime.validate_manifest(manifest(source))
    source = expanded()
    source["files"] += [library(index, runtime.SMB_MAX_FILE_BYTES) for index in range(3)]
    source["files"].sort(key=lambda row: row["destination"])
    assert runtime.validate_manifest(manifest(source))
    source["files"].append(library(99, 8 * 1024 * 1024))
    source["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError): runtime.validate_manifest(manifest(source))
    source = expanded()
    source["files"].append(library(99, runtime.SMB_MAX_FILE_BYTES + 1))
    source["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError): runtime.validate_manifest(manifest(source))
    source = expanded()
    source["files"] += [library(str(index) + "x" * 1100) for index in range(18)]
    source["files"].sort(key=lambda row: row["destination"])
    value = manifest(source)
    assert len(runtime.encode(value)) > runtime.SMB_MAX_MANIFEST_BYTES
    with pytest.raises(ValueError): runtime.validate_manifest(value)


@pytest.mark.parametrize("tool_id", [runtime.DIG, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.RPCINFO, runtime.SHOWMOUNT])
def test_existing_manifests_keep_their_schema_and_lower_limits(tool_id):
    value = expanded(tool_id)
    raw = runtime.encode(value)
    assert runtime.compact_manifest(value) is value
    assert runtime.encode(runtime.validate_manifest(value)) == raw
    assert runtime.MAX_FILE_BYTES == 16 * 1024 * 1024
    assert runtime.MAX_RUNTIME_BYTES == 64 * 1024 * 1024
    assert runtime.MAX_MANIFEST_BYTES == 12288
    for fault in ("smb_profile", "smb_roots", "large_file", "many_files", "large_total"):
        changed = deepcopy(value)
        if fault == "smb_profile": changed["profile"] = runtime.SMB_PROFILE
        elif fault == "smb_roots": changed["roots"] = ["/lib64"]
        elif fault == "large_file": changed["files"][0]["size"] = runtime.MAX_FILE_BYTES + 1
        elif fault == "many_files": changed["files"] += [library(index) for index in range(49)]
        elif fault == "large_total": changed["files"] += [library(index, runtime.MAX_FILE_BYTES) for index in range(4)]
        changed["files"].sort(key=lambda row: row["destination"])
        with pytest.raises(ValueError): runtime.validate_manifest(changed)


def test_smb_fixed_command_is_anonymous_and_cannot_select_a_share_or_shell():
    assert runtime.FIXED_ARGV[runtime.SMB] == ("/tool/smbclient", "-L", "127.0.0.1", "-I", "127.0.0.1",
        "-p", "8080", "-U", "%", "-N", "-g", "-t", "2", "--use-kerberos=off", "-s", "/tool/data/smb.conf")
    config = runtime.SMB_CONFIG.decode("ascii")
    for line in ("client min protocol = SMB2_02", "client max protocol = SMB2_02", "client use kerberos = off",
                 "disable netbios = yes", "name resolve order = host", "interfaces = 127.0.0.1/8"):
        assert line + "\n" in config
    assert config.count("[") == 1
    assert "network_tools_smb_fixture" not in runtime.MODULES
    assert not {"HOME", "USER", "PASSWD", "PASSWD_FD", "PASSWD_FILE", "KRB5CCNAME"} & set(runtime.execution_environment(runtime.SMB))


@pytest.mark.parametrize("tool_id", [runtime.DIG, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.SMB, runtime.RPCINFO, runtime.SHOWMOUNT])
def test_read_and_snapshot_caps_expand_only_for_smb(monkeypatch, tool_id):
    calls = []
    monkeypatch.setattr(runtime, "_read_regular", lambda path, **kw: calls.append((path, kw)))
    runtime.read_runtime_file("/selected", tool_id)
    assert calls == [("/selected", {"maximum": 40 * 1024 * 1024} if tool_id == runtime.SMB else {})]
    captured = []
    monkeypatch.setattr(runtime, "sealed_snapshots", lambda *args, **kw: captured.append((args, kw)))
    selected = runtime.compact_manifest(expanded(tool_id))
    runtime._snapshot(selected, object())
    args, kwargs = captured[0]
    assert args[0]["files"] == runtime.runtime_files(selected)
    expected = ({"maximum_file_bytes": 40 * 1024 * 1024} if tool_id == runtime.SMB else
                {"additional_compiled": (("compiled:rpc-services", runtime.RPC_SERVICES),)}
                if tool_id in (runtime.RPCINFO, runtime.SHOWMOUNT) else {})
    assert kwargs == expected


def test_shared_reader_still_refuses_oversized_files_without_explicit_smb_cap(tmp_path):
    path = tmp_path / "runtime.so"
    with path.open("wb") as stream:
        stream.truncate(common.MAX_FILE_BYTES + 1)
    with pytest.raises(IsolationUnavailable): common._read_regular(str(path))
    assert len(common._read_regular(str(path), maximum=runtime.SMB_MAX_FILE_BYTES)) == common.MAX_FILE_BYTES + 1


@pytest.mark.parametrize("tool_id", [runtime.DIG, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.SMB, runtime.RPCINFO, runtime.SHOWMOUNT])
def test_smb_large_staging_does_not_expand_native_tool_limits(monkeypatch, tool_id):
    applied = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: applied.__setitem__(kind, value))
    worker._limits(tool_id)
    assert applied == {worker.resource.RLIMIT_AS: (256 * 1024 * 1024,) * 2,
        worker.resource.RLIMIT_CPU: (5, 5), worker.resource.RLIMIT_NOFILE: (64, 64),
        worker.resource.RLIMIT_NPROC: (16, 16) if tool_id == runtime.DIG else (1, 1),
        worker.resource.RLIMIT_CORE: (0, 0), worker.resource.RLIMIT_FSIZE: (0, 0)}


@pytest.mark.parametrize("selected", [None, "nmap_runtime", "web_tools_runtime", "network_tools_runtime", "smb_runtime"])
def test_outer_smb_staging_caps_leave_existing_profiles_unchanged(monkeypatch, selected):
    applied = {}
    monkeypatch.setattr(launcher_worker, "ENTRY_DESCRIPTORS_VERIFIED", True)
    monkeypatch.setattr(launcher_worker.sys, "platform", "linux")
    monkeypatch.setattr(launcher_worker.os, "getuid", lambda: 1000)
    monkeypatch.setattr(launcher_worker.os, "getgid", lambda: 1000)
    monkeypatch.setattr(launcher_worker.os, "readlink", lambda _: "private")
    monkeypatch.setattr(launcher_worker, "Path", lambda _: SimpleNamespace(read_text=lambda: "1000 1000 1\n"))
    monkeypatch.setattr(launcher_worker.socket, "if_nameindex", lambda: [(1, "lo")])
    for method in ("_zero_capabilities", "_no_new_privileges", "_root_read_only"):
        monkeypatch.setattr(launcher_worker.bootstrap, method, lambda: None)
    monkeypatch.setattr(launcher_worker.resource, "setrlimit", lambda kind, value: applied.__setitem__(kind, value))
    assert launcher_worker.boundary({"user": "host"}, **({selected: True} if selected else {})) == dict.fromkeys(protocol.CHECKS, True)
    cap = 40 if selected == "smb_runtime" else 16 if selected else 1
    assert applied[launcher_worker.resource.RLIMIT_FSIZE] == (cap * 1024 * 1024,) * 2
    assert applied[launcher_worker.resource.RLIMIT_NOFILE] == ((256,) * 2 if selected == "smb_runtime" else (128,) * 2)
    assert applied[launcher_worker.resource.RLIMIT_AS] == ((2048 if selected == "web_tools_runtime" else 256) * 1024 * 1024,) * 2


@pytest.mark.parametrize("profile,tool_id", [("fixture", None), ("owned_lab", None), ("owned_nmap_lab", None),
    ("owned_web_lab", None), ("owned_http_headers_lab", None), ("owned_web_tools_lab", None),
    *[("owned_network_tools_lab", tool) for tool in (runtime.DIG, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.SMB, runtime.RPCINFO, runtime.SHOWMOUNT)]])
def test_larger_bootstrap_tag_is_bound_to_the_smb_closure(profile, tool_id):
    config = {"profile": profile}
    closure = {"network_tools_runtime": runtime.compact_manifest(expanded(tool_id))} if tool_id else {}
    expected = "smb-tools-launch-preconditions" if tool_id == runtime.SMB else protocol.RUNTIME_TAGS.get(profile)
    assert protocol.runtime_tag(config, closure) == expected
    protocol.validate_runtime_tag(expected, config, closure)
    for tag in {*protocol.RUNTIME_TAGS.values(), "smb-tools-launch-preconditions", None, "launch-preconditions"}:
        if tag == expected or (expected is None and tag == "launch-preconditions"):
            continue
        with pytest.raises(ValueError): protocol.validate_runtime_tag(tag, config, closure)
