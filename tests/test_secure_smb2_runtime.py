"""The repository SMB2 adapter retains exact runtime and transport authority."""

from copy import deepcopy
import hashlib
from pathlib import Path
import re
import resource
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_smb2_runtime as smb2
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def manifest():
    """Synthetic closure for portable checks, never native execution evidence."""
    compiled = {source: raw for source, _, raw in smb2.COMPILED}
    return {"version": "1", "profile": smb2.PROFILE, "tool_id": smb2.TOOL_ID,
        "executable": smb2.DESTINATION, "interpreter": smb2.INTERPRETER,
        "files": sorted([{"source": source, "destination": destination,
            "size": len(compiled.get(source, b"data")),
            "sha256": hashlib.sha256(compiled.get(source, b"data")).hexdigest()}
            for source, destination in smb2.fixed_entries()], key=lambda row: row["destination"])}


def test_all_twenty_one_accepted_runtime_contracts_remain_byte_identical():
    values = {tool: [executable, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, executable in runtime.EXECUTABLES.items() if tool != "ssh_transport_policy_v1" and tool not in (runtime.SMB2, runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.HTTP_OPTIONS, runtime.SNMP_NEXT, runtime.SSH_ALGORITHMS, runtime.TLS_CERTIFICATE, runtime.NUCLEI, runtime.NUCLEI_GIT, runtime.DIG_MX)}
    assert len(values) == 21
    # Captured from accepted main 846e459 before any C6 runtime edits.
    assert hashlib.sha256(runtime.encode(values)).hexdigest() == (
        "0aafd009ea69ef4c877d82811405b18a1346b1f757d39b03d26bcf7c813240ee")


def test_compiled_client_pins_the_public_negotiation_request():
    encoded = smb2.CLIENT.split(b"request = [\n", 1)[1].split(b"].join", 1)[0]
    request = bytes.fromhex(b"".join(re.findall(rb"'([0-9a-f]+)'", encoded)).decode("ascii"))
    assert request == fixture.SMB2_REQUEST
    assert len(request) == fixture.SMB2_MAX_REQUEST_BYTES == 108


def test_manifest_contains_exact_finite_ruby_socket_client_closure():
    value = manifest()
    assert runtime.validate_manifest(value, tool_id=runtime.SMB2) == value
    assert runtime.runtime_files(value) == value["files"]
    assert runtime.compact_manifest(value) is value
    assert len(value["files"]) == len(set(smb2.fixed_entries())) == 13
    assert len(runtime.encode(value)) < smb2.MAX_MANIFEST_BYTES
    assert all(not source.startswith("compiled:") for source, _ in runtime.runtime_source_mounts(value))
    assert runtime.compiled_files(runtime.SMB2) == smb2.COMPILED


@pytest.mark.parametrize("field,value", [("version", "2"), ("profile", runtime.PROFILE),
    ("tool_id", runtime.WHATWEB), ("tool_id", runtime.RDP), ("executable", "/usr/bin/ruby3.3"),
    ("interpreter", "/usr/bin/python3"), ("interpreter", "/usr/lib/ld-linux-x86-64.so.2")])
def test_manifest_identity_cannot_borrow_other_runtime_or_interpreter(field, value):
    candidate = manifest()
    candidate[field] = value
    with pytest.raises(ValueError):
        runtime.validate_manifest(candidate, tool_id=runtime.SMB2)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "reorder", "extra_field", "row_field",
    "list_row", "source_type", "destination_type", "size_bool", "size_zero", "size_large", "hash"])
def test_manifest_refuses_malformed_or_incomplete_runtime(fault):
    value = manifest()
    if fault == "missing": value["files"].pop()
    elif fault == "duplicate": value["files"][-1] = deepcopy(value["files"][0])
    elif fault == "reorder": value["files"].reverse()
    elif fault == "extra_field": value["roots"] = []
    elif fault == "row_field": value["files"][0]["unexpected"] = True
    elif fault == "list_row": value["files"][0] = [0, 4, "a" * 64]
    elif fault == "source_type": value["files"][0]["source"] = True
    elif fault == "destination_type": value["files"][0]["destination"] = []
    elif fault == "size_bool": value["files"][0]["size"] = True
    elif fault == "size_zero": value["files"][0]["size"] = 0
    elif fault == "size_large": value["files"][0]["size"] = smb2.MAX_FILE_BYTES + 1
    else: value["files"][0]["sha256"] = "g" * 64
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("path", ["/usr/bin/python3", "/usr/bin/sh", "/tmp/client.rb",
    "/usr/lib/ruby/3.3.0/openssl.rb", "/usr/lib/ruby/3.3.0/timeout.rb",
    "/usr/lib/ruby/vendor_ruby/rubygems.rb", "/usr/lib/x86_64-linux-gnu/extra.so",
    "/usr/lib/ruby/3.3.0/../private.rb", "/root/.gem/credentials", "/etc/resolv.conf"])
def test_exact_closure_refuses_extra_code_configuration_and_secrets(path):
    candidate = manifest()
    candidate["files"][-1].update(source=path, destination=path)
    candidate["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError):
        runtime.validate_manifest(candidate)


@pytest.mark.parametrize("fault", ["hash", "size", "source"])
def test_fresh_manifest_digest_cannot_change_compiled_client(fault):
    candidate = manifest()
    row = next(row for row in candidate["files"] if row["source"].startswith("compiled:"))
    if fault == "hash": row["sha256"] = "a" * 64
    elif fault == "size": row["size"] += 1
    else: row["source"] = "/tmp/substitute.rb"
    with pytest.raises(ValueError):
        runtime.manifest_digest(candidate)


def test_fixed_argv_environment_and_landlock_expose_only_reviewed_runtime(monkeypatch):
    for name in ("HOME", "RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH", "LD_PRELOAD", "http_proxy"):
        monkeypatch.setenv(name, "/private/injected")
    assert runtime.EXECUTABLES[runtime.SMB2] == "/usr/bin/ruby3.3"
    assert runtime.FIXED_ARGV[runtime.SMB2] == ("/tool/ruby", "--disable=all", smb2.SCRIPT_PATH)
    assert runtime.execution_environment(runtime.SMB2) == {"LC_ALL": "C", "MALLOC_ARENA_MAX": "1"}
    permissions = worker._landlock_permissions(manifest())
    assert {path for path, rights in permissions.items() if rights & 1} == {
        smb2.DESTINATION, smb2.INTERPRETER}
    assert not any(rights & 8 for rights in permissions.values())
    assert all(permissions[row["destination"]] & 4 for row in manifest()["files"])
    assert not {"/usr/bin/python3", "/etc/resolv.conf", "/home", "/root"} & permissions.keys()


def test_ruby_uses_reviewed_thread_filter_with_inherited_resource_caps(monkeypatch):
    seen, limits = [], {}
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kwargs: seen.append(kwargs))
    worker.syscall_filter(runtime.SMB2)
    assert seen == [{"allow_threads": True}]
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda key, value: limits.update({key: value}))
    worker._limits(runtime.SMB2)
    assert limits[resource.RLIMIT_NPROC] == (16, 16)
    assert limits[resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    assert limits[resource.RLIMIT_FSIZE] == (0, 0)
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (2, 2))
    worker._limits(runtime.SMB2)
    assert set(limits.values()) == {(2, 2), (0, 0)}


def test_sealed_snapshot_contains_only_selected_files_and_fixed_client(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "sealed_snapshots", lambda *args, **kwargs: calls.append((args, kwargs)) or [])
    value, control = manifest(), object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = smb2.COMPILED[0]
    assert calls == [((value, source, raw, control), {})]


def test_inspection_only_reads_exact_files_and_uses_ldd(monkeypatch):
    seen = []
    aliases = {destination: source for source, destination in smb2.NATIVE_FILES}
    monkeypatch.setattr(smb2.Path, "resolve", lambda path, **kwargs: Path(aliases.get(str(path), str(path))))
    monkeypatch.setattr(smb2, "_read_regular", lambda _: b"\x7fELFdata")
    monkeypatch.setattr(smb2, "_trusted_program", lambda name: "/usr/bin/" + name)
    listing = "\n".join(destination + " (0x100)" for _, destination in smb2.NATIVE_FILES).encode()
    monkeypatch.setattr(smb2, "_runtime_probe", lambda argv, *args: seen.append(argv) or listing)
    value = runtime.inspect_tool_runtime(runtime.SMB2, SimpleNamespace(check=lambda: None))
    assert runtime.validate_manifest(value, tool_id=runtime.SMB2) == value
    assert seen == [["/usr/bin/ldd", smb2.EXECUTABLE,
        *(path for path in smb2.RUBY_FILES if path.endswith(".so"))]]
    monkeypatch.setattr(smb2, "_runtime_probe", lambda *args: listing + b"\n/usr/lib/x86_64-linux-gnu/extra.so (0x101)")
    with pytest.raises(IsolationUnavailable, match="finite closure"):
        runtime.inspect_tool_runtime(runtime.SMB2, SimpleNamespace(check=lambda: None))


def test_inspection_refuses_a_relocated_file_or_non_elf_extension(monkeypatch):
    monkeypatch.setattr(smb2.Path, "resolve", lambda path, **kwargs: Path("/tmp/substitute"))
    with pytest.raises(IsolationUnavailable, match="distribution file layout"):
        runtime.inspect_tool_runtime(runtime.SMB2, SimpleNamespace(check=lambda: None))
    monkeypatch.setattr(smb2.Path, "resolve", lambda path, **kwargs: path)
    monkeypatch.setattr(smb2, "_read_regular", lambda _: b"not an ELF")
    with pytest.raises(IsolationUnavailable, match="ELF"):
        runtime.inspect_tool_runtime(runtime.SMB2, SimpleNamespace(check=lambda: None))


def test_command_seals_runtime_without_mounting_smb2_owner_or_parser(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        manifest(), list(range(20, 33)), "a" * 64, "b" * 64)
    assert argv.count("--ro-bind-data") == 13
    assert "CAP_NET_ADMIN" not in argv and "--unshare-net" not in argv
    assert not any("network_tools_smb2_fixture" in item or "network_tools_smb2_parser" in item for item in argv)
