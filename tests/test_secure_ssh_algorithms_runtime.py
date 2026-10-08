"""The repository SSH_ALGORITHMS adapter retains exact runtime and transport authority."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import re
import resource
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_ssh_algorithms_runtime as ssh_algorithms
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import tool_adapters as adapters
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import SSHAlgorithmsParameters, ValidationError, parse_action, parse_policy


def manifest():
    """Synthetic closure for portable checks, never native execution evidence."""
    compiled = {source: raw for source, _, raw in ssh_algorithms.COMPILED}
    return {"version": "1", "profile": ssh_algorithms.PROFILE, "tool_id": ssh_algorithms.TOOL_ID,
        "executable": ssh_algorithms.DESTINATION, "interpreter": ssh_algorithms.INTERPRETER,
        "files": sorted([{"source": source, "destination": destination,
            "size": len(compiled.get(source, b"data")),
            "sha256": hashlib.sha256(compiled.get(source, b"data")).hexdigest()}
            for source, destination in ssh_algorithms.fixed_entries()], key=lambda row: row["destination"])}


def test_all_twenty_nine_accepted_runtime_contracts_remain_byte_identical():
    values = {tool: [executable, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, executable in runtime.EXECUTABLES.items() if tool not in (runtime.SSH_ALGORITHMS, runtime.TLS_CERTIFICATE)}
    assert len(values) == 29
    # Captured from accepted main 7cc6645 before any C14 runtime edits.
    assert hashlib.sha256(runtime.encode(values)).hexdigest() == (
        "767ee187cfffed10fae3f5aecd2f9284b3cc8d896939cddfcabf2095c29c8231")


def test_compiled_client_pins_the_public_negotiation_request():
    encoded = ssh_algorithms.CLIENT.split(b"request = [\n", 1)[1].split(b"].join", 1)[0]
    request = bytes.fromhex(b"".join(re.findall(rb"'([0-9a-f]+)'", encoded)).decode("ascii"))
    assert request == fixture.SSH_ALGORITHMS_REQUEST
    assert len(request) == fixture.SSH_ALGORITHMS_MAX_REQUEST_BYTES == 184


def test_all_38_accepted_adapters_remain_byte_identical():
    values = {tool: adapter.to_dict() for tool, adapter in adapters.ADAPTERS.items()
              if tool not in (adapters.SSH_ALGORITHMS_TOOL_ID, adapters.TLS_CERTIFICATE_TOOL_ID)}
    assert len(values) == 38
    assert hashlib.sha256(runtime.encode(values)).hexdigest() == (
        "01fdd622d95c321c96dd941b6edc0f4e8086c8012453d12d03e1fbb03148e0dc")


def test_client_has_one_fresh_cookie_and_permanent_write_shutdown_before_reads():
    source = ssh_algorithms.CLIENT
    assert source.count(b"Random.urandom(16)") == 1
    assert fixture.SSH_ALGORITHMS_COOKIE_OFFSET == 30
    assert source.count(b"request[30, 16] = cookie") == 1
    assert source.count(b"Socket.new(") == source.count(b"write_nonblock(") == 1
    before, after = source.split(b"connection.shutdown(Socket::SHUT_WR)", 1)
    assert before.index(b"Random.urandom(16)") < before.index(b"write_nonblock(")
    assert b"read_to(connection, response," not in before.split(b"address =", 1)[1]
    assert b"write_nonblock" not in after and b"connect_nonblock" not in after
    assert b"unless response.bytesize < 255" in after
    assert b"response.bytesize + 1, deadline" in after
    assert b"response.start_with?('SSH-2.0-'.b)" in after
    assert b"size >= 12 && size <= 4096" in after
    assert b"read_to(connection, response, identification_size + 4 + size, deadline)" in after
    assert source.count(b"STDOUT.write(") == source.count(b"STDERR.write(") == 1
    assert b'STDERR.write("ssh_transport_algorithms_failed\\n")' in source
    assert fixture.SSH_ALGORITHMS_MAX_CAPTURE_BYTES == 255 + 4 + 4096 == 4355


def test_ssh_algorithms_is_typed_immutable_and_distinct_from_host_key_authority():
    from test_secure_network_tools_runtime import policy
    action = parse_action(contract.action("ssh-algos-ok"))
    assert type(action.parameters) is SSHAlgorithmsParameters
    assert action.parameters.to_dict() == dict(adapters.SSH_ALGORITHMS_PARAMETERS)
    with pytest.raises(FrozenInstanceError):
        action.parameters.port = 22
    descriptor = adapters.get_adapter(runtime.SSH_ALGORITHMS).to_dict()
    assert descriptor["parameters"]["additionalProperties"] is False
    assert descriptor["parameters"]["required"] == ["port", "timeout_seconds", "max_output_bytes"]
    assert descriptor["parser_version"] == "ssh-kexinit-wire-v1"
    configured = policy().to_dict()
    configured.update(allowed_tools=[runtime.SSH_ALGORITHMS], allowed_methods=[])
    assert parse_policy(configured).evaluate(action).decision == "approval_required"
    assert parse_policy(configured).evaluate(parse_action(contract.action("ssh-ok"))).reasons == ("tool_not_allowed",)
    configured["allowed_tools"] = [runtime.SSH]
    assert parse_policy(configured).evaluate(action).reasons == ("tool_not_allowed",)


@pytest.mark.parametrize("field", ["client_identification", "cookie", "kex_algorithms", "host_key_algorithms",
    "cipher", "mac", "compression", "username", "password", "private_key", "agent_socket",
    "known_hosts", "host_trust", "authentication", "key_exchange", "service", "command", "shell",
    "subsystem", "channel", "sftp", "followup", "retry", "proxy", "argv", "environment", "config"])
def test_caller_cannot_supply_ssh_protocol_inputs_or_secrets(field):
    action = contract.action("ssh-algos-ok")
    action["parameters"][field] = "untrusted"
    with pytest.raises(ValidationError, match="unknown_parameters_fields"):
        parse_action(action)


@pytest.mark.parametrize("other", ["ssh-ok", "smb2-21-optional", "rdp-tls"])
@pytest.mark.parametrize("reverse", [False, True])
def test_runtime_and_action_cannot_borrow_legacy_authority(other, reverse):
    from test_secure_network_tools_runtime import envelope, recommit, verify
    cases = (other, "ssh-algos-ok") if reverse else ("ssh-algos-ok", other)
    value, replacement = (envelope(case) for case in cases)
    value["runtime"] = deepcopy(replacement["runtime"])
    with pytest.raises(ValueError):
        verify(value)
    value["launch"]["action"] = replacement["launch"]["action"]
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize("fault", ["mode", "inner_mode", "identity", "manifest", "namespace",
    "deadline", "sequence", "reservation", "policy", "action", "limit"])
def test_fresh_commitments_cannot_expand_ssh_algorithms_authority(fault):
    from test_secure_network_tools_runtime import test_fresh_commitments_do_not_bypass_fixed_authority
    test_fresh_commitments_do_not_bypass_fixed_authority("ssh-algos-ok", fault)


def test_manifest_contains_exact_finite_ruby_socket_client_closure():
    value = manifest()
    assert runtime.validate_manifest(value, tool_id=runtime.SSH_ALGORITHMS) == value
    assert runtime.runtime_files(value) == value["files"]
    assert runtime.compact_manifest(value) is value
    assert len(value["files"]) == len(set(ssh_algorithms.fixed_entries())) == 13
    assert len(runtime.encode(value)) < ssh_algorithms.MAX_MANIFEST_BYTES
    assert all(not source.startswith("compiled:") for source, _ in runtime.runtime_source_mounts(value))
    assert runtime.compiled_files(runtime.SSH_ALGORITHMS) == ssh_algorithms.COMPILED


@pytest.mark.parametrize("field,value", [("version", "2"), ("profile", runtime.PROFILE),
    ("tool_id", runtime.WHATWEB), ("tool_id", runtime.RDP), ("tool_id", runtime.SMB2), ("executable", "/usr/bin/ruby3.3"),
    ("interpreter", "/usr/bin/python3"), ("interpreter", "/usr/lib/ld-linux-x86-64.so.2")])
def test_manifest_identity_cannot_borrow_other_runtime_or_interpreter(field, value):
    candidate = manifest()
    candidate[field] = value
    with pytest.raises(ValueError):
        runtime.validate_manifest(candidate, tool_id=runtime.SSH_ALGORITHMS)


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
    elif fault == "size_large": value["files"][0]["size"] = ssh_algorithms.MAX_FILE_BYTES + 1
    else: value["files"][0]["sha256"] = "g" * 64
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("path", ["/usr/bin/python3", "/usr/bin/sh", "/tmp/client.rb",
    "/usr/lib/ruby/3.3.0/openssl.rb", "/usr/lib/ruby/3.3.0/timeout.rb",
    "/usr/lib/ruby/vendor_ruby/rubygems.rb", "/usr/lib/x86_64-linux-gnu/extra.so",
    "/usr/lib/ruby/3.3.0/../private.rb", "/root/.gem/credentials", "/etc/resolv.conf", "/root/.ssh/config",
    "/root/.ssh/known_hosts", "/root/.ssh/id_ed25519", "/run/ssh-agent.sock"])
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
    for name in ("HOME", "RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH", "LD_PRELOAD", "http_proxy", "SSH_AUTH_SOCK", "SSH_ASKPASS", "SSLKEYLOGFILE"):
        monkeypatch.setenv(name, "/private/injected")
    assert runtime.EXECUTABLES[runtime.SSH_ALGORITHMS] == "/usr/bin/ruby3.3"
    assert runtime.FIXED_ARGV[runtime.SSH_ALGORITHMS] == ("/tool/ruby", "--disable=all", ssh_algorithms.SCRIPT_PATH)
    assert runtime.execution_environment(runtime.SSH_ALGORITHMS) == {"LC_ALL": "C", "MALLOC_ARENA_MAX": "1"}
    permissions = worker._landlock_permissions(manifest())
    assert {path for path, rights in permissions.items() if rights & 1} == {
        ssh_algorithms.DESTINATION, ssh_algorithms.INTERPRETER}
    assert not any(rights & 8 for rights in permissions.values())
    assert all(permissions[row["destination"]] & 4 for row in manifest()["files"])
    assert not {"/usr/bin/python3", "/etc/resolv.conf", "/home", "/root"} & permissions.keys()


def test_ruby_uses_reviewed_thread_filter_with_inherited_resource_caps(monkeypatch):
    seen, limits = [], {}
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kwargs: seen.append(kwargs))
    worker.syscall_filter(runtime.SSH_ALGORITHMS)
    assert seen == [{"allow_threads": True}]
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda key, value: limits.update({key: value}))
    worker._limits(runtime.SSH_ALGORITHMS)
    assert limits[resource.RLIMIT_NPROC] == (16, 16)
    assert limits[resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    assert limits[resource.RLIMIT_FSIZE] == (0, 0)
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (2, 2))
    worker._limits(runtime.SSH_ALGORITHMS)
    assert set(limits.values()) == {(2, 2), (0, 0)}


def test_sealed_snapshot_contains_only_selected_files_and_fixed_client(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "sealed_snapshots", lambda *args, **kwargs: calls.append((args, kwargs)) or [])
    value, control = manifest(), object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = ssh_algorithms.COMPILED[0]
    assert calls == [((value, source, raw, control), {})]


def test_inspection_only_reads_exact_files_and_uses_ldd(monkeypatch):
    seen = []
    aliases = {destination: source for source, destination in ssh_algorithms.NATIVE_FILES}
    monkeypatch.setattr(ssh_algorithms.Path, "resolve", lambda path, **kwargs: Path(aliases.get(str(path), str(path))))
    monkeypatch.setattr(ssh_algorithms, "_read_regular", lambda _: b"\x7fELFdata")
    monkeypatch.setattr(ssh_algorithms, "_trusted_program", lambda name: "/usr/bin/" + name)
    listing = "\n".join(destination + " (0x100)" for _, destination in ssh_algorithms.NATIVE_FILES).encode()
    monkeypatch.setattr(ssh_algorithms, "_runtime_probe", lambda argv, *args: seen.append(argv) or listing)
    value = runtime.inspect_tool_runtime(runtime.SSH_ALGORITHMS, SimpleNamespace(check=lambda: None))
    assert runtime.validate_manifest(value, tool_id=runtime.SSH_ALGORITHMS) == value
    assert seen == [["/usr/bin/ldd", ssh_algorithms.EXECUTABLE,
        *(path for path in ssh_algorithms.RUBY_FILES if path.endswith(".so"))]]
    monkeypatch.setattr(ssh_algorithms, "_runtime_probe", lambda *args: listing + b"\n/usr/lib/x86_64-linux-gnu/extra.so (0x101)")
    with pytest.raises(IsolationUnavailable, match="finite closure"):
        runtime.inspect_tool_runtime(runtime.SSH_ALGORITHMS, SimpleNamespace(check=lambda: None))


def test_inspection_refuses_a_relocated_file_or_non_elf_extension(monkeypatch):
    monkeypatch.setattr(ssh_algorithms.Path, "resolve", lambda path, **kwargs: Path("/tmp/substitute"))
    with pytest.raises(IsolationUnavailable, match="distribution file layout"):
        runtime.inspect_tool_runtime(runtime.SSH_ALGORITHMS, SimpleNamespace(check=lambda: None))
    monkeypatch.setattr(ssh_algorithms.Path, "resolve", lambda path, **kwargs: path)
    monkeypatch.setattr(ssh_algorithms, "_read_regular", lambda _: b"not an ELF")
    with pytest.raises(IsolationUnavailable, match="ELF"):
        runtime.inspect_tool_runtime(runtime.SSH_ALGORITHMS, SimpleNamespace(check=lambda: None))


def test_command_seals_runtime_without_mounting_ssh_algorithms_owner(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        manifest(), list(range(20, 33)), "a" * 64, "b" * 64)
    assert argv.count("--ro-bind-data") == 13
    assert "CAP_NET_ADMIN" not in argv and "--unshare-net" not in argv
    assert not any("network_tools_ssh_algorithms_fixture" in item for item in argv)
    parser_paths = {item for item in argv if item.endswith("/network_tools_ssh_algorithms_parser.py")}
    assert parser_paths
    assert not parser_paths & worker._landlock_permissions(manifest()).keys()
