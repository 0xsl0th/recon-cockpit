"""Fixed C1 invocations cannot acquire configuration, transport or task authority."""

import base64
import hashlib
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker


TOOLS = (runtime.REDIS, runtime.SNMP)


def manifest(tool):
    entries = ((runtime.EXECUTABLES[tool], runtime.FIXED_ARGV[tool][0], b"tool"),
               ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", b"loader"))
    return {"version": "1", "profile": runtime.PROFILE, "tool_id": tool,
            "executable": runtime.FIXED_ARGV[tool][0], "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "files": [{"source": source, "destination": destination, "size": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest()}
                      for source, destination, raw in sorted(entries, key=lambda row: row[1])]}


def test_accepted_b1_b8_invocations_configuration_and_environment_are_unchanged():
    # Captured from accepted main 7de63a4; adding a profile cannot rewrite an
    # older invocation or its compiled input bytes while keeping its identity.
    tools = (runtime.DIG, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.SMB,
             runtime.RPCINFO, runtime.SHOWMOUNT, runtime.FTP, runtime.SMTP,
             runtime.DOCKER_PING, runtime.DOCKER_VERSION, runtime.WINRM,
             runtime.NMAP_SERVICE, runtime.KERBRUTE)
    values = {tool: {"argv": runtime.FIXED_ARGV[tool], "env": runtime.execution_environment(tool),
        "compiled": [(source, destination, base64.b64encode(raw).decode("ascii"))
                     for source, destination, raw in runtime.compiled_files(tool)]} for tool in tools}
    assert hashlib.sha256(runtime.encode(values)).hexdigest() == "eb5c70e270eaa57fdd96abf09fbcc20c907071c1ee3fabfedb48b42c555dd8a8"


def test_redis_runs_only_resp2_server_metadata_with_errors_nonzero():
    assert runtime.FIXED_ARGV[runtime.REDIS] == (
        "/tool/redis-cli", "-2", "-e", "--raw", "-h", "127.0.0.1", "-p", "8080", "INFO", "server")
    assert runtime.EXECUTABLES[runtime.REDIS] == "/usr/bin/redis-cli"
    assert runtime.execution_environment(runtime.REDIS) == {
        "LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1"}


def test_snmp_get_fixes_transport_community_oids_retry_budget_and_config_exclusion():
    argv = runtime.FIXED_ARGV[runtime.SNMP]
    assert argv == ("/tool/snmpget", "-v", "2c", "-c", "recon-fixture-public", "-r", "0", "-t", "2",
        "-Cf", "-On", "-Ot", "-Ox", "-m", "", "-M", "", "--dontLoadHostConfig=true",
        "--noPersistentLoad=true", "--noPersistentSave=true", "tcp:127.0.0.1:8080",
        ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0")
    assert runtime.EXECUTABLES[runtime.SNMP] == "/usr/bin/snmpget"
    environment = runtime.execution_environment(runtime.SNMP)
    assert environment == {"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1",
        "MIBS": "", "MIBDIRS": "", "MIBFILES": "", "SNMPCONFPATH": "/tool/no-snmp-config",
        "SNMP_PERSISTENT_DIR": "/tool/no-snmp-state"}


@pytest.mark.parametrize("tool", TOOLS)
def test_c1_runtime_never_inherits_host_secrets_or_configuration(monkeypatch, tool):
    injected = {"HOME": "/private", "REDISCLI_AUTH": "synthetic-secret", "REDISCLI_HISTFILE": "/private/history",
                "SNMPCONFPATH": "/private/snmp", "MIBS": "ALL", "MIBFILES": "/private/mib",
                "SNMP_PERSISTENT_FILE": "/private/snmpget.conf", "LD_PRELOAD": "/private/plugin.so"}
    for key, value in injected.items():
        monkeypatch.setenv(key, value)
    environment = runtime.execution_environment(tool)
    assert not any(environment.get(key) == value for key, value in injected.items())
    assert runtime.compiled_files(tool) == ()
    permissions = worker._landlock_permissions(manifest(tool))
    assert not any(path.startswith(("/etc", "/home", "/root", "/var", "/tool/data", "/tool/no-snmp"))
                   for path in permissions)
    assert "/usr/bin/python3" not in permissions


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("path", ["/etc/snmp/snmp.conf", "/etc/redis.conf", "/root/.redisclirc",
    "/usr/share/snmp/mibs/SNMPv2-MIB.txt", "/var/lib/snmp/snmpget.conf", "/tmp/credential"])
def test_c1_manifest_refuses_configuration_and_mib_mounts(tool, path):
    selected = manifest(tool)
    selected["files"].append({"source": path, "destination": path, "size": 1, "sha256": "a" * 64})
    selected["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError):
        runtime.validate_manifest(selected)


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("fault", ["other_tool", "interpreter", "large_file", "roots", "smb_profile", "missing_loader"])
def test_c1_manifest_cannot_borrow_other_tool_authority_or_larger_caps(tool, fault):
    selected = manifest(tool)
    assert runtime.validate_manifest(selected, tool_id=tool) == selected
    assert runtime.compact_manifest(selected) is selected
    if fault == "other_tool":
        selected["files"][-1]["source"] = runtime.EXECUTABLES[runtime.SNMP if tool == runtime.REDIS else runtime.REDIS]
    elif fault == "interpreter":
        selected["interpreter"] = "/usr/bin/python3"
    elif fault == "large_file":
        selected["files"][0]["size"] = runtime.MAX_FILE_BYTES + 1
    elif fault == "roots":
        selected["roots"] = ["/lib64"]
    elif fault == "smb_profile":
        selected["profile"] = runtime.SMB_PROFILE
    else:
        selected["files"].pop(0)
    with pytest.raises(ValueError):
        runtime.validate_manifest(selected)


@pytest.mark.parametrize("tool", TOOLS)
def test_c1_native_command_has_only_pinned_tool_files_and_no_owner_fixture(monkeypatch, tool):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        manifest(tool), [20, 21], "a" * 64, "b" * 64)
    assert argv.count("--ro-bind-data") == 2
    assert "CAP_NET_ADMIN" not in argv and "CAP_NET_BIND_SERVICE" not in argv
    assert not any("network_tools_redis_snmp_fixture" in arg for arg in argv)
    assert not any(arg.startswith(("/etc/snmp", "/usr/share/snmp", "/var/lib/snmp", "/root")) for arg in argv)


@pytest.mark.parametrize("tool", TOOLS)
def test_c1_preserves_single_task_resource_and_tcp_only_filter(monkeypatch, tool):
    selected = []
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **values: selected.append(values))
    worker.syscall_filter(tool)
    assert selected == [{"allow_threads": False}]
    applied = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda key, value: applied.__setitem__(key, value))
    worker._limits(tool)
    assert applied == {worker.resource.RLIMIT_AS: (256 * 1024 * 1024,) * 2,
        worker.resource.RLIMIT_CPU: (5, 5), worker.resource.RLIMIT_NOFILE: (64, 64),
        worker.resource.RLIMIT_NPROC: (1, 1), worker.resource.RLIMIT_CORE: (0, 0),
        worker.resource.RLIMIT_FSIZE: (0, 0)}


def test_c1_transport_witness_requires_kernel_udp_socket_denial(monkeypatch):
    attempted = []
    def denied(*args):
        attempted.append(args)
        raise PermissionError
    monkeypatch.setattr(worker.socket, "socket", denied)
    worker._metadata_transport_witness()
    assert attempted == [(worker.socket.AF_INET, worker.socket.SOCK_DGRAM, worker.socket.IPPROTO_UDP)]
    closed = []
    monkeypatch.setattr(worker.socket, "socket", lambda *_: SimpleNamespace(close=lambda: closed.append(True)))
    with pytest.raises(RuntimeError, match="metadata_udp_socket_allowed"):
        worker._metadata_transport_witness()
    assert closed == [True]


def test_c1_profiles_are_declared_by_both_secure_network_backends():
    from recon_cockpit.secure_agent.network_tools_backend import (
        AuthorizedNetworkToolsBackend, ConfinedNetworkToolsBackend)

    for backend in (AuthorizedNetworkToolsBackend, ConfinedNetworkToolsBackend):
        assert set(TOOLS) <= set(backend.supported_tools)
