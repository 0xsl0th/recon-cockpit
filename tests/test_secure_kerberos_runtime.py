"""The finite user-enumeration profile cannot acquire credentials or UDP."""

import errno
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import nmap_runtime
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from test_secure_network_tools_runtime import manifest


def test_accepted_b1_through_b7_runtime_profiles_remain_exact():
    values = {tool: [exe, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
                    [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
              for tool, exe in runtime.EXECUTABLES.items() if tool not in (runtime.KERBRUTE, runtime.REDIS, runtime.SNMP, runtime.POSTGRESQL_TLS, runtime.MYSQL_TLS, runtime.WHATWEB, runtime.DIG_SRV, runtime.RDP, runtime.SMB2, runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS, runtime.DIG_AXFR, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.HTTP_OPTIONS, runtime.SNMP_NEXT)}
    values["old_nmap"] = nmap_runtime.FIXED_ARGV
    assert len(values) == 14
    assert hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == (
        "d9c22962214b3ab401ad51cbeb6bf950f2a2260508e8e7d18574d61dd22a6303")


def test_b8_fixed_userenum_has_no_password_hash_output_or_target_selector():
    assert runtime.FIXED_ARGV[runtime.KERBRUTE] == (
        "/tool/kerbrute", "userenum", "--dc", "127.0.0.1:8080", "--domain", "harbordesk.test",
        "--threads", "1", "--safe", "--verbose", "/tool/data/principals.txt")
    assert runtime.compiled_files(runtime.KERBRUTE) == (
        ("compiled:kerbrute-principals", "/tool/data/principals.txt", b"fixture-a\nfixture-b\n"),)
    assert runtime.execution_environment(runtime.KERBRUTE) == {
        "LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1",
        "GOMAXPROCS": "1", "GOMEMLIMIT": "64MiB"}


@pytest.mark.parametrize("fault", ["missing", "source", "destination", "size", "sha256"])
def test_b8_principal_list_is_compiled_pinned_and_cannot_be_replaced(fault):
    value = manifest(runtime.KERBRUTE)
    row = next(row for row in value["files"] if row["destination"] == "/tool/data/principals.txt")
    if fault == "missing":
        value["files"].remove(row)
    elif fault == "source":
        row["source"] = "/tmp/principals.txt"
    elif fault == "destination":
        row["destination"] = "/tool/data/passwords.txt"
    elif fault == "size":
        row["size"] += 1
    else:
        row["sha256"] = hashlib.sha256(b"administrator\n").hexdigest()
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("path", ["/etc/krb5.conf", "/etc/krb5.keytab", "/tmp/krb5cc_1000",
    "/tool/data/passwords.txt", "/tool/data/principals2.txt", "/root/.config/kerbrute",
    "/etc/resolv.conf", "/etc/hosts", "/bin/sh", "/usr/bin/python3"])
def test_b8_cannot_add_credential_configuration_or_unreviewed_executable_files(path):
    value = manifest(runtime.KERBRUTE)
    value["files"].append({"source": path, "destination": path, "size": 4,
                           "sha256": hashlib.sha256(b"data").hexdigest()})
    value["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("source", ["/tmp/kerbrute", "/usr/bin/kerbrute", "/opt/kerbrute/kerbrute",
    "/usr/bin/ffuf", "/bin/sh"])
def test_b8_executable_source_is_a_single_reviewed_location(source):
    value = manifest(runtime.KERBRUTE)
    next(row for row in value["files"] if row["destination"] == "/tool/kerbrute")["source"] = source
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


def test_b8_inspects_the_elf_without_running_it_or_loading_host_config(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "_read_regular", lambda path: b"\x7fELFkerbrute")
    monkeypatch.setattr(runtime, "read_runtime_file", lambda path, tool_id: b"\x7fELFbytes")
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(Path, "resolve", lambda self, strict: self)
    def probe(argv, *args):
        calls.append(argv)
        return b"libc.so.6 => /usr/lib/libc.so.6 (0x1)\n/usr/lib/ld-linux.so.2 (0x2)\n"
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    value = runtime.inspect_tool_runtime(runtime.KERBRUTE, SimpleNamespace(check=lambda: None))
    assert calls == [["/usr/bin/ldd", "/usr/local/bin/kerbrute"]]
    assert {row["source"] for row in value["files"]} == {
        "/usr/local/bin/kerbrute", "/usr/lib/libc.so.6", "/usr/lib/ld-linux.so.2",
        "compiled:kerbrute-principals"}


def test_b8_rejects_a_shell_wrapper_before_any_runtime_probe(monkeypatch):
    monkeypatch.setattr(runtime, "_read_regular", lambda path: b"#!/bin/sh\nexec other")
    def forbidden(*args):
        pytest.fail("wrapper inspection must not launch any process")
    monkeypatch.setattr(runtime, "_runtime_probe", forbidden)
    with pytest.raises(IsolationUnavailable, match="ELF"):
        runtime.inspect_tool_runtime(runtime.KERBRUTE, SimpleNamespace(check=lambda: None))


def test_b8_snapshots_only_the_two_compiled_synthetic_principals(monkeypatch):
    value, seen = manifest(runtime.KERBRUTE), []
    def stage(selected, source, raw, control, **kwargs):
        seen.append((selected, source, raw, kwargs))
        return [11, 12, 13]
    monkeypatch.setattr(runtime, "sealed_snapshots", stage)
    assert runtime._snapshot(value, object()) == [11, 12, 13]
    assert seen == [(value, "compiled:kerbrute-principals", b"fixture-a\nfixture-b\n", {})]
    assert not any("compiled:" in source or source.endswith("principals.txt")
                   for source, _ in runtime.runtime_source_mounts(value))


@pytest.mark.parametrize("tool_id", tuple(runtime.EXECUTABLES))
def test_go_runtime_allowances_do_not_expand_accepted_other_tools(monkeypatch, tool_id):
    calls, limits = [], {}
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    worker.syscall_filter(tool_id)
    worker._limits(tool_id)
    threaded = tool_id in (runtime.DIG_AXFR, runtime.DIG_NSID, runtime.DIG, runtime.DIG_SRV, runtime.KERBRUTE, runtime.WHATWEB, runtime.RDP, runtime.SMB2)
    assert calls == [{"allow_threads": threaded}]
    assert limits == {
        worker.resource.RLIMIT_AS: ((2048 if tool_id == runtime.KERBRUTE else 256) * 1024 * 1024,) * 2,
        worker.resource.RLIMIT_CPU: (5, 5), worker.resource.RLIMIT_NOFILE: (64, 64),
        worker.resource.RLIMIT_NPROC: ((16 if threaded else 1),) * 2,
        worker.resource.RLIMIT_CORE: (0, 0), worker.resource.RLIMIT_FSIZE: (0, 0)}


def test_b8_limits_never_raise_a_stricter_inherited_ceiling(monkeypatch):
    limits = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (2, 2))
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    worker._limits(runtime.KERBRUTE)
    assert set(limits.values()) == {(2, 2), (0, 0)}


def test_b8_landlock_exposes_only_the_wordlist_for_reading():
    permissions = worker._landlock_permissions(manifest(runtime.KERBRUTE))
    assert permissions["/tool/data/principals.txt"] == 4
    assert permissions["/tool/kerbrute"] == 5
    assert "/tool/data" not in permissions
    assert all("krb5" not in path and "password" not in path for path in permissions)


def test_b8_udp_witness_requires_actual_socket_denial(monkeypatch):
    calls = []
    def denied(*args):
        calls.append(args)
        raise PermissionError(errno.EPERM, "denied")
    monkeypatch.setattr(worker.socket, "socket", denied)
    worker._kerberos_transport_witness()
    assert calls == [(worker.socket.AF_INET, worker.socket.SOCK_DGRAM, worker.socket.IPPROTO_UDP)]


def test_b8_udp_witness_closes_and_refuses_an_unrestricted_socket(monkeypatch):
    closed = []
    monkeypatch.setattr(worker.socket, "socket", lambda *args: SimpleNamespace(close=lambda: closed.append(True)))
    with pytest.raises(RuntimeError, match="udp_socket_allowed"):
        worker._kerberos_transport_witness()
    assert closed == [True]


def test_b8_udp_witness_does_not_mistake_resource_failure_for_denial(monkeypatch):
    def exhausted(*args):
        raise OSError(errno.EMFILE, "too many files")
    monkeypatch.setattr(worker.socket, "socket", exhausted)
    with pytest.raises(OSError) as error:
        worker._kerberos_transport_witness()
    assert error.value.errno == errno.EMFILE


@pytest.mark.parametrize("tool_id", tuple(runtime.EXECUTABLES))
def test_only_b8_gets_its_distinct_outer_launcher_tag(tool_id):
    from recon_cockpit.secure_agent import launcher_protocol
    config = {"profile": "owned_network_tools_lab"}
    closure = {"network_tools_runtime": manifest(tool_id)}
    wanted = ("whatweb-tools-launch-preconditions" if tool_id == runtime.WHATWEB else
              "kerberos-tools-launch-preconditions" if tool_id == runtime.KERBRUTE else
              "smb-tools-launch-preconditions" if tool_id == runtime.SMB else "network-tools-launch-preconditions")
    assert launcher_protocol.runtime_tag(config, closure) == wanted
    launcher_protocol.validate_runtime_tag(wanted, config, closure)
    for incorrect in {"network-tools-launch-preconditions", "smb-tools-launch-preconditions",
                      "kerberos-tools-launch-preconditions", "whatweb-tools-launch-preconditions",
                      "web-tools-launch-preconditions", None} - {wanted}:
        with pytest.raises(ValueError, match="runtime_profile_changed"):
            launcher_protocol.validate_runtime_tag(incorrect, config, closure)


@pytest.mark.parametrize("case", ["dig-ok", "smb-ok", "nmap-service-http"])
def test_b8_manifest_cannot_increase_outer_limits_for_a_different_tool_case(case):
    from recon_cockpit.secure_agent import launcher_protocol
    from recon_cockpit.secure_agent.network_tools_lab_contract import identity
    from test_secure_network_tools_runtime import configuration
    from uuid import uuid4
    config = {**configuration(case), "owned_lab": identity(case, str(uuid4()))}
    closure = {"stdlib": "/usr/lib/python3.11", "files": ["/usr/bin/python3", "/usr/sbin/nft",
        "/usr/bin/bwrap", "/usr/bin/nsenter"], "network_tools_runtime": manifest(runtime.KERBRUTE)}
    with pytest.raises(ValueError, match="launcher_network_tool_runtime_changed"):
        launcher_protocol.initial({"configuration": config, "runtime": closure, "deadline": 130}, 100)


@pytest.mark.parametrize("kwargs,megabytes,staging_megabytes,descriptors", [
    ({}, 256, 1, 128), ({"network_tools_runtime": True}, 256, 16, 128),
    ({"nmap_runtime": True}, 256, 16, 128), ({"smb_runtime": True}, 256, 40, 256),
    ({"web_tools_runtime": True}, 2048, 16, 128), ({"kerberos_runtime": True}, 2048, 16, 128)])
def test_launcher_go_reservation_is_scoped_and_preserves_other_caps(monkeypatch, kwargs, megabytes,
                                                                   staging_megabytes, descriptors):
    from recon_cockpit.secure_agent import launcher_worker
    limits = {}
    monkeypatch.setattr(launcher_worker, "ENTRY_DESCRIPTORS_VERIFIED", True)
    monkeypatch.setattr(launcher_worker.sys, "platform", "linux")
    monkeypatch.setattr(launcher_worker.os, "getuid", lambda: 1000)
    monkeypatch.setattr(launcher_worker.os, "getgid", lambda: 1000)
    monkeypatch.setattr(launcher_worker.os, "readlink", lambda path: "private")
    monkeypatch.setattr(launcher_worker.Path, "read_text", lambda self: "1000 1000 1\n")
    monkeypatch.setattr(launcher_worker.socket, "if_nameindex", lambda: [(1, "lo")])
    for name in ("_zero_capabilities", "_no_new_privileges", "_root_read_only"):
        monkeypatch.setattr(launcher_worker.bootstrap, name, lambda: None)
    monkeypatch.setattr(launcher_worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    launcher_worker.boundary({"net": "host"}, **kwargs)
    assert limits == {
        launcher_worker.resource.RLIMIT_AS: (megabytes * 1048576,) * 2,
        launcher_worker.resource.RLIMIT_CPU: (30, 30),
        launcher_worker.resource.RLIMIT_NOFILE: (descriptors,) * 2,
        launcher_worker.resource.RLIMIT_CORE: (0, 0),
        launcher_worker.resource.RLIMIT_FSIZE: (staging_megabytes * 1048576,) * 2,
        launcher_worker.resource.RLIMIT_NPROC: (64, 64)}
