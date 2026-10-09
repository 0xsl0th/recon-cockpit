"""The AXFR profile reuses dig without inheriting query or follow-up authority."""

import base64
from copy import deepcopy
import hashlib
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from test_secure_network_tools_runtime import envelope, manifest, recommit, verify


def test_all_26_accepted_native_invocations_remain_byte_identical():
    selected = {tool: [executable, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, executable in runtime.EXECUTABLES.items() if tool != "ssh_transport_policy_v1" and tool not in (runtime.DIG_AXFR, runtime.HTTP_OPTIONS, runtime.SNMP_NEXT, runtime.SSH_ALGORITHMS, runtime.TLS_CERTIFICATE, runtime.NUCLEI, runtime.NUCLEI_GIT, runtime.DIG_MX)}
    assert len(selected) == 26
    # Captured from accepted PR64 main before C11 edits.
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == (
        "7abe077ccf3f8a947589ff1cfbc607366f53b96206cf11930e2a86d517b1896d")


def test_fixed_axfr_argv_changes_only_transfer_type_and_complete_text_rendering():
    assert runtime.EXECUTABLES[runtime.DIG_AXFR] == "/usr/bin/dig"
    assert runtime.FIXED_ARGV[runtime.DIG_AXFR] == (
        "/tool/dig", "-r", "-4", "@127.0.0.1", "-p", "8080", "harbordesk.test.", "AXFR",
        "+tcp", "+norecurse", "+tries=1", "+time=2", "+nosearch", "+noedns",
        "+nobadcookie", "+noadflag", "+nocdflag", "+noall", "+comments", "+question",
        "+answer", "+additional", "+nocmd", "+noednsnegotiation", "+nobesteffort",
        "+authority", "+noonesoa", "+nomultiline", "+norrcomments")
    forbidden = {"-f", "-x", "+trace", "+search", "+recurse", "+retry", "+cookie",
                 "+edns", "+nsid", "+ednsnegotiation", "+besteffort", "+ignore", "IXFR", "ANY",
                 "+onesoa", "+multiline", "-k", "-y"}
    assert not forbidden & set(runtime.FIXED_ARGV[runtime.DIG_AXFR])


def test_axfr_cannot_inherit_resolver_search_configuration_keys_or_environment(monkeypatch):
    for name in ("HOME", "LOCALDOMAIN", "RES_OPTIONS", "DIGRC", "LD_PRELOAD", "LD_LIBRARY_PATH",
                 "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "/private/injected")
    assert runtime.execution_environment(runtime.DIG_AXFR) == {
        "LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1", "UV_THREADPOOL_SIZE": "1"}
    assert runtime.execution_environment(runtime.DIG_AXFR) == runtime.execution_environment(runtime.DIG)
    assert runtime.compiled_files(runtime.DIG_AXFR) == runtime.compiled_files(runtime.DIG) == (
        ("compiled:resolver", "/etc/resolv.conf", b"# fixed TCP nameserver supplied by reviewed argv\n"),)
    permissions = worker._landlock_permissions(manifest(runtime.DIG_AXFR))
    assert permissions == worker._landlock_permissions(manifest(runtime.DIG))
    assert permissions["/etc/resolv.conf"] == 4 and permissions["/tool/dig"] == 5
    assert not {"/usr/bin/python3", "/etc/hosts", "/etc", "/root", "/home", "/tool/data"} & permissions.keys()


@pytest.mark.parametrize("path", ["/etc/hosts", "/root/.digrc", "/home/user/.digrc", "/etc/bind/rndc.key",
    "/etc/nsswitch.conf", "/tool/data/query.txt", "/tool/data/tsig.key", "/tmp/credential", "/bin/sh"])
def test_manifest_rejects_host_resolution_configuration_batch_files_and_keys(path):
    value = manifest(runtime.DIG_AXFR)
    value["files"].append({"source": path, "destination": path, "size": 4, "sha256": "a" * 64})
    value["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("fault", ["missing", "source", "hash", "size", "interpreter", "executable", "tool"])
def test_fresh_digest_cannot_replace_pinned_resolver_or_other_runtime_identity(fault):
    value = manifest(runtime.DIG_AXFR)
    row = next(item for item in value["files"] if item["source"] == "compiled:resolver")
    if fault == "missing": value["files"].remove(row)
    elif fault == "source": row["source"] = "/etc/resolv.conf"
    elif fault == "hash": row["sha256"] = "b" * 64
    elif fault == "size": row["size"] += 1
    elif fault == "interpreter": value["interpreter"] = "/usr/bin/python3"
    elif fault == "executable": value["executable"] = "/usr/bin/dig"
    else: value["tool_id"] = runtime.DIG
    with pytest.raises(ValueError):
        runtime.validate_manifest(value, tool_id=runtime.DIG_AXFR)


def test_reused_dig_closure_is_identical_but_manifest_commitment_is_profile_specific():
    old, new = manifest(runtime.DIG), manifest(runtime.DIG_AXFR)
    assert new == {**old, "tool_id": runtime.DIG_AXFR}
    assert runtime.manifest_digest(new) != runtime.manifest_digest(old)
    assert runtime.runtime_source_mounts(new) == runtime.runtime_source_mounts(old)


def test_compiled_resolver_is_snapshotted_without_reading_a_host_file(monkeypatch):
    value, seen = manifest(runtime.DIG_AXFR), []
    monkeypatch.setattr(runtime, "sealed_snapshots", lambda *args, **kwargs: seen.append((args, kwargs)) or [])
    control = object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = runtime.compiled_files(runtime.DIG_AXFR)[0]
    assert seen == [((value, source, raw, control), {})]
    assert not any(source.startswith("compiled:") or destination == "/etc/resolv.conf"
                   for source, destination in runtime.runtime_source_mounts(value))


def test_runtime_inspection_uses_existing_dig_elf_and_libraries_only(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "_read_regular", lambda path: b"\x7fELFdig")
    monkeypatch.setattr(runtime, "read_runtime_file", lambda path, tool_id: b"\x7fELFbytes")
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(Path, "resolve", lambda self, strict: self)
    def probe(argv, *args):
        calls.append(argv)
        return b"libc.so.6 => /usr/lib/libc.so.6 (0x1)\n/usr/lib/ld-linux.so.2 (0x2)\n"
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    value = runtime.inspect_tool_runtime(runtime.DIG_AXFR, SimpleNamespace(check=lambda: None))
    assert calls == [["/usr/bin/ldd", "/usr/bin/dig"]]
    assert {row["source"] for row in value["files"]} == {
        "/usr/bin/dig", "/usr/lib/libc.so.6", "/usr/lib/ld-linux.so.2", "compiled:resolver"}


def test_shell_wrapper_is_rejected_before_any_probe(monkeypatch):
    monkeypatch.setattr(runtime, "_read_regular", lambda path: b"#!/bin/sh\nexec other")
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *args: pytest.fail("wrapper probed"))
    with pytest.raises(IsolationUnavailable, match="ELF"):
        runtime.inspect_tool_runtime(runtime.DIG_AXFR, SimpleNamespace(check=lambda: None))


@pytest.mark.parametrize("case,other_case", [("dig-axfr-ok", "dig-ok"), ("dig-ok", "dig-axfr-ok"),
    ("dig-axfr-ok", "dig-srv-ok"), ("dig-srv-ok", "dig-axfr-ok"),
    ("dig-axfr-ok", "dig-nsid-ok"), ("dig-nsid-ok", "dig-axfr-ok")])
def test_shared_elf_and_resolver_do_not_allow_cross_profile_launch_authority(case, other_case):
    value, other = envelope(case), envelope(other_case)
    assert value["runtime"]["files"] == other["runtime"]["files"]
    value["runtime"] = deepcopy(other["runtime"])
    with pytest.raises(ValueError): verify(value)
    value["launch"]["action"] = other["launch"]["action"]
    recommit(value)
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("code,reason,expected", [(0, None, "succeeded"), (1, None, "failed"),
    (-15, "timeout", "timeout"), (-15, "output_limit", "output_limit")])
def test_axfr_capture_retains_both_channels_and_failure_reasons(monkeypatch, code, reason, expected):
    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform="linux"))
    launch = envelope("dig-axfr-ok")
    selected = launch.pop("runtime")
    monkeypatch.setattr(runtime, "_snapshot", lambda *_: [])
    monkeypatch.setattr(runtime, "_command", lambda *_: ["fixed-worker"])
    stdout, stderr = b"untrusted DNS data", b"untrusted diagnostics"
    def capture(argv, raw, timeout, maximum, **kwargs):
        assert argv == ["fixed-worker"] and 0 < timeout <= 5
        prefix = runtime.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b"\n"
        assert maximum == 8192 + len(prefix)
        return code, stdout, prefix + stderr, reason
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    lab = SimpleNamespace(_namespace_fds=(10, 11), _check=lambda *_: None, _verify_pins=lambda: None)
    result = runtime.run_network_tool_owned(lab=lab, launch=launch,
        control=ExecutionControl(time.monotonic() + 20), manifest=selected,
        closure={"stdlib": "/usr/lib/python3.13", "files": [], "network_tools_runtime": selected})
    assert result["status"] == expected and result["tool_observation"] is None
    assert result["truncated"] is (reason == "output_limit")
    assert base64.b64decode(result["raw_output_base64"]) == stdout
    assert base64.b64decode(result["raw_stderr_base64"]) == stderr
    assert result["provenance"]["runtime_manifest"]["tool_id"] == runtime.DIG_AXFR
    assert result["provenance"]["parser_version"] == "dig-dns-axfr-text-v1"
    assert result["provenance"]["exit_code"] == code
    assert result["provenance"]["stop_reason"] == reason


def test_axfr_resources_match_dig_without_raising_stricter_inherited_limits(monkeypatch):
    limits = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    worker._limits(runtime.DIG_AXFR)
    first = dict(limits)
    worker._limits(runtime.DIG)
    assert limits == first
    assert first[worker.resource.RLIMIT_NPROC] == (16, 16)
    assert first[worker.resource.RLIMIT_NOFILE] == (64, 64)
    assert first[worker.resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (2, 2))
    worker._limits(runtime.DIG_AXFR)
    assert set(limits.values()) == {(2, 2), (0, 0)}


@pytest.mark.parametrize("case", fixture.DNS_AXFR_CASES)
@pytest.mark.parametrize("fault", ["mode", "inner_mode", "identity", "manifest", "namespace",
    "deadline", "sequence", "reservation", "policy", "action", "limit"])
def test_fresh_launch_commitments_do_not_expand_axfr_authority(case, fault):
    from test_secure_network_tools_runtime import test_fresh_commitments_do_not_bypass_fixed_authority
    test_fresh_commitments_do_not_bypass_fixed_authority(case, fault)


def test_axfr_retains_bounded_thread_exception(monkeypatch):
    seen = []
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kwargs: seen.append(kwargs))
    worker.syscall_filter(runtime.DIG_AXFR)
    assert seen == [{"allow_threads": True}]


def test_axfr_parser_source_is_present_at_outer_and_tool_isolation_boundaries():
    from recon_cockpit.secure_agent import launcher_isolation
    assert "network_tools_dns_axfr_parser" in runtime.MODULES
    assert "network_tools_dns_axfr_parser" in launcher_isolation.NETWORK_TOOLS_MODULES
    assert "network_tools_dns_axfr_fixture" in launcher_isolation.NETWORK_TOOLS_MODULES
