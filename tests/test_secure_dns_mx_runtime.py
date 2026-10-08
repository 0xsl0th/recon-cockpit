"""The MX profile reuses dig without inheriting query or follow-up authority."""

import base64
from copy import deepcopy
import hashlib
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from test_secure_network_tools_runtime import envelope as shared_envelope, manifest, recommit, verify
from recon_cockpit.secure_agent.models import parse_policy


def envelope(case="dig-mx-ok"):
    value = shared_envelope(case)
    selected = value["launch"]["policy"]
    if runtime.DIG_MX not in selected["allowed_tools"]:
        selected["allowed_tools"].append(runtime.DIG_MX)
    value["launch"]["policy"] = parse_policy(selected).to_dict()
    recommit(value)
    return value


def test_fixed_mx_argv_changes_only_the_reviewed_name_and_record_type():
    assert runtime.EXECUTABLES[runtime.DIG_MX] == "/usr/bin/dig"
    assert runtime.FIXED_ARGV[runtime.DIG_MX] == (
        "/tool/dig", "-r", "-4", "@127.0.0.1", "-p", "8080", "harbordesk.test.", "MX",
        "+tcp", "+norecurse", "+tries=1", "+time=2", "+nosearch", "+noedns",
        "+nobadcookie", "+noadflag", "+nocdflag", "+noall", "+comments", "+question",
        "+answer", "+additional", "+nocmd")
    old, new = runtime.FIXED_ARGV[runtime.DIG], runtime.FIXED_ARGV[runtime.DIG_MX]
    assert old[:6] == new[:6] and old[8:] == new[8:]
    assert not {"-f", "-x", "+trace", "+search", "+recurse", "+retry", "AXFR", "IXFR", "ANY"} & set(new)


def test_mx_cannot_inherit_resolver_search_configuration_keys_or_environment(monkeypatch):
    for name in ("HOME", "LOCALDOMAIN", "RES_OPTIONS", "DIGRC", "LD_PRELOAD", "LD_LIBRARY_PATH",
                 "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "/private/injected")
    assert runtime.execution_environment(runtime.DIG_MX) == {
        "LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1", "UV_THREADPOOL_SIZE": "1"}
    assert runtime.execution_environment(runtime.DIG_MX) == runtime.execution_environment(runtime.DIG)
    assert runtime.compiled_files(runtime.DIG_MX) == runtime.compiled_files(runtime.DIG) == (
        ("compiled:resolver", "/etc/resolv.conf", b"# fixed TCP nameserver supplied by reviewed argv\n"),)
    permissions = worker._landlock_permissions(manifest(runtime.DIG_MX))
    assert permissions == worker._landlock_permissions(manifest(runtime.DIG))
    assert permissions["/etc/resolv.conf"] == 4 and permissions["/tool/dig"] == 5
    assert not {"/usr/bin/python3", "/etc/hosts", "/etc", "/root", "/home", "/tool/data"} & permissions.keys()


@pytest.mark.parametrize("path", ["/etc/hosts", "/root/.digrc", "/home/user/.digrc", "/etc/bind/rndc.key",
    "/etc/nsswitch.conf", "/tool/data/query.txt", "/tool/data/tsig.key", "/tmp/credential", "/bin/sh"])
def test_manifest_rejects_host_resolution_configuration_batch_files_and_keys(path):
    value = manifest(runtime.DIG_MX)
    value["files"].append({"source": path, "destination": path, "size": 4, "sha256": "a" * 64})
    value["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("fault", ["missing", "source", "hash", "size", "interpreter", "executable", "tool"])
def test_fresh_digest_cannot_replace_pinned_resolver_or_other_runtime_identity(fault):
    value = manifest(runtime.DIG_MX)
    row = next(item for item in value["files"] if item["source"] == "compiled:resolver")
    if fault == "missing": value["files"].remove(row)
    elif fault == "source": row["source"] = "/etc/resolv.conf"
    elif fault == "hash": row["sha256"] = "b" * 64
    elif fault == "size": row["size"] += 1
    elif fault == "interpreter": value["interpreter"] = "/usr/bin/python3"
    elif fault == "executable": value["executable"] = "/usr/bin/dig"
    else: value["tool_id"] = runtime.DIG
    with pytest.raises(ValueError):
        runtime.validate_manifest(value, tool_id=runtime.DIG_MX)


def test_reused_dig_closure_is_identical_but_manifest_commitment_is_profile_specific():
    old, new = manifest(runtime.DIG), manifest(runtime.DIG_MX)
    assert new == {**old, "tool_id": runtime.DIG_MX}
    assert runtime.manifest_digest(new) != runtime.manifest_digest(old)
    assert runtime.runtime_source_mounts(new) == runtime.runtime_source_mounts(old)


def test_compiled_resolver_is_snapshotted_without_reading_a_host_file(monkeypatch):
    value, seen = manifest(runtime.DIG_MX), []
    monkeypatch.setattr(runtime, "sealed_snapshots", lambda *args, **kwargs: seen.append((args, kwargs)) or [])
    control = object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = runtime.compiled_files(runtime.DIG_MX)[0]
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
    value = runtime.inspect_tool_runtime(runtime.DIG_MX, SimpleNamespace(check=lambda: None))
    assert calls == [["/usr/bin/ldd", "/usr/bin/dig"]]
    assert {row["source"] for row in value["files"]} == {
        "/usr/bin/dig", "/usr/lib/libc.so.6", "/usr/lib/ld-linux.so.2", "compiled:resolver"}


def test_shell_wrapper_is_rejected_before_any_probe(monkeypatch):
    monkeypatch.setattr(runtime, "_read_regular", lambda path: b"#!/bin/sh\nexec other")
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *args: pytest.fail("wrapper probed"))
    with pytest.raises(IsolationUnavailable, match="ELF"):
        runtime.inspect_tool_runtime(runtime.DIG_MX, SimpleNamespace(check=lambda: None))


@pytest.mark.parametrize("case,other_case", [pair for other in ("dig-ok", "dig-srv-ok", "dig-nsid-ok", "dig-axfr-ok")
    for pair in (("dig-mx-ok", other), (other, "dig-mx-ok"))])
def test_shared_elf_and_resolver_do_not_allow_cross_profile_launch_authority(case, other_case):
    value, other = envelope(case), envelope(other_case)
    verify(value)
    verify(other)
    assert value["runtime"]["files"] == other["runtime"]["files"]
    value["runtime"] = deepcopy(other["runtime"])
    with pytest.raises(ValueError): verify(value)
    value["launch"]["action"] = other["launch"]["action"]
    recommit(value)
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("code,reason,expected", [(0, None, "succeeded"), (1, None, "failed"),
    (-15, "timeout", "timeout"), (-15, "output_limit", "output_limit")])
def test_mx_capture_retains_both_channels_and_failure_reasons(monkeypatch, code, reason, expected):
    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform="linux"))
    launch = envelope("dig-mx-ok")
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
    assert result["provenance"]["runtime_manifest"]["tool_id"] == runtime.DIG_MX
    assert result["provenance"]["parser_version"] == "dig-dns-mx-text-v1"
    assert result["provenance"]["exit_code"] == code
    assert result["provenance"]["stop_reason"] == reason


def test_mx_resources_match_dig_without_raising_stricter_inherited_limits(monkeypatch):
    limits = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    worker._limits(runtime.DIG_MX)
    first = dict(limits)
    worker._limits(runtime.DIG)
    assert limits == first
    assert first[worker.resource.RLIMIT_NPROC] == (16, 16)
    assert first[worker.resource.RLIMIT_NOFILE] == (64, 64)
    assert first[worker.resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (2, 2))
    worker._limits(runtime.DIG_MX)
    assert set(limits.values()) == {(2, 2), (0, 0)}


def test_mx_retains_only_the_existing_bounded_thread_exception(monkeypatch):
    seen = []
    monkeypatch.setattr(worker.common, 'syscall_filter', lambda **kwargs: seen.append(kwargs))
    worker.syscall_filter(runtime.DIG_MX)
    assert seen == [{'allow_threads': True}]
    assert worker.clone_denials() == worker.common.clone_denials()


def test_launcher_inner_runtime_and_owner_include_the_required_fixture_closure(monkeypatch):
    from uuid import uuid4
    from recon_cockpit.secure_agent.launcher_isolation import NETWORK_TOOLS_MODULES
    from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
    from recon_cockpit.secure_agent.owned_lab import OwnedLab
    from recon_cockpit.secure_agent.session_limits import SessionLimits
    from recon_cockpit.secure_agent.network_tools_contract import LIMITS

    required = {'network_tools_dns_mx_fixture', 'network_tools_dns_mx_parser'}
    assert required <= set(NETWORK_TOOLS_MODULES) and required <= set(runtime.MODULES)
    selected = manifest(runtime.DIG_MX)
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    descriptors = list(range(40, 40 + len(selected['files'])))
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ('/stdlib', [('/usr/bin/python3', '/usr/bin/python3'), ('/usr/bin/dig', '/tool/dig')]),
        selected, descriptors, 'a' * 64, 'b' * 64)
    assert '--user=/proc/self/fd/10' in argv and '--net=/proc/self/fd/11' in argv
    assert argv.count('--ro-bind-data') == len(selected['files'])
    assert '--clearenv' in argv and '--tmpfs' not in argv and '/usr/bin/dig' not in argv
    assert '/etc/resolv.conf' in argv and 'CAP_NET_ADMIN' not in argv
    assert 'CAP_NET_BIND_SERVICE' not in argv and 'CAP_SYS_ADMIN' not in argv
    for name in required:
        assert '/app/recon_cockpit/secure_agent/' + name + '.py' in argv
    base = ['/usr/bin/bwrap', '--cap-drop', 'ALL', '--die-with-parent', '--remount-ro', '/',
        '/usr/bin/python3', '-I', '-S', '/app/owned_lab_worker.py']
    monkeypatch.setattr(OwnedLab, '_owner_command', lambda *_: list(base))
    command = NetworkToolsLab('dig-mx-ok', str(uuid4()), SessionLimits(**LIMITS))._owner_command('/stdlib', [], 9)
    path = '/app/network_tools_dns_mx_fixture.py'
    index = command.index(path)
    assert command[index - 2] == '--ro-bind' and command.count(path) == 1
    assert 'CAP_NET_BIND_SERVICE' not in command
    assert command[-1] == '/app/network_tools_lab_worker.py'


@pytest.mark.parametrize('other_case', ['dig-ok', 'dig-srv-ok', 'dig-nsid-ok', 'dig-axfr-ok'])
def test_synthetic_approval_cannot_cross_dig_profiles_even_with_the_same_executable(other_case):
    from recon_cockpit.secure_agent.approvals import ApprovalStore
    from recon_cockpit.secure_agent.models import parse_action
    from recon_cockpit.secure_agent.network_tools_contract import action

    policy = parse_policy(envelope()['launch']['policy'])
    selected, other = parse_action(action('dig-mx-ok')), parse_action(action(other_case))
    for approved, attempted in ((selected, other), (other, selected)):
        approvals = ApprovalStore(clock=lambda: 100)
        grant = approvals.issue(approved, policy)
        assert approvals.consume(grant.reference, attempted, policy) == 'approval_action_changed'
        assert approvals.consume(grant.reference, approved, policy) == 'approval_unknown_or_replayed'


@pytest.mark.parametrize('fault', ['mode', 'inner_mode', 'identity', 'manifest', 'namespace',
    'deadline', 'sequence', 'reservation', 'policy', 'target', 'limit', 'port', 'timeout', 'output'])
def test_recommitted_mx_launch_cannot_expand_the_fixed_profile(fault):
    from recon_cockpit.secure_agent.network_tools_contract import LIMITS
    value = envelope()
    verify(value)
    launch = value['launch']
    if fault == 'mode': value['mode'] = 'owned_http_headers_lab'
    elif fault == 'inner_mode': launch['mode'] = 'http_headers_owned'
    elif fault == 'identity': value['identity']['spec_sha256'] = 'b' * 64
    elif fault == 'manifest': value['runtime'] = manifest(runtime.DIG_SRV)
    elif fault == 'namespace': value['namespaces'] = dict(launch['host_namespaces'])
    elif fault == 'deadline': launch['deadline'] = 161
    elif fault == 'sequence': launch['sequence'] = 2
    elif fault == 'reservation': launch['output_reserved_before'] = 1
    elif fault == 'policy': launch['policy']['allowed_tools'] = []
    elif fault == 'target':
        launch['action']['target'] = '127.0.0.2'
        launch['policy']['allowed_targets'] = ['127.0.0.0/8']
    elif fault == 'port':
        launch['action']['parameters']['port'] = 8081
        launch['policy']['allowed_ports'] = [8080, 8081]
    elif fault == 'timeout': launch['action']['parameters']['timeout_seconds'] = 10
    elif fault == 'output':
        launch['action']['parameters']['max_output_bytes'] = 16384
        launch['policy']['max_output_bytes'] = 16384
    else: launch['limits'] = {**LIMITS, 'max_steps': 2}
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)
