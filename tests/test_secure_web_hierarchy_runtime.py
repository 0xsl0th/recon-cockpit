"""Production launch binding and confinement for the distinct T04 candidate."""

from copy import deepcopy
import errno
import hashlib
import io
from pathlib import Path
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import isolation
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_web_hierarchy_runtime as hierarchy
from recon_cockpit.secure_agent import network_tools_web_hierarchy_worker as worker
from recon_cockpit.secure_agent import web_tools_runtime as accepted
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.executor_worker import digest
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_contract import action
from recon_cockpit.secure_agent.network_tools_execution import consume_launch
from recon_cockpit.secure_agent.network_tools_web_hierarchy_identity import identity
from recon_cockpit.secure_agent.network_tools_web_hierarchy_spec import CASES, LIMITS, TOOL_ID, WORDLIST


def manifest():
    entries = [(hierarchy.EXECUTABLE, hierarchy.FIXED_ARGV[0], b"\x7fELFdata"),
        ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", b"data"),
        *hierarchy.COMPILED]
    return {"version": "1", "profile": hierarchy.PROFILE, "tool_id": TOOL_ID,
        "executable": hierarchy.FIXED_ARGV[0], "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "files": [{"source": source, "destination": destination, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}
            for source, destination, raw in sorted(entries, key=lambda row: row[1])]}


def envelope(case=CASES[0]):
    selected = parse_action(action(case))
    policy = parse_policy({"schema_version": "1", "policy_version": "test-hierarchy-v1",
        "allowed_targets": ["127.0.0.1"], "allowed_tools": [TOOL_ID], "allowed_ports": [8080],
        "allowed_methods": ["GET"], "max_timeout_seconds": 10, "max_output_bytes": 8192,
        "max_targets": 1, "require_approval": True, "approval_ttl_seconds": 60})
    host = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    return {"mode": "owned_network_tools_lab", "identity": identity(case, str(uuid4())),
        "namespaces": {name: name + ":[200]" for name in host}, "runtime": manifest(),
        "launch": {"schema_version": "1", "mode": "network_tools_owned", "execute": True,
            "session_id": str(uuid4()), "nonce": "a" * 64, "sequence": 1,
            "action": selected.to_dict(), "action_digest": selected.digest,
            "policy": policy.to_dict(), "policy_digest": policy.digest,
            "limits": dict(LIMITS), "limits_digest": digest(dict(LIMITS)), "deadline": 160,
            "output_reserved_before": 0, "output_reserved_after": 8192, "host_namespaces": host}}


def encoded(value):
    raw = hierarchy.encode(value)
    return raw, "a" * 64, hashlib.sha256(raw).hexdigest()


def recommit(value):
    for field in ("action", "policy", "limits"):
        value["launch"][field + "_digest"] = digest(value["launch"][field])


@pytest.mark.parametrize("case", CASES)
def test_production_launch_binds_case_authority_and_distinct_runtime(case):
    value = envelope(case)
    request = hierarchy.consume_launch(*encoded(value), now=100)
    assert request["tool_id"] == TOOL_ID and request["deadline"] == 160
    assert request["manifest"] == value["runtime"]
    assert request["host_namespaces"] == value["launch"]["host_namespaces"]
    assert request["lab_namespaces"] == value["namespaces"]
    delegated, deadline, namespaces, runtime_digest = consume_launch(*encoded(value), now=100)
    assert delegated["tool_id"] == TOOL_ID and deadline == request["deadline"]
    assert namespaces == request["lab_namespaces"]
    assert runtime_digest == hierarchy.manifest_digest(request["manifest"])


@pytest.mark.parametrize("fault", ["diagnostic", "oversize", "commitment", "duplicate", "empty", "extra", "list"])
def test_non_authority_inputs_never_substitute_for_production_launch(fault):
    value = envelope()
    raw, nonce, commitment = encoded(value)
    if fault == "diagnostic": raw = hierarchy.encode({"deadline": 160, "manifest": manifest()})
    elif fault == "oversize": raw = b" " * (hierarchy.MAX_LAUNCH_BYTES + 1)
    elif fault == "duplicate": raw = raw[:-1] + b',"mode":"owned_network_tools_lab"}'
    elif fault == "empty": raw = b""
    elif fault == "extra": raw = raw[:-1] + b',"approved":true}'
    elif fault == "list": raw = b"[]"
    commitment = "0" * 64 if fault == "commitment" else hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError): hierarchy.consume_launch(raw, nonce, commitment, now=100)


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("fault", ["mode", "inner_mode", "identity", "case", "runtime", "target",
    "tool", "timeout", "port", "output", "policy", "steps", "duration", "limit_output",
    "reservation_before", "reservation_after", "namespace", "namespace_missing", "expired",
    "future", "nonce", "sequence", "execute", "session_id"])
def test_fresh_commitments_cannot_expand_or_replace_authority(case, fault):
    value = envelope(case)
    launch = value["launch"]
    if fault == "mode": value["mode"] = "owned_web_tools_lab"
    elif fault == "inner_mode": launch["mode"] = "web_tools_owned"
    elif fault == "identity": value["identity"]["spec_sha256"] = "b" * 64
    elif fault == "case": value["identity"]["scenario"] = CASES[1] if case != CASES[1] else CASES[0]
    elif fault == "runtime": value["runtime"]["profile"] = "web-hierarchy-diagnostic-runtime-v1"
    elif fault == "target":
        launch["action"]["target"] = "127.0.0.2"
        launch["policy"]["allowed_targets"] = ["127.0.0.0/8"]
    elif fault == "tool": launch["action"]["tool_id"] = accepted.FFUF
    elif fault == "timeout": launch["action"]["parameters"]["timeout_seconds"] = 5
    elif fault == "port": launch["action"]["parameters"]["port"] = 8081
    elif fault == "output": launch["action"]["parameters"]["max_output_bytes"] = 8191
    elif fault == "policy": launch["policy"]["allowed_tools"] = []
    elif fault == "steps": launch["limits"]["max_steps"] = 2
    elif fault == "duration": launch["limits"]["max_runtime_seconds"] = 61
    elif fault == "limit_output": launch["limits"]["max_output_bytes"] = 8191
    elif fault == "reservation_before": launch["output_reserved_before"] = True
    elif fault == "reservation_after": launch["output_reserved_after"] = 8191
    elif fault == "namespace": value["namespaces"] = launch["host_namespaces"]
    elif fault == "namespace_missing": del value["namespaces"]["net"]
    elif fault == "expired": launch["deadline"] = 100
    elif fault == "future": launch["deadline"] = 161
    elif fault == "nonce": launch["nonce"] = "b" * 64
    elif fault == "sequence": launch["sequence"] = True
    elif fault == "execute": launch["execute"] = False
    else: launch["session_id"] = "not-a-uuid"
    recommit(value)
    with pytest.raises(ValueError): hierarchy.consume_launch(*encoded(value), now=100)
    with pytest.raises(ValueError): consume_launch(*encoded(value), now=100)


@pytest.mark.parametrize("fault", ["profile", "tool", "extra", "path", "source", "hash", "size", "interpreter", "duplicate", "missing", "order"])
def test_manifest_pins_exact_compiled_data_and_excludes_unreviewed_paths(fault):
    value = manifest()
    row = next(item for item in value["files"] if item["source"].startswith("compiled:"))
    if fault == "profile": value["profile"] = accepted.PROFILE
    elif fault == "tool": value["tool_id"] = accepted.FFUF
    elif fault == "extra": value["approved"] = True
    elif fault == "path": row["destination"] = "/tool/data/words.txt"
    elif fault == "source": row["source"] = "compiled:fixture-paths"
    elif fault == "hash": row["sha256"] = "0" * 64
    elif fault == "size": row["size"] = True
    elif fault == "interpreter": value["interpreter"] = "/usr/bin/python3"
    elif fault == "duplicate": value["files"].append(deepcopy(value["files"][0]))
    elif fault == "missing": value["files"].pop(0)
    else: value["files"].reverse()
    with pytest.raises(ValueError): hierarchy.validate_manifest(value)
    with pytest.raises(ValueError): runtime.validate_manifest(value)


def test_new_runtime_reuses_elf_inspection_without_changing_accepted_profile(monkeypatch):
    original = manifest()
    old_source, old_destination, old_words = accepted._compiled(accepted.FFUF)
    original.update(profile=accepted.PROFILE, tool_id=accepted.FFUF)
    original["files"] = [row for row in original["files"] if not row["source"].startswith("compiled:")]
    original["files"].append({"source": old_source, "destination": old_destination, "size": len(old_words),
                             "sha256": hashlib.sha256(old_words).hexdigest()})
    original["files"].sort(key=lambda row: row["destination"])
    before = deepcopy(original)
    monkeypatch.setattr(accepted, "inspect_tool_runtime", lambda tool, control: original)
    selected = runtime.inspect_tool_runtime(TOOL_ID, ExecutionControl(160, clock=lambda: 100))
    assert selected == manifest() and original == before
    assert runtime.compiled_files(TOOL_ID) == hierarchy.COMPILED
    assert len(WORDLIST.splitlines()) == 12 and len(old_words.splitlines()) == 8
    assert runtime.execution_environment(TOOL_ID) == dict(hierarchy.ENVIRONMENT)
    assert runtime.manifest_digest(selected) == hierarchy.manifest_digest(selected)
    with pytest.raises(ValueError): hierarchy.validate_manifest(original)
    with pytest.raises(ValueError): accepted.validate_manifest(selected)


def test_client_mounts_pure_authority_and_sealed_data_without_owner_diagnostic_or_management(monkeypatch):
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11), private_peer_fd=999),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"), ("/usr/sbin/nft", "/usr/sbin/nft")]),
        manifest(), [20, 21, 22], "a" * 64, "b" * 64)
    assert argv[-3:] == ["/app/recon_cockpit/secure_agent/network_tools_web_hierarchy_worker.py", "a" * 64, "b" * 64]
    assert "20,21,22" in argv and "999" not in argv and argv.count("--ro-bind-data") == 3
    assert "--net=/proc/self/fd/11" in argv and "CAP_NET_ADMIN" not in argv and "--unshare-net" not in argv
    for forbidden in ("fixture.py", "diagnostic", "owner.py", "owned_lab_worker", "network_tools_worker.py", "/usr/sbin/nft"):
        assert not any(forbidden in item for item in argv)
    assert hierarchy.SCRAPER_DIRECTORY in argv
    with pytest.raises(ValueError): runtime._command(None, None, manifest(), [], "a" * 64, "b" * 64, service_web=True)


def test_closed_client_package_imports_and_verifies_authority_without_diagnostic_or_owner(tmp_path):
    package = tmp_path / "recon_cockpit" / "secure_agent"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    source = Path(hierarchy.__file__).parent
    for name in hierarchy.CLIENT_MODULES:
        (package / (name + ".py")).write_bytes((source / (name + ".py")).read_bytes())
    raw, nonce, commitment = encoded(envelope())
    code = """
import sys
sys.path.insert(0, sys.argv[1])
from recon_cockpit.secure_agent import network_tools_web_hierarchy_worker
from recon_cockpit.secure_agent.network_tools_web_hierarchy_runtime import consume_launch
consume_launch(sys.stdin.buffer.read(), sys.argv[2], sys.argv[3], now=100)
assert not any('fixture' in name or 'diagnostic' in name or 'owner' in name for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), nonce, commitment],
                            input=raw, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("fault", [None, "allowed", "other_error"])
def test_udp_witness_only_accepts_actual_permission_denial(monkeypatch, fault):
    closed = []
    def open_socket(*args):
        assert args == (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if fault == "allowed": return SimpleNamespace(close=lambda: closed.append(True))
        raise PermissionError(errno.EACCES if fault == "other_error" else errno.EPERM, "denied")
    monkeypatch.setattr(worker.socket, "socket", open_socket)
    if fault is None: worker.transport_witnesses()
    else:
        with pytest.raises((ValueError, PermissionError)): worker.transport_witnesses()
    assert closed == ([True] if fault == "allowed" else [])


@pytest.mark.parametrize("inherited", [worker.resource.RLIM_INFINITY, 1])
def test_go_resource_limits_never_raise_inherited_hard_limits(monkeypatch, inherited):
    limits = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (inherited, inherited))
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, pair: limits.update({kind: pair}))
    worker.limits()
    expected = {worker.resource.RLIMIT_AS: 2 * 1024 ** 3, worker.resource.RLIMIT_CPU: 5,
        worker.resource.RLIMIT_NOFILE: 64, worker.resource.RLIMIT_NPROC: 16,
        worker.resource.RLIMIT_CORE: 0, worker.resource.RLIMIT_FSIZE: 0}
    assert limits == {kind: (cap, cap) if inherited == worker.resource.RLIM_INFINITY
                      else (min(cap, inherited),) * 2 for kind, cap in expected.items()}


@pytest.mark.parametrize("prefix", [runtime.READY_PREFIX, b"RECON_WEB_HIERARCHY_DIAGNOSTIC_READY_V1 ", hierarchy.READY_PREFIX])
def test_capture_requires_production_worker_witness_and_ten_second_bound(monkeypatch, prefix):
    value = envelope()
    launch = {key: item for key, item in value.items() if key != "runtime"}
    lab = SimpleNamespace(_namespace_fds=(10, 11), _check=lambda _: None,
        _verify_pins=lambda: None, _runtime=lambda _: ("stdlib", []))
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime, "_snapshot", lambda *args: [])
    monkeypatch.setattr(runtime, "_command", lambda *args: ["fixed"])
    def capture(argv, raw, seconds, limit, **kwargs):
        assert seconds == 10 and kwargs["pass_fds"] == (10, 11)
        return 1, b"", prefix + hashlib.sha256(raw).hexdigest().encode("ascii") + b"\nrejected", None
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    control = ExecutionControl(160, clock=lambda: 100)
    if prefix != hierarchy.READY_PREFIX:
        with pytest.raises(isolation.IsolationUnavailable, match="confinement"):
            runtime.run_network_tool_owned(lab=lab, launch=launch, control=control, manifest=value["runtime"])
    else:
        result = runtime.run_network_tool_owned(lab=lab, launch=launch, control=control, manifest=value["runtime"])
        assert result["status"] == "failed" and result["provenance"]["exit_code"] == 1
        assert all(result["boundary_checks"][key] is True for key in hierarchy.BOUNDARY_FIELDS)
        assert result["tool_observation"] is None


@pytest.fixture
def worker_ready(monkeypatch):
    events, value = [], envelope()
    raw, nonce, commitment = encoded(value)
    request = hierarchy.consume_launch(raw, nonce, commitment, now=100)
    input_stream, errors = io.BytesIO(raw), io.StringIO()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(argv=["worker", nonce, commitment],
        stdin=SimpleNamespace(buffer=input_stream, close=lambda: events.append("stdin_closed")), stderr=errors))
    monkeypatch.setattr(worker.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFIFO))
    targets = [(hierarchy, "consume_launch", "authority"), (worker, "namespaces", "namespaces"),
        (worker, "verify_files", "files"), (worker, "limits", "limits"),
        (worker.worker, "drop_privileges", "privileges"), (worker.common, "_witnesses", "common_witnesses"),
        (worker.common, "_thread_bound_witness", "thread_witness"),
        (worker, "transport_witnesses", "transport_witnesses"),
        (worker, "close_private_descriptors", "close_fds"), (worker, "private_descriptors", "private_fds")]
    for module, function, label in targets:
        def record(*args, label=label):
            events.append(label)
            return request if label == "authority" else None
        monkeypatch.setattr(module, function, record)
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kwargs: events.append(("filter", kwargs)))
    monkeypatch.setattr(worker.os, "close", lambda fd: events.append(("close", fd)))
    monkeypatch.setattr(worker.os, "open", lambda *args: events.append(("open", args)) or 0)
    monkeypatch.setattr(worker.os, "dup2", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker.os, "set_inheritable", lambda *args: None)
    monkeypatch.setattr(worker.common, "apply_landlock", lambda permissions: events.append(("landlock", permissions)))
    monkeypatch.setattr(worker.time, "monotonic", lambda: 100)
    monkeypatch.setattr(worker.os, "write", lambda fd, raw: events.append(("ready", fd, raw)))
    class ExecReplaced(BaseException):
        pass
    def execute(*args):
        events.append(("execute", args))
        raise ExecReplaced()
    monkeypatch.setattr(worker.os, "execve", execute)
    return events, errors, ExecReplaced


def test_worker_authority_confinement_descriptor_eof_and_landlock_precede_readiness(worker_ready):
    events, errors, replaced = worker_ready
    with pytest.raises(replaced): worker.main()
    assert events[:8] == ["authority", "namespaces", "files", "limits", "privileges",
        ("filter", {"allow_threads": True}), "common_witnesses", "thread_witness"]
    assert events[8:12] == ["transport_witnesses", "stdin_closed", "close_fds", "private_fds"]
    assert events[12:14] == [("close", 0), ("open", ("/dev/null", worker.os.O_RDONLY | worker.os.O_CLOEXEC))]
    assert events[14][0] == "landlock" and events[15][0] == "ready" and events[16][0] == "execute"
    assert not any("/app" in path or "python" in path for path in events[14][1])
    assert events[15][2].startswith(hierarchy.READY_PREFIX) and errors.getvalue() == ""
    assert events[16][1] == (hierarchy.FIXED_ARGV[0], hierarchy.FIXED_ARGV, dict(hierarchy.ENVIRONMENT))


@pytest.mark.parametrize("stage", ["authority", "namespaces", "files", "limits", "privileges", "filter",
    "common_witnesses", "thread_witness", "transport_witnesses", "close_fds", "private_fds", "landlock", "deadline"])
def test_failed_worker_stage_never_issues_readiness_or_exec(worker_ready, monkeypatch, stage):
    events, errors, _ = worker_ready
    targets = {"authority": (hierarchy, "consume_launch"), "namespaces": (worker, "namespaces"),
        "files": (worker, "verify_files"), "limits": (worker, "limits"),
        "privileges": (worker.worker, "drop_privileges"), "filter": (worker.common, "syscall_filter"),
        "common_witnesses": (worker.common, "_witnesses"), "thread_witness": (worker.common, "_thread_bound_witness"),
        "transport_witnesses": (worker, "transport_witnesses"), "close_fds": (worker, "close_private_descriptors"),
        "private_fds": (worker, "private_descriptors"), "landlock": (worker.common, "apply_landlock")}
    def refuse(*args, **kwargs):
        raise ValueError("private authority or namespace detail")
    if stage == "deadline": monkeypatch.setattr(worker.time, "monotonic", lambda: 160)
    else: monkeypatch.setattr(*targets[stage], refuse)
    assert worker.main() == 78
    assert not any(isinstance(event, tuple) and event[0] in {"ready", "execute"} for event in events)
    assert errors.getvalue() == "network_web_hierarchy_worker_refused\n"
