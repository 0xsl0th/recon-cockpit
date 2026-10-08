"""Portable production authority and confinement checks for the four TLS probes."""

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

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_tls_posture_runtime as native
from recon_cockpit.secure_agent import network_tools_tls_posture_worker as worker
from recon_cockpit.secure_agent import isolation
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.network_tools_tls_posture_spec import CASES, TOOL_VERSIONS
from recon_cockpit.secure_agent.network_tools_execution import consume_launch
from test_secure_network_tools_runtime import manifest, envelope, recommit


def encoded(value):
    raw = runtime.encode(value)
    return raw, "a" * 64, hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("case", CASES)
def test_production_launch_selects_only_its_version_case_and_runtime(case):
    value = envelope(case)
    request = native.consume_launch(*encoded(value), now=100)
    assert request["version"] == TOOL_VERSIONS[request["tool_id"]]
    assert request["manifest"] == value["runtime"] and request["deadline"] == 130
    delegated, deadline, namespaces, digest = consume_launch(*encoded(value), now=100)
    assert delegated["tool_id"] == request["tool_id"] and deadline == 130
    assert namespaces == value["namespaces"] and digest == native.manifest_digest(value["runtime"])


@pytest.mark.parametrize("fault", ["diagnostic", "oversize", "commitment", "duplicate", "empty", "extra"])
def test_non_authority_input_cannot_substitute_for_a_production_launch(fault):
    value = envelope(CASES[0])
    raw, nonce, commitment = encoded(value)
    if fault == "diagnostic": raw = native.fixed.encode({"version": "tls1", "diagnostic_only": True})
    elif fault == "oversize": raw = b" " * (native.MAX_LAUNCH_BYTES + 1)
    elif fault == "duplicate": raw = raw[:-1] + b',"mode":"owned_network_tools_lab"}'
    elif fault == "empty": raw = b""
    elif fault == "extra": raw = raw[:-1] + b',"approved":true}'
    if fault != "commitment": commitment = hashlib.sha256(raw).hexdigest()
    else: commitment = "0" * 64
    with pytest.raises(ValueError): native.consume_launch(raw, nonce, commitment, now=100)


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("fault", ["limits", "runtime", "case", "target", "version", "approval_policy",
    "reservation", "namespace", "expired", "future", "nonce", "sequence", "execute"])
def test_recommitted_mutations_cannot_expand_authority(case, fault):
    value = envelope(case)
    launch = value["launch"]
    if fault == "limits": launch["limits"]["max_runtime_seconds"] = 31
    elif fault == "runtime": value["runtime"] = manifest(runtime.TLS_CERTIFICATE)
    elif fault == "case": value["identity"]["scenario"] = "tls-posture-tls1-modern" if case != "tls-posture-tls1-modern" else "tls-posture-tls1_3-hrr"
    elif fault == "target": launch["action"]["target"] = "127.0.0.2"
    elif fault == "version": launch["action"]["tool_id"] = runtime.TLS_CERTIFICATE
    elif fault == "approval_policy": launch["policy"]["allowed_tools"] = []
    elif fault == "reservation": launch["output_reserved_after"] = True
    elif fault == "namespace": value["namespaces"] = launch["host_namespaces"]
    elif fault == "expired": launch["deadline"] = 100
    elif fault == "future": launch["deadline"] = 131
    elif fault == "nonce": launch["nonce"] = "b" * 64
    elif fault == "sequence": launch["sequence"] = True
    else: launch["execute"] = False
    recommit(value)
    with pytest.raises(ValueError): native.consume_launch(*encoded(value), now=100)
    with pytest.raises(ValueError): consume_launch(*encoded(value), now=100)


@pytest.mark.parametrize("tool", TOOL_VERSIONS)
def test_new_runtime_is_versioned_but_client_bytes_and_environment_are_unchanged(tool):
    selected = manifest(tool)
    original = manifest(runtime.TLS_CERTIFICATE)
    assert selected["files"] == original["files"]
    assert native.validate_manifest(selected) == runtime.validate_manifest(selected) == selected
    assert runtime.runtime_source_mounts(selected) == runtime.runtime_source_mounts(original)
    assert runtime.compiled_files(tool) == runtime.compiled_files(runtime.TLS_CERTIFICATE)
    assert native.FIXED_ARGV[tool] == native.fixed.FIXED_ARGV[TOOL_VERSIONS[tool]]
    assert runtime.execution_environment(tool) == dict(native.fixed.ENVIRONMENT)
    with pytest.raises(ValueError): native.validate_manifest(original)
    with pytest.raises(ValueError): native.fixed.validate_manifest(selected)


@pytest.mark.parametrize("tool", TOOL_VERSIONS)
@pytest.mark.parametrize("fault", ["profile", "tool", "key", "ca", "extra", "size", "interpreter", "duplicate"])
def test_runtime_manifest_rejects_unreviewed_bytes_paths_and_profile_substitution(tool, fault):
    value = manifest(tool)
    if fault == "profile": value["profile"] = runtime.PROFILE
    elif fault == "tool": value["tool_id"] = runtime.TLS_CERTIFICATE
    elif fault == "key": value["files"][1]["destination"] = "/tool/data/fixture-key.pem"
    elif fault == "ca": value["files"][1]["sha256"] = "0" * 64
    elif fault == "extra": value["authority"] = True
    elif fault == "size": value["files"][0]["size"] = True
    elif fault == "interpreter": value["interpreter"] = "/usr/bin/python3"
    else: value["files"].append(deepcopy(value["files"][0]))
    with pytest.raises(ValueError): native.validate_manifest(value)


@pytest.mark.parametrize("tool", TOOL_VERSIONS)
def test_dedicated_client_mounts_only_pure_authority_helpers_and_fixed_sealed_files(monkeypatch, tool):
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11), private_peer_fd=999),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"), ("/usr/sbin/nft", "/usr/sbin/nft")]),
        manifest(tool), [20, 21, 22], "a" * 64, "b" * 64)
    assert argv[-3:] == ["/app/recon_cockpit/secure_agent/network_tools_tls_posture_worker.py", "a" * 64, "b" * 64]
    assert "20,21,22" in argv and "999" not in argv and argv.count("--ro-bind-data") == 3
    assert "--net=/proc/self/fd/11" in argv and "CAP_NET_ADMIN" not in argv and "--unshare-net" not in argv
    for forbidden in ("fixture.py", "material.py", "owner.py", "owned_lab_worker", "network_tools_worker.py", "/usr/sbin/nft"):
        assert not any(forbidden in item for item in argv)
    with pytest.raises(ValueError):
        runtime._command(None, None, manifest(tool), [], "a" * 64, "b" * 64, service_web=True)


def test_pure_client_package_loads_with_no_owner_or_fixture_modules(tmp_path):
    package = tmp_path / "recon_cockpit" / "secure_agent"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    source = Path(native.__file__).parent
    for name in native.CLIENT_MODULES:
        (package / (name + ".py")).write_bytes((source / (name + ".py")).read_bytes())
    raw, nonce, commitment = encoded(envelope(CASES[0]))
    code = """
import sys
sys.path.insert(0, sys.argv[1])
from recon_cockpit.secure_agent import network_tools_tls_posture_worker
from recon_cockpit.secure_agent.network_tools_tls_posture_runtime import consume_launch
consume_launch(sys.stdin.buffer.read(), sys.argv[2], sys.argv[3], now=100)
assert not any('fixture' in name or 'material' in name or 'owner' in name for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), nonce, commitment],
                            input=raw, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("allowed", ["unix", "udp", "pair", None])
def test_transport_witnesses_refuse_every_bypass_before_readiness(monkeypatch, allowed):
    closed = []
    def sock(family, kind, protocol):
        label = "unix" if family == socket.AF_UNIX else "udp"
        if label != allowed:
            raise PermissionError(errno.EPERM, "denied")
        return SimpleNamespace(close=lambda: closed.append(label))
    def pair():
        if allowed != "pair":
            raise PermissionError(errno.EPERM, "denied")
        return [SimpleNamespace(close=lambda: closed.append("pair")) for _ in range(2)]
    monkeypatch.setattr(worker.socket, "socket", sock)
    monkeypatch.setattr(worker.socket, "socketpair", pair)
    if allowed is None:
        worker.transport_witnesses()
        assert closed == []
    else:
        with pytest.raises(ValueError): worker.transport_witnesses()
        assert closed == ([allowed] if allowed != "pair" else ["pair", "pair"])


@pytest.mark.parametrize("fault", ["inherited", "listing", "denied"])
def test_private_descriptor_check_distinguishes_closed_listing_from_unreadable_live_fd(monkeypatch, fault):
    monkeypatch.setattr(worker.os, "listdir", lambda _: ["0", "1", "2", "3"])
    def fstat(fd):
        if fault == "listing": raise OSError(errno.EBADF, "closed")
        if fault == "denied": raise OSError(errno.EPERM, "denied")
        return SimpleNamespace()
    monkeypatch.setattr(worker.os, "fstat", fstat)
    if fault == "listing": worker.private_descriptors()
    else:
        with pytest.raises((ValueError, OSError)): worker.private_descriptors()


@pytest.mark.parametrize("prefix", [runtime.READY_PREFIX, native.fixed.READY_PREFIX,
                                  b"RECON_TLS_MEDIATED_READY_V1 ", native.READY_PREFIX])
def test_runner_requires_new_identity_before_reporting_extra_transport_witnesses(monkeypatch, prefix):
    value = envelope(CASES[0])
    control = ExecutionControl(130, clock=lambda: 100)
    launch = {key: item for key, item in value.items() if key != "runtime"}
    lab = SimpleNamespace(_namespace_fds=(10, 11), _check=lambda _: None,
        _verify_pins=lambda: None, _runtime=lambda _: ("stdlib", []))
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime, "_snapshot", lambda *args: [])
    monkeypatch.setattr(runtime, "_command", lambda *args: ["fixed"])
    def capture(argv, raw, seconds, limit, **kwargs):
        assert seconds == 5 and kwargs["pass_fds"] == (10, 11)
        return 1, b"", prefix + hashlib.sha256(raw).hexdigest().encode("ascii") + b"\nrejected", None
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    if prefix != native.READY_PREFIX:
        with pytest.raises(isolation.IsolationUnavailable, match="confinement"):
            runtime.run_network_tool_owned(lab=lab, launch=launch, control=control, manifest=value["runtime"])
    else:
        result = runtime.run_network_tool_owned(lab=lab, launch=launch, control=control, manifest=value["runtime"])
        assert result["status"] == "failed" and result["provenance"]["exit_code"] == 1
        assert all(result["boundary_checks"][key] is True for key in native.BOUNDARY_FIELDS)
        assert result["tool_observation"] is None  # Interpretation belongs to the confined parser.


@pytest.fixture
def worker_ready(monkeypatch):
    events, value = [], envelope(CASES[0])
    raw, nonce, commitment = encoded(value)
    request = native.consume_launch(raw, nonce, commitment, now=100)
    input_stream = io.BytesIO(raw)
    errors = io.StringIO()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(argv=["worker", nonce, commitment],
        stdin=SimpleNamespace(buffer=input_stream, close=lambda: events.append("stdin_closed")), stderr=errors))
    monkeypatch.setattr(worker.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFIFO))
    monkeypatch.setattr(native, "consume_launch", lambda *args: events.append("authority") or request)
    monkeypatch.setattr(native.fixed, "_namespaces", lambda *args: events.append("namespaces"))
    monkeypatch.setattr(native.fixed, "verify_files", lambda *args: events.append("files"))
    monkeypatch.setattr(native.fixed, "limits", lambda: events.append("limits"))
    monkeypatch.setattr(worker.worker, "drop_privileges", lambda: events.append("privileges"))
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kwargs: events.append(("filter", kwargs)))
    monkeypatch.setattr(worker.common, "_witnesses", lambda: events.append("common_witnesses"))
    monkeypatch.setattr(worker, "transport_witnesses", lambda: events.append("transport_witnesses"))
    monkeypatch.setattr(native.fixed, "close_private_descriptors", lambda: events.append("close_fds"))
    monkeypatch.setattr(worker, "private_descriptors", lambda: events.append("private_fds"))
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
    assert events[:7] == ["authority", "namespaces", "files", "limits", "privileges",
        ("filter", {"allow_threads": False}), "common_witnesses"]
    assert events[7:11] == ["transport_witnesses", "stdin_closed", "close_fds", "private_fds"]
    assert events[11:13] == [("close", 0), ("open", ("/dev/null", worker.os.O_RDONLY | worker.os.O_CLOEXEC))]
    assert events[13][0] == "landlock" and events[14][0] == "ready" and events[15][0] == "execute"
    assert not any("/app" in path or "python" in path for path in events[13][1])
    assert events[14][2].startswith(native.READY_PREFIX) and errors.getvalue() == ""


@pytest.mark.parametrize("stage", ["authority", "namespaces", "files", "limits", "privileges", "filter",
    "common_witnesses", "transport_witnesses", "close_fds", "private_fds", "landlock", "deadline"])
def test_failed_worker_stage_never_issues_readiness_or_exec(worker_ready, monkeypatch, stage):
    events, errors, _ = worker_ready
    targets = {"authority": (native, "consume_launch"), "namespaces": (native.fixed, "_namespaces"),
        "files": (native.fixed, "verify_files"), "limits": (native.fixed, "limits"),
        "privileges": (worker.worker, "drop_privileges"), "filter": (worker.common, "syscall_filter"),
        "common_witnesses": (worker.common, "_witnesses"), "transport_witnesses": (worker, "transport_witnesses"),
        "close_fds": (native.fixed, "close_private_descriptors"), "private_fds": (worker, "private_descriptors"),
        "landlock": (worker.common, "apply_landlock")}
    def refuse(*args, **kwargs):
        raise ValueError("private authority or namespace detail")
    if stage == "deadline": monkeypatch.setattr(worker.time, "monotonic", lambda: 130)
    else: monkeypatch.setattr(*targets[stage], refuse)
    assert worker.main() == 78
    assert not any(isinstance(event, tuple) and event[0] in {"ready", "execute"} for event in events)
    assert errors.getvalue() == "network_tls_posture_worker_refused\n"
