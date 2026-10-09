import hashlib
import json
import threading
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import network_tools_tls_posture_parser as parser
from recon_cockpit.secure_agent import network_tools_tls_posture_parser_runtime as runtime
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.planner_worker import BOUNDARY_NAMES
from test_network_tools_tls_posture_parser import sample


def setup(monkeypatch, *, change=None):
    captures = []
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(runtime, "_runtime_files", lambda *a, **k: ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]))
    monkeypatch.setattr(runtime, "_command", lambda bootstrap: ["fixed-parser"])
    def capture(argv, raw, seconds, maximum, **kwargs):
        captures.append((argv, raw, seconds, maximum))
        result = {"input_sha256": hashlib.sha256(raw).hexdigest(), "observation": parser.parse_input(raw)}
        reply = {"contract_version": runtime.PARSER_VERSION, "boundary_checks": {name: True for name in BOUNDARY_NAMES},
                 "status": "parsed", "result": result}
        if change: change(reply)
        return 0, json.dumps(reply).encode(), b"", None
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    return captures


@pytest.mark.parametrize("kind", ["success", "rejection", "hrr"])
def test_actual_receipts_roundtrip_with_exact_commitments(monkeypatch, kind):
    captures = setup(monkeypatch)
    tool, out, err, extra = sample(rejection=kind == "rejection", hrr=kind == "hrr")
    observed = runtime.parse_isolated_tls_posture(tool, out, err, **extra)
    assert observed == parser.parse_input(captures[0][1])
    assert captures[0][2] <= 2 and captures[0][3] == 5120


@pytest.mark.parametrize("mutation", ["input", "owner", "stdout", "stderr", "boundary", "extra", "profile", "tool", "bool", "verdict"])
def test_reply_changes_cannot_release_an_observation(monkeypatch, mutation):
    def change(reply):
        if mutation == "input": reply["result"]["input_sha256"] = "0" * 64
        if mutation in {"owner", "stdout", "stderr"}: reply["result"]["observation"][mutation + "_sha256"] = "0" * 64
        if mutation == "boundary": reply["boundary_checks"][next(iter(BOUNDARY_NAMES))] = False
        if mutation == "extra": reply["permit"] = True
        if mutation == "profile": reply["contract_version"] = "other"
        if mutation == "tool": reply["result"]["observation"]["tool_id"] = "openssl_tls10_posture_v1"
        if mutation == "bool": reply["result"]["observation"]["peer_client_hellos"] = True
        if mutation == "verdict": reply["result"]["observation"]["outcome"] = "explicit_protocol_rejection"
    setup(monkeypatch, change=change)
    tool, out, err, extra = sample()
    with pytest.raises(IsolationUnavailable): runtime.parse_isolated_tls_posture(tool, out, err, **extra)


@pytest.mark.parametrize("code,stderr,reason", [(1,b"",None), (0,b"unexpected",None), (0,b"","timeout"), (True,b"",None)])
def test_failed_noisy_or_stopped_worker_has_no_fallback(monkeypatch, code, stderr, reason):
    setup(monkeypatch)
    monkeypatch.setattr(runtime, "_capture_bounded", lambda *a,**k: (code,b"{}",stderr,reason))
    tool, out, err, extra = sample()
    with pytest.raises(IsolationUnavailable): runtime.parse_isolated_tls_posture(tool, out, err, **extra)


def test_actual_invalid_status_remains_invalid_input(monkeypatch):
    setup(monkeypatch, change=lambda reply: reply.update(status="invalid", result=None))
    tool, out, err, extra = sample()
    with pytest.raises(ValueError, match="invalid_tls_observation_input"):
        runtime.parse_isolated_tls_posture(tool, out, err, **extra)


@pytest.mark.parametrize("stopped", ["cancelled", "deadline"])
def test_cancellation_and_deadline_prevent_launch(monkeypatch, stopped):
    calls = setup(monkeypatch)
    cancelled = threading.Event()
    if stopped == "cancelled": cancelled.set()
    control = ExecutionControl(0 if stopped == "deadline" else 100, cancelled, lambda: 1)
    tool, out, err, extra = sample()
    with pytest.raises(ExecutionStopped): runtime.parse_isolated_tls_posture(tool, out, err, **extra, control=control)
    assert not calls


def test_mounts_are_closed_to_pure_parser_modules(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runtime, "_namespaces", lambda: {name: "1" for name in ("user", "net", "mnt", "pid")})
    argv = runtime._command(("/usr/lib/python3.13", [("/usr/bin/python3.13", "/usr/bin/python3"),
        ("/lib/libc.so.6", "/lib/libc.so.6")]))
    assert "--unshare-net" in argv and "--clearenv" in argv
    assert not any("owner.py" in arg or "fixture" in arg or "material" in arg for arg in argv)
    assert not any(Path(arg).name in {"openssl", "curl", "nft"} for arg in argv)
    assert any(arg.endswith("network_tools_tls_posture_parser.py") for arg in argv)


@pytest.mark.parametrize("files", [[("/bin/sh", "/usr/bin/python3")], [("/usr/bin/python3", "/usr/bin/python3"), ("/tmp/libx.so", "/lib/libx.so")],
    [("/usr/bin/python3", "/usr/bin/python3"), ("/lib/../secret.so", "/lib/secret.so")], []])
def test_runtime_mount_injection_is_refused(monkeypatch, files):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    with pytest.raises(IsolationUnavailable): runtime._command(("/usr/lib/python3.13", files))
