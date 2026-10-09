"""Opt-in real execution, restricted to the disposable namespace-owned lab."""

from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.executor_worker import digest
from recon_cockpit.secure_agent.isolation import _namespaces
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.nmap_contract import action, LIMITS
from recon_cockpit.secure_agent.nmap_runtime import run_nmap_owned
from recon_cockpit.secure_agent import nmap_runtime as runtime
from recon_cockpit.secure_agent.owned_lab import OwnedLab
from recon_cockpit.secure_agent.session_limits import SessionLimits


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned Nmap confinement")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.fixture
def owned():
    session = str(uuid4())
    limits = SessionLimits(**LIMITS)
    policy_path = Path(__file__).resolve().parents[1] / "examples/secure-agent-nmap-policy.json"
    policy = parse_policy({**json.loads(policy_path.read_text()), "require_approval": False})
    selected = parse_action(action("a", 1))
    control = ExecutionControl(time.monotonic() + 60, cancelled=threading.Event())
    lab = OwnedLab("a", session, limits)
    try:
        lab.start(control)
        inner = {"schema_version": "1", "mode": "nmap_owned", "execute": True,
                 "session_id": session, "nonce": secrets.token_hex(32), "sequence": 1,
                 "action": selected.to_dict(), "action_digest": selected.digest,
                 "policy": policy.to_dict(), "policy_digest": policy.digest,
                 "limits": asdict(limits), "limits_digest": digest(asdict(limits)),
                 "deadline": control.deadline, "output_reserved_before": 0,
                 "output_reserved_after": 16384, "host_namespaces": _namespaces()}
        launch = {"mode": "owned_nmap_lab", "launch": inner, "identity": lab.identity,
                  "namespaces": lab._lab_namespaces}
        yield lab, launch, control
    finally:
        assert lab.close()["status"] == "closed"


def test_actual_nmap_elf_uses_owned_namespace_then_networkless_xml_parser(owned):
    lab, launch, control = owned
    result = run_nmap_owned(lab=lab, launch=launch, control=control)
    assert result["status"] == "succeeded", (
        result["provenance"], base64.b64decode(result["raw_stderr_base64"]),
        base64.b64decode(result["raw_xml_base64"]))
    assert result["results"] == [{"target": "127.0.0.1", "port": 8080, "state": "open"}]
    assert result["provenance"]["exit_code"] == 0
    assert all(result["boundary_checks"].values())
    assert result["bytes_received"] <= 16384 and result["truncated"] is False
    assert lab.snapshot(control)["request_count"] == 0


def replace_final_exec(monkeypatch, tmp_path, statement):
    """Trusted test harness changes only the final post-confinement operation."""
    source = Path(runtime.__file__).with_name("nmap_worker.py")
    original = 'os.execve(runtime.FIXED_ARGV[0], runtime.FIXED_ARGV, {"LC_ALL": "C"})'
    text = source.read_text()
    assert text.count(original) == 1
    probe = tmp_path / "nmap-boundary-probe.py"
    probe.write_text(text.replace(original, statement))
    command = runtime._command

    def wrapped(*args):
        argv = command(*args)
        position = argv.index(str(source))
        argv[position] = str(probe)
        return argv
    monkeypatch.setattr(runtime, "_command", wrapped)


@pytest.mark.parametrize("statement", [
    'os.execve("/usr/bin/python3", ("/usr/bin/python3", "-c", "print(987654321)"), {"LC_ALL":"C"})',
    'os.execve(manifest["interpreter"], (manifest["interpreter"], "/usr/bin/python3", "-c", "print(987654321)"), {"LC_ALL":"C"})',
])
def test_sealed_tool_cannot_exec_python_directly_or_through_loader(owned, monkeypatch, tmp_path, statement):
    lab, launch, control = owned
    replace_final_exec(monkeypatch, tmp_path, statement)
    result = run_nmap_owned(lab=lab, launch=launch, control=control)
    assert result["status"] == "failed" and result["results"] == []
    assert b"987654321" not in base64.b64decode(result["raw_xml_base64"])
    assert result["provenance"]["exit_code"] != 0
    assert lab.snapshot(control)["request_count"] == 0


@pytest.mark.parametrize("statement,status", [
    ('time.sleep(15)', "timeout"),
    ('[os.write(1, b"x" * 4096) for _ in range(100)]', "output_limit"),
])
def test_scanner_output_and_wall_time_are_supervised(owned, monkeypatch, tmp_path, statement, status):
    lab, launch, control = owned
    replace_final_exec(monkeypatch, tmp_path, statement)
    result = run_nmap_owned(lab=lab, launch=launch, control=control)
    assert result["status"] == status and result["results"] == []
    assert result["bytes_received"] <= 16384
    assert result["truncated"] == (status == "output_limit")


def test_cancelled_scanner_is_killed_and_reaped(owned, monkeypatch, tmp_path):
    from recon_cockpit.secure_agent.execution import ExecutionStopped
    lab, launch, control = owned
    replace_final_exec(monkeypatch, tmp_path, 'time.sleep(15)')
    children = []
    popen = subprocess.Popen

    def record(*args, **kwargs):
        process = popen(*args, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(subprocess, "Popen", record)
    timer = threading.Timer(1, control.cancelled.set)
    timer.start()
    try:
        with pytest.raises(ExecutionStopped, match="session_cancelled"):
            run_nmap_owned(lab=lab, launch=launch, control=control)
        assert children and all(process.poll() is not None for process in children)
    finally:
        timer.cancel()


def test_isolated_parser_rejects_external_entities_without_network_or_host_files(owned):
    lab, _, control = owned
    bootstrap = lab._runtime(control)
    xml = b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd"><nmaprun scanner="nmap"/>'
    with pytest.raises(ValueError, match="parser_refused"):
        runtime._parse_isolated(xml, control, bootstrap)
