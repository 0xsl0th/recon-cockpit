"""Real network-tool authority gates and the enforced native thread ceiling."""

from contextlib import contextmanager
import json
import os
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_contract import BACKEND, LIMITS, action
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from recon_cockpit.secure_agent.network_tools_runtime import inspect_tool_runtime
from test_secure_approval_linux import scripted_review, terminal
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import instrument
from test_secure_network_tools_runtime import policy as required_policy


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned network-tool gates")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


@contextmanager
def boundary(tmp_path, control, *, case="dig-ok", approval_required=True):
    value = required_policy().to_dict()
    value["require_approval"] = approval_required
    policy, session = parse_policy(value), str(uuid4())
    limits = SessionLimits(**LIMITS)
    lab = NetworkToolsLab(case, session, limits)
    backend = AuthorizedNetworkToolsBackend(policy, session, limits, lab, execute=True)
    backend._network_tools_manifest = inspect_tool_runtime(action(case)["tool_id"], control)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session


@pytest.mark.parametrize("case,requests", [("dig-ok", 1), ("openssl-ok", 1), ("ssh-ok", 1), ("ldap-ok", 1), ("smb-ok", 1), ("rpc-ok", 1), ("nfs-ok", 1), ("ftp-ok", 1), ("smtp-ok", 1),
    ("docker-ping-ok", 1), ("docker-version-ok", 1), ("winrm-ok", 1), ("nmap-service-http", 1), ("kerberos-ok", 2)])
def test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, case, requests):
    control = ExecutionControl(time.monotonic() + 40)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        reference, prompt = scripted_review(approvals, selected, policy, terminal, control)
        assert reference is not None and selected.digest.encode() in prompt
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        result = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert result["execution_status"] == "succeeded", result
        assert result["untrusted_result"]["owned_lab"]["request_count"] == requests
        assert result["untrusted_result"]["tool_observation"] is not None
        replay = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert replay["execution_status"] == "blocked" and replay["reasons"] == ["approval_unknown_or_replayed"]
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(row["event_type"] == "approval_consumed" for row in events) == 1


@pytest.mark.parametrize("case", ["dig-ok", "openssl-ok", "ssh-ok", "ldap-ok", "smb-ok", "rpc-ok", "nfs-ok", "ftp-ok", "smtp-ok",
    "docker-ping-ok", "docker-version-ok", "winrm-ok", "nmap-service-http", "kerberos-ok"])
def test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, case):
    instrument(tmp_path, monkeypatch, lambda source: source.replace("granted = gate.admit(",
        "os.write(2, b'UNEXPECTED-NETWORK-TOOLS-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        event = intent(selected, policy, session, backend=BACKEND)
        event["approval_reference"] = "a" * 48
        audit.emit(event)
        with pytest.raises((IsolationUnavailable, ExecutionStopped)):
            launcher.run(selected, policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert b"UNEXPECTED-NETWORK-TOOLS-ADMISSION" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0


def test_absent_kernel_thread_ceiling_is_refused_before_dig_exec(tmp_path, monkeypatch):
    # Widen the actual kernel limit while retaining the production witness.
    # A seventeenth task (including the private supervisor and worker) exceeds
    # the advertised total; its creation must cause refusal before dig exec.
    def widen(source):
        assert "threads = 16 if tool_id == runtime.DIG else 1" in source
        return source.replace("threads = 16 if tool_id == runtime.DIG else 1",
                              "threads = 32 if tool_id == runtime.DIG else 1")
    instrument(tmp_path, monkeypatch, widen, name="network_tools_worker")
    control = ExecutionControl(time.monotonic() + 30)
    with boundary(tmp_path, control, case="dig-ok", approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("dig-ok"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked", result
        assert launcher._closed and launcher._process.poll() is not None
        assert launcher.close()["request_count"] == 0


@pytest.mark.parametrize("tag", ["launch-preconditions", "http-headers-launch-preconditions", "web-tools-launch-preconditions"])
def test_existing_bootstrap_tags_cannot_relabel_new_profile(tmp_path, monkeypatch, tag):
    original = LinuxFixtureLauncher._command
    def changed(self, *args):
        argv = original(self, *args)
        assert argv[-1] == "network-tools-launch-preconditions"
        argv[-1] = tag
        return argv
    monkeypatch.setattr(LinuxFixtureLauncher, "_command", changed)
    control = ExecutionControl(time.monotonic() + 20)
    with boundary(tmp_path, control, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action("dig-ok"), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked"
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["request_count"] == 0


def test_rpc_snapshot_seals_both_compiled_databases_without_reading_host_config(monkeypatch):
    import os
    assert hasattr(os, "memfd_create")
    import fcntl
    from recon_cockpit.secure_agent import tool_runtime_common as common
    from recon_cockpit.secure_agent import network_tools_runtime as runtime
    from test_secure_network_tools_runtime import manifest
    inspected = []
    def read(path):
        assert not path.startswith(("compiled:", "/etc/"))
        inspected.append(path)
        return b"data"
    monkeypatch.setattr(common, "_read_regular", read)
    selected = manifest(runtime.RPCINFO)
    descriptors = runtime._snapshot(selected, ExecutionControl(time.monotonic() + 5))
    compiled = {source: raw for source, _, raw in runtime.compiled_files(runtime.RPCINFO)}
    try:
        assert len(descriptors) == 4
        for row, descriptor in zip(selected["files"], descriptors):
            assert os.read(descriptor, row["size"] + 1) == compiled.get(row["source"], b"data")
            seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
            assert seals & (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL) == 15
        assert len(inspected) == 2
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
