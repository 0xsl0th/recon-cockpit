"""Owned HTTP/SSH CLI execution, scope enforcement, replay and cancellation.

Unattended test policies do not represent human approval. All native work stays
inside the production isolated authority path and disconnected fixture owners.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.configurable_backend import AuthorizedConfigurableBackend
from recon_cockpit.secure_agent.configurable_contract import (BACKEND, ENDPOINTS, LIMITS, TOOL_IDS,
    action, policy_for_scope)
from recon_cockpit.secure_agent.configurable_evidence import inspect_assessment
from recon_cockpit.secure_agent.configurable_lab import ConfigurableLab, ConfigurableEndpointLab
from recon_cockpit.secure_agent.configurable_runtime import BOUNDARY_NAMES, inspect_configurable_runtime, underlying_tool
from recon_cockpit.secure_agent.configurable_scope import load_scope, scope_digest
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_fixture_launcher_linux import descendants
from test_secure_nmap_cli import GATES
from test_secure_owned_launcher_linux import assert_reaped

pytestmark = pytest.mark.integration
SCOPES = (Path("examples/secure-agent-configurable-scope.json"),
          Path("examples/secure-agent-configurable-scope-alternate.json"))


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned configurable HTTP/SSH execution")
    assert sys.platform == "linux" and os.geteuid() != 0
    # The confined processes import their own immutable module copies; a host
    # fallback reaches these traps and cannot accidentally make a trial pass.
    monkeypatch.setattr(ConfigurableEndpointLab, "start", lambda *_: pytest.fail("host endpoint owner started"))
    monkeypatch.setattr(AuthorizedConfigurableBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def snapshot(path):
    return {item.name: (item.read_bytes(), item.stat().st_mtime_ns, item.stat().st_mode)
            for item in path.iterdir()}


@pytest.mark.parametrize("scope_path", SCOPES, ids=("primary", "alternate"))
def test_complete_native_http_and_ssh_preserve_scope_and_replay_readonly(
        tmp_path, capsys, record_property, scope_path):
    scope = load_scope(scope_path.read_bytes())
    policy = policy_for_scope(scope, require_approval=False).to_dict()
    policy["policy_version"] = "synthetic-configurable-unattended-test-v1"
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    started = time.monotonic()
    code = cli.main(["--configurable-assessment", str(scope_path), "--assessment-dir", str(evidence),
        "--audit", str(audit), "--policy", str(policy_path), *GATES, "--execute"])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert code == 0, (summary, captured.err)
    assert summary["assessment_outcome"] == "completed"
    assert summary["actions_succeeded"] == summary["steps_attempted"] == 4
    assert summary["output_reserved_bytes"] == 26624 and summary["live_calls_enabled"] is False
    metrics = summary["metrics"]
    assert metrics["legitimate_task_completed"] is True and metrics["useful_actions_completed"] == 4
    assert metrics["actual_provider_calls"] == metrics["actual_cost_microusd"] == 0
    assert metrics["comparison_baseline"] is None
    assert 0 <= metrics["elapsed_ms"] < 60000 and time.monotonic() - started < 60
    assert summary["scope_sha256"] == scope_digest(scope)
    assert summary["coordinator_boundary_checks"] and all(summary["coordinator_boundary_checks"].values())
    record_property("legitimate_task_completed", True)
    record_property("useful_actions_completed", 4)
    record_property("forbidden_listening_destinations_blocked", 12)
    record_property("execution_elapsed_ms", metrics["elapsed_ms"])
    record_property("actual_provider_calls", 0)
    record_property("actual_cost_microusd", 0)
    report = json.loads((evidence / "report.json").read_text())
    manifest = json.loads((evidence / "manifest.json").read_text())
    assert report["integrity_issues"] == [] and report["outcome"] == "completed"
    assert report["scope"] == scope and report["metrics"] == metrics
    closure = report["lab_closure"]
    assert closure["status"] == "closed"
    for name, maximum in (("http", 4), ("ssh", 3)):
        endpoint = closure["endpoints"][name]
        assert endpoint["status"] == "closed" and endpoint["request_count"] == 2
        assert 3 <= endpoint["connection_count"] <= maximum
        assert endpoint["identity"]["target"] == scope[name]["target"]
        assert endpoint["identity"]["port"] == scope[name]["port"]
    assert len(report["records"]) == 4
    for step, row in enumerate(report["records"], 1):
        endpoint_id = ENDPOINTS[step - 1]
        expected = scope[endpoint_id]
        assert row["action"] == action(scope, step) and row["status"] == "succeeded"
        artifact = json.loads((evidence / row["artifact"]["filename"]).read_text())
        assert artifact["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
        assert all(flag is True for flag in artifact["boundary_checks"].values())
        assert artifact["backend"] == BACKEND and artifact["scope_sha256"] == scope_digest(scope)
        assert artifact["scope_step"] == step and artifact["truncated"] is False
        assert artifact["bytes_received"] <= (2048 if step == 2 else 8192)
        assert artifact["owned_lab"]["identity"] == closure["identity"]
        details = artifact["tool_observation"]
        assert details["target"] == expected["target"] and details["port"] == expected["port"]
        if step == 2:
            assert details["path"] == expected["path"]
            assert details["headers"]["status_code"] == 200
            assert base64.b64decode(artifact["results"][0]["raw_response"], validate=True).startswith(b"HTTP/1.1 200 ")
        else:
            provenance = artifact["provenance"]
            assert provenance["runtime_sha256"] == manifest["runtime_bindings"][TOOL_IDS[step - 1]]
            assert provenance["runtime_manifest"]["tool_id"] == underlying_tool(TOOL_IDS[step - 1])
            assert provenance["exit_code"] == 0 and provenance["stop_reason"] is None
            raw = base64.b64decode(artifact["raw_output_base64"], validate=True)
            if step in (1, 3):
                assert details["service"]["name"] == endpoint_id
                assert ('addr="' + expected["target"] + '"').encode() in raw
                assert ('portid="' + str(expected["port"]) + '"').encode() in raw
            else:
                lines = raw.splitlines()
                if len(lines) == 2:
                    assert lines.pop(0) == ("# " + expected["target"] + ":" + str(expected["port"])
                                           + " SSH-2.0-OpenSSH_9.7").encode()
                assert len(lines) == 1
                assert lines[0] == ("[" + expected["target"] + "]:" + str(expected["port"])
                                    + " ssh-rsa " + details["key_base64"]).encode()
                assert details["trust"] == "unverified" and details["key_bits"] == 2048
    audit_events = events(audit)
    assert sum(item["event_type"] == "execution_started" for item in audit_events) == 4
    assert not any(item["event_type"] == "approval_consumed" for item in audit_events)
    before = snapshot(evidence)
    replay = inspect_assessment(evidence)
    assert replay == report and before == snapshot(evidence)


def test_required_noninteractive_approval_stops_before_any_owner_or_launcher(tmp_path, monkeypatch, capsys):
    scope = load_scope(SCOPES[0].read_bytes())
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_for_scope(scope).to_dict()))
    monkeypatch.setattr(LinuxFixtureLauncher, "_start", lambda *a, **k: pytest.fail("unapproved launcher started"))
    monkeypatch.setattr(LinuxApprovalService, "_start", lambda *a, **k: pytest.fail("unattended approval service started"))
    monkeypatch.setattr(cli, "_isolated_human_approval", lambda *a, **k: pytest.fail("human approval was synthesized"))
    evidence, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    code = cli.main(["--configurable-assessment", str(SCOPES[0]), "--assessment-dir", str(evidence),
        "--audit", str(audit), "--policy", str(policy_path), *GATES, "--execute"])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert code == 2, (summary, captured.err)
    assert summary["actions_succeeded"] == 0 and summary["metrics"]["legitimate_task_completed"] is False
    assert summary["metrics"]["actual_provider_calls"] == summary["metrics"]["actual_cost_microusd"] == 0
    audit_events = events(audit)
    denied = [item for item in audit_events if item["event_type"] == "approval_rejected"]
    assert denied and denied[0]["reasons"] == ["noninteractive_approval_required"]
    assert not any(item["event_type"] in {"approval_consumed", "execution_started"} for item in audit_events)
    report = json.loads((evidence / "report.json").read_text())
    assert report["records"] == [] and report["lab_closure"]["status"] == "closed"
    for endpoint in report["lab_closure"]["endpoints"].values():
        assert endpoint["status"] == "closed" and endpoint["connection_count"] == endpoint["request_count"] == 0


@contextmanager
def boundary(tmp_path, control):
    scope = load_scope(SCOPES[1].read_bytes())
    policy = policy_for_scope(scope, require_approval=False)
    session, limits = str(uuid4()), SessionLimits(**LIMITS)
    backend = AuthorizedConfigurableBackend(policy, session, limits, ConfigurableLab(scope, session, limits), execute=True)
    backend._configurable_manifests = inspect_configurable_runtime(control)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield scope, policy, session, audit, approvals, launcher


def test_cancellation_after_native_start_reaps_endpoint_and_executor(tmp_path):
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic() + 40, cancelled)
    observed = set()
    with boundary(tmp_path, control) as (scope, policy, session, audit, approvals, launcher):
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(controller.submit, action(scope, 1), execute=True, interactive=False,
                                  execution_control=control)
            try:
                seen = False
                expiry = min(control.deadline, time.monotonic() + 20)
                while time.monotonic() < expiry and not pending.done():
                    process = getattr(launcher, "_process", None)
                    if process is not None:
                        observed.add(process.pid)
                        observed.update(descendants(process.pid))
                    for pid in tuple(observed):
                        try:
                            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0", 1)[0]
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        seen |= command == b"/tool/nmap"
                    if seen:
                        break
                    time.sleep(0.005)
                assert seen and not pending.done(), "actual confined Nmap did not reach its run"
                cancelled.set()
                result = pending.result(timeout=8)
            finally:
                cancelled.set()
            assert result["execution_status"] == "cancelled", result
            assert launcher._closed and launcher._process.poll() is not None
            closure = launcher.close()
            assert closure["status"] == "closed"
            assert all(endpoint["status"] == "closed" for endpoint in closure["endpoints"].values())
            # No result was acknowledged; never invent final probe counters.
            assert all(endpoint["connection_count"] == endpoint["request_count"] == 0
                       for endpoint in closure["endpoints"].values())
        assert_reaped(observed)
    audit_events = events(tmp_path / "audit.jsonl")
    assert sum(item["event_type"] == "execution_started" for item in audit_events) == 1
    finished = [item for item in audit_events if item["event_type"] == "execution_finished"]
    assert len(finished) == 1 and finished[0]["execution_status"] == "cancelled"
