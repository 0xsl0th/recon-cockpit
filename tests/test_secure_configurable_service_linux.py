"""Shared-service execution uses the same disconnected native authority path.

The fixture-only unattended policy permits automated validation; it never
represents an operator's approval. No model or external network is involved.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.configurable_backend import AuthorizedConfigurableBackend
from recon_cockpit.secure_agent.configurable_contract import ENDPOINTS, TOOL_IDS, action, policy_for_scope
from recon_cockpit.secure_agent.configurable_evidence import inspect_assessment
from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab
from recon_cockpit.secure_agent.configurable_runtime import BOUNDARY_NAMES, underlying_tool
from recon_cockpit.secure_agent.configurable_scope import load_scope, scope_digest
from recon_cockpit.secure_agent.configurable_service import (
    ConfigurableAssessmentRequest, ConfigurableAssessmentService,
)
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from test_secure_configurable_linux import SCOPES, events, snapshot
from test_secure_fixture_launcher_linux import descendants
from test_secure_owned_launcher_linux import assert_reaped

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for shared-service native execution")
    assert sys.platform == "linux" and os.geteuid() != 0
    # These host objects must never execute a tool or start an endpoint. The
    # confined launcher imports separate reviewed copies of their modules.
    monkeypatch.setattr(ConfigurableEndpointLab, "start", lambda *_: pytest.fail("host endpoint owner started"))
    monkeypatch.setattr(AuthorizedConfigurableBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


def configured_service(tmp_path, *, require_approval=False):
    raw = SCOPES[1].read_bytes()
    scope = load_scope(raw)
    policy = policy_for_scope(scope, require_approval=require_approval).to_dict()
    if not require_approval:
        policy["policy_version"] = "synthetic-shared-service-unattended-test-v1"
    request = ConfigurableAssessmentRequest(scope_json=raw,
        policy_json=json.dumps(policy).encode("ascii"), assessment_dir=tmp_path / "evidence",
        audit_path=tmp_path / "audit.jsonl", execute=True)
    return ConfigurableAssessmentService(request), scope


def retain_launchers(monkeypatch):
    launchers = []
    original = LinuxFixtureLauncher.__init__

    def observed(self, *args, **kwargs):
        original(self, *args, **kwargs)
        launchers.append(self)

    monkeypatch.setattr(LinuxFixtureLauncher, "__init__", observed)
    return launchers


def test_service_completes_native_work_from_background_thread_without_terminal_or_signals(
        tmp_path, monkeypatch, capsys, record_property):
    service, scope = configured_service(tmp_path)
    launchers = retain_launchers(monkeypatch)
    callbacks, callback_threads, observed = [], [], set()
    handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def completed(step):
        callbacks.append(step)
        callback_threads.append(threading.get_ident())
        for launcher in launchers:
            process = getattr(launcher, "_process", None)
            if process is not None:
                observed.add(process.pid)
                observed.update(descendants(process.pid))

    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(service.run, interactive_terminal=False, on_step=completed).result(timeout=60)
    assert capsys.readouterr() == ("", "")
    assert handlers == {number: signal.getsignal(number) for number in handlers}
    assert len(callbacks) == 4 and set(callback_threads).isdisjoint({threading.get_ident()})
    assert [row["execution_status"] for row in callbacks] == ["succeeded"] * 4
    assert result["assessment_outcome"] == "completed"
    assert result["actions_succeeded"] == result["steps_attempted"] == 4
    assert result["scope_sha256"] == scope_digest(scope) and result["live_calls_enabled"] is False
    assert result["output_reserved_bytes"] == 26624
    metrics = result["metrics"]
    assert metrics["legitimate_task_completed"] is True and metrics["useful_actions_completed"] == 4
    assert metrics["unnecessary_refusals"] == 0
    assert metrics["actual_provider_calls"] == metrics["actual_cost_microusd"] == 0
    assert metrics["comparison_baseline"] is None and 0 <= metrics["elapsed_ms"] < 60000
    assert result["coordinator_boundary_checks"] and all(result["coordinator_boundary_checks"].values())
    current = service.snapshot()
    assert current["result"] == result and current["session_id"] == result["session_id"]
    assert current["scope"] == scope and current["steps"] == callbacks
    record_property("useful_actions_completed", 4)
    record_property("forbidden_listening_destinations_blocked", 12)
    record_property("execution_elapsed_ms", metrics["elapsed_ms"])
    record_property("actual_provider_calls", 0)
    record_property("actual_cost_microusd", 0)

    evidence = tmp_path / "evidence"
    report = json.loads((evidence / "report.json").read_text())
    manifest = json.loads((evidence / "manifest.json").read_text())
    assert report["outcome"] == "completed" and report["integrity_issues"] == []
    assert report["metrics"] == metrics and len(report["records"]) == 4
    for step, row in enumerate(report["records"], 1):
        expected = scope[ENDPOINTS[step - 1]]
        assert row["action"] == action(scope, step) and row["status"] == "succeeded"
        artifact = json.loads((evidence / row["artifact"]["filename"]).read_text())
        assert artifact["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
        assert all(flag is True for flag in artifact["boundary_checks"].values())
        details = artifact["tool_observation"]
        assert details["target"] == expected["target"] and details["port"] == expected["port"]
        if step == 2:
            assert details["path"] == expected["path"] and details["headers"]["status_code"] == 200
            assert base64.b64decode(artifact["results"][0]["raw_response"], validate=True).startswith(b"HTTP/1.1 200 ")
        else:
            provenance = artifact["provenance"]
            assert provenance["runtime_sha256"] == manifest["runtime_bindings"][TOOL_IDS[step - 1]]
            assert provenance["runtime_manifest"]["tool_id"] == underlying_tool(TOOL_IDS[step - 1])
            raw = base64.b64decode(artifact["raw_output_base64"], validate=True)
            if step in (1, 3):
                assert ('addr="' + expected["target"] + '"').encode() in raw
                assert ('portid="' + str(expected["port"]) + '"').encode() in raw
            else:
                assert ("[" + expected["target"] + "]:" + str(expected["port"])
                        + " ssh-rsa " + details["key_base64"]).encode() in raw.splitlines()
                assert details["trust"] == "unverified"
    for name, endpoint in report["lab_closure"]["endpoints"].items():
        assert endpoint["status"] == "closed" and endpoint["request_count"] == 2
        assert 3 <= endpoint["connection_count"] <= (4 if name == "http" else 3)
    assert launchers and all(item._closed and item._process.poll() is not None for item in launchers)
    assert_reaped(observed)
    audit = events(tmp_path / "audit.jsonl")
    assert sum(row["event_type"] == "execution_started" for row in audit) == 4
    assert not any(row["event_type"] == "approval_consumed" for row in audit)
    before = snapshot(evidence)
    assert inspect_assessment(evidence) == report and snapshot(evidence) == before


def test_service_cannot_turn_noninteractive_execution_into_operator_approval(tmp_path, monkeypatch):
    service, _ = configured_service(tmp_path, require_approval=True)
    monkeypatch.setattr(LinuxFixtureLauncher, "_start", lambda *a, **k: pytest.fail("unapproved launcher started"))
    monkeypatch.setattr(LinuxApprovalService, "_start", lambda *a, **k: pytest.fail("unattended approval service started"))
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(service.run, interactive_terminal=False).result(timeout=60)
    assert result["actions_succeeded"] == 0 and result["assessment_outcome"] != "completed"
    assert result["metrics"]["legitimate_task_completed"] is False
    assert result["metrics"]["actual_provider_calls"] == result["metrics"]["actual_cost_microusd"] == 0
    audit = events(tmp_path / "audit.jsonl")
    rejected = [row for row in audit if row["event_type"] == "approval_rejected"]
    assert rejected and rejected[0]["reasons"] == ["noninteractive_approval_required"]
    assert not any(row["event_type"] in {"approval_consumed", "execution_started"} for row in audit)
    evidence = tmp_path / "evidence"
    report = json.loads((evidence / "report.json").read_text())
    assert report["records"] == [] and report["lab_closure"]["status"] == "closed"
    for endpoint in report["lab_closure"]["endpoints"].values():
        assert endpoint["connection_count"] == endpoint["request_count"] == 0
    before = snapshot(evidence)
    assert inspect_assessment(evidence) == report and snapshot(evidence) == before


def test_service_cancel_after_native_start_reaps_owned_lab_and_persists_incomplete_evidence(
        tmp_path, monkeypatch):
    service, _ = configured_service(tmp_path)
    launchers = retain_launchers(monkeypatch)
    observed = set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(service.run, interactive_terminal=False)
        try:
            seen = False
            expiry = time.monotonic() + 20
            while time.monotonic() < expiry and not pending.done():
                for launcher in tuple(launchers):
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
            service.cancel()
            result = pending.result(timeout=8)
        finally:
            service.cancel()
    assert result["stop_reason"] == "session_cancelled" and result["actions_succeeded"] == 0
    assert result["metrics"]["legitimate_task_completed"] is False
    assert result["metrics"]["actual_provider_calls"] == result["metrics"]["actual_cost_microusd"] == 0
    assert service.snapshot()["result"] == result
    assert launchers and all(item._closed and item._process.poll() is not None for item in launchers)
    assert_reaped(observed)
    evidence = tmp_path / "evidence"
    report = json.loads((evidence / "report.json").read_text())
    assert report["outcome"] != "completed" and report["integrity_issues"] == []
    assert len(report["records"]) == 1 and report["records"][0]["status"] == "cancelled"
    assert report["lab_closure"]["status"] == "closed"
    for endpoint in report["lab_closure"]["endpoints"].values():
        assert endpoint["connection_count"] == endpoint["request_count"] == 0
    audit = events(tmp_path / "audit.jsonl")
    assert sum(row["event_type"] == "execution_started" for row in audit) == 1
    finished = [row for row in audit if row["event_type"] == "execution_finished"]
    assert len(finished) == 1 and finished[0]["execution_status"] == "cancelled"
    before = snapshot(evidence)
    assert inspect_assessment(evidence) == report and snapshot(evidence) == before


def test_service_observer_failure_after_native_success_stops_and_reaps_before_next_action(
        tmp_path, monkeypatch):
    service, scope = configured_service(tmp_path)
    launchers = retain_launchers(monkeypatch)
    observed, callbacks = set(), []
    observer_error = RuntimeError("native observer unavailable")

    def unavailable(step):
        callbacks.append(step)
        assert step["execution_status"] == "succeeded"
        for launcher in launchers:
            process = getattr(launcher, "_process", None)
            if process is not None:
                observed.add(process.pid)
                observed.update(descendants(process.pid))
        raise observer_error

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(service.run, interactive_terminal=False, on_step=unavailable)
        with pytest.raises(RuntimeError, match="^native observer unavailable$") as failure:
            pending.result(timeout=60)
    assert failure.value is observer_error and len(callbacks) == 1
    current = service.snapshot()
    assert current["state"] == "failed" and current["stop_reason"] == "assessment_failed"
    assert current["steps"] == callbacks and current["result"] is None
    assert launchers and all(item._closed and item._process.poll() is not None for item in launchers)
    for launcher in launchers:
        closure = launcher.close()
        assert closure["status"] == "closed"
        assert closure["endpoints"]["http"]["request_count"] == 1
        assert 2 <= closure["endpoints"]["http"]["connection_count"] <= 3
        assert closure["endpoints"]["ssh"]["request_count"] == 0
        assert closure["endpoints"]["ssh"]["connection_count"] == 0
    assert_reaped(observed)
    audit_path, evidence = tmp_path / "audit.jsonl", tmp_path / "evidence"
    audit = events(audit_path)
    assert sum(row["event_type"] == "execution_started" for row in audit) == 1
    finished = [row for row in audit if row["event_type"] == "execution_finished"]
    assert len(finished) == 1 and finished[0]["execution_status"] == "succeeded"
    assert not any(row["event_type"] == "approval_consumed" for row in audit)

    # Preserve the real first result, but never fabricate a final report after a
    # failed application observer. Inspection must identify unfinished evidence.
    journal = events(evidence / "evidence.jsonl")
    saved = [row["record"] for row in journal if row["event_type"] == "configurable_execution_finished"]
    assert len(saved) == 1 and saved[0]["status"] == "succeeded"
    assert saved[0]["action"] == action(scope, 1)
    artifact = json.loads((evidence / saved[0]["artifact"]["filename"]).read_text())
    assert artifact["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
    assert artifact["tool_observation"]["service"]["name"] == "http"
    raw = base64.b64decode(artifact["raw_output_base64"], validate=True)
    assert ('addr="' + scope["http"]["target"] + '"').encode() in raw
    assert ('portid="' + str(scope["http"]["port"]) + '"').encode() in raw
    assert not any(row["event_type"] == "configurable_finished" for row in journal)
    assert not (evidence / "report.json").exists() and not (evidence / "report.md").exists()
    before, audit_before = snapshot(evidence), audit_path.read_bytes()
    inspected = inspect_assessment(evidence)
    assert inspected["outcome"] == "incomplete" and inspected["integrity_issues"]
    assert snapshot(evidence) == before
    with pytest.raises(RuntimeError, match="^assessment_already_used$"):
        service.run()
    assert snapshot(evidence) == before and audit_path.read_bytes() == audit_before
    assert service.snapshot() == current
