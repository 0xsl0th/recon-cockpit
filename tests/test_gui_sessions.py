"""Desktop lifecycle with real shared-service code and portable isolation doubles.

These checks establish controller custody, not Linux isolation or human approval.
Owned-execution cases deny through portable doubles and never run a tool.
"""

import json
import os
from pathlib import Path
import threading
import time

import pytest

from recon_cockpit.gui import controller as desktop
from recon_cockpit.gui.presentation import present_session, scope_fields
from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent import configurable_service as application
from recon_cockpit.secure_agent.configurable_evidence import inspect_assessment
from recon_cockpit.secure_agent.models import parse_policy
from test_secure_http_headers_cli import portable_services


@pytest.fixture(autouse=True)
def supported_platform(monkeypatch):
    # Platform selection only. All kernel work in this file uses portable_services.
    monkeypatch.setattr(desktop.sys, "platform", "linux")


def settle(controller):
    expiry = time.monotonic() + 5
    while time.monotonic() < expiry:
        controller.poll()
        if not controller.snapshot()["busy"]:
            return controller.snapshot()
        time.sleep(0.002)
    raise AssertionError("desktop operation did not finish")


def files(directory):
    return {path.relative_to(directory): (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
            for path in directory.rglob("*") if path.is_file()}


def guard_execution(monkeypatch):
    from recon_cockpit.secure_agent import configurable_runtime
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.configurable_backend import AuthorizedConfigurableBackend
    from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab
    def forbidden(*args, **kwargs):
        pytest.fail("desktop dry run attempted execution or approval input")
    monkeypatch.setattr(configurable_runtime, "inspect_configurable_runtime", forbidden)
    monkeypatch.setattr(ConfigurableEndpointLab, "start", forbidden)
    monkeypatch.setattr(AuthorizedConfigurableBackend, "run", forbidden)
    monkeypatch.setattr(LinuxApprovalService, "review", forbidden)
    monkeypatch.setattr(LinuxApprovalService, "consume", forbidden)


@pytest.fixture
def portable_owned_review(monkeypatch, portable_services):
    """Keep the actual service flow, but deny without native runtime or input."""
    from recon_cockpit.secure_agent import configurable_runtime
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab

    captured = {"requests": [], "run_calls": [], "reviews": []}
    original_service = desktop.ConfigurableAssessmentService
    original_run = application.ConfigurableAssessmentService.run

    def service(request):
        captured["requests"].append(request)
        return original_service(request)

    def run(self, **kwargs):
        captured["run_calls"].append(kwargs)
        return original_run(self, **kwargs)

    def review(self, action, policy, *, control):
        control.check()
        captured["reviews"].append((self._frontend, action.to_dict(), policy.require_approval))
        return None

    monkeypatch.setattr(desktop, "ConfigurableAssessmentService", service)
    monkeypatch.setattr(application.ConfigurableAssessmentService, "run", run)
    monkeypatch.setattr(configurable_runtime, "inspect_configurable_runtime",
                        lambda *_: {contract.NMAP: {"portable": True}, contract.SSH: {"portable": True}})
    monkeypatch.setattr(LinuxApprovalService, "review", review)
    monkeypatch.setattr(ConfigurableEndpointLab, "start",
                        lambda *_: pytest.fail("denied desktop request started fixture"))
    captured["audit"] = portable_services
    return captured


def test_real_service_dry_run_is_private_fresh_and_never_claims_useful_work(
        tmp_path, monkeypatch, portable_services):
    guard_execution(monkeypatch)
    captured = []
    original = desktop.ConfigurableAssessmentService
    def service(request):
        captured.append(request)
        return original(request)
    monkeypatch.setattr(desktop, "ConfigurableAssessmentService", service)
    controller = desktop.DesktopController()
    assert not list(tmp_path.iterdir())
    controller.start_dry_run(tmp_path)
    current = settle(controller)
    request = captured[0]
    assert request.execute is False and parse_policy(request.policy_json).require_approval is True
    assert request.limits.max_steps == 4 and request.limits.max_runtime_seconds == 60
    assert request.limits.max_output_bytes == 26624
    assert current["session"]["phase"] == "finished" and current["session"]["mode"] == "dry_run"
    assert current["operation"] is None and current["error"] is None
    assert current["report"]["outcome"] == "dry_run" and current["report"]["integrity_issues"] == []
    session_dir = Path(current["session"]["session_dir"])
    assert session_dir.parent == tmp_path and session_dir.stat().st_mode & 0o777 == 0o700
    assert request.assessment_dir == session_dir / "evidence"
    assert request.audit_path == session_dir / "audit.jsonl"
    report = inspect_assessment(request.assessment_dir)
    assert report["records"] == []
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["metrics"]["useful_actions_completed"] == 0
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert len(current["session"]["steps"]) == 1  # no simulated successors
    step = current["session"]["steps"][0]
    assert step["tool"] == "Nmap service ID" and step["target"] == "10.77.0.10:8080"
    assert "not a pending human prompt" in step["detail"]
    assert not any(event["event_type"] in {"execution_started", "approval_consumed"} for event in portable_services)
    before = files(session_dir)
    original_id = current["session"]["session_id"]
    current["session"]["scope"]["http"]["target"] = "8.8.8.8"
    assert controller.snapshot()["session"]["scope"]["http"]["target"] == "10.77.0.10"
    controller.start_dry_run(tmp_path)
    next_run = settle(controller)
    assert next_run["session"]["session_id"] != original_id
    assert next_run["session"]["session_dir"] != str(session_dir)
    assert files(session_dir) == before
    controller.inspect_directory(request.assessment_dir)
    inspected = settle(controller)
    assert inspected["session"] is None and inspected["report"]["outcome"] == "dry_run"
    assert files(session_dir) == before and controller.close()


@pytest.mark.parametrize("start", ["start_dry_run", "start_owned_execution"])
@pytest.mark.parametrize("kind", ["file", "missing", "symlink", "group_writable", "other_writable"])
def test_invalid_parent_cannot_create_session_or_change_old_view(tmp_path, kind, start):
    parent = tmp_path / "parent"
    if kind == "file":
        parent.write_text("keep")
    elif kind == "symlink":
        parent.symlink_to(tmp_path, target_is_directory=True)
    elif kind != "missing":
        parent.mkdir(mode=0o700)
        parent.chmod(0o720 if kind == "group_writable" else 0o702)
    controller = desktop.DesktopController()
    before = controller.snapshot()
    with pytest.raises((OSError, ValueError)):
        getattr(controller, start)(parent)
    assert controller.snapshot() == before
    assert not list(tmp_path.glob("recon-*-*"))


@pytest.mark.parametrize("start,mode", [("start_dry_run", "dry_run"),
                                        ("start_owned_execution", "owned_execution")])
def test_unsupported_platform_fails_before_creating_files(tmp_path, monkeypatch, start, mode):
    monkeypatch.setattr(desktop.sys, "platform", "darwin")
    controller = desktop.DesktopController()
    before = controller.snapshot()
    with pytest.raises(ValueError, match=mode + "_requires_supported_linux"):
        getattr(controller, start)(tmp_path)
    assert controller.snapshot() == before
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("start,mode", [("start_dry_run", "dry_run"),
                                        ("start_owned_execution", "owned_execution")])
@pytest.mark.parametrize("close", [False, True])
def test_early_cancel_or_close_is_sticky_and_scope_remains_frozen(
        tmp_path, monkeypatch, portable_services, close, start, mode):
    entered, release = threading.Event(), threading.Event()
    original = application.ConfigurableAssessmentService._run
    def delayed(service, *args):
        entered.set()
        assert release.wait(5)
        return original(service, *args)
    monkeypatch.setattr(application.ConfigurableAssessmentService, "_run", delayed)
    controller = desktop.DesktopController()
    getattr(controller, start)(tmp_path)
    try:
        assert entered.wait(2)
        controller.poll()
        assert controller.snapshot()["session"]["mode"] == mode
        initial = controller.snapshot()["session"]["scope"]
        edited = scope_fields(initial)
        edited["scope_id"] = "later-draft"
        edited["http_target"] = "172.23.0.12"
        controller.configure_scope(edited)
        assert controller.snapshot()["session"]["scope"] == initial
        with pytest.raises(ValueError, match="desktop_operation_running"):
            controller.start_dry_run(tmp_path)
        with pytest.raises(ValueError, match="desktop_operation_running"):
            controller.start_owned_execution(tmp_path)
        with pytest.raises(ValueError, match="desktop_operation_running"):
            controller.inspect_directory(tmp_path)
        if close:
            assert controller.close() is False
            with pytest.raises(ValueError, match="desktop_closed"):
                controller.start_dry_run(tmp_path)
            with pytest.raises(ValueError, match="desktop_closed"):
                controller.start_owned_execution(tmp_path)
        else:
            controller.cancel_session()
            controller.cancel_session()
        assert controller.snapshot()["session"]["cancel_requested"] is True
    finally:
        release.set()
    if close:
        deadline = time.monotonic() + 5
        while not controller.close() and time.monotonic() < deadline:
            time.sleep(0.002)
        assert controller.close()
        final = controller.snapshot()
        assert final["report"] is None and final["status"] == "Closed."
    else:
        final = settle(controller)
        assert final["session"]["phase"] == "stopped"
        assert final["session"]["stop_reason"] == "session_cancelled"
        assert final["error"] is None and final["report"] is None
        assert "cancelled" in final["status"]
        if mode == "owned_execution":
            assert "No tools executed" not in final["status"]
            assert "No final outcome is verified" in final["status"]
        assert controller.close()
    assert final["busy"] is False
    assert not portable_services
    assert not list(tmp_path.rglob("manifest.json"))


def test_cancellation_after_observed_step_retains_incomplete_report(tmp_path, monkeypatch, portable_services):
    entered, release = threading.Event(), threading.Event()
    original = application.ConfigurableAssessmentService.run
    def observed(service, **kwargs):
        def hold(_):
            entered.set()
            assert release.wait(5)
        return original(service, on_step=hold, **kwargs)
    monkeypatch.setattr(application.ConfigurableAssessmentService, "run", observed)
    controller = desktop.DesktopController()
    controller.start_dry_run(tmp_path)
    try:
        assert entered.wait(2)
        controller.poll()
        view = controller.snapshot()
        assert view["busy"] and view["report"] is None
        assert len(view["session"]["steps"]) == 1
        controller.cancel_session()
    finally:
        release.set()
    final = settle(controller)
    assert final["session"]["stop_reason"] == "session_cancelled"
    assert final["report"]["outcome"] != "completed"
    assert final["report"]["integrity_issues"] == []
    assert not any(event["event_type"] == "execution_started" for event in portable_services)
    assert controller.close()


@pytest.mark.parametrize("start,outcome", [("start_dry_run", "dry_run"),
                                           ("start_owned_execution", "incomplete")])
def test_run_failure_and_replay_failure_remain_distinct_and_recoverable(
        tmp_path, monkeypatch, portable_owned_review, start, outcome):
    original_run, original_inspect = application.ConfigurableAssessmentService.run, desktop.inspect_saved_assessment
    def broken(*args, **kwargs):
        raise RuntimeError("private sensitive error")
    controller = desktop.DesktopController()
    monkeypatch.setattr(application.ConfigurableAssessmentService, "run", broken)
    getattr(controller, start)(tmp_path)
    failed = settle(controller)
    assert failed["session"]["phase"] == "failed" and failed["report"] is None
    assert failed["error"] and "sensitive" not in failed["error"]
    monkeypatch.setattr(application.ConfigurableAssessmentService, "run", original_run)
    monkeypatch.setattr(desktop, "inspect_saved_assessment", broken)
    getattr(controller, start)(tmp_path)
    failed = settle(controller)
    assert failed["session"]["phase"] == "replay_failed"
    assert failed["report"] is None and "sensitive" not in failed["error"]
    monkeypatch.setattr(desktop, "inspect_saved_assessment", original_inspect)
    getattr(controller, start)(tmp_path)
    assert settle(controller)["report"]["outcome"] == outcome
    assert controller.close()


@pytest.mark.parametrize("start", ["start_dry_run", "start_owned_execution"])
def test_replay_remains_owned_and_close_suppresses_late_results(
        tmp_path, monkeypatch, portable_owned_review, start):
    entered, release = threading.Event(), threading.Event()
    original = desktop.inspect_saved_assessment
    def held(path):
        entered.set()
        assert release.wait(5)
        return original(path)
    monkeypatch.setattr(desktop, "inspect_saved_assessment", held)
    controller = desktop.DesktopController()
    getattr(controller, start)(tmp_path)
    try:
        assert entered.wait(2)
        controller.poll()
        assert controller.snapshot()["session"]["phase"] == "replaying"
        assert controller.snapshot()["report"] is None
        for operation in (controller.start_dry_run, controller.start_owned_execution,
                          controller.inspect_directory):
            with pytest.raises(ValueError, match="desktop_operation_running"):
                operation(tmp_path)
        assert controller.close() is False
        assert controller.poll() is False
    finally:
        release.set()
    deadline = time.monotonic() + 5
    while not controller.close() and time.monotonic() < deadline:
        time.sleep(0.002)
    assert controller.close() and controller.snapshot()["report"] is None
    assert controller._results.empty()


@pytest.mark.parametrize("start,outcome", [("start_dry_run", "dry_run"),
                                           ("start_owned_execution", "incomplete")])
def test_worker_start_failure_can_be_followed_by_fresh_session(
        tmp_path, monkeypatch, portable_owned_review, start, outcome):
    original = desktop.Thread.start
    def broken(*args, **kwargs):
        raise RuntimeError("thread start failed")
    monkeypatch.setattr(desktop.Thread, "start", broken)
    controller = desktop.DesktopController()
    with pytest.raises(RuntimeError):
        getattr(controller, start)(tmp_path)
    failed = controller.snapshot()
    assert failed["busy"] is False and failed["session"]["phase"] == "failed"
    assert failed["session"]["cancel_requested"]
    assert not list(tmp_path.rglob("manifest.json"))
    monkeypatch.setattr(desktop.Thread, "start", original)
    getattr(controller, start)(tmp_path)
    assert settle(controller)["report"]["outcome"] == outcome
    assert controller.close()


def test_owned_execution_uses_fixed_graphical_request_and_fresh_private_sessions(
        tmp_path, portable_owned_review):
    from dataclasses import FrozenInstanceError, asdict

    controller = desktop.DesktopController()
    fields = scope_fields(controller.snapshot()["scope"])
    fields["http_target"] = "192.168.50.20"
    fields["http_port"] = "8081"
    controller.configure_scope(fields)
    controller.start_owned_execution(tmp_path)
    final = settle(controller)
    captured = portable_owned_review
    request = captured["requests"][0]
    assert request.execute is True and request.approval_frontend == "graphical_v1"
    assert json.loads(request.scope_json) == final["session"]["scope"]
    assert json.loads(request.policy_json) == contract.policy_for_scope(
        final["session"]["scope"], require_approval=True).to_dict()
    assert asdict(request.limits) == {"max_steps": 4, "max_runtime_seconds": 60,
                                     "max_output_bytes": 26624}
    with pytest.raises(FrozenInstanceError):
        request.execute = False
    assert captured["run_calls"] == [{"interactive_terminal": False}]
    assert len(captured["reviews"]) == 1
    frontend, action, approval_required = captured["reviews"][0]
    assert frontend == "graphical_v1" and approval_required is True
    assert action["target"] == "192.168.50.20" and action["parameters"]["port"] == 8081
    assert final["session"]["mode"] == "owned_execution"
    assert final["session"]["stop_reason"] == "action_blocked"
    assert final["report"]["mode"] == "execute" and final["report"]["outcome"] == "incomplete"
    assert final["report"]["integrity_issues"] == [] and final["error"] is None
    assert "No tools executed" not in final["status"]
    directory = Path(final["session"]["session_dir"])
    assert directory.parent == tmp_path and directory.name.startswith("recon-owned-execution-")
    assert directory.stat().st_mode & 0o777 == 0o700
    assert request.assessment_dir == directory / "evidence" and request.audit_path == directory / "audit.jsonl"
    report = inspect_assessment(request.assessment_dir)
    assert report["metrics"]["legitimate_task_completed"] is False and report["records"] == []
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert not any(row["event_type"] in {"approval_consumed", "execution_started"} for row in captured["audit"])
    before = files(directory)
    controller.start_owned_execution(tmp_path)
    another = settle(controller)
    assert another["session"]["session_id"] != final["session"]["session_id"]
    assert another["session"]["session_dir"] != str(directory)
    assert files(directory) == before
    controller.inspect_directory(request.assessment_dir)
    inspected = settle(controller)
    assert inspected["session"] is None and inspected["report"] == final["report"]
    assert len(captured["requests"]) == 2 and len(captured["reviews"]) == 2
    assert files(directory) == before and controller.close()


def test_owned_pending_review_cancellation_uses_frozen_scope_and_never_launches(
        tmp_path, monkeypatch, portable_owned_review):
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService

    entered, release = threading.Event(), threading.Event()

    def review(self, action, policy, *, control):
        entered.set()
        assert release.wait(5)
        control.check()
        pytest.fail("cancelled review continued")

    monkeypatch.setattr(LinuxApprovalService, "review", review)
    controller = desktop.DesktopController()
    controller.start_owned_execution(tmp_path)
    try:
        assert entered.wait(2)
        controller.poll()
        active = controller.snapshot()
        assert active["busy"] and active["report"] is None
        assert active["session"]["steps"] == []  # policy alone is not an observed completed step
        edited = scope_fields(active["scope"])
        edited["http_target"] = "172.23.0.12"
        controller.configure_scope(edited)
        assert controller.snapshot()["session"]["scope"] == active["session"]["scope"]
        for operation in (controller.start_dry_run, controller.start_owned_execution,
                          controller.inspect_directory):
            with pytest.raises(ValueError, match="desktop_operation_running"):
                operation(tmp_path)
        controller.cancel_session()
        assert controller.snapshot()["busy"] and controller.snapshot()["session"]["cancel_requested"]
        assert "Cancellation requested" in controller.snapshot()["status"]
    finally:
        release.set()
    final = settle(controller)
    assert final["session"]["stop_reason"] == "session_cancelled"
    assert final["report"]["outcome"] == "incomplete" and final["report"]["integrity_issues"] == []
    assert final["scope"]["http"]["target"] == "172.23.0.12"
    assert final["report"]["scope"]["http"]["target"] == "10.77.0.10"
    audit = portable_owned_review["audit"]
    assert [row["outcome"] for row in audit if row["event_type"] == "graphical_review_finished"] == ["session_cancelled"]
    assert not any(row["event_type"] in {"approval_consumed", "execution_started"} for row in audit)
    assert "cancelled" in final["status"] and "No tools executed" not in final["status"]
    assert controller.close()


def test_owned_final_display_uses_replay_not_returned_completion_claim(
        tmp_path, monkeypatch, portable_owned_review):
    original = application.ConfigurableAssessmentService.run

    def misleading_return(service, **kwargs):
        original(service, **kwargs)
        return {"assessment_outcome": "completed", "metrics": {"legitimate_task_completed": True}}

    monkeypatch.setattr(application.ConfigurableAssessmentService, "run", misleading_return)
    controller = desktop.DesktopController()
    controller.start_owned_execution(tmp_path)
    final = settle(controller)
    assert final["report"]["outcome"] == "incomplete"
    assert final["report"]["metrics"][0]["value"] == "No"
    assert final["report"]["metrics"][1]["value"] == "0/4"
    assert controller.close()


def test_owned_replay_integrity_issue_suppresses_verified_outcome(tmp_path, monkeypatch, portable_owned_review):
    original = desktop.inspect_saved_assessment

    def inconsistent(path):
        report = original(path)
        report["integrity_issues"] = ["test_only_replay_mismatch"]
        return report

    monkeypatch.setattr(desktop, "inspect_saved_assessment", inconsistent)
    controller = desktop.DesktopController()
    controller.start_owned_execution(tmp_path)
    final = settle(controller)
    assert final["report"]["integrity_issues"] == ["test_only_replay_mismatch"]
    assert final["report"]["outcome"] == "incomplete"
    assert final["report"]["metrics"][0]["value"] == "Unavailable"
    assert "No final outcome is verified" in final["status"]
    assert controller.close()


def test_lifecycle_projection_bounds_hostile_text_and_does_not_guess_actions():
    snapshot = {"scope": desktop.DEFAULT_SCOPE, "state": "running", "session_id": "session",
        "stop_reason": None, "steps": [{"step": 1, "action_digest": "unknown",
            "execution_status": "blocked\u202e", "reasons": ["evil\n" + "x" * 10000]}] * 100}
    view = present_session(snapshot, phase="running", cancel_requested=False, directory=Path("/tmp/path\n"))
    assert len(view["steps"]) == 4
    assert len({row["id"] for row in view["steps"]}) == 4
    assert all(row["tool"] == "Unknown action" for row in view["steps"])
    assert all("\\u202e" in row["status"] for row in view["steps"])
    assert "\\u000a" in view["session_dir"]
    assert len(json.dumps(view)) < 15000
