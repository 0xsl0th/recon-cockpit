"""Actual Tk lifecycle around the real offline shared-authority dry run.

Opt in with RECON_GUI_INTEGRATION=1 and RECON_LINUX_INTEGRATION=1 under a
private display. The observation latch below pauses the caller's real service
callback to make progress/cancel/close deterministic; it replaces no authority,
coordinator, policy, execution result or evidence. No tool or model executes.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def desktop_session_opt_in():
    if (os.environ.get("RECON_GUI_INTEGRATION") != "1"
            or os.environ.get("RECON_LINUX_INTEGRATION") != "1"):
        pytest.skip("enable GUI and Linux integration for actual desktop dry-run validation")
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.environ.get("DISPLAY"), "actual Tk validation requires a display"


def pump(root, predicate, *, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("desktop dry run did not reach the expected state")


def capture(root, name):
    supplied = os.environ.get("RECON_GUI_SCREENSHOTS")
    if not supplied:
        return
    directory = Path(supplied)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.update()
    destination = directory / name
    subprocess.run(["/usr/bin/import", "-window", str(root.winfo_id()), str(destination)],
                   check=True, timeout=15)
    destination.chmod(0o600)


def visible_controls(root, window):
    left, top = root.winfo_rootx(), root.winfo_rooty()
    right, bottom = left + root.winfo_width(), top + root.winfo_height()
    for widget in (window.buttons["start_dry_run"], window.buttons["cancel_session"],
                   window.buttons["load_evidence"], *window.metrics_labels):
        assert widget.winfo_ismapped()
        assert left <= widget.winfo_rootx() < right
        assert top <= widget.winfo_rooty() < bottom
        assert widget.winfo_rootx() + widget.winfo_width() <= right
        assert widget.winfo_rooty() + widget.winfo_height() <= bottom


@pytest.fixture
def desktop(monkeypatch):
    import tkinter as tk

    from recon_cockpit.gui.controller import DesktopController
    from recon_cockpit.gui.window import CockpitWindow
    from recon_cockpit.secure_agent import configurable_runtime
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
    from recon_cockpit.secure_agent.configurable_backend import AuthorizedConfigurableBackend
    from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher

    forbidden_calls, audits = [], []

    def forbidden(*args, **kwargs):
        forbidden_calls.append(True)
        pytest.fail("desktop dry run tried to execute tools or create an approval grant")

    # Constructors remain real: the shared service keeps all mandatory authority
    # components. Their execution/approval entry points must remain unused.
    monkeypatch.setattr(configurable_runtime, "inspect_configurable_runtime", forbidden)
    monkeypatch.setattr(ConfigurableEndpointLab, "start", forbidden)
    monkeypatch.setattr(AuthorizedConfigurableBackend, "run", forbidden)
    monkeypatch.setattr(LinuxFixtureLauncher, "_start", forbidden)
    monkeypatch.setattr(LinuxApprovalService, "review", forbidden)
    monkeypatch.setattr(LinuxApprovalService, "consume", forbidden)
    original_audit = LinuxAuditSink.__init__

    def track_audit(self, *args, **kwargs):
        original_audit(self, *args, **kwargs)
        audits.append(self)

    monkeypatch.setattr(LinuxAuditSink, "__init__", track_audit)
    root = tk.Tk()
    errors = []
    root.report_callback_exception = lambda *details: errors.append(details)
    controller = DesktopController()
    window = CockpitWindow(root, controller)
    root.update()
    try:
        yield root, window, controller
    finally:
        deadline = time.monotonic() + 20
        while not controller.close() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert controller.close(), "desktop abandoned its dry-run/cleanup/replay worker"
        try:
            root.destroy()
        except tk.TclError:
            pass
        assert not errors, "Tk raised instead of displaying an expected session state"
        assert not forbidden_calls
        for audit in audits:
            assert audit._closed
            process = getattr(audit, "_process", None)
            assert process is None or process.poll() is not None


@pytest.fixture
def observation_latch(monkeypatch):
    """Pause only after the real authority has recorded its first proposal."""
    from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentService

    entered, release = threading.Event(), threading.Event()
    original_run = ConfigurableAssessmentService.run

    def run_with_test_latch(self, *, interactive_terminal=False, on_step=None):
        assert self._request.execute is False and interactive_terminal is False

        def observed(step):
            if on_step is not None:
                on_step(step)
            entered.set()
            assert release.wait(15), "test did not release the real observation callback"

        return original_run(self, interactive_terminal=interactive_terminal, on_step=observed)

    monkeypatch.setattr(ConfigurableAssessmentService, "run", run_with_test_latch)
    try:
        yield entered, release
    finally:
        release.set()


def start_from_widgets(root, window, controller, parent, monkeypatch):
    from recon_cockpit.gui import window as window_module

    monkeypatch.setattr(window_module.filedialog, "askdirectory", lambda **_: str(parent))
    window.buttons["start_dry_run"].invoke()
    root.update()
    started = controller.snapshot()
    assert started["busy"] and started["operation"] == "session"
    assert started["session"]["mode"] == "dry_run" and started["report"] is None
    assert window.buttons["start_dry_run"].cget("state") == "disabled"
    assert window.buttons["load_evidence"].cget("state") == "disabled"
    assert window.buttons["cancel_session"].cget("state") == "normal"
    return Path(started["session"]["session_dir"])


def read_finished_session(directory):
    assert directory.stat().st_mode & 0o777 == 0o700
    audit_path, evidence = directory / "audit.jsonl", directory / "evidence"
    assert audit_path.stat().st_mode & 0o777 == 0o600
    assert evidence.stat().st_mode & 0o777 == 0o700
    for path in evidence.iterdir():
        if path.is_file():
            assert path.stat().st_mode & 0o777 == 0o600
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert events
    assert not any(item["event_type"] in {"execution_started", "approval_consumed"} for item in events)
    report = json.loads((evidence / "report.json").read_bytes())
    assert report["integrity_issues"] == [] and report["outcome"] != "completed"
    metrics = report["metrics"]
    assert metrics["legitimate_task_completed"] is False
    assert metrics["useful_actions_completed"] == 0 and metrics["unnecessary_refusals"] is None
    assert metrics["actual_provider_calls"] == metrics["actual_cost_microusd"] == 0
    assert report["records"] == []
    assert report["lab_closure"]["status"] == "closed"
    for endpoint in report["lab_closure"]["endpoints"].values():
        assert endpoint["connection_count"] == endpoint["request_count"] == 0
    return report


def test_native_desktop_dry_run_uses_current_scope_and_real_evidence_without_execution(
        desktop, observation_latch, tmp_path, monkeypatch):
    from recon_cockpit.gui import window as window_module

    root, window, controller = desktop
    entered, release = observation_latch
    selected = []
    monkeypatch.setattr(window_module.filedialog, "askdirectory", lambda **_: selected.append(True))
    window.scope_fields["http_target"].set("8.8.8.8")
    window.buttons["start_dry_run"].invoke()
    assert selected == [] and controller.snapshot()["session"] is None
    assert window.page == "scope"

    window.scope_fields["http_target"].set("10.77.0.13")
    directory = start_from_widgets(root, window, controller, tmp_path, monkeypatch)
    assert directory.parent == tmp_path and directory.name.startswith("recon-dry-run-")
    assert entered.wait(10), "real authority did not observe its dry-run proposal"
    pump(root, lambda: len(controller.snapshot()["session"]["steps"]) == 1)
    current = controller.snapshot()
    assert current["session"]["scope"]["http"]["target"] == "10.77.0.13"
    assert len(window.timeline.get_children()) == 1
    assert window.metrics_labels[0].cget("text") == "Dry run"
    assert window.metrics_labels[1].cget("text") == "0"

    window.scope_fields["http_target"].set("10.77.0.14")
    window.buttons["validate_scope"].invoke()
    assert controller.snapshot()["scope"]["http"]["target"] == "10.77.0.14"
    assert controller.snapshot()["session"]["scope"]["http"]["target"] == "10.77.0.13"
    assert "10.77.0.13" in window.bundle_detail.get("1.0", "end")
    window.show_page("overview")
    root.update()
    visible_controls(root, window)
    capture(root, "session-progress-dark.png")
    root.geometry("1280x800")
    window.toggle_theme()
    root.update()
    visible_controls(root, window)
    assert window.scope_fields["http_target"].get() == "10.77.0.14"
    assert controller.snapshot()["session"]["scope"] == current["session"]["scope"]
    capture(root, "session-progress-light-1280x800.png")
    release.set()
    pump(root, lambda: not controller.snapshot()["busy"])
    final = controller.snapshot()
    assert final["error"] is None and final["session"]["phase"] == "finished"
    assert final["report"]["mode"] == "dry_run" and final["report"]["outcome"] == "dry_run"
    assert final["report"]["scope"]["http"]["target"] == "10.77.0.13"
    assert window.metrics_labels[0].cget("text") == "No"
    assert window.metrics_labels[1].cget("text") == "0/4"
    assert window.buttons["start_dry_run"].cget("state") == "normal"
    assert window.buttons["cancel_session"].cget("state") == "disabled"
    capture(root, "session-finished-light-1280x800.png")
    read_finished_session(directory)

    evidence = directory / "evidence"
    before = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
              for path in evidence.iterdir() if path.is_file()}
    controller.inspect_directory(evidence)
    window.refresh()
    pump(root, lambda: not controller.snapshot()["busy"])
    assert controller.snapshot()["report"] == final["report"]
    after = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
             for path in evidence.iterdir() if path.is_file()}
    assert after == before


def test_native_desktop_cancel_waits_for_real_authority_cleanup_and_replay(
        desktop, observation_latch, tmp_path, monkeypatch):
    root, window, controller = desktop
    entered, release = observation_latch
    directory = start_from_widgets(root, window, controller, tmp_path, monkeypatch)
    assert entered.wait(10)
    pump(root, lambda: len(controller.snapshot()["session"]["steps"]) == 1)
    window.buttons["cancel_session"].invoke()
    root.update()
    pending = controller.snapshot()
    assert pending["busy"] and pending["session"]["cancel_requested"]
    assert window.buttons["cancel_session"].cget("state") == "disabled"
    assert window.buttons["start_dry_run"].cget("state") == "disabled"
    release.set()
    pump(root, lambda: not controller.snapshot()["busy"])
    final = controller.snapshot()
    assert final["error"] is None and final["session"]["stop_reason"] == "session_cancelled"
    assert final["report"]["outcome"] != "completed"
    assert window.buttons["load_evidence"].cget("state") == "normal"
    read_finished_session(directory)


def test_native_desktop_close_cancels_real_session_before_destroying_window(
        desktop, observation_latch, tmp_path, monkeypatch):
    import tkinter as tk

    root, window, controller = desktop
    entered, release = observation_latch
    directory = start_from_widgets(root, window, controller, tmp_path, monkeypatch)
    assert entered.wait(10)
    window.close()
    root.update()
    assert root.winfo_exists() and controller.snapshot()["closing"]
    assert controller.snapshot()["busy"] and controller.snapshot()["session"]["cancel_requested"]
    assert not controller.close()
    release.set()

    def destroyed():
        try:
            return not root.winfo_exists()
        except tk.TclError:
            return True

    pump(root, destroyed)
    assert controller.close() and controller.snapshot()["status"] == "Closed."
    assert controller.snapshot()["report"] is None
    read_finished_session(directory)


def test_native_desktop_real_dry_run_with_failed_replay_never_shows_verified_outcome(
        desktop, tmp_path, monkeypatch):
    from recon_cockpit.gui import controller as controller_module

    root, window, controller = desktop

    def unavailable(_):
        raise ValueError("test-only replay failure after real authority cleanup")

    monkeypatch.setattr(controller_module, "inspect_saved_assessment", unavailable)
    directory = start_from_widgets(root, window, controller, tmp_path, monkeypatch)
    pump(root, lambda: not controller.snapshot()["busy"])
    final = controller.snapshot()
    assert final["session"]["state"] == "finished"
    assert final["session"]["phase"] == "replay_failed" and final["report"] is None
    assert final["error"] and "EVIDENCE REPLAY FAILED" in window.timeline_state.cget("text")
    assert "finished" not in window.timeline_state.cget("text").lower()
    assert all(label.cget("text") not in {"Yes", "4/4"} for label in window.metrics_labels)
    assert window.buttons["start_dry_run"].cget("state") == "normal"
    assert window.buttons["cancel_session"].cget("state") == "disabled"
    window.toggle_theme()
    root.update()
    assert "EVIDENCE REPLAY FAILED" in window.timeline_state.cget("text")
    read_finished_session(directory)


def test_native_desktop_service_failure_overrides_ready_state(desktop, tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentService
    from recon_cockpit.gui import window as window_module

    root, window, controller = desktop

    def unavailable(self, **kwargs):
        raise RuntimeError("test-only startup failure before authority exists")

    monkeypatch.setattr(ConfigurableAssessmentService, "run", unavailable)
    monkeypatch.setattr(window_module.filedialog, "askdirectory", lambda **_: str(tmp_path))
    window.buttons["start_dry_run"].invoke()
    pump(root, lambda: not controller.snapshot()["busy"])
    final = controller.snapshot()
    assert final["session"]["state"] == "ready" and final["session"]["phase"] == "failed"
    assert final["error"] and final["report"] is None
    assert "DRY RUN FAILED" in window.timeline_state.cget("text")
    assert "ready" not in window.timeline_state.cget("text").lower()
    assert window.buttons["cancel_session"].cget("state") == "disabled"
