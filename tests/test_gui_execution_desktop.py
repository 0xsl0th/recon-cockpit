"""Actual desktop execution on a private Xvfb, never owner approval input.

Opt in with RECON_GUI_INTEGRATION, RECON_LINUX_INTEGRATION and
RECON_GRAPHICAL_APPROVAL_INTEGRATION all set to 1. Only the existing native
reviewer fixture supplies scripted input; the desktop and shared service retain
their production authority, transport, execution and evidence paths.
"""

import gc
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

import pytest

from test_secure_graphical_approval_linux import instrument
from test_secure_fixture_launcher_linux import descendants
from test_secure_owned_launcher_linux import assert_reaped


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def owned_display():
    names = ("RECON_GUI_INTEGRATION", "RECON_LINUX_INTEGRATION",
             "RECON_GRAPHICAL_APPROVAL_INTEGRATION")
    if not all(os.environ.get(name) == "1" for name in names):
        pytest.skip("enable GUI, Linux and graphical approval integration on a private Xvfb")
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.environ.get("DISPLAY") not in (None, ":0", ":0.0")
    assert os.environ.get("XAUTHORITY"), "use a private authenticated Xvfb display"


def pump(root, predicate, *, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError("desktop execution did not reach the expected state")


def capture(root, name):
    supplied = os.environ.get("RECON_GUI_SCREENSHOTS")
    if supplied:
        directory = Path(supplied)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.update()
        path = directory / name
        subprocess.run(["/usr/bin/import", "-window", str(root.winfo_id()), str(path)],
                       check=True, timeout=15)
        path.chmod(0o600)


def visible_controls(root, window):
    left, top = root.winfo_rootx(), root.winfo_rooty()
    right, bottom = left + root.winfo_width(), top + root.winfo_height()
    names = ("theme", "start_dry_run", "start_owned_execution", "cancel_session", "load_evidence")
    metric_widgets = [*window.metrics_labels, *window.metrics_details]
    for widget in [*(window.buttons[name] for name in names), *metric_widgets]:
        assert widget.winfo_ismapped(), "essential execution control is hidden"
        assert left <= widget.winfo_rootx() < right
        assert top <= widget.winfo_rooty() < bottom
        assert widget.winfo_rootx() + widget.winfo_width() <= right
        assert widget.winfo_rooty() + widget.winfo_height() <= bottom
        if widget in metric_widgets:
            parent = widget.master
            assert parent.winfo_rootx() <= widget.winfo_rootx()
            assert parent.winfo_rooty() <= widget.winfo_rooty()
            assert widget.winfo_rootx() + widget.winfo_width() <= parent.winfo_rootx() + parent.winfo_width()
            assert widget.winfo_rooty() + widget.winfo_height() <= parent.winfo_rooty() + parent.winfo_height()


def reviewer_visible():
    executable = shutil.which("xdotool")
    assert executable, "native reviewer visibility checks require xdotool"
    result = subprocess.run([executable, "search", "--onlyvisible", "--name",
                             r"^Recon Cockpit \| Review exact action$"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
    assert result.returncode in (0, 1), "could not inspect the private display"
    identifiers = result.stdout.splitlines()
    assert len(identifiers) <= 1, "expected one reviewer on this private display"
    return bool(identifiers)


@pytest.fixture
def desktop(monkeypatch):
    import tkinter as tk

    from recon_cockpit import runner
    from recon_cockpit.gui.controller import DesktopController
    from recon_cockpit.gui.window import CockpitWindow
    from recon_cockpit.secure_agent import graphical_approval_protocol as graphical
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
    from recon_cockpit.secure_agent.configurable_backend import AuthorizedConfigurableBackend
    from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher

    # Other native cases create and destroy Tk interpreters in this process.
    # Finalize their retired cycles here on Tk's main thread, before starting a
    # service worker whose allocations might otherwise trigger collection.
    assert threading.current_thread() is threading.main_thread()
    gc.collect()
    objects, reviewers, forbidden_calls, observed = [], [], [], set()
    checks, reviewer_ready = [], threading.Event()

    def forbidden(*args, **kwargs):
        forbidden_calls.append(True)
        pytest.fail("desktop bypassed the isolated execution path")

    monkeypatch.setattr(runner, "run_command", forbidden)
    monkeypatch.setattr(runner, "stream_command", forbidden)
    monkeypatch.setattr(AuthorizedConfigurableBackend, "run", forbidden)
    monkeypatch.setattr(ConfigurableEndpointLab, "start", forbidden)

    def track_constructor(cls):
        original = cls.__init__

        def tracked(self, *args, **kwargs):
            original(self, *args, **kwargs)
            objects.append(self)
            if cls is LinuxApprovalService:
                reviewers.append(self)

        monkeypatch.setattr(cls, "__init__", tracked)

    for cls in (LinuxAuditSink, LinuxApprovalService, LinuxFixtureLauncher):
        track_constructor(cls)
    original_start = LinuxApprovalService._start

    def reviewer_started(self, *args, **kwargs):
        result = original_start(self, *args, **kwargs)
        assert self._frontend == "graphical_v1"
        assert self.boundary_checks == dict.fromkeys(graphical.CHECKS, True)
        checks.append(self.boundary_checks)
        # Capture while the actual reviewer is alive, including fast denials
        # that can finish before the desktop's next polling iteration.
        observe_processes()
        reviewer_ready.set()
        return result

    monkeypatch.setattr(LinuxApprovalService, "_start", reviewer_started)

    def observe_processes():
        for item in objects:
            process = getattr(item, "_process", None)
            if process is not None:
                observed.add(process.pid)
                observed.update(descendants(process.pid))

    root = tk.Tk()
    errors = []
    root.report_callback_exception = lambda *details: errors.append(details)
    controller = DesktopController()
    window = CockpitWindow(root, controller)
    root.update()
    state = {"objects": objects, "reviewers": reviewers, "checks": checks,
             "reviewer_ready": reviewer_ready, "observe_processes": observe_processes}
    try:
        yield root, window, controller, state
    finally:
        deadline = time.monotonic() + 25
        while not controller.close() and time.monotonic() < deadline:
            time.sleep(.01)
        assert controller.close(), "desktop abandoned authority cleanup or replay"
        try:
            root.destroy()
        except tk.TclError:
            pass
        gc.collect()
        assert not errors, "Tk callback failed instead of displaying a verified result"
        assert not forbidden_calls
        for item in objects:
            assert item._closed
            process = getattr(item, "_process", None)
            assert process is None or process.poll() is not None
        assert_reaped(observed)


@pytest.fixture
def first_step_latch(monkeypatch):
    """Pause after a real execution has been recorded, without replacing it."""
    from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentService

    entered, release = threading.Event(), threading.Event()
    observed_steps = []
    original = ConfigurableAssessmentService.run

    def run(self, *, interactive_terminal=False, on_step=None):
        assert self._request.execute is True
        assert self._request.approval_frontend == "graphical_v1"
        assert interactive_terminal is False

        def observed(step):
            if on_step is not None:
                on_step(step)
            if not entered.is_set():
                observed_steps.append(step)
                entered.set()
                assert release.wait(20), "test did not release its completed-action observer"

        return original(self, interactive_terminal=interactive_terminal, on_step=observed)

    monkeypatch.setattr(ConfigurableAssessmentService, "run", run)
    try:
        yield entered, release, observed_steps
    finally:
        release.set()


def start_from_widgets(desktop, parent, monkeypatch):
    from recon_cockpit.gui import window as window_module

    root, window, controller, _ = desktop
    monkeypatch.setattr(window_module.filedialog, "askdirectory", lambda **_: str(parent))
    window.buttons["start_owned_execution"].invoke()
    root.update()
    started = controller.snapshot()
    assert started["busy"] and started["operation"] == "session"
    assert started["session"]["mode"] == "owned_execution"
    assert started["report"] is None
    assert controller._service._request.execute is True
    assert controller._service._request.approval_frontend == "graphical_v1"
    for name in ("start_dry_run", "start_owned_execution", "load_evidence"):
        assert window.buttons[name].cget("state") == "disabled"
    assert window.buttons["cancel_session"].cget("state") == "normal"
    directory = Path(started["session"]["session_dir"])
    assert directory.parent == parent
    return directory


def finished_evidence(directory, *, expected, stop_reason, review_outcomes):
    from recon_cockpit.secure_agent.assessment_inspection import inspect_saved_assessment
    from recon_cockpit.secure_agent.configurable_contract import LIMITS
    from recon_cockpit.secure_agent.configurable_runtime import BOUNDARY_NAMES

    evidence = directory / "evidence"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert evidence.stat().st_mode & 0o777 == 0o700
    assert (directory / "audit.jsonl").stat().st_mode & 0o777 == 0o600
    audit = [json.loads(line) for line in (directory / "audit.jsonl").read_text().splitlines()]
    assert next(row for row in audit if row["event_type"] == "session_started")["limits"] == LIMITS
    summary = next(row for row in audit if row["event_type"] == "session_finished")
    assert summary["actions_succeeded"] == expected and summary["stop_reason"] == stop_reason
    for event in ("approval_consumed", "execution_started", "execution_finished"):
        assert sum(row["event_type"] == event for row in audit) == expected
    assert all(row["execution_status"] == "succeeded" for row in audit
               if row["event_type"] == "execution_finished")
    requested = [row for row in audit if row["event_type"] == "graphical_review_requested"]
    finished = [row for row in audit if row["event_type"] == "graphical_review_finished"]
    assert len(requested) == len(finished) == len(review_outcomes)
    assert [row["outcome"] for row in finished] == review_outcomes
    for request, result in zip(requested, finished):
        assert request["action_digest"] == result["action_digest"]
        assert request["session_id"] == result["session_id"] == summary["session_id"]
        assert request["policy_digest"] == result["policy_digest"]
        assert request["frontend"] == result["frontend"] == "graphical_v1"
        assert not {"reference", "approval_reference", "answer", "challenge"} & request.keys()
        assert not {"reference", "approval_reference", "answer", "challenge"} & result.keys()
    report = json.loads((evidence / "report.json").read_text())
    assert report["integrity_issues"] == []
    assert report["outcome"] == ("completed" if expected == 4 else "incomplete")
    assert len(report["records"]) == expected
    assert report["lab_closure"]["status"] == "closed"
    for endpoint in report["lab_closure"]["endpoints"].values():
        assert endpoint["status"] == "closed"
        if expected == 0:
            assert endpoint["connection_count"] == endpoint["request_count"] == 0
    metrics = report["metrics"]
    assert metrics["legitimate_task_completed"] is (expected == 4)
    assert metrics["useful_actions_completed"] == expected
    assert metrics["unnecessary_refusals"] == (0 if expected == 4 else None)
    assert metrics["actual_provider_calls"] == metrics["actual_cost_microusd"] == 0
    assert metrics["comparison_baseline"] is None and 0 <= metrics["elapsed_ms"] < 60000
    blocked = 0
    for record in report["records"]:
        artifact = json.loads((evidence / record["artifact"]["filename"]).read_text())
        assert artifact["boundary_checks"] == dict.fromkeys(BOUNDARY_NAMES, True)
        blocked += sum(artifact["boundary_checks"][name] is True for name in
                       ("cross_service_blocked", "forbidden_ip_blocked", "forbidden_port_blocked"))
    assert blocked == 3 * expected
    before = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
              for path in evidence.iterdir() if path.is_file()}
    assert all(value[1] & 0o777 == 0o600 for value in before.values())
    assert inspect_saved_assessment(evidence) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                      for path in evidence.iterdir() if path.is_file()}
    return report


@pytest.mark.parametrize("input_mode", ["approve", "clipboard"])
def test_native_desktop_completes_four_actions_with_review_and_replayed_evidence(
        desktop, first_step_latch, tmp_path, monkeypatch, record_property, input_mode):
    root, window, controller, state = desktop
    entered, release, observed_steps = first_step_latch
    instrument(tmp_path, monkeypatch, answer=input_mode)
    directory = start_from_widgets(desktop, tmp_path, monkeypatch)
    pump(root, lambda: entered.is_set())
    assert observed_steps[0]["execution_status"] == "succeeded", observed_steps[0]
    pump(root, lambda: len(controller.snapshot()["session"]["steps"]) == 1)
    state["observe_processes"]()
    frozen = controller.snapshot()["session"]["scope"]
    window.scope_fields["http_target"].set("10.77.0.14")
    window.buttons["validate_scope"].invoke()
    assert controller.snapshot()["scope"]["http"]["target"] == "10.77.0.14"
    assert controller.snapshot()["session"]["scope"] == frozen
    window.show_page("overview")
    root.geometry("1120x720")
    for theme in ("dark", "light"):
        if window.theme != theme:
            window.toggle_theme()
        root.update()
        assert root.winfo_width() == 1120 and root.winfo_height() == 720
        visible_controls(root, window)
        for name in ("start_dry_run", "start_owned_execution", "load_evidence"):
            assert window.buttons[name].cget("state") == "disabled"
        assert window.buttons["cancel_session"].cget("state") == "normal"
        assert controller.snapshot()["session"]["mode"] == "owned_execution"
        assert "dry run" not in window.timeline_state.cget("text").lower()
        capture(root, f"execution-progress-{input_mode}-{theme}-1120x720.png")
    release.set()
    pump(root, lambda: not controller.snapshot()["busy"])
    final = controller.snapshot()
    assert final["error"] is None and final["session"]["mode"] == "owned_execution"
    assert final["report"]["outcome"] == "completed" and final["report"]["mode"] == "execute"
    assert final["report"]["scope"] == frozen
    assert len(window.timeline.get_children()) == len(window.evidence_table.get_children()) == 4
    assert window.metrics_labels[0].cget("text") == "Yes"
    assert window.metrics_labels[1].cget("text") == "4/4"
    assert window.metrics_labels[3].cget("text") == "0 / $0"
    for name in ("start_dry_run", "start_owned_execution", "load_evidence"):
        assert window.buttons[name].cget("state") == "normal"
    assert window.buttons["cancel_session"].cget("state") == "disabled"
    assert len(state["checks"]) == 1
    report = finished_evidence(directory, expected=4, stop_reason="coordinator_done",
                               review_outcomes=["grant_issued"] * 4)
    for theme in ("dark", "light"):
        if window.theme != theme:
            window.toggle_theme()
        root.update()
        visible_controls(root, window)
        capture(root, f"execution-complete-{input_mode}-{theme}-1120x720.png")
    record_property("scripted_input_not_owner_approval", True)
    record_property("scripted_input_mode", input_mode)
    record_property("useful_actions_completed", 4)
    record_property("forbidden_listening_destinations_blocked", 12)
    record_property("elapsed_ms", report["metrics"]["elapsed_ms"])
    record_property("actual_provider_calls", 0)


def test_native_desktop_denial_never_launches_and_reports_incomplete(
        desktop, tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher

    root, window, controller, state = desktop
    instrument(tmp_path, monkeypatch, answer="deny")
    monkeypatch.setattr(LinuxFixtureLauncher, "_start", lambda *a, **k: pytest.fail("denied launcher started"))
    directory = start_from_widgets(desktop, tmp_path, monkeypatch)
    pump(root, lambda: not controller.snapshot()["busy"])
    final = controller.snapshot()
    assert final["error"] is None and final["report"]["outcome"] == "incomplete"
    assert final["session"]["stop_reason"] == "action_blocked"
    assert window.metrics_labels[0].cget("text") == "No"
    assert window.metrics_labels[1].cget("text") == "0/4"
    assert len(state["checks"]) == 1
    finished_evidence(directory, expected=0, stop_reason="action_blocked", review_outcomes=["denied"])


@pytest.mark.parametrize("operation", ["cancel", "close"])
def test_native_desktop_cancel_or_close_while_review_pending_cannot_launch(
        desktop, tmp_path, monkeypatch, operation):
    import tkinter as tk
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher

    root, window, controller, state = desktop
    instrument(tmp_path, monkeypatch, answer="wait")
    monkeypatch.setattr(LinuxFixtureLauncher, "_start", lambda *a, **k: pytest.fail("unapproved launcher started"))
    directory = start_from_widgets(desktop, tmp_path, monkeypatch)
    pump(root, state["reviewer_ready"].is_set)
    pump(root, reviewer_visible)
    state["observe_processes"]()
    if operation == "cancel":
        window.buttons["cancel_session"].invoke()
        assert controller.snapshot()["session"]["cancel_requested"]
        assert window.buttons["cancel_session"].cget("state") == "disabled"
        pump(root, lambda: not controller.snapshot()["busy"])
        final = controller.snapshot()
        assert final["error"] is None and final["session"]["stop_reason"] == "session_cancelled"
        assert final["report"]["outcome"] == "incomplete"
        assert window.metrics_labels[1].cget("text") == "0/4"
    else:
        window.close()
        assert controller.snapshot()["closing"] and controller.snapshot()["session"]["cancel_requested"]

        def destroyed():
            try:
                return not root.winfo_exists()
            except tk.TclError:
                return True

        pump(root, destroyed)
        assert controller.close() and not controller.snapshot()["busy"]
        assert controller.snapshot()["report"] is None and controller.snapshot()["status"] == "Closed."
    finished_evidence(directory, expected=0, stop_reason="session_cancelled",
                      review_outcomes=["session_cancelled"])


def test_native_desktop_cancel_after_one_execution_preserves_partial_results(
        desktop, first_step_latch, tmp_path, monkeypatch):
    root, window, controller, state = desktop
    entered, release, observed_steps = first_step_latch
    instrument(tmp_path, monkeypatch, answer="clipboard")
    directory = start_from_widgets(desktop, tmp_path, monkeypatch)
    pump(root, lambda: entered.is_set())
    assert observed_steps[0]["execution_status"] == "succeeded", observed_steps[0]
    pump(root, lambda: len(controller.snapshot()["session"]["steps"]) == 1)
    state["observe_processes"]()
    window.buttons["cancel_session"].invoke()
    assert controller.snapshot()["busy"] and controller.snapshot()["session"]["cancel_requested"]
    assert window.buttons["start_owned_execution"].cget("state") == "disabled"
    release.set()
    pump(root, lambda: not controller.snapshot()["busy"])
    final = controller.snapshot()
    assert final["error"] is None and final["report"]["outcome"] == "incomplete"
    assert final["session"]["stop_reason"] == "session_cancelled"
    assert window.metrics_labels[0].cget("text") == "No"
    assert window.metrics_labels[1].cget("text") == "1/4"
    assert len(window.timeline.get_children()) == len(window.evidence_table.get_children()) == 1
    assert "No tools executed" not in final["status"]
    finished_evidence(directory, expected=1, stop_reason="session_cancelled", review_outcomes=["grant_issued"])
