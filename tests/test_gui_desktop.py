"""Opt-in actual Tk desktop checks against owned, already recorded evidence.

These checks inspect private evidence; they never create an assessment, approve
an action, or invoke a model. Run under a private Xvfb with RECON_GUI_INTEGRATION=1
and RECON_GUI_EVIDENCE pointing at an accepted native configurable assessment.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

import pytest


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def desktop_opt_in():
    if os.environ.get("RECON_GUI_INTEGRATION") != "1":
        pytest.skip("set RECON_GUI_INTEGRATION=1 under a display for native Tk validation")
    assert os.environ.get("DISPLAY"), "actual Tk validation requires a display"


def pump(root, predicate, *, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("desktop did not reach expected state before the deadline")


def evidence_snapshot(directory):
    return {item.name: (item.read_bytes(), item.stat().st_mode, item.stat().st_mtime_ns)
            for item in directory.iterdir() if item.is_file()}


@pytest.fixture
def accepted_evidence():
    supplied = os.environ.get("RECON_GUI_EVIDENCE")
    assert supplied, "RECON_GUI_EVIDENCE must select an accepted private native assessment"
    directory = Path(supplied)
    report = json.loads((directory / "report.json").read_bytes())
    assert report["outcome"] == "completed" and not report["integrity_issues"]
    assert len(report["records"]) == 4
    before = evidence_snapshot(directory)
    yield directory
    assert evidence_snapshot(directory) == before


@pytest.fixture
def desktop(monkeypatch):
    import tkinter as tk

    from recon_cockpit import runner
    from recon_cockpit.gui.controller import DesktopController
    from recon_cockpit.gui.window import CockpitWindow
    from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentService
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService

    def forbidden(*args, **kwargs):
        pytest.fail("the desktop attempted to create execution or approval authority")

    monkeypatch.setattr(ConfigurableAssessmentService, "__init__", forbidden)
    monkeypatch.setattr(LinuxApprovalService, "__init__", forbidden)
    monkeypatch.setattr(runner, "run_command", forbidden)
    monkeypatch.setattr(runner, "stream_command", forbidden)
    root = tk.Tk()
    errors = []
    root.report_callback_exception = lambda *details: errors.append(details)
    controller = DesktopController()
    window = CockpitWindow(root, controller)
    root.update()
    try:
        yield root, window, controller
    finally:
        deadline = time.monotonic() + 15
        while not controller.close() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert controller.close(), "desktop abandoned a live evidence reader"
        try:
            root.destroy()
        except tk.TclError:
            pass
        assert not errors, "Tk callback raised instead of displaying an expected state"


def test_native_empty_startup_theme_and_navigation_never_claim_a_session(desktop):
    root, window, controller = desktop
    empty = controller.snapshot()
    assert empty["report"] is None and empty["path"] is None and not empty["busy"]
    assert window.theme == "dark"
    for page in ("scope", "evidence", "overview"):
        window.show_page(page)
        root.update()
        assert window.page == page
        assert controller.snapshot() == empty
    window.toggle_theme()
    root.update()
    assert window.theme == "light" and controller.snapshot() == empty
    window.toggle_theme()
    root.update()
    assert window.theme == "dark" and controller.snapshot() == empty
    assert not window.timeline.get_children() and not window.evidence_table.get_children()


def test_native_scope_validation_import_export_remain_draft_only(desktop, tmp_path, monkeypatch):
    from recon_cockpit.gui import window as window_module

    root, window, controller = desktop
    window.show_page("scope")
    original = controller.snapshot()["scope"]
    window.scope_fields["http_target"].set("8.8.8.8")
    window.buttons["validate_scope"].invoke()
    root.update()
    assert controller.snapshot()["scope"] == original
    assert window.scope_feedback.get()
    window.scope_fields["http_target"].set("10.77.0.11")
    window.scope_fields["http_path"].set("/review/index.html")
    window.buttons["validate_scope"].invoke()
    root.update()
    edited = controller.snapshot()
    assert edited["scope"]["http"]["target"] == "10.77.0.11"
    assert edited["scope"]["http"]["path"] == "/review/index.html"
    assert len(edited["preview"]["rows"]) == 4 and edited["report"] is None
    assert all(row["status"] == "Draft — not executed" for row in edited["preview"]["rows"])
    assert "/review/index.html" in window.scope_preview.get("1.0", "end")

    supplied = Path("examples/secure-agent-configurable-scope-alternate.json").absolute()
    monkeypatch.setattr(window_module.filedialog, "askopenfilename", lambda **_: str(supplied))
    window.buttons["import_scope"].invoke()
    root.update()
    imported = controller.snapshot()
    assert imported["scope"] == json.loads(supplied.read_bytes())
    assert window.scope_fields["http_target"].get() == "172.23.0.10"
    assert window.scope_fields["ssh_port"].get() == "12222"

    destination = tmp_path / "reviewed-scope.json"
    monkeypatch.setattr(window_module.filedialog, "asksaveasfilename", lambda **_: str(destination))
    window.buttons["export_scope"].invoke()
    root.update()
    assert json.loads(destination.read_bytes()) == imported["scope"]
    assert destination.stat().st_mode & 0o777 == 0o600
    assert controller.snapshot()["report"] is None and not controller.snapshot()["busy"]


def capture_if_requested(root, name):
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


def assert_visible_inside(root, widgets):
    left, top = root.winfo_rootx(), root.winfo_rooty()
    right, bottom = left + root.winfo_width(), top + root.winfo_height()
    for widget in widgets:
        assert widget.winfo_ismapped(), "essential control is hidden"
        assert left <= widget.winfo_rootx() < right
        assert top <= widget.winfo_rooty() < bottom
        assert widget.winfo_rootx() + widget.winfo_width() <= right
        assert widget.winfo_rooty() + widget.winfo_height() <= bottom


def test_native_saved_evidence_replays_without_execution_and_survives_theme_changes(
        desktop, accepted_evidence, monkeypatch):
    from recon_cockpit.gui import window as window_module

    root, window, controller = desktop
    draft_scope = controller.snapshot()["scope"]
    monkeypatch.setattr(window_module.filedialog, "askdirectory", lambda **_: str(accepted_evidence))
    window.buttons["load_evidence"].invoke()
    assert window.buttons["load_evidence"].cget("state") == "disabled"
    pump(root, lambda: not controller.snapshot()["busy"])
    saved = controller.snapshot()
    assert saved["error"] is None and saved["report"]["outcome"] == "completed"
    assert saved["report"]["read_only"] is True and saved["report"]["integrity_issues"] == []
    assert saved["path"] == str(accepted_evidence)
    assert saved["scope"] == draft_scope
    metrics = {item["label"]: item["value"] for item in saved["report"]["metrics"]}
    assert metrics["Legitimate completion"] == "Yes" and metrics["Useful actions"] == "4/4"
    assert metrics["Model calls / cost"] == "0 / $0"
    window.show_page("evidence")
    root.update()
    rows = window.evidence_table.get_children()
    assert len(rows) == 4
    window.evidence_table.selection_set(rows[0])
    window.evidence_table.event_generate("<<TreeviewSelect>>")
    root.update()
    detail = window.selected_detail.get("1.0", "end")
    assert saved["report"]["rows"][0]["detail"] in detail
    assert "max_output_bytes" in detail and "result-" in detail
    window.evidence_table.selection_set(rows[1])
    window.evidence_table.event_generate("<<TreeviewSelect>>")
    root.update()
    assert window.timeline.selection() == (rows[1],)
    window.timeline.selection_set(rows[0])
    window.timeline.event_generate("<<TreeviewSelect>>")
    root.update()
    assert window.evidence_table.selection() == (rows[0],)
    capture_if_requested(root, "evidence-dark.png")
    window.show_page("overview")
    root.update()
    assert_visible_inside(root, [window.buttons["theme"], window.buttons["load_evidence"],
                                 window.buttons["start_dry_run"], window.buttons["start_owned_execution"],
                                 window.buttons["cancel_session"],
                                 *window.metrics_labels])
    assert len(window.timeline.get_children()) == 4
    capture_if_requested(root, "overview-dark.png")
    window.toggle_theme()
    root.update()
    assert window.theme == "light" and controller.snapshot() == saved
    assert len(window.timeline.get_children()) == 4
    capture_if_requested(root, "overview-light.png")
    window.show_page("scope")
    root.update()
    assert_visible_inside(root, [window.buttons[name] for name in
                                 ("theme", "load_evidence", "validate_scope", "import_scope", "export_scope")])
    capture_if_requested(root, "scope-light.png")
    root.geometry("1280x800")
    window.show_page("overview")
    root.update()
    assert root.winfo_width() == 1280 and root.winfo_height() == 800
    assert_visible_inside(root, [window.buttons["theme"], window.buttons["load_evidence"],
                                 window.buttons["start_dry_run"], window.buttons["start_owned_execution"],
                                 window.buttons["cancel_session"],
                                 *window.metrics_labels])
    capture_if_requested(root, "overview-light-1280x800.png")
    window.toggle_theme()
    root.update()
    capture_if_requested(root, "overview-dark-1280x800.png")
    window.show_page("scope")
    root.update()
    assert_visible_inside(root, [window.buttons[name] for name in
                                 ("theme", "load_evidence", "validate_scope", "import_scope", "export_scope")])
    capture_if_requested(root, "scope-dark-1280x800.png")
    root.geometry("1120x720")
    window.show_page("overview")
    for theme in ("dark", "light"):
        if window.theme != theme:
            window.toggle_theme()
        root.update()
        assert root.winfo_width() == 1120 and root.winfo_height() == 720
        assert_visible_inside(root, [window.buttons[name] for name in
                                     ("theme", "load_evidence", "start_dry_run", "start_owned_execution",
                                      "cancel_session")])
        for detail in window.metrics_details:
            assert_visible_inside(detail.master, [detail])
            assert detail.winfo_reqwidth() <= detail.winfo_width()
            assert detail.winfo_reqheight() <= detail.winfo_height()
        capture_if_requested(root, "overview-" + theme + "-1120x720.png")
    assert controller.snapshot() == saved


def test_native_failed_replay_clears_previous_success(desktop, accepted_evidence, tmp_path):
    root, window, controller = desktop
    controller.inspect_directory(accepted_evidence)
    window.refresh()
    pump(root, lambda: not controller.snapshot()["busy"])
    assert controller.snapshot()["report"]["outcome"] == "completed"
    assert len(window.timeline.get_children()) == 4
    controller.inspect_directory(tmp_path / "missing-evidence")
    window.refresh()
    assert not window.timeline.get_children() and not window.evidence_table.get_children()
    pump(root, lambda: not controller.snapshot()["busy"])
    current = controller.snapshot()
    assert current["report"] is None and current["error"]
    assert window.error_var.get() == current["error"]
    assert not window.timeline.get_children() and not window.evidence_table.get_children()
    assert all(label.cget("text") == "—" for label in window.metrics_labels)


def test_native_corrupt_saved_report_does_not_display_success(desktop, accepted_evidence, tmp_path):
    root, window, controller = desktop
    copied = tmp_path / "copied-evidence"
    shutil.copytree(accepted_evidence, copied)
    target = copied / "report.json"
    report = json.loads(target.read_bytes())
    report["metrics"]["useful_actions_completed"] = 4000
    target.write_text(json.dumps(report))
    target.chmod(0o600)
    controller.inspect_directory(copied)
    window.refresh()
    pump(root, lambda: not controller.snapshot()["busy"])
    current = controller.snapshot()
    assert current["error"] is None
    assert current["report"]["outcome"] == "incomplete" and current["report"]["integrity_issues"]
    assert all(metric["value"] == "Unavailable" for metric in current["report"]["metrics"])
    assert "4000" not in json.dumps(current["report"]["metrics"])


def test_native_close_waits_for_pending_reader_and_discards_late_presentation(desktop, monkeypatch, tmp_path):
    import tkinter as tk
    from recon_cockpit.gui import controller as controller_module

    root, window, controller = desktop
    entered, release = threading.Event(), threading.Event()

    def blocked(_):
        entered.set()
        assert release.wait(10), "test did not release its blocked reader"
        raise ValueError("private detail must not become a GUI message")

    monkeypatch.setattr(controller_module, "inspect_saved_assessment", blocked)
    controller.inspect_directory(tmp_path)
    window.refresh()
    assert entered.wait(2)
    try:
        window.close()
        root.update()
        assert root.winfo_exists() and controller.snapshot()["closing"]
        assert controller.snapshot()["busy"] and controller.close() is False
        with pytest.raises(ValueError, match="desktop_closed"):
            controller.inspect_directory(tmp_path)
    finally:
        release.set()

    def destroyed():
        try:
            return not root.winfo_exists()
        except tk.TclError:
            return True

    pump(root, destroyed)
    final = controller.snapshot()
    assert final["report"] is None and final["error"] is None and not final["busy"]
    assert final["status"] == "Closed."
