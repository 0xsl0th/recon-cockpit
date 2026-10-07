"""Provisional execution labels without creating a Tk root or any authority."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


@pytest.fixture
def window_type(monkeypatch):
    """Load only the view code, leaving real Tk imports and module caches intact."""
    tk = ModuleType("tkinter")
    for name in ("filedialog", "font", "ttk"):
        setattr(tk, name, ModuleType("tkinter." + name))
    source = Path(__file__).resolve().parents[1] / "recon_cockpit/gui/window.py"
    spec = importlib.util.spec_from_file_location("recon_cockpit.gui._execution_view_test", source)
    module = importlib.util.module_from_spec(spec)
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "tkinter", tk)
        for name in ("filedialog", "font", "ttk"):
            patch.setitem(sys.modules, "tkinter." + name, getattr(tk, name))
        spec.loader.exec_module(module)
    return module.CockpitWindow


class DisplayWidget:
    def __init__(self):
        self.values = {}

    def configure(self, **values):
        self.values.update(values)

    def cget(self, name):
        return self.values.get(name)


@pytest.mark.parametrize("phase,pending", [
    ("running", True), ("replaying", True), ("failed", False),
    ("replay_failed", False), ("stopped", False), ("finished", False), (None, False),
])
def test_execution_without_replayed_report_only_promises_metrics_while_work_is_pending(window_type, phase, pending):
    window = window_type.__new__(window_type)
    window.colors = {"error": "red", "muted": "grey"}
    for name in ("engagement_label", "timeline_state", "evidence_path", "bundle_detail", "limitations"):
        setattr(window, name, DisplayWidget())
    window.metrics_labels = [DisplayWidget() for _ in range(5)]
    window.metrics_details = [DisplayWidget() for _ in range(5)]
    window._set_text = lambda widget, text: widget.configure(text=text)
    observed_rows = []
    window._replace_rows = observed_rows.extend
    step = {"id": "session-1", "status": "succeeded"}

    window._render_session({"mode": "owned_execution", "phase": phase, "state": "closed",
                            "session_id": "fixture-session", "session_dir": "/private/fixture",
                            "cancel_requested": phase == "stopped", "steps": [step]})

    values = [widget.cget("text") for widget in window.metrics_labels]
    assert values == (["Pending", "Pending", "Unavailable", "—", "—"] if pending else
                      ["Unavailable", "Unavailable", "Unavailable", "—", "—"])
    if not pending:
        for index in (0, 1, 2, 4):
            assert window.metrics_details[index].cget("text").startswith("No verified ")
    assert observed_rows == [step]
    assert "No tool execution" not in window.timeline_state.cget("text")
    assert "earlier actions may already have executed" in window.limitations.cget("text")
