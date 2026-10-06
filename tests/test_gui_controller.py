"""Portable lifecycle and file-custody checks; no graphical or kernel claims."""

import json
import os
from pathlib import Path
import threading
import time

import pytest

from recon_cockpit.gui import controller as module
from recon_cockpit.gui.presentation import scope_fields


def settle(controller):
    expires = time.monotonic() + 3
    while time.monotonic() < expires:
        controller.poll()
        if not controller.snapshot()["busy"]:
            return controller.snapshot()
        time.sleep(0.001)
    pytest.fail("read-only worker did not finish")


@pytest.fixture
def inspection(monkeypatch):
    calls = []
    def inspect(path):
        calls.append((path, threading.get_ident()))
        return {"outcome": "completed", "rows": [{"target": "owned fixture"}]}
    monkeypatch.setattr(module, "inspect_saved_assessment", inspect)
    monkeypatch.setattr(module, "present_report", lambda report, path: report)
    return calls


def test_new_desktop_has_no_session_and_creates_no_files(tmp_path):
    controller = module.DesktopController()
    view = controller.snapshot()
    assert view["report"] is view["path"] is None
    assert view["busy"] is False and view["closing"] is False
    assert len(view["preview"]["rows"]) == 4
    view["scope"]["http"]["target"] = "8.8.8.8"
    assert controller.snapshot()["scope"]["http"]["target"] == "10.77.0.10"
    assert list(tmp_path.iterdir()) == [] and controller.close()


def test_invalid_edit_preserves_last_valid_scope_and_valid_edit_detaches_input():
    controller = module.DesktopController()
    original = controller.snapshot()["scope"]
    fields = scope_fields(original)
    fields["http_target"] = "8.8.8.8"
    with pytest.raises(ValueError):
        controller.configure_scope(fields)
    assert controller.snapshot()["scope"] == original
    fields["http_target"] = "192.168.50.20"
    fields["scope_id"] = "draft-office"
    view = controller.configure_scope(fields)
    fields["http_target"] = "192.168.50.30"
    view["scope"]["http"]["target"] = "192.168.50.40"
    assert controller.snapshot()["scope"]["http"]["target"] == "192.168.50.20"


def test_scope_export_roundtrip_is_private_and_never_overwrites(tmp_path):
    controller = module.DesktopController()
    path = tmp_path / "scope.json"
    controller.export_scope_file(path)
    assert path.stat().st_mode & 0o777 == 0o600
    before = path.read_bytes(), path.stat().st_mtime_ns
    with pytest.raises(FileExistsError):
        controller.export_scope_file(path)
    assert before == (path.read_bytes(), path.stat().st_mtime_ns)
    loaded = module.DesktopController()
    loaded.load_scope_file(path)
    assert loaded.snapshot()["scope"] == controller.snapshot()["scope"]
    assert json.loads(path.read_bytes()) == controller.snapshot()["scope"]


@pytest.mark.parametrize("kind", ["oversize", "invalid", "duplicate", "symlink", "fifo", "directory"])
def test_scope_import_rejects_nonregular_or_invalid_input_without_changing_draft(tmp_path, kind):
    path = tmp_path / "scope"
    if kind == "oversize":
        path.write_bytes(b" " * 4097)
    elif kind == "invalid":
        path.write_text('{}')
    elif kind == "duplicate":
        path.write_text('{"schema_version":"1","schema_version":"1"}')
    elif kind == "symlink":
        target = tmp_path / "target"
        target.write_text('{}')
        path.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    controller = module.DesktopController()
    before = controller.snapshot()["scope"]
    with pytest.raises((OSError, ValueError)):
        controller.load_scope_file(path)
    assert controller.snapshot()["scope"] == before


def test_scope_export_does_not_follow_existing_symlink(tmp_path):
    target = tmp_path / "original"
    target.write_text("keep")
    link = tmp_path / "scope.json"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        module.DesktopController().export_scope_file(link)
    assert target.read_text() == "keep" and link.is_symlink()


def test_background_replay_retains_draft_and_returns_detached_views(tmp_path, inspection):
    controller = module.DesktopController()
    fields = scope_fields(controller.snapshot()["scope"])
    fields["scope_id"] = "independent-draft"
    controller.configure_scope(fields)
    controller.inspect_directory(tmp_path)
    result = settle(controller)
    assert inspection == [(tmp_path.absolute(), inspection[0][1])]
    assert inspection[0][1] != threading.get_ident()
    assert result["scope"]["scope_id"] == "independent-draft"
    result["report"]["rows"][0]["target"] = "changed in GUI"
    assert controller.snapshot()["report"]["rows"][0]["target"] == "owned fixture"
    assert controller.close()


def test_failure_clears_previous_success_and_next_read_can_recover(tmp_path, monkeypatch, inspection):
    controller = module.DesktopController()
    controller.inspect_directory(tmp_path)
    assert settle(controller)["report"]["outcome"] == "completed"
    def broken(path):
        raise RuntimeError("secret or hostile exception text")
    monkeypatch.setattr(module, "inspect_saved_assessment", broken)
    controller.inspect_directory(tmp_path / "bad")
    assert controller.snapshot()["report"] is None
    failed = settle(controller)
    assert failed["report"] is None and failed["error"]
    assert "secret" not in failed["error"]
    monkeypatch.setattr(module, "inspect_saved_assessment", lambda _: {"outcome": "incomplete"})
    controller.inspect_directory(tmp_path)
    assert settle(controller)["report"]["outcome"] == "incomplete"
    assert controller.close()


def test_one_reader_only_and_close_waits_without_publishing_a_late_result(tmp_path, monkeypatch, inspection):
    entered, release = threading.Event(), threading.Event()
    def inspect(path):
        entered.set()
        assert release.wait(3)
        return {"outcome": "completed"}
    monkeypatch.setattr(module, "inspect_saved_assessment", inspect)
    controller = module.DesktopController()
    controller.inspect_directory(tmp_path)
    try:
        assert entered.wait(1)
        with pytest.raises(ValueError, match="inspection_already_running"):
            controller.inspect_directory(tmp_path)
        assert controller.close() is False
        with pytest.raises(ValueError, match="desktop_closed"):
            controller.inspect_directory(tmp_path)
        with pytest.raises(ValueError, match="desktop_closed"):
            controller.configure_scope(scope_fields(controller.snapshot()["scope"]))
    finally:
        release.set()
    deadline = time.monotonic() + 3
    while not controller.close() and time.monotonic() < deadline:
        controller.poll()
        time.sleep(0.001)
    assert controller.close() is True
    assert controller.snapshot()["report"] is None
    assert controller.snapshot()["busy"] is False
    assert controller._results.empty()


def test_thread_start_failure_leaves_reusable_controller(tmp_path, monkeypatch, inspection):
    original = module.Thread.start
    def failure(_):
        raise RuntimeError("cannot start")
    monkeypatch.setattr(module.Thread, "start", failure)
    controller = module.DesktopController()
    with pytest.raises(RuntimeError):
        controller.inspect_directory(tmp_path)
    assert controller.snapshot()["busy"] is False
    monkeypatch.setattr(module.Thread, "start", original)
    controller.inspect_directory(tmp_path)
    assert settle(controller)["report"]["outcome"] == "completed"
    assert controller.close()
