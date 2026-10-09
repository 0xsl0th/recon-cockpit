"""Actual Tk widget behavior on an owned display, with scripted fixture input.

These direct-view cases do not create an isolated worker, issue grants or launch
tools. Separate test_secure_graphical_approval_linux cases verify that boundary.
No scripted input or screenshot is the owner's personal approval/acceptance.
"""

import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent.configurable_contract import action, policy_for_scope
from recon_cockpit.secure_agent.graphical_approval_view import ReviewWindow, review_text
from recon_cockpit.secure_agent.models import parse_action


pytestmark = pytest.mark.integration

SCOPE = {"schema_version": "1", "scope_id": "review-view-fixture",
         "http": {"target": "10.77.0.10", "port": 8080, "path": "/harbordesk/portal.html"},
         "ssh": {"target": "10.77.0.20", "port": 2222}}


@pytest.fixture(autouse=True)
def owned_display():
    if os.environ.get("RECON_GRAPHICAL_APPROVAL_INTEGRATION") != "1":
        pytest.skip("enable RECON_GRAPHICAL_APPROVAL_INTEGRATION under an owned Xvfb display")
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.environ.get("DISPLAY") and os.environ.get("XAUTHORITY")


@pytest.fixture
def review_view():
    view = ReviewWindow()
    peer, channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    errors = []

    def callback_error(*details):
        errors.append(details)
        view._decision = False

    view._root.report_callback_exception = callback_error
    try:
        yield view, peer, channel
    finally:
        view.close()
        peer.close()
        channel.close()
        assert not errors, "a Tk test callback failed instead of proving its assertions"


def run_review(view, channel, *, seconds=5, session_id="view-test-session"):
    return view.review(parse_action(action(SCOPE, 2)), policy_for_scope(SCOPE), session_id,
                       time.monotonic() + seconds, channel.fileno())


def captured_window(view, geometry="900x740"):
    supplied = os.environ.get("RECON_GUI_SCREENSHOTS")
    if supplied:
        directory = Path(supplied)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = directory / ("exact-action-review-dark.png" if geometry == "900x740"
                                   else "exact-action-review-dark-" + geometry + ".png")
        # Screenshot capture runs in this host-side fixture, never in a reviewer.
        subprocess.run(["/usr/bin/import", "-window", str(view._root.winfo_id()), str(destination)],
                       check=True, timeout=15)
        destination.chmod(0o600)


@pytest.mark.parametrize("geometry", ["900x740", "780x650"])
def test_actual_window_exact_bindings_fresh_answer_and_clearance(review_view, geometry):
    view, _, channel = review_view
    view._root.geometry(geometry)
    challenges = []
    for attempt in range(2):
        def approve_fixture():
            assert view._active and not view._entry.get()
            challenges.append(view._challenge)
            shown = view._details.get("1.0", "end-1c")
            assert shown == review_text(parse_action(action(SCOPE, 2)), policy_for_scope(SCOPE),
                                        "view-test-session")
            for widget in (view._details, view._entry, view._challenge_field,
                           view._copy_button, view._approve_button, view._deny_button):
                assert widget.winfo_ismapped()
                x = widget.winfo_rootx() - view._root.winfo_rootx()
                y = widget.winfo_rooty() - view._root.winfo_rooty()
                assert 0 <= x and x + widget.winfo_width() <= view._root.winfo_width()
                assert 0 <= y and y + widget.winfo_height() <= view._root.winfo_height()
            if attempt == 0:
                captured_window(view, geometry)
            view._entry.insert(0, view._challenge)
            view._approve_button.invoke()

        view._root.after(120, approve_fixture)
        assert run_review(view, channel)
        assert view._root.state() == "withdrawn"
        assert view._entry.get() == "" and view._challenge is None
        assert view._challenge_field.get() == ""
        assert view._approve_button.cget("state") == "disabled"
        assert view._copy_button.cget("state") == "disabled"
    assert challenges[0] != challenges[1]


def test_actual_window_copy_button_never_fills_answer_or_approves(review_view):
    view, _, channel = review_view
    copied = []

    def copy_fixture():
        assert view._challenge_field.cget("state") == "readonly"
        assert view._challenge_field.get() == view._challenge
        view._challenge_field.delete(0, "end")
        view._challenge_field.insert(0, "changed")
        assert view._challenge_field.get() == view._challenge
        view._copy_button.invoke()
        copied.append(view._root.clipboard_get())
        assert copied[-1] == view._challenge
        assert not view._entry.get() and view._decision is None
        assert view._feedback.cget("text") == "Copied. Paste with Ctrl+V, then choose Approve once."
        view._deny_button.invoke()

    view._root.after(120, copy_fixture)
    assert not run_review(view, channel)
    assert len(copied) == 1 and view._root.clipboard_get() == copied[0]
    assert not view._challenge_field.get() and not view._entry.get()


def test_actual_window_selected_phrase_key_copy_paste_still_needs_explicit_approval(review_view):
    view, _, channel = review_view
    checked = []

    def approve_explicitly():
        assert view._decision is None
        checked.append("explicit")
        view._approve_button.invoke()

    def after_paste():
        assert view._entry.get() == view._challenge and view._decision is None
        checked.append("paste")
        view._entry.event_generate("<Return>", when="tail")
        view._root.after(40, approve_explicitly)

    def after_copy():
        assert view._root.clipboard_get() == view._challenge
        assert not view._entry.get() and view._decision is None
        assert view._root.focus_get() is view._entry
        checked.append("copy")
        view._entry.focus_force()
        view._root.after(30, lambda: view._entry.event_generate("<Control-v>", when="tail"))
        view._root.after(70, after_paste)

    def select_fixture():
        view._challenge_field.focus_force()
        view._challenge_field.selection_range(0, "end")
        assert view._challenge_field.selection_present()
        view._root.after(30, lambda: view._challenge_field.event_generate("<Control-c>", when="tail"))
        view._root.after(70, after_copy)

    view._root.after(120, select_fixture)
    assert run_review(view, channel)
    assert checked == ["copy", "paste", "explicit"]


def test_actual_window_previous_clipboard_phrase_cannot_approve_new_review(review_view):
    view, _, channel = review_view
    copied = []

    def first_copy():
        view._copy_button.invoke()
        copied.append(view._root.clipboard_get())
        view._deny_button.invoke()

    view._root.after(120, first_copy)
    assert not run_review(view, channel)

    def stale_paste():
        assert view._root.clipboard_get() == copied[0] != view._challenge
        view._entry.event_generate("<<Paste>>")
        assert view._entry.get() == copied[0]
        view._approve_button.invoke()
        assert view._decision is None and not view._entry.get()
        view._deny_button.invoke()

    view._root.after(120, stale_paste)
    assert not run_review(view, channel)
    assert view._root.clipboard_get() == copied[0]


def test_actual_window_inactive_or_expired_copy_preserves_unrelated_clipboard(review_view):
    view, _, channel = review_view
    view._root.clipboard_clear()
    view._root.clipboard_append("unrelated clipboard text")
    view._copy_button.invoke()
    view._copy_phrase()
    view._challenge_field.event_generate("<<Copy>>")
    assert view._root.clipboard_get() == "unrelated clipboard text"
    checked = []

    def expired_copy():
        view._deadline = time.monotonic() - 1
        view._copy_button.invoke()
        view._challenge_field.event_generate("<<Copy>>")
        assert view._root.clipboard_get() == "unrelated clipboard text"
        assert not view._entry.get() and view._decision is None
        checked.append(True)
        view._deny_button.invoke()

    view._root.after(120, expired_copy)
    assert not run_review(view, channel) and checked == [True]
    assert view._root.clipboard_get() == "unrelated clipboard text"


def test_actual_window_oversized_clipboard_cannot_bypass_answer_limit(review_view):
    view, _, channel = review_view
    checked = []

    def paste_fixture():
        view._root.clipboard_clear()
        view._root.clipboard_append("x" * 1024)
        view._entry.event_generate("<<Paste>>")
        assert not view._entry.get()
        view._approve_button.invoke()
        assert view._decision is None
        checked.append(True)
        view._deny_button.invoke()

    view._root.after(120, paste_fixture)
    assert not run_review(view, channel) and checked == [True]


def test_actual_window_remote_tcl_interpreter_is_unregistered(review_view):
    import tkinter as tk

    view, _, _ = review_view
    observer = tk.Tk(className="ReviewViewObserver")
    observer.withdraw()
    try:
        assert not view._root.tk.call("info", "commands", "send")
        registered = observer.tk.splitlist(observer.tk.call("winfo", "interps"))
        assert view._interpreter_name not in registered
        with pytest.raises(tk.TclError, match="no application named"):
            observer.tk.call("send", view._interpreter_name, "set remoteExecuted 1")
        assert view._root.tk.call("info", "exists", "remoteExecuted") == 0
    finally:
        observer.destroy()


def test_actual_window_pretyped_and_stale_answer_cannot_approve(review_view):
    view, _, channel = review_view
    old = []

    def first_answer():
        old.append(view._challenge)
        view._entry.insert(0, view._challenge)
        view._approve_button.invoke()

    view._root.after(120, first_answer)
    assert run_review(view, channel)
    view._entry.insert(0, old[0])
    # An event already queued before the new prompt must not accept input.
    view._root.after(0, view._approve_button.invoke)

    def stale_answer():
        assert view._challenge != old[0] and not view._entry.get()
        view._entry.insert(0, old[0])
        view._approve_button.invoke()
        assert view._decision is None and not view._entry.get()
        assert "does not match" in view._feedback.cget("text")
        view._deny_button.invoke()

    view._root.after(120, stale_answer)
    assert not run_review(view, channel)


@pytest.mark.parametrize("key", ["<Return>", "<KP_Enter>"])
def test_actual_window_enter_never_approves_an_exact_phrase(review_view, key):
    view, _, channel = review_view
    checked = []

    def after_key():
        assert view._decision is None
        checked.append(True)
        view._deny_button.invoke()

    def key_fixture():
        view._entry.insert(0, view._challenge)
        view._entry.focus_force()
        view._entry.event_generate(key, when="tail")
        view._root.after(40, after_key)

    view._root.after(120, key_fixture)
    assert not run_review(view, channel) and checked == [True]


@pytest.mark.parametrize("event", ["window_close", "channel_eof", "queued_message", "deadline"])
def test_actual_window_pending_review_fails_closed(review_view, event):
    view, peer, channel = review_view
    if event == "window_close":
        operation = lambda: view._root.tk.call(view._root.protocol("WM_DELETE_WINDOW"))
    elif event == "channel_eof":
        operation = peer.close
    elif event == "queued_message":
        operation = lambda: peer.send(b'{"approved":true}')
    else:
        operation = None
    if operation is not None:
        view._root.after(120, operation)
    assert not run_review(view, channel, seconds=.2 if event == "deadline" else 5)
    assert view._root.state() == "withdrawn"
    assert view._challenge is None and view._entry.get() == ""


def test_actual_window_untrusted_session_text_is_literal(review_view):
    view, _, channel = review_view
    checked = []

    def inspect_fixture():
        shown = view._details.get("1.0", "end-1c")
        assert '"session\\n\\u202e[exec hostile]"' in shown
        assert "\u202e" not in shown
        checked.append(True)
        view._deny_button.invoke()

    view._root.after(120, inspect_fixture)
    assert not run_review(view, channel, session_id="session\n\u202e[exec hostile]")
    assert checked == [True]
