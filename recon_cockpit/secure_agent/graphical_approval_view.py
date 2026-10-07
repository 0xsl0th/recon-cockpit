"""Dedicated worker-owned exact-action review window.

Only the isolated reviewer imports this view. It exposes no parent-supplied
answer callback, grant or witness operation. X11 and the local desktop remain
trusted: deleting Tk's remote interpreter interface does not authenticate human
input against another privileged desktop client.
"""

import json
import math
import secrets
import select
import time


def review_text(action, policy, session_id):
    """Render validated bindings literally; never display planner rationale."""
    canonical = action.to_dict()
    canonical.pop("rationale", None)
    parameters = canonical["parameters"]
    literal = lambda value: json.dumps(value, ensure_ascii=True)
    lines = [
        "Tool profile  " + literal(canonical["tool_id"]),
        "Destination   " + literal(canonical["target"]) + ":" + str(parameters["port"]),
    ]
    if "method" in parameters:
        lines.append("Request       " + literal(parameters["method"]) + " " + literal(parameters["path"]))
    lines += [
        "Timeout       " + str(parameters["timeout_seconds"]) + " seconds",
        "Output limit  " + str(parameters["max_output_bytes"]) + " bytes",
        "", "Session       " + literal(session_id),
        "Policy        " + literal(policy.policy_version),
        "Allowed scope " + literal(list(policy.allowed_targets)),
        "Allowed ports " + literal(list(policy.allowed_ports)),
        "", "Action digest " + action.digest,
        "Policy digest " + policy.digest,
        "", "Exact action (planner rationale omitted):",
        json.dumps(canonical, sort_keys=True, ensure_ascii=True, indent=2),
    ]
    return "\n".join(lines)


def fresh_challenge(action):
    """A new answer is required even when the exact same action is reviewed."""
    return "approve " + action.digest[:16] + " " + secrets.token_hex(16)


class ReviewWindow:
    """Persistent private Tk interpreter; one blocking review at a time."""

    def __init__(self):
        import _tkinter
        import tkinter as tk
        from tkinter import font

        self._tk = tk
        self._events = _tkinter.ALL_EVENTS | _tkinter.DONT_WAIT
        self._active = False
        self._closed = False
        self._decision = None
        self._challenge = None
        self._deadline = 0.0
        self._root = tk.Tk(className="ReconActionReview")
        self._root.withdraw()
        self._interpreter_name = self._root.tk.call("tk", "appname")
        # In Tk/X11, deleting `send` invokes its DeleteProc and unregisters the
        # interpreter. Never set `tk appname` afterward: that registers it again.
        # Source: tcltk/tk core-8-6-branch/unix/tkUnixSend.c, DeleteProc.
        if self._root.tk.call("info", "commands", "send"):
            self._root.tk.call("rename", "send", "")
        if self._root.tk.call("info", "commands", "send"):
            self._root.destroy()
            raise ValueError("graphical_remote_interpreter_enabled")
        self._root.report_callback_exception = self._callback_error
        self._root.title("Recon Cockpit | Review exact action")
        self._root.geometry("900x740")
        self._root.minsize(780, 650)
        self._root.configure(background="#0D1721")
        self._root.protocol("WM_DELETE_WINDOW", self._deny)
        self._root.bind("<Return>", lambda _: "break")
        self._root.bind("<KP_Enter>", lambda _: "break")
        self._root.bind("<Escape>", lambda _: self._deny())
        self._fonts = [font.Font(family="DejaVu Sans", size=10),
                       font.Font(family="DejaVu Sans", size=17, weight="bold"),
                       font.Font(family="DejaVu Sans Mono", size=10)]
        for item in self._fonts:
            item.measure("".join(chr(value) for value in range(32, 127)))
        frame = tk.Frame(self._root, background="#0D1721", padx=22, pady=18)
        frame.pack(fill="both", expand=True)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)
        tk.Label(frame, text="Review this exact action", font=self._fonts[1], anchor="w",
                 foreground="#F0F4F8", background="#0D1721").grid(row=0, column=0, sticky="ew")
        tk.Label(frame, text="One action only. Denying or closing this window issues no approval.",
                 font=self._fonts[0], anchor="w", foreground="#AEC0CD", background="#0D1721").grid(
                     row=1, column=0, sticky="ew", pady=(8, 12))
        details = tk.Frame(frame, background="#14212D")
        details.grid(row=2, column=0, sticky="nsew")
        details.grid_columnconfigure(0, weight=1)
        details.grid_rowconfigure(0, weight=1)
        self._details = tk.Text(details, font=self._fonts[2], wrap="word", height=20,
            state="disabled", background="#14212D", foreground="#F0F4F8", borderwidth=0,
            padx=12, pady=12, takefocus=False, exportselection=False)
        self._details.grid(row=0, column=0, sticky="nsew")
        scrollbar = tk.Scrollbar(details, command=self._details.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self._details.configure(yscrollcommand=scrollbar.set)
        self._time_label = tk.Label(frame, text="Review deadline", font=self._fonts[0], anchor="w",
            foreground="#FFC27D", background="#0D1721")
        self._time_label.grid(row=3, column=0, sticky="ew", pady=(12, 6))
        tk.Label(frame, text="Copy and paste, or type the fresh phrase. Then choose Approve once:",
            font=self._fonts[0], anchor="w", foreground="#F0F4F8", background="#0D1721").grid(
                row=4, column=0, sticky="ew")
        phrase_row = tk.Frame(frame, background="#0D1721")
        phrase_row.grid(row=5, column=0, sticky="ew", pady=8)
        phrase_row.grid_columnconfigure(0, weight=1)
        self._challenge_text = tk.StringVar(master=self._root, value="")
        self._challenge_field = tk.Entry(phrase_row, textvariable=self._challenge_text,
            font=self._fonts[2], foreground="#FF7B2C", readonlybackground="#14212D",
            state="readonly", exportselection=False, relief="flat", width=1)
        self._challenge_field.grid(row=0, column=0, sticky="ew", ipady=8)
        self._challenge_field.bind("<<Copy>>", self._copy_phrase)
        self._copy_button = tk.Button(phrase_row, text="Copy phrase", command=self._copy_phrase,
            font=self._fonts[0], background="#1A2B39", foreground="#F0F4F8", padx=12, pady=8,
            relief="flat", state="disabled")
        self._copy_button.grid(row=0, column=1, padx=(10, 0))
        self._entry = tk.Entry(frame, font=self._fonts[2], background="#101C26", foreground="#F0F4F8",
            insertbackground="#F0F4F8", exportselection=False, relief="solid", borderwidth=1,
            validate="key", validatecommand=(self._root.register(lambda value: len(value) <= 128), "%P"))
        self._entry.grid(row=6, column=0, sticky="ew", ipady=8)
        self._entry.bind("<Return>", lambda _: "break")
        self._entry.bind("<KP_Enter>", lambda _: "break")
        self._feedback = tk.Label(frame, text="Enter does not approve. The phrase is valid only for this review.",
            font=self._fonts[0], anchor="w", foreground="#AEC0CD", background="#0D1721")
        self._feedback.grid(row=7, column=0, sticky="ew", pady=(6, 12))
        controls = tk.Frame(frame, background="#0D1721")
        controls.grid(row=8, column=0, sticky="e")
        self._deny_button = tk.Button(controls, text="Deny", command=self._deny, font=self._fonts[0],
            background="#1A2B39", foreground="#F0F4F8", padx=20, pady=10, relief="flat")
        self._deny_button.pack(side="left", padx=(0, 10))
        self._approve_button = tk.Button(controls, text="Approve once", command=self._approve,
            font=self._fonts[0], background="#FF7B2C", foreground="#16100C", padx=20, pady=10,
            relief="flat", default="disabled")
        self._approve_button.pack(side="left")
        self.warmup()

    def _callback_error(self, *_):
        self._decision = False

    def warmup(self):
        """Load fonts/widget paths while the worker still permits setup access."""
        if self._closed:
            raise ValueError("graphical_review_closed")
        # Tk leaves keyboard traversal and word-selection helpers lazy. Real
        # Tab/double-click/Ctrl-arrow bindings otherwise try to read focus.tcl or
        # word.tcl after the worker has sealed filesystem opens. Load only these
        # fixed helpers, and skip existing commands so repeated warmup is inert.
        for name in ("tk_focusNext", "tk_focusPrev", "tk::FocusOK",
                     "tcl_wordBreakAfter", "tcl_wordBreakBefore", "tcl_endOfWord",
                     "tcl_startOfNextWord", "tcl_startOfPreviousWord"):
            if not self._root.tk.call("info", "commands", name):
                self._root.tk.call("auto_load", name)
            if not self._root.tk.call("info", "commands", name):
                raise ValueError("graphical_interaction_helpers_missing")
        self._root.update_idletasks()
        self._pump()

    def _pump(self):
        # Bound work per poll, so event traffic cannot hide the deadline/channel.
        for _ in range(256):
            if not self._root.tk.dooneevent(self._events):
                break

    def _deny(self):
        if self._active:
            self._decision = False

    def _copy_phrase(self, _event=None):
        # Clipboard access belongs to the already trusted desktop. Copy is a
        # separate operator gesture; it never fills the answer or approves.
        if (self._active and self._decision is None and self._challenge is not None
                and time.monotonic() < self._deadline):
            self._root.clipboard_clear()
            self._root.clipboard_append(self._challenge)
            self._entry.focus_set()
            self._feedback.configure(text="Copied. Paste with Ctrl+V, then choose Approve once.")
        return "break"

    def _approve(self):
        if not self._active or self._decision is not None:
            return
        if time.monotonic() >= self._deadline:
            self._decision = False
        elif self._entry.get() == self._challenge:
            self._decision = True
        else:
            self._feedback.configure(text="The phrase does not match. Review the action and type the exact phrase.")
            self._entry.delete(0, "end")

    def review(self, action, policy, session_id, deadline, peer_fd):
        """Wait for direct window input; deadline or channel activity denies.

        The authority must wait for this response; any concurrently queued
        message is a protocol violation, never an affirmative input channel.
        """
        if self._closed or self._active:
            raise ValueError("graphical_review_unavailable")
        if type(deadline) not in (float, int) or not math.isfinite(deadline):
            raise ValueError("invalid_graphical_review_deadline")
        if policy.evaluate(action).decision != "approval_required":
            raise ValueError("graphical_review_not_required")
        poller = select.poll()
        poller.register(peer_fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        self._deadline = deadline
        # Disable acceptance while draining input from the previous transaction.
        self._approve_button.configure(state="disabled")
        self._copy_button.configure(state="disabled")
        self._challenge_text.set("")
        self._entry.delete(0, "end")
        self._challenge = None
        self._decision = None
        self._pump()
        self._entry.delete(0, "end")
        if time.monotonic() >= deadline or poller.poll(0):
            return False
        self._challenge = fresh_challenge(action)
        self._details.configure(state="normal")
        self._details.delete("1.0", "end")
        self._details.insert("1.0", review_text(action, policy, session_id))
        self._details.configure(state="disabled")
        self._details.yview_moveto(0)
        self._challenge_text.set(self._challenge)
        self._feedback.configure(text="Enter does not approve. The phrase is valid only for this review.")
        self._active = True
        self._approve_button.configure(state="normal")
        self._copy_button.configure(state="normal")
        try:
            self._root.deiconify()
            self._root.lift()
            self._entry.focus_set()
            while self._decision is None:
                if time.monotonic() >= deadline or poller.poll(0):
                    return False
                self._time_label.configure(text=f"Session time remaining: {max(0, math.ceil(deadline - time.monotonic()))} seconds")
                self._pump()
                if self._decision is None:
                    time.sleep(0.01)
            return self._decision is True and time.monotonic() < deadline and not poller.poll(0)
        except self._tk.TclError:
            return False
        finally:
            self._active = False
            self._challenge = None
            self._decision = None
            try:
                self._entry.delete(0, "end")
                self._challenge_text.set("")
                self._copy_button.configure(state="disabled")
                self._approve_button.configure(state="disabled")
                self._root.withdraw()
            except self._tk.TclError:
                self._closed = True

    def close(self):
        """Destroy the worker's graphical surface without approving anything."""
        self._decision = False
        self._active = False
        if not self._closed:
            self._closed = True
            try:
                self._root.destroy()
            except self._tk.TclError:
                pass
