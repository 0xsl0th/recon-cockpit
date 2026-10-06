"""Local Tk views for scope, dry-run lifecycle and saved evidence.

The controller owns validation, dry-run orchestration and evidence inspection.
There is deliberately no tool-execution or approval operation in these widgets.
"""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, font, ttk

from .presentation import safe_text
from .themes import palette


class CockpitWindow:
    """Swiss Industrial desktop shell around the shared offline controller."""

    FIELD_NAMES = ("scope_id", "http_target", "http_port", "http_path", "ssh_target", "ssh_port")

    def __init__(self, root, controller, *, theme="dark"):
        self.root, self.controller = root, controller
        palette(theme)
        self.theme = theme
        self.page = "overview"
        self._closing = False
        self._closed = False
        self._after_id = None
        self._last_snapshot = None
        self._rows = {}
        self._selected = None
        self._last_scope = None
        self.scope_fields = {name: tk.StringVar(root) for name in self.FIELD_NAMES}
        self.status_var = tk.StringVar(root, "Ready")
        self.error_var = tk.StringVar(root, "")
        self.scope_feedback = tk.StringVar(root, "Validate changes to update the planned actions.")
        self.root.title("Recon Cockpit · Offline desktop")
        self.root.geometry("1360x900")
        self.root.minsize(1120, 720)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self._configure_fonts()
        self._build()
        self.refresh()
        self._after_id = self.root.after(100, self._poll)

    def _configure_fonts(self):
        families = set(font.families(self.root))
        self.family = next((name for name in ("Cantarell", "DejaVu Sans", "Arial") if name in families),
                           "TkDefaultFont")
        self.mono = next((name for name in ("DejaVu Sans Mono", "Menlo", "Consolas") if name in families),
                         "TkFixedFont")
        font.nametofont("TkDefaultFont").configure(family=self.family, size=10)

    def _frame(self, parent, *, color=None, border=False, **kwargs):
        return tk.Frame(parent, background=color or self.colors["surface"],
                        highlightbackground=self.colors["border"], highlightthickness=int(border), **kwargs)

    def _label(self, parent, text="", *, size=10, bold=False, color=None, background=None, **kwargs):
        return tk.Label(parent, text=text, font=(self.family, size, "bold" if bold else "normal"),
                        foreground=color or self.colors["text"],
                        background=background or parent.cget("background"), anchor="w", **kwargs)

    def _button(self, parent, text, command, *, primary=False, **kwargs):
        c = self.colors
        return tk.Button(parent, text=text, command=command,
                         background=c["accent"] if primary else c["raised"],
                         foreground=c["accent_text"] if primary else c["text"],
                         activebackground=c["selection"], activeforeground=c["text"],
                         disabledforeground=c["muted"], borderwidth=0, relief="flat",
                         highlightthickness=1, highlightbackground=c["border"],
                         highlightcolor=c["accent"], padx=13, pady=8, cursor="hand2",
                         font=(self.family, 10, "bold" if primary else "normal"), **kwargs)

    def _build(self):
        c = self.colors = palette(self.theme)
        self.root.configure(background=c["background"])
        self.buttons, self.pages, self.nav_buttons = {}, {}, {}
        self.metrics_labels, self.metrics_details = [], []
        self.container = self._frame(self.root, color=c["background"])
        self.container.pack(fill="both", expand=True)
        self.container.grid_columnconfigure(1, weight=1)
        self.container.grid_rowconfigure(0, weight=1)
        self._build_rail()
        main = self._frame(self.container, color=c["background"])
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)
        self._build_header(main)
        error = self._label(main, textvariable=self.error_var, color=c["error"],
                            background=c["background"], padx=20, pady=2,
                            wraplength=1000, justify="left")
        error.grid(row=1, column=0, sticky="ew")
        content = self._frame(main, color=c["background"])
        content.grid(row=2, column=0, sticky="nsew", padx=18, pady=(4, 14))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        for name in ("overview", "scope", "evidence"):
            page = self._frame(content, color=c["background"])
            page.grid(row=0, column=0, sticky="nsew")
            self.pages[name] = page
        self._configure_tree_style()
        self._build_overview(self.pages["overview"])
        self._build_scope(self.pages["scope"])
        self._build_evidence(self.pages["evidence"])
        footer = self._frame(main, border=True)
        footer.grid(row=3, column=0, sticky="ew")
        footer.grid_columnconfigure(1, weight=1)
        self._label(footer, "●  OFFLINE DESKTOP", size=9, bold=True, color=c["success"],
                    padx=14, pady=10).grid(row=0, column=0, sticky="w")
        self._label(footer, textvariable=self.status_var, size=9,
                    color=c["muted"], padx=14, wraplength=700).grid(row=0, column=1, sticky="e")
        self.show_page(self.page)

    def _build_rail(self):
        c = self.colors
        rail = self._frame(self.container, color=c["rail"], width=182)
        rail.grid(row=0, column=0, sticky="ns")
        rail.grid_propagate(False)
        rail.grid_columnconfigure(0, weight=1)
        rail.grid_rowconfigure(5, weight=1)
        brand = self._frame(rail, color=c["rail"])
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(27, 5))
        mark = tk.Canvas(brand, width=27, height=36, background=c["rail"], highlightthickness=0)
        mark.pack(side="left", padx=(0, 9))
        for offset in (-6, 5, 16):
            mark.create_line(offset, 33, offset + 24, 3, fill=c["accent"], width=4)
        self._label(brand, "RECON\nCOCKPIT", size=16, bold=True, color="#F3F6F8",
                    justify="left").pack(side="left")
        self._label(rail, "INTELLIGENCE. ACTION. EVIDENCE.", size=7, color=c["rail_muted"],
                    padx=18).grid(row=1, column=0, sticky="w", pady=(4, 27))
        for row, (name, number, title) in enumerate((("overview", "01", "Overview"),
                                                   ("scope", "02", "Scope"),
                                                   ("evidence", "03", "Evidence")), 2):
            button = tk.Button(rail, text=f"{number}    {title}", anchor="w",
                               command=lambda page=name: self.show_page(page),
                               font=(self.family, 11), padx=16, pady=13, relief="flat",
                               borderwidth=0, highlightthickness=1, highlightcolor=c["accent"],
                               cursor="hand2")
            button.grid(row=row, column=0, sticky="ew", padx=10, pady=3)
            self.nav_buttons[name] = button
        notes = self._frame(rail, color=c["rail"])
        notes.grid(row=6, column=0, sticky="ew", padx=17, pady=22)
        self._label(notes, "LOCAL WORKSPACE", size=8, bold=True,
                    color=c["rail_muted"]).pack(anchor="w", pady=(0, 10))
        self._label(notes, "●  Saved evidence", size=10, color=c["rail_text"]).pack(anchor="w")
        self._label(notes, "Scope preparation\nDry-run planning\nEvidence inspection", size=9,
                    color=c["rail_muted"], justify="left").pack(anchor="w", pady=(7, 18))
        self._label(notes, "Know more.\nTake informed action.", size=10, bold=True,
                    color=c["rail_text"], justify="left").pack(anchor="w")

    def _build_header(self, parent):
        header = self._frame(parent, border=True)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        labelbox = self._frame(header)
        labelbox.grid(row=0, column=0, sticky="w", padx=20, pady=13)
        self._label(labelbox, "OWNED LAB  /  ASSESSMENT WORKSPACE", size=8,
                    color=self.colors["muted"], bold=True).pack(anchor="w")
        self.engagement_label = self._label(labelbox, "Local evidence workspace", size=15, bold=True)
        self.engagement_label.pack(anchor="w", pady=(3, 0))
        self.buttons["theme"] = self._button(header, "Light theme" if self.theme == "dark" else "Dark theme",
                                               self.toggle_theme)
        self.buttons["theme"].grid(row=0, column=1, padx=8)
        self.buttons["load_evidence"] = self._button(header, "Open evidence folder", self._choose_evidence,
                                                       primary=True)
        self.buttons["load_evidence"].grid(row=0, column=2, padx=(0, 17))

    def _heading(self, parent, title, subtitle):
        box = self._frame(parent, color=self.colors["background"])
        self._label(box, title, size=18, bold=True).pack(anchor="w")
        self._label(box, subtitle, size=10, color=self.colors["muted"]).pack(anchor="w", pady=(4, 0))
        return box

    def _card(self, parent, title):
        card = self._frame(parent, border=True)
        card.grid_columnconfigure(0, weight=1)
        self._label(card, title.upper(), size=9, bold=True, padx=13, pady=11).grid(row=0, column=0, sticky="ew")
        return card

    def _text(self, parent, *, height=6, mono=False):
        frame = self._frame(parent)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        text = tk.Text(frame, height=height, width=1, wrap="word", borderwidth=0,
                       highlightthickness=0, background=self.colors["surface"],
                       foreground=self.colors["text"], selectbackground=self.colors["selection"],
                       selectforeground=self.colors["text"], padx=13, pady=9, spacing3=5,
                       font=(self.mono if mono else self.family, 10), state="disabled")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        text.bind("<Tab>", lambda event: self._focus_next(event.widget))
        return frame, text

    @staticmethod
    def _focus_next(widget):
        widget.tk_focusNext().focus_set()
        return "break"

    @staticmethod
    def _set_text(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", str(value))
        widget.configure(state="disabled")

    def _configure_tree_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        c = self.colors
        style.configure("Cockpit.Treeview", background=c["surface"], fieldbackground=c["surface"],
                        foreground=c["text"], borderwidth=0, bordercolor=c["surface"],
                        lightcolor=c["surface"], darkcolor=c["surface"],
                        rowheight=40, font=(self.family, 9))
        style.configure("Cockpit.Treeview.Heading", background=c["raised"], foreground=c["muted"],
                        borderwidth=0, padding=(7, 9), font=(self.family, 9, "bold"))
        style.map("Cockpit.Treeview", background=[("selected", c["selection"])],
                  foreground=[("selected", c["text"])])
        style.map("Cockpit.Treeview.Heading", background=[("active", c["raised"])])
        for orientation in ("Vertical", "Horizontal"):
            name = orientation + ".TScrollbar"
            style.configure(name, background=c["raised"], troughcolor=c["surface"],
                            bordercolor=c["surface"], arrowcolor=c["muted"],
                            lightcolor=c["raised"], darkcolor=c["raised"])
            style.map(name, background=[("active", c["selection"])])

    def _table(self, parent, *, height=7):
        frame = self._frame(parent)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=("step", "tool", "target", "status"), show="headings",
                            height=height, selectmode="browse", style="Cockpit.Treeview")
        for name, title, width, stretch in (("step", "#", 36, False), ("tool", "Recorded action", 185, True),
                                           ("target", "Destination", 145, True), ("status", "Result", 92, False)):
            tree.heading(name, text=title, anchor="w")
            tree.column(name, width=width, minwidth=width if not stretch else 70, stretch=stretch, anchor="w")
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.bind("<<TreeviewSelect>>", lambda event, table=tree: self._select_row(table))
        return frame, tree

    def _build_overview(self, page):
        page.grid_columnconfigure(0, weight=3)
        page.grid_columnconfigure(1, weight=2)
        page.grid_rowconfigure(2, weight=3)
        page.grid_rowconfigure(3, weight=2)
        self._heading(page, "Assessment overview", "Inspect saved work or rehearse the owned-lab plan.").grid(
            row=0, column=0, sticky="ew", pady=(0, 16))
        controls = self._frame(page, color=self.colors["background"])
        controls.grid(row=0, column=1, sticky="e", pady=(0, 16))
        self.buttons["start_dry_run"] = self._button(controls, "Start dry run…", self._start_dry_run,
                                                        primary=True)
        self.buttons["start_dry_run"].grid(row=0, column=0, padx=(0, 8))
        self.buttons["cancel_session"] = self._button(controls, "Cancel session", self._cancel_session)
        self.buttons["cancel_session"].grid(row=0, column=1)
        self._label(controls, "No tool execution or approvals", size=8, color=self.colors["muted"]).grid(
            row=1, column=0, columnspan=2, sticky="e", pady=(4, 0))
        metrics = self._frame(page, color=self.colors["background"])
        metrics.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        self.metric_titles = []
        for index, name in enumerate(("LEGITIMATE COMPLETION", "USEFUL ACTIONS", "UNNECESSARY REFUSALS",
                                       "MODEL CALLS / COST", "ELAPSED TIME")):
            metrics.grid_columnconfigure(index, weight=1, uniform="metrics")
            card = self._frame(metrics, border=True)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 4, 0 if index == 4 else 4))
            title = self._label(card, name, size=8, bold=True, color=self.colors["muted"])
            title.pack(anchor="w", padx=11, pady=(12, 4))
            self.metric_titles.append(title)
            value = self._label(card, "—", size=17, bold=True)
            value.pack(anchor="w", padx=11)
            detail = self._label(card, "No evidence loaded", size=8, color=self.colors["muted"],
                                 wraplength=175, justify="left")
            detail.pack(anchor="w", padx=11, pady=(5, 12))
            self.metrics_labels.append(value)
            self.metrics_details.append(detail)
        timeline = self._card(page, "Session timeline")
        timeline.grid(row=2, column=0, sticky="nsew", padx=(0, 7), pady=(0, 13))
        timeline.grid_rowconfigure(2, weight=1)
        self.timeline_state = self._label(timeline, "Open an evidence folder to inspect a saved assessment.",
                                         size=9, color=self.colors["muted"], padx=13)
        self.timeline_state.grid(row=1, column=0, sticky="ew", pady=(0, 9))
        frame, self.timeline = self._table(timeline, height=6)
        frame.grid(row=2, column=0, sticky="nsew", padx=1)
        detail = self._card(page, "Action detail")
        detail.grid(row=2, column=1, sticky="nsew", padx=(7, 0), pady=(0, 13))
        detail.grid_rowconfigure(1, weight=1)
        frame, self.selected_detail = self._text(detail, height=10, mono=True)
        frame.grid(row=1, column=0, sticky="nsew")
        bundle = self._card(page, "Evidence bundle")
        bundle.grid(row=3, column=0, sticky="nsew", padx=(0, 7))
        bundle.grid_rowconfigure(1, weight=1)
        frame, self.bundle_detail = self._text(bundle, height=5)
        frame.grid(row=1, column=0, sticky="nsew")
        limits = self._card(page, "Interpretation & boundaries")
        limits.grid(row=3, column=1, sticky="nsew", padx=(7, 0))
        limits.grid_rowconfigure(1, weight=1)
        frame, self.limitations = self._text(limits, height=5)
        frame.grid(row=1, column=0, sticky="nsew")

    def _build_scope(self, page):
        page.grid_columnconfigure(0, weight=1)
        page.grid_columnconfigure(1, weight=1)
        page.grid_rowconfigure(4, weight=1)
        self._heading(page, "Prepare owned scope", "Configure two disconnected fixture endpoints for a dry run or CLI execution.").grid(
            row=0, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        identity = self._card(page, "Scope identity")
        identity.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        self._entry(identity, "Scope ID", "scope_id", row=1)
        for column, (title, fields) in enumerate((("HTTP fixture", (("IPv4 address", "http_target"),
                ("Port", "http_port"), ("Origin path", "http_path"))),
                ("SSH fixture", (("IPv4 address", "ssh_target"), ("Port", "ssh_port"))))):
            card = self._card(page, title)
            card.grid(row=2, column=column, sticky="nsew", padx=(0, 7) if column == 0 else (7, 0))
            for row, (label, field) in enumerate(fields, 1):
                self._entry(card, label, field, row=row)
        controls = self._frame(page, color=self.colors["background"])
        controls.grid(row=3, column=0, columnspan=2, sticky="ew", pady=13)
        self.buttons["validate_scope"] = self._button(controls, "Validate scope", self.validate_scope, primary=True)
        self.buttons["validate_scope"].pack(side="left", padx=(0, 10))
        self.buttons["import_scope"] = self._button(controls, "Import scope…", self._choose_scope)
        self.buttons["import_scope"].pack(side="left", padx=(0, 10))
        self.buttons["export_scope"] = self._button(controls, "Export scope…", self._export_scope)
        self.buttons["export_scope"].pack(side="left")
        self._label(controls, textvariable=self.scope_feedback, size=9, color=self.colors["muted"],
                    wraplength=400, justify="left").pack(side="right", padx=(12, 0))
        planned = self._card(page, "Planned actions · validated draft")
        planned.grid(row=4, column=0, columnspan=2, sticky="nsew")
        planned.grid_rowconfigure(1, weight=1)
        frame, self.scope_preview = self._text(planned, height=6, mono=True)
        frame.grid(row=1, column=0, sticky="nsew")

    def _entry(self, parent, label, name, *, row):
        box = self._frame(parent)
        box.grid(row=row, column=0, sticky="ew", padx=13, pady=(0, 12))
        box.grid_columnconfigure(1, weight=1)
        self._label(box, label, size=10, color=self.colors["muted"], width=13).grid(row=0, column=0, sticky="w")
        entry = tk.Entry(box, textvariable=self.scope_fields[name], background=self.colors["input"],
                         foreground=self.colors["text"], insertbackground=self.colors["text"],
                         selectbackground=self.colors["selection"], selectforeground=self.colors["text"],
                         relief="flat", borderwidth=0, highlightthickness=1,
                         highlightbackground=self.colors["border"], highlightcolor=self.colors["accent"],
                         font=(self.mono, 10))
        entry.grid(row=0, column=1, sticky="ew", ipady=8)
        entry.bind("<Return>", lambda _event: self.validate_scope())

    def _build_evidence(self, page):
        page.grid_columnconfigure(0, weight=3)
        page.grid_columnconfigure(1, weight=2)
        page.grid_rowconfigure(2, weight=1)
        self._heading(page, "Evidence inspection", "Read-only reconciliation of local assessment artifacts.").grid(
            row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        self.evidence_path = self._label(page, "No evidence folder selected", size=9, color=self.colors["muted"],
                                         wraplength=1030, justify="left")
        self.evidence_path.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        card = self._card(page, "Recorded actions")
        card.grid(row=2, column=0, sticky="nsew", padx=(0, 7))
        card.grid_rowconfigure(1, weight=1)
        frame, self.evidence_table = self._table(card, height=10)
        frame.grid(row=1, column=0, sticky="nsew")
        details = self._card(page, "Observation detail · untrusted text")
        details.grid(row=2, column=1, sticky="nsew", padx=(7, 0))
        details.grid_rowconfigure(1, weight=1)
        frame, self.evidence_detail = self._text(details, height=14, mono=True)
        frame.grid(row=1, column=0, sticky="nsew")

    def show_page(self, name):
        if name not in self.pages:
            raise ValueError("unknown_desktop_page")
        self.page = name
        self.pages[name].tkraise()
        for page, button in self.nav_buttons.items():
            selected = page == name
            button.configure(background=self.colors["accent"] if selected else self.colors["rail"],
                             foreground=self.colors["accent_text"] if selected else self.colors["rail_text"],
                             activebackground=self.colors["accent"] if selected else self.colors["selection"],
                             activeforeground=self.colors["accent_text"] if selected else self.colors["rail_text"],
                             highlightbackground=self.colors["accent"] if selected else self.colors["rail"])

    def toggle_theme(self):
        if self._closing:
            return
        self.theme = "light" if self.theme == "dark" else "dark"
        self.container.destroy()
        self._build()
        self.refresh()

    def _fill_scope(self, scope):
        self.scope_fields["scope_id"].set(scope["scope_id"])
        for service in ("http", "ssh"):
            for field, value in scope[service].items():
                self.scope_fields[f"{service}_{field}"].set(str(value))
        self._last_scope = scope

    def refresh(self):
        snapshot = self.controller.snapshot()
        self._last_snapshot = snapshot
        if snapshot["scope"] != self._last_scope:
            self._fill_scope(snapshot["scope"])
        self.error_var.set(safe_text(snapshot["error"]) if snapshot.get("error") else "")
        self.status_var.set("Finishing background work and cleanup…" if self._closing else safe_text(snapshot.get("status", "Ready")))
        busy = snapshot["busy"]
        for name in ("load_evidence", "start_dry_run"):
            self.buttons[name].configure(state="disabled" if busy or self._closing else "normal")
        session = snapshot.get("session")
        cancellable = (snapshot.get("operation") == "session" and busy and session is not None
                       and session.get("phase") == "running" and not session.get("cancel_requested"))
        self.buttons["cancel_session"].configure(state="normal" if cancellable and not self._closing else "disabled")
        preview = snapshot.get("preview", {})
        lines = [str(preview.get("notice", "Scope preparation does not launch an assessment.")), ""]
        for row in preview.get("rows", []):
            destination = row["target"]
            if str(row["step"]) == "2":
                destination += "  GET " + snapshot["scope"]["http"]["path"]
            lines.append(f"{row['step']}. {row['tool']}  →  {destination}")
        limits = preview.get("limits")
        if limits:
            lines += ["", f"Session limits: {limits['max_steps']} actions · "
                      f"{limits['max_runtime_seconds']} seconds · "
                      f"{limits['max_output_bytes']:,} output bytes"]
        if preview.get("scope_sha256"):
            lines += ["", "Scope digest: " + preview["scope_sha256"]]
        self._set_text(self.scope_preview, "\n".join(lines))
        report = snapshot.get("report")
        self._render_report(report, snapshot.get("path"))
        if report is None and session is not None:
            self._render_session(session)
        elif report is not None and session is not None and session.get("phase") in {"failed", "stopped"}:
            label = "FAILED" if session["phase"] == "failed" else "STOPPED"
            self.timeline_state.configure(text=f"DRY RUN {label} · Saved evidence",
                                          foreground=self.colors["error"] if label == "FAILED" else self.colors["muted"])
        elif busy and snapshot.get("operation") != "session":
            self.engagement_label.configure(text="Replaying saved evidence…")
            self.timeline_state.configure(text="Inspecting recorded artifacts. No assessment is running.",
                                          foreground=self.colors["muted"])
            self.evidence_path.configure(text=safe_text(snapshot.get("path")))

    def _render_session(self, session):
        """Display observed dry-run progress without claiming useful execution."""
        scope = session.get("scope") or {}
        self.engagement_label.configure(text=safe_text(scope.get("scope_id", "Owned-lab dry run"))[:55])
        phase = session.get("phase")
        failed = phase in {"failed", "replay_failed"}
        if phase == "failed":
            state = "DRY RUN FAILED · No verified outcome"
        elif phase == "replay_failed":
            state = "EVIDENCE REPLAY FAILED · No verified outcome"
        elif phase == "stopped":
            state = "DRY RUN STOPPED · No tool execution"
        elif phase == "replaying":
            state = "DRY RUN · Replaying final evidence"
        elif session.get("cancel_requested") and phase == "running":
            state = "DRY RUN · Cancellation requested; waiting for cleanup"
        else:
            state = "DRY RUN · " + safe_text(session.get("state", phase or "Preparing"))
        self.timeline_state.configure(text=state, foreground=self.colors["error"] if failed else self.colors["muted"])
        directory = safe_text(session.get("session_dir", "Preparing a private session folder"))
        self.evidence_path.configure(text=directory)
        live_metrics = (("Dry run", "No legitimate tool work is executed."),
                        ("0", "Dry-run decisions do not count as useful actions."),
                        ("Unavailable", "Not graded for a dry run."),
                        ("—", "Model access is disabled."),
                        ("—", "Final recorded duration appears after evidence replay."))
        for index, (value, detail) in enumerate(live_metrics):
            self.metrics_labels[index].configure(text=value)
            self.metrics_details[index].configure(text=detail)
        lines = ["Mode  Dry run · no tool execution", "State  " + safe_text(session.get("state", "Preparing")),
                 "Session  " + safe_text(session.get("session_id", "Preparing")), "", "Session scope"]
        for name in ("http", "ssh"):
            endpoint = scope.get(name)
            if endpoint:
                destination = safe_text(endpoint.get("target")) + ":" + safe_text(endpoint.get("port"))
                if name == "http":
                    destination += "  GET " + safe_text(endpoint.get("path"))
                lines.append(name.upper() + "  " + destination)
        lines += ["", "Folder  " + directory]
        if session.get("scope_sha256"):
            lines += ["Scope digest  " + safe_text(session["scope_sha256"])]
        if session.get("stop_reason"):
            lines += ["Stop reason  " + safe_text(session["stop_reason"])]
        self._set_text(self.bundle_detail, "\n".join(lines))
        self._set_text(self.limitations,
            "This session rehearses the owned-lab plan. No tools, model calls or approval grants are issued.\n\n"
            "Progress is provisional until final evidence replay. Dry-run decisions are not legitimate task completion.\n\n"
            "The session uses its captured scope. Editing the draft does not change the current session.")
        self._replace_rows(session.get("steps", []))

    def _render_report(self, report, path):
        if report is None:
            self.engagement_label.configure(text="Local evidence workspace")
            self.timeline_state.configure(text="Start a dry run or open an evidence folder.",
                                          foreground=self.colors["muted"])
            self.evidence_path.configure(text="No evidence folder selected")
            self._set_text(self.bundle_detail, "No saved assessment loaded.\n\nOpen a private evidence folder to inspect its recorded actions and outcomes.")
            self._set_text(self.limitations, "This desktop prepares scope, rehearses dry-run plans and reads saved evidence.\n\nTool execution and personal approvals remain in the CLI. Model credentials and paid calls remain deferred.")
            self._set_text(self.selected_detail, "Select a recorded action to view its exact destination and observation.\n\nTool output is displayed as untrusted text.")
            self._set_text(self.evidence_detail, "No observation selected.")
            for widget in self.metrics_labels:
                widget.configure(text="—")
            for widget in self.metrics_details:
                widget.configure(text="No evidence loaded")
            self._replace_rows([])
            return
        recorded_scope = report.get("scope")
        title = (safe_text(recorded_scope["scope_id"]) if recorded_scope else
                 report.get("title", "Saved assessment"))
        self.engagement_label.configure(text=title[:55])
        outcome = str(report.get("outcome", "unavailable"))
        issues = report.get("integrity_issues", [])
        state = "INTEGRITY ISSUES · See boundaries" if issues else f"{outcome.upper()}  ·  Saved session"
        self.timeline_state.configure(text=state, foreground=self.colors["error"] if issues else self.colors["muted"])
        shown_path = safe_text(path) if path else report.get("source_path", "Saved evidence")
        self.evidence_path.configure(text=shown_path)
        for index, metric in enumerate(report.get("metrics", [])[:5]):
            self.metric_titles[index].configure(text=str(metric["label"]).upper())
            self.metrics_labels[index].configure(text=str(metric["value"]))
            self.metrics_details[index].configure(text=str(metric.get("detail", "")))
        lines = ["Assessment  " + str(report.get("assessment_id", "Unavailable")),
                 "Outcome  " + outcome,
                 "Workflow  " + str(report.get("workflow", "Unavailable")),
                 "Session  " + str(report.get("session_id", "Unavailable")), "",
                 "Source  " + shown_path]
        if report.get("recorded_scope_text"):
            lines += ["", "Recorded scope", str(report["recorded_scope_text"])]
        self._set_text(self.bundle_detail, "\n".join(lines))
        notes = ["INTEGRITY ISSUES\n" + "\n".join("• " + str(issue) for issue in issues)] if issues else []
        notes.extend("• " + str(item) for item in report.get("limitations", []))
        self._set_text(self.limitations, "\n\n".join(notes) or "No interpretation details available.")
        self._replace_rows(report.get("rows", []))

    def _replace_rows(self, rows):
        self._rows = {str(row["id"]): row for row in rows}
        for table in (self.timeline, self.evidence_table):
            table.delete(*table.get_children())
            for row in rows:
                table.insert("", "end", iid=str(row["id"]), values=(row["step"], row["tool"], row["target"], row["status"]))
        if self._selected not in self._rows:
            self._selected = next(iter(self._rows), None)
        if self._selected:
            for table in (self.timeline, self.evidence_table):
                table.selection_set(self._selected)
            self._display_row(self._selected)
        elif rows == []:
            self._set_text(self.selected_detail, "No recorded action is available in this evidence bundle.")
            self._set_text(self.evidence_detail, "No recorded action is available in this evidence bundle.")

    def _select_row(self, table):
        selection = table.selection()
        if selection and selection[0] in self._rows:
            self._selected = selection[0]
            for other in (self.timeline, self.evidence_table):
                if other.selection() != selection:
                    other.selection_set(self._selected)
            self._display_row(self._selected)

    def _display_row(self, identifier):
        row = self._rows[identifier]
        detail = (f"{row['tool']}\n\nDestination  {row['target']}\nResult       {row['status']}\n\n"
                  + str(row.get("detail", "No structured observation available.")))
        self._set_text(self.selected_detail, detail)
        self._set_text(self.evidence_detail, detail)

    def validate_scope(self):
        if self._closing:
            return False
        try:
            self.controller.configure_scope({name: value.get() for name, value in self.scope_fields.items()})
        except (ValueError, OSError) as exc:
            self.scope_feedback.set("Scope is invalid. Check the ID, private IPv4 addresses, ports and path.")
            self.error_var.set(safe_text(str(exc)))
            return False
        self.scope_feedback.set("Valid draft · four bounded actions. Ready for a dry run or export.")
        self.refresh()
        return True

    def _choose_scope(self):
        if self._closing:
            return
        path = filedialog.askopenfilename(parent=self.root, title="Import owned scope",
                                          filetypes=(("JSON scope", "*.json"), ("All files", "*")))
        if path:
            try:
                self.controller.load_scope_file(Path(path))
                self._last_scope = None
                self.scope_feedback.set("Scope imported and validated.")
                self.refresh()
            except (ValueError, OSError) as exc:
                self.error_var.set("Could not import scope: " + safe_text(str(exc)))

    def _export_scope(self):
        if not self.validate_scope():
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export owned scope to a new file",
                                           defaultextension=".json", initialfile="owned-scope.json",
                                           confirmoverwrite=False, filetypes=(("JSON scope", "*.json"),))
        if path:
            try:
                self.controller.export_scope_file(Path(path))
                self.scope_feedback.set("Validated scope exported privately.")
                self.error_var.set("")
            except (ValueError, OSError) as exc:
                self.error_var.set("Could not export scope; choose a new file. " + safe_text(str(exc)))

    def _choose_evidence(self):
        if self._closing:
            return
        path = filedialog.askdirectory(parent=self.root, title="Open private assessment evidence folder", mustexist=True)
        if path:
            try:
                self.controller.inspect_directory(Path(path))
                self.refresh()
            except (ValueError, OSError, RuntimeError) as exc:
                self.error_var.set("Could not inspect evidence: " + safe_text(str(exc)))

    def _start_dry_run(self):
        if self._closing or self.controller.snapshot()["busy"]:
            return
        if not self.validate_scope():
            self.show_page("scope")
            return
        path = filedialog.askdirectory(parent=self.root, title="Choose a parent folder for a new private dry-run session",
                                        mustexist=True)
        if path:
            try:
                self.controller.start_dry_run(Path(path))
                self.show_page("overview")
                self.refresh()
            except (ValueError, OSError, RuntimeError) as exc:
                self.error_var.set("Could not start dry run: " + safe_text(str(exc)))

    def _cancel_session(self):
        if self._closing:
            return
        try:
            self.controller.cancel_session()
            self.refresh()
        except (ValueError, OSError, RuntimeError) as exc:
            self.error_var.set("Could not cancel session: " + safe_text(str(exc)))

    def _poll(self):
        self._after_id = None
        if self._closed:
            return
        changed = self.controller.poll()
        if changed:
            self.refresh()
        if self._closing and self.controller.close():
            self._finish_close()
            return
        self._after_id = self.root.after(100, self._poll)

    def close(self):
        if self._closed:
            return
        self._closing = True
        if self.controller.close():
            self._finish_close()
        else:
            self.status_var.set("Finishing background work and cleanup…")
            for button in self.buttons.values():
                button.configure(state="disabled")

    def _finish_close(self):
        self._closed = True
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
            self._after_id = None
        self.root.destroy()


# Kept as a descriptive alias for embedding applications and UI smoke helpers.
DesktopWindow = CockpitWindow
