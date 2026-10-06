"""One desktop operation: saved replay or a shared-authority dry-run session.

The UI owns this controller on its main thread. One non-daemon worker owns the
whole run/cleanup/replay lifetime. No execution or approval input is exposed.
"""

from copy import deepcopy
import os
from pathlib import Path
from queue import Empty, Queue
import stat
import sys
import tempfile
from threading import Thread

from ..secure_agent.assessment_inspection import inspect_saved_assessment
from ..secure_agent.configurable_scope import MAX_SCOPE_BYTES, encode, load_scope, validate_scope
from ..secure_agent.configurable_contract import encode as encode_contract, policy_for_scope
from ..secure_agent.configurable_service import ConfigurableAssessmentRequest, ConfigurableAssessmentService
from ..secure_agent.execution import ExecutionStopped
from .presentation import present_report, present_session, scope_from_fields, scope_preview


DEFAULT_SCOPE = {
    "schema_version": "1", "scope_id": "owned-http-ssh-primary",
    "http": {"target": "10.77.0.10", "port": 8080, "path": "/harbordesk/portal.html"},
    "ssh": {"target": "10.77.0.20", "port": 2222},
}


def read_scope_file(path):
    """Read a finite regular file without following a final symlink or FIFO."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SCOPE_BYTES:
            raise ValueError("invalid_scope_file")
        raw = os.read(descriptor, MAX_SCOPE_BYTES + 1)
        return load_scope(raw)
    finally:
        os.close(descriptor)


class DesktopController:
    """A draft and a saved session stay separate; neither authorizes execution."""

    def __init__(self):
        self._scope = validate_scope(DEFAULT_SCOPE)
        self._report = None
        self._path = None
        self._status = "Choose saved evidence or configure an owned fixture scope."
        self._error = None
        self._busy = False
        self._closing = False
        self._generation = 0
        self._thread = None
        self._results = Queue(maxsize=1)
        self._operation = None
        self._service = None
        self._session = None
        self._session_dir = None
        self._cancel_requested = False

    def snapshot(self):
        return deepcopy({"scope": self._scope, "preview": scope_preview(self._scope),
            "report": self._report, "path": self._path, "status": self._status,
            "error": self._error, "busy": self._busy, "closing": self._closing,
            "operation": self._operation, "session": self._session})

    def _open(self):
        if self._closing:
            raise ValueError("desktop_closed")

    def _idle(self):
        self._open()
        if self._busy or (self._thread is not None and self._thread.is_alive()):
            raise ValueError("inspection_already_running" if self._operation == "inspection"
                             else "desktop_operation_running")

    def configure_scope(self, fields):
        self._open()
        scope = scope_from_fields(fields)
        self._scope = scope
        self._status = ("Scope draft validated. The running session keeps its original scope." if
                        self._operation == "session" else "Scope draft validated. No assessment has been started.")
        self._error = None
        return self.snapshot()

    def load_scope_file(self, path):
        self._open()
        self._scope = read_scope_file(Path(path))
        self._status = "Scope imported into the draft. Saved session scope is unchanged."
        self._error = None
        return self.snapshot()

    def export_scope_file(self, path):
        self._open()
        raw = encode(self._scope) + b"\n"
        # The file chooser supplies an explicit destination. Never overwrite an
        # existing file or follow its final symlink; exported scope is private.
        descriptor = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        self._status = "Scope draft exported. This file does not authorize network access."

    def inspect_directory(self, path):
        self._idle()
        directory = Path(path).absolute()
        self._generation += 1
        generation = self._generation
        self._busy = True
        self._error = None
        # Do not display old successful evidence while a different directory is
        # being checked, or after that inspection fails.
        self._report = None
        self._path = str(directory)
        self._status = "Replaying saved evidence…"
        self._operation = "inspection"
        self._service = self._session = self._session_dir = None

        def inspect():
            try:
                result = present_report(inspect_saved_assessment(directory), directory)
                error = None
            except BaseException:
                result = None
                error = ("Evidence could not be replayed. Select a private assessment directory; "
                         "native tool evidence requires the supported Linux parser environment.")
            self._results.put((generation, result, error, None))

        self._thread = Thread(target=inspect, name="recon-evidence-reader", daemon=False)
        try:
            self._thread.start()
        except BaseException:
            self._busy = False
            self._operation = None
            self._thread = None
            self._error = "Evidence inspection could not start."
            self._status = self._error
            raise

    def start_dry_run(self, parent):
        """Start fresh authority with execution disabled; never resume a bundle.

        The selected parent must be an existing operator-owned directory without
        group/other write access. A new private random child holds audit/evidence.
        No service factory, policy override, execute flag or approval callback is
        accepted from widgets. The immutable request freezes the current draft.
        """
        self._idle()
        if sys.platform != "linux":
            raise ValueError("dry_run_requires_supported_linux")
        parent = Path(parent).absolute()
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise ValueError("select_owned_nonwritable_session_parent")
        scope = encode(self._scope)
        policy = encode_contract(policy_for_scope(self._scope, require_approval=True).to_dict())
        directory = Path(tempfile.mkdtemp(prefix="recon-dry-run-", dir=parent))
        request = ConfigurableAssessmentRequest(scope_json=scope, policy_json=policy,
            assessment_dir=directory / "evidence", audit_path=directory / "audit.jsonl", execute=False)
        service = ConfigurableAssessmentService(request)
        self._service, self._session_dir = service, directory
        self._cancel_requested = False
        self._generation += 1
        generation = self._generation
        self._operation, self._busy = "session", True
        self._report = self._error = None
        self._path = str(request.assessment_dir)
        self._session = self._session_view("running")
        self._status = "Starting dry run. No tools or model calls will execute."

        def run():
            error, phase = None, "finished"
            try:
                service.run(interactive_terminal=False)
            except ExecutionStopped:
                phase = "stopped"
            except BaseException:
                phase = "failed"
                error = ("Dry run failed. Check the supported Linux isolation requirements. "
                         "Any partial evidence remains in the new session folder.")
            # The service has closed its authority before replay begins. Never
            # promote its returned summary directly to verified GUI metrics.
            try:
                report = present_report(inspect_saved_assessment(request.assessment_dir),
                                        request.assessment_dir)
            except BaseException:
                report = None
                if phase == "finished":
                    phase = "replay_failed"
                    error = "Dry run ended, but its evidence could not be replayed. No outcome is verified."
            self._results.put((generation, report, error, phase))

        self._thread = Thread(target=run, name="recon-desktop-session", daemon=False)
        try:
            self._thread.start()
        except BaseException:
            service.cancel()
            self._cancel_requested = True
            self._busy, self._operation, self._thread = False, None, None
            self._session = self._session_view("failed")
            self._error = self._status = "Dry run worker could not start. The new private folder was retained."
            raise

    def _session_view(self, phase):
        return present_session(self._service.snapshot(), phase=phase,
            cancel_requested=self._cancel_requested, directory=self._session_dir)

    def cancel_session(self):
        """Request sticky cooperative cancellation; keep cleanup/replay owned."""
        self._open()
        if self._operation != "session" or not self._busy:
            return
        self._service.cancel()
        self._cancel_requested = True
        self._session = self._session_view(self._session["phase"])
        self._status = "Cancellation requested. Waiting for authority cleanup and evidence replay…"

    def poll(self):
        changed = False
        if self._closing:
            return False
        if self._operation == "session" and self._busy:
            state = self._service.snapshot()["state"]
            current = self._session_view("running" if state in {"ready", "running"} else "replaying")
            changed = current != self._session
            self._session = current
            if current["phase"] == "replaying":
                self._status = "Authority closed. Replaying dry-run evidence…"
            elif not self._cancel_requested:
                self._status = "Dry run in progress. No tools or model calls execute."
        # Queue publication can precede the thread's final return. Do not enable
        # another operation or report cleanup complete while that worker lives.
        if self._thread is not None and self._thread.is_alive():
            return changed
        try:
            generation, report, error, phase = self._results.get_nowait()
        except Empty:
            return changed
        if generation != self._generation or self._closing:
            return False
        self._busy = False
        self._operation = None
        self._report, self._error = report, error
        if phase is not None:
            self._session = self._session_view(phase)
            self._status = error or ("Dry run cancelled. No tools executed." if
                self._session["stop_reason"] == "session_cancelled" else
                "Dry run ended. No tools executed; useful completion is not established.")
        else:
            self._status = error or "Saved evidence replay finished. Read-only inspection; no assessment is running."
        return True

    def close(self):
        """Cancel authority, then wait for run/cleanup/replay; never abandon it."""
        if not self._closing:
            if self._operation == "session" and self._busy:
                self.cancel_session()
            self._closing = True
            self._generation += 1
        if self._thread is not None and self._thread.is_alive():
            self._status = "Waiting for session cleanup and evidence inspection before closing…"
            return False
        while True:
            try:
                self._results.get_nowait()
            except Empty:
                break
        self._busy = False
        self._operation = None
        self._status = "Closed."
        return True
