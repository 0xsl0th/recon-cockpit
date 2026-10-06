"""Scope drafts and one asynchronous, read-only saved-evidence inspection.

This module never creates an assessment, executor, approval service or listener.
The UI owns this controller on its main thread; only detached inspection results
cross the bounded worker queue. Closing waits for the existing replay to finish.
"""

from copy import deepcopy
import os
from pathlib import Path
from queue import Empty, Queue
import stat
from threading import Thread

from ..secure_agent.assessment_inspection import inspect_saved_assessment
from ..secure_agent.configurable_scope import MAX_SCOPE_BYTES, encode, load_scope, validate_scope
from .presentation import present_report, scope_from_fields, scope_preview


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

    def snapshot(self):
        return deepcopy({"scope": self._scope, "preview": scope_preview(self._scope),
            "report": self._report, "path": self._path, "status": self._status,
            "error": self._error, "busy": self._busy, "closing": self._closing})

    def _open(self):
        if self._closing:
            raise ValueError("desktop_closed")

    def configure_scope(self, fields):
        self._open()
        scope = scope_from_fields(fields)
        self._scope = scope
        self._status = "Scope draft validated. No assessment has been started."
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
        self._open()
        if self._busy or (self._thread is not None and self._thread.is_alive()):
            raise ValueError("inspection_already_running")
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

        def inspect():
            try:
                result = present_report(inspect_saved_assessment(directory), directory)
                error = None
            except BaseException:
                result = None
                error = ("Evidence could not be replayed. Select a private assessment directory; "
                         "native tool evidence requires the supported Linux parser environment.")
            self._results.put((generation, result, error))

        self._thread = Thread(target=inspect, name="recon-evidence-reader", daemon=False)
        try:
            self._thread.start()
        except BaseException:
            self._busy = False
            self._thread = None
            self._error = "Evidence inspection could not start."
            self._status = self._error
            raise

    def poll(self):
        try:
            generation, report, error = self._results.get_nowait()
        except Empty:
            return False
        if generation != self._generation or self._closing:
            return False
        self._busy = False
        self._report, self._error = report, error
        self._status = error or ("Saved evidence replay finished. Read-only inspection; no assessment is running.")
        return True

    def close(self):
        """Return true only when no replay worker remains; never abandon it."""
        if not self._closing:
            self._closing = True
            self._generation += 1
        if self._thread is not None and self._thread.is_alive():
            self._status = "Finishing evidence inspection before closing…"
            return False
        while True:
            try:
                self._results.get_nowait()
            except Empty:
                break
        self._busy = False
        self._status = "Closed."
        return True
