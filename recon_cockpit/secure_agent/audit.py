"""Private JSONL events for downstream consumers, including a future PivotTrail."""

from __future__ import annotations

import json
import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class AuditUnavailable(RuntimeError):
    code = "audit_unavailable"


class AuditSink:
    """Keep one verified file descriptor; fsync every event before returning.

    Use a private operator-owned directory. No raw proposal, rationale, response
    body, headers, exception messages, or environment variables are logged. This
    omission avoids promising that regexes can discover arbitrary secrets.
    Local logs remain mutable by their owner or a compromised host.
    """

    def __init__(self, path: Path):
        self._fd: int | None = None
        self._path = Path(path)
        self._lock = threading.Lock()
        try:
            path = Path(path)
            missing_directories = []
            ancestor = path.parent
            while not ancestor.exists():
                missing_directories.append(ancestor)
                ancestor = ancestor.parent
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory = path.parent.stat()
            if directory.st_uid != os.getuid() or directory.st_mode & 0o077:
                raise AuditUnavailable("audit_directory_must_be_private")
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                         | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            self._fd = fd
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise AuditUnavailable("audit_file_must_be_private_regular_file")
            # Persist the audit filename and any new directory entries as well
            # as event data. File fsync alone does not persist its parent entry.
            for directory_path in dict.fromkeys(
                [path.parent] + [item.parent for item in missing_directories]
            ):
                directory_fd = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except (OSError, AuditUnavailable) as exc:
            self.close()
            raise AuditUnavailable("audit_unavailable") from exc

    def emit(self, event: dict) -> None:
        payload = {
            "event_schema_version": "1",
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "recon-cockpit.secure-agent",
            **event,
        }
        try:
            encoded = (json.dumps(payload, sort_keys=True, ensure_ascii=True,
                                  allow_nan=False) + "\n").encode("utf-8")
            if len(encoded) > 32768:
                raise AuditUnavailable("audit_event_too_large")
            with self._lock:
                if self._fd is None:
                    raise AuditUnavailable("audit_closed")
                current = os.fstat(self._fd)
                named = self._path.stat(follow_symlinks=False)
                if (current.st_nlink != 1 or current.st_mode & 0o077
                        or (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino)):
                    raise AuditUnavailable("audit_removed_or_replaced")
                # A lock also prevents torn events across cooperating processes.
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_EX)
                try:
                    offset = 0
                    while offset < len(encoded):
                        written = os.write(self._fd, encoded[offset:])
                        if written <= 0:
                            raise AuditUnavailable("audit_short_write")
                        offset += written
                    os.fsync(self._fd)
                finally:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
        except (OSError, TypeError, ValueError) as exc:
            raise AuditUnavailable("audit_unavailable") from exc

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
