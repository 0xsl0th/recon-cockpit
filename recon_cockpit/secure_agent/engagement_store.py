"""Private, offline engagement metadata; this store grants no execution authority.

SQLite commits state and its immutable receipt together. The trusted host and
filesystem are outside rollback protection; saved records never restore grants.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from uuid import UUID

from .engagement_contract import (
    EngagementError, canonical, request_digest, roe_digest, validate_export,
    validate_request, _operation_deadline, _using_deadline,
)

DATABASE = "records.sqlite3"
JOURNAL = DATABASE + "-journal"
MAX_DATABASE = 2097152
MAX_JOURNAL = 4194304
OPERATION_SECONDS = 2.0
MAX_PROGRESS_CALLBACKS = 2000
SCHEMA_SQL = ("CREATE TABLE revisions (revision INTEGER PRIMARY KEY CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 64), roe_json TEXT NOT NULL CHECK(typeof(roe_json)='text' AND length(roe_json) BETWEEN 1 AND 4096), roe_sha256 TEXT NOT NULL CHECK(typeof(roe_sha256)='text' AND length(roe_sha256)=64))", "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), engagement_id TEXT NOT NULL CHECK(typeof(engagement_id)='text' AND length(engagement_id)=36), current_revision INTEGER NOT NULL REFERENCES revisions(revision) CHECK(typeof(current_revision)='integer' AND current_revision BETWEEN 1 AND 64), generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 0 AND 64), status TEXT NOT NULL CHECK(status IN ('recorded','revoked')), last_sequence INTEGER NOT NULL CHECK(typeof(last_sequence)='integer' AND last_sequence BETWEEN 1 AND 65))", "CREATE TABLE events (sequence INTEGER PRIMARY KEY CHECK(typeof(sequence)='integer' AND sequence BETWEEN 1 AND 65), event_id TEXT NOT NULL UNIQUE CHECK(typeof(event_id)='text' AND length(event_id)=36), request_sha256 TEXT NOT NULL CHECK(typeof(request_sha256)='text' AND length(request_sha256)=64), receipt_json TEXT NOT NULL CHECK(typeof(receipt_json)='text' AND length(receipt_json) BETWEEN 1 AND 4096))", "CREATE TRIGGER immutable_revisions_update BEFORE UPDATE ON revisions BEGIN SELECT RAISE(ABORT,'engagement_immutable'); END", "CREATE TRIGGER immutable_revisions_delete BEFORE DELETE ON revisions BEGIN SELECT RAISE(ABORT,'engagement_immutable'); END", "CREATE TRIGGER immutable_events_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'engagement_immutable'); END", "CREATE TRIGGER immutable_events_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'engagement_immutable'); END")

_SCHEMA_OBJECTS = sorted(
    [("table", name, name, statement)
     for name, statement in zip(("revisions", "metadata", "events"), SCHEMA_SQL[:3])]
    + [("trigger", statement.split()[2],
        "revisions" if " ON revisions " in statement else "events", statement)
       for statement in SCHEMA_SQL[3:]]
    + [("index", "sqlite_autoindex_events_1", "events", None)], key=lambda row: row[1])
_LIMITS = {"LENGTH": 524288, "SQL_LENGTH": 16384, "COLUMN": 32,
           "EXPR_DEPTH": 32, "ATTACHED": 0, "VARIABLE_NUMBER": 64,
           "TRIGGER_DEPTH": 8}
_POISON_CODES = {"engagement_store_unavailable", "engagement_store_invalid",
                 "engagement_timeout", "engagement_snapshot_changed"}


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        if (parsed is None or str(parsed) != value or parsed.version != 4
                or parsed.variant != "specified in RFC 4122"):
            raise ValueError
    except (ValueError, AttributeError):
        raise EngagementError("engagement_invalid_input") from None
    return value


def _identity(info):
    return info.st_dev, info.st_ino


def _private_directory(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise EngagementError("engagement_store_unavailable")


def _private_file(info, maximum, *, empty=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not (0 if empty else 1) <= info.st_size <= maximum):
        raise EngagementError("engagement_store_unavailable")


class EngagementStore:
    """One engagement, with private process-owned connections and bounded history."""

    @classmethod
    def create(cls, directory, *, engagement_id, roe, event_id):
        deadline = _operation_deadline()
        opened = None
        try:
            with _using_deadline(deadline):
                request = validate_request({"schema_version": "1", "engagement_id": engagement_id,
                    "event_id": event_id, "operation": "create", "expected_revision": None,
                    "expected_generation": None, "roe": roe})
                opened = cls._open(directory, read_only=False, initial=request, deadline=deadline)
            return opened
        except BaseException:
            if opened is not None:
                opened._close_resources()
            raise

    @classmethod
    def open(cls, directory, *, read_only=False):
        deadline = _operation_deadline()
        opened = None
        try:
            with _using_deadline(deadline):
                if type(read_only) is not bool:
                    raise EngagementError("engagement_invalid_input")
                opened = cls._open(directory, read_only=read_only, initial=None, deadline=deadline)
            return opened
        except BaseException:
            if opened is not None:
                opened._close_resources()
            raise

    @classmethod
    def _open(cls, directory, *, read_only, initial, deadline):
        self = cls.__new__(cls)
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._db = self._parent_fd = self._directory_fd = None
        self._database_identity = self._parent_identity = self._directory_identity = None
        self._failed, self._read_only = False, read_only
        self._engagement_id = None
        self._deadline, self._callbacks, self._interrupted = deadline, 0, False
        try:
            requested = Path(directory).absolute()
            self.parent = requested.parent.resolve(strict=True)
            self.directory = self.parent / requested.name
            self._parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY
                                      | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._parent_identity = _identity(os.fstat(self._parent_fd))
            self._check_parent()
            self._check_deadline()
            if initial is not None:
                try:
                    os.mkdir(self.directory.name, mode=0o700, dir_fd=self._parent_fd)
                except FileExistsError:
                    raise EngagementError("engagement_already_exists") from None
            self._directory_fd = os.open(self.directory.name, os.O_RDONLY | os.O_DIRECTORY
                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._parent_fd)
            self._directory_identity = _identity(os.fstat(self._directory_fd))
            self._check_directory()
            if initial is not None:
                descriptor = os.open(DATABASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._directory_fd)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(self._directory_fd)
                os.fsync(self._parent_fd)
            info = os.stat(DATABASE, dir_fd=self._directory_fd, follow_symlinks=False)
            self._database_identity = _identity(info)
            self._check_files(empty=initial is not None, read_entry=read_only)
            # Do not open another DB descriptor: closing it can release this
            # process's SQLite locks, even on a different active connection.
            uri = (self.directory / DATABASE).as_uri() + ("?mode=ro" if read_only else "?mode=rw")
            self._db = sqlite3.connect(uri, uri=True, timeout=0.25,
                isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._db.set_progress_handler(self._progress, 1000)
            for name, limit in _LIMITS.items():
                category = getattr(sqlite3, "SQLITE_LIMIT_" + name)
                self._db.setlimit(category, limit)
                if self._db.getlimit(category) > limit:
                    raise EngagementError("engagement_store_unavailable")
            self._configure(initial=initial is not None)
            with self._transaction(write=initial is not None, deadline=deadline,
                                   initializing=initial is not None) as before:
                if initial is not None:
                    for statement in SCHEMA_SQL:
                        self._execute(statement)
                    self._execute("PRAGMA user_version=1")
                    digest = roe_digest(initial["roe"])
                    self._execute("INSERT INTO revisions VALUES (1,?,?)",
                                  (canonical(initial["roe"]).decode("ascii"), digest))
                    self._execute("INSERT INTO metadata VALUES (1,?,1,0,'recorded',1)",
                                  (initial["engagement_id"],))
                    self._insert_event(self._receipt(initial, revision=1, generation=0,
                        sequence=1, status="recorded", digest=digest))
                    before = self._snapshot_checked()
                self._engagement_id = before["engagement_id"]
            return self
        except BaseException as exc:
            self._close_resources()
            if isinstance(exc, EngagementError):
                raise
            if isinstance(exc, (OSError, sqlite3.Error, ValueError, TypeError, KeyError,
                                OverflowError, AttributeError)):
                raise EngagementError(self._failure_code(exc)) from None
            raise

    @property
    def engagement_id(self):
        return self._engagement_id

    def _check_owner(self):
        if self._pid != os.getpid():
            raise EngagementError("engagement_store_unavailable")

    def _check_deadline(self):
        if time.monotonic() >= self._deadline:
            raise EngagementError("engagement_timeout")

    def _progress(self):
        self._callbacks += 1
        if self._callbacks >= MAX_PROGRESS_CALLBACKS or time.monotonic() >= self._deadline:
            self._interrupted = True
            return 1
        return 0

    def _set_busy_timeout(self):
        self._check_deadline()
        remaining = max(0, min(250, int((self._deadline - time.monotonic()) * 1000)))
        self._db.execute(f"PRAGMA busy_timeout={remaining}")
        self._check_deadline()

    def _execute(self, statement, parameters=()):
        self._set_busy_timeout()
        result = self._db.execute(statement, parameters)
        self._check_deadline()
        return result

    def _configure(self, *, initial):
        for name, value in (("foreign_keys", 1), ("trusted_schema", 0),
                            ("fullfsync", 1), ("temp_store", 2)):
            self._execute(f"PRAGMA {name}={value}")
            if self._execute(f"PRAGMA {name}").fetchone()[0] != value:
                raise EngagementError("engagement_store_unavailable")
        if initial:
            self._execute("PRAGMA page_size=4096")
        if self._execute("PRAGMA page_size").fetchone()[0] != 4096:
            raise EngagementError("engagement_store_invalid")
        if self._execute("PRAGMA max_page_count=512").fetchone()[0] != 512:
            raise EngagementError("engagement_store_invalid")
        if not self._read_only:
            if self._execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
                raise EngagementError("engagement_store_unavailable")
        elif self._execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise EngagementError("engagement_store_invalid")
        self._execute("PRAGMA synchronous=EXTRA")
        if self._execute("PRAGMA synchronous").fetchone()[0] != 3:
            raise EngagementError("engagement_store_unavailable")
        if self._read_only:
            self._execute("PRAGMA query_only=ON")
            if self._execute("PRAGMA query_only").fetchone()[0] != 1:
                raise EngagementError("engagement_store_unavailable")

    def _check_parent(self):
        info = os.fstat(self._parent_fd)
        named = self.parent.stat(follow_symlinks=False)
        _private_directory(info)
        _private_directory(named)
        if _identity(info) != self._parent_identity or _identity(named) != self._parent_identity:
            raise EngagementError("engagement_store_unavailable")

    def _check_directory(self):
        self._check_parent()
        info = os.fstat(self._directory_fd)
        named = os.stat(self.directory.name, dir_fd=self._parent_fd, follow_symlinks=False)
        _private_directory(info)
        _private_directory(named)
        if _identity(info) != self._directory_identity or _identity(named) != self._directory_identity:
            raise EngagementError("engagement_store_unavailable")

    def _check_files(self, *, empty=False, read_entry=False):
        self._check_owner()
        if self._failed:
            raise EngagementError("engagement_store_unavailable")
        self._check_directory()
        info = os.stat(DATABASE, dir_fd=self._directory_fd, follow_symlinks=False)
        _private_file(info, MAX_DATABASE, empty=empty)
        if _identity(info) != self._database_identity:
            raise EngagementError("engagement_store_unavailable")
        # A concurrent SQLite writer may create/remove its valid journal. Only
        # transient disappearance of the one permitted name is benign.
        with os.scandir(self._directory_fd) as entries:
            for count, entry in enumerate(entries):
                if count >= 2 or entry.name not in {DATABASE, JOURNAL}:
                    raise EngagementError("engagement_store_unavailable")
                self._check_deadline()
        try:
            journal = os.stat(JOURNAL, dir_fd=self._directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            journal = None
        if journal is not None:
            _private_file(journal, MAX_JOURNAL, empty=True)
            if read_entry:
                raise EngagementError("engagement_store_unavailable")

    def _schema_checked(self):
        if self._execute("PRAGMA user_version").fetchone()[0] != 1:
            raise EngagementError("engagement_store_invalid")
        rows = self._execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name LIMIT 9").fetchall()
        if [tuple(row) for row in rows] != _SCHEMA_OBJECTS:
            raise EngagementError("engagement_store_invalid")
        if (self._execute("PRAGMA page_size").fetchone()[0] != 4096
                or self._execute("PRAGMA page_count").fetchone()[0] > 512
                or self._execute("PRAGMA quick_check(1)").fetchone()[0] != "ok"
                or self._execute("PRAGMA foreign_key_check").fetchone() is not None):
            raise EngagementError("engagement_store_invalid")

    def _snapshot_checked(self):
        self._schema_checked()
        try:
            metadata = self._execute("SELECT * FROM metadata LIMIT 2").fetchall()
            revisions = self._execute("SELECT * FROM revisions ORDER BY revision LIMIT 65").fetchall()
            events = self._execute("SELECT * FROM events ORDER BY sequence LIMIT 66").fetchall()
            if len(metadata) != 1 or metadata[0]["singleton"] != 1:
                raise ValueError
            item = metadata[0]
            parsed_revisions, parsed_events = [], []
            for row in revisions:
                roe = json.loads(row["roe_json"])
                if canonical(roe).decode("ascii") != row["roe_json"]:
                    raise ValueError
                parsed_revisions.append({"revision": row["revision"], "roe": roe,
                                         "roe_sha256": row["roe_sha256"]})
            for row in events:
                receipt = json.loads(row["receipt_json"])
                if (canonical(receipt).decode("ascii") != row["receipt_json"]
                        or receipt["sequence"] != row["sequence"]
                        or receipt["event_id"] != row["event_id"]
                        or receipt["request_sha256"] != row["request_sha256"]):
                    raise ValueError
                parsed_events.append(receipt)
            snapshot = validate_export({"schema_version": "1", "kind": "engagement-record-export",
                "engagement_id": item["engagement_id"], "state": {
                    "revision": item["current_revision"], "generation": item["generation"],
                    "status": item["status"], "last_sequence": item["last_sequence"]},
                "revisions": parsed_revisions, "events": parsed_events})
            if self._engagement_id is not None and snapshot["engagement_id"] != self._engagement_id:
                raise ValueError
            self._check_deadline()
            return snapshot
        except (EngagementError, ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError) as exc:
            if isinstance(exc, EngagementError) and exc.code == "engagement_timeout":
                raise
            raise EngagementError("engagement_store_invalid") from None

    def _failure_code(self, exc):
        if self._interrupted or (isinstance(exc, sqlite3.Error)
                and getattr(exc, "sqlite_errorcode", 0) & 255 in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)):
            return "engagement_timeout"
        return "engagement_store_unavailable"

    @contextmanager
    def _operation(self):
        self._check_owner()
        try:
            with _using_deadline(_operation_deadline()) as deadline:
                yield deadline
        except EngagementError as exc:
            if exc.code in _POISON_CODES:
                self._failed = True
            raise

    @contextmanager
    def _transaction(self, *, write=False, deadline=None, initializing=False):
        self._check_owner()
        deadline = _operation_deadline() if deadline is None else deadline
        try:
            with _using_deadline(deadline) as effective:
                with self._transaction_body(write=write, deadline=effective,
                                            initializing=initializing) as before:
                    yield before
        except EngagementError as exc:
            if exc.code in _POISON_CODES:
                self._failed = True
            raise

    @contextmanager
    def _transaction_body(self, *, write, deadline, initializing):
        self._check_owner()  # Before touching an inherited lock or connection.
        if self._failed or self._db is None:
            raise EngagementError("engagement_store_unavailable")
        if write and self._read_only:
            raise EngagementError("engagement_read_only")
        if not self._lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise EngagementError("engagement_timeout")
        try:
            self._deadline, self._callbacks, self._interrupted = deadline, 0, False
            self._check_deadline()
            self._check_files(empty=initializing, read_entry=self._read_only)
            self._db.set_progress_handler(self._progress, 1000)
            self._execute("BEGIN IMMEDIATE" if write else "BEGIN")
            before = None if initializing else self._snapshot_checked()
            yield before
            self._snapshot_checked()
            self._check_files(empty=initializing)
            self._set_busy_timeout()
            self._db.commit()
            self._check_deadline()
            self._check_files()
            self._check_deadline()
        except BaseException as exc:
            try:
                self._db.set_progress_handler(None, 0)
            except sqlite3.Error:
                self._failed = True
            try:
                self._db.rollback()
            except sqlite3.Error:
                self._failed = True
            if isinstance(exc, EngagementError):
                if exc.code in _POISON_CODES:
                    self._failed = True
                raise
            if isinstance(exc, (sqlite3.Error, OSError, ValueError, TypeError,
                                KeyError, IndexError, OverflowError)):
                self._failed = True
                raise EngagementError(self._failure_code(exc)) from None
            raise
        finally:
            self._lock.release()

    @staticmethod
    def _receipt(request, *, revision, generation, sequence, status, digest):
        return {"schema_version": "1", "engagement_id": request["engagement_id"],
            "event_id": request["event_id"], "sequence": sequence,
            "operation": request["operation"], "expected_revision": request["expected_revision"],
            "expected_generation": request["expected_generation"], "revision": revision,
            "generation": generation, "status": status, "roe_sha256": digest,
            "request_sha256": request_digest(request)}

    def _insert_event(self, receipt):
        self._execute("INSERT INTO events VALUES (?,?,?,?)", (receipt["sequence"],
            receipt["event_id"], receipt["request_sha256"], canonical(receipt).decode("ascii")))

    def _mutate(self, request, *, deadline):
        with self._transaction(write=True, deadline=deadline) as before:
            for event in before["events"]:
                if event["event_id"] == request["event_id"]:
                    old = {"schema_version": "1", "engagement_id": event["engagement_id"],
                        "event_id": event["event_id"], "operation": event["operation"],
                        "expected_revision": event["expected_revision"],
                        "expected_generation": event["expected_generation"],
                        "roe": None if event["operation"] == "revoke" else
                            before["revisions"][event["revision"] - 1]["roe"]}
                    if old != request or event["request_sha256"] != request_digest(request):
                        raise EngagementError("engagement_conflict")
                    return event
            state = before["state"]
            if state["status"] == "revoked":
                raise EngagementError("engagement_revoked")
            if (request["expected_revision"] != state["revision"]
                    or request["expected_generation"] != state["generation"]):
                raise EngagementError("engagement_conflict")
            revision = state["revision"]
            if request["operation"] == "revise":
                if revision >= 64:
                    raise EngagementError("engagement_limit_exceeded")
                revision += 1
                digest = roe_digest(request["roe"])
                self._execute("INSERT INTO revisions VALUES (?,?,?)", (revision,
                    canonical(request["roe"]).decode("ascii"), digest))
                status = "recorded"
            else:
                digest = before["revisions"][-1]["roe_sha256"]
                status = "revoked"
            receipt = self._receipt(request, revision=revision, generation=state["generation"] + 1,
                sequence=state["last_sequence"] + 1, status=status, digest=digest)
            self._execute("UPDATE metadata SET current_revision=?,generation=?,status=?,last_sequence=? WHERE singleton=1",
                          (revision, receipt["generation"], status, receipt["sequence"]))
            self._insert_event(receipt)
            return receipt

    def append_revision(self, roe, *, expected_revision, expected_generation, event_id):
        with self._operation() as deadline:
            request = validate_request({"schema_version": "1", "engagement_id": self._engagement_id,
                "event_id": event_id, "operation": "revise", "expected_revision": expected_revision,
                "expected_generation": expected_generation, "roe": roe})
            return self._mutate(request, deadline=deadline)

    def revoke(self, *, expected_revision, expected_generation, event_id):
        with self._operation() as deadline:
            request = validate_request({"schema_version": "1", "engagement_id": self._engagement_id,
                "event_id": event_id, "operation": "revoke", "expected_revision": expected_revision,
                "expected_generation": expected_generation, "roe": None})
            return self._mutate(request, deadline=deadline)

    def snapshot(self):
        with self._operation() as deadline:
            with self._transaction(deadline=deadline) as snapshot:
                return snapshot

    def event_receipt(self, event_id):
        with self._operation() as deadline:
            _uuid(event_id)
            with self._transaction(deadline=deadline) as snapshot:
                for event in snapshot["events"]:
                    if event["event_id"] == event_id:
                        return event
                raise EngagementError("engagement_event_unknown")

    def _close_resources(self):
        failed = False
        if self._db is not None:
            try:
                self._db.set_progress_handler(None, 0)
            except sqlite3.Error:
                failed = True
            try:
                self._db.close()
            except sqlite3.Error:
                failed = True
            finally:
                self._db = None
        for name in ("_directory_fd", "_parent_fd"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
                finally:
                    setattr(self, name, None)
        return failed

    def close(self):
        deadline = _operation_deadline()
        self._check_owner()
        if not self._lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise EngagementError("engagement_timeout")
        try:
            failed = self._close_resources()
            self._failed = True
            if failed:
                raise EngagementError("engagement_store_unavailable")
            if time.monotonic() >= deadline:
                raise EngagementError("engagement_timeout")
        finally:
            self._lock.release()

    def __enter__(self):
        self._check_owner()
        if self._failed or self._db is None:
            raise EngagementError("engagement_store_unavailable")
        return self

    def __exit__(self, *_):
        self.close()
