"""Private durable dispatch accounting; records never grant execution authority.

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
from uuid import UUID, uuid4

from .engagement_dispatch_contract import (
    DispatchLedgerError, canonical, request_digest, validate_export,
    validate_request, _apply, _operation_deadline, _deadline_context,
    SCHEMA_SQL, SCHEMA_OBJECTS, SQLITE_LIMITS,
)

DATABASE = "records.sqlite3"
JOURNAL = DATABASE + "-journal"
MAX_DATABASE = 8388608
MAX_JOURNAL = 16777216
MAX_PROGRESS_CALLBACKS = 4000
_SCHEMA_OBJECTS = sorted(SCHEMA_OBJECTS, key=lambda row: row[1])
_LIMITS = SQLITE_LIMITS
_POISON_CODES = {"engagement_dispatch_store_unavailable", "engagement_dispatch_store_invalid",
                 "engagement_dispatch_timeout", "engagement_dispatch_snapshot_changed"}


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        if (parsed is None or str(parsed) != value or parsed.version != 4
                or parsed.variant != "specified in RFC 4122"):
            raise ValueError
    except (ValueError, AttributeError):
        raise DispatchLedgerError("engagement_dispatch_invalid_input") from None
    return value


def _identity(info):
    return info.st_dev, info.st_ino


def _private_directory(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise DispatchLedgerError("engagement_dispatch_store_unavailable")


def _private_file(info, maximum, *, empty=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not (0 if empty else 1) <= info.st_size <= maximum):
        raise DispatchLedgerError("engagement_dispatch_store_unavailable")


class DispatchLedger:
    """One engagement, with private process-owned connections and bounded history."""

    @classmethod
    def create(cls, directory, *, engagement_id, roe, event_id):
        deadline = _operation_deadline()
        opened = None
        try:
            with _deadline_context(deadline):
                request = validate_request({"schema_version": "2", "engagement_id": engagement_id,
                    "event_id": event_id, "operation": "create", "expected_revision": None,
                    "expected_generation": None, "body": roe})
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
            with _deadline_context(deadline):
                if type(read_only) is not bool:
                    raise DispatchLedgerError("engagement_dispatch_invalid_input")
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
        self._owner_reference = str(uuid4())
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
                    raise DispatchLedgerError("engagement_dispatch_already_exists") from None
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
                    raise DispatchLedgerError("engagement_dispatch_store_unavailable")
            self._configure(initial=initial is not None)
            with self._transaction(write=initial is not None, deadline=deadline,
                                   initializing=initial is not None) as before:
                if initial is not None:
                    for statement in SCHEMA_SQL:
                        self._execute(statement)
                    self._execute("PRAGMA user_version=2")
                    after, _receipt = _apply(None, initial)
                    self._persist(None, after)
                    before = self._snapshot_checked()
                self._engagement_id = before["engagement_id"]
            return self
        except BaseException as exc:
            self._close_resources()
            if isinstance(exc, DispatchLedgerError):
                raise
            if isinstance(exc, (OSError, sqlite3.Error, ValueError, TypeError, KeyError,
                                OverflowError, AttributeError, RecursionError)):
                raise DispatchLedgerError(self._failure_code(exc)) from None
            raise

    @property
    def owner_reference(self):
        self._check_owner()
        if self._failed or self._db is None:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        return self._owner_reference

    def _check_owner(self):
        if self._pid != os.getpid():
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")

    def _check_deadline(self):
        if time.monotonic() >= self._deadline:
            raise DispatchLedgerError("engagement_dispatch_timeout")

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
                raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        if initial:
            self._execute("PRAGMA page_size=4096")
        if self._execute("PRAGMA page_size").fetchone()[0] != 4096:
            raise DispatchLedgerError("engagement_dispatch_store_invalid")
        if self._execute("PRAGMA max_page_count=2048").fetchone()[0] != 2048:
            raise DispatchLedgerError("engagement_dispatch_store_invalid")
        if initial:
            if self._execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
                raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        elif self._execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            # Existing stores are verified, never converted before validation.
            # Switching an unsupported WAL header would mutate even a refused DB.
            raise DispatchLedgerError("engagement_dispatch_store_invalid")
        self._execute("PRAGMA synchronous=EXTRA")
        if self._execute("PRAGMA synchronous").fetchone()[0] != 3:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        if self._read_only:
            self._execute("PRAGMA query_only=ON")
            if self._execute("PRAGMA query_only").fetchone()[0] != 1:
                raise DispatchLedgerError("engagement_dispatch_store_unavailable")

    def _check_parent(self):
        info = os.fstat(self._parent_fd)
        named = self.parent.stat(follow_symlinks=False)
        _private_directory(info)
        _private_directory(named)
        if _identity(info) != self._parent_identity or _identity(named) != self._parent_identity:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")

    def _check_directory(self):
        self._check_parent()
        info = os.fstat(self._directory_fd)
        named = os.stat(self.directory.name, dir_fd=self._parent_fd, follow_symlinks=False)
        _private_directory(info)
        _private_directory(named)
        if _identity(info) != self._directory_identity or _identity(named) != self._directory_identity:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")

    def _check_files(self, *, empty=False, read_entry=False):
        self._check_owner()
        if self._failed:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        self._check_directory()
        info = os.stat(DATABASE, dir_fd=self._directory_fd, follow_symlinks=False)
        _private_file(info, MAX_DATABASE, empty=empty)
        if _identity(info) != self._database_identity:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        # A concurrent SQLite writer may create/remove its valid journal. Only
        # transient disappearance of the one permitted name is benign.
        with os.scandir(self._directory_fd) as entries:
            for count, entry in enumerate(entries):
                if count >= 2 or entry.name not in {DATABASE, JOURNAL}:
                    raise DispatchLedgerError("engagement_dispatch_store_unavailable")
                self._check_deadline()
        try:
            journal = os.stat(JOURNAL, dir_fd=self._directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            journal = None
        if journal is not None:
            _private_file(journal, MAX_JOURNAL, empty=True)
            if read_entry:
                raise DispatchLedgerError("engagement_dispatch_store_unavailable")

    def _schema_checked(self):
        if self._execute("PRAGMA user_version").fetchone()[0] != 2:
            raise DispatchLedgerError("engagement_dispatch_store_invalid")
        rows = self._execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name LIMIT 24").fetchall()
        actual = [tuple(row[:3]) + (None if row[3] is None else row[3].rstrip(';'),) for row in rows]
        if actual != _SCHEMA_OBJECTS:
            raise DispatchLedgerError("engagement_dispatch_store_invalid")
        # Check implicit index columns as well as their exact schema entries.
        expected = {
            "sqlite_autoindex_sessions_1": ["session_id"],
            "sqlite_autoindex_reservations_1": ["dispatch_id"],
            "sqlite_autoindex_reservations_2": ["session_id", "slot"],
            "sqlite_autoindex_reservations_3": ["approval_broker_id", "approval_consume_sequence"],
            "sqlite_autoindex_reservations_4": ["audit_writer_id", "audit_sequence"],
            "sqlite_autoindex_completions_1": ["dispatch_id"],
            "sqlite_autoindex_events_1": ["event_id"],
        }
        for name, columns in expected.items():
            if [row[2] for row in self._execute(f"PRAGMA index_info({name})").fetchall()] != columns:
                raise DispatchLedgerError("engagement_dispatch_store_invalid")
        if (self._execute("PRAGMA page_size").fetchone()[0] != 4096
                or self._execute("PRAGMA page_count").fetchone()[0] > 2048
                or self._execute("PRAGMA quick_check(1)").fetchone()[0] != "ok"
                or self._execute("PRAGMA foreign_key_check").fetchone() is not None):
            raise DispatchLedgerError("engagement_dispatch_store_invalid")

    @staticmethod
    def _json_cell(raw, maximum):
        if type(raw) is not str or len(raw) > maximum:
            raise ValueError
        encoded = raw.encode("ascii")
        if not 1 <= len(encoded) <= maximum:
            raise ValueError
        value = json.loads(raw)
        if canonical(value) != encoded:
            raise ValueError
        return value

    def _snapshot_checked(self):
        self._schema_checked()
        try:
            metadata = self._execute("SELECT * FROM metadata LIMIT 2").fetchall()
            if len(metadata) != 1 or metadata[0]["singleton"] != 1:
                raise ValueError
            item = metadata[0]
            revisions = []
            for row in self._execute("SELECT * FROM revisions ORDER BY revision LIMIT 65").fetchall():
                revisions.append({"revision": row["revision"],
                    "roe": self._json_cell(row["roe_json"], 4096), "roe_sha256": row["roe_sha256"]})
            sessions, reservations, completions, events = [], [], [], []
            for row in self._execute("SELECT * FROM sessions ORDER BY rowid LIMIT 65").fetchall():
                value = self._json_cell(row["session_json"], 4096)
                if any(value[key] != row[key] for key in ("session_id", "owner_id", "revision", "generation")):
                    raise ValueError
                sessions.append(value)
            for row in self._execute("SELECT * FROM reservations ORDER BY rowid LIMIT 65").fetchall():
                value = self._json_cell(row["reservation_json"], 8192)
                if (any(value[key] != row[key] for key in ("dispatch_id", "session_id", "slot"))
                        or value["approval"]["broker_id"] != row["approval_broker_id"]
                        or value["approval"]["consume_sequence"] != row["approval_consume_sequence"]
                        or value["audit"]["writer_id"] != row["audit_writer_id"]
                        or value["audit"]["audit_sequence"] != row["audit_sequence"]):
                    raise ValueError
                reservations.append(value)
            for row in self._execute("SELECT * FROM completions ORDER BY rowid LIMIT 65").fetchall():
                value = self._json_cell(row["completion_json"], 4096)
                if value["dispatch_id"] != row["dispatch_id"]:
                    raise ValueError
                completions.append(value)
            for row in self._execute("SELECT * FROM events ORDER BY sequence LIMIT 258").fetchall():
                request = self._json_cell(row["request_json"], 8192)
                receipt = self._json_cell(row["receipt_json"], 4096)
                if receipt["sequence"] != row["sequence"] or receipt["event_id"] != row["event_id"]:
                    raise ValueError
                events.append({"sequence": row["sequence"], "event_id": row["event_id"],
                    "request": request, "request_sha256": row["request_sha256"], "receipt": receipt})
            usage = {key: item[key + "_reserved"] for key in
                ("actions", "connections", "request_bytes", "response_bytes", "runtime_ms")}
            snapshot = validate_export({"schema_version": "2", "kind": "engagement_dispatch_ledger",
                "engagement_id": item["engagement_id"], "state": {
                    "revision": item["current_revision"], "generation": item["generation"],
                    "status": item["status"], "last_sequence": item["last_sequence"],
                    "roe_sha256": revisions[-1]["roe_sha256"], "usage": usage,
                    "utc_high_water_ns": item["utc_high_water_ns"]},
                "revisions": revisions, "sessions": sessions, "reservations": reservations,
                "completions": completions, "events": events})
            if self._engagement_id is not None and snapshot["engagement_id"] != self._engagement_id:
                raise ValueError
            self._check_deadline()
            return snapshot
        except (DispatchLedgerError, ValueError, TypeError, KeyError, IndexError,
                OverflowError, RecursionError) as exc:
            if isinstance(exc, DispatchLedgerError) and exc.code == "engagement_dispatch_timeout":
                raise
            raise DispatchLedgerError("engagement_dispatch_store_invalid") from None

    def _failure_code(self, exc):
        if self._interrupted or (isinstance(exc, sqlite3.Error)
                and getattr(exc, "sqlite_errorcode", 0) & 255 in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)):
            return "engagement_dispatch_timeout"
        return "engagement_dispatch_store_unavailable"

    @contextmanager
    def _operation(self):
        self._check_owner()
        try:
            with _deadline_context(_operation_deadline()) as deadline:
                yield deadline
        except DispatchLedgerError as exc:
            if exc.code in _POISON_CODES:
                self._failed = True
            raise

    @contextmanager
    def _transaction(self, *, write=False, deadline=None, initializing=False):
        self._check_owner()
        deadline = _operation_deadline() if deadline is None else deadline
        try:
            with _deadline_context(deadline) as effective:
                with self._transaction_body(write=write, deadline=effective,
                                            initializing=initializing) as before:
                    yield before
        except DispatchLedgerError as exc:
            if exc.code in _POISON_CODES:
                self._failed = True
            raise

    @contextmanager
    def _transaction_body(self, *, write, deadline, initializing):
        self._check_owner()  # Before touching an inherited lock or connection.
        if self._failed or self._db is None:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        if write and self._read_only:
            raise DispatchLedgerError("engagement_dispatch_read_only")
        if not self._lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise DispatchLedgerError("engagement_dispatch_timeout")
        try:
            self._deadline = deadline
            # _open already started the constructor budget before configuration.
            # Only later independent operations receive a fresh callback count.
            if self._engagement_id is not None:
                self._callbacks, self._interrupted = 0, False
            self._check_deadline()
            self._check_files(empty=initializing, read_entry=self._read_only)
            self._db.set_progress_handler(self._progress, 1000)
            self._execute("BEGIN IMMEDIATE" if write else "BEGIN")
            before = None if initializing else self._snapshot_checked()
            yield before
            # Only trusted private read methods enter without write=True. Their
            # validated SQLite read snapshot cannot change within this transaction.
            # Mutations always independently reread and replay persisted after-state.
            if write:
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
            if isinstance(exc, DispatchLedgerError):
                if exc.code in _POISON_CODES:
                    self._failed = True
                raise
            if isinstance(exc, (sqlite3.Error, OSError, ValueError, TypeError,
                                KeyError, IndexError, OverflowError)):
                self._failed = True
                raise DispatchLedgerError(self._failure_code(exc)) from None
            raise
        finally:
            self._lock.release()

    def _insert_event(self, event):
        self._execute("INSERT INTO events VALUES (?,?,?,?,?)", (event["sequence"],
            event["event_id"], event["request_sha256"], canonical(event["request"]).decode("ascii"),
            canonical(event["receipt"]).decode("ascii")))

    def _persist(self, before, after):
        start = lambda name: 0 if before is None else len(before[name])
        for row in after["revisions"][start("revisions"):]:
            self._execute("INSERT INTO revisions VALUES (?,?,?)", (row["revision"],
                canonical(row["roe"]).decode("ascii"), row["roe_sha256"]))
        for row in after["sessions"][start("sessions"):]:
            self._execute("INSERT INTO sessions VALUES (?,?,?,?,?)", (row["session_id"],
                row["owner_id"], row["revision"], row["generation"], canonical(row).decode("ascii")))
        for row in after["reservations"][start("reservations"):]:
            self._execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?)", (
                row["dispatch_id"], row["session_id"], row["slot"], row["approval"]["broker_id"],
                row["approval"]["consume_sequence"], row["audit"]["writer_id"],
                row["audit"]["audit_sequence"], canonical(row).decode("ascii")))
        for row in after["completions"][start("completions"):]:
            self._execute("INSERT INTO completions VALUES (?,?)", (
                row["dispatch_id"], canonical(row).decode("ascii")))
        state, usage = after["state"], after["state"]["usage"]
        values = (after["engagement_id"], state["revision"], state["generation"],
            state["status"], state["last_sequence"], usage["actions"], usage["connections"],
            usage["request_bytes"], usage["response_bytes"], usage["runtime_ms"], state["utc_high_water_ns"])
        if before is None:
            self._execute("INSERT INTO metadata VALUES (1,?,?,?,?,?,?,?,?,?,?,?)", values)
        else:
            self._execute("UPDATE metadata SET engagement_id=?,current_revision=?,generation=?,status=?,"
                "last_sequence=?,actions_reserved=?,connections_reserved=?,request_bytes_reserved=?,"
                "response_bytes_reserved=?,runtime_ms_reserved=?,utc_high_water_ns=? WHERE singleton=1", values)
        for event in after["events"][start("events"):]:
            self._insert_event(event)

    @staticmethod
    def _result(receipt, *, retry=False):
        return {"schema_version": "2", "kind": "data_only",
                "disposition": "already_recorded" if retry else "recorded", "receipt": receipt}

    @staticmethod
    def _existing(snapshot, request):
        for event in snapshot["events"]:
            if event["event_id"] == request["event_id"]:
                if event["request"] != request or event["request_sha256"] != request_digest(request):
                    raise DispatchLedgerError("engagement_dispatch_conflict")
                return event["receipt"]
        return None

    def _mutate(self, operation, body, *, event_id, expected_revision=None, expected_generation=None):
        with self._operation() as deadline:
            with self._transaction(write=True, deadline=deadline) as before:
                request = validate_request({"schema_version": "2", "engagement_id": self._engagement_id,
                    "event_id": event_id, "operation": operation, "expected_revision": expected_revision,
                    "expected_generation": expected_generation, "body": body})
                previous = self._existing(before, request)
                if previous is not None:
                    return self._result(previous, retry=True)
                if operation in {"session", "reserve", "complete"} and body["owner_id"] != self._owner_reference:
                    raise DispatchLedgerError("engagement_dispatch_foreign_owner")
                after, receipt = _apply(before, request)
                self._persist(before, after)
                return self._result(receipt)

    def append_revision(self, roe, *, expected_revision, expected_generation, event_id):
        return self._mutate("revise", roe, expected_revision=expected_revision,
                            expected_generation=expected_generation, event_id=event_id)

    def revoke(self, *, expected_revision, expected_generation, event_id):
        return self._mutate("revoke", None, expected_revision=expected_revision,
                            expected_generation=expected_generation, event_id=event_id)

    def record_session(self, *, session_id, clock, original_deadline_ns, event_id,
                       expected_revision, expected_generation):
        return self._mutate("session", {"session_id": session_id, "owner_id": self._owner_reference,
            "clock": clock, "original_deadline_ns": original_deadline_ns}, event_id=event_id,
            expected_revision=expected_revision, expected_generation=expected_generation)

    def reserve(self, *, dispatch_id, session_id, slot, approval, audit, clock, event_id,
                expected_revision, expected_generation):
        return self._mutate("reserve", {"dispatch_id": dispatch_id, "session_id": session_id,
            "owner_id": self._owner_reference, "slot": slot, "approval": approval, "audit": audit,
            "clock": clock}, event_id=event_id, expected_revision=expected_revision,
            expected_generation=expected_generation)

    def complete(self, *, dispatch_id, session_id, outcome, observation, clock, event_id):
        return self._mutate("complete", {"dispatch_id": dispatch_id, "session_id": session_id,
            "owner_id": self._owner_reference, "outcome": outcome, "observation": observation,
            "clock": clock}, event_id=event_id)

    def retry(self, request):
        with self._operation() as deadline:
            with self._transaction(deadline=deadline) as snapshot:
                normalized = validate_request(request)
                receipt = self._existing(snapshot, normalized)
                if receipt is None:
                    raise DispatchLedgerError("engagement_dispatch_event_unknown")
                return self._result(receipt, retry=True)

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
                        return event["receipt"]
                raise DispatchLedgerError("engagement_dispatch_event_unknown")

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
            raise DispatchLedgerError("engagement_dispatch_timeout")
        try:
            failed = self._close_resources()
            self._failed = True
            if failed:
                raise DispatchLedgerError("engagement_dispatch_store_unavailable")
            if time.monotonic() >= deadline:
                raise DispatchLedgerError("engagement_dispatch_timeout")
        finally:
            self._lock.release()

    def __enter__(self):
        self._check_owner()
        if self._failed or self._db is None:
            raise DispatchLedgerError("engagement_dispatch_store_unavailable")
        return self

    def __exit__(self, *_):
        self.close()
        return False
