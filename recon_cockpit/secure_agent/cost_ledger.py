"""Durable host-owned provider accounting and atomic hierarchical admission.

SQLite transactions contain both the accounting change and its append-only
event. No method grants tool approval or sends a request. A trusted broker must
reserve, then claim dispatch exactly once before handing a request to transport.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
from uuid import uuid4

from .cost_contract import CostError, PriceCard, TokenUsage, canonical, identifier, integer, quote


_PARENTS = {"engagement": {"account"}, "session": {"engagement"},
            "agent": {"session"}, "action": {"session", "agent"}}
_SCHEMA = """
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), ledger_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK(currency='USD'), period TEXT NOT NULL, account_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('provider','simulation'))
);
CREATE TABLE scopes (
    scope_id TEXT PRIMARY KEY, parent_id TEXT REFERENCES scopes(scope_id), kind TEXT NOT NULL,
    limit_microusd INTEGER CHECK(limit_microusd IS NULL OR
        (typeof(limit_microusd)='integer' AND limit_microusd>=0))
);
CREATE INDEX scope_parent ON scopes(parent_id);
CREATE TABLE prices (
    provider TEXT NOT NULL, model TEXT NOT NULL, version TEXT NOT NULL, payload TEXT NOT NULL,
    PRIMARY KEY(provider,model,version)
);
CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
    request_digest TEXT NOT NULL, quote TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('estimated','reserved','dispatched','uncertain','settled','cancelled')),
    reserved_microusd INTEGER NOT NULL DEFAULT 0 CHECK(typeof(reserved_microusd)='integer' AND reserved_microusd>=0),
    actual_microusd INTEGER CHECK(actual_microusd IS NULL OR
        (typeof(actual_microusd)='integer' AND actual_microusd>=0)),
    actual_source TEXT, usage TEXT, receipt_reference TEXT
);
CREATE INDEX attempt_scope ON attempts(scope_id);
CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL, kind TEXT NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
    attempt_id TEXT REFERENCES attempts(attempt_id), payload TEXT NOT NULL
);
CREATE INDEX event_attempt ON events(attempt_id,sequence);
CREATE TRIGGER immutable_events_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT,'cost_events_immutable'); END;
CREATE TRIGGER immutable_events_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT,'cost_events_immutable'); END;
CREATE TABLE receipts (
    provider TEXT NOT NULL, source TEXT NOT NULL, reference TEXT NOT NULL,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    PRIMARY KEY(provider,source,reference)
);
PRAGMA user_version=1;
"""


class BudgetExceeded(CostError):
    def __init__(self, snapshot, requested_microusd):
        super().__init__("cost_budget_exceeded")
        self.scope_id = snapshot["scope_id"]
        self.available_microusd = snapshot["available_microusd"]
        self.requested_microusd = requested_microusd


class CostLedger:
    """One explicitly created account/period; opening never replenishes budgets.

    The directory and database must remain private and owned by this user. The
    host owner, filesystem and SQLite durability guarantees are trusted. Child
    agents must never receive this object, its descriptors or its directory.
    """

    @classmethod
    def create(cls, directory, *, account_id, limit_microusd, period="lifetime", mode="provider"):
        identifier(account_id)
        identifier(period)
        integer(limit_microusd)
        if type(mode) is not str or mode not in {"provider", "simulation"}:
            raise CostError("cost_invalid_mode")
        directory = Path(directory).absolute()
        try:
            directory.mkdir(mode=0o700)  # Existing stores are never replaced.
            fd = os.open(directory / "ledger.sqlite3", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            for path in (directory, directory.parent):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return cls(directory, _initial=(account_id, limit_microusd, period, mode))
        except (OSError, sqlite3.Error, ValueError):
            raise CostError("cost_ledger_unavailable") from None

    def __init__(self, directory, *, read_only=False, _initial=None):
        if type(read_only) is not bool or read_only and _initial is not None:
            raise CostError("cost_invalid_configuration")
        self.directory = Path(directory).absolute()
        self._db = self._directory_fd = self._file_identity = None
        self._lock = threading.RLock()
        self._pid, self._failed, self._read_only = os.getpid(), False, read_only
        try:
            self._directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            # Do not open a second descriptor for the database: closing ANY
            # such descriptor can release this process's SQLite POSIX locks.
            info = os.stat("ledger.sqlite3", dir_fd=self._directory_fd, follow_symlinks=False)
            self._file_identity = (info.st_dev, info.st_ino)
            self._check_files()
            uri = (self.directory / "ledger.sqlite3").as_uri() + ("?mode=ro" if read_only else "?mode=rw")
            self._db = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA trusted_schema=OFF")
            self._db.execute("PRAGMA fullfsync=ON")
            if read_only:
                self._db.execute("PRAGMA query_only=ON")
            else:
                # EXTRA also syncs the directory after deleting a commit journal.
                if self._db.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
                    raise CostError("cost_ledger_unavailable")
                self._db.execute("PRAGMA synchronous=EXTRA")
            if _initial is not None:
                account, limit, period, mode = _initial
                self._db.executescript("BEGIN IMMEDIATE;" + _SCHEMA)
                self._db.execute("INSERT INTO metadata VALUES (1,?,'USD',?,?,?)", (str(uuid4()), period, account, mode))
                self._db.execute("INSERT INTO scopes VALUES (?,NULL,'account',?)", (account, limit))
                self._event("scope_created", account, None,
                            {"parent_id": None, "kind": "account", "limit_microusd": limit})
                self._db.commit()
            if (self._db.execute("PRAGMA user_version").fetchone()[0] != 1
                    or self._db.execute("PRAGMA quick_check").fetchone()[0] != "ok"
                    or self._db.execute("PRAGMA foreign_key_check").fetchone() is not None):
                raise CostError("cost_ledger_invalid")
            metadata = self._db.execute("SELECT * FROM metadata WHERE singleton=1").fetchone()
            if metadata is None or metadata["currency"] != "USD":
                raise CostError("cost_ledger_invalid")
            self.ledger_id, self.period, self.account_id = metadata["ledger_id"], metadata["period"], metadata["account_id"]
            self.mode = metadata["mode"]
            root = self._scope(self.account_id)
            if root["kind"] != "account" or root["parent_id"] is not None or root["limit_microusd"] is None:
                raise CostError("cost_ledger_invalid")
            self._check_files()
        except (OSError, sqlite3.Error, CostError, ValueError, KeyError, IndexError, TypeError):
            self.close()
            raise CostError("cost_ledger_unavailable") from None

    def _check_files(self):
        if self._failed or self._pid != os.getpid() or self._directory_fd is None:
            raise CostError("cost_ledger_unavailable")
        directory = os.fstat(self._directory_fd)
        named = self.directory.stat(follow_symlinks=False)
        if ((directory.st_dev, directory.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != os.getuid() or directory.st_mode & 0o077):
            raise CostError("cost_ledger_unavailable")
        info = os.stat("ledger.sqlite3", dir_fd=self._directory_fd, follow_symlinks=False)
        if ((info.st_dev, info.st_ino) != self._file_identity or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1):
            raise CostError("cost_ledger_unavailable")

    @contextmanager
    def _transaction(self, *, write=False):
        # A forked child must not touch an inherited SQLite connection, even to
        # roll it back, nor acquire a lock possibly held by a vanished thread.
        if self._pid != os.getpid():
            raise CostError("cost_ledger_unavailable")
        with self._lock:
            if write and self._read_only:
                raise CostError("cost_ledger_read_only")
            try:
                self._check_files()
                if self._db is None:
                    raise CostError("cost_ledger_unavailable")
                self._db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield
                self._check_files()
                self._db.commit()
            except BaseException as exc:
                try:
                    if self._db is not None:
                        self._db.rollback()
                except sqlite3.Error:
                    self._failed = True
                if isinstance(exc, (OSError, sqlite3.Error, ValueError, KeyError, IndexError, TypeError)):
                    self._failed = True
                    raise CostError("cost_ledger_unavailable") from None
                raise

    def _event(self, kind, scope_id, attempt_id, payload, event_id=None):
        self._db.execute("INSERT INTO events(event_id,timestamp,kind,scope_id,attempt_id,payload) VALUES (?,?,?,?,?,?)",
                         (event_id or str(uuid4()), datetime.now(timezone.utc).isoformat(), kind,
                          scope_id, attempt_id, canonical(payload)))

    def _replayed(self, event_id, kind, scope_id, attempt_id, payload):
        identifier(event_id)
        old = self._db.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
        if old is None:
            return False
        if (old["kind"], old["scope_id"], old["attempt_id"], old["payload"]) != (
                kind, scope_id, attempt_id, canonical(payload)):
            raise CostError("cost_idempotency_conflict")
        return True

    def _scope(self, scope_id):
        identifier(scope_id)
        row = self._db.execute("SELECT * FROM scopes WHERE scope_id=?", (scope_id,)).fetchone()
        if row is None:
            raise CostError("cost_scope_unknown")
        return dict(row)

    def _attempt(self, attempt_id):
        identifier(attempt_id)
        row = self._db.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        if row is None:
            raise CostError("cost_attempt_unknown")
        result = dict(row)
        result["quote"] = json.loads(result["quote"])
        result["usage"] = json.loads(result["usage"]) if result["usage"] is not None else None
        result["reservation_overrun_microusd"] = (None if result["actual_microusd"] is None else
            max(0, result["actual_microusd"] - result["quote"]["ceiling_microusd"]))
        return result

    def add_scope(self, scope_id, *, parent_id, kind, limit_microusd=None):
        identifier(scope_id)
        if type(kind) is not str or kind not in _PARENTS:
            raise CostError("cost_invalid_scope_kind")
        if limit_microusd is not None:
            integer(limit_microusd)
        with self._transaction(write=True):
            parent = self._scope(parent_id)
            if parent["kind"] not in _PARENTS[kind]:
                raise CostError("cost_invalid_scope_parent")
            old = self._db.execute("SELECT * FROM scopes WHERE scope_id=?", (scope_id,)).fetchone()
            value = {"scope_id": scope_id, "parent_id": parent_id, "kind": kind, "limit_microusd": limit_microusd}
            if old is not None:
                if dict(old) != value:
                    raise CostError("cost_scope_conflict")
            else:
                self._db.execute("INSERT INTO scopes VALUES (?,?,?,?)", (scope_id, parent_id, kind, limit_microusd))
                self._event("scope_created", scope_id, None, value)
            return value

    def set_limit(self, scope_id, limit_microusd, *, event_id):
        """Operator-only adjustment, including zero to block further spending."""
        if limit_microusd is not None:
            integer(limit_microusd)
        with self._transaction(write=True):
            scope = self._scope(scope_id)
            if scope["kind"] == "account" and limit_microusd is None:
                raise CostError("cost_account_requires_limit")
            payload = {"limit_microusd": limit_microusd}
            if not self._replayed(event_id, "limit_changed", scope_id, None, payload):
                self._db.execute("UPDATE scopes SET limit_microusd=? WHERE scope_id=?", (limit_microusd, scope_id))
                self._event("limit_changed", scope_id, None, payload, event_id)
            return self._snapshot(scope_id)

    def estimate(self, attempt_id, *, scope_id, request_digest, price, usage,
                 input_token_limit, output_token_limit):
        identifier(attempt_id)
        if type(request_digest) is not str or re.fullmatch("[0-9a-f]{64}", request_digest) is None:
            raise CostError("cost_invalid_request_digest")
        quotation = quote(price, usage, input_token_limit, output_token_limit)
        with self._transaction(write=True):
            if self._scope(scope_id)["kind"] != "action":
                raise CostError("cost_attempt_requires_action_scope")
            old = self._db.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if old is not None:
                if (old["scope_id"], old["request_digest"], old["quote"]) != (scope_id, request_digest, canonical(quotation)):
                    raise CostError("cost_attempt_conflict")
                return self._attempt(attempt_id)
            key = (price.provider, price.model, price.version)
            stored = self._db.execute("SELECT payload FROM prices WHERE provider=? AND model=? AND version=?", key).fetchone()
            payload = canonical(asdict(price))
            if stored is not None and stored[0] != payload:
                raise CostError("cost_price_version_conflict")
            if stored is None:
                self._db.execute("INSERT INTO prices VALUES (?,?,?,?)", (*key, payload))
            self._db.execute("INSERT INTO attempts(attempt_id,scope_id,request_digest,quote,state) VALUES (?,?,?,?,'estimated')",
                             (attempt_id, scope_id, request_digest, canonical(quotation)))
            self._event("cost_estimated", scope_id, attempt_id, {"request_digest": request_digest, **quotation})
            return self._attempt(attempt_id)

    def _chain(self, scope_id):
        chain = []
        while scope_id is not None:
            scope = self._scope(scope_id)
            chain.append(scope)
            scope_id = scope["parent_id"]
            if len(chain) > 5:
                raise CostError("cost_ledger_invalid")
        if chain[-1]["scope_id"] != self.account_id:
            raise CostError("cost_ledger_invalid")
        return list(reversed(chain))

    def reserve(self, attempt_id):
        rejection = None
        with self._transaction(write=True):
            attempt = self._attempt(attempt_id)
            if attempt["state"] == "reserved":
                return attempt
            if attempt["state"] != "estimated":
                raise CostError("cost_invalid_transition")
            amount = attempt["quote"]["ceiling_microusd"]
            for scope in self._chain(attempt["scope_id"]):
                current = self._snapshot(scope["scope_id"])
                if scope["limit_microusd"] is not None and current["committed_microusd"] + amount > scope["limit_microusd"]:
                    rejection = BudgetExceeded(current, amount)
                    break
            if rejection is not None:
                self._record_denial("reservation_denied", attempt, rejection)
            else:
                self._db.execute("UPDATE attempts SET state='reserved',reserved_microusd=? WHERE attempt_id=?", (amount, attempt_id))
                self._event("cost_reserved", attempt["scope_id"], attempt_id, {"reserved_microusd": amount})
                result = self._attempt(attempt_id)
        if rejection is not None:
            raise rejection
        return result

    def _record_denial(self, kind, attempt, rejection):
        self._event(kind, attempt["scope_id"], attempt["attempt_id"], {
            "blocking_scope_id": rejection.scope_id, "available_microusd": rejection.available_microusd,
            "requested_microusd": rejection.requested_microusd, "reason": rejection.code})

    def begin_dispatch(self, attempt_id, *, request_digest):
        """Consume the send claim once. A replay must never authorize a resend."""
        rejection = None
        with self._transaction(write=True):
            attempt = self._attempt(attempt_id)
            if attempt["state"] != "reserved":
                raise CostError("cost_invalid_transition")
            if request_digest != attempt["request_digest"]:
                raise CostError("cost_request_mismatch")
            # A limit may have been lowered, or another call may have overrun,
            # since reservation. Existing holds count; do not add this one twice.
            for scope in self._chain(attempt["scope_id"]):
                current = self._snapshot(scope["scope_id"])
                if scope["limit_microusd"] is not None and current["committed_microusd"] > scope["limit_microusd"]:
                    rejection = BudgetExceeded(current, 0)
                    break
            if rejection is not None:
                self._record_denial("dispatch_denied", attempt, rejection)
            else:
                self._db.execute("UPDATE attempts SET state='dispatched' WHERE attempt_id=?", (attempt_id,))
                self._event("dispatch_started", attempt["scope_id"], attempt_id, {"request_digest": request_digest})
                result = self._attempt(attempt_id)
        if rejection is not None:
            raise rejection
        return result

    def cancel(self, attempt_id):
        """Release only work that has never crossed the durable dispatch point."""
        with self._transaction(write=True):
            attempt = self._attempt(attempt_id)
            if attempt["state"] == "cancelled":
                return attempt
            if attempt["state"] not in {"estimated", "reserved"}:
                raise CostError("cost_reconciliation_required")
            self._db.execute("UPDATE attempts SET state='cancelled',reserved_microusd=0,actual_microusd=0,"
                             "actual_source='not_sent' WHERE attempt_id=?", (attempt_id,))
            self._event("reservation_released", attempt["scope_id"], attempt_id,
                        {"released_microusd": attempt["reserved_microusd"], "reason": "not_sent"})
            return self._attempt(attempt_id)

    def mark_uncertain(self, attempt_id, *, reason):
        if type(reason) is not str or reason not in {"timeout", "cancelled", "transport_error", "missing_usage", "recovery"}:
            raise CostError("cost_invalid_uncertainty_reason")
        with self._transaction(write=True):
            attempt = self._attempt(attempt_id)
            if attempt["state"] == "uncertain":
                return attempt
            if attempt["state"] != "dispatched":
                raise CostError("cost_invalid_transition")
            self._db.execute("UPDATE attempts SET state='uncertain' WHERE attempt_id=?", (attempt_id,))
            self._event("cost_uncertain", attempt["scope_id"], attempt_id, {"reason": reason})
            return self._attempt(attempt_id)

    def settle_usage(self, attempt_id, usage, *, receipt_reference, event_id):
        """Settle complete cumulative usage from the trusted transport adapter.

        Partial streaming usage must leave the reservation outstanding instead.
        Usage-derived charges remain distinguishable from billing confirmation.
        """
        if type(usage) is not TokenUsage:
            raise CostError("cost_invalid_usage")
        return self._settle(attempt_id, usage=usage, amount=None, source="usage_derived",
                            reference=receipt_reference, event_id=event_id)

    def reconcile(self, attempt_id, actual_microusd, *, billing_reference, event_id):
        """Trusted billing evidence may correct earlier usage-derived charges.

        The operator supplies a reference to retained evidence, not a model claim.
        Zero requires affirmative billing evidence too; silence is not a refund.
        """
        integer(actual_microusd)
        return self._settle(attempt_id, usage=None, amount=actual_microusd, source="billing_confirmed",
                            reference=billing_reference, event_id=event_id)

    def _settle(self, attempt_id, *, usage, amount, source, reference, event_id):
        identifier(reference)
        with self._transaction(write=True):
            attempt = self._attempt(attempt_id)
            if usage is not None:
                amount = PriceCard(**attempt["quote"]["price"]).cost(usage)
            payload = {"actual_microusd": amount, "source": source, "reference": reference,
                       "usage": asdict(usage) if usage is not None else None}
            if self._replayed(event_id, "cost_settled", attempt["scope_id"], attempt_id, payload):
                return self._attempt(attempt_id)
            if attempt["state"] not in {"dispatched", "uncertain", "settled"} or (
                    attempt["state"] == "settled" and source != "billing_confirmed"):
                raise CostError("cost_invalid_transition")
            provider = attempt["quote"]["price"]["provider"]
            receipt = self._db.execute("SELECT attempt_id FROM receipts WHERE provider=? AND source=? AND reference=?",
                                       (provider, source, reference)).fetchone()
            if receipt is not None:
                raise CostError("cost_receipt_already_used")
            self._db.execute("INSERT INTO receipts VALUES (?,?,?,?)", (provider, source, reference, attempt_id))
            self._db.execute("UPDATE attempts SET state='settled',reserved_microusd=0,actual_microusd=?,"
                             "actual_source=?,usage=COALESCE(?,usage),receipt_reference=? WHERE attempt_id=?",
                             (amount, source, canonical(asdict(usage)) if usage is not None else None, reference, attempt_id))
            # Never reject an incurred charge merely because it exceeds a limit.
            self._event("cost_settled", attempt["scope_id"], attempt_id, payload, event_id)
            return self._attempt(attempt_id)

    def _scope_attempts(self, scope_id):
        return self._db.execute("""WITH RECURSIVE descendants(id) AS (
            SELECT ? UNION ALL SELECT s.scope_id FROM scopes s JOIN descendants d ON s.parent_id=d.id
        ) SELECT a.* FROM attempts a JOIN descendants d ON a.scope_id=d.id""", (scope_id,)).fetchall()

    def _snapshot(self, scope_id):
        scope = self._scope(scope_id)
        rows = self._scope_attempts(scope_id)
        reserved = sum(row["reserved_microusd"] for row in rows)
        actual = sum(row["actual_microusd"] or 0 for row in rows)
        limit = scope["limit_microusd"]
        unresolved = sum(row["state"] in {"dispatched", "uncertain"} for row in rows)
        return {**scope, "ledger_id": self.ledger_id, "mode": self.mode,
                "currency": "USD", "unit": "microUSD", "period": self.period,
                "estimated_microusd": sum(json.loads(row["quote"])["estimated_microusd"] for row in rows),
                "pending_estimated_microusd": sum(json.loads(row["quote"])["estimated_microusd"] for row in rows if row["state"] == "estimated"),
                "reserved_microusd": reserved, "actual_microusd": actual, "committed_microusd": actual + reserved,
                "available_microusd": None if limit is None else max(0, limit - actual - reserved),
                "overcommitted_microusd": 0 if limit is None else max(0, actual + reserved - limit),
                "overspent_microusd": 0 if limit is None else max(0, actual - limit),
                "usage_derived_microusd": sum(row["actual_microusd"] or 0 for row in rows if row["actual_source"] == "usage_derived"),
                "billing_confirmed_microusd": sum(row["actual_microusd"] or 0 for row in rows if row["actual_source"] == "billing_confirmed"),
                "unresolved_attempts": unresolved, "actual_complete": unresolved == 0, "attempt_count": len(rows)}

    def snapshot(self, scope_id):
        with self._transaction():
            return self._effective_snapshot(scope_id)

    def _effective_snapshot(self, scope_id):
        result = self._snapshot(scope_id)
        chain = [self._snapshot(scope["scope_id"]) for scope in self._chain(scope_id)]
        limits = [row for row in chain if row["available_microusd"] is not None]
        binding = min(limits, key=lambda row: row["available_microusd"])
        result.update(effective_available_microusd=binding["available_microusd"],
                      limiting_scope_id=binding["scope_id"])
        return result

    def report(self, scope_id=None):
        """One consistent read for budget indicators and provider/model totals."""
        scope_id = self.account_id if scope_id is None else scope_id
        with self._transaction():
            summary = self._effective_snapshot(scope_id)
            groups = {}
            for row in self._scope_attempts(scope_id):
                price = json.loads(row["quote"])["price"]
                key = (price["provider"], price["model"])
                group = groups.setdefault(key, {"provider": key[0], "model": key[1],
                    "actual_microusd": 0, "reserved_microusd": 0, "attempt_count": 0,
                    "unresolved_attempts": 0, "input_tokens": 0, "cached_input_tokens": 0,
                    "output_tokens": 0, "attempts_with_usage": 0})
                group["actual_microusd"] += row["actual_microusd"] or 0
                group["reserved_microusd"] += row["reserved_microusd"]
                group["attempt_count"] += 1
                group["unresolved_attempts"] += row["state"] in {"dispatched", "uncertain"}
                if row["usage"] is not None:
                    for field, value in json.loads(row["usage"]).items():
                        group[field] += value
                    group["attempts_with_usage"] += 1
            return {"schema_version": "1", "summary": summary,
                    "budget_chain": [self._snapshot(scope["scope_id"]) for scope in self._chain(scope_id)],
                    "by_model": [groups[key] for key in sorted(groups)],
                    "last_event_sequence": self._db.execute("SELECT COALESCE(MAX(sequence),0) FROM events").fetchone()[0]}

    def attempt(self, attempt_id):
        with self._transaction():
            return self._attempt(attempt_id)

    def events(self, *, after_sequence=0, limit=100):
        integer(after_sequence, 2**63 - 1)
        integer(limit, 1000)
        with self._transaction():
            return [{**dict(row), "payload": json.loads(row["payload"])} for row in self._db.execute(
                "SELECT * FROM events WHERE sequence>? ORDER BY sequence LIMIT ?", (after_sequence, limit))]

    def attempts(self, *, after_id="", limit=100):
        if after_id != "":
            identifier(after_id)
        integer(limit, 1000)
        with self._transaction():
            return [self._attempt(row[0]) for row in self._db.execute(
                "SELECT attempt_id FROM attempts WHERE attempt_id>? ORDER BY attempt_id LIMIT ?", (after_id, limit))]

    def close(self):
        if self._pid != os.getpid():
            raise CostError("cost_ledger_unavailable")
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
            if self._directory_fd is not None:
                os.close(self._directory_fd)
                self._directory_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
