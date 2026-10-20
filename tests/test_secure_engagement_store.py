"""The 28 pinned S4.2a metadata-store gates; no dispatch/native authority claims."""

from contextlib import contextmanager
import copy
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.engagement_contract import EngagementError, canonical, validate_export
from recon_cockpit.secure_agent import engagement_store as module
from recon_cockpit.secure_agent import engagement_contract as contract
from recon_cockpit.secure_agent.engagement_store import EngagementStore, SCHEMA_SQL


ROE = {
    "schema_version": "1", "mode": "disconnected_owned",
    "scope": {"schema_version": "1", "scope_id": "owned-example",
        "http": {"target": "10.77.0.10", "port": 8080, "path": "/"},
        "ssh": {"target": "10.77.0.20", "port": 2222}},
    "allowed_profiles": ["configurable_http_headers_v1", "configurable_nmap_service_v1",
                         "configurable_ssh_host_keys_v1"], "excluded_services": [],
    "window": {"start_utc": "2026-10-20T00:00:00Z", "end_utc": "2026-10-21T00:00:00Z"},
    "limits": {"max_actions": 64, "max_connections": 256, "max_request_bytes": 1048576,
        "max_response_bytes": 1048576, "max_action_ms": 60000, "max_engagement_ms": 86400000}}


def new_store(tmp_path, name="case"):
    parent = tmp_path / name
    parent.mkdir(mode=0o700)
    return EngagementStore.create(parent / "store", engagement_id=str(uuid4()),
                                  roe=copy.deepcopy(ROE), event_id=str(uuid4()))


@pytest.fixture
def store(tmp_path):
    result = new_store(tmp_path)
    try:
        yield result
    finally:
        result.close()


def revised(value=63):
    roe = copy.deepcopy(ROE)
    roe["limits"]["max_actions"] = value
    return roe


def revise(store, *, event_id=None, revision=1, generation=0, value=63):
    return store.append_revision(revised(value), expected_revision=revision,
        expected_generation=generation, event_id=event_id or str(uuid4()))


@contextmanager
def refusal(code):
    with pytest.raises(EngagementError) as caught:
        yield
    assert caught.value.code == code
    assert str(caught.value) == code


class DBProxy:
    def __init__(self, connection, *, commit=None):
        self.connection, self.commit_hook = connection, commit

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def commit(self):
        if self.commit_hook is not None:
            return self.commit_hook(self.connection)
        return self.connection.commit()


def _race_writer(path, barrier, channel, operation, event_id, value):
    try:
        with EngagementStore.open(path) as opened:
            barrier.wait(timeout=10)
            if operation == "revise":
                receipt = revise(opened, event_id=event_id, value=value)
            else:
                receipt = opened.revoke(expected_revision=1, expected_generation=0, event_id=event_id)
            channel.send({"ok": receipt})
    except EngagementError as error:
        channel.send({"error": error.code})
    finally:
        channel.close()


def race(path, plans):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(len(plans) + 1)
    processes, channels = [], []
    try:
        for operation, event, value in plans:
            receiving, sending = context.Pipe(duplex=False)
            process = context.Process(target=_race_writer,
                args=(str(path), barrier, sending, operation, event, value))
            process.start()
            sending.close()
            processes.append(process)
            channels.append(receiving)
        barrier.wait(timeout=10)
        results = []
        for channel in channels:
            assert channel.poll(10), "worker did not produce a bounded result"
            results.append(channel.recv())
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        return results
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
            process.close()
        for channel in channels:
            channel.close()


def _crash_writer(path, channel, phase, event):
    store = EngagementStore.open(path)
    # Force actual dirty-page spill so an uncommitted crash leaves a hot journal.
    store._db.execute("PRAGMA cache_size=1")
    if phase == "before":
        original = store._insert_event
        def insert(receipt):
            original(receipt)
            channel.send("uncommitted")
            os._exit(0)
        store._insert_event = insert
    else:
        def commit(connection):
            connection.commit()
            channel.send("committed")
            os._exit(0)
        store._db = DBProxy(store._db, commit=commit)
    revise(store, event_id=event)
    os._exit(91)


def crash(path, phase, event):
    context = multiprocessing.get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_crash_writer, args=(str(path), sending, phase, event))
    process.start()
    sending.close()
    try:
        assert receiving.poll(10), "crash helper did not reach pinned transaction point"
        assert receiving.recv() == ("uncommitted" if phase == "before" else "committed")
        process.join(10)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        process.close()
        receiving.close()


def _hold_writer(path, ready, release, reader=False):
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("BEGIN" if reader else "BEGIN IMMEDIATE")
    if reader:
        connection.execute("SELECT count(*) FROM metadata").fetchone()
    ready.send("locked")
    release.recv()
    connection.rollback()
    connection.close()
    ready.close()
    release.close()


def test_exclusive_private_creation(tmp_path):
    with new_store(tmp_path) as store:
        snapshot = store.snapshot()
        assert snapshot["state"] == {"revision": 1, "generation": 0,
            "status": "recorded", "last_sequence": 1}
        assert snapshot["revisions"][0]["roe"] == ROE
        before = (store.directory / module.DATABASE).read_bytes()
        with refusal("engagement_already_exists"):
            EngagementStore.create(store.directory, engagement_id=str(uuid4()),
                                   roe=ROE, event_id=str(uuid4()))
        assert (store.directory / module.DATABASE).read_bytes() == before
        assert store.directory.stat().st_mode & 0o777 == 0o700
        assert (store.directory / module.DATABASE).stat().st_mode & 0o777 == 0o600


def test_reopen_preserves_all_committed_metadata(tmp_path):
    with new_store(tmp_path) as store:
        revise(store)
        store.revoke(expected_revision=2, expected_generation=1, event_id=str(uuid4()))
        snapshot, path = store.snapshot(), store.directory
    with EngagementStore.open(path) as reopened:
        assert reopened.snapshot() == snapshot
        assert reopened.engagement_id == snapshot["engagement_id"]
    with EngagementStore.open(path, read_only=True) as reopened:
        assert reopened.snapshot() == snapshot


def test_revision_transaction_and_receipt(store):
    before = store.snapshot()
    receipt = revise(store)
    snapshot = store.snapshot()
    assert snapshot["revisions"][:1] == before["revisions"]
    assert snapshot["events"] == before["events"] + [receipt]
    assert snapshot["state"] == {"revision": 2, "generation": 1,
        "status": "recorded", "last_sequence": 2}
    assert validate_export(snapshot) == snapshot
    receipt["status"] = "revoked"
    snapshot["revisions"][0]["roe"]["limits"]["max_actions"] = 1
    assert store.snapshot()["events"][-1]["status"] == "recorded"
    assert store.snapshot()["revisions"][0]["roe"] == ROE


def test_stale_revision_and_generation_refuse(store):
    revise(store)
    before = store.snapshot()
    for revision, generation in ((1, 1), (2, 0), (1, 0)):
        with refusal("engagement_conflict"):
            revise(store, revision=revision, generation=generation)
        assert store.snapshot() == before
    assert revise(store, revision=2, generation=1)["revision"] == 3


def test_terminal_revocation(store):
    event = str(uuid4())
    receipt = store.revoke(expected_revision=1, expected_generation=0, event_id=event)
    before = store.snapshot()
    assert receipt["revision"] == 1 and receipt["generation"] == 1
    assert receipt["status"] == "revoked"
    for callback in (lambda: revise(store), lambda: store.revoke(expected_revision=1,
            expected_generation=1, event_id=str(uuid4()))):
        with refusal("engagement_revoked"):
            callback()
        assert store.snapshot() == before


def test_exact_retry_after_later_state(store):
    event = str(uuid4())
    receipt = revise(store, event_id=event)
    revise(store, revision=2, generation=1, value=62)
    revoke_id = str(uuid4())
    revoked = store.revoke(expected_revision=3, expected_generation=2, event_id=revoke_id)
    before = store.snapshot()
    assert revise(store, event_id=event) == receipt
    assert store.revoke(expected_revision=3, expected_generation=2, event_id=revoke_id) == revoked
    assert store.event_receipt(event) == receipt
    assert store.snapshot() == before


def test_event_id_content_conflict(store):
    event = str(uuid4())
    revise(store, event_id=event)
    before = store.snapshot()
    for callback in (lambda: revise(store, event_id=event, value=62),
            lambda: revise(store, event_id=event, revision=2, generation=1),
            lambda: store.revoke(expected_revision=1, expected_generation=0, event_id=event)):
        with refusal("engagement_conflict"):
            callback()
        assert store.snapshot() == before


def test_explicit_same_content_revision(store):
    before = store.snapshot()
    receipt = store.append_revision(ROE, expected_revision=1,
        expected_generation=0, event_id=str(uuid4()))
    after = store.snapshot()
    assert receipt["revision"] == 2 and receipt["generation"] == 1
    assert after["revisions"][0]["roe_sha256"] == after["revisions"][1]["roe_sha256"]
    assert len(after["events"]) == len(before["events"]) + 1


def test_concurrent_distinct_cas_processes(store):
    results = race(store.directory, [("revise", str(uuid4()), 63), ("revise", str(uuid4()), 62)])
    assert len([item for item in results if "ok" in item]) == 1
    assert [item["error"] for item in results if "error" in item] == ["engagement_conflict"]
    snapshot = store.snapshot()
    assert len(snapshot["events"]) == len(snapshot["revisions"]) == 2
    assert snapshot["events"][-1] == next(item["ok"] for item in results if "ok" in item)


def test_concurrent_exact_event_retry(store):
    event = str(uuid4())
    results = race(store.directory, [("revise", event, 63), ("revise", event, 63)])
    assert all("ok" in item for item in results)
    assert results[0] == results[1]
    assert len(store.snapshot()["events"]) == 2


def test_concurrent_revise_revoke_order(store):
    results = race(store.directory, [("revise", str(uuid4()), 63), ("revoke", str(uuid4()), 63)])
    successes = [item["ok"] for item in results if "ok" in item]
    assert len(successes) == 1
    assert [item["error"] for item in results if "error" in item][0] in {
        "engagement_conflict", "engagement_revoked"}
    snapshot = validate_export(store.snapshot())
    assert snapshot["events"][-1] == successes[0]
    assert snapshot["state"]["last_sequence"] == 2


def test_revision_and_event_capacity(store):
    for revision in range(1, 64):
        store.append_revision(ROE, expected_revision=revision,
            expected_generation=revision - 1, event_id=str(uuid4()))
    before = store.snapshot()
    with refusal("engagement_limit_exceeded"):
        revise(store, revision=64, generation=63)
    assert store.snapshot() == before
    receipt = store.revoke(expected_revision=64, expected_generation=63, event_id=str(uuid4()))
    assert receipt["sequence"] == 65 and receipt["generation"] == 64
    snapshot = store.snapshot()
    assert len(snapshot["revisions"]) == 64 and len(snapshot["events"]) == 65


def test_event_write_failure_rolls_back(store, monkeypatch):
    before = store.snapshot()
    def fail(_receipt):
        raise sqlite3.OperationalError("private event failure")
    monkeypatch.setattr(store, "_insert_event", fail)
    with refusal("engagement_store_unavailable"):
        revise(store)
    assert store._failed
    with refusal("engagement_store_unavailable"):
        store.snapshot()
    with EngagementStore.open(store.directory) as reopened:
        assert reopened.snapshot() == before


def test_commit_failure_is_not_success(tmp_path):
    for committed in (False, True):
        with new_store(tmp_path, str(committed)) as store:
            before = store.snapshot()
            event = str(uuid4())
            def fail(connection):
                if committed:
                    connection.commit()
                raise sqlite3.OperationalError("private commit acknowledgment")
            store._db = DBProxy(store._db, commit=fail)
            with refusal("engagement_store_unavailable"):
                revise(store, event_id=event)
            assert store._failed
            with EngagementStore.open(store.directory) as reopened:
                snapshot = reopened.snapshot()
                if committed:
                    assert snapshot["state"]["revision"] == 2
                    receipt = reopened.event_receipt(event)
                    assert revise(reopened, event_id=event) == receipt
                    assert reopened.snapshot() == snapshot
                else:
                    assert snapshot == before
                    with refusal("engagement_event_unknown"):
                        reopened.event_receipt(event)


def test_crash_before_commit(tmp_path):
    with new_store(tmp_path) as store:
        before, path = store.snapshot(), store.directory
    crash(path, "before", str(uuid4()))
    with EngagementStore.open(path) as reopened:
        assert reopened.snapshot() == before


def test_crash_after_commit_before_ack(tmp_path):
    with new_store(tmp_path) as store:
        path = store.directory
    event = str(uuid4())
    crash(path, "after", event)
    with EngagementStore.open(path) as reopened:
        snapshot = reopened.snapshot()
        assert snapshot["state"]["revision"] == 2
        assert revise(reopened, event_id=event) == reopened.event_receipt(event)
        assert reopened.snapshot() == snapshot


def test_exact_schema_and_trigger_inventory(tmp_path):
    mutations = ["PRAGMA user_version=2", "DROP TRIGGER immutable_events_update",
        "CREATE TABLE extra(value)", "CREATE VIEW extra AS SELECT 1",
        "CREATE INDEX extra ON metadata(generation)", "DROP TABLE events",
        "DROP TRIGGER immutable_events_update; CREATE TRIGGER immutable_events_update BEFORE UPDATE ON events BEGIN SELECT 1; END"]
    for index, statement in enumerate(mutations):
        with new_store(tmp_path, str(index)) as store:
            path = store.directory
        with sqlite3.connect(path / module.DATABASE) as raw:
            raw.executescript(statement)
        with refusal("engagement_store_invalid"):
            EngagementStore.open(path)
    inventory = json.loads((Path(__file__).parents[1] / "docs/stage4-engagement-records-gates.json").read_text())
    assert list(SCHEMA_SQL) == inventory["sqlite"]["schema_sql"]


def test_stored_row_replay_tampering(tmp_path):
    for index, mutation in enumerate(("metadata", "roe", "event", "nested")):
        with new_store(tmp_path, str(index)) as store:
            path = store.directory
        with sqlite3.connect(path / module.DATABASE) as raw:
            with pytest.raises(sqlite3.IntegrityError):
                raw.execute("UPDATE events SET sequence=sequence")
            with pytest.raises(sqlite3.IntegrityError):
                raw.execute("DELETE FROM revisions")
            if mutation == "metadata":
                raw.execute("UPDATE metadata SET generation=1")
            elif mutation in {"roe", "nested"}:
                raw.execute("DROP TRIGGER immutable_revisions_update")
                if mutation == "roe":
                    value = canonical(revised()).decode("ascii")
                else:
                    value = "[" * 1900 + "0" + "]" * 1900
                raw.execute("UPDATE revisions SET roe_json=?", (value,))
                raw.execute(SCHEMA_SQL[3])
            else:
                raw.execute("DROP TRIGGER immutable_events_update")
                raw.execute("UPDATE events SET request_sha256=?", ("0" * 64,))
                raw.execute(SCHEMA_SQL[5])
        with refusal("engagement_store_invalid"):
            EngagementStore.open(path)


def test_corruption_growth_and_query_bounds(tmp_path, monkeypatch):
    for name, size in (("corrupt", 512), ("oversize", module.MAX_DATABASE + 1), ("empty", 0)):
        with new_store(tmp_path, name) as store:
            path = store.directory
        with open(path / module.DATABASE, "wb") as output:
            output.truncate(size)
        with pytest.raises(EngagementError):
            EngagementStore.open(path)
    with new_store(tmp_path, "progress") as store:
        def expensive():
            store._execute("WITH RECURSIVE x(v) AS (VALUES(0) UNION ALL SELECT v+1 FROM x WHERE v<100000000) SELECT sum(v) FROM x").fetchone()
        monkeypatch.setattr(store, "_schema_checked", expensive)
        started = time.monotonic()
        with refusal("engagement_timeout"):
            store.snapshot()
        assert store._interrupted and store._callbacks <= module.MAX_PROGRESS_CALLBACKS
        assert time.monotonic() - started < 3


def test_store_path_permissions_and_identity(tmp_path):
    for index, fault in enumerate(("parent_mode", "directory_mode", "file_mode", "hardlink", "symlink", "replace", "directory_replace", "uid")):
        with new_store(tmp_path, str(index)) as store:
            path = store.directory / module.DATABASE
            if fault == "parent_mode":
                store.parent.chmod(0o755)
            elif fault == "directory_mode":
                store.directory.chmod(0o755)
            elif fault == "file_mode":
                path.chmod(0o644)
            elif fault == "hardlink":
                os.link(path, store.parent / "linked")
            elif fault == "symlink":
                path.rename(store.parent / "original")
                path.symlink_to(store.parent / "original")
            elif fault == "replace":
                replacement = store.parent / "replacement"
                replacement.write_bytes(b"invalid")
                replacement.chmod(0o600)
                replacement.replace(path)
            elif fault == "directory_replace":
                store.directory.rename(store.parent / "old")
                store.directory.mkdir(mode=0o700)
            else:
                old = module.os
                class OSProxy:
                    def __getattr__(self, key):
                        return getattr(old, key)
                    def getuid(self):
                        return old.getuid() + 1
                module.os = OSProxy()
            try:
                with refusal("engagement_store_unavailable"):
                    store.snapshot()
                assert store._failed
            finally:
                if fault == "uid":
                    module.os = old
                if fault == "parent_mode":
                    store.parent.chmod(0o700)


def test_sidecar_and_foreign_entry_custody(tmp_path):
    for index, fault in enumerate(("wal", "shm", "extra", "symlink", "hardlink", "mode", "size")):
        with new_store(tmp_path, str(index)) as store:
            if fault in {"wal", "shm", "extra"}:
                name = module.DATABASE + "-" + fault if fault != "extra" else "export.json"
                extra = store.directory / name
                extra.write_bytes(b"x")
                extra.chmod(0o600)
            else:
                journal = store.directory / module.JOURNAL
                if fault == "symlink":
                    journal.symlink_to(store.directory / module.DATABASE)
                elif fault == "hardlink":
                    os.link(store.directory / module.DATABASE, journal)
                else:
                    journal.write_bytes(b"x")
                    journal.chmod(0o644 if fault == "mode" else 0o600)
                    if fault == "size":
                        with journal.open("wb") as output:
                            output.truncate(module.MAX_JOURNAL + 1)
            with refusal("engagement_store_unavailable"):
                store.snapshot()


    # Enumeration itself is bounded, even for a directory flooded by its owner.
    with new_store(tmp_path, "enumeration") as store:
        class Entries:
            calls = 0
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def __iter__(self):
                return self
            def __next__(self):
                self.calls += 1
                if self.calls > 3:
                    pytest.fail("directory enumeration exceeded the closed inventory")
                return SimpleNamespace(name=(module.DATABASE, module.JOURNAL, "foreign")[self.calls-1])
        entries = Entries()
        original = module.os.scandir
        module.os.scandir = lambda _fd: entries
        try:
            with refusal("engagement_store_unavailable"):
                store.snapshot()
            assert entries.calls == 3
        finally:
            module.os.scandir = original


def test_hot_journal_readonly_and_recovery(tmp_path):
    with new_store(tmp_path) as store:
        path, before = store.directory, store.snapshot()
    original_database = (path / module.DATABASE).read_bytes()
    crash(path, "before", str(uuid4()))
    journal = path / module.JOURNAL
    assert journal.is_file() and journal.stat().st_size > 0
    old = journal.read_bytes()
    assert len(old) > 512 and old[:8] != bytes(8)
    assert (path / module.DATABASE).read_bytes() != original_database
    with refusal("engagement_store_unavailable"):
        EngagementStore.open(path, read_only=True)
    assert journal.read_bytes() == old
    with EngagementStore.open(path) as recovered:
        assert recovered.snapshot() == before
    assert not journal.exists()
    with EngagementStore.open(path, read_only=True) as readonly:
        assert readonly.snapshot() == before


def test_other_handle_close_preserves_lock(store):
    other = EngagementStore.open(store.directory)
    script = """
import sqlite3,sys
connection=sqlite3.connect(sys.argv[1],timeout=0.05,isolation_level=None)
try:
    connection.execute('BEGIN IMMEDIATE')
except sqlite3.OperationalError as error:
    assert error.sqlite_errorcode==sqlite3.SQLITE_BUSY
    print('blocked')
else:
    print('acquired')
    connection.rollback()
finally:
    connection.close()
"""
    def probe():
        result = subprocess.run([sys.executable, "-c", script, str(store.directory / module.DATABASE)],
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stderr == ""
        return result.stdout.strip()
    try:
        with store._transaction(write=True):
            assert probe() == "blocked"
            other.close()
            assert probe() == "blocked"
        assert probe() == "acquired"
    finally:
        other.close()


def test_inherited_handle_refuses_before_touch(store):
    class Forbidden:
        def __getattr__(self, _name):
            pytest.fail("inherited handle touched a lock/SQLite resource")
    original = store._lock, store._db, store._pid
    store._lock = store._db = Forbidden()
    store._pid = os.getpid() + 1000000
    try:
        for callback in (store.snapshot, store.close, lambda: revise(store),
                lambda: store.event_receipt(str(uuid4())),
                lambda: store.revoke(expected_revision=1, expected_generation=0, event_id=str(uuid4()))):
            with refusal("engagement_store_unavailable"):
                callback()
    finally:
        store._lock, store._db, store._pid = original


def test_original_deadline_and_busy_bound(tmp_path, monkeypatch):
    with new_store(tmp_path, "busy") as store:
        context = multiprocessing.get_context("spawn")
        receiving, sending = context.Pipe(duplex=False)
        release_read, release_write = context.Pipe(duplex=False)
        process = context.Process(target=_hold_writer,
            args=(str(store.directory / module.DATABASE), sending, release_read))
        process.start()
        sending.close()
        release_read.close()
        try:
            assert receiving.poll(10) and receiving.recv() == "locked"
            started = time.monotonic()
            with refusal("engagement_timeout"):
                revise(store)
            assert time.monotonic() - started < 2
        finally:
            release_write.send("release")
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join(5)
            assert process.exitcode == 0
            process.close()
            receiving.close()
            release_write.close()
    with new_store(tmp_path, "commit_wait") as store:
        before = store.snapshot()
        context = multiprocessing.get_context("spawn")
        receiving, sending = context.Pipe(duplex=False)
        release_read, release_write = context.Pipe(duplex=False)
        process = context.Process(target=_hold_writer,
            args=(str(store.directory / module.DATABASE), sending, release_read, True))
        process.start()
        sending.close()
        release_read.close()
        try:
            assert receiving.poll(10) and receiving.recv() == "locked"
            clock, custody_calls, observed = [10.0], [0], []
            original_files = store._check_files
            def near_deadline(**kwargs):
                original_files(**kwargs)
                custody_calls[0] += 1
                if custody_calls[0] == 2:
                    clock[0] = 11.990
            def blocked_commit(connection):
                observed.append(connection.execute("PRAGMA busy_timeout").fetchone()[0])
                connection.commit()  # Real reader holds SHARED: SQLITE_BUSY.
            with monkeypatch.context() as patch:
                patch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
                patch.setattr(contract, "time", SimpleNamespace(monotonic=lambda: clock[0]))
                patch.setattr(store, "_check_files", near_deadline)
                store._db = DBProxy(store._db, commit=blocked_commit)
                with refusal("engagement_timeout"):
                    revise(store)
            assert len(observed) == 1 and 0 <= observed[0] <= 10
        finally:
            release_write.send("release")
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join(5)
            assert process.exitcode == 0
            process.close()
            receiving.close()
            release_write.close()
        with EngagementStore.open(store.directory) as reopened:
            assert reopened.snapshot() == before
    for phase in ("before_commit", "after_commit", "after_custody"):
        with new_store(tmp_path, phase) as store:
            event = str(uuid4())
            clock = [10.0]
            original_files = store._check_files
            original_event = store._insert_event
            committed = [False]
            def insert(receipt):
                original_event(receipt)
                if phase == "before_commit":
                    clock[0] = 12.01
            def commit(connection):
                connection.commit()
                committed[0] = True
                if phase == "after_commit":
                    clock[0] = 12.01
            def files(**kwargs):
                original_files(**kwargs)
                if phase == "after_custody" and committed[0]:
                    clock[0] = 12.01
            with monkeypatch.context() as patch:
                patch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
                patch.setattr(contract, "time", SimpleNamespace(monotonic=lambda: clock[0]))
                patch.setattr(store, "_insert_event", insert)
                patch.setattr(store, "_check_files", files)
                store._db = DBProxy(store._db, commit=commit)
                with refusal("engagement_timeout"):
                    revise(store, event_id=event)
            with EngagementStore.open(store.directory) as reopened:
                assert reopened.snapshot()["state"]["revision"] == (1 if phase == "before_commit" else 2)
                if phase != "before_commit":
                    assert reopened.event_receipt(event)["revision"] == 2


    # Store input validation inherits its budget; an expired phase must not
    # start scope validation with another two-second allowance.
    with new_store(tmp_path, "nested_validation") as store:
        before = store.snapshot()
        clock, calls = [100.0], []
        original = contract.canonical
        def slow_first_phase(value):
            result = original(value)
            if not calls:
                calls.append(True)
                clock[0] = 102.01
            return result
        def forbidden_scope(_value):
            pytest.fail("expired store work entered a new validation phase")
        with monkeypatch.context() as patch:
            patch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
            patch.setattr(contract, "time", SimpleNamespace(monotonic=lambda: clock[0]))
            patch.setattr(contract, "canonical", slow_first_phase)
            patch.setattr(contract, "validate_scope", forbidden_scope)
            with refusal("engagement_timeout"):
                revise(store)
        assert calls
        with EngagementStore.open(store.directory) as reopened:
            assert reopened.snapshot() == before

    # A final shared-context check can expire after _open has returned. Both
    # constructors must retain and close that handle, including a committed
    # create whose acknowledgement is now uncertain.
    for constructor in ("create", "open"):
        parent = tmp_path / ("constructor_" + constructor)
        parent.mkdir(mode=0o700)
        target, event, engagement = parent / "store", str(uuid4()), str(uuid4())
        if constructor == "open":
            with EngagementStore.create(target, engagement_id=engagement,
                    roe=ROE, event_id=event) as prepared:
                expected = prepared.snapshot()
        clock, captured = [100.0], []
        original_open = EngagementStore._open.__func__
        def expired_open(cls, *args, **kwargs):
            opened = original_open(cls, *args, **kwargs)
            captured.append((opened, opened._parent_fd, opened._directory_fd, opened._db))
            clock[0] = 102.01
            return opened
        with monkeypatch.context() as patch:
            patch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
            patch.setattr(contract, "time", SimpleNamespace(monotonic=lambda: clock[0]))
            patch.setattr(EngagementStore, "_open", classmethod(expired_open))
            with refusal("engagement_timeout"):
                if constructor == "create":
                    EngagementStore.create(target, engagement_id=engagement,
                                           roe=ROE, event_id=event)
                else:
                    EngagementStore.open(target)
        assert len(captured) == 1
        opened, parent_fd, directory_fd, connection = captured[0]
        assert opened._db is opened._parent_fd is opened._directory_fd is None
        for descriptor in (parent_fd, directory_fd):
            with pytest.raises(OSError):
                os.fstat(descriptor)
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        with EngagementStore.open(target) as recovered:
            if constructor == "open":
                assert recovered.snapshot() == expected
            else:
                assert recovered.event_receipt(event)["engagement_id"] == engagement


def test_descriptor_cleanup_and_poison(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    descriptors, connection = (store._parent_fd, store._directory_fd), store._db
    store.close()
    store.close()
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
    with refusal("engagement_store_unavailable"):
        store.snapshot()
    caught = []
    original = EngagementStore._configure
    def fail(self, *, initial):
        caught.append((self, self._parent_fd, self._directory_fd, self._db))
        raise sqlite3.OperationalError("private configure fault")
    monkeypatch.setattr(EngagementStore, "_configure", fail)
    with refusal("engagement_store_unavailable"):
        EngagementStore.open(store.directory)
    assert len(caught) == 1
    failed, parent, directory, connection = caught[0]
    assert failed._db is failed._parent_fd is failed._directory_fd is None
    for fd in (parent, directory):
        with pytest.raises(OSError):
            os.fstat(fd)
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
    monkeypatch.setattr(EngagementStore, "_configure", original)


    # A failure disabling the callback must not skip close or the other FDs.
    with new_store(tmp_path, "cleanup") as cleanup:
        connection = cleanup._db
        descriptors = cleanup._parent_fd, cleanup._directory_fd
        class CleanupProxy(DBProxy):
            def set_progress_handler(self, *_args):
                raise sqlite3.OperationalError("private cleanup callback failure")
        cleanup._db = CleanupProxy(connection)
        with refusal("engagement_store_unavailable"):
            cleanup.close()
        for descriptor in descriptors:
            with pytest.raises(OSError):
                os.fstat(descriptor)
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_creation_write_and_sync_failures(tmp_path, monkeypatch):
    for failing_call in (1, 2, 3):
        parent = tmp_path / str(failing_call)
        parent.mkdir(mode=0o700)
        count = [0]
        fsync = os.fsync
        def fail(fd):
            count[0] += 1
            if count[0] == failing_call:
                raise OSError("private fsync fault")
            return fsync(fd)
        with monkeypatch.context() as patch:
            patch.setattr(module.os, "fsync", fail)
            with refusal("engagement_store_unavailable"):
                EngagementStore.create(parent / "store", engagement_id=str(uuid4()),
                    roe=ROE, event_id=str(uuid4()))
        assert (parent / "store").is_dir()
        with pytest.raises(EngagementError):
            EngagementStore.open(parent / "store")
        with refusal("engagement_already_exists"):
            EngagementStore.create(parent / "store", engagement_id=str(uuid4()),
                roe=ROE, event_id=str(uuid4()))


def test_create_lost_ack_and_readonly_mutation(tmp_path):
    event = str(uuid4())
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    with EngagementStore.create(parent / "store", engagement_id=str(uuid4()), roe=ROE, event_id=event) as store:
        expected = store.event_receipt(event)
        snapshot = store.snapshot()
    with EngagementStore.open(parent / "store", read_only=True) as reopened:
        assert reopened.event_receipt(event) == expected
        for callback in (lambda: revise(reopened), lambda: reopened.revoke(
                expected_revision=1, expected_generation=0, event_id=str(uuid4()))):
            with refusal("engagement_read_only"):
                callback()
        assert reopened.snapshot() == snapshot
