"""The36 pinned SQLite gates; reported data confers no physical authority."""
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
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

from recon_cockpit.secure_agent import engagement_dispatch_store as module
from recon_cockpit.secure_agent import engagement_dispatch_contract as contract
from recon_cockpit.secure_agent import engagement_contract as original_contract
from recon_cockpit.secure_agent.engagement_dispatch_contract import DispatchLedgerError, canonical
from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger

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
UTC = int(datetime(2026, 10, 20, 1, tzinfo=timezone.utc).timestamp()) * 10**9
MONO = 10**9
ZERO = dict.fromkeys(("actions", "connections", "request_bytes", "response_bytes", "runtime_ms"), 0)
COST = dict(actions=1, connections=3, request_bytes=4096, response_bytes=4096, runtime_ms=30000)


def uid():
    return str(uuid4())


def clock(offset=0):
    return {"utc_ns": UTC + offset, "mono_before_ns": MONO + offset, "mono_after_ns": MONO + offset}


def new_store(tmp_path, name="case", roe=None):
    parent = tmp_path / name
    parent.mkdir(mode=0o700)
    return DispatchLedger.create(parent / "store", engagement_id=uid(),
        roe=copy.deepcopy(ROE if roe is None else roe), event_id=uid())


@pytest.fixture
def store(tmp_path):
    opened = new_store(tmp_path)
    try:
        yield opened
    finally:
        opened.close()


@contextmanager
def refusal(code):
    with pytest.raises(DispatchLedgerError) as caught:
        yield
    assert caught.value.code == "engagement_dispatch_" + code
    assert str(caught.value) == caught.value.code


def register(store, *, session=None, sample=None, revision=1, generation=0):
    session, sample = session or uid(), sample or clock()
    result = store.record_session(session_id=session, clock=sample,
        original_deadline_ns=sample["mono_after_ns"] + 60 * 10**9, event_id=uid(),
        expected_revision=revision, expected_generation=generation)
    assert result["disposition"] == "recorded" and result["kind"] == "data_only"
    return session


def reserve(store, session, *, dispatch=None, event=None, slot="http_identify", sample=None,
            approval=None, audit=None, revision=1, generation=0):
    return store.reserve(dispatch_id=dispatch or uid(), session_id=session, slot=slot,
        approval=approval or {"broker_id": uid(), "consume_sequence": 1, "witness_sha256": "a" * 64},
        audit=audit or {"writer_id": uid(), "audit_sequence": 1, "event_sha256": "b" * 64},
        clock=sample or clock(10**6), event_id=event or uid(),
        expected_revision=revision, expected_generation=generation)


def finish(store, session, dispatch, *, outcome="reported_success", observation="default", sample=None, event=None):
    if observation == "default":
        observation = {"evidence_sha256": "c" * 64, "connections": 1, "request_bytes": 32, "response_bytes": 64}
    return store.complete(dispatch_id=dispatch, session_id=session, outcome=outcome,
        observation=observation, clock=sample or clock(2 * 10**6), event_id=event or uid())


def revise(store, roe=None, *, revision=1, generation=0, event=None):
    return store.append_revision(copy.deepcopy(roe or ROE), expected_revision=revision,
        expected_generation=generation, event_id=event or uid())


def revoke(store, *, revision=1, generation=0):
    return store.revoke(expected_revision=revision, expected_generation=generation, event_id=uid())


class DBProxy:
    def __init__(self, connection, *, commit=None):
        self.connection, self.commit_hook = connection, commit

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def commit(self):
        return self.connection.commit() if self.commit_hook is None else self.commit_hook(self.connection)


def _stop(process):
    process.join(10)
    if process.is_alive():
        process.terminate()
        process.join(5)
    if process.is_alive():
        process.kill()
        process.join(5)
    assert not process.is_alive()


def _racer(path, barrier, channel, operation, options):
    try:
        with DispatchLedger.open(path) as opened:
            session = register(opened) if operation == "reserve" else None
            barrier.wait(timeout=15)
            if operation == "reserve":
                result = reserve(opened, session, **options)
            elif operation == "revise":
                result = revise(opened)
            else:
                result = revoke(opened)
            channel.send({"ok": result})
    except DispatchLedgerError as exc:
        channel.send({"error": exc.code})
    finally:
        channel.close()


def race(path, plans):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(len(plans) + 1)
    processes, channels = [], []
    try:
        for operation, options in plans:
            incoming, outgoing = context.Pipe(duplex=False)
            process = context.Process(target=_racer, args=(str(path), barrier, outgoing, operation, options))
            process.start()
            outgoing.close()
            processes.append(process)
            channels.append(incoming)
        barrier.wait(timeout=15)
        results = []
        for channel in channels:
            assert channel.poll(15)
            results.append(channel.recv())
        for process in processes:
            _stop(process)
            assert process.exitcode == 0
        return results
    finally:
        for process in processes:
            _stop(process)
            process.close()
        for channel in channels:
            channel.close()


def _ordered_writer(path, channel, operation, hold):
    try:
        with DispatchLedger.open(path) as opened:
            session = register(opened) if operation == "reserve" else None
            channel.send("prepared")
            assert channel.recv() == "go"
            if hold:
                def commit(connection):
                    channel.send("precommit")
                    assert channel.recv() == "release"
                    connection.commit()
                opened._db = DBProxy(opened._db, commit=commit)
            else:
                def trace(statement):
                    if statement == "BEGIN IMMEDIATE":
                        channel.send("begin_immediate")
                opened._db.set_trace_callback(trace)
            result = reserve(opened, session) if operation == "reserve" else revoke(opened)
            channel.send({"ok": result})
    except DispatchLedgerError as exc:
        channel.send({"error": exc.code})
    finally:
        channel.close()


def ordered(path, first, second):
    context = multiprocessing.get_context("spawn")
    processes, channels = [], []
    try:
        for operation, hold in ((first, True), (second, False)):
            parent, child = context.Pipe()
            process = context.Process(target=_ordered_writer, args=(str(path), child, operation, hold))
            process.start()
            child.close()
            processes.append(process)
            channels.append(parent)
            assert parent.poll(15) and parent.recv() == "prepared"
        channels[0].send("go")
        assert channels[0].poll(10) and channels[0].recv() == "precommit"
        channels[1].send("go")
        assert channels[1].poll(10) and channels[1].recv() == "begin_immediate"
        # SQLite has entered the actual BEGIN while the first writer still
        # holds its transaction. It cannot produce a result before release.
        assert not channels[1].poll(0.05)
        channels[0].send("release")
        results = []
        for channel in channels:
            assert channel.poll(10)
            results.append(channel.recv())
        for process in processes:
            _stop(process)
            assert process.exitcode == 0
        return results
    finally:
        for process in processes:
            _stop(process)
            process.close()
        for channel in channels:
            channel.close()


def _crash_writer(path, channel, phase, operation):
    opened = DispatchLedger.open(path)
    session = register(opened)
    dispatch = None
    if operation == "complete":
        dispatch = reserve(opened, session)["receipt"]["dispatch_id"]
    baseline = opened.snapshot()
    opened._db.execute("PRAGMA cache_size=1")
    old_insert = opened._insert_event
    retained = []
    def insert(event):
        old_insert(event)
        retained.append(event)
        if phase == "before":
            channel.send({"phase": phase, "before": baseline, "event": event})
            channel.recv()  # Parent kills the actual process at this point.
    opened._insert_event = insert
    if phase == "after":
        def commit(connection):
            connection.commit()
            channel.send({"phase": phase, "before": baseline, "event": retained[-1]})
            channel.recv()
        opened._db = DBProxy(opened._db, commit=commit)
    if operation == "complete":
        finish(opened, session, dispatch)
    else:
        reserve(opened, session)
    os._exit(91)


def crash(path, phase, operation="reserve"):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=_crash_writer, args=(str(path), child, phase, operation))
    process.start()
    child.close()
    try:
        assert parent.poll(15), "mutator did not reach the declared commit boundary"
        retained = parent.recv()
        assert retained["phase"] == phase
        process.kill()
        process.join(10)
        assert process.exitcode is not None and process.exitcode != 0
        return retained
    finally:
        _stop(process)
        process.close()
        parent.close()


def _hold_lock(path, channel, reader):
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("BEGIN" if reader else "BEGIN IMMEDIATE")
    if reader:
        connection.execute("SELECT count(*) FROM metadata").fetchone()
    channel.send("locked")
    channel.recv()
    connection.rollback()
    connection.close()
    channel.close()


@contextmanager
def locked(path, reader=False):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=_hold_lock, args=(str(path), child, reader))
    process.start()
    child.close()
    try:
        assert parent.poll(15) and parent.recv() == "locked"
        yield
    finally:
        parent.send("release")
        _stop(process)
        assert process.exitcode == 0
        process.close()
        parent.close()


def test_creates_fresh_private_v2(tmp_path):
    with new_store(tmp_path) as opened:
        snapshot = opened.snapshot()
        assert snapshot["state"]["usage"] == ZERO
        assert snapshot["state"]["utc_high_water_ns"] is None
        assert snapshot["state"]["revision"] == 1 and snapshot["state"]["generation"] == 0
        assert len(snapshot["events"]) == 1 and snapshot["events"][0]["request"]["operation"] == "create"
        assert snapshot["revisions"][0]["roe"] == ROE
        assert opened.directory.stat().st_mode & 0o777 == 0o700
        assert (opened.directory / module.DATABASE).stat().st_mode & 0o777 == 0o600
        assert opened.owner_reference not in (snapshot["engagement_id"], snapshot["events"][0]["event_id"])
        with refusal("already_exists"):
            DispatchLedger.create(opened.directory, engagement_id=uid(), roe=ROE, event_id=uid())


def test_opens_read_only_without_recovery(tmp_path):
    with new_store(tmp_path) as opened:
        path, expected = opened.directory, opened.snapshot()
    with DispatchLedger.open(path, read_only=True) as readonly:
        assert readonly._db.execute("PRAGMA query_only").fetchone()[0] == 1
        assert readonly.snapshot() == expected
    retained = crash(path, "before")
    journal = path / module.JOURNAL
    data, info = journal.read_bytes(), journal.stat()
    assert len(data) > 512 and data[:8] != bytes(8)
    with refusal("store_unavailable"):
        DispatchLedger.open(path, read_only=True)
    assert journal.read_bytes() == data and journal.stat().st_mtime_ns == info.st_mtime_ns
    with DispatchLedger.open(path) as recovered:
        assert recovered.snapshot() == retained["before"]


def test_pins_sqlite_schema_and_limits(store):
    rows = [tuple(row) for row in store._db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name")]
    assert rows == module._SCHEMA_OBJECTS and len(rows) == 23
    for pragma, expected in (("page_size",4096),("max_page_count",2048),("journal_mode","delete"),
            ("synchronous",3),("fullfsync",1),("foreign_keys",1),("trusted_schema",0),("temp_store",2),("user_version",2)):
        assert store._db.execute("PRAGMA " + pragma).fetchone()[0] == expected
    for name, maximum in module._LIMITS.items():
        assert store._db.getlimit(getattr(sqlite3,"SQLITE_LIMIT_"+name)) <= maximum
    for table in ("revisions","sessions","reservations","completions","events"):
        for verb in ("UPDATE", "DELETE"):
            sql = f"UPDATE {table} SET rowid=rowid" if verb == "UPDATE" else f"DELETE FROM {table}"
            # Empty tables still have exact rejection triggers; populated rows exercise them.
            if table in {"revisions","events"}:
                with pytest.raises(sqlite3.IntegrityError):
                    store._db.execute(sql)


def test_reopens_exact_durable_snapshot(tmp_path):
    with new_store(tmp_path) as opened:
        sid = register(opened)
        dispatch = reserve(opened, sid)["receipt"]["dispatch_id"]
        finish(opened, sid, dispatch)
        before, owner, path = opened.snapshot(), opened.owner_reference, opened.directory
    for readonly in (False,True):
        with DispatchLedger.open(path, read_only=readonly) as reopened:
            assert reopened.owner_reference != owner and reopened.snapshot() == before
            assert reopened.snapshot()["state"]["usage"] == COST


def test_revises_without_refund(store):
    sid = register(store)
    reserve(store,sid)
    smaller=copy.deepcopy(ROE); smaller["limits"]["max_connections"]=1
    revise(store,smaller)
    assert store.snapshot()["state"]["usage"] == COST
    with refusal("conflict"):
        reserve(store,sid,revision=2,generation=1)
    fresh=register(store,revision=2,generation=1)
    with refusal("allowance_exhausted"):
        reserve(store,fresh,revision=2,generation=1)
    revise(store,revision=2,generation=1)
    fresh=register(store,revision=3,generation=2)
    reserve(store,fresh,revision=3,generation=2)
    assert store.snapshot()["state"]["usage"] == {k:v*2 for k,v in COST.items()}


def test_revokes_before_reservation(store):
    sid=register(store); revoke(store); before=store.snapshot()
    with refusal("revoked"):
        reserve(store,sid,revision=1,generation=1)
    with refusal("revoked"):
        register(store,revision=1,generation=1)
    assert store.snapshot()==before and before["state"]["usage"]==ZERO


def test_registers_owned_bounded_session(store):
    sid=register(store); row=store.snapshot()["sessions"][0]
    assert row["owner_id"]==store.owner_reference and row["session_id"]==sid
    assert row["plan"]=="http-prefix-v1" and row["session_deadline_ns"]==MONO+60*10**9
    assert row["revision"]==1 and row["generation"]==0
    with refusal("conflict"):
        register(store,session=sid)
    changed=copy.deepcopy(ROE);changed["scope"]["http"]["path"]="/private"
    revise(store,changed)
    with refusal("unsupported_plan"):
        register(store,revision=2,generation=1)


def test_reserves_exact_identify_cost(store):
    sid=register(store); result=reserve(store,sid); snapshot=store.snapshot();row=snapshot["reservations"][0]
    assert row["reservation"]==COST and snapshot["state"]["usage"]==COST
    assert result["kind"]=="data_only" and result["receipt"]["usage"]==COST
    assert row["ready_at_ns"]==MONO and row["deadline_ns"]==MONO+30*10**9
    assert row["policy_sha256"]==snapshot["sessions"][0]["policy_sha256"]
    from recon_cockpit.secure_agent.configurable_contract import action
    from recon_cockpit.secure_agent.models import parse_action
    expected=action(ROE["scope"],1)
    assert row["action_id"]==expected["action_id"] and row["action_sha256"]==parse_action(expected).digest


def test_requires_same_session_predecessor(store):
    sid=register(store)
    with refusal("predecessor_required"):
        reserve(store,sid,slot="http_headers")
    dispatch=reserve(store,sid)["receipt"]["dispatch_id"]
    finish(store,sid,dispatch)
    other=register(store)
    with refusal("predecessor_required"):
        reserve(store,other,slot="http_headers",sample=clock(3*10**6))
    reserve(store,sid,slot="http_headers",sample=clock(3*10**6))
    snapshot=store.snapshot()
    assert snapshot["state"]["usage"]==dict(actions=2,connections=4,request_bytes=4352,response_bytes=6144,runtime_ms=60000)
    assert snapshot["reservations"][1]["ready_at_ns"]==MONO+2*10**6


def test_records_completion_without_new_charge(store):
    sid=register(store);dispatch=reserve(store,sid)["receipt"]["dispatch_id"]
    result=finish(store,sid,dispatch);snapshot=store.snapshot()
    assert snapshot["state"]["usage"]==COST and len(snapshot["completions"])==1
    assert snapshot["completions"][0]["continuation_eligible"] is True
    assert result["kind"]=="data_only" and "authorized" not in result
    with refusal("conflict"):
        finish(store,sid,dispatch)


def test_retains_failed_cancelled_unresolved_charge(tmp_path):
    for outcome in ("reported_failure","cancelled","unresolved"):
        with new_store(tmp_path,outcome) as opened:
            sid=register(opened);dispatch=reserve(opened,sid)["receipt"]["dispatch_id"]
            finish(opened,sid,dispatch,outcome=outcome,observation=None)
            snapshot=opened.snapshot()
            assert snapshot["state"]["usage"]==COST
            assert snapshot["completions"][0]["observation"] is None
            assert snapshot["completions"][0]["continuation_eligible"] is False
            with refusal("predecessor_required"):
                reserve(opened,sid,slot="http_headers",sample=clock(3*10**6))


def test_recovers_exact_lost_ack_receipt(tmp_path):
    with new_store(tmp_path) as opened:
        sid=register(opened);result=reserve(opened,sid);event=opened.snapshot()["events"][-1]
        revoke(opened);path=opened.directory;before=opened.snapshot()
        assert opened.retry(event["request"])["receipt"]==result["receipt"]
    with DispatchLedger.open(path,read_only=True) as reopened:
        result=reopened.retry(event["request"])
        assert result==dict(schema_version="2",kind="data_only",disposition="already_recorded",receipt=event["receipt"])
        assert reopened.snapshot()==before
        unknown=copy.deepcopy(event["request"]);unknown["event_id"]=uid()
        with refusal("event_unknown"):
            reopened.retry(unknown)


def test_rejects_changed_event_request(store):
    sid=register(store);reserve(store,sid);event=store.snapshot()["events"][-1];before=store.snapshot()
    for variant in ("cas","clock","approval","body"):
        request=copy.deepcopy(event["request"])
        if variant=="cas":request["expected_generation"]=1
        elif variant=="clock":request["body"]["clock"]["utc_ns"]+=1
        elif variant=="approval":request["body"]["approval"]["witness_sha256"]="d"*64
        else:request["body"]["dispatch_id"]=uid()
        with refusal("conflict"):
            store.retry(request)
    assert store.snapshot()==before


def test_rejects_foreign_session_and_owner(store,tmp_path):
    sid=register(store);dispatch=reserve(store,sid)["receipt"]["dispatch_id"]
    with DispatchLedger.open(store.directory) as other:
        for operation in (lambda:reserve(other,sid),lambda:finish(other,sid,dispatch)):
            with refusal("foreign_owner"):operation()
    with new_store(tmp_path,"foreign") as foreign:
        # A foreign engagement has no such session; no owner is available to compare.
        with refusal("conflict"):
            reserve(foreign,sid)
    assert store.snapshot()["state"]["usage"]==COST


def test_enforces_dispatch_approval_audit_uniqueness(store):
    sid=register(store);reserve(store,sid);first=store.snapshot()["reservations"][0]
    for variant in ("dispatch","approval","audit","slot"):
        other=sid if variant=="slot" else register(store)
        kwargs={}
        if variant=="dispatch":kwargs["dispatch"]=first["dispatch_id"]
        if variant=="approval":kwargs["approval"]=first["approval"]
        if variant=="audit":kwargs["audit"]=first["audit"]
        with refusal("conflict"):reserve(store,other,**kwargs)
    assert store.snapshot()["state"]["usage"]==COST


def test_exhausts_each_aggregate_allowance(tmp_path):
    limits={"actions":"max_actions","connections":"max_connections","request_bytes":"max_request_bytes",
            "response_bytes":"max_response_bytes","runtime_ms":"max_engagement_ms"}
    for counter,limit in limits.items():
        roe=copy.deepcopy(ROE);roe["limits"][limit]=COST[counter]
        if counter=="runtime_ms":roe["limits"]["max_action_ms"]=30000
        with new_store(tmp_path,counter,roe) as opened:
            reserve(opened,register(opened));before=opened.snapshot()
            sid=register(opened)
            with refusal("allowance_exhausted"):reserve(opened,sid)
            assert opened.snapshot()["state"]["usage"]==before["state"]["usage"]==COST
        if counter in {"connections","request_bytes","response_bytes"}:
            roe["limits"][limit]-=1
            with new_store(tmp_path,counter+"_short",roe) as opened:
                sid=register(opened)
                with refusal("allowance_exhausted"):reserve(opened,sid)
                assert opened.snapshot()["state"]["usage"]==ZERO


def test_serializes_real_last_allowance_race(tmp_path):
    roe=copy.deepcopy(ROE);roe["limits"]["max_actions"]=1
    with new_store(tmp_path,roe=roe) as opened:
        result=race(opened.directory,[("reserve",{}),("reserve",{})])
        assert sum("ok" in row for row in result)==1
        assert [row["error"] for row in result if "error" in row]==["engagement_dispatch_allowance_exhausted"]
        snapshot=opened.snapshot();assert len(snapshot["reservations"])==1 and snapshot["state"]["usage"]==COST


def _pending_writer(path, channel):
    with DispatchLedger.open(path) as opened:
        sid=register(opened)
        insert=opened._insert_event
        def pause(event):
            insert(event);channel.send(event);assert channel.recv()=="commit"
        opened._insert_event=pause
        result=reserve(opened,sid);channel.send(result)
    channel.close()


def test_serializes_real_exact_retry_readers(store):
    context=multiprocessing.get_context("spawn");parent,child=context.Pipe()
    process=context.Process(target=_pending_writer,args=(str(store.directory),child));process.start();child.close()
    try:
        assert parent.poll(15);event=parent.recv()
        with refusal("event_unknown"):store.retry(event["request"])
        parent.send("commit");assert parent.poll(10);result=parent.recv()
        _stop(process);assert process.exitcode==0
        assert store.retry(event["request"])["receipt"]==result["receipt"]
        with DispatchLedger.open(store.directory,read_only=True) as reader:
            assert reader.retry(event["request"])["receipt"]==result["receipt"]
        assert len(store.snapshot()["reservations"])==1 and store.snapshot()["state"]["usage"]==COST
    finally:
        _stop(process);process.close();parent.close()


def test_serializes_real_same_dispatch_race(store):
    dispatch=uid();result=race(store.directory,[("reserve",{"dispatch":dispatch}),("reserve",{"dispatch":dispatch})])
    assert sum("ok" in r for r in result)==1
    assert [r["error"] for r in result if "error" in r]==["engagement_dispatch_conflict"]
    assert len(store.snapshot()["reservations"])==1 and store.snapshot()["state"]["usage"]==COST


def test_serializes_real_same_approval_race(store):
    approval={"broker_id":uid(),"consume_sequence":1,"witness_sha256":"a"*64}
    result=race(store.directory,[("reserve",{"approval":approval}),("reserve",{"approval":approval})])
    assert sum("ok" in r for r in result)==1
    assert [r["error"] for r in result if "error" in r]==["engagement_dispatch_conflict"]
    assert store.snapshot()["state"]["usage"]==COST


def test_orders_real_revoke_before_reserve(store):
    result=ordered(store.directory,"revoke","reserve")
    assert "ok" in result[0] and result[1]=={"error":"engagement_dispatch_revoked"}
    snapshot=store.snapshot();assert snapshot["state"]["status"]=="revoked"
    assert snapshot["state"]["usage"]==ZERO and not snapshot["reservations"]


def test_orders_real_reserve_before_revoke(store):
    result=ordered(store.directory,"reserve","revoke")
    assert all("ok" in row for row in result)
    snapshot=store.snapshot();assert snapshot["state"]["usage"]==COST
    assert snapshot["state"]["status"]=="revoked" and not snapshot["completions"]
    assert [e["request"]["operation"] for e in snapshot["events"]][-2:]==["reserve","revoke"]


def test_serializes_real_revision_revoke_cas(store):
    result=race(store.directory,[("revise",{}),("revoke",{})])
    assert sum("ok" in row for row in result)==1
    snapshot=store.snapshot();assert snapshot["state"]["generation"]==1
    assert len(snapshot["events"])==2
    if snapshot["state"]["status"]=="recorded":
        revoke(store,revision=2,generation=1)
    assert store.snapshot()["state"]["status"]=="revoked"


def test_survives_real_precommit_crash(store):
    retained=crash(store.directory,"before")
    with DispatchLedger.open(store.directory) as recovered:
        assert recovered.snapshot()==retained["before"]
        with refusal("event_unknown"):recovered.retry(retained["event"]["request"])
    assert retained["before"]["state"]["usage"]==ZERO


def test_survives_real_postcommit_lost_ack(store):
    retained=crash(store.directory,"after")
    with DispatchLedger.open(store.directory) as recovered:
        snapshot=recovered.snapshot();event=retained["event"]
        assert snapshot["events"][-1]==event and snapshot["state"]["usage"]==COST
        assert recovered.retry(event["request"])["receipt"]==event["receipt"]
        with refusal("foreign_owner"):
            finish(recovered,event["receipt"]["session_id"],event["receipt"]["dispatch_id"])
        assert not snapshot["completions"]


def test_survives_completion_commit_crashes(tmp_path):
    for phase in ("before","after"):
        with new_store(tmp_path,phase) as opened:
            retained=crash(opened.directory,phase,"complete")
            with DispatchLedger.open(opened.directory) as recovered:
                snapshot=recovered.snapshot()
                assert snapshot["state"]["usage"]==COST
                assert len(snapshot["completions"])==(phase=="after")
                if phase=="after":assert recovered.retry(retained["event"]["request"])["receipt"]==retained["event"]["receipt"]
                else:assert snapshot==retained["before"]


def test_poisons_on_storage_faults(tmp_path,monkeypatch):
    for phase in ("insert","commit","lost_ack"):
        with new_store(tmp_path,phase) as opened:
            sid=register(opened);event=uid();before=opened.snapshot()
            if phase=="insert":
                original=opened._insert_event
                def fail(row):original(row);raise sqlite3.OperationalError("private insert fault")
                monkeypatch.setattr(opened,"_insert_event",fail)
            else:
                def fail(connection):
                    if phase=="lost_ack":connection.commit()
                    raise sqlite3.OperationalError("private commit fault")
                opened._db=DBProxy(opened._db,commit=fail)
            with refusal("store_unavailable"):reserve(opened,sid,event=event)
            assert opened._failed
            with refusal("store_unavailable"):opened.snapshot()
            with DispatchLedger.open(opened.directory) as recovered:
                if phase=="lost_ack":assert recovered.event_receipt(event)["usage"]==COST
                else:assert recovered.snapshot()==before
    for index in (1,2,3):
        parent=tmp_path/("fsync"+str(index));parent.mkdir(mode=0o700);calls=[0];original=os.fsync
        def broken(fd):
            calls[0]+=1
            if calls[0]==index:raise OSError("private fsync fault")
            return original(fd)
        with monkeypatch.context() as patch:
            patch.setattr(module.os,"fsync",broken)
            with refusal("store_unavailable"):
                DispatchLedger.create(parent/"store",engagement_id=uid(),roe=ROE,event_id=uid())
        assert (parent/"store").is_dir()
        with refusal("already_exists"):
            DispatchLedger.create(parent/"store",engagement_id=uid(),roe=ROE,event_id=uid())


def test_rejects_reopened_and_inherited_owners(store):
    sid=register(store)
    with DispatchLedger.open(store.directory) as other:
        with refusal("foreign_owner"):reserve(other,sid)
    class Forbidden:
        def __getattr__(self,name):pytest.fail("foreign process touched inherited resource: "+name)
    originals=store._pid,store._lock,store._db;store._pid+=10**6;store._lock=store._db=Forbidden()
    try:
        for call in (store.close,store.snapshot,lambda:store.owner_reference,lambda:reserve(store,sid),
                lambda:register(store),lambda:store.retry({}),lambda:store.event_receipt(uid())):
            with refusal("store_unavailable"):call()
    finally:store._pid,store._lock,store._db=originals


def test_preserves_real_external_sqlite_lock(store,tmp_path):
    from recon_cockpit.secure_agent.engagement_dispatch_inspection import inspect_export,read_roe_file
    from recon_cockpit.secure_agent.engagement_store import EngagementStore
    from recon_cockpit.secure_agent.engagement_contract import EngagementError
    script="""
import sqlite3,sys
c=sqlite3.connect(sys.argv[1],timeout=.05,isolation_level=None)
try:
 c.execute('BEGIN IMMEDIATE')
except sqlite3.OperationalError as e:
 assert e.sqlite_errorcode==sqlite3.SQLITE_BUSY
 print('blocked')
else:
 print('acquired');c.rollback()
finally:c.close()
"""
    parent=tmp_path/"v1_parent";parent.mkdir(mode=0o700)
    with EngagementStore.create(parent/"store",engagement_id=uid(),roe=ROE,event_id=uid()) as v1:
        for active,own_class,foreign_class,foreign_error in ((store,DispatchLedger,EngagementStore,EngagementError),
                (v1,EngagementStore,DispatchLedger,DispatchLedgerError)):
            path=active.directory/module.DATABASE
            def probe():
                r=subprocess.run([sys.executable,"-c",script,str(path)],capture_output=True,text=True,timeout=10)
                assert r.returncode==0 and not r.stderr
                return r.stdout.strip()
            other=own_class.open(active.directory)
            try:
                with active._transaction(write=True):
                    assert probe()=="blocked"
                    other.close();assert probe()=="blocked"
                    for reader in (read_roe_file,inspect_export):
                        with pytest.raises(DispatchLedgerError):reader(path)
                        assert probe()=="blocked"
                    with pytest.raises(foreign_error):foreign_class.open(active.directory)
                    assert probe()=="blocked"
                assert probe()=="acquired"
            finally:other.close()


def test_enforces_private_file_custody(tmp_path):
    for fault in ("parent_mode","directory_mode","file_mode","hardlink","symlink","replace","directory_replace","foreign","journal_mode","journal_link","journal_size","uid"):
        with new_store(tmp_path,fault) as opened:
            path=opened.directory/module.DATABASE
            old_os=module.os
            if fault=="parent_mode":opened.parent.chmod(0o755)
            elif fault=="directory_mode":opened.directory.chmod(0o755)
            elif fault=="file_mode":path.chmod(0o644)
            elif fault=="hardlink":os.link(path,opened.parent/"linked")
            elif fault=="symlink":path.rename(opened.parent/"original");path.symlink_to(opened.parent/"original")
            elif fault=="replace":
                replacement=opened.parent/"new";replacement.write_bytes(b"invalid");replacement.chmod(0o600);replacement.replace(path)
            elif fault=="directory_replace":opened.directory.rename(opened.parent/"old");opened.directory.mkdir(mode=0o700)
            elif fault=="foreign":(opened.directory/"foreign").write_bytes(b"x")
            elif fault=="journal_link":os.link(path,opened.directory/module.JOURNAL)
            elif fault.startswith("journal_"):
                journal=opened.directory/module.JOURNAL;journal.write_bytes(b"x");journal.chmod(0o644 if fault=="journal_mode" else 0o600)
                if fault=="journal_size":
                    with journal.open("wb") as stream:stream.truncate(module.MAX_JOURNAL+1)
            else:
                class OSProxy:
                    def __getattr__(self,k):return getattr(old_os,k)
                    def getuid(self):return old_os.getuid()+1
                module.os=OSProxy()
            try:
                with refusal("store_unavailable"):opened.snapshot()
                assert opened._failed
            finally:
                module.os=old_os
                if fault=="parent_mode":opened.parent.chmod(0o700)


def test_handles_corruption_and_hot_journal(tmp_path):
    for fault in ("metadata","trigger","nested","bytes"):
        with new_store(tmp_path,fault) as opened:path=opened.directory
        if fault=="bytes":(path/module.DATABASE).write_bytes(b"not sqlite")
        else:
            connection=sqlite3.connect(path/module.DATABASE,isolation_level=None)
            if fault=="metadata":connection.execute("UPDATE metadata SET actions_reserved=1")
            elif fault=="trigger":connection.execute("DROP TRIGGER events_no_delete")
            else:
                connection.execute("DROP TRIGGER events_no_update")
                connection.execute("UPDATE events SET request_json=?",("["*1900+"0"+"]"*1900,))
                connection.execute(next(s for s in module.SCHEMA_SQL if s.startswith("CREATE TRIGGER events_no_update")))
            connection.close()
        with pytest.raises(DispatchLedgerError) as caught:DispatchLedger.open(path)
        assert caught.value.code in {"engagement_dispatch_store_invalid","engagement_dispatch_store_unavailable"}
    # A closed WAL database has no live sidecars, yet assigning DELETE would
    # rewrite its header before rejecting unsupported version99. Both open modes
    # must instead leave the main database file unchanged.
    with new_store(tmp_path,"unsupported_wal") as opened:path=opened.directory
    database=path/module.DATABASE
    connection=sqlite3.connect(database,isolation_level=None)
    assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]=="wal"
    connection.execute("PRAGMA user_version=99")
    connection.close()
    assert {entry.name for entry in path.iterdir()}=={module.DATABASE}
    def identity():
        info=database.stat()
        return (database.read_bytes(),info.st_dev,info.st_ino,info.st_mode,info.st_uid,
                info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    original=identity()
    assert original[0][18:20]==bytes((2,2))
    for readonly in (False,True):
        with refusal("store_invalid"):DispatchLedger.open(path,read_only=readonly)
        assert identity()==original
        # SQLite may retain its own WAL/SHM auxiliaries while diagnosing an
        # unsupported WAL header, especially in read-only mode. Main DB remains
        # unchanged; refusal never adopts or silently deletes these artifacts.
        assert {entry.name for entry in path.iterdir()} <= {
            module.DATABASE, module.DATABASE+"-wal", module.DATABASE+"-shm"}
    with new_store(tmp_path,"journal") as opened:
        retained=crash(opened.directory,"before")
        journal=opened.directory/module.JOURNAL;data=journal.read_bytes()
        assert len(data)>512 and data[:8]!=bytes(8)
        assert (opened.directory/module.DATABASE).read_bytes()!=b""
        with refusal("store_unavailable"):DispatchLedger.open(opened.directory,read_only=True)
        assert journal.read_bytes()==data
        with DispatchLedger.open(opened.directory) as recovered:assert recovered.snapshot()==retained["before"]
        assert not journal.exists()


def test_bounds_shared_operation_work(tmp_path,monkeypatch):
    # Configuration and constructor replay share actual SQLite callbacks.
    query="WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n"
    for constructor in ("create","rw","ro"):
        with new_store(tmp_path,"prepared_"+constructor) as prepared:path=prepared.directory
        callbacks=[];captured=[]
        original_progress=DispatchLedger._progress;original_configure=DispatchLedger._configure
        original_snapshot=DispatchLedger._snapshot_checked
        def progress(self):callbacks.append(1);return original_progress(self)
        def configure(self,*,initial):
            original_configure(self,initial=initial);self._db.execute(query).fetchone()
        def snapshot(self):
            captured.append((self,self._parent_fd,self._directory_fd,self._db))
            while True:self._execute(query).fetchone()
        with monkeypatch.context() as patch:
            patch.setattr(DispatchLedger,"_progress",progress);patch.setattr(DispatchLedger,"_configure",configure)
            patch.setattr(DispatchLedger,"_snapshot_checked",snapshot)
            with refusal("timeout"):
                if constructor=="create":new_store(tmp_path,"exhausted")
                else:DispatchLedger.open(path,read_only=constructor=="ro")
        assert len(callbacks)==4000
        opened,parent,directory,connection=captured[0]
        assert opened._db is opened._parent_fd is opened._directory_fd is None
        for fd in (parent,directory):
            with pytest.raises(OSError):os.fstat(fd)
        with pytest.raises(sqlite3.ProgrammingError):connection.execute("SELECT 1")
    with new_store(tmp_path,"fresh") as opened:
        calls=[];original=opened._progress
        def counted():calls.append(1);return original()
        monkeypatch.setattr(opened,"_progress",counted)
        for call in (opened.snapshot,lambda:opened.event_receipt(opened.snapshot()["events"][0]["event_id"])):
            # Snapshot/receipt each receive an independent allowance under the lock.
            calls.clear();call();assert 0<=opened._callbacks<=len(calls)<4000
    with new_store(tmp_path,"blocked") as opened:
        with locked(opened.directory/module.DATABASE):
            start=time.monotonic()
            with refusal("timeout"):revise(opened)
            assert time.monotonic()-start<2
    with new_store(tmp_path,"commit") as opened:
        before=opened.snapshot()
        with locked(opened.directory/module.DATABASE,reader=True):
            now=[10.0];checks=[0];observed=[];old=opened._check_files
            def files(**kwargs):
                old(**kwargs);checks[0]+=1
                if checks[0]==2:now[0]=11.99
            def blocked(connection):observed.append(connection.execute("PRAGMA busy_timeout").fetchone()[0]);connection.commit()
            with monkeypatch.context() as patch:
                patch.setattr(module,"time",SimpleNamespace(monotonic=lambda:now[0]))
                patch.setattr(original_contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
                if hasattr(contract,"time"):patch.setattr(contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
                patch.setattr(opened,"_check_files",files);opened._db=DBProxy(opened._db,commit=blocked)
                with refusal("timeout"):revise(opened)
            assert len(observed)==1 and 0<=observed[0]<=10
        with DispatchLedger.open(opened.directory) as recovered:assert recovered.snapshot()==before
    for phase in ("before_commit","after_commit","after_custody"):
        with new_store(tmp_path,phase) as opened:
            now=[10.0];event=uid();old_insert=opened._insert_event;old_files=opened._check_files;committed=[False]
            def insert(row):
                old_insert(row)
                if phase=="before_commit":now[0]=12.01
            def commit(connection):
                connection.commit();committed[0]=True
                if phase=="after_commit":now[0]=12.01
            def files(**kwargs):
                old_files(**kwargs)
                if phase=="after_custody" and committed[0]:now[0]=12.01
            with monkeypatch.context() as patch:
                patch.setattr(module,"time",SimpleNamespace(monotonic=lambda:now[0]));patch.setattr(original_contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
                if hasattr(contract,"time"):patch.setattr(contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
                patch.setattr(opened,"_insert_event",insert);patch.setattr(opened,"_check_files",files)
                opened._db=DBProxy(opened._db,commit=commit)
                with refusal("timeout"):revise(opened,event=event)
            with DispatchLedger.open(opened.directory) as recovered:
                assert recovered.snapshot()["state"]["revision"]==(1 if phase=="before_commit" else 2)


    # Reused v1 validation consumes the same original operation clock.
    with new_store(tmp_path,"nested") as opened:
        before=opened.snapshot();now=[100.0];calls=[];old=contract.canonical
        def slow(value):
            result=old(value)
            if not calls:calls.append(True);now[0]=102.01
            return result
        def forbidden(_value):pytest.fail("expired v1 validation entered a fresh scope phase")
        with monkeypatch.context() as patch:
            patch.setattr(module,"time",SimpleNamespace(monotonic=lambda:now[0]))
            patch.setattr(original_contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
            if hasattr(contract,"time"):patch.setattr(contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
            patch.setattr(contract,"canonical",slow);patch.setattr(original_contract,"validate_scope",forbidden)
            with refusal("timeout"):revise(opened)
        assert calls
        with DispatchLedger.open(opened.directory) as recovered:assert recovered.snapshot()==before
    # A slow creation fsync consumes the original budget; it cannot start anew.
    parent=tmp_path/"slow_sync";parent.mkdir(mode=0o700);now=[10.0];sync=os.fsync;calls=[]
    def delayed_sync(fd):
        sync(fd);calls.append(fd);now[0]=12.01
    with monkeypatch.context() as patch:
        patch.setattr(module,"time",SimpleNamespace(monotonic=lambda:now[0]))
        patch.setattr(original_contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
        if hasattr(contract,"time"):patch.setattr(contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
        patch.setattr(module.os,"fsync",delayed_sync)
        with refusal("timeout"):
            DispatchLedger.create(parent/"store",engagement_id=uid(),roe=ROE,event_id=uid())
    assert calls and (parent/"store").exists()
    # Final context expiry after _open returns still owns and closes the handle.
    for kind in ("create","open"):
        parent=tmp_path/("late_"+kind);parent.mkdir(mode=0o700);path=parent/"store";event=uid();engagement=uid()
        if kind=="open":
            with DispatchLedger.create(path,engagement_id=engagement,roe=ROE,event_id=event) as prepared:
                before=prepared.snapshot()
        now=[10.0];captured=[];original_open=DispatchLedger._open.__func__
        def late(cls,*args,**kwargs):
            opened=original_open(cls,*args,**kwargs)
            captured.append((opened,opened._parent_fd,opened._directory_fd,opened._db));now[0]=12.01
            return opened
        with monkeypatch.context() as patch:
            patch.setattr(module,"time",SimpleNamespace(monotonic=lambda:now[0]))
            patch.setattr(original_contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
            if hasattr(contract,"time"):patch.setattr(contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
            patch.setattr(DispatchLedger,"_open",classmethod(late))
            with refusal("timeout"):
                if kind=="create":DispatchLedger.create(path,engagement_id=engagement,roe=ROE,event_id=event)
                else:DispatchLedger.open(path)
        opened,parent_fd,directory_fd,connection=captured[0]
        assert opened._db is opened._parent_fd is opened._directory_fd is None
        for fd in (parent_fd,directory_fd):
            with pytest.raises(OSError):os.fstat(fd)
        with pytest.raises(sqlite3.ProgrammingError):connection.execute("SELECT 1")
        with DispatchLedger.open(path) as recovered:
            if kind=="open":assert recovered.snapshot()==before
            else:assert recovered.event_receipt(event)["engagement_id"]==engagement


def test_refuses_row_event_and_file_overflow(tmp_path):
    with new_store(tmp_path,"combined") as opened:
        for revision in range(1,64):revise(opened,revision=revision,generation=revision-1)
        before=opened.snapshot()
        with refusal("limit_exceeded"):revise(opened,revision=64,generation=63)
        assert opened.snapshot()==before
        for index in range(64):
            offset=index*3*10**6
            sid=register(opened,sample=clock(offset),revision=64,generation=63)
            dispatch=reserve(opened,sid,sample=clock(offset+10**6),revision=64,generation=63)["receipt"]["dispatch_id"]
            finish(opened,sid,dispatch,sample=clock(offset+2*10**6))
        before=opened.snapshot()
        assert [len(before[k]) for k in ("revisions","sessions","reservations","completions","events")]==[64,64,64,64,256]
        with refusal("limit_exceeded"):
            register(opened,sample=clock(192*10**6),revision=64,generation=63)
        assert opened.snapshot()==before
        revoke(opened,revision=64,generation=63)
        expected=opened.snapshot();path=opened.directory
        assert len(expected["events"])==257 and expected["state"]["generation"]==64
        assert expected["state"]["usage"]=={k:v*64 for k,v in COST.items()}
        assert len(canonical(expected))<=2097152
        assert (path/module.DATABASE).stat().st_size<=module.MAX_DATABASE
    with DispatchLedger.open(path,read_only=True) as reopened:
        assert reopened.snapshot()==expected
    for name,maximum in (("db",module.MAX_DATABASE),("journal",module.MAX_JOURNAL)):
        with new_store(tmp_path,name) as opened:
            target=opened.directory/(module.DATABASE if name=="db" else module.JOURNAL)
            with target.open("ab") as stream:stream.truncate(maximum+1)
            target.chmod(0o600)
            with refusal("store_unavailable"):opened.snapshot()
    with refusal("limit_exceeded"):contract.decode_export(b" "*(2097152+1))


def test_persists_clock_water_across_handles(tmp_path):
    with new_store(tmp_path) as opened:
        sid=register(opened);dispatch=reserve(opened,sid)["receipt"]["dispatch_id"]
        late=clock(10**9);finish(opened,sid,dispatch,sample=late)
        before=opened.snapshot();path=opened.directory
        assert before["state"]["utc_high_water_ns"]==UTC+10**9
    with DispatchLedger.open(path) as reopened:
        with refusal("clock_invalid"):register(reopened,sample=clock())
        sid=register(reopened,sample=clock(10**9))
        reserve(reopened,sid,sample=clock(10**9+10**6))
        snapshot=reopened.snapshot();row=snapshot["reservations"][-1]
        assert row["deadline_ns"]<=snapshot["sessions"][-1]["session_deadline_ns"]


def test_keeps_read_only_operations_nonmutating(tmp_path):
    with new_store(tmp_path) as opened:
        sid=register(opened);reserve(opened,sid);snapshot=opened.snapshot();path=opened.directory
    db=path/module.DATABASE;before=(db.read_bytes(),db.stat().st_mode,db.stat().st_mtime_ns)
    with DispatchLedger.open(path,read_only=True) as readonly:
        assert readonly.snapshot()==snapshot
        event=snapshot["events"][-1]
        assert readonly.event_receipt(event["event_id"])==event["receipt"]
        assert readonly.retry(event["request"])["receipt"]==event["receipt"]
        for call in (lambda:revise(readonly),lambda:revoke(readonly),lambda:register(readonly),
                lambda:reserve(readonly,sid),lambda:finish(readonly,sid,event["receipt"]["dispatch_id"])):
            with refusal("read_only"):call()
    assert (db.read_bytes(),db.stat().st_mode,db.stat().st_mtime_ns)==before
    # Removing duplicate read replay never permits a malformed before-state to
    # reach the private read body; a separate writer performs the actual tamper.
    with DispatchLedger.open(path,read_only=True) as readonly:
        connection=sqlite3.connect(db,isolation_level=None)
        connection.execute("UPDATE metadata SET actions_reserved=2")
        connection.close()
        changed=(db.read_bytes(),db.stat().st_mode,db.stat().st_mtime_ns)
        entered=[]
        with refusal("store_invalid"):
            with readonly._transaction():entered.append(True)
        assert not entered and readonly._failed
        assert (db.read_bytes(),db.stat().st_mode,db.stat().st_mtime_ns)==changed


def test_closes_owned_resources_idempotently(tmp_path,monkeypatch):
    opened=new_store(tmp_path);fds=opened._parent_fd,opened._directory_fd;connection=opened._db
    opened.close();opened.close()
    for fd in fds:
        with pytest.raises(OSError):os.fstat(fd)
    with pytest.raises(sqlite3.ProgrammingError):connection.execute("SELECT 1")
    with refusal("store_unavailable"):opened.snapshot()
    captured=[];original=DispatchLedger._configure
    def fail(self,*,initial):captured.append((self,self._parent_fd,self._directory_fd,self._db));raise sqlite3.OperationalError("private fault")
    with monkeypatch.context() as patch:
        patch.setattr(DispatchLedger,"_configure",fail)
        with refusal("store_unavailable"):DispatchLedger.open(opened.directory)
    failed,parent,directory,connection=captured[0]
    assert failed._db is failed._parent_fd is failed._directory_fd is None
    for fd in (parent,directory):
        with pytest.raises(OSError):os.fstat(fd)
    with pytest.raises(sqlite3.ProgrammingError):connection.execute("SELECT 1")
    with new_store(tmp_path,"callback_close") as opened:
        connection=opened._db;fds=opened._parent_fd,opened._directory_fd
        class Broken(DBProxy):
            def set_progress_handler(self,*args):raise sqlite3.OperationalError("private cleanup fault")
        opened._db=Broken(connection)
        with refusal("store_unavailable"):opened.close()
        for fd in fds:
            with pytest.raises(OSError):os.fstat(fd)
        with pytest.raises(sqlite3.ProgrammingError):connection.execute("SELECT 1")

    # Normal close must finish all resource cleanup but refuse a late success.
    opened=new_store(tmp_path,"late_close");fds=opened._parent_fd,opened._directory_fd;connection=opened._db;now=[10.0]
    class SlowClose(DBProxy):
        def close(self):self.connection.close();now[0]=12.01
    opened._db=SlowClose(connection)
    with monkeypatch.context() as patch:
        patch.setattr(module,"time",SimpleNamespace(monotonic=lambda:now[0]))
        patch.setattr(original_contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
        if hasattr(contract,"time"):patch.setattr(contract,"time",SimpleNamespace(monotonic=lambda:now[0]))
        with refusal("timeout"):opened.close()
    assert opened._db is opened._parent_fd is opened._directory_fd is None
    for fd in fds:
        with pytest.raises(OSError):os.fstat(fd)
    with pytest.raises(sqlite3.ProgrammingError):connection.execute("SELECT 1")
