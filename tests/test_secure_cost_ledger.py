"""Real SQLite accounting, process races, crash recovery and safe inspection."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

from recon_cockpit.secure_agent.cost_contract import CostError, PriceCard, TokenUsage, MAX_AMOUNT
from recon_cockpit.secure_agent.cost_ledger import BudgetExceeded, CostLedger


PRICE = PriceCard("fixture-provider", "fixture-model", "test-v1", 1_000_000, 500_000, 2_000_000)
DIGEST = hashlib.sha256(b"synthetic request").hexdigest()


@pytest.fixture
def ledger(tmp_path):
    with CostLedger.create(tmp_path / "costs", account_id="account", limit_microusd=10_000,
                           mode="simulation") as value:
        value.add_scope("engagement", parent_id="account", kind="engagement")
        value.add_scope("session", parent_id="engagement", kind="session")
        value.add_scope("agent", parent_id="session", kind="agent")
        value.add_scope("action", parent_id="agent", kind="action")
        yield value


def estimate(ledger, attempt_id="attempt", **kwargs):
    return ledger.estimate(attempt_id, **{"scope_id": "action", "request_digest": DIGEST, "price": PRICE,
        "usage": TokenUsage(10, 10), "input_token_limit": 100, "output_token_limit": 100, **kwargs})


def dispatch(ledger, attempt_id="attempt"):
    estimate(ledger, attempt_id)
    ledger.reserve(attempt_id)
    return ledger.begin_dispatch(attempt_id, request_digest=DIGEST)


def files(path):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir() if p.is_file()}


def test_estimate_hold_actual_and_billing_revision_are_distinct(ledger):
    attempt = estimate(ledger)
    assert attempt["quote"]["estimated_microusd"] == 30
    assert attempt["quote"]["ceiling_microusd"] == 300
    assert attempt["actual_microusd"] is None
    assert ledger.snapshot("account")["available_microusd"] == 10_000
    ledger.reserve("attempt")
    held = ledger.snapshot("account")
    assert (held["actual_microusd"], held["reserved_microusd"], held["available_microusd"]) == (0, 300, 9700)
    ledger.begin_dispatch("attempt", request_digest=DIGEST)
    assert not ledger.snapshot("account")["actual_complete"]
    ledger.settle_usage("attempt", TokenUsage(80, 40, 20), receipt_reference="request-1", event_id="usage-1")
    settled = ledger.snapshot("account")
    assert (settled["actual_microusd"], settled["reserved_microusd"], settled["available_microusd"]) == (150, 0, 9850)
    assert settled["usage_derived_microusd"] == 150
    ledger.reconcile("attempt", 140, billing_reference="bill-1-line-1", event_id="billing-1")
    final = ledger.snapshot("account")
    assert (final["actual_microusd"], final["usage_derived_microusd"], final["billing_confirmed_microusd"]) == (140, 0, 140)
    assert ledger.attempt("attempt")["usage"] == {"input_tokens": 80, "output_tokens": 40, "cached_input_tokens": 20}
    assert [e["payload"]["actual_microusd"] for e in ledger.events() if e["kind"] == "cost_settled"] == [150, 140]


@pytest.mark.parametrize("scope", ["account", "engagement", "session", "agent", "action"])
def test_every_ancestor_limit_blocks_atomically_and_identifies_the_limit(ledger, scope):
    ledger.set_limit(scope, 299, event_id="limit-change")
    estimate(ledger)
    before = ledger.events()
    with pytest.raises(BudgetExceeded) as exc:
        ledger.reserve("attempt")
    assert exc.value.scope_id == scope
    assert exc.value.available_microusd == 299 and exc.value.requested_microusd == 300
    assert ledger.events()[:-1] == before
    denial = ledger.events()[-1]
    assert denial["kind"] == "reservation_denied"
    assert denial["payload"]["blocking_scope_id"] == scope
    assert ledger.attempt("attempt")["state"] == "estimated"
    assert ledger.snapshot("account")["reserved_microusd"] == 0
    assert ledger.snapshot("action")["effective_available_microusd"] == 299


def test_new_session_and_reopen_share_the_existing_account_budget(ledger):
    ledger.set_limit("engagement", 300, event_id="limit")
    dispatch(ledger)
    ledger.add_scope("next-session", parent_id="engagement", kind="session")
    ledger.add_scope("next-action", parent_id="next-session", kind="action")
    estimate(ledger, "next-attempt", scope_id="next-action")
    path = ledger.directory
    ledger.close()
    with CostLedger(path) as reopened:
        assert reopened.snapshot("next-action")["effective_available_microusd"] == 0
        with pytest.raises(BudgetExceeded):
            reopened.reserve("next-attempt")
        with pytest.raises(CostError, match="cost_invalid_transition"):
            reopened.begin_dispatch("attempt", request_digest=DIGEST)
        with pytest.raises(CostError, match="cost_reconciliation_required"):
            reopened.cancel("attempt")


@pytest.mark.parametrize("reason", ["timeout", "cancelled", "transport_error", "missing_usage", "recovery"])
def test_unknown_cost_never_becomes_zero_or_refunds_a_hold(ledger, reason):
    dispatch(ledger)
    ledger.mark_uncertain("attempt", reason=reason)
    result = ledger.attempt("attempt")
    assert result["state"] == "uncertain" and result["actual_microusd"] is None
    assert result["reserved_microusd"] == 300
    with pytest.raises(CostError, match="cost_reconciliation_required"):
        ledger.cancel("attempt")
    with pytest.raises(CostError, match="cost_invalid_transition"):
        ledger.reserve("attempt")
    ledger.reconcile("attempt", 0, billing_reference="confirmed-no-charge", event_id="reconciled")
    assert ledger.snapshot("account")["available_microusd"] == 10_000
    assert ledger.attempt("attempt")["actual_source"] == "billing_confirmed"


@pytest.mark.parametrize("reserve", [False, True])
def test_cancellation_before_dispatch_is_idempotent_and_releases_only_its_hold(ledger, reserve):
    estimate(ledger)
    if reserve:
        ledger.reserve("attempt")
    cancelled = ledger.cancel("attempt")
    assert ledger.cancel("attempt") == cancelled
    assert cancelled["actual_source"] == "not_sent"
    assert ledger.snapshot("account")["available_microusd"] == 10_000
    with pytest.raises(CostError, match="cost_invalid_transition"):
        ledger.begin_dispatch("attempt", request_digest=DIGEST)


def test_replays_do_not_double_charge_or_roll_back_newer_billing(ledger):
    estimate(ledger)
    ledger.reserve("attempt")
    before = ledger.events()
    assert ledger.reserve("attempt")["reserved_microusd"] == 300
    assert estimate(ledger)["state"] == "reserved"
    assert ledger.events() == before
    ledger.begin_dispatch("attempt", request_digest=DIGEST)
    args = {"receipt_reference": "request-1", "event_id": "usage-1"}
    ledger.settle_usage("attempt", TokenUsage(10, 10), **args)
    ledger.reconcile("attempt", 40, billing_reference="bill-1", event_id="bill-event-1")
    ledger.settle_usage("attempt", TokenUsage(10, 10), **args)
    assert ledger.snapshot("account")["actual_microusd"] == 40
    ledger.reconcile("attempt", 40, billing_reference="bill-1", event_id="bill-event-1")
    assert len([e for e in ledger.events() if e["kind"] == "cost_settled"]) == 2
    with pytest.raises(CostError, match="cost_idempotency_conflict"):
        ledger.reconcile("attempt", 41, billing_reference="bill-1", event_id="bill-event-1")


@pytest.mark.parametrize("billing", [False, True])
def test_a_receipt_cannot_charge_another_attempt(ledger, billing):
    for attempt in ("one", "two"):
        dispatch(ledger, attempt)
    if billing:
        ledger.reconcile("one", 30, billing_reference="shared", event_id="event-1")
        settle = lambda: ledger.reconcile("two", 30, billing_reference="shared", event_id="event-2")
    else:
        ledger.settle_usage("one", TokenUsage(10, 10), receipt_reference="shared", event_id="event-1")
        settle = lambda: ledger.settle_usage("two", TokenUsage(10, 10), receipt_reference="shared", event_id="event-2")
    with pytest.raises(CostError, match="cost_receipt_already_used"):
        settle()
    assert ledger.snapshot("account")["actual_microusd"] == 30
    assert ledger.attempt("two")["reserved_microusd"] == 300


def test_actual_overrun_is_recorded_and_blocks_reserved_and_new_dispatch(ledger):
    ledger.set_limit("account", 600, event_id="limit")
    dispatch(ledger)
    estimate(ledger, "pending")
    ledger.reserve("pending")
    ledger.settle_usage("attempt", TokenUsage(400, 200), receipt_reference="usage", event_id="settled")
    snapshot = ledger.snapshot("account")
    assert snapshot["actual_microusd"] == 800 and snapshot["reserved_microusd"] == 300
    assert ledger.attempt("attempt")["reservation_overrun_microusd"] == 500
    assert snapshot["overspent_microusd"] == 200 and snapshot["overcommitted_microusd"] == 500
    with pytest.raises(BudgetExceeded):
        ledger.begin_dispatch("pending", request_digest=DIGEST)
    estimate(ledger, "next")
    with pytest.raises(BudgetExceeded):
        ledger.reserve("next")
    ledger.cancel("pending")
    ledger.reconcile("attempt", 100, billing_reference="corrected-billing", event_id="corrected")
    assert ledger.reserve("next")["state"] == "reserved"


def test_changed_budget_is_audited_and_rechecked_before_dispatch(ledger):
    estimate(ledger)
    ledger.reserve("attempt")
    ledger.set_limit("action", 100, event_id="lower")
    with pytest.raises(BudgetExceeded):
        ledger.begin_dispatch("attempt", request_digest=DIGEST)
    assert ledger.events()[-1]["kind"] == "dispatch_denied"
    ledger.set_limit("action", None, event_id="inherit")
    ledger.set_limit("action", 100, event_id="lower")  # Replay cannot restore an old limit.
    assert ledger.snapshot("action")["limit_microusd"] is None
    ledger.begin_dispatch("attempt", request_digest=DIGEST)


def test_binding_changes_and_unknown_prices_fail_before_any_reservation(ledger):
    estimate(ledger)
    with pytest.raises(CostError, match="cost_attempt_conflict"):
        estimate(ledger, request_digest="b" * 64)
    with pytest.raises(CostError, match="cost_price_version_conflict"):
        estimate(ledger, "other", price=replace(PRICE, output_microusd_per_million=3_000_000))
    ledger.reserve("attempt")
    with pytest.raises(CostError, match="cost_request_mismatch"):
        ledger.begin_dispatch("attempt", request_digest="b" * 64)
    assert ledger.attempt("attempt")["state"] == "reserved"


def test_new_tariff_version_does_not_reprice_a_previous_attempt(ledger):
    dispatch(ledger)
    estimate(ledger, "new", price=replace(PRICE, version="test-v2", output_microusd_per_million=9_000_000))
    ledger.settle_usage("attempt", TokenUsage(10, 10), receipt_reference="usage", event_id="settled")
    assert ledger.attempt("attempt")["actual_microusd"] == 30
    assert ledger.attempt("new")["quote"]["estimated_microusd"] == 100


def test_readonly_gui_views_are_consistent_and_do_not_modify_files(ledger):
    dispatch(ledger)
    ledger.settle_usage("attempt", TokenUsage(80, 40, 20), receipt_reference="usage", event_id="settled")
    dispatch(ledger, "unresolved")
    ledger.mark_uncertain("unresolved", reason="timeout")
    expected = ledger.report("action")
    path = ledger.directory
    ledger.close()
    before = files(path)
    with CostLedger(path, read_only=True) as reader:
        assert reader.report("action") == expected
        assert expected["summary"]["mode"] == "simulation"
        model = expected["by_model"][0]
        assert (model["actual_microusd"], model["reserved_microusd"], model["input_tokens"], model["output_tokens"]) == (150, 300, 80, 40)
        assert model["unresolved_attempts"] == 1 and model["attempts_with_usage"] == 1
        page = reader.events(limit=3)
        assert len(page) == 3 and reader.events(after_sequence=page[-1]["sequence"])[0]["sequence"] == 4
        assert len(reader.attempts(limit=1)) == 1
        assert reader.attempts(after_id="attempt")[0]["attempt_id"] == "unresolved"
        with pytest.raises(CostError, match="cost_ledger_read_only"):
            reader.cancel("unresolved")
    assert files(path) == before


def test_journal_failure_rolls_back_the_hold_before_any_send_can_be_claimed(ledger, monkeypatch):
    estimate(ledger)
    old_events = ledger.events()
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("PRIVATE database write failure")
    monkeypatch.setattr(ledger, "_event", fail)
    with pytest.raises(CostError, match="^cost_ledger_unavailable$"):
        ledger.reserve("attempt")
    with pytest.raises(CostError, match="cost_ledger_unavailable"):
        ledger.begin_dispatch("attempt", request_digest=DIGEST)
    with CostLedger(ledger.directory, read_only=True) as reader:
        assert reader.events() == old_events
        assert reader.attempt("attempt")["state"] == "estimated"
        assert reader.snapshot("account")["reserved_microusd"] == 0


def test_concurrent_threads_cannot_consume_one_allowance_twice(ledger):
    ledger.set_limit("account", 300, event_id="limit")
    for attempt in ("one", "two"):
        estimate(ledger, attempt)
    barrier = threading.Barrier(2)
    def reserve(attempt):
        barrier.wait(timeout=10)
        try:
            ledger.reserve(attempt)
            return "reserved"
        except BudgetExceeded:
            return "denied"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reserve, ("one", "two"))) == ["denied", "reserved"]
    assert ledger.snapshot("account")["reserved_microusd"] == 300


def test_two_connections_cannot_claim_the_same_dispatch(ledger):
    estimate(ledger)
    ledger.reserve("attempt")
    barrier = threading.Barrier(2)
    def claim(_):
        with CostLedger(ledger.directory) as connection:
            barrier.wait(timeout=10)
            try:
                connection.begin_dispatch("attempt", request_digest=DIGEST)
                return "claimed"
            except CostError as exc:
                return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(claim, (1, 2))) == ["claimed", "cost_invalid_transition"]
    assert len([e for e in ledger.events() if e["kind"] == "dispatch_started"]) == 1


@pytest.mark.parametrize("read_only", [False, True])
def test_closing_another_handle_preserves_the_active_cross_process_lock(ledger, read_only):
    other = CostLedger(ledger.directory, read_only=read_only)
    probe = """
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1], timeout=0.1, isolation_level=None)
try:
    connection.execute('BEGIN IMMEDIATE')
except sqlite3.OperationalError as exc:
    if exc.sqlite_errorcode != sqlite3.SQLITE_BUSY:
        raise
    print('blocked')
else:
    print('acquired')
    connection.rollback()
finally:
    connection.close()
"""
    def probe_writer():
        result = subprocess.run([sys.executable, "-c", probe, str(ledger.directory / "ledger.sqlite3")],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()
    try:
        with ledger._transaction(write=True):
            assert probe_writer() == "blocked"
            other.close()
            assert probe_writer() == "blocked"
        assert probe_writer() == "acquired"
    finally:
        other.close()


@pytest.mark.parametrize("operation", ["snapshot", "reserve", "close"])
def test_inherited_handle_is_rejected_before_touching_any_lock_or_database(ledger, monkeypatch, operation):
    class Forbidden:
        def __getattr__(self, name):
            pytest.fail("inherited database was accessed")

        def __enter__(self):
            pytest.fail("inherited lock was acquired")

        def __exit__(self, *_):
            pytest.fail("inherited lock was released")

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "_pid", ledger._pid + 1)
        patch.setattr(ledger, "_db", Forbidden())
        patch.setattr(ledger, "_lock", Forbidden())
        with pytest.raises(CostError, match="^cost_ledger_unavailable$"):
            if operation == "close":
                ledger.close()
            else:
                getattr(ledger, operation)("account" if operation == "snapshot" else "attempt")
    assert ledger.snapshot("account")["actual_microusd"] == 0


def test_denial_is_durable_and_never_changes_the_existing_hold(ledger):
    ledger.set_limit("account", 300, event_id="limit")
    dispatch(ledger, "existing")
    estimate(ledger, "blocked")
    with pytest.raises(BudgetExceeded):
        ledger.reserve("blocked")
    with CostLedger(ledger.directory, read_only=True) as reader:
        event = reader.events()[-1]
        assert event["kind"] == "reservation_denied" and event["attempt_id"] == "blocked"
        assert event["payload"] == {"blocking_scope_id": "account", "available_microusd": 0,
                                    "requested_microusd": 300, "reason": "cost_budget_exceeded"}
        assert reader.attempt("blocked")["state"] == "estimated"
        assert reader.snapshot("account")["reserved_microusd"] == 300


def test_malformed_saved_quote_fails_with_a_safe_code(ledger):
    estimate(ledger)
    ledger._db.execute("UPDATE attempts SET quote='PRIVATE invalid JSON'")
    with pytest.raises(CostError, match="^cost_ledger_unavailable$"):
        ledger.report()


def _reserve_process(path, attempt, start, results):
    try:
        with CostLedger(path) as worker:
            results.put("ready")
            if not start.wait(10):
                raise RuntimeError("barrier_timeout")
            try:
                worker.reserve(attempt)
                results.put("reserved")
            except BudgetExceeded:
                results.put("denied")
    except Exception as exc:
        results.put(type(exc).__name__)


def test_independent_processes_share_one_atomic_ancestor_budget(ledger):
    ledger.set_limit("engagement", 300, event_id="limit")
    estimate(ledger, "one")
    ledger.add_scope("other-session", parent_id="engagement", kind="session")
    ledger.add_scope("other-action", parent_id="other-session", kind="action")
    estimate(ledger, "two", scope_id="other-action")
    context = multiprocessing.get_context("spawn")
    start, results = context.Event(), context.Queue()
    workers = [context.Process(target=_reserve_process, args=(ledger.directory, attempt, start, results)) for attempt in ("one", "two")]
    try:
        for worker in workers:
            worker.start()
        assert [results.get(timeout=15), results.get(timeout=15)] == ["ready", "ready"]
        start.set()
        assert sorted([results.get(timeout=15), results.get(timeout=15)]) == ["denied", "reserved"]
        for worker in workers:
            worker.join(15)
            assert worker.exitcode == 0
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
            worker.join(5)
        results.close()
    assert ledger.snapshot("account")["reserved_microusd"] == 300


@pytest.mark.parametrize("stage", ["reserved", "dispatched", "reserve_interrupted", "settlement_interrupted"])
def test_process_crash_preserves_committed_holds_and_rolls_back_partial_changes(ledger, stage):
    estimate(ledger)
    path = ledger.directory
    ledger.close()
    script = """
import os, sys
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.cost_contract import TokenUsage
ledger = CostLedger(sys.argv[1])
ledger._db.execute('PRAGMA cache_size=1')
stage = sys.argv[2]
if stage == 'reserve_interrupted':
    ledger._event = lambda *a, **k: os._exit(23)
ledger.reserve('attempt')
if stage == 'reserved':
    os._exit(23)
ledger.begin_dispatch('attempt', request_digest=sys.argv[3])
if stage == 'settlement_interrupted':
    ledger._event = lambda *a, **k: os._exit(23)
    ledger.settle_usage('attempt', TokenUsage(10, 10), receipt_reference='usage', event_id='settled')
os._exit(23)
"""
    result = subprocess.run([sys.executable, "-c", script, str(path), stage, DIGEST], capture_output=True, timeout=20)
    assert result.returncode == 23, result.stderr
    with CostLedger(path) as recovered:
        attempt = recovered.attempt("attempt")
        expected = "estimated" if stage == "reserve_interrupted" else "reserved" if stage == "reserved" else "dispatched"
        assert attempt["state"] == expected
        assert attempt["reserved_microusd"] == (0 if expected == "estimated" else 300)
        assert attempt["actual_microusd"] is None
        assert not any(e["kind"] == "cost_settled" for e in recovered.events())
        if expected == "dispatched":
            with pytest.raises(CostError, match="cost_invalid_transition"):
                recovered.begin_dispatch("attempt", request_digest=DIGEST)


@pytest.mark.parametrize("change", ["directory_public", "file_public", "hardlink", "replace", "symlink"])
def test_private_storage_identity_is_checked_before_mutation(ledger, change, tmp_path):
    estimate(ledger)
    path = ledger.directory / "ledger.sqlite3"
    if change == "directory_public":
        ledger.directory.chmod(0o755)
    elif change == "file_public":
        path.chmod(0o644)
    elif change == "hardlink":
        os.link(path, tmp_path / "alias")
    else:
        path.rename(ledger.directory / "original")
        if change == "symlink":
            path.symlink_to(ledger.directory / "original")
        else:
            path.write_bytes(b"different database")
            path.chmod(0o600)
    with pytest.raises(CostError, match="cost_ledger_unavailable"):
        ledger.reserve("attempt")


def test_storage_missing_or_corrupt_never_creates_a_fresh_budget(tmp_path):
    path = tmp_path / "missing"
    with pytest.raises(CostError, match="cost_ledger_unavailable"):
        CostLedger(path)
    assert not path.exists()
    path.mkdir(mode=0o700)
    (path / "ledger.sqlite3").write_bytes(b"corrupt")
    (path / "ledger.sqlite3").chmod(0o600)
    with pytest.raises(CostError, match="cost_ledger_unavailable"):
        CostLedger(path)
    with pytest.raises(CostError, match="cost_ledger_unavailable"):
        CostLedger.create(path, account_id="account", limit_microusd=100)


def test_history_is_append_only_and_raw_request_content_is_absent(ledger):
    dispatch(ledger)
    with pytest.raises(sqlite3.IntegrityError, match="cost_events_immutable"):
        ledger._db.execute("DELETE FROM events")
    with pytest.raises(sqlite3.IntegrityError, match="cost_events_immutable"):
        ledger._db.execute("UPDATE events SET kind='changed'")
    raw = json.dumps(ledger.events())
    assert "synthetic request" not in raw and DIGEST in raw


@pytest.mark.parametrize("bad", [True, False, -1, 0.1, "100", None, MAX_AMOUNT + 1])
def test_bad_monetary_limits_are_rejected_before_storage_creation(tmp_path, bad):
    with pytest.raises(CostError, match="cost_invalid_amount"):
        CostLedger.create(tmp_path / "bad", account_id="account", limit_microusd=bad)
    assert not (tmp_path / "bad").exists()


@pytest.mark.parametrize("kind,parent", [("account", "account"), ("session", "account"),
    ("action", "engagement"), ("engagement", "action"), ("agent", "agent"), ([], "account")])
def test_budget_hierarchy_cannot_be_reparented_or_skipped(ledger, kind, parent):
    with pytest.raises(CostError):
        ledger.add_scope("bad", parent_id=parent, kind=kind)


def test_scope_reuse_cannot_reset_limits_or_move_existing_costs(ledger):
    ledger.add_scope("capped", parent_id="agent", kind="action", limit_microusd=1)
    with pytest.raises(CostError, match="cost_scope_conflict"):
        ledger.add_scope("capped", parent_id="agent", kind="action", limit_microusd=1000)
    with pytest.raises(CostError, match="cost_account_requires_limit"):
        ledger.set_limit("account", None, event_id="no-account-cap")
    with pytest.raises(CostError, match="cost_attempt_requires_action_scope"):
        estimate(ledger, scope_id="account")
