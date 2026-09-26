"""Portable adversarial tests at the owned runtime's trusted host boundary."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.provider_broker import OwnedProviderBroker
from recon_cockpit.secure_agent.provider_contract import (
    BOUNDARY_NAMES, MAX_OUTPUT_TOKENS, MAX_RESPONSE_BYTES, MODEL, ProviderError,
    ProviderLimits, SyntheticTariff, build_request, success_response,
)
from recon_cockpit.secure_agent.provider_lab import LinuxOwnedProviderTransport


OBSERVATION = b'{"step":1,"untrusted_observation":null}'


def receipt(expected_digest, **changes):
    result = {"schema_version": "1", "context_digest": expected_digest, "status": "ok",
              "http_status": 200, "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True),
              "cleanup": {"worker_reaped": True, "owner_reaped": True},
              "connection_count": 1, "request_count": 1}
    result.update(changes)
    return result


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def call(harness, source=OBSERVATION, request=None, control=None):
    return harness.broker.exchange(source, build_request(source) if request is None else request,
                                   control=harness.control if control is None else control)


@pytest.fixture
def factory(tmp_path, monkeypatch):
    directory = tmp_path / "audit"
    directory.mkdir(mode=0o700)
    path = directory / "provider.jsonl"
    states = {}

    def exchange(self, request, *, control, context_digest):
        state = states[id(self)]
        state.calls.append((request, control, context_digest))
        if state.handler is not None:
            return state.handler(request, control, context_digest)
        state.receipt = receipt(context_digest)
        return {"body": success_response(), "receipt": state.receipt}

    monkeypatch.setattr(LinuxOwnedProviderTransport, "exchange", exchange)
    monkeypatch.setattr(LinuxOwnedProviderTransport, "last_receipt",
                        property(lambda self: states[id(self)].receipt))
    with AuditSink(path) as audit:
        def create(*, limits=None, tariff=None):
            runtime = LinuxOwnedProviderTransport("success")
            state = SimpleNamespace(calls=[], receipt=None, handler=None)
            states[id(runtime)] = state
            return SimpleNamespace(broker=OwnedProviderBroker(audit, runtime, limits=limits, tariff=tariff),
                                   runtime=runtime, state=state, audit=audit, path=path,
                                   control=ExecutionControl(time.monotonic() + 30))
        yield create


def test_full_reservation_is_durable_before_runtime_and_body_never_enters_audit(factory):
    tariff = SyntheticTariff(7, 3, 5)
    h = factory(tariff=tariff)
    source = json.dumps({"step": 2, "untrusted_observation": {
        "execution_status": "succeeded", "body": "PRIVATE-BODY Authorization: synthetic-credential"}}).encode()
    request = build_request(source)

    def inspect(raw, control, context_digest):
        event = rows(h.path)[-1]
        assert event["event_type"] == "provider_request_reserved"
        assert event["context_digest"] == context_digest
        assert event["request_digest"] == hashlib.sha256(raw).hexdigest()
        assert dict(h.broker.snapshot) == {
            "calls_reserved": 1, "output_tokens_reserved": 1024, "request_bytes_reserved": len(raw),
            "synthetic_cost_units_reserved": 7 + len(raw) * 3 + 1024 * 5}
        assert control is h.control and raw == request
        assert b"PRIVATE-BODY" not in raw and b"synthetic-credential" not in raw
        return {"body": b'PRIVATE-RESPONSE {"usage":{"output_tokens":0}}', "receipt": receipt(context_digest)}

    h.state.handler = inspect
    assert call(h, source) == b'PRIVATE-RESPONSE {"usage":{"output_tokens":0}}'
    assert [row["event_type"] for row in rows(h.path)] == ["provider_request_reserved", "provider_exchange_finished"]
    assert rows(h.path)[-1]["exchange_status"] == "succeeded"
    assert "PRIVATE" not in h.path.read_text() and "synthetic-credential" not in h.path.read_text()
    assert MODEL not in h.path.read_text()
    assert h.broker.last_error is None and len(h.state.calls) == 1


@pytest.mark.parametrize("field,value", [
    ("model", "external-model"), ("max_output_tokens", 4096), ("stream", True), ("store", True),
    ("background", True), ("tools", [{"type": "web_search"}]), ("tool_choice", "auto"),
    ("url", "https://external.invalid"), ("proxy", "http://external.invalid"),
    ("headers", {"Authorization": "PRIVATE-KEY"}), ("verify_tls", False), ("retries", 9),
])
def test_child_cannot_replace_fixed_request_fields(factory, field, value):
    h = factory()
    request = json.loads(build_request(OBSERVATION))
    request[field] = value
    with pytest.raises(ProviderError, match="^provider_request_mismatch$"):
        call(h, request=json.dumps(request).encode())
    assert h.broker.snapshot["calls_reserved"] == 0 and not h.state.calls
    assert "PRIVATE" not in h.path.read_text() and "external" not in h.path.read_text()


@pytest.mark.parametrize("submitted", [b"{}", b"\xff", build_request(OBSERVATION) + b" ",
    build_request(OBSERVATION)[:-1] + b',"store":false}'])
def test_exact_canonical_request_is_required(factory, submitted):
    h = factory()
    with pytest.raises(ProviderError, match="provider_request_mismatch"):
        call(h, request=submitted)
    assert not h.state.calls and h.broker.snapshot["calls_reserved"] == 0


@pytest.mark.parametrize("submitted", ["{}", {}, bytearray(b"{}"), b"", b"x" * 16385])
def test_wrong_request_type_or_size_never_reserves(factory, submitted):
    h = factory()
    with pytest.raises(ProviderError, match="provider_invalid_request"):
        call(h, request=submitted)
    assert not h.state.calls and h.broker.snapshot["calls_reserved"] == 0


@pytest.mark.parametrize("source", [b"{}", b"\xff", b'{"step":true,"untrusted_observation":null}',
    b'{"step":2,"untrusted_observation":null}',
    b'{"step":1,"untrusted_observation":{"execution_status":"succeeded","body":""}}',
    b'{"step":2,"untrusted_observation":{"execution_status":"arbitrary","body":""}}'])
def test_invalid_release_source_is_rejected_before_reservation(factory, source):
    h = factory()
    with pytest.raises(ProviderError, match="provider_invalid_observation"):
        call(h, source=source, request=b"{}")
    assert not h.state.calls and h.broker.snapshot["calls_reserved"] == 0


@pytest.mark.parametrize("field,limit,code", [
    ("max_calls", 1, "provider_call_limit"),
    ("max_reserved_output_tokens", 1024, "provider_token_limit"),
    ("max_request_bytes", len(build_request(OBSERVATION)), "provider_request_limit"),
    ("max_synthetic_cost_units", SyntheticTariff().reserve(len(build_request(OBSERVATION))), "provider_cost_limit"),
])
def test_exact_budget_is_allowed_once_then_no_retry_or_refund(factory, field, limit, code):
    h = factory(limits=ProviderLimits(**{field: limit}))
    assert call(h) == success_response()
    before = dict(h.broker.snapshot)
    with pytest.raises(ProviderError, match="^" + code + "$"):
        call(h)
    assert dict(h.broker.snapshot) == before and len(h.state.calls) == 1


@pytest.mark.parametrize("field,limit,code", [
    ("max_reserved_output_tokens", 1023, "provider_token_limit"),
    ("max_request_bytes", len(build_request(OBSERVATION)) - 1, "provider_request_limit"),
    ("max_synthetic_cost_units", SyntheticTariff().reserve(len(build_request(OBSERVATION))) - 1, "provider_cost_limit"),
])
def test_entire_attempt_must_fit_before_runtime(factory, field, limit, code):
    h = factory(limits=ProviderLimits(**{field: limit}))
    with pytest.raises(ProviderError, match=code):
        call(h)
    assert not h.state.calls and not any(h.broker.snapshot.values())


@pytest.mark.parametrize("status,http_status", [("tls_error", None), ("http_error", 302), ("http_error", 429),
    ("malformed_response", 200), ("response_too_large", 200), ("credential_reflection", 200),
    ("deadline_exceeded", None), ("transport_error", None)])
def test_runtime_failures_keep_all_reservations_and_never_retry(factory, status, http_status):
    h = factory()
    h.state.handler = lambda request, control, context_digest: {
        "body": None, "receipt": receipt(context_digest, status=status, http_status=http_status)}
    with pytest.raises(ProviderError, match="^provider_" + status + "$"):
        call(h)
    assert len(h.state.calls) == h.broker.snapshot["calls_reserved"] == 1
    assert h.broker.snapshot["output_tokens_reserved"] == MAX_OUTPUT_TOKENS
    assert h.broker.snapshot["synthetic_cost_units_reserved"] == SyntheticTariff().reserve(len(build_request(OBSERVATION)))


@pytest.mark.parametrize("event,calls", [("provider_request_reserved", 0), ("provider_exchange_finished", 1)])
def test_audit_failure_permanently_closes_broker_without_refund(factory, monkeypatch, event, calls):
    h = factory()
    original = h.audit.emit

    def fail(value):
        if value["event_type"] == event:
            raise OSError("PRIVATE-DISK-ERROR")
        original(value)

    monkeypatch.setattr(h.audit, "emit", fail)
    with pytest.raises(ProviderError, match="^provider_audit_unavailable$"):
        call(h)
    before = dict(h.broker.snapshot)
    assert len(h.state.calls) == calls and before["calls_reserved"] == 1
    monkeypatch.setattr(h.audit, "emit", original)
    with pytest.raises(ProviderError, match="^provider_audit_unavailable$"):
        call(h)
    assert dict(h.broker.snapshot) == before and len(h.state.calls) == calls
    assert "PRIVATE" not in h.path.read_text()


def test_real_fsync_failure_prevents_runtime_entry(factory, monkeypatch):
    h = factory()

    def fail(_fd):
        raise OSError("PRIVATE-FSYNC-ERROR")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(ProviderError, match="provider_audit_unavailable"):
        call(h)
    assert not h.state.calls and h.broker.snapshot["calls_reserved"] == 1


def test_rejected_request_audit_failure_also_permanently_closes(factory, monkeypatch):
    h = factory()
    monkeypatch.setattr(h.audit, "emit", lambda value: (_ for _ in ()).throw(RuntimeError("PRIVATE")))
    with pytest.raises(ProviderError, match="provider_audit_unavailable"):
        call(h, request=b"{}")
    assert not any(h.broker.snapshot.values())
    with pytest.raises(ProviderError, match="provider_audit_unavailable"):
        call(h)
    assert not h.state.calls


@pytest.mark.parametrize("failure", [OSError, ValueError, TypeError, KeyError, RuntimeError])
def test_unexpected_runtime_errors_are_static_and_keep_reservation(factory, failure):
    h = factory()

    def fail(*_args):
        raise failure("PRIVATE-RUNTIME-ERROR")

    h.state.handler = fail
    with pytest.raises(ProviderError, match="^provider_transport_failed$") as error:
        call(h)
    assert error.value.__suppress_context__ is True
    assert "PRIVATE" not in h.path.read_text()
    assert len(h.state.calls) == h.broker.snapshot["calls_reserved"] == 1


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"context_digest": "0" * 64}, {"status": "PRIVATE-ERROR"},
    {"http_status": True}, {"http_status": 302}, {"connection_count": True},
    {"request_count": 2}, {"connection_count": None}, {"request_count": 0},
    {"boundary_checks": {"invented": True}}, {"cleanup": {"worker_reaped": True}},
    {"extra": "PRIVATE-EXTRA"},
])
def test_invalid_receipts_are_never_audited_or_released(factory, change):
    h = factory()
    h.state.handler = lambda request, control, context_digest: {
        "body": b"PRIVATE-RESPONSE", "receipt": receipt(context_digest, **change)}
    with pytest.raises(ProviderError, match="provider_receipt_invalid"):
        call(h)
    assert h.broker.last_receipt is None
    assert "PRIVATE" not in h.path.read_text() and len(h.state.calls) == 1


@pytest.mark.parametrize("change,code", [
    ({"cleanup": {"worker_reaped": False, "owner_reaped": True}}, "provider_cleanup_failed"),
    ({"cleanup": {"worker_reaped": True, "owner_reaped": False}}, "provider_cleanup_failed"),
    ({"boundary_checks": dict.fromkeys(BOUNDARY_NAMES, False)}, "provider_isolation_failed"),
    ({"boundary_checks": None}, "provider_isolation_failed"),
])
def test_unproven_isolation_or_cleanup_blocks_even_success_body(factory, change, code):
    h = factory()
    h.state.handler = lambda request, control, context_digest: {
        "body": success_response(), "receipt": receipt(context_digest, **change)}
    with pytest.raises(ProviderError, match=code):
        call(h)
    assert h.broker.last_receipt is not None
    assert h.broker.snapshot["calls_reserved"] == 1


@pytest.mark.parametrize("body", [None, "text", bytearray(b"x"), b"", b"x" * (MAX_RESPONSE_BYTES + 1)])
def test_success_body_is_bounded_bytes(factory, body):
    h = factory()
    h.state.handler = lambda request, control, context_digest: {"body": body, "receipt": receipt(context_digest)}
    with pytest.raises(ProviderError, match="provider_receipt_invalid"):
        call(h)


def test_failure_body_is_never_returned_even_if_receipt_is_valid(factory):
    h = factory()
    h.state.handler = lambda request, control, context_digest: {
        "body": b"PRIVATE-FAILURE", "receipt": receipt(context_digest, status="http_error", http_status=429)}
    with pytest.raises(ProviderError, match="provider_receipt_invalid"):
        call(h)
    assert "PRIVATE" not in h.path.read_text()


def test_setup_failure_retains_unknown_measurements_without_inventing_success(factory):
    h = factory()

    def fail(request, control, context_digest):
        h.state.receipt = receipt(context_digest, status="transport_error", http_status=None,
                                  boundary_checks=None, connection_count=None, request_count=None)
        raise RuntimeError("PRIVATE-SETUP-ERROR")

    h.state.handler = fail
    with pytest.raises(ProviderError, match="provider_transport_failed"):
        call(h)
    assert h.broker.last_receipt["boundary_checks"] is None
    assert h.broker.last_receipt["request_count"] is None
    assert rows(h.path)[-1]["receipt"] == h.broker.last_receipt


@pytest.mark.parametrize("kind", ["provider", "stop"])
def test_mutated_exception_codes_cannot_leak_to_audit_or_caller(factory, kind):
    h = factory()
    failure = ProviderError("provider_transport_failed") if kind == "provider" else ExecutionStopped("session_timeout")
    setattr(failure, "code" if kind == "provider" else "reason", "PRIVATE-EXCEPTION-CODE")

    def fail(*_args):
        raise failure

    h.state.handler = fail
    with pytest.raises(ProviderError, match="^provider_transport_failed$"):
        call(h)
    assert "PRIVATE" not in h.path.read_text()


def test_later_failed_reservation_cannot_report_previous_success_receipt(factory, monkeypatch):
    h = factory()
    call(h)
    assert h.broker.last_receipt["status"] == "ok"
    monkeypatch.setattr(h.audit, "emit", lambda value: (_ for _ in ()).throw(OSError("PRIVATE")))
    with pytest.raises(ProviderError, match="provider_audit_unavailable"):
        call(h)
    assert h.broker.last_receipt is None
    assert h.broker.snapshot["calls_reserved"] == 2 and len(h.state.calls) == 1


@pytest.mark.parametrize("invalid", [None, object(), ExecutionControl(time.monotonic() + 30, clock=lambda: 0),
                                     ExecutionControl(time.monotonic() + 1000)])
def test_real_bounded_immutable_control_is_required(factory, invalid):
    h = factory()
    with pytest.raises(ProviderError, match="provider_invalid_control"):
        h.broker.exchange(OBSERVATION, build_request(OBSERVATION), control=invalid)
    assert not h.state.calls and not any(h.broker.snapshot.values())


def test_equal_but_new_control_cannot_extend_or_replace_lifetime(factory):
    h = factory()
    call(h)
    other = ExecutionControl(h.control.deadline)
    with pytest.raises(ProviderError, match="provider_control_changed"):
        call(h, control=other)
    assert len(h.state.calls) == h.broker.snapshot["calls_reserved"] == 1


@pytest.mark.parametrize("field,value", [("deadline", time.monotonic() + 60),
                                         ("clock", lambda: 0), ("cancelled", threading.Event())])
def test_low_level_mutation_of_same_control_is_rejected(factory, field, value):
    h = factory()
    call(h)
    object.__setattr__(h.control, field, value)
    with pytest.raises(ProviderError, match="provider_control_changed"):
        call(h)
    assert len(h.state.calls) == 1


@pytest.mark.parametrize("cancelled", [False, True])
def test_preexisting_timeout_or_cancel_never_reserves(factory, cancelled):
    h = factory()
    event = threading.Event()
    if cancelled:
        event.set()
    h.control = ExecutionControl(time.monotonic() - 1, cancelled=event)
    with pytest.raises(ExecutionStopped, match="session_cancelled" if cancelled else "session_timeout"):
        call(h)
    assert not h.state.calls and not any(h.broker.snapshot.values())


@pytest.mark.parametrize("event,calls", [("provider_request_reserved", 0), ("provider_exchange_finished", 1)])
def test_audit_time_cancellation_never_releases_body(factory, monkeypatch, event, calls):
    h = factory()
    cancelled = threading.Event()
    h.control = ExecutionControl(time.monotonic() + 30, cancelled=cancelled)
    original = h.audit.emit

    def cancel(value):
        original(value)
        if value["event_type"] == event:
            cancelled.set()

    monkeypatch.setattr(h.audit, "emit", cancel)
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        call(h)
    assert len(h.state.calls) == calls and h.broker.snapshot["calls_reserved"] == 1
    assert h.broker.last_error == "session_cancelled"


def test_runtime_stop_keeps_cleanup_receipt_and_full_reservation(factory):
    h = factory()

    def stop(request, control, context_digest):
        h.state.receipt = receipt(context_digest, status="deadline_exceeded", http_status=None,
                                  boundary_checks=None, connection_count=None, request_count=None)
        raise ExecutionStopped("session_timeout")

    h.state.handler = stop
    with pytest.raises(ExecutionStopped, match="session_timeout"):
        call(h)
    assert h.broker.last_receipt["cleanup"] == {"worker_reaped": True, "owner_reaped": True}
    assert h.broker.snapshot["output_tokens_reserved"] == 1024
    assert rows(h.path)[-1]["exchange_status"] == "stopped"


def test_concurrent_calls_reserve_only_one_attempt(factory):
    h = factory()
    entered, release = threading.Event(), threading.Event()

    def block(request, control, context_digest):
        entered.set()
        assert release.wait(3)
        return {"body": success_response(), "receipt": receipt(context_digest)}

    h.state.handler = block
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(call, h)
        try:
            assert entered.wait(3)
            with pytest.raises(ProviderError, match="provider_already_running"):
                call(h)
            assert h.broker.snapshot["calls_reserved"] == 1
        finally:
            release.set()
        assert first.result(3) == success_response()
    assert len(h.state.calls) == 1


def test_exact_owned_runtime_type_and_no_arbitrary_callable_are_required(factory):
    h = factory()

    class OtherRuntime(LinuxOwnedProviderTransport):
        pass

    for runtime in (object(), None, lambda *_: b"x", OtherRuntime("success")):
        with pytest.raises(ProviderError, match="provider_invalid_transport"):
            OwnedProviderBroker(h.audit, runtime)


def test_public_state_is_detached_and_fixed_configuration_cannot_be_changed(factory):
    limits, tariff = ProviderLimits(), SyntheticTariff()
    h = factory(limits=limits, tariff=tariff)
    old = h.broker.snapshot
    with pytest.raises(TypeError):
        old["calls_reserved"] = 900
    with pytest.raises(FrozenInstanceError):
        h.broker.config.model = "changed"
    object.__setattr__(limits, "max_calls", 16)
    object.__setattr__(tariff, "fixed_attempt_units", 999)
    object.__setattr__(h.broker.config, "model", "changed")
    object.__setattr__(h.broker.limits, "max_calls", 16)
    object.__setattr__(h.broker.tariff, "fixed_attempt_units", 999)
    assert h.broker.config.model == MODEL and h.broker.limits.max_calls == 3
    assert h.broker.tariff.fixed_attempt_units == 100
    call(h)
    value = h.broker.last_receipt
    value["cleanup"]["worker_reaped"] = False
    assert h.broker.last_receipt["cleanup"]["worker_reaped"] is True
    assert old["calls_reserved"] == 0
    for name in ("broker_id", "config_digest", "config", "limits", "tariff", "last_error", "last_receipt", "snapshot"):
        with pytest.raises(AttributeError):
            setattr(h.broker, name, None)
