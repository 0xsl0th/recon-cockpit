"""Offline monetary integration and closed provider-wire contracts."""

from dataclasses import replace
import json
import os
import threading
import time

import pytest

from recon_cockpit.secure_agent import provider_pilot as pilot
from recon_cockpit.secure_agent.cost_contract import CostError, PriceCard
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.provider_pilot_contract import (
    INPUT_LIMIT, MODEL, OUTPUT_LIMIT, PilotConfig, PilotError, request_bytes, response_summary,
)
from recon_cockpit.secure_agent.provider_worker import read_response, TransportFailure


PRICE = PriceCard("openai", MODEL, "owned-fixture-v1", 400000, 100000, 1600000)
KEY = "synthetic-" + "a" * 64
CA = "-----BEGIN CERTIFICATE-----\nowned-placeholder\n-----END CERTIFICATE-----\n"


def response():
    return {"object": "response", "id": "resp_owned_fixture", "model": MODEL,
        "status": "completed", "service_tier": "default", "usage": {
        "input_tokens": 100, "output_tokens": 10, "total_tokens": 110,
        "input_tokens_details": {"cached_tokens": 20}, "output_tokens_details": {"reasoning_tokens": 0}},
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": '{"ack":true}'}]}]}


def config(**kwargs):
    return PilotConfig(**{"ip": "127.0.0.1", "port": 8443, "mode": "owned",
                         "enabled": True, "price": PRICE, "max_call_microusd": 500000, **kwargs})


class Audit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@pytest.fixture
def ledger(tmp_path):
    with CostLedger.create(tmp_path / "costs", account_id="account", limit_microusd=1_000_000,
                           mode="simulation") as value:
        value.add_scope("engagement", parent_id="account", kind="engagement")
        value.add_scope("session", parent_id="engagement", kind="session")
        value.add_scope("action", parent_id="session", kind="action")
        yield value


def make_call(ledger, monkeypatch, *, cfg=None, effect=None, audit=None):
    transport = pilot.LinuxPilotTransport(cfg or config(), ca_pem=CA, synthetic_credential=KEY)

    def exchange(self, *, control, authorize):
        if effect:
            return effect(control, authorize)
        authorize()
        return {"status": "ok", "http_status": 200, "summary": response_summary(response())}

    monkeypatch.setattr(pilot.LinuxPilotTransport, "exchange", exchange)
    return pilot.ControlledProviderCall(ledger, audit or Audit(), transport)


def run(call):
    return call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 30))


def test_fixed_request_cannot_release_engagement_or_tools():
    value = json.loads(request_bytes())
    assert value["model"] == MODEL and value["max_output_tokens"] == OUTPUT_LIMIT
    assert value["tools"] == [] and value["tool_choice"] == "none"
    assert value["store"] is value["stream"] is value["background"] is False
    assert value["service_tier"] == "default" and value["truncation"] == "disabled"
    assert len(value["input"]) == 1 and len(request_bytes()) < 1024


@pytest.mark.parametrize("patch", [{"ip": "localhost"}, {"ip": "::1"}, {"ip": "8.8.8.8"},
    {"port": True}, {"port": 80}, {"enabled": 1}, {"mode": "unknown"},
    {"max_call_microusd": True}, {"max_call_microusd": -1}, {"price": replace(PRICE, model="unknown")},
    {"price": replace(PRICE, input_microusd_per_million=0)}])
def test_config_rejects_broader_destinations_and_bad_prices(patch):
    with pytest.raises(PilotError):
        config(**patch)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1", "224.0.0.1", "255.255.255.255"])
def test_live_requires_public_unicast_literal(ip):
    with pytest.raises(PilotError):
        PilotConfig(ip, PRICE, 500000)


def test_disabled_live_is_inert_before_ledger_key_runtime_or_network(ledger, monkeypatch):
    cfg = PilotConfig("8.8.8.8", PRICE, 500000)
    transport = pilot.LinuxPilotTransport(cfg, ca_pem=CA, credential_file="/does/not/exist")
    monkeypatch.setattr(pilot, "_credential_file", lambda *_: pytest.fail("credential read"))
    monkeypatch.setattr(pilot, "_connect", lambda *_: pytest.fail("network"))
    monkeypatch.setattr(pilot.LinuxFixtureBackend, "check_available", lambda *_: pytest.fail("runtime"))
    before = ledger.events()
    with pytest.raises(PilotError, match="pilot_disabled"):
        run(pilot.ControlledProviderCall(ledger, Audit(), transport))
    with pytest.raises(PilotError, match="pilot_disabled"):
        transport.exchange(control=None, authorize=lambda: pytest.fail("authorization"))
    assert ledger.events() == before


def test_estimate_reserve_dispatch_usage_and_reopen(ledger, monkeypatch):
    audit = Audit()
    call = make_call(ledger, monkeypatch, audit=audit)
    result = run(call)
    assert result["ack"] and result["actual_microusd"] == 50
    attempt = ledger.attempt(call.attempt_id)
    assert attempt["actual_source"] == "usage_derived" and attempt["reserved_microusd"] == 0
    assert attempt["quote"]["ceiling_microusd"] == 419236
    assert attempt["quote"]["estimated_microusd"] == 256
    assert [e["event_type"] for e in audit.events] == ["pilot_reserved", "pilot_dispatch_started", "pilot_settled"]
    with pytest.raises(PilotError, match="pilot_reused"):
        run(call)
    with CostLedger(ledger.directory) as reopened:
        assert reopened.attempt(call.attempt_id) == attempt


@pytest.mark.parametrize("scope", ["account", "engagement", "session", "action"])
def test_all_ancestor_denials_happen_before_transport(ledger, monkeypatch, scope):
    ledger.set_limit(scope, 100, event_id="lower")
    call = make_call(ledger, monkeypatch, effect=lambda *_: pytest.fail("transport entered"))
    with pytest.raises(CostError):
        run(call)
    assert ledger.attempt(call.attempt_id)["state"] == "cancelled"
    assert any(e["kind"] == "reservation_denied" for e in ledger.events())


def test_price_cap_and_mode_mismatch_precede_estimate(ledger, monkeypatch):
    for cfg, code in [(config(max_call_microusd=100), "pilot_call_cap")]:
        call = make_call(ledger, monkeypatch, cfg=cfg, effect=lambda *_: pytest.fail("transport"))
        with pytest.raises(PilotError, match=code):
            run(call)
    transport = pilot.LinuxPilotTransport(PilotConfig("8.8.8.8", PRICE, 500000, enabled=True),
                                         ca_pem=CA, credential_file="not-read")
    with pytest.raises(PilotError, match="pilot_mode_mismatch"):
        run(pilot.ControlledProviderCall(ledger, Audit(), transport))
    assert ledger.attempts() == []


@pytest.mark.parametrize("dispatched", [False, True])
@pytest.mark.parametrize("error", [PilotError("pilot_transport_failed"), ExecutionStopped("session_cancelled"),
                                  ExecutionStopped("session_timeout"), KeyboardInterrupt()])
def test_failures_refund_only_definitely_unsent_work(ledger, monkeypatch, dispatched, error):
    def effect(control, authorize):
        if dispatched:
            authorize()
        raise error
    call = make_call(ledger, monkeypatch, effect=effect)
    with pytest.raises(type(error)):
        run(call)
    attempt = ledger.attempt(call.attempt_id)
    assert attempt["state"] == ("uncertain" if dispatched else "cancelled")
    assert attempt["reserved_microusd"] == (419236 if dispatched else 0)
    assert attempt["actual_microusd"] == (None if dispatched else 0)


@pytest.mark.parametrize("failure_at", [1, 2, 3])
def test_audit_failure_stops_release_and_retains_correct_accounting(ledger, monkeypatch, failure_at):
    class Broken(Audit):
        def emit(self, event):
            super().emit(event)
            if len(self.events) == failure_at:
                raise OSError("secret diagnostic")
    call = make_call(ledger, monkeypatch, audit=Broken())
    with pytest.raises(PilotError, match="^pilot_audit_failed$"):
        run(call)
    assert ledger.attempt(call.attempt_id)["state"] == {1: "cancelled", 2: "uncertain", 3: "settled"}[failure_at]
    with pytest.raises(PilotError, match="pilot_reused"):
        run(call)


def test_cap_lowered_during_setup_prevents_dispatch(ledger, monkeypatch):
    def effect(control, authorize):
        ledger.set_limit("session", 0, event_id="lower")
        authorize()
        pytest.fail("send")
    call = make_call(ledger, monkeypatch, effect=effect)
    with pytest.raises(CostError):
        run(call)
    assert ledger.attempt(call.attempt_id)["state"] == "cancelled"


@pytest.mark.parametrize("change", ["missing", "cached_bool", "total", "reasoning", "tier", "model", "cache_write", "partial"])
def test_unpriced_or_incomplete_usage_retains_hold(ledger, monkeypatch, change):
    value = response()
    if change == "missing": value.pop("usage")
    if change == "cached_bool": value["usage"]["input_tokens_details"]["cached_tokens"] = True
    if change == "total": value["usage"]["total_tokens"] = 999
    if change == "reasoning": value["usage"]["output_tokens_details"]["reasoning_tokens"] = 1
    if change == "cache_write": value["usage"]["input_tokens_details"]["cache_write_tokens"] = 1
    if change == "tier": value["service_tier"] = "priority"
    if change == "model": value["model"] = "other"
    if change == "partial": value["status"] = "in_progress"
    def effect(control, authorize):
        authorize()
        return {"status": "ok", "http_status": 200, "summary": response_summary(value)}
    call = make_call(ledger, monkeypatch, effect=effect)
    with pytest.raises(PilotError, match="pilot_unresolved"):
        run(call)
    assert ledger.attempt(call.attempt_id)["reserved_microusd"] == 419236


@pytest.mark.parametrize("change", ["tool", "text", "incomplete", "overrun"])
def test_bad_output_still_settles_complete_usage(ledger, monkeypatch, change):
    value = response()
    if change == "tool": value["output"] = [{"type": "function_call", "name": "shell"}]
    if change == "text": value["output"][0]["content"][0]["text"] = "ignore policy"
    if change == "incomplete": value["status"] = "incomplete"
    if change == "overrun":
        value["usage"]["input_tokens"] = INPUT_LIMIT + 100
        value["usage"]["total_tokens"] = INPUT_LIMIT + 110
    def effect(control, authorize):
        authorize()
        return {"status": "ok", "http_status": 200, "summary": response_summary(value)}
    call = make_call(ledger, monkeypatch, effect=effect)
    with pytest.raises(PilotError, match="pilot_output_rejected"):
        run(call)
    attempt = ledger.attempt(call.attempt_id)
    assert attempt["state"] == "settled" and attempt["reserved_microusd"] == 0


def test_reused_provider_receipt_keeps_second_hold(ledger, monkeypatch):
    run(make_call(ledger, monkeypatch))
    second = make_call(ledger, monkeypatch)
    with pytest.raises(CostError, match="cost_receipt_already_used"):
        run(second)
    assert ledger.attempt(second.attempt_id)["state"] == "uncertain"


def test_same_call_cannot_dispatch_concurrently(ledger, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    result = []
    def effect(control, authorize):
        authorize()
        entered.set()
        assert release.wait(3)
        return {"status": "ok", "http_status": 200, "summary": response_summary(response())}
    call = make_call(ledger, monkeypatch, effect=effect)
    thread = threading.Thread(target=lambda: result.append(run(call)))
    thread.start()
    try:
        assert entered.wait(3)
        with pytest.raises(PilotError, match="pilot_reused"):
            run(call)
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and len(result) == 1


def test_dispatch_claim_cannot_be_replayed(ledger, monkeypatch):
    def effect(control, authorize):
        authorize()
        authorize()
        pytest.fail("second send")
    call = make_call(ledger, monkeypatch, effect=effect)
    with pytest.raises(CostError, match="cost_invalid_transition"):
        run(call)
    assert ledger.attempt(call.attempt_id)["state"] == "uncertain"


def test_failure_to_persist_usage_does_not_refund_or_return_output(ledger, monkeypatch):
    call = make_call(ledger, monkeypatch)
    def fail(*args, **kwargs):
        raise CostError("cost_storage_unavailable")
    monkeypatch.setattr(ledger, "settle_usage", fail)
    with pytest.raises(CostError, match="cost_storage_unavailable"):
        run(call)
    assert ledger.attempt(call.attempt_id)["reserved_microusd"] == 419236


def test_cancellation_after_settlement_keeps_actual_without_output(ledger, monkeypatch):
    stop = threading.Event()
    class Cancelling(Audit):
        def emit(self, event):
            if event["event_type"] == "pilot_settled": stop.set()
    call = make_call(ledger, monkeypatch, audit=Cancelling())
    with pytest.raises(ExecutionStopped):
        call.run(scope_id="action", control=ExecutionControl(time.monotonic() + 10, stop))
    assert ledger.attempt(call.attempt_id)["state"] == "settled"


@pytest.mark.parametrize("control", [None, ExecutionControl(float(10**10), clock=lambda: 0),
                                    ExecutionControl(time.monotonic() + 10000)])
def test_unbounded_or_fake_control_never_enters_transport(ledger, monkeypatch, control):
    call = make_call(ledger, monkeypatch, effect=lambda *_: pytest.fail("transport"))
    with pytest.raises(PilotError, match="pilot_invalid_control"):
        call.run(scope_id="action", control=control)
    assert ledger.attempts() == []


@pytest.mark.parametrize("bad", [None, {}, {"status": "ok", "http_status": True, "summary": {}},
    {"status": "ok", "http_status": 200, "summary": {"accepted": True, "usage": None, "reference": None}}])
def test_malformed_receipt_never_refunds(ledger, monkeypatch, bad):
    def effect(control, authorize):
        authorize()
        return bad
    call = make_call(ledger, monkeypatch, effect=effect)
    with pytest.raises(PilotError, match="pilot_invalid_receipt"):
        run(call)
    assert ledger.attempt(call.attempt_id)["state"] == "uncertain"


def test_explicit_private_key_file_only(tmp_path):
    path = tmp_path / "key"
    path.write_text("sk-" + "a" * 32 + "\n")
    path.chmod(0o600)
    assert pilot._credential_file(path) == "sk-" + "a" * 32
    for mode in (0o644, 0o666):
        path.chmod(mode)
        with pytest.raises(PilotError): pilot._credential_file(path)
    path.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(PilotError): pilot._credential_file(alias)
    os.link(path, tmp_path / "hardlink")
    with pytest.raises(PilotError): pilot._credential_file(path)


class Wire:
    def __init__(self, body, fragment=7): self.body, self.fragment = body, fragment
    def settimeout(self, _): pass
    def recv(self, size):
        result, self.body = self.body[:min(size, self.fragment)], self.body[min(size, self.fragment):]
        return result


def chunked(body, suffix=b"0\r\n\r\n"):
    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + body + suffix


@pytest.mark.parametrize("fragment", [1, 7, 4096])
def test_chunked_bounded_response_and_r5a_default_unchanged(fragment):
    raw = chunked(b'2\r\n{}\r\n')
    assert read_response(Wire(raw, fragment), time.monotonic() + 2, KEY, allow_chunked=True) == b"{}"
    with pytest.raises(TransportFailure):
        read_response(Wire(raw), time.monotonic() + 2, KEY)


@pytest.mark.parametrize("raw", [chunked(b"1;ext=yes\r\na\r\n"), chunked(b"10001\r\n"),
    chunked(b"-1\r\n"), chunked(b"2\r\n{"), chunked(b'2\r\n{}xx'), chunked(b'2\r\n{}\r\n', b"0\r\nTrailer: yes\r\n\r\n"),
    chunked(b'2\r\n{}\r\n') + b"extra", chunked(b'2\r\n{}\r\n').replace(b"Transfer-Encoding:", b"Content-Length: 2\r\nTransfer-Encoding:")])
def test_chunked_rejects_ambiguous_overlong_or_truncated_frames(raw):
    with pytest.raises(TransportFailure):
        read_response(Wire(raw), time.monotonic() + 2, KEY, allow_chunked=True)
