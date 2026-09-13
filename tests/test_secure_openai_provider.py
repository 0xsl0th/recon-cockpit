"""Host adapter correlation and concurrency; parser doubles are trusted tests."""

import json
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import openai_provider
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.openai_broker import BrokerError, OfflineTransport
from recon_cockpit.secure_agent.openai_fixtures import SCENARIOS, scenario_responses
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig, build_request, decode_response


OBSERVATION = b'{"step":1,"untrusted_observation":null}'


class Audit:
    def __init__(self):
        self.events = []
        self.fail = False

    def emit(self, event):
        if self.fail:
            raise OSError("PRIVATE AUDIT DETAILS")
        self.events.append(event)


def make_provider(monkeypatch):
    calls = []

    class Parser:
        boundary_checks = None

        def plan(self, config, observation, exchange, *, control):
            calls.append(observation)
            return decode_response(exchange(build_request(config, observation), control=control))

    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", Parser)
    audit = Audit()
    provider = openai_provider.OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit,
        OfflineTransport(scenario_responses("three_step")))
    return provider, audit, calls


def test_binding_failure_blocks_future_planning_even_when_audit_recovers(monkeypatch):
    provider, audit, calls = make_provider(monkeypatch)
    audit.fail = True
    with pytest.raises(AuditUnavailable, match="^audit_unavailable$"):
        provider.bind_session(str(uuid4()))
    audit.fail = False
    with pytest.raises(AuditUnavailable):
        provider.propose(OBSERVATION, control=ExecutionControl(time.monotonic() + 2))
    with pytest.raises(AuditUnavailable):
        provider.bind_session(str(uuid4()))
    assert calls == []
    assert provider.broker.snapshot["calls_reserved"] == 0


def test_adapter_prevents_concurrent_plan_or_rebinding(monkeypatch):
    provider, audit, calls = make_provider(monkeypatch)
    provider._lock.acquire()
    try:
        with pytest.raises(BrokerError, match="broker_already_running"):
            provider.propose(OBSERVATION, control=ExecutionControl(time.monotonic() + 2))
        with pytest.raises(BrokerError, match="broker_already_running"):
            provider.bind_session(str(uuid4()))
    finally:
        provider._lock.release()
    assert calls == [] and audit.events == []
    session = str(uuid4())
    provider.bind_session(session)
    with pytest.raises(RuntimeError, match="already_bound"):
        provider.bind_session(str(uuid4()))
    assert len(audit.events) == 1
    assert audit.events[0]["session_id"] == session


def test_cancelled_adapter_does_not_launch_or_reserve(monkeypatch):
    provider, audit, calls = make_provider(monkeypatch)
    event = threading.Event()
    event.set()
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        provider.propose(OBSERVATION, control=ExecutionControl(time.monotonic() + 2, event))
    assert calls == [] and audit.events == []


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_synthetic_scripts_are_bounded_and_repeatable(scenario):
    replies = scenario_responses(scenario)
    assert replies == scenario_responses(scenario)
    assert 1 <= len(replies) <= 16
    assert all(type(reply.body) is bytes and len(reply.body) <= 65536 for reply in replies)
    if scenario == "injection_target":
        action = json.loads(decode_response(replies[1].body))["action"]
        assert action["target"] == "127.0.0.2"
    elif scenario == "injection_authority":
        with pytest.raises(ValueError, match="invalid_openai_response"):
            decode_response(replies[1].body)
    elif scenario == "three_step":
        plans = [json.loads(decode_response(reply.body)) for reply in replies]
        assert [plan["done"] for plan in plans] == [False, False, True]
        assert len({plan["action"]["action_id"] for plan in plans}) == 3
