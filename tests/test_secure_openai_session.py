"""Offline broker/session tests; scripted grants exercise mechanisms, not humans."""

import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import openai_provider
from recon_cockpit.secure_agent.approvals import ApprovalStore
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.openai_broker import BrokerLimits, OfflineTransport
from recon_cockpit.secure_agent.openai_fixtures import scenario_responses
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig, build_request, decode_response
from recon_cockpit.secure_agent.openai_provider import OfflineOpenAIProvider
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES
from recon_cockpit.secure_agent.session import SessionLimits, SessionRunner
from recon_cockpit.secure_agent.worker import INJECTION_FIXTURE
from scripts.secure_agent_session_demo import VerifiedFixtureBackend, demo_policy


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class PortableParser:
    """Controlled codec double: no subprocess and no claim of kernel isolation."""

    boundary_checks = None

    def __init__(self):
        self.observations = []

    def plan(self, config, observation, exchange, *, control):
        control.check()
        self.observations.append(json.loads(observation))
        response = exchange(build_request(config, observation), control=control)
        control.check()
        return decode_response(response)


class FakeBackend:
    """No sockets/processes; verify durable authorization before fake results."""

    name = "OFFLINE-SESSION-UNIT-TEST-NOT-ISOLATION"

    def __init__(self, audit_path):
        self.path = audit_path
        self.calls = []
        self.availability_checks = 0

    def check_available(self, action=None):
        self.availability_checks += 1

    def run(self, action, policy, *, control=None):
        latest = events(self.path)[-1]
        assert latest["event_type"] == "execution_started"
        assert latest["action_digest"] == action.digest
        assert latest["policy_digest"] == policy.digest
        self.calls.append(action)
        body = INJECTION_FIXTURE.decode("ascii") if action.parameters.path == "/injection" else "owned response"
        return {"status": "succeeded", "bytes_received": len(body), "results": [
            {"body": body, "http_status": 200, "bytes_received": len(body)},
        ]}


@pytest.fixture
def make_session(monkeypatch, tmp_path):
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", PortableParser)
    path = tmp_path / "audit.jsonl"
    with AuditSink(path) as audit:
        def create(scenario="three_step", *, approval=False, broker_limits=None, session_limits=None):
            policy = parse_policy({**demo_policy().to_dict(), "require_approval": approval})
            provider = OfflineOpenAIProvider(
                OpenAIConfig("offline-fixture-model"), audit, OfflineTransport(scenario_responses(scenario)),
                limits=broker_limits,
            )
            backend = FakeBackend(path)
            runner = SessionRunner(policy, audit, backend, provider, session_limits)
            provider.bind_session(runner.session_id)
            return runner, provider, backend, path
        yield create


def scripted_grant(controller, raw, *, control):
    """Test-only approval-store mechanism; never presented as a human action."""
    control.check()
    return controller.approvals.issue(parse_action(raw), controller.policy).reference


def test_offline_three_step_uses_real_broker_and_previous_untrusted_data(make_session):
    runner, provider, backend, path = make_session()
    summary = runner.run(execute=True)
    assert summary["session_status"] == "completed"
    assert summary["stop_reason"] == "planner_done"
    assert summary["actions_succeeded"] == summary["steps_attempted"] == 3
    assert summary["output_reserved_bytes"] == 3072
    assert [action.parameters.path for action in backend.calls] == ["/", "/injection", "/"]
    assert provider.broker.snapshot["calls_reserved"] == 3
    assert provider.broker.snapshot["output_tokens_reserved"] == 3072
    assert provider.broker.snapshot["request_bytes_reserved"] > 0
    assert provider.boundary_checks is None  # This test has not run a sandbox.
    observations = provider._planner.observations
    assert observations[0] == {"step": 1, "untrusted_observation": None}
    assert observations[1]["untrusted_observation"]["body"] == "owned response"
    assert observations[2]["untrusted_observation"]["body"] == INJECTION_FIXTURE.decode("ascii")
    assert len({action.action_id for action in backend.calls}) == 3
    text = path.read_text()
    assert "Ignore prior instructions" not in text + json.dumps(summary)
    assert '"body"' not in text
    records = events(path)
    assert records[-1]["event_type"] == "session_finished"
    assert sum(event["event_type"] == "execution_started" for event in records) == 3
    assert all(event.get("approval_reference") is None for event in records)
    with pytest.raises(RuntimeError, match="session_already_used"):
        runner.run(execute=True)


def test_offline_dry_run_never_requests_a_grant_or_checks_backend(make_session):
    runner, provider, backend, _path = make_session(approval=True)
    summary = runner.run(interactive=True, approval=lambda *a, **k: pytest.fail("dry-run grant request"))
    assert summary["session_status"] == "completed"
    assert summary["actions_succeeded"] == 0
    assert all(step["execution_status"] == "dry_run" for step in summary["steps"])
    assert backend.availability_checks == 0
    assert backend.calls == []
    assert provider.broker.snapshot["calls_reserved"] == 3


def test_every_offline_proposal_requires_a_fresh_scripted_grant(make_session):
    runner, provider, backend, path = make_session(approval=True)
    granted = []

    def approve(controller, raw, *, control):
        action = parse_action(raw)
        reference = scripted_grant(controller, raw, control=control)
        granted.append((action.digest, reference))
        return reference

    summary = runner.run(execute=True, interactive=True, approval=approve)
    assert summary["session_status"] == "completed"
    assert summary["actions_succeeded"] == 3
    assert len(granted) == len(backend.calls) == 3
    assert len({reference for _, reference in granted}) == 3
    consumed = [event for event in events(path) if event["event_type"] == "approval_consumed"]
    assert [(event["action_digest"], event["approval_reference"]) for event in consumed] == granted
    assert provider.broker.snapshot["calls_reserved"] == 3


@pytest.mark.parametrize("interactive,reason", [
    (False, "noninteractive_approval_required"), (True, "approval_missing"),
])
def test_unapproved_first_offline_action_stops_before_any_tool(make_session, interactive, reason):
    runner, provider, backend, _path = make_session(approval=True)
    summary = runner.run(execute=True, interactive=interactive, approval=lambda *a, **k: None)
    assert summary["stop_reason"] == "action_blocked"
    assert summary["steps_attempted"] == 1
    assert summary["steps"][0]["reasons"] == [reason]
    assert backend.calls == []
    assert backend.availability_checks == 0
    assert provider.broker.snapshot["calls_reserved"] == 1


@pytest.mark.parametrize("mode,reason", [
    ("refuse_second", "approval_missing"), ("replay_first", "approval_unknown_or_replayed"),
])
def test_offline_second_step_cannot_reuse_or_skip_approval(make_session, mode, reason):
    runner, provider, backend, path = make_session(approval=True)
    references = []

    def approve(controller, raw, *, control):
        if references:
            return None if mode == "refuse_second" else references[0]
        references.append(scripted_grant(controller, raw, control=control))
        return references[0]

    summary = runner.run(execute=True, interactive=True, approval=approve)
    assert summary["stop_reason"] == "action_blocked"
    assert summary["steps_attempted"] == 2
    assert summary["actions_succeeded"] == len(backend.calls) == 1
    assert summary["steps"][-1]["reasons"] == [reason]
    assert provider.broker.snapshot["calls_reserved"] == 2
    assert sum(event["event_type"] == "approval_consumed" for event in events(path)) == 1


@pytest.mark.parametrize("mode,reason", [
    ("expired", "approval_expired"), ("different_action", "approval_action_changed"),
])
def test_stale_offline_grant_cannot_authorize_a_tool(make_session, mode, reason):
    runner, provider, backend, _path = make_session(approval=True)
    now = [100.0]
    runner.controller.approvals = ApprovalStore(clock=lambda: now[0])

    def approve(controller, raw, *, control):
        action = json.loads(raw)
        if mode == "different_action":
            action["parameters"]["method"] = "HEAD"
        reference = scripted_grant(controller, json.dumps(action), control=control)
        if mode == "expired":
            now[0] += controller.policy.approval_ttl_seconds
        return reference

    summary = runner.run(execute=True, interactive=True, approval=approve)
    assert summary["stop_reason"] == "action_blocked"
    assert summary["steps"][0]["reasons"] == [reason]
    assert backend.calls == []
    assert provider.broker.snapshot["calls_reserved"] == 1


@pytest.mark.parametrize("scenario,stop", [
    ("injection_target", "proposal_denied"), ("injection_authority", "session_component_failed"),
])
def test_hostile_offline_followup_cannot_request_another_grant(make_session, scenario, stop):
    runner, provider, backend, path = make_session(scenario, approval=True)
    original_digest = runner.controller.policy.digest
    grants = []

    def approve(controller, raw, *, control):
        reference = scripted_grant(controller, raw, control=control)
        grants.append(reference)
        return reference

    summary = runner.run(execute=True, interactive=True, approval=approve)
    assert summary["stop_reason"] == stop
    assert summary["steps_attempted"] == 2
    assert summary["actions_succeeded"] == len(backend.calls) == len(grants) == 1
    assert backend.calls[0].parameters.path == "/injection"
    assert provider.broker.snapshot["calls_reserved"] == 2
    assert runner.controller.policy.digest == original_digest
    if scenario == "injection_target":
        assert summary["steps"][-1]["reasons"] == ["target_out_of_scope"]
    assert sum(event["event_type"] == "execution_started" for event in events(path)) == 1


@pytest.mark.parametrize("scenario", ["refusal", "malformed", "incomplete"])
def test_rejected_offline_response_does_not_retry_or_request_approval(make_session, scenario):
    runner, provider, backend, _path = make_session(scenario, approval=True)
    summary = runner.run(execute=True, interactive=True,
                         approval=lambda *a, **k: pytest.fail("invalid reply requested approval"))
    assert summary["stop_reason"] == "session_component_failed"
    assert summary["steps_attempted"] == 1
    assert summary["steps"] == []
    assert summary["output_reserved_bytes"] == 0
    assert backend.calls == []
    assert provider.broker.snapshot["calls_reserved"] == 1
    assert provider.broker.snapshot["output_tokens_reserved"] == 1024


@pytest.mark.parametrize("limits,reason", [
    (BrokerLimits(max_calls=2), "broker_call_limit"),
    (BrokerLimits(max_reserved_output_tokens=2048), "broker_token_limit"),
])
def test_broker_budgets_stop_offline_session_before_third_send(make_session, limits, reason):
    runner, provider, backend, _path = make_session("endless", broker_limits=limits)
    summary = runner.run(execute=True)
    assert summary["stop_reason"] == reason
    assert summary["steps_attempted"] == 3
    assert summary["actions_succeeded"] == len(backend.calls) == 2
    assert provider.broker.snapshot["calls_reserved"] == 2
    assert provider.broker.snapshot["output_tokens_reserved"] == 2048
    assert provider.broker.last_error == reason


@pytest.mark.parametrize("stop", ["session_cancelled", "session_timeout"])
def test_offline_transport_delay_obeys_session_control(make_session, stop):
    runner, provider, backend, _path = make_session("timeout", session_limits=SessionLimits(max_runtime_seconds=1))
    timer = threading.Timer(0.05, runner.cancel) if stop == "session_cancelled" else None
    if timer is not None:
        timer.start()
    started = time.monotonic()
    try:
        summary = runner.run(execute=True)
    finally:
        if timer is not None:
            timer.cancel()
            timer.join(timeout=1)
    assert time.monotonic() - started < 2
    assert summary["stop_reason"] == stop
    assert summary["steps_attempted"] == 1
    assert summary["actions_succeeded"] == 0
    assert backend.calls == []
    assert provider.broker.snapshot["calls_reserved"] == 1
    assert provider.broker.last_error == stop


@pytest.fixture
def real_linux():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real offline planner isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux":
        pytest.skip("real offline planner isolation requires Linux")
    from recon_cockpit.secure_agent.openai_isolation import LinuxOpenAIPlanner
    LinuxOpenAIPlanner().check_available()


@pytest.mark.integration
@pytest.mark.parametrize("mode,successes", [("fresh", 3), ("refuse_second", 1), ("replay_first", 1)])
def test_real_offline_session_approval_mechanism(real_linux, tmp_path, mode, successes):
    """Scripted store callbacks test enforcement; these are not human grants."""
    path = tmp_path / "audit.jsonl"
    policy = parse_policy({**demo_policy().to_dict(), "require_approval": True})
    backend = VerifiedFixtureBackend()
    references = []

    def approve(controller, raw, *, control):
        if references and mode == "refuse_second":
            return None
        if references and mode == "replay_first":
            return references[0]
        references.append(scripted_grant(controller, raw, control=control))
        return references[-1]

    with AuditSink(path) as audit:
        provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit,
                                         OfflineTransport(scenario_responses("three_step")))
        runner = SessionRunner(policy, audit, backend, provider)
        provider.bind_session(runner.session_id)
        summary = runner.run(execute=True, interactive=True, approval=approve)
    assert summary["actions_succeeded"] == backend.calls == successes
    assert runner.controller.policy.digest == policy.digest
    assert len(backend.evidence) == successes
    assert provider.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
    if mode == "fresh":
        assert summary["session_status"] == "completed"
        assert len(set(references)) == 3
        assert backend.evidence[1]["injection_fixture_received"] is True
    else:
        assert summary["stop_reason"] == "action_blocked"
        reason = "approval_missing" if mode == "refuse_second" else "approval_unknown_or_replayed"
        assert summary["steps"][-1]["reasons"] == [reason]
    text = path.read_text()
    assert "Ignore prior instructions" not in text + json.dumps(summary)
    records = events(path)
    assert sum(event["event_type"] == "execution_started" for event in records) == successes
    assert sum(event["event_type"] == "approval_consumed" for event in records) == successes
