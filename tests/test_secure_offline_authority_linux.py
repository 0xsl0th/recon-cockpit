"""Opt-in combined Linux boundaries; planning and approval callbacks are synthetic."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES as COORDINATOR_BOUNDARIES
from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.openai_broker import BrokerLimits, OfflineTransport
from recon_cockpit.secure_agent.openai_fixtures import scenario_responses
from recon_cockpit.secure_agent.openai_isolation import LinuxOpenAIPlanner
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig
from recon_cockpit.secure_agent.openai_provider import OfflineOpenAIProvider
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES as PARSER_BOUNDARIES
from recon_cockpit.secure_agent.session import SessionLimits
from recon_cockpit.secure_agent.worker import INJECTION_FIXTURE
from scripts.secure_agent_control_plane_demo import demo_policy


EXECUTOR_BOUNDARIES = {"forbidden_ip_blocked", "forbidden_port_blocked",
                       "namespace_creation_blocked", "capabilities_dropped"}


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class RecordingBackend(AuthorizedFixtureBackend):
    """Collect the real executor's bounded evidence without replacing execution."""

    def __init__(self, policy, session_id, limits, *, execute=False):
        super().__init__(policy, session_id, limits, execute=execute)
        self.controls, self.evidence = [], []

    def run(self, action, policy, *, control):
        self.controls.append(control)
        result = super().run(action, policy, control=control)
        self.evidence.append({
            "path": action.parameters.path, "checks": result["boundary_checks"],
            "injection_fixture_received": any(row.get("body") == INJECTION_FIXTURE.decode("ascii")
                                               for row in result.get("results", [])),
        })
        return result


@pytest.fixture
def linux_lab():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual Linux isolation")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxOfflineCoordinator().check_available()
    LinuxOpenAIPlanner().check_available()


@pytest.mark.integration
@pytest.mark.parametrize("execute", [False, True])
def test_real_combined_three_step_has_distinct_boundaries_and_shared_authority(linux_lab, tmp_path, monkeypatch, execute):
    path = tmp_path / "private-audit" / "events.jsonl"
    policy, limits, session_id = demo_policy(), SessionLimits(), str(uuid4())
    coordinator = LinuxOfflineCoordinator()
    backend = RecordingBackend(policy, session_id, limits, execute=execute)
    children, parser_controls, coordinator_controls = [], [], []
    original_popen, original_run = subprocess.Popen, coordinator.run

    def launch(argv, *args, **kwargs):
        child = original_popen(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            children.append(child)
        return child

    def run(init, exchange, *, control):
        coordinator_controls.append(control)
        return original_run(init, exchange, control=control)

    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(coordinator, "run", run)
    with AuditSink(path) as audit:
        transport = OfflineTransport(scenario_responses("three_step"))
        provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit, transport)
        original_plan = provider._planner.plan

        def plan(config, observation, exchange, *, control):
            parser_controls.append(control)
            return original_plan(config, observation, exchange, control=control)

        monkeypatch.setattr(provider._planner, "plan", plan)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits,
                                     session_id=session_id, provider=provider)
        summary = authority.run(execute=execute)
    assert summary["session_status"] == "completed" and summary["stop_reason"] == "coordinator_done"
    assert summary["steps_attempted"] == 3 and summary["output_reserved_bytes"] == 3072
    assert summary["actions_succeeded"] == (3 if execute else 0)
    assert transport.calls == provider.broker.snapshot["calls_reserved"] == 3
    assert provider.broker.snapshot["output_tokens_reserved"] == 3072
    assert coordinator.boundary_checks == dict.fromkeys(COORDINATOR_BOUNDARIES, True)
    assert provider.boundary_checks == dict.fromkeys(PARSER_BOUNDARIES, True)
    assert len(parser_controls) == 3 and len(coordinator_controls) == 1
    assert all(control is coordinator_controls[0] for control in parser_controls + backend.controls)
    assert len(children) == (7 if execute else 4)
    assert len({child.pid for child in children}) == len(children)
    assert all(child.returncode == 0 for child in children)
    assert backend.snapshot["executions_reserved"] == (3 if execute else 0)
    if execute:
        assert [row["path"] for row in backend.evidence] == ["/", "/injection", "/"]
        assert all(row["checks"] == dict.fromkeys(EXECUTOR_BOUNDARIES, True) for row in backend.evidence)
        assert backend.evidence[1]["injection_fixture_received"] is True
    records = events(path)
    assert sum(row["event_type"] == "offline_provider_session_bound" for row in records) == 1
    assert sum(row["event_type"] == "execution_started" for row in records) == (3 if execute else 0)
    assert records[-1]["event_type"] == "session_finished"
    disclosed = path.read_text() + json.dumps(summary)
    assert "Ignore prior instructions" not in disclosed and '"body"' not in disclosed


@pytest.mark.integration
@pytest.mark.parametrize("mode,successes", [("fresh", 3), ("refuse_second", 1), ("replay_first", 1)])
def test_real_combined_executor_checks_scripted_grant_for_every_action(linux_lab, tmp_path, mode, successes):
    """These callbacks witness store enforcement; no human approval is inferred."""
    path = tmp_path / "private-audit" / "events.jsonl"
    policy, limits, session_id = demo_policy(approval=True), SessionLimits(), str(uuid4())
    coordinator = LinuxOfflineCoordinator()
    backend = RecordingBackend(policy, session_id, limits, execute=True)
    grants = []

    def approve(controller, raw, *, control):
        control.check()
        if grants and mode == "refuse_second":
            return None
        if grants and mode == "replay_first":
            return grants[0][1]
        action = parse_action(raw)
        reference = controller.approvals.issue(action, controller.policy).reference
        grants.append((action.digest, reference))
        return reference

    with AuditSink(path) as audit:
        provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit,
                                         OfflineTransport(scenario_responses("three_step")))
        authority = AuthoritySession(policy, audit, backend, coordinator, limits,
                                     session_id=session_id, provider=provider)
        summary = authority.run(execute=True, interactive=True, approval=approve)
    assert summary["actions_succeeded"] == backend.snapshot["executions_reserved"] == successes
    assert len(backend.evidence) == successes
    assert coordinator.boundary_checks == dict.fromkeys(COORDINATOR_BOUNDARIES, True)
    assert provider.boundary_checks == dict.fromkeys(PARSER_BOUNDARIES, True)
    if mode == "fresh":
        assert summary["session_status"] == "completed"
        assert len({reference for _, reference in grants}) == 3
    else:
        assert summary["stop_reason"] == "action_blocked"
        reason = "approval_missing" if mode == "refuse_second" else "approval_unknown_or_replayed"
        assert summary["steps"][-1]["reasons"] == [reason]
    assert provider.broker.snapshot["calls_reserved"] == (3 if mode == "fresh" else 2)
    records = events(path)
    consumed = [row for row in records if row["event_type"] == "approval_consumed"]
    launched = [row for row in records if row["event_type"] == "execution_started"]
    assert [(row["action_digest"], row["approval_reference"]) for row in consumed] == grants
    assert [(row["action_digest"], row["approval_reference"]) for row in launched] == grants
    assert all(reference not in json.dumps(summary) for _, reference in grants)


@pytest.mark.integration
@pytest.mark.parametrize("scenario,stop", [("injection_target", "proposal_denied"),
                                          ("injection_authority", "provider_failed")])
def test_real_combined_hostile_followup_stops_before_second_executor(linux_lab, tmp_path, scenario, stop):
    path = tmp_path / "private-audit" / "events.jsonl"
    policy, limits, session_id = demo_policy(), SessionLimits(), str(uuid4())
    backend = RecordingBackend(policy, session_id, limits, execute=True)
    with AuditSink(path) as audit:
        provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit,
                                         OfflineTransport(scenario_responses(scenario)))
        authority = AuthoritySession(policy, audit, backend, LinuxOfflineCoordinator(), limits,
                                     session_id=session_id, provider=provider)
        summary = authority.run(execute=True)
    assert summary["stop_reason"] == stop
    assert summary["steps_attempted"] == provider.broker.snapshot["calls_reserved"] == 2
    assert summary["actions_succeeded"] == backend.snapshot["executions_reserved"] == 1
    assert summary["output_reserved_bytes"] == backend.snapshot["output_bytes_reserved"] == 1024
    assert backend.evidence[0]["injection_fixture_received"] is True
    assert authority.controller.policy.digest == policy.digest
    assert sum(row["event_type"] == "execution_started" for row in events(path)) == 1


@pytest.mark.integration
def test_real_coordinator_can_complete_all_sixteen_provider_steps(linux_lab, tmp_path):
    """Thirty-two v2 requests fit the fixed dialogue without creating a new quota."""
    path = tmp_path / "private-audit" / "events.jsonl"
    policy, session_id = demo_policy(), str(uuid4())
    limits = SessionLimits(max_steps=16, max_output_bytes=16384)
    broker_limits = BrokerLimits(max_calls=16, max_reserved_output_tokens=16384, max_request_bytes=262144)
    coordinator = LinuxOfflineCoordinator()
    backend = RecordingBackend(policy, session_id, limits)
    with AuditSink(path) as audit:
        provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit,
                                         OfflineTransport(scenario_responses("endless")), limits=broker_limits)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits,
                                     session_id=session_id, provider=provider)
        summary = authority.run()
    assert summary["stop_reason"] == "step_limit" and summary["steps_attempted"] == 16
    assert summary["output_reserved_bytes"] == provider.broker.snapshot["output_tokens_reserved"] == 16384
    assert provider.broker.snapshot["calls_reserved"] == 16
    assert backend.snapshot["executions_reserved"] == 0
    assert coordinator.boundary_checks == dict.fromkeys(COORDINATOR_BOUNDARIES, True)


@pytest.mark.integration
def test_real_provider_budget_stops_combined_session_before_next_execution(linux_lab, tmp_path):
    path = tmp_path / "private-audit" / "events.jsonl"
    policy, limits, session_id = demo_policy(), SessionLimits(), str(uuid4())
    backend = RecordingBackend(policy, session_id, limits, execute=True)
    with AuditSink(path) as audit:
        provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit,
                                         OfflineTransport(scenario_responses("endless")),
                                         limits=BrokerLimits(max_calls=1))
        authority = AuthoritySession(policy, audit, backend, LinuxOfflineCoordinator(), limits,
                                     session_id=session_id, provider=provider)
        summary = authority.run(execute=True)
    assert summary["stop_reason"] == "broker_call_limit" and summary["steps_attempted"] == 2
    assert summary["actions_succeeded"] == backend.snapshot["executions_reserved"] == 1
    assert provider.broker.snapshot["calls_reserved"] == 1
    assert sum(row["event_type"] == "execution_started" for row in events(path)) == 1


@pytest.mark.integration
@pytest.mark.parametrize("reason", ["session_cancelled", "session_timeout"])
def test_shared_stop_reaps_both_real_waiting_coordinator_and_parser(linux_lab, tmp_path, monkeypatch, reason):
    path = tmp_path / "private-audit" / "events.jsonl"
    policy, session_id = demo_policy(), str(uuid4())
    limits = SessionLimits(max_runtime_seconds=3 if reason == "session_timeout" else 30)
    backend = RecordingBackend(policy, session_id, limits, execute=True)
    children, timers = [], []
    original_popen = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original_popen(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    try:
        with AuditSink(path) as audit:
            transport = OfflineTransport(scenario_responses("timeout"))
            provider = OfflineOpenAIProvider(OpenAIConfig("offline-fixture-model"), audit, transport)
            coordinator = LinuxOfflineCoordinator()
            authority = AuthoritySession(policy, audit, backend, coordinator, limits,
                                         session_id=session_id, provider=provider)
            original_emit = audit.emit

            def emit(event):
                original_emit(event)
                if reason == "session_cancelled" and event["event_type"] == "broker_request_reserved":
                    timer = threading.Timer(0.05, authority.cancel)
                    timers.append(timer)
                    timer.start()

            monkeypatch.setattr(audit, "emit", emit)
            started = time.monotonic()
            summary = authority.run(execute=True)
        assert time.monotonic() - started < 5
        assert summary["stop_reason"] == provider.broker.last_error == reason
        assert summary["steps_attempted"] == transport.calls == 1
        assert summary["actions_succeeded"] == backend.snapshot["executions_reserved"] == 0
        assert provider.broker.snapshot["calls_reserved"] == 1
        assert provider.broker.snapshot["output_tokens_reserved"] == 1024
        assert len(children) == 2
        assert all(child.returncode == -signal.SIGKILL for child in children)
        assert coordinator.boundary_checks is provider.boundary_checks is None
        assert not any(row["event_type"] == "execution_started" for row in events(path))
    finally:
        for timer in timers:
            timer.cancel()
            timer.join(timeout=1)
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)
