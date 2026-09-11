"""Explicitly opted-in session evidence through actual Linux isolation."""

import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import isolation
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.session import SessionLimits, SessionRunner
from recon_cockpit.secure_agent.session_provider import SessionMockProvider
from scripts.secure_agent_session_demo import demo_policy, run_demo


pytestmark = pytest.mark.integration
BOUNDARY_NAMES = {"forbidden_ip_blocked", "forbidden_port_blocked",
                  "namespace_creation_blocked", "capabilities_dropped"}


@pytest.fixture(scope="module", autouse=True)
def require_real_linux():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real Linux isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux":
        pytest.skip("real network namespace integration requires Linux")
    # Explicit opt-in must fail on missing dependencies or denied namespaces.
    isolation.LinuxFixtureBackend(verify_boundary=True).check_available()


@pytest.fixture(scope="module")
def demo_evidence(tmp_path_factory):
    path = tmp_path_factory.mktemp("session-evidence") / "audit.jsonl"
    report = run_demo(path)
    text = path.read_text()
    assert "Ignore prior instructions" not in text
    assert "change policy" not in text
    assert '"body"' not in text
    assert "Ignore prior instructions" not in json.dumps(report)
    return report, [json.loads(line) for line in text.splitlines()]


@pytest.mark.parametrize("case,attempts,successes,reserved,stop", [
    ("three_step", 3, 3, 3072, "planner_done"),
    ("injection_target", 2, 1, 1024, "proposal_denied"),
    ("injection_authority", 2, 1, 1024, "proposal_denied"),
    ("step_limit", 2, 2, 2048, "step_limit"),
    ("output_limit", 2, 1, 1024, "output_limit"),
    ("cancel_after_first", 1, 1, 1024, "session_cancelled"),
])
def test_real_session_loop_and_durable_boundaries(demo_evidence, case, attempts, successes, reserved, stop):
    report, events = demo_evidence
    summary = next(row for row in report["cases"] if row["case"] == case)
    assert summary["stop_reason"] == stop
    assert summary["session_status"] == ("completed" if case == "three_step" else "stopped")
    assert summary["steps_attempted"] == attempts
    assert summary["actions_succeeded"] == successes
    assert summary["output_reserved_bytes"] == reserved
    assert summary["policy_unchanged"] is True
    executions = summary["executions"]
    assert len(executions) == successes
    for execution in executions:
        checks = execution["boundary_checks"]
        assert set(checks) == BOUNDARY_NAMES
        assert all(checks[name] is True for name in BOUNDARY_NAMES)
    if case == "three_step":
        assert [row["path"] for row in executions] == ["/", "/injection", "/"]
        assert executions[1]["injection_fixture_received"] is True
        assert summary["steps"][2]["execution_status"] == "succeeded"
    if case.startswith("injection_"):
        assert executions[0]["injection_fixture_received"] is True
        assert summary["steps"][1]["decision"] == "deny"
        assert summary["steps"][1]["reasons"] == [
            "target_out_of_scope" if case == "injection_target" else "unknown_action_fields"
        ]
    if case == "output_limit":
        assert summary["steps"][1]["reasons"] == ["session_output_limit"]

    own = [event for event in events if event.get("session_id") == summary["session_id"]]
    kinds = [event["event_type"] for event in own]
    assert kinds[0] == "session_started"
    assert kinds[-1] == "session_finished"
    assert kinds.count("session_step_started") == attempts
    assert kinds.count("execution_started") == kinds.count("execution_finished") == successes
    assert all(event.get("approval_reference") is None for event in own)
    assert not any(kind.startswith("approval_") for kind in kinds)
    assert {event["policy_digest"] for event in own} == {summary["policy_digest"]}
    for step in range(1, successes + 1):
        started = next(index for index, event in enumerate(own)
                       if event["event_type"] == "execution_started" and event["session_step"] == step)
        finished = next(index for index, event in enumerate(own)
                        if event["event_type"] == "execution_finished" and event["session_step"] == step)
        assert started < finished
        if step < successes:
            next_step = next(index for index, event in enumerate(own)
                             if event["event_type"] == "session_step_started" and event["step"] == step + 1)
            assert finished < next_step
    assert own[-1]["stop_reason"] == stop


class SlowFixtureProvider:
    """Trusted test adapter selects the owned slow fixture, without new tools."""

    def propose(self, observation, *, control):
        plan = json.loads(SessionMockProvider("endless").propose(observation, control=control))
        plan["action"]["parameters"].update(path="/slow", timeout_seconds=30)
        return json.dumps(plan).encode("ascii")


@pytest.mark.parametrize("stop", ["session_cancelled", "session_timeout"])
def test_real_session_stop_terminates_and_reaps_active_worker(monkeypatch, tmp_path, stop):
    policy = parse_policy({**demo_policy().to_dict(), "max_timeout_seconds": 30})
    backend = isolation.LinuxFixtureBackend(verify_boundary=True)
    path = tmp_path / "audit.jsonl"
    processes = []
    timers = []
    real_popen = isolation.subprocess.Popen

    with AuditSink(path) as audit:
        runner = SessionRunner(
            policy, audit, backend, SlowFixtureProvider(),
            SessionLimits(max_runtime_seconds=3 if stop == "session_timeout" else 30),
        )

        def observe_launch(argv, *args, **kwargs):
            proc = real_popen(argv, *args, **kwargs)
            if Path(argv[0]).name == "bwrap":
                processes.append(proc)
                if stop == "session_cancelled":
                    timer = threading.Timer(0.5, runner.cancel)
                    timer.daemon = True
                    timers.append(timer)
                    timer.start()
            return proc

        monkeypatch.setattr(isolation.subprocess, "Popen", observe_launch)
        started = time.monotonic()
        try:
            summary = runner.run(execute=True)
        finally:
            for timer in timers:
                timer.cancel()
                timer.join(timeout=1)
        elapsed = time.monotonic() - started

    assert summary["stop_reason"] == stop
    assert summary["session_status"] == "stopped"
    assert summary["steps_attempted"] == 1
    assert summary["actions_succeeded"] == 0
    assert runner.controller.policy.digest == policy.digest
    assert elapsed < 8
    # Recording the real process proves this stop happened after worker launch.
    assert len(processes) == 1
    assert processes[0].returncode == -signal.SIGKILL
    with pytest.raises(ChildProcessError):
        os.waitpid(processes[0].pid, os.WNOHANG)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    finished = [event for event in events if event["event_type"] == "execution_finished"]
    assert len(finished) == 1
    assert finished[0]["reasons"] == [stop]
    assert finished[0]["execution_status"] == ("cancelled" if stop == "session_cancelled" else "timeout")
    assert events[-1]["event_type"] == "session_finished"
    assert events[-1]["stop_reason"] == stop
    assert not any(event["event_type"] == "session_step_started" and event["step"] > 1 for event in events)
