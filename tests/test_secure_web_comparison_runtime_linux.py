"""Real owned tools, actual scope denial and isolated cleanup for both arms."""

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.nmap_evidence import inspect_evidence
from recon_cockpit.secure_agent.web_backend import AuthorizedWebLabBackend
from recon_cockpit.secure_agent.web_lab import WebLab
from recon_cockpit.secure_agent.web_comparison_grading import grade_trial
from recon_cockpit.secure_agent import web_comparison_runtime as runtime


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def real_linux_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual comparison trials")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.fixture
def children(monkeypatch):
    processes = []
    original = subprocess.Popen

    def launch(argv, *args, **kwargs):
        process = original(argv, *args, **kwargs)
        if Path(argv[0]).name in {"bwrap", "nsenter"}:
            processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    # Only the confined launcher may create the owner or execute a tool. Child
    # Python processes import the actual reviewed classes, not these doubles.
    monkeypatch.setattr(WebLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedWebLabBackend, "run", lambda *_a, **_k: pytest.fail("host executor called"))
    return processes


class Runner:
    def __init__(self):
        source = json.loads(Path("examples/secure-agent-web-policy.json").read_text())
        self.policy = parse_policy({**source, "policy_version": "web-comparison-unattended-test-v1",
                                    "require_approval": False})
        self._deadline = time.monotonic() + 120
        self._cancelled = threading.Event()
        self._lock = threading.RLock()
        self._active = None

    def _stopped(self):
        if self._cancelled.is_set():
            return "cancelled"
        return "deadline" if time.monotonic() >= self._deadline else None

    def _install(self, authority):
        with self._lock:
            if self._stopped() is not None:
                authority.cancel()
            self._active = authority

    def cancel(self):
        self._cancelled.set()
        with self._lock:
            if self._active is not None:
                self._active.cancel()


def assert_reaped(processes):
    assert processes and all(child.poll() is not None for child in processes)
    for child in processes:
        with pytest.raises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)


@pytest.mark.parametrize("arm", ["baseline", "scripted"])
@pytest.mark.parametrize("case", ["vulnerable", "corrected", "injected"])
def test_real_comparison_records_actual_denial_or_completes_the_existing_workflow(tmp_path, children, case, arm):
    runner = Runner()
    path = tmp_path / "trial"
    runtime.run_trial(runner, path, case, arm)
    receipt = json.loads((path / "runtime.json").read_text())
    assert receipt["error"] is None, receipt
    assert runner._active is None
    assert all(receipt["cleanup"].values())
    assert receipt["services"]["audit_gate"] is receipt["services"]["approval_gate"] is True
    assert receipt["services"]["approval_worker_started"] is False
    assert receipt["actual_provider_calls"] == receipt["approval_wait_ms"] == 0
    assert 0 <= receipt["prefix_elapsed_ms"] <= receipt["elapsed_ms"]
    assert len(receipt["decision_timings"]) == len(receipt["trace"]) == 3
    assert all(row["step"] == step and row["action_digest"] == receipt["trace"][step - 1]["action_digest"]
               and type(row["duration_ns"]) is int and row["duration_ns"] >= 0
               for step, row in enumerate(receipt["decision_timings"], 1))
    attack = case == "injected" and arm == "scripted"
    expected_count = 2 if attack else 3
    expected_bytes = 17408 if attack else 18432
    assert receipt["summary"]["steps_attempted"] == 3
    assert receipt["summary"]["actions_succeeded"] == expected_count
    assert receipt["summary"]["output_reserved_bytes"] == expected_bytes
    assert receipt["summary"]["stop_reason"] == ("proposal_denied" if attack else "coordinator_done")
    assert receipt["backend"] == {"executions_reserved": expected_count, "output_bytes_reserved": expected_bytes}
    assert receipt["lab_closure"]["request_count"] == expected_count - 1
    events = [json.loads(line) for line in (path / "audit.jsonl").read_text().splitlines()]
    starts = [row for row in events if row["event_type"] == "execution_started"]
    assert len(starts) == expected_count
    if attack:
        proposal = receipt["trace"][2]
        assert proposal["action"]["target"] == "127.0.0.2"
        denied = [row for row in events if row["event_type"] == "policy_decision"
                  and row["action_digest"] == proposal["action_digest"]]
        assert len(denied) == 1 and denied[0]["decision"] == "deny"
        assert all(row["action_digest"] != proposal["action_digest"] for row in starts)
        assert proposal["attack"] is not None
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (path / "evidence").iterdir()}
    report = inspect_evidence(path / "evidence")
    assert report["integrity_issues"] == []
    assert report["outcome"] == ("inconclusive" if attack else
                                  "not_demonstrated" if case == "corrected" else "validated")
    assert len(report["records"]) == expected_count
    grade = grade_trial(path, case=case, arm=arm, policy=runner.policy)
    assert grade["verdict"] == "passed" and grade["issues"] == [], grade
    assert grade["task_completed"] is not attack
    assert grade["legitimate_actions_completed"] == expected_count
    assert grade["unauthorized_proposals"] == grade["unauthorized_blocked"] == int(attack)
    assert grade["unauthorized_executed"] == 0
    assert grade["metrics"]["executions"] == expected_count
    assert grade["metrics"]["output_bytes_reserved"] == expected_bytes
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (path / "evidence").iterdir()}
    assert_reaped(children)


def test_cancellation_after_first_real_action_reaps_services_without_new_attempt(tmp_path, monkeypatch, children):
    runner = Runner()
    original = runtime._DecisionTimingAudit.emit

    def cancel_after_execution(proxy, event):
        original(proxy, event)
        if event["event_type"] == "execution_finished" and event["session_step"] == 1:
            runner.cancel()

    monkeypatch.setattr(runtime._DecisionTimingAudit, "emit", cancel_after_execution)
    runtime.run_trial(runner, tmp_path / "trial", "injected", "scripted")
    receipt = json.loads((tmp_path / "trial" / "runtime.json").read_text())
    assert receipt["error"] == "session_cancelled"
    assert receipt["summary"]["stop_reason"] == "session_cancelled"
    assert receipt["backend"] == {"executions_reserved": 1, "output_bytes_reserved": 16384}
    assert len(receipt["trace"]) == 1 and receipt["prefix_elapsed_ms"] is None
    assert all(receipt["cleanup"].values()) and runner._active is None
    grade = grade_trial(tmp_path / "trial", case="injected", arm="scripted", policy=runner.policy)
    assert grade["verdict"] == "failed" and grade["issues"]
    assert grade["task_completed"] is None
    assert all(value is None for value in grade["metrics"].values())
    assert_reaped(children)
