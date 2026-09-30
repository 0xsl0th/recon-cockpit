"""Trusted timing instrumentation and original-deadline setup checks."""

import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.web_comparison_runtime import _DecisionTimingAudit


class Audit:
    def __init__(self):
        self.events = []
        self.fail = False

    def emit(self, event):
        if self.fail:
            raise AuditUnavailable("test_audit_failed")
        self.events.append(event)


def test_timing_starts_after_durable_plan_and_ends_after_first_policy_ack(monkeypatch):
    audit = Audit()
    measured = _DecisionTimingAudit(audit)
    ticks = iter((100, 120, 145, 200, 220, 240))
    monkeypatch.setattr(time, "monotonic_ns", lambda: next(ticks))
    plan = {"event_type": "session_plan_received", "step": 1}
    preview = {"event_type": "policy_decision", "session_step": 1, "action_digest": "a" * 64}
    measured.emit(plan)
    measured.emit(preview)
    measured.emit(dict(preview))  # Execution recheck must not overwrite the first acknowledgement.
    measured.emit({"event_type": "session_plan_received", "step": 2})
    measured.emit({"event_type": "policy_decision", "session_step": 2, "action_digest": "b" * 64})
    measured.emit({"event_type": "session_step_finished", "step": 2})
    assert audit.events[0] is plan and audit.events[1] is preview
    assert measured.timings == [{"step": 1, "action_digest": "a" * 64, "duration_ns": 20},
                                {"step": 2, "action_digest": "b" * 64, "duration_ns": 20}]
    copy = measured.timings
    copy[0]["duration_ns"] = 999
    assert measured.timings[0]["duration_ns"] == 20


def test_audit_failure_never_creates_a_timing_receipt():
    audit = Audit()
    measured = _DecisionTimingAudit(audit)
    measured.emit({"event_type": "session_plan_received", "step": 1})
    audit.fail = True
    with pytest.raises(AuditUnavailable):
        measured.emit({"event_type": "policy_decision", "session_step": 1, "action_digest": "a" * 64})
    assert measured.timings == []


def test_cancelled_preparation_does_not_inspect_nmap_or_start_any_services(tmp_path, monkeypatch):
    import json
    from pathlib import Path
    from recon_cockpit.secure_agent import web_comparison_runtime as runtime
    from recon_cockpit.secure_agent.models import parse_policy

    source = json.loads(Path("examples/secure-agent-web-policy.json").read_text())
    policy = parse_policy({**source, "require_approval": False})
    cancelled = threading.Event()
    cancelled.set()
    runner = SimpleNamespace(policy=policy, _deadline=time.monotonic() + 30,
        _cancelled=cancelled, _stopped=lambda: "cancelled", _lock=threading.RLock(), _active=None)
    monkeypatch.setattr(runtime, "inspect_nmap_runtime", lambda *_: pytest.fail("cancelled setup inspected runtime"))
    monkeypatch.setattr(runtime, "LinuxAuditSink", lambda *_a, **_k: pytest.fail("cancelled setup started audit"))
    runtime.run_trial(runner, tmp_path / "trial", "injected", "scripted")
    receipt = json.loads((tmp_path / "trial" / "runtime.json").read_text())
    assert receipt["error"] == "session_cancelled"
    assert receipt["summary"] is None and receipt["backend"] is None
    assert receipt["trace"] == receipt["decision_timings"] == []
    assert set(p.name for p in (tmp_path / "trial").iterdir()) == {"runtime.json"}
