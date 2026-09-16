"""Trusted, single-use bounded sessions; planners receive data, never authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import threading
import time
from uuid import uuid4

from .audit import AuditUnavailable
from .controller import Controller
from .execution import ExecutionControl, ExecutionStopped
from .models import ValidationError, parse_action
from .session_protocol import _plan


@dataclass(frozen=True, slots=True)
class SessionLimits:
    max_steps: int = 3
    max_runtime_seconds: int = 60
    max_output_bytes: int = 3072

    def __post_init__(self):
        for name, maximum in (("max_steps", 16), ("max_runtime_seconds", 600),
                              ("max_output_bytes", 16 * 65536)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid_session_" + name)

    @property
    def digest(self):
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True,
                                         separators=(",", ":")).encode("ascii")).hexdigest()


def _observation(step, outcome):
    # Previous result only: no growing transcript, policy object, grant, prompt
    # instruction interpretation or controller handle crosses this interface.
    observation = None
    if outcome is not None:
        body = ""
        result = outcome.get("untrusted_result", {})
        rows = result.get("results") if type(result) is dict else None
        if type(rows) is list and rows and type(rows[0]) is dict:
            value = rows[0].get("body")
            if type(value) is str:
                body = value.encode("utf-8", "replace")[:1024].decode("utf-8", "ignore")
        observation = {"execution_status": outcome["execution_status"], "body": body}
    encoded = json.dumps({"step": step, "untrusted_observation": observation},
                         ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > 8192:
        raise ValueError("session_observation_too_large")
    return encoded


def _public_step(step, outcome):
    fields = ("action_id", "action_digest", "execution_id", "decision", "execution_status", "reasons", "result_metadata")
    return {"step": step, **{key: outcome[key] for key in fields if key in outcome}}


class SessionRunner:
    """Internal trusted API, not an arbitrary Python provider/plugin sandbox.

    Every planner attempt costs a step. Every policy-accepted action reserves its
    full response allowance, with no refunds based on untrusted result metadata.
    The budget limits retained HTTP responses, not wire bytes or fixed separately
    bounded bootstrap/planner output. Audit fsync/host kernel stalls are not
    hard-preemptible; they cannot authorize a later launch after expiry.
    """

    def __init__(self, policy, audit, backend, provider, limits=None, *, clock=time.monotonic):
        self.limits = limits if limits is not None else SessionLimits()
        if type(self.limits) is not SessionLimits:
            raise ValueError("invalid_session_limits")
        self.session_id = str(uuid4())
        self.controller = Controller(policy, audit, backend, session_id=self.session_id)
        self.provider = provider
        self._clock = clock
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._used = False

    def cancel(self):
        # Signal handlers set state, never interrupt durable writes or cleanup.
        self._cancelled.set()

    def run(self, *, execute=False, interactive=False, approval=None, on_step=None):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("session_already_running")
        try:
            if self._used:
                raise RuntimeError("session_already_used")
            self._used = True
            return self._run(execute, interactive, approval, on_step)
        finally:
            self._lock.release()

    def _run(self, execute, interactive, approval, on_step):
        started = self._clock()
        control = ExecutionControl(started + self.limits.max_runtime_seconds,
                                   cancelled=self._cancelled, clock=self._clock)
        base = {"session_id": self.session_id, "policy_digest": self.controller.policy.digest,
                "limits_digest": self.limits.digest}
        summary = {**base, "session_status": "stopped", "stop_reason": "step_limit",
                   "steps_attempted": 0, "actions_succeeded": 0, "output_reserved_bytes": 0,
                   "mode": "execute" if execute else "dry_run", "steps": []}

        def emit(kind, **fields):
            self.controller._emit({**base, "event_type": kind, **fields})

        def record(step, outcome):
            public = _public_step(step, outcome)
            summary["steps"].append(public)
            emit("session_step_finished", **public,
                 output_reserved_bytes=summary["output_reserved_bytes"])
            if on_step is not None:
                on_step(public)

        emit("session_started", limits=asdict(self.limits), mode=summary["mode"])
        previous = None
        try:
            for step in range(1, self.limits.max_steps + 1):
                control.check()
                summary["steps_attempted"] += 1
                emit("session_step_started", step=step)
                raw = self.provider.propose(_observation(step, previous), control=control)
                control.check()
                try:
                    plan = _plan(raw)
                except ValidationError as exc:
                    emit("session_proposal_rejected", step=step, reason=exc.code)
                    summary["stop_reason"] = "invalid_proposal"
                    break
                if plan["action"] is None:
                    summary.update(session_status="completed", stop_reason="planner_done")
                    break
                proposal = plan["action"]
                preview = self.controller.submit(proposal, execution_control=control, session_step=step)
                if preview["decision"] == "deny":
                    record(step, preview)
                    summary["stop_reason"] = "proposal_denied"
                    break
                action = parse_action(proposal)
                allowance = action.parameters.max_output_bytes
                if summary["output_reserved_bytes"] + allowance > self.limits.max_output_bytes:
                    record(step, {**preview, "execution_status": "blocked", "reasons": ["session_output_limit"]})
                    summary["stop_reason"] = "output_limit"
                    break
                summary["output_reserved_bytes"] += allowance
                emit("session_output_reserved", step=step, action_digest=action.digest,
                     action_output_allowance=allowance, output_reserved_bytes=summary["output_reserved_bytes"])
                control.check()
                outcome = preview
                if execute:
                    reference = None
                    if preview["decision"] == "approval_required" and interactive and approval is not None:
                        reference = approval(self.controller, json.dumps(proposal), control=control)
                    control.check()
                    outcome = self.controller.submit(proposal, execute=True, interactive=interactive,
                                                     approval_reference=reference, execution_control=control,
                                                     session_step=step)
                    if outcome["execution_status"] == "succeeded":
                        summary["actions_succeeded"] += 1
                record(step, outcome)
                control.check()
                if execute and outcome["execution_status"] != "succeeded":
                    summary["stop_reason"] = "action_" + outcome["execution_status"]
                    break
                if plan["done"]:
                    summary.update(session_status="completed", stop_reason="planner_done")
                    break
                previous = outcome
        except ExecutionStopped as exc:
            summary["stop_reason"] = exc.reason
        except AuditUnavailable:
            # No fabricated successful close event when durable storage fails.
            raise
        except (RuntimeError, OSError, ValueError, TypeError, RecursionError):
            summary["stop_reason"] = "session_component_failed"
        summary["duration_ms"] = max(0, min(10**9, int((self._clock() - started) * 1000)))
        emit("session_finished", **{key: value for key, value in summary.items()
                                    if key not in {*base, "steps"}})
        return summary
