"""Host authority for a session driven by a Linux-confined coordinator.

Only bounded proposal messages cross the coordinator channel. Policy, mode,
session creation, approval input, accounting, audit and execution remain owned
by trusted bootstrap/authority code. Python callers of this module are trusted;
the process boundary is supplied by LinuxCoordinator, never by these objects.
"""

from __future__ import annotations

from dataclasses import asdict
import json
import threading
import time
from uuid import UUID, uuid4

from .audit import AuditUnavailable
from .controller import Controller
from .execution import ExecutionControl, ExecutionStopped
from .models import ValidationError, load_json, parse_action
from .session import SessionLimits, _observation, _public_step
from .session_protocol import _plan


MAX_REQUEST_BYTES = 20480


class AuthorityProtocolError(RuntimeError):
    """Static failure of the coordinator's proposal-only authority channel."""


def _encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


class AuthoritySession:
    """Single-use authority service, driven only through a private IPC pipe.

    Reconnecting cannot create a session: bootstrap owns this instance and its
    absolute deadline. Any protocol failure closes it permanently. Restarting
    the service abandons the session; there is no automatic restart or resume.
    """

    def __init__(self, policy, audit, backend, coordinator, limits=None, *,
                 clock=time.monotonic, session_id=None):
        limits = SessionLimits() if limits is None else limits
        if type(limits) is not SessionLimits:
            raise ValueError("invalid_session_limits")
        self.limits = SessionLimits(**asdict(limits))
        self.session_id = str(uuid4()) if session_id is None else session_id
        if type(self.session_id) is not str or str(UUID(self.session_id)) != self.session_id:
            raise ValueError("invalid_session_id")
        self.controller = Controller(policy, audit, backend, session_id=self.session_id)
        self.coordinator = coordinator
        self._clock = clock
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._used = False

    def cancel(self):
        self._cancelled.set()

    def run(self, *, execute=False, interactive=False, approval=None, on_step=None):
        if type(execute) is not bool or type(interactive) is not bool:
            raise ValueError("invalid_authority_mode")
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
        session_control = ExecutionControl(started + self.limits.max_runtime_seconds,
                                           cancelled=self._cancelled, clock=self._clock)
        base = {"session_id": self.session_id, "policy_digest": self.controller.policy.digest,
                "limits_digest": self.limits.digest, "control_plane": "privsep-v1"}
        summary = {**base, "session_status": "stopped", "stop_reason": "coordinator_protocol_error",
                   "steps_attempted": 0, "actions_succeeded": 0, "output_reserved_bytes": 0,
                   "mode": "execute" if execute else "dry_run", "steps": []}
        closed = False
        protocol_failed = False
        request_lock = threading.Lock()

        def emit(kind, **fields):
            self.controller._emit({**base, "event_type": kind, **fields})

        def reject(reason):
            nonlocal closed, protocol_failed
            closed = protocol_failed = True
            # Poison outstanding authority work as well as future requests.
            # The real supervisor is serial, but an internal concurrent caller
            # must not let a request already waiting for approval later launch.
            self._cancelled.set()
            summary.update(session_status="stopped", stop_reason="coordinator_protocol_error")
            emit("coordinator_request_rejected", reason=reason)
            raise AuthorityProtocolError("coordinator_protocol_error")

        def record(step, outcome):
            public = _public_step(step, outcome)
            summary["steps"].append(public)
            emit("session_step_finished", **public,
                 output_reserved_bytes=summary["output_reserved_bytes"])
            if on_step is not None:
                on_step(dict(public))

        def response(step, outcome=None):
            observation = json.loads(_observation(step + 1, outcome))["untrusted_observation"]
            return _encode({"schema_version": "1", "session_id": self.session_id,
                            "sequence": step, "stop": closed, "observation": observation})

        def handle(raw):
            nonlocal closed
            session_control.check()
            if closed:
                reject("session_closed")
            if type(raw) is not bytes or len(raw) > MAX_REQUEST_BYTES:
                reject("invalid_request_envelope")
            try:
                request = load_json(raw)
            except ValidationError:
                reject("invalid_request_envelope")
            if (set(request) != {"schema_version", "session_id", "sequence", "plan"}
                    or request["schema_version"] != "1"):
                reject("invalid_request_envelope")
            if request["session_id"] != self.session_id:
                reject("wrong_session")
            step = request["sequence"]
            if type(step) is not int or step != summary["steps_attempted"] + 1:
                reject("sequence_mismatch")
            if step > self.limits.max_steps:
                reject("step_limit")
            summary["steps_attempted"] = step
            emit("session_step_started", step=step)
            try:
                plan = _plan(_encode(request["plan"]))
            except (ValidationError, ValueError, TypeError, RecursionError):
                closed = True
                summary["stop_reason"] = "invalid_proposal"
                emit("session_proposal_rejected", step=step, reason="invalid_session_proposal")
                return response(step)
            if plan["action"] is None:
                closed = True
                summary.update(session_status="completed", stop_reason="coordinator_done")
                return response(step)
            proposal = plan["action"]
            preview = self.controller.submit(proposal, execution_control=session_control, session_step=step)
            if preview["decision"] == "deny":
                closed = True
                summary["stop_reason"] = "proposal_denied"
                record(step, preview)
                return response(step, preview)
            # Only the authority's parsed action contributes to accounting.
            # Reserve before prompting or launching; denial/failure never refunds.
            action = parse_action(proposal)
            allowance = action.parameters.max_output_bytes
            if summary["output_reserved_bytes"] + allowance > self.limits.max_output_bytes:
                closed = True
                summary["stop_reason"] = "output_limit"
                blocked = {**preview, "execution_status": "blocked", "reasons": ["session_output_limit"]}
                record(step, blocked)
                return response(step, blocked)
            summary["output_reserved_bytes"] += allowance
            emit("session_output_reserved", step=step, action_digest=action.digest,
                 action_output_allowance=allowance, output_reserved_bytes=summary["output_reserved_bytes"])
            session_control.check()
            outcome = preview
            if execute:
                reference = None
                if preview["decision"] == "approval_required" and interactive and approval is not None:
                    # This callback belongs to the host UI and reads /dev/tty.
                    # It is never exposed as a coordinator IPC operation.
                    reference = approval(self.controller, _encode(proposal), control=session_control)
                session_control.check()
                outcome = self.controller.submit(proposal, execute=True, interactive=interactive,
                                                 approval_reference=reference, execution_control=session_control,
                                                 session_step=step)
                if outcome["execution_status"] == "succeeded":
                    summary["actions_succeeded"] += 1
            record(step, outcome)
            session_control.check()
            if execute and outcome["execution_status"] != "succeeded":
                closed = True
                summary["stop_reason"] = "action_" + outcome["execution_status"]
            elif plan["done"]:
                closed = True
                summary.update(session_status="completed", stop_reason="coordinator_done")
            elif step == self.limits.max_steps:
                closed = True
                summary["stop_reason"] = "step_limit"
            return response(step, outcome)

        def exchange(raw, *, control):
            nonlocal closed
            if not request_lock.acquire(blocking=False):
                reject("concurrent_request")
            try:
                if control is not session_control:
                    reject("invalid_control")
                return handle(raw)
            except BaseException:
                # Even an internal callback failure irrevocably closes this
                # authority channel before the supervisor reaps the child.
                closed = True
                raise
            finally:
                request_lock.release()

        emit("session_started", limits=asdict(self.limits), mode=summary["mode"])
        try:
            session_control.check()
            result = self.coordinator.run(_encode({"schema_version": "1", "session_id": self.session_id}),
                                          exchange, control=session_control)
            session_control.check()
            if protocol_failed or not closed or type(result) is not bytes or len(result) > 512:
                reject("invalid_session_close")
            try:
                result = load_json(result)
            except ValidationError:
                reject("invalid_session_close")
            if result != {"schema_version": "1", "session_id": self.session_id, "status": "closed"}:
                reject("invalid_session_close")
        except ExecutionStopped as exc:
            summary.update(session_status="stopped", stop_reason=(
                "coordinator_protocol_error" if protocol_failed else exc.reason))
        except AuditUnavailable:
            raise
        except AuthorityProtocolError:
            summary.update(session_status="stopped", stop_reason="coordinator_protocol_error")
        except (RuntimeError, OSError, ValueError, TypeError, RecursionError):
            summary.update(session_status="stopped", stop_reason=(
                "coordinator_protocol_error" if protocol_failed else "coordinator_failed"))
        finally:
            closed = True
        summary["duration_ms"] = max(0, min(10**9, int((self._clock() - started) * 1000)))
        emit("session_finished", **{key: value for key, value in summary.items()
                                    if key not in {*base, "steps"}})
        return summary
