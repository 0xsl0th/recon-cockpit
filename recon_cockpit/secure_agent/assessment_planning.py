"""Owned mock planning with explicit release and durable simulation accounting.

The reviewed workflow remains the source of eligible actions. This provider has
no network transport, credentials, approval interface or execution capability.
Only the existing networkless parser receives the bounded planning descriptor.
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from uuid import UUID, uuid4

from .assessment_contract import CASES
from . import assessment_planning_contract as contract
from .audit import AuditUnavailable
from .cost_contract import TokenUsage
from .cost_ledger import CostLedger
from .execution import ExecutionControl, ExecutionStopped
from .models import load_json
from .openai_broker import BrokerLimits, OfflineOpenAIBroker, OfflineTransport
from .openai_isolation import LinuxOpenAIPlanner
from .openai_protocol import build_request
from .session_protocol import _plan


class OwnedAssessmentPlanningProvider:
    """A single session, finite mock transcript, and simulation ledger only.

    Account, engagement, session and planning scopes are selected by the trusted
    caller. No constructor or proposal creates/replenishes a budget. Monetary
    admission authorizes only a scripted exchange, never an assessment action.
    """

    name = "owned-mock-assessment-planning-v1"

    def __init__(self, case, audit, evidence, ledger, *, scope_id, scenario="success"):
        if (type(case) is not str or case not in CASES
                or type(scenario) is not str or scenario not in contract.SCENARIOS
                or type(ledger) is not CostLedger or ledger.mode != "simulation"
                or ledger.snapshot(scope_id)["kind"] != "action"
                or ledger.snapshot(scope_id)["attempt_count"] != 0):
            raise ValueError("invalid_owned_planning_configuration")
        self._case, self._audit, self._evidence = case, audit, evidence
        self._ledger, self._scope_id = ledger, scope_id
        self._instance_id = uuid4().hex
        self._broker = OfflineOpenAIBroker(
            contract.CONFIG, audit,
            OfflineTransport(contract.replies(case, scenario, run_id=self._instance_id)),
            BrokerLimits(max_calls=3, max_reserved_output_tokens=3 * contract.OUTPUT_LIMIT,
                         max_request_bytes=3 * contract.INPUT_LIMIT),
        )
        self._planner = LinuxOpenAIPlanner()
        self._lock = threading.Lock()
        self._session_id = None
        self._closed = self._audit_failed = False
        self._next_step = 1
        self._control = self._control_fields = None

    @property
    def broker(self):
        return self._broker

    @property
    def boundary_checks(self):
        return self._planner.boundary_checks

    @property
    def accounting(self):
        return self._ledger.report(self._scope_id)

    def _emit(self, event, **fields):
        if self._audit_failed:
            raise AuditUnavailable("audit_previously_failed")
        try:
            self._audit.emit({"event_type": event, "session_id": self._session_id,
                              "broker_id": self.broker.broker_id,
                              "config_digest": self.broker.config_digest,
                              "provider": self.name, **fields})
        except BaseException as exc:
            self._audit_failed = True
            if not isinstance(exc, Exception):
                raise
            raise AuditUnavailable("audit_unavailable") from None

    def bind_session(self, session_id):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("planning_already_running")
        try:
            if (self._closed or self._session_id is not None or type(session_id) is not str
                    or str(UUID(session_id)) != session_id
                    or self._ledger.mode != "simulation"
                    or self._ledger.snapshot(self._scope_id)["attempt_count"] != 0):
                raise ValueError("planning_session_binding_failed")
            self._session_id = session_id
            self._emit("assessment_planning_session_bound", mode="simulation",
                       live_calls_enabled=False, ledger_id=self._ledger.ledger_id,
                       scope_id=self._scope_id)
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()

    def _check_control(self, control):
        if self._ledger.mode != "simulation":
            raise ValueError("invalid_owned_planning_configuration")
        if (type(control) is not ExecutionControl
                or type(control.deadline) not in {int, float} or not math.isfinite(control.deadline)
                or control.clock is not time.monotonic
                or control.cancelled is not None and type(control.cancelled) is not threading.Event):
            raise ValueError("invalid_planning_control")
        fields = (type(control.deadline), control.deadline, control.cancelled, control.clock)
        if self._control is not None and (control is not self._control or fields != self._control_fields):
            raise ValueError("planning_control_changed")
        if control.remaining() > 120:
            raise ValueError("invalid_planning_control")
        if self._control is None:
            self._control, self._control_fields = control, fields

    def _exchange(self, observation, request, *, step, control):
        """Settle known usage before any response byte reaches the parser."""
        self._check_control(control)
        if (self._ledger.mode != "simulation" or type(request) is not bytes
                or request != build_request(contract.CONFIG, observation)):
            raise ValueError("planning_request_mismatch")
        attempt_id = "planning-" + self._instance_id + "-" + str(step)
        request_digest = hashlib.sha256(request).hexdigest()
        try:
            self._ledger.estimate(attempt_id, scope_id=self._scope_id,
                request_digest=request_digest, price=contract.PRICE,
                usage=TokenUsage(len(request), contract.OUTPUT_LIMIT),
                input_token_limit=contract.INPUT_LIMIT, output_token_limit=contract.OUTPUT_LIMIT)
            self._ledger.reserve(attempt_id)
            self._emit("assessment_planning_reserved", step=step, attempt_id=attempt_id,
                       request_digest=request_digest, mode="simulation")
            self._check_control(control)
            self._ledger.begin_dispatch(attempt_id, request_digest=request_digest)
            self._emit("assessment_planning_dispatch_started", step=step, attempt_id=attempt_id)
            self._check_control(control)
            raw = self.broker.exchange(observation, request, control=control)
            self._check_control(control)
            usage, reference = contract.usage(raw)
            attempt = self._ledger.settle_usage(attempt_id, usage,
                receipt_reference=reference, event_id=attempt_id + "-usage")
            accepted = usage.input_tokens <= contract.INPUT_LIMIT and usage.output_tokens <= contract.OUTPUT_LIMIT
            self._emit("assessment_planning_settled", step=step, attempt_id=attempt_id,
                       within_token_limits=accepted, actual_microusd=attempt["actual_microusd"],
                       actual_source="usage_derived", mode="simulation")
            self._check_control(control)
            if not accepted:
                raise ValueError("planning_usage_overrun")
            return raw
        except BaseException as exc:
            # A commit can succeed even when its acknowledgement is lost. The
            # durable state, not a local return flag, determines safe cleanup.
            try:
                state = self._ledger.attempt(attempt_id)["state"]
                if state == "dispatched":
                    reason = ("cancelled" if isinstance(exc, ExecutionStopped) and exc.reason == "session_cancelled"
                              else "timeout" if isinstance(exc, ExecutionStopped)
                              else "missing_usage" if isinstance(exc, ValueError)
                              and str(exc) == "planning_usage_unrecognized" else "transport_error")
                    self._ledger.mark_uncertain(attempt_id, reason=reason)
                elif state in {"estimated", "reserved"}:
                    self._ledger.cancel(attempt_id)
            except BaseException:
                # An unavailable ledger retains its durable state and any hold;
                # never replace the original stop or release a proposal here.
                pass
            raise

    def propose(self, observation, *, control):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("planning_already_running")
        try:
            if self._closed or self._session_id is None:
                raise RuntimeError("planning_provider_closed")
            self._check_control(control)
            if type(observation) is not bytes or len(observation) > 8192:
                raise ValueError("invalid_planning_observation")
            value = load_json(observation)
            if (set(value) != {"step", "untrusted_observation"}
                    or type(value["step"]) is not int or value["step"] != self._next_step
                    or not 1 <= value["step"] <= 3):
                raise ValueError("invalid_planning_observation")
            step = self._next_step
            self._next_step += 1
            # This sink durably records the independent workflow decision first.
            decision = self._evidence.record_decision(step, observation)
            plan = {"schema_version": "1", "action": decision.action, "done": decision.done}
            self._check_control(control)
            if plan["action"] is None:
                self._closed = True
                if plan["done"] is not True:
                    raise ValueError("invalid_planning_decision")
                return contract.encode(plan)
            released = contract.release_observation(self._case, decision, observation)
            exchanged = completed = exchange_failed = False

            def exchange(request, *, control):
                nonlocal exchanged, completed, exchange_failed
                if exchanged:
                    exchange_failed = True
                    raise RuntimeError("planning_exchange_reused")
                exchanged = True
                try:
                    result = self._exchange(released, request, step=step, control=control)
                    completed = True
                    return result
                except BaseException:
                    exchange_failed = True
                    raise

            raw = self._planner.plan(contract.CONFIG, released, exchange, control=control)
            self._check_control(control)
            if (not completed or exchange_failed or type(raw) is not bytes or len(raw) > 16384
                    or contract.encode(_plan(raw)) != contract.encode(plan)):
                raise ValueError("planning_candidate_mismatch")
            self._emit("assessment_planning_proposal_released", step=step,
                       action_digest=decision.action_digest, workflow_digest=decision.workflow_digest)
            self._check_control(control)
            if plan["done"]:
                self._closed = True
            return raw
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()
