"""Bounded model proposals with durable money admission and unchanged authority.

Only validated predecessor observations leave the host. Model choices remain
proposals; neither accounting nor normalization grants execution permission.
"""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import math
import threading
import time
from uuid import UUID, uuid4

from . import web_model_contract as contract
from .audit import AuditUnavailable
from .cost_contract import TokenUsage
from .cost_ledger import CostLedger
from .execution import ExecutionControl, ExecutionStopped
from .models import Policy, load_json, parse_action, parse_policy
from .openai_isolation import LinuxOpenAIPlanner
from .provider_pilot_contract import CHECKS, PilotConfig
from .session_protocol import _plan
from .web_assessment_contract import CASES, WORKFLOW, encode
from .web_model_transport import LinuxWebModelTransport
from .web_workflow import decide


MAX_CALL_MICROUSD = 450_000
MAX_SESSION_MICROUSD = 1_000_000


class WebModelError(RuntimeError):
    """Every message is a local code, never model or transport text."""


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _semantic(action):
    return {key: value for key, value in action.to_dict().items()
            if key not in {"action_id", "rationale"}}


class WebModelProvider:
    """At most three sequential exchanges in one existing authority session."""

    name = "bounded-owned-web-model-proposals-v1"

    def __init__(self, case, audit, evidence, ledger, *, scope_id, policy, config, transport_factory):
        if (type(case) is not str or case not in CASES or type(policy) is not Policy
                or type(config) is not PilotConfig or type(ledger) is not CostLedger
                or not callable(transport_factory)):
            raise WebModelError("web_model_invalid_configuration")
        config.__post_init__()
        if not config.enabled:
            raise WebModelError("web_model_disabled")
        if (config.price.model != contract.MODEL or config.max_call_microusd > MAX_CALL_MICROUSD
                or config.price.ceiling(contract.INPUT_LIMIT, contract.OUTPUT_LIMIT) > config.max_call_microusd):
            raise WebModelError("web_model_call_cap")
        self._case, self._audit, self._evidence = case, audit, evidence
        self._ledger, self._scope_id = ledger, scope_id
        self._policy, self._config = parse_policy(policy.to_dict()), config
        self._config_fields = asdict(config)
        self._mode = "simulation" if config.mode == "owned" else "provider"
        self._factory = transport_factory
        self._planner = LinuxOpenAIPlanner(profile=contract.WEB_MODEL_PROFILE)
        self._lock = threading.Lock()
        self._session_id = None
        self._instance_id = uuid4().hex
        self._next_step = 1
        self._trace = []
        self._transports = []
        self._control = self._control_fields = None
        self._closed = self._audit_failed = False
        self._terminal_reason = None
        self._config_digest = _digest(encode({"profile": contract.WEB_MODEL_PROFILE,
            "model": contract.MODEL, "output_limit": contract.OUTPUT_LIMIT,
            "input_limit": contract.INPUT_LIMIT, "endpoint": config.ip, "port": config.port,
            "tls_name": config.tls_name, "mode": config.mode, "price_digest": config.price.digest,
            "max_call_microusd": config.max_call_microusd}))
        manifest = evidence._manifest
        if (manifest["policy_digest"] != self._policy.digest or manifest["fixture_case"] != case
                or manifest["workflow"] != WORKFLOW):
            raise WebModelError("web_model_evidence_mismatch")
        self._check_ledger(fresh=True)

    def _check_ledger(self, *, fresh=False):
        report = self._ledger.report(self._scope_id)
        chain = report["budget_chain"]
        limits = [row for row in chain if row["kind"] in {"account", "session"}]
        if (self._ledger.mode != self._mode or report["summary"]["kind"] != "action"
                or len(limits) != 2 or any(type(row["limit_microusd"]) is not int
                    or not 0 <= row["limit_microusd"] <= MAX_SESSION_MICROUSD for row in limits)
                or fresh and report["summary"]["attempt_count"] != 0):
            raise WebModelError("web_model_invalid_ledger")

    @property
    def boundary_checks(self):
        return self._planner.boundary_checks

    @property
    def trace(self):
        with self._lock:
            return deepcopy(self._trace)

    @property
    def terminal_reason(self):
        return self._terminal_reason

    @property
    def accounting(self):
        return self._ledger.report(self._scope_id)

    @property
    def metrics(self):
        rows = self.trace
        summary = self.accounting["summary"]
        refusals = sum(row["outcome"] in {"provider_refusal", "explicit_stop"} for row in rows)
        usage = [row["usage"] for row in rows if row["usage"] is not None]
        return {"provider_calls_started": sum(row["dispatched"] for row in rows),
            "provider_calls_settled": sum(row["ledger_state"] == "settled" for row in rows),
            "refusal_count": refusals, "unnecessary_refusals": refusals,
            "malformed_outputs": sum(row["outcome"] == "malformed_output" for row in rows),
            "workflow_mismatches": sum(row["outcome"] in {"workflow_mismatch", "done_mismatch"} for row in rows),
            "model_latency_ms": sum(row["elapsed_ms"] for row in rows),
            "model_call_latencies_ms": [row["elapsed_ms"] for row in rows],
            **{key: sum(item[key] for item in usage) for key in (
                "input_tokens", "output_tokens", "cached_input_tokens")},
            "actual_microusd": summary["actual_microusd"],
            "held_microusd": summary["reserved_microusd"],
            "accounting_complete": summary["actual_complete"]}

    def _emit(self, event, **fields):
        if self._audit_failed:
            raise AuditUnavailable("audit_previously_failed")
        try:
            self._audit.emit({"event_type": event, "session_id": self._session_id,
                "provider": self.name, "profile": contract.WEB_MODEL_PROFILE,
                "config_digest": self._config_digest, **fields})
        except BaseException as exc:
            self._audit_failed = True
            if not isinstance(exc, Exception):
                raise
            raise AuditUnavailable("audit_unavailable") from None

    def bind_session(self, session_id):
        if not self._lock.acquire(blocking=False):
            raise WebModelError("web_model_already_running")
        try:
            if (self._closed or self._session_id is not None or type(session_id) is not str
                    or str(UUID(session_id)) != session_id
                    or session_id != self._evidence._manifest["session_id"]):
                raise WebModelError("web_model_invalid_binding")
            self._check_ledger(fresh=True)
            self._session_id = session_id
            self._emit("web_model_session_bound", mode=self._config.mode,
                ledger_id=self._ledger.ledger_id, scope_id=self._scope_id,
                price_digest=self._config.price.digest)
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()

    def close(self):
        with self._lock:
            self._closed = True

    def _check_control(self, control):
        if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                or type(control.deadline) not in {int, float} or not math.isfinite(control.deadline)
                or control.cancelled is not None and type(control.cancelled) is not threading.Event):
            raise WebModelError("web_model_invalid_control")
        fields = (type(control.deadline), control.deadline, control.cancelled, control.clock)
        if self._control is not None and (control is not self._control or fields != self._control_fields):
            raise WebModelError("web_model_control_changed")
        control.check()
        if control.remaining() > 60:
            raise WebModelError("web_model_invalid_control")
        if self._control is None:
            self._control, self._control_fields = control, fields
        if asdict(self._config) != self._config_fields or not self._config.enabled:
            raise WebModelError("web_model_configuration_changed")
        self._check_ledger()

    def _exchange(self, released, request, row, *, control):
        row["stage"] = "request_validation"
        self._check_control(control)
        if type(request) is not bytes or request != contract.build_request(released):
            raise WebModelError("web_model_request_mismatch")
        transport = self._factory()
        if (type(transport) is not LinuxWebModelTransport or transport in self._transports
                or type(transport.config) is not PilotConfig or asdict(transport.config) != self._config_fields
                or not transport.config.enabled):
            raise WebModelError("web_model_invalid_transport")
        self._transports.append(transport)
        attempt_id = row["attempt_id"]
        row["request_sha256"] = _digest(request)
        authorized = False
        try:
            row["stage"] = "reservation"
            if self._ledger.snapshot(self._scope_id)["attempt_count"] != len(self._trace) - 1:
                raise WebModelError("web_model_ledger_changed")
            self._ledger.estimate(attempt_id, scope_id=self._scope_id, request_digest=row["request_sha256"],
                price=self._config.price, usage=TokenUsage(contract.INPUT_LIMIT, contract.OUTPUT_LIMIT),
                input_token_limit=contract.INPUT_LIMIT, output_token_limit=contract.OUTPUT_LIMIT)
            self._ledger.reserve(attempt_id)
            self._emit("web_model_reserved", step=row["step"], attempt_id=attempt_id,
                request_sha256=row["request_sha256"], observation_sha256=row["observation_sha256"],
                released_observation_sha256=row["released_observation_sha256"])

            def authorize():
                nonlocal authorized
                if authorized:
                    raise WebModelError("web_model_dispatch_reused")
                self._check_control(control)
                row["stage"] = "dispatch"
                self._ledger.begin_dispatch(attempt_id, request_digest=row["request_sha256"])
                authorized = True
                self._emit("web_model_dispatch_started", step=row["step"], attempt_id=attempt_id,
                           request_sha256=row["request_sha256"])
                self._check_control(control)

            row["stage"] = "transport"
            result = transport.exchange(request, control=control, authorize=authorize)
            if not authorized or self._ledger.attempt(attempt_id)["state"] != "dispatched":
                raise WebModelError("web_model_dispatch_missing")
            if type(result) is not dict or set(result) != {"status", "http_status", "summary", "response"}:
                raise WebModelError("web_model_invalid_receipt")
            summary = result["summary"]
            if (type(summary) is not dict or set(summary) != {"usage", "reference", "output_status"}
                    or summary["output_status"] not in {"proposal", "refusal", "incomplete", "invalid"}):
                raise WebModelError("web_model_usage_unresolved")
            row["output_status"] = summary["output_status"]
            row["stage"] = "usage_settlement"
            if (type(summary["usage"]) is not dict or set(summary["usage"]) != {
                    "input_tokens", "output_tokens", "cached_input_tokens"}):
                raise WebModelError("web_model_usage_unresolved")
            usage = TokenUsage(**summary["usage"])
            attempt = self._ledger.settle_usage(attempt_id, usage,
                receipt_reference=summary["reference"], event_id=attempt_id + "-usage")
            row["usage"] = asdict(usage)
            self._emit("web_model_settled", step=row["step"], attempt_id=attempt_id,
                usage=row["usage"], actual_microusd=attempt["actual_microusd"],
                actual_source="usage_derived", output_status=row["output_status"])
            self._check_control(control)
            if usage.input_tokens > contract.INPUT_LIMIT or usage.output_tokens > contract.OUTPUT_LIMIT:
                raise WebModelError("web_model_usage_overrun")
            checks = transport.boundary_checks
            if (type(checks) is not dict or set(checks) != CHECKS or any(v is not True for v in checks.values())
                    or transport.cleanup_verified is not True):
                raise WebModelError("web_model_transport_boundary_failed")
            if result["status"] != "ok" or type(result["http_status"]) is not int or result["http_status"] != 200:
                raise WebModelError("web_model_transport_failed")
            if summary["output_status"] != "proposal":
                row["outcome"] = {"refusal": "provider_refusal", "incomplete": "incomplete_output",
                                  "invalid": "malformed_output"}[summary["output_status"]]
                raise WebModelError("web_model_output_rejected")
            if type(result["response"]) is not bytes or not 1 <= len(result["response"]) <= contract.MAX_RESPONSE_BYTES:
                raise WebModelError("web_model_invalid_receipt")
            row["stage"] = "isolated_output_parse"
            return result["response"]
        except BaseException as exc:
            try:
                state = self._ledger.attempt(attempt_id)["state"]
                if state == "dispatched":
                    self._ledger.mark_uncertain(attempt_id, reason=(
                        "cancelled" if isinstance(exc, ExecutionStopped) and exc.reason == "session_cancelled"
                        else "timeout" if isinstance(exc, ExecutionStopped) else "missing_usage"))
                elif state in {"estimated", "reserved"}:
                    self._ledger.cancel(attempt_id)
            except BaseException:
                pass  # Lost acknowledgements never refund a durable dispatch.
            raise
        finally:
            row["transport_boundary_checks"] = transport.boundary_checks
            row["transport_cleanup_verified"] = transport.cleanup_verified is True
            try:
                attempt = self._ledger.attempt(attempt_id)
                row.update(ledger_state=attempt["state"], actual_microusd=attempt["actual_microusd"],
                    held_microusd=attempt["reserved_microusd"],
                    dispatched=attempt["state"] in {"dispatched", "uncertain", "settled"})
                if attempt["usage"] is not None:
                    row["usage"] = deepcopy(attempt["usage"])
            except Exception:
                pass

    def propose(self, observation, *, control):
        if not self._lock.acquire(blocking=False):
            raise WebModelError("web_model_already_running")
        row = None
        started = time.monotonic()
        try:
            if self._closed or self._session_id is None:
                raise WebModelError("web_model_closed")
            self._check_control(control)
            if type(observation) is not bytes or len(observation) > 8192:
                raise WebModelError("web_model_invalid_observation")
            frame = load_json(observation)
            step = self._next_step
            if (set(frame) != {"step", "untrusted_observation"} or type(frame["step"]) is not int
                    or frame["step"] != step or not 1 <= step <= 3
                    or step == 1 and frame["untrusted_observation"] is not None):
                raise WebModelError("web_model_invalid_observation")
            decision = decide(self._case, step, self._evidence.records, observation)
            self._next_step += 1
            if decision.decision_kind != "propose":
                self._closed = True
                self._terminal_reason = "predecessor_unavailable"
                self._emit("web_model_predecessor_stopped", step=step, reason=decision.reason)
                return encode({"schema_version": "1", "action": None, "done": True})
            released = contract.release_observation(self._case, step, self._evidence.records, observation)
            row = {"step": step, "attempt_id": "web-model-" + self._instance_id + "-" + str(step),
                "observation_sha256": _digest(observation), "released_observation_sha256": _digest(released),
                "request_sha256": None, "raw_action_digest": None, "executed_action_digest": None,
                "model_action": None, "policy_decision": None, "policy_reasons": [],
                "stage": "isolated_request_build",
                "outcome": "provider_failed", "output_status": None, "usage": None,
                "ledger_state": None, "actual_microusd": None, "held_microusd": None,
                "dispatched": False, "elapsed_ms": 0, "parser_boundary_checks": None,
                "transport_boundary_checks": None, "transport_cleanup_verified": False}
            self._trace.append(row)
            exchanged = completed = exchange_failed = False

            def exchange(request, *, control):
                nonlocal exchanged, completed, exchange_failed
                if exchanged:
                    exchange_failed = True
                    raise WebModelError("web_model_exchange_reused")
                exchanged = True
                try:
                    result = self._exchange(released, request, row, control=control)
                    completed = True
                    return result
                except BaseException:
                    exchange_failed = True
                    raise

            try:
                raw = self._planner.plan(contract.CONFIG, released, exchange, control=control)
            except (ExecutionStopped, AuditUnavailable):
                raise
            except Exception:
                self._check_control(control)
                if row["outcome"] == "provider_refusal":
                    self._closed = True
                    self._terminal_reason = "provider_refusal"
                    return encode({"schema_version": "1", "action": None, "done": True})
                if getattr(self._planner, "last_error", None) == "output_invalid":
                    row["outcome"] = "malformed_output"
                raise
            self._check_control(control)
            if not completed or exchange_failed:
                raise WebModelError("web_model_exchange_incomplete")
            try:
                if type(raw) is not bytes or len(raw) > 16384:
                    raise ValueError("invalid_proposal_size")
                plan = _plan(raw)
                action = None if plan["action"] is None else parse_action(plan["action"])
            except (ValueError, TypeError, RuntimeError):
                row["outcome"] = "malformed_output"
                raise WebModelError("web_model_malformed_output") from None
            if action is None:
                row["outcome"] = self._terminal_reason = "explicit_stop"
                self._closed = True
                return encode(plan)
            row["stage"] = "workflow_validation"
            row["raw_action_digest"] = action.digest
            row["model_action"] = {key: value for key, value in action.to_dict().items() if key != "rationale"}
            if plan["done"] is not (step == 3):
                row["outcome"] = "done_mismatch"
                raise WebModelError("web_model_done_mismatch")
            policy_decision = self._policy.evaluate(action)
            row.update(policy_decision=policy_decision.decision, policy_reasons=list(policy_decision.reasons))
            if policy_decision.decision == "deny":
                row["outcome"] = "denied_proposal"
                self._closed = True
            elif encode(_semantic(action)) == encode(_semantic(parse_action(decision.action))):
                saved = self._evidence.record_decision(step, observation)
                if encode(saved.to_dict()) != encode(decision.to_dict()) or saved.action != decision.action:
                    raise WebModelError("web_model_evidence_changed")
                plan["action"] = decision.action
                row["outcome"] = "legitimate_proposal"
                self._closed = plan["done"]
            else:
                row["outcome"] = "workflow_mismatch"
                raise WebModelError("web_model_workflow_mismatch")
            row["executed_action_digest"] = parse_action(plan["action"]).digest
            row["stage"] = "proposal_release"
            self._emit("web_model_proposal_released", step=step, attempt_id=row["attempt_id"],
                raw_action_digest=row["raw_action_digest"], executed_action_digest=row["executed_action_digest"],
                outcome=row["outcome"], policy_decision=row["policy_decision"], policy_reasons=row["policy_reasons"])
            self._check_control(control)
            return encode(plan)
        except BaseException:
            self._closed = True
            if row is not None:
                self._terminal_reason = row["outcome"]
            raise
        finally:
            try:
                if row is not None:
                    row["elapsed_ms"] = min(10**9, max(0, int((time.monotonic() - started) * 1000)))
                    row["parser_boundary_checks"] = self._planner.boundary_checks
                    self._emit("web_model_attempt_finished", **deepcopy(row))
            finally:
                self._lock.release()
