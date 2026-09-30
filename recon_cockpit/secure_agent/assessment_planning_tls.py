"""Owned TLS planning composed with the reviewed evidence and money gate.

Only the closed planning descriptor enters a disconnected fixture network.
The host retains evidence, monetary admission and receipt validation; the fixed
TLS worker owns the synthetic credential and network exchange. Neither gains
approval, launch or finding authority. No live-provider switch exists here.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import math
import threading
import time
from types import MappingProxyType
from uuid import uuid4

from . import assessment_planning_contract as contract
from .assessment_planning import OwnedAssessmentPlanningProvider
from .assessment_planning_tls_contract import SCENARIOS
from .assessment_planning_transport import LinuxOwnedPlanningTransport
from .audit import AuditUnavailable
from .execution import ExecutionControl, ExecutionStopped
from .openai_protocol import MAX_RESPONSE_BYTES, build_request
from .provider_broker import _receipt
from .provider_contract import ERROR_CODES, ProviderError


class OwnedPlanningTLSBroker:
    """Three bounded owned exchanges; no retries, replacements or refunds."""

    def __init__(self, audit, transport):
        if type(transport) is not LinuxOwnedPlanningTransport:
            raise ProviderError("provider_invalid_transport")
        self._audit, self._transport = audit, transport
        self._identity = (transport.case, transport.scenario, transport.run_id)
        self._broker_id = str(uuid4())
        self._config_digest = hashlib.sha256(contract.encode({
            "profile": contract.PROFILE, "model": contract.MODEL,
            "transport": "disconnected_owned_tls", "case": transport.case,
            "scenario": transport.scenario, "run_id": transport.run_id,
            "max_calls": 3, "input_limit": contract.INPUT_LIMIT,
            "output_limit": contract.OUTPUT_LIMIT, "retries": 0,
        })).hexdigest()
        self._counters = {"calls_reserved": 0, "output_tokens_reserved": 0,
                          "request_bytes_reserved": 0}
        self._lock = threading.Lock()
        self._control = self._control_fields = self._last_receipt = self._last_error = None
        self._closed = self._audit_failed = False

    @property
    def broker_id(self):
        return self._broker_id

    @property
    def config_digest(self):
        return self._config_digest

    @property
    def snapshot(self):
        return MappingProxyType(dict(self._counters))

    @property
    def last_error(self):
        return self._last_error

    @property
    def last_receipt(self):
        return deepcopy(self._last_receipt)

    def _emit(self, kind, **fields):
        if self._audit_failed:
            raise AuditUnavailable("audit_previously_failed")
        try:
            self._audit.emit({"event_type": kind, "broker_id": self.broker_id,
                              "config_digest": self.config_digest, **fields})
        except BaseException as exc:
            self._audit_failed = True
            if not isinstance(exc, Exception):
                raise
            raise AuditUnavailable("audit_unavailable") from None

    def _check_control(self, control):
        if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                or type(control.deadline) not in {int, float} or not math.isfinite(control.deadline)
                or control.cancelled is not None and type(control.cancelled) is not threading.Event):
            raise ProviderError("provider_invalid_control")
        fields = (type(control.deadline), control.deadline, control.cancelled, control.clock)
        if self._control is not None and (control is not self._control or fields != self._control_fields):
            raise ProviderError("provider_control_changed")
        if control.remaining() > 120:
            raise ProviderError("provider_invalid_control")
        if self._control is None:
            self._control, self._control_fields = control, fields

    def _accept_receipt(self, value, context_digest):
        receipt = _receipt(value, context_digest)
        self._last_receipt = receipt
        if not all(receipt["cleanup"].values()):
            raise ProviderError("provider_cleanup_failed")
        checks = receipt["boundary_checks"]
        if (checks is not None and not all(checks.values())
                or receipt["status"] == "ok" and checks is None):
            raise ProviderError("provider_isolation_failed")
        return receipt

    def exchange(self, observation, request, *, control):
        if not self._lock.acquire(blocking=False):
            raise ProviderError("provider_already_running")
        base = None
        terminal_recorded = False
        try:
            if self._closed:
                raise ProviderError("provider_closed")
            self._check_control(control)
            if (type(self._transport) is not LinuxOwnedPlanningTransport
                    or (self._transport.case, self._transport.scenario, self._transport.run_id) != self._identity):
                raise ProviderError("provider_invalid_transport")
            if (type(request) is not bytes or not 1 <= len(request) <= contract.INPUT_LIMIT
                    or request != build_request(contract.CONFIG, observation)):
                raise ProviderError("provider_request_mismatch")
            if self._counters["calls_reserved"] >= 3:
                raise ProviderError("provider_call_limit")
            self._counters["calls_reserved"] += 1
            self._counters["request_bytes_reserved"] += len(request)
            self._counters["output_tokens_reserved"] += contract.OUTPUT_LIMIT
            base = {"broker_sequence": self._counters["calls_reserved"],
                    "request_digest": hashlib.sha256(request).hexdigest(), **self._counters}
            context_digest = hashlib.sha256(contract.encode({
                "broker_id": self.broker_id, "config_digest": self.config_digest,
                "deadline": control.deadline, **base})).hexdigest()
            base["context_digest"] = context_digest
            self._last_receipt = None
            self._emit("assessment_planning_tls_reserved", **base)
            self._check_control(control)
            try:
                result = self._transport.exchange(request, control=control, context_digest=context_digest)
            except BaseException:
                receipt = self._transport.last_receipt
                if receipt is not None:
                    self._accept_receipt(receipt, context_digest)
                raise
            if type(result) is not dict or set(result) != {"body", "receipt"}:
                raise ProviderError("provider_receipt_invalid")
            receipt = self._accept_receipt(result["receipt"], context_digest)
            if receipt["status"] != "ok":
                if result["body"] is not None:
                    raise ProviderError("provider_receipt_invalid")
                raise ProviderError("provider_" + receipt["status"])
            body = result["body"]
            if type(body) is not bytes or not 1 <= len(body) <= MAX_RESPONSE_BYTES:
                raise ProviderError("provider_receipt_invalid")
            self._check_control(control)
            self._emit("assessment_planning_tls_finished", **base,
                       exchange_status="succeeded", receipt=receipt)
            terminal_recorded = True
            self._check_control(control)
            return body
        except BaseException as exc:
            self._closed = True
            code = (exc.code if type(exc) is ProviderError and exc.code in ERROR_CODES
                    else exc.reason if type(exc) is ExecutionStopped
                    and exc.reason in {"session_cancelled", "session_timeout"}
                    else "provider_audit_unavailable" if isinstance(exc, AuditUnavailable)
                    else "provider_transport_failed")
            self._last_error = code
            if base is not None and not self._audit_failed and not terminal_recorded:
                self._emit("assessment_planning_tls_finished", **base,
                           exchange_status="failed", reason=code, receipt=self.last_receipt)
            if isinstance(exc, (ExecutionStopped, AuditUnavailable)) or not isinstance(exc, Exception):
                raise
            raise ProviderError(code) from None
        finally:
            self._lock.release()


class OwnedTLSAssessmentPlanningProvider(OwnedAssessmentPlanningProvider):
    """Same evidence/settlement/proposal gate, with one fixed owned TLS broker."""

    name = "owned-tls-assessment-planning-v1"

    def __init__(self, case, audit, evidence, ledger, *, scope_id, scenario="success"):
        if type(scenario) is not str or scenario not in SCENARIOS:
            raise ValueError("invalid_owned_planning_configuration")
        self._initialize(case, audit, evidence, ledger, scope_id=scope_id)
        self._broker = OwnedPlanningTLSBroker(audit,
            LinuxOwnedPlanningTransport(case, scenario=scenario, run_id=self._instance_id))
