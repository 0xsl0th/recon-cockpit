"""Trusted reservations and receipt checks for the fixed owned TLS fixture.

This broker releases only the explicit status-only profile. Every accepted
attempt reserves its full allowance before durable audit and runtime entry;
neither remote usage nor any failure can refund it or trigger a retry.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
import math
import threading
import time
from types import MappingProxyType
from uuid import uuid4

from .execution import ExecutionControl, ExecutionStopped
from .openai_protocol import OpenAIConfig
from .provider_contract import (
    BOUNDARY_NAMES, ERROR_CODES, HOST, MAX_OUTPUT_TOKENS, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    METHOD, MODEL, PATH, PORT, TLS_NAME, WORKER_STATUSES, ProviderError,
    ProviderLimits, SyntheticTariff, build_request, digest, release_profile,
)
from .provider_lab import LinuxOwnedProviderTransport


_MONOTONIC = time.monotonic
_RECEIPT_FIELDS = frozenset({"schema_version", "context_digest", "status", "http_status",
                             "boundary_checks", "cleanup", "connection_count", "request_count"})


def _receipt(value, context_digest):
    """Copy only a closed, bounded schema, before exposing or auditing it."""
    if (type(value) is not dict or set(value) != _RECEIPT_FIELDS
            or type(value["schema_version"]) is not str or value["schema_version"] != "1"
            or type(value["context_digest"]) is not str or value["context_digest"] != context_digest
            or type(value["status"]) is not str or value["status"] not in WORKER_STATUSES):
        raise ProviderError("provider_receipt_invalid")
    status = value["http_status"]
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise ProviderError("provider_receipt_invalid")
    checks = value["boundary_checks"]
    if checks is not None and (type(checks) is not dict or set(checks) != BOUNDARY_NAMES
                              or any(type(item) is not bool for item in checks.values())):
        raise ProviderError("provider_receipt_invalid")
    cleanup = value["cleanup"]
    if (type(cleanup) is not dict or set(cleanup) != {"worker_reaped", "owner_reaped"}
            or any(type(item) is not bool for item in cleanup.values())):
        raise ProviderError("provider_receipt_invalid")
    connections, requests = value["connection_count"], value["request_count"]
    if ((connections is None) != (requests is None)
            or connections is not None and (type(connections) is not int or type(requests) is not int
                                           or not 0 <= requests <= connections <= 1)):
        raise ProviderError("provider_receipt_invalid")
    if (value["status"] == "ok" and (status != 200 or connections != 1 or requests != 1)
            or value["status"] == "http_error" and (status is None or status == 200)):
        raise ProviderError("provider_receipt_invalid")
    return deepcopy(value)


class OwnedProviderBroker:
    """A single fixed runtime, tariff and immutable control lifetime."""

    def __init__(self, audit, transport, *, limits=None, tariff=None):
        if type(transport) is not LinuxOwnedProviderTransport:
            raise ProviderError("provider_invalid_transport")
        limits = ProviderLimits() if limits is None else limits
        tariff = SyntheticTariff() if tariff is None else tariff
        if type(limits) is not ProviderLimits:
            raise ProviderError("provider_invalid_limits")
        if type(tariff) is not SyntheticTariff:
            raise ProviderError("provider_invalid_tariff")
        self._limits = ProviderLimits(**asdict(limits))
        self._tariff = SyntheticTariff(**asdict(tariff))
        self._transport, self._scenario, self._audit = transport, transport.scenario, audit
        self._broker_id = str(uuid4())
        self._config_digest = digest({
            "config": asdict(self.config), "limits": asdict(self._limits), "tariff": asdict(self._tariff),
            "host": HOST, "port": PORT, "tls_name": TLS_NAME, "method": METHOD, "path": PATH,
            "verify_tls": True, "scenario": self._scenario, "release_profile": release_profile(),
            "transport": "owned_tls", "retries": 0,
        })
        self._lock, self._state_lock = threading.Lock(), threading.Lock()
        self._counters = {"calls_reserved": 0, "output_tokens_reserved": 0,
                          "request_bytes_reserved": 0, "synthetic_cost_units_reserved": 0}
        self._audit_failed = False
        self._last_error = self._last_receipt = self._control = self._control_fields = None

    @property
    def broker_id(self):
        return self._broker_id

    @property
    def config_digest(self):
        return self._config_digest

    @property
    def config(self):
        return OpenAIConfig(MODEL, MAX_OUTPUT_TOKENS)

    @property
    def limits(self):
        return ProviderLimits(**asdict(self._limits))

    @property
    def tariff(self):
        return SyntheticTariff(**asdict(self._tariff))

    @property
    def snapshot(self):
        with self._state_lock:
            return MappingProxyType(dict(self._counters))

    @property
    def last_error(self):
        with self._state_lock:
            return self._last_error

    @property
    def last_receipt(self):
        with self._state_lock:
            return deepcopy(self._last_receipt)

    def _set_error(self, code):
        with self._state_lock:
            self._last_error = code

    def _emit(self, kind, **fields):
        if self._audit_failed:
            raise ProviderError("provider_audit_unavailable")
        try:
            self._audit.emit({"event_type": kind, "broker_id": self.broker_id,
                              "config_digest": self.config_digest, **fields})
        except Exception:
            self._audit_failed = True
            self._set_error("provider_audit_unavailable")
            raise ProviderError("provider_audit_unavailable") from None

    def _reject(self, code):
        self._set_error(code)
        self._emit("provider_request_rejected", reason=code, **dict(self.snapshot))
        raise ProviderError(code)

    def _check_control(self, control):
        if type(control) is not ExecutionControl:
            raise ProviderError("provider_invalid_control")
        fields = (type(control.deadline), control.deadline, control.cancelled, control.clock)
        if self._control is not None and (self._control is not control or self._control_fields != fields):
            raise ProviderError("provider_control_changed")
        if (type(control.deadline) not in {int, float} or not math.isfinite(control.deadline)
                or control.clock is not _MONOTONIC
                or control.cancelled is not None and type(control.cancelled) is not threading.Event):
            raise ProviderError("provider_invalid_control")
        if control.remaining() > 120:
            raise ProviderError("provider_invalid_control")
        if self._control is None:
            self._control, self._control_fields = control, fields

    def _accept_receipt(self, receipt, context_digest):
        receipt = _receipt(receipt, context_digest)
        with self._state_lock:
            self._last_receipt = receipt
        if not all(receipt["cleanup"].values()):
            raise ProviderError("provider_cleanup_failed")
        checks = receipt["boundary_checks"]
        if checks is not None and not all(checks.values()) or receipt["status"] == "ok" and checks is None:
            raise ProviderError("provider_isolation_failed")
        return receipt

    def _exchange(self, request, control, base):
        """Record exactly one terminal event for each durably reserved attempt."""
        context_digest = base["context_digest"]
        with self._state_lock:
            self._last_receipt = None
        try:
            self._check_control(control)
            try:
                result = self._transport.exchange(request, control=control, context_digest=context_digest)
            except Exception:
                # Runtime receipts on setup/stop failures are observations, not
                # fabricated success. Missing measurements remain unknown.
                receipt = self._transport.last_receipt
                if receipt is not None:
                    self._accept_receipt(receipt, context_digest)
                raise
            if type(result) is not dict or set(result) != {"body", "receipt"}:
                raise ProviderError("provider_receipt_invalid")
            receipt = self._accept_receipt(result["receipt"], context_digest)
            body = result["body"]
            if receipt["status"] != "ok":
                if body is not None:
                    raise ProviderError("provider_receipt_invalid")
                raise ProviderError("provider_" + receipt["status"])
            if type(body) is not bytes or not 1 <= len(body) <= MAX_RESPONSE_BYTES:
                raise ProviderError("provider_receipt_invalid")
            self._check_control(control)
        except ExecutionStopped as exc:
            if type(exc.reason) is not str or exc.reason not in {"session_timeout", "session_cancelled"}:
                self._set_error("provider_transport_failed")
                self._emit("provider_exchange_finished", **base, exchange_status="failed",
                           reason="provider_transport_failed", receipt=self.last_receipt)
                raise ProviderError("provider_transport_failed") from None
            self._set_error(exc.reason)
            self._emit("provider_exchange_finished", **base, exchange_status="stopped",
                       reason=exc.reason, receipt=self.last_receipt)
            raise
        except Exception as exc:
            code = (exc.code if type(exc) is ProviderError and type(exc.code) is str
                    and exc.code in ERROR_CODES else "provider_transport_failed")
            self._set_error(code)
            self._emit("provider_exchange_finished", **base, exchange_status="failed",
                       reason=code, receipt=self.last_receipt)
            raise ProviderError(code) from None
        self._emit("provider_exchange_finished", **base, exchange_status="succeeded",
                   response_bytes=len(body), response_digest=hashlib.sha256(body).hexdigest(),
                   receipt=self.last_receipt)
        self._check_control(control)
        self._set_error(None)
        return body

    def exchange(self, observation, request, *, control):
        if not self._lock.acquire(blocking=False):
            raise ProviderError("provider_already_running")
        try:
            if self._audit_failed:
                self._set_error("provider_audit_unavailable")
                raise ProviderError("provider_audit_unavailable")
            self._set_error(None)
            try:
                self._check_control(control)
                if type(request) is not bytes or not 1 <= len(request) <= MAX_REQUEST_BYTES:
                    raise ProviderError("provider_invalid_request")
                expected = build_request(observation)
                if request != expected:
                    raise ProviderError("provider_request_mismatch")
                if (type(self._transport) is not LinuxOwnedProviderTransport
                        or self._transport.scenario != self._scenario):
                    raise ProviderError("provider_invalid_transport")
                self._check_control(control)
                cost = self._tariff.reserve(len(request))
                increments = {"calls_reserved": 1, "output_tokens_reserved": MAX_OUTPUT_TOKENS,
                              "request_bytes_reserved": len(request), "synthetic_cost_units_reserved": cost}
                budgets = (("calls_reserved", self._limits.max_calls, "provider_call_limit"),
                           ("output_tokens_reserved", self._limits.max_reserved_output_tokens, "provider_token_limit"),
                           ("request_bytes_reserved", self._limits.max_request_bytes, "provider_request_limit"),
                           ("synthetic_cost_units_reserved", self._limits.max_synthetic_cost_units, "provider_cost_limit"))
                counters = self.snapshot
                for field, limit, code in budgets:
                    if counters[field] + increments[field] > limit:
                        raise ProviderError(code)
            except ProviderError as exc:
                self._reject(exc.code)
            with self._state_lock:
                self._last_receipt = None
                for field, value in increments.items():
                    self._counters[field] += value
            base = {"broker_sequence": self.snapshot["calls_reserved"],
                    "request_digest": hashlib.sha256(request).hexdigest(), **dict(self.snapshot)}
            base["context_digest"] = digest({"broker_id": self.broker_id, "config_digest": self.config_digest,
                                             "deadline": control.deadline, **base})
            self._emit("provider_request_reserved", **base)
            return self._exchange(request, control, base)
        except ExecutionStopped as exc:
            self._set_error(exc.reason)
            raise
        except ProviderError as exc:
            self._set_error(exc.code)
            raise
        finally:
            self._lock.release()
