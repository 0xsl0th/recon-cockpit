"""Trusted policy and accounting for scripted, strictly offline exchanges.

No HTTP client, key lookup, environment access, proxy handling, or live mode is
implemented. The fixed HTTPS metadata is a future transport contract only; this
module cannot make a network request. Responses remain untrusted bytes for the
isolated decoder, and provider accounting grants no tool execution authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import threading
import time
from types import MappingProxyType
from uuid import uuid4

from .audit import AuditUnavailable
from .execution import ExecutionControl, ExecutionStopped
from .openai_protocol import (MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, REQUEST_METHOD,
                              RESPONSE_URL, OpenAIConfig, build_request)


_ERROR_CODES = frozenset({
    "broker_invalid_config", "broker_invalid_limits", "broker_invalid_transport",
    "broker_invalid_control", "broker_invalid_request", "broker_request_mismatch",
    "broker_transport_contract", "broker_transport_exhausted", "broker_transport_busy",
    "broker_transport_failed", "broker_http_status", "broker_response_limit",
    "broker_already_running",
})


class BrokerError(RuntimeError):
    """Only static local codes may cross the provider boundary."""

    def __init__(self, code):
        if type(code) is not str or code not in _ERROR_CODES:
            raise ValueError("invalid_broker_error")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class BrokerLimits:
    max_calls: int = 3
    max_reserved_output_tokens: int = 3072
    max_request_bytes: int = 49152

    def __post_init__(self):
        for name, maximum in (("max_calls", 16), ("max_reserved_output_tokens", 65536),
                              ("max_request_bytes", 262144)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid_broker_limits")


@dataclass(frozen=True, slots=True)
class OfflineReply:
    status_code: int
    body: bytes
    delay_seconds: float = 0

    def __post_init__(self):
        # One extra byte models a bounded reader detecting response overflow.
        # The broker never releases a response larger than MAX_RESPONSE_BYTES.
        if (type(self.status_code) is not int or not 100 <= self.status_code <= 599
                or type(self.body) is not bytes or len(self.body) > MAX_RESPONSE_BYTES + 1
                or type(self.delay_seconds) not in (int, float)
                or not math.isfinite(self.delay_seconds) or not 0 <= self.delay_seconds <= 600):
            raise ValueError("invalid_offline_reply")


class OfflineTransport:
    """Finite scripted replies, never an HTTP implementation or plugin host."""

    def __init__(self, replies: tuple[OfflineReply, ...]):
        if type(replies) is not tuple or len(replies) > 16:
            raise ValueError("invalid_offline_transport")
        for reply in replies:
            if type(reply) is not OfflineReply:
                raise ValueError("invalid_offline_transport")
            reply.__post_init__()
        self._replies = replies
        self._index = 0
        self._lock = threading.Lock()

    @property
    def calls(self):
        return self._index

    def exchange(self, request: bytes, *, method, url, verify_tls, control: ExecutionControl) -> OfflineReply:
        if (method != REQUEST_METHOD or url != RESPONSE_URL or verify_tls is not True
                or type(request) is not bytes or len(request) > MAX_REQUEST_BYTES
                or type(control) is not ExecutionControl):
            raise BrokerError("broker_transport_contract")
        if not self._lock.acquire(blocking=False):
            raise BrokerError("broker_transport_busy")
        try:
            control.check()
            if self._index >= len(self._replies):
                raise BrokerError("broker_transport_exhausted")
            reply = self._replies[self._index]
            if type(reply) is not OfflineReply:
                raise BrokerError("broker_transport_failed")
            reply.__post_init__()
            # Cancellation or timeout cannot make a scripted reply reusable.
            self._index += 1
            ready = control.clock() + reply.delay_seconds
            while True:
                remaining = control.remaining()
                delay = ready - control.clock()
                if delay <= 0:
                    break
                interval = min(delay, remaining, 0.05)
                if control.cancelled is None:
                    time.sleep(interval)
                else:
                    control.cancelled.wait(interval)
            control.check()
            return reply
        finally:
            self._lock.release()


def _digest(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


class OfflineOpenAIBroker:
    """Reserve complete allowances before durable audit and offline exchange.

    Each accepted request spends one call, the complete configured output-token
    allowance, and its request bytes. There are no refunds or automatic retries,
    including on cancellation, transport errors, HTTP failures, or audit failure.
    Usage metadata is untrusted and never changes these counters.
    """

    def __init__(self, config: OpenAIConfig, audit, transport: OfflineTransport, limits=None):
        if type(config) is not OpenAIConfig:
            raise BrokerError("broker_invalid_config")
        try:
            self._config = OpenAIConfig(config.model, config.max_output_tokens)
        except ValueError:
            raise BrokerError("broker_invalid_config") from None
        if limits is None:
            limits = BrokerLimits()
        if type(limits) is not BrokerLimits:
            raise BrokerError("broker_invalid_limits")
        self._limits = BrokerLimits(**asdict(limits))
        if type(transport) is not OfflineTransport:
            raise BrokerError("broker_invalid_transport")
        self._transport = transport
        self._audit = audit
        self._broker_id = str(uuid4())
        self._config_digest = _digest({
            "config": asdict(self._config), "limits": asdict(self._limits),
            "method": REQUEST_METHOD, "url": RESPONSE_URL,
            "verify_tls": True, "transport": "offline",
        })
        self._lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._counters = {"calls_reserved": 0, "output_tokens_reserved": 0, "request_bytes_reserved": 0}
        self._audit_failed = False
        self._last_error = None

    @property
    def broker_id(self):
        return self._broker_id

    @property
    def config_digest(self):
        return self._config_digest

    @property
    def config(self):
        return self._config

    @property
    def limits(self):
        return self._limits

    @property
    def snapshot(self):
        with self._state_lock:
            return MappingProxyType(dict(self._counters))

    @property
    def last_error(self):
        with self._state_lock:
            return self._last_error

    def _set_error(self, code):
        with self._state_lock:
            self._last_error = code

    def _emit(self, kind, **fields):
        if self._audit_failed:
            raise AuditUnavailable("audit_previously_failed")
        event = {"event_type": kind, "broker_id": self.broker_id,
                 "config_digest": self.config_digest, **fields}
        try:
            self._audit.emit(event)
        except Exception:
            self._audit_failed = True
            self._set_error("audit_unavailable")
            raise AuditUnavailable("audit_unavailable") from None

    def _reject(self, code, *, budget=False):
        self._set_error(code)
        self._emit("broker_request_rejected", reason=code, **dict(self.snapshot))
        if budget:
            raise ExecutionStopped(code)
        raise BrokerError(code)

    def exchange(self, observation: bytes, request: bytes, *, control: ExecutionControl) -> bytes:
        if not self._lock.acquire(blocking=False):
            self._set_error("broker_already_running")
            raise BrokerError("broker_already_running")
        try:
            if self._audit_failed:
                self._set_error("audit_unavailable")
                raise AuditUnavailable("audit_previously_failed")
            self._set_error(None)
            if type(control) is not ExecutionControl:
                self._reject("broker_invalid_control")
            control.check()
            if type(request) is not bytes or len(request) > MAX_REQUEST_BYTES:
                self._reject("broker_invalid_request")
            try:
                expected = build_request(self._config, observation)
            except (ValueError, TypeError, RecursionError):
                self._reject("broker_invalid_request")
            if request != expected:
                self._reject("broker_request_mismatch")
            if type(self._transport) is not OfflineTransport:
                self._reject("broker_invalid_transport")
            control.check()
            counters = self.snapshot
            if counters["calls_reserved"] + 1 > self._limits.max_calls:
                self._reject("broker_call_limit", budget=True)
            if counters["output_tokens_reserved"] + self._config.max_output_tokens > self._limits.max_reserved_output_tokens:
                self._reject("broker_token_limit", budget=True)
            if counters["request_bytes_reserved"] + len(request) > self._limits.max_request_bytes:
                self._reject("broker_request_limit", budget=True)
            with self._state_lock:
                self._counters["calls_reserved"] += 1
                self._counters["output_tokens_reserved"] += self._config.max_output_tokens
                self._counters["request_bytes_reserved"] += len(request)
            base = {"broker_sequence": self.snapshot["calls_reserved"],
                    "request_digest": hashlib.sha256(request).hexdigest(), **dict(self.snapshot)}
            self._emit("broker_request_reserved", **base)
            try:
                control.check()
                reply = self._transport.exchange(request, method=REQUEST_METHOD, url=RESPONSE_URL,
                                                 verify_tls=True, control=control)
                control.check()
                if (type(reply) is not OfflineReply or type(reply.body) is not bytes
                        or type(reply.status_code) is not int or not 100 <= reply.status_code <= 599):
                    raise BrokerError("broker_transport_failed")
                if len(reply.body) > MAX_RESPONSE_BYTES:
                    raise BrokerError("broker_response_limit")
                if reply.status_code != 200:
                    raise BrokerError("broker_http_status")
            except ExecutionStopped as exc:
                self._set_error(exc.reason)
                self._emit("broker_exchange_finished", **base, exchange_status="stopped", reason=exc.reason)
                raise
            except BrokerError as exc:
                self._set_error(exc.code)
                self._emit("broker_exchange_finished", **base, exchange_status="failed", reason=exc.code)
                raise
            except Exception:
                self._set_error("broker_transport_failed")
                self._emit("broker_exchange_finished", **base, exchange_status="failed", reason="broker_transport_failed")
                raise BrokerError("broker_transport_failed") from None
            self._emit("broker_exchange_finished", **base, exchange_status="succeeded",
                       status_code=reply.status_code, response_bytes=len(reply.body),
                       response_digest=hashlib.sha256(reply.body).hexdigest())
            # A completion audit write may exhaust the same session deadline.
            control.check()
            self._set_error(None)
            return reply.body
        except ExecutionStopped as exc:
            self._set_error(exc.reason)
            raise
        finally:
            self._lock.release()
