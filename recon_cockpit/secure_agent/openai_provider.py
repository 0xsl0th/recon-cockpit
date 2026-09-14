"""Offline broker/session adapter; only the fixed Linux parser is runnable."""

from __future__ import annotations

import threading
from uuid import UUID

from .audit import AuditUnavailable
from .openai_broker import BrokerError, OfflineOpenAIBroker
from .openai_isolation import LinuxOpenAIPlanner


class OfflineOpenAIProvider:
    """Simulated API exchanges with real parser isolation and host-side limits.

    This trusted adapter owns the broker. Only framed request/response bytes
    cross the sandbox boundary; neither the broker nor the audit sink does.
    Reusing this instance retains all reservations. There is no live mode.
    """

    name = "linux-isolated-openai-offline"

    def __init__(self, config, audit, transport, limits=None):
        self._broker = OfflineOpenAIBroker(config, audit, transport, limits)
        self._planner = LinuxOpenAIPlanner()
        self._audit = audit
        self._lock = threading.Lock()
        self._session_id = None
        self._audit_failed = False

    @property
    def broker(self):
        return self._broker

    @property
    def boundary_checks(self):
        return self._planner.boundary_checks

    def bind_session(self, session_id):
        """Record a trusted session/broker correlation without sharing handles."""
        if type(session_id) is not str or str(UUID(session_id)) != session_id:
            raise ValueError("invalid_broker_session")
        if not self._lock.acquire(blocking=False):
            raise BrokerError("broker_already_running")
        try:
            if self._audit_failed:
                raise AuditUnavailable("audit_previously_failed")
            if self._session_id is not None:
                raise RuntimeError("broker_session_already_bound")
            try:
                self._audit.emit({"event_type": "offline_provider_session_bound",
                                  "session_id": session_id, "broker_id": self.broker.broker_id,
                                  "provider": self.name, "live_calls_enabled": False})
            except (AuditUnavailable, RuntimeError, OSError, ValueError, TypeError):
                self._audit_failed = True
                raise AuditUnavailable("audit_unavailable") from None
            self._session_id = session_id
        finally:
            self._lock.release()

    def propose(self, observation: bytes, *, control) -> bytes:
        if not self._lock.acquire(blocking=False):
            raise BrokerError("broker_already_running")
        try:
            if self._audit_failed:
                raise AuditUnavailable("audit_previously_failed")
            control.check()

            def exchange(request, *, control):
                return self.broker.exchange(observation, request, control=control)

            return self._planner.plan(self.broker.config, observation, exchange, control=control)
        finally:
            self._lock.release()
