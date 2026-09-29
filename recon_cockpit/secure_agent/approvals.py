"""Ephemeral human grants; never part of the planner interface."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .models import Action, Policy


class ApprovalUnavailable(RuntimeError):
    code = "approval_unavailable"


@dataclass(frozen=True, slots=True)
class Approval:
    reference: str
    action_digest: str
    policy_digest: str
    expires_at: float


class ApprovalStore:
    """Single-session grants. Restarting the owning process invalidates every grant.

    Only the trusted UI/review worker calls issue(); no agent IPC can call it. Monotonic
    deadlines avoid wall-clock rollback. consume() burns a grant on any attempt,
    including a changed action or policy, and is atomic across caller threads.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._grants: dict[str, Approval] = {}
        self._lock = threading.Lock()

    def issue(self, action: Action, policy: Policy) -> Approval:
        if policy.evaluate(action).decision != "approval_required":
            raise ValueError("approval_not_required")
        with self._lock:
            now = self._clock()
            self._grants = {
                key: value for key, value in self._grants.items()
                if value.expires_at > now
            }
            if len(self._grants) >= 1024:
                raise ValueError("approval_capacity")
            grant = Approval(secrets.token_hex(24), action.digest, policy.digest,
                             now + policy.approval_ttl_seconds)
            self._grants[grant.reference] = grant
            return grant

    def consume(self, reference: str | None, action: Action, policy: Policy) -> str | None:
        """Return a machine-readable failure code, or None on success."""
        return self.consume_with_grant(reference, action, policy)[0]

    def consume_with_grant(self, reference: str | None, action: Action,
                           policy: Policy) -> tuple[str | None, Approval | None]:
        """Burn once and retain the original expiry for the trusted launch witness."""
        with self._lock:
            if reference is None:
                return "approval_missing", None
            if not isinstance(reference, str) or len(reference) != 48:
                return "approval_unknown_or_replayed", None
            grant = self._grants.pop(reference, None)
            if grant is None:
                return "approval_unknown_or_replayed", None
            if self._clock() >= grant.expires_at:
                return "approval_expired", None
            if grant.action_digest != action.digest:
                return "approval_action_changed", None
            if grant.policy_digest != policy.digest:
                return "approval_policy_changed", None
            return None, grant
