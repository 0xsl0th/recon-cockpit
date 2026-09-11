"""Controller-only, in-memory human grants; never part of the planner interface."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .models import Action, Policy


@dataclass(frozen=True, slots=True)
class Approval:
    reference: str
    action_digest: str
    policy_digest: str
    expires_at: float


class ApprovalStore:
    """Single-session grants. Restarting the controller invalidates every grant.

    Only the trusted human UI calls issue(); no agent IPC can call it. Monotonic
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
        with self._lock:
            if reference is None:
                return "approval_missing"
            if not isinstance(reference, str) or len(reference) != 48:
                return "approval_unknown_or_replayed"
            grant = self._grants.pop(reference, None)
            if grant is None:
                return "approval_unknown_or_replayed"
            if self._clock() >= grant.expires_at:
                return "approval_expired"
            if grant.action_digest != action.digest:
                return "approval_action_changed"
            if grant.policy_digest != policy.digest:
                return "approval_policy_changed"
            return None
