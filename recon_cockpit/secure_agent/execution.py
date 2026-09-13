"""Trusted, process-local cancellation and monotonic session deadlines."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import threading
import time
from typing import Callable


class ExecutionStopped(RuntimeError):
    """A session stop, not an isolation failure or successful tool result."""

    def __init__(self, reason: str):
        if reason not in {"session_timeout", "session_cancelled", "broker_call_limit",
                          "broker_token_limit", "broker_request_limit"}:
            raise ValueError("invalid_execution_stop_reason")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ExecutionControl:
    """One immutable absolute deadline; no control fields come from proposals.

    Cancellation is cooperative in trusted supervisors. They terminate and reap
    child processes before propagating a stop. Host filesystem/kernel stalls
    cannot be hard-preempted safely by this in-process control.
    """

    deadline: float
    cancelled: threading.Event | None = None
    clock: Callable[[], float] = field(default=time.monotonic, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.deadline) not in {int, float} or not math.isfinite(self.deadline):
            raise ValueError("invalid_execution_deadline")
        if self.cancelled is not None and not isinstance(self.cancelled, threading.Event):
            raise ValueError("invalid_execution_cancellation")
        if not callable(self.clock):
            raise ValueError("invalid_execution_clock")

    def remaining(self) -> float:
        if self.cancelled is not None and self.cancelled.is_set():
            raise ExecutionStopped("session_cancelled")
        remaining = self.deadline - self.clock()
        if not math.isfinite(remaining) or remaining <= 0:
            raise ExecutionStopped("session_timeout")
        return remaining

    def check(self) -> None:
        self.remaining()
