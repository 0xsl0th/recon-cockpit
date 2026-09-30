"""Owned-only planning TLS transport; no URL, credential or live selector."""

from __future__ import annotations

import math
import threading
import time

from . import assessment_planning_tls_contract as contract
from .execution import ExecutionControl
from .provider_lab import LinuxOwnedProviderTransport


class LinuxOwnedPlanningTransport:
    """At most three ordered requests in one immutable control lifetime."""

    def __init__(self, case, scenario="success", *, run_id):
        configuration = contract.context({"case": case, "scenario": scenario, "run_id": run_id})
        self._case = configuration["case"]
        self._scenario = configuration["scenario"]
        self._run_id = configuration["run_id"]
        self._runtime = None
        self._lock = threading.Lock()
        self._next_step = 1
        self._closed = False
        self._control = self._control_fields = self._owned_lab = None

    @property
    def case(self):
        return self._case

    @property
    def scenario(self):
        return self._scenario

    @property
    def run_id(self):
        return self._run_id

    @property
    def last_receipt(self):
        return None if self._runtime is None else self._runtime.last_receipt

    def exchange(self, request, *, control, context_digest):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("planning_transport_already_running")
        try:
            # A refusal before runtime creation must never expose the preceding
            # exchange's receipt as evidence about this attempted request.
            self._runtime = None
            if self._closed:
                raise RuntimeError("planning_transport_closed")
            if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(control.deadline) not in {int, float} or not math.isfinite(control.deadline)
                    or control.cancelled is not None and type(control.cancelled) is not threading.Event):
                raise ValueError("planning_transport_invalid_control")
            fields = (type(control.deadline), control.deadline, control.cancelled, control.clock)
            if (control.remaining() > 120 or self._control is not None
                    and (control is not self._control or fields != self._control_fields)):
                raise ValueError("planning_transport_invalid_control")
            details = contract.request_details(request, case=self.case)
            if (details["step"] != self._next_step or self._owned_lab is not None
                    and details["owned_lab"] is not self._owned_lab):
                raise ValueError("planning_transport_invalid_sequence")
            self._control, self._control_fields = control, fields
            self._owned_lab = details["owned_lab"]
            scenario = self.scenario if self._next_step == 1 else "success"
            self._next_step += 1
            self._runtime = LinuxOwnedProviderTransport(contract.transport_scenario(scenario))
            result = self._runtime._exchange_profile(request, control=control, context_digest=context_digest,
                planning={"case": self.case, "scenario": scenario, "run_id": self.run_id})
            if result["receipt"]["status"] != "ok" or self._next_step > 3:
                self._closed = True
            return result
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()
