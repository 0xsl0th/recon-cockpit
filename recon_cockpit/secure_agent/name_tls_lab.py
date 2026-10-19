"""Metadata host handle; live binding state belongs to the isolated owner."""

from copy import deepcopy
from dataclasses import asdict
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend
from .session_limits import SessionLimits
from . import name_tls_contract as contract
from . import name_tls_native_runtime as native


class NameTLSLab:
    def __init__(self, selection, session_id, limits, *, execute=False, runtime=None,
                 identity=None, closure=None):
        self.selection = contract.validate_selection(selection)
        if type(limits) is not SessionLimits or type(execute) is not bool:
            raise ValueError("invalid_name_tls_lab")
        contract.validate_limits(asdict(limits), self.selection)
        self.session_id, self.limits, self.execute = session_id, limits, execute
        self._runtime = native.validate_runtime(runtime)
        self._identity = contract.validate_identity(identity or contract.identity(
            self.selection, session_id, self._runtime), selection=self.selection,
            session_id=session_id, runtime=self._runtime)
        self._closure = closure
        self._control = self.topology = self.services = None
        self._started = self._closed = False
        self._receipt = self._last_ledger = None
        self._sequence = 0

    @property
    def identity(self):
        return deepcopy(self._identity)

    @property
    def runtime(self):
        return native.validate_runtime(self._runtime)

    @property
    def started(self):
        return self._started

    def __enter__(self):
        if self._closed:
            raise IsolationUnavailable("Name/TLS owner is permanently closed")
        return self

    def __exit__(self, *_):
        self.close()

    def _check_available(self):
        if self._closure is None:
            LinuxFixtureBackend().check_available()

    def start(self, control):
        if (type(self) is not ConfinedNameTLSLab or self._closed or not self.execute
                or type(control) is not ExecutionControl or control.clock is not time.monotonic
                or self._control is not None and self._control is not control
                or not 0 < control.remaining() <= 60
                or self._closure["name_tls_runtime"] != self._runtime):
            raise IsolationUnavailable("Name/TLS requires witnessed confined ownership")
        control.check()
        if self._started:
            return
        from .owned_launcher_runtime import runtime as bootstrap
        from .name_tls_topology import Topology
        from .name_tls_services import Services
        self._control = control
        self.topology = Topology(bootstrap(self._closure, owner=True), control,
            selection=self.selection, identity=self.identity, runtime=self.runtime)
        try:
            startup_deadline = min(control.deadline, time.monotonic() + 10)
            self.topology.start()
            self.services = Services(self.topology, selection=self.selection, identity=self.identity,
                runtime=self.runtime, closure=self._closure, control=control)
            self.services.start(startup_deadline)
            self._started = True
        except BaseException:
            self.close()
            raise

    def arm_action(self, action):
        self._control.check()
        self._sequence += 1
        # ARM is authoritative inside the still-live owner. No snapshot or host
        # constructor can replace its binding/generation/monotonic checks.
        return self.services.arm_action(action, self._sequence)

    def snapshot(self):
        self._last_ledger = self.topology.ledger_snapshot()
        return deepcopy(self._last_ledger)

    def evidence(self, *, deadline=None):
        value = (self.topology.ledger_evidence() if deadline is None else
                 self.services._topology_rpc(self.topology.ledger_evidence, deadline))
        self._last_ledger = value["ledger"]
        return value

    def close(self):
        if self._receipt is not None:
            return deepcopy(self._receipt)
        self._closed = True
        services = topology = None
        try:
            if self.services is not None:
                services = self.services.close()
        finally:
            if self.topology is not None:
                topology = self.topology.close()
        self._receipt = {"identity": self.identity, "status": "closed", "started": self._started,
                         "services": services, "topology": topology}
        return deepcopy(self._receipt)


class ConfinedNameTLSLab(NameTLSLab):
    def __init__(self, config, closure):
        super().__init__(config["case"], config["session_id"], SessionLimits(**config["limits"]),
            execute=config["execute"], runtime=closure["name_tls_runtime"],
            identity=config["owned_lab"], closure=closure)
