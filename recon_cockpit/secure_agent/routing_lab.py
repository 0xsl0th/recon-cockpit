"""Metadata-only host handle and confined lifetime owner for routed actions."""

from copy import deepcopy
from dataclasses import asdict
import time

from . import routing_contract as contract
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend
from .session_limits import SessionLimits


class RoutingLab:
    def __init__(self, selection, session_id, limits, *, execute=True, runtime=None, identity=None, closure=None):
        self.selection = contract.validate_selection(selection)
        if type(limits) is not SessionLimits or type(execute) is not bool:
            raise ValueError("invalid_routing_lab")
        contract.validate_limits(asdict(limits), self.selection)
        self.session_id, self.limits, self.execute = session_id, limits, execute
        self._runtime = contract.validate_runtime(runtime, self.selection)
        self._identity = contract.validate_identity(identity or contract.identity(self.selection, session_id, self._runtime),
            selection=self.selection, session_id=session_id, runtime=self._runtime)
        self._closure = closure
        self._control = self.topology = self.services = None
        self._started = self._closed = False
        self._receipt = None
        self._last_ledger = None

    @property
    def identity(self):
        return deepcopy(self._identity)

    @property
    def runtime(self):
        return contract.validate_runtime(self._runtime, self.selection)

    @property
    def started(self):
        return self._started

    def __enter__(self):
        if self._closed:
            raise IsolationUnavailable("Routing lab permanently closed")
        return self

    def __exit__(self, *_):
        self.close()

    def _check_available(self):
        if self._closure is None:
            LinuxFixtureBackend().check_available()

    def start(self, control):
        if (type(self) is not ConfinedRoutingLab or self._closed or not self.execute
                or type(control) is not ExecutionControl or control.clock is not time.monotonic
                or self._control is not None and self._control is not control
                or control.remaining() > self.limits.max_runtime_seconds):
            raise IsolationUnavailable("Routing lab requires witnessed confined authority")
        control.check()
        if (type(self._closure) is not dict or "routing_runtime" not in self._closure
                or contract.validate_runtime(self._closure["routing_runtime"], self.selection) != self.runtime):
            raise IsolationUnavailable("Routing runtime commitment changed")
        if self._started:
            return
        from .owned_launcher_runtime import runtime as bootstrap
        from .routing_topology import Topology
        from .routing_services import Services
        self._control = control
        self.topology = Topology(bootstrap(self._closure, owner=True), control,
                                 selection=self.selection, identity=self.identity)
        try:
            self.topology.start()
            self.services = Services(self.topology, selection=self.selection, identity=self.identity,
                runtime=self.runtime, closure=self._closure, control=control, arm_action=self.arm_action)
            self._started = True
        except BaseException:
            self.close()
            raise

    def arm_action(self, selector, action_sequence, action_digest, action_deadline):
        self._control.check()
        # The owner's clock supplies its own action deadline; the client cannot
        # enlarge it. This acknowledgement precedes frontend ARM and client GO.
        now = time.monotonic()
        if not now < action_deadline <= min(self._control.deadline, now + contract.action_bounds(selector)["timeout_seconds"]):
            raise IsolationUnavailable("Routing action deadline changed")
        reply = self.topology.ledger_request({"operation": "ARM", "selector": selector,
            "action_sequence": action_sequence, "action_digest": action_digest,
            "runtime_digests": self.identity["runtimes"][selector]})
        if reply["status"] != "ok":
            raise IsolationUnavailable("Routing aggregate authority refused action")
        return reply

    def finish_action(self, sequence, digest, output_bytes):
        reply = self.topology.ledger_request({"operation": "FINISH_ACTION", "action_sequence": sequence,
            "action_digest": digest, "output_bytes": output_bytes})
        if reply["status"] != "ok":
            raise IsolationUnavailable("Routing action did not settle")
        return self.snapshot()

    def snapshot(self):
        from .routing_ledger import validate_snapshot
        self._last_ledger = validate_snapshot(self.topology.ledger_snapshot(), selected=self.selection, identity=self.identity)
        return deepcopy(self._last_ledger)

    def close(self):
        if self._receipt is not None:
            return deepcopy(self._receipt)
        self._closed = True
        service_receipt = topology_receipt = None
        try:
            if self.services is not None:
                service_receipt = self.services.close()
        finally:
            if self.topology is not None:
                topology_receipt = self.topology.close()
        self._receipt = {"identity": self.identity, "status": "closed", "started": self._started,
            "services": service_receipt, "topology": topology_receipt}
        return deepcopy(self._receipt)


class ConfinedRoutingLab(RoutingLab):
    def __init__(self, config, closure):
        super().__init__(config["case"], config["session_id"], SessionLimits(**config["limits"]),
            execute=config["execute"], runtime=closure["routing_runtime"], identity=config["owned_lab"], closure=closure)
