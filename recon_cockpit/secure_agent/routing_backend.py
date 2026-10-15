"""Routed actions reachable only behind audit, approval and admission witnesses."""

from copy import deepcopy
from dataclasses import asdict
import secrets
import time

from .authorized_execution import AuthorizedFixtureBackend
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces
from .models import Action, Policy, parse_action, parse_policy
from .session_limits import SessionLimits
from . import routing_contract as contract


class AuthorizedRoutingBackend(AuthorizedFixtureBackend):
    name = contract.BACKEND
    launch_mode = contract.PROFILE
    supported_tools = ("configurable_nmap_service_v1", "configurable_http_headers_v1", "configurable_ssh_host_keys_v1")
    _closure = None

    def __init__(self, policy, session_id, limits, lab, *, execute=False):
        from .routing_lab import RoutingLab
        super().__init__(policy, session_id, limits, execute=execute)
        if (not isinstance(lab, RoutingLab) or lab.session_id != session_id
                or lab.limits != limits or lab.execute != execute):
            raise ValueError("invalid_routing_authority")
        self.selection = contract.validate_selection(lab.selection)
        contract.validate_policy(policy.to_dict(), self.selection)
        contract.validate_limits(asdict(limits), self.selection)
        self._routing_runtime = contract.validate_runtime(lab.runtime, self.selection)
        self.lab = lab
        self._lab_identity = contract.validate_identity(lab.identity, selection=self.selection,
            session_id=session_id, runtime=self._routing_runtime)
        self._used = set()
        self._previous = None

    def check_available(self, action=None):
        if not self._execute or action is not None and not contract.profile_allows(action, self.selection):
            raise IsolationUnavailable("Disconnected routing profile denied")
        LinuxFixtureBackend.check_available(self)
        self.lab._check_available()

    def run(self, action, policy, *, control=None):
        if type(self) is not ConfinedRoutingBackend:
            raise IsolationUnavailable("Routing requires witnessed isolated launcher")
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Routing action already running")
        try:
            if (not self._execute or type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(action) is not Action or type(policy) is not Policy):
                raise IsolationUnavailable("Invalid routing execution control")
            control.check()
            action, policy = parse_action(action.to_dict()), parse_policy(policy.to_dict())
            selector = contract.action_selector(action, self.selection)
            if (selector in self._used or self._sequence >= 4
                    or self._output + action.parameters.max_output_bytes > self._limits.max_output_bytes
                    or policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or policy.evaluate(action).decision == "deny"
                    or self.lab.identity != self._lab_identity or self.lab.runtime != self._routing_runtime
                    or self._control is not None and self._control is not control
                    or control.remaining() > self._limits.max_runtime_seconds):
                raise IsolationUnavailable("Routing authority changed or exhausted")
            self._control = control
            self.check_available(action)
            if self._closure is None or contract.validate_runtime(self._closure["routing_runtime"], self.selection) != self._routing_runtime:
                raise IsolationUnavailable("Routing runtime changed")
            before = self._output
            self._sequence += 1
            self._output += action.parameters.max_output_bytes
            self._used.add(selector)
            startup = time.monotonic()
            self.lab.start(control)
            startup_ms = round((time.monotonic() - startup) * 1000)
            launch = {"schema_version": "1", "mode": contract.PROFILE, "execute": True,
                "session_id": self._session_id, "nonce": secrets.token_hex(32), "sequence": self._sequence,
                "action": action.to_dict(), "action_digest": action.digest,
                "policy": self._policy.to_dict(), "policy_digest": self._policy_digest,
                "limits": asdict(self._limits), "limits_digest": self._limits_digest,
                "deadline": control.deadline, "output_reserved_before": before,
                "output_reserved_after": self._output, "host_namespaces": _namespaces()}
            result = self.lab.services.run_action(selector, launch)
            result["backend"] = self.name
            ledger = self.lab.finish_action(self._sequence, action.digest, result["bytes_received"])
            result["routing_topology"] = self.lab.topology.identity
            result["routing_ledger"] = ledger
            result["owned_lab"] = {"identity": self._lab_identity,
                "connection_count": ledger["counters"]["connections"],
                "request_count": ledger["counters"]["http_requests"] + ledger["counters"]["kex_exchanges"],
                "owner_receipt_sha256": contract.digest({key: result[key] for key in
                    ("routing_topology", "routing_ledger", "routing_service")})}
            result["timing"]["owner_startup_ms"] = result["timing"].get("owner_startup_ms", 0) + startup_ms
            from .routing_context import validate_result_context
            self._previous = validate_result_context(result, self._lab_identity, previous=self._previous,
                tool_id=action.tool_id, execution_status=result["status"])
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._lock.release()

    def close(self):
        return self.lab.close()


class ConfinedRoutingBackend(AuthorizedRoutingBackend):
    def __init__(self, config, closure):
        from .routing_lab import ConfinedRoutingLab
        self._closure = closure
        super().__init__(parse_policy(config["policy"]), config["session_id"], SessionLimits(**config["limits"]),
            ConfinedRoutingLab(config, closure), execute=config["execute"])

    def check_available(self, action=None):
        if not self._execute or action is not None and not contract.profile_allows(action, self.selection):
            raise IsolationUnavailable("Confined routing denied")
        self.lab._check_available()
