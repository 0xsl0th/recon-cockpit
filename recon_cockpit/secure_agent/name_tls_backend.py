"""Name-bound actions behind independent audit, approval and admission witnesses."""

from dataclasses import asdict
import secrets
import time

from .authorized_execution import AuthorizedFixtureBackend
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces
from .models import Action, Policy, parse_action, parse_policy
from .session_limits import SessionLimits
from . import name_tls_contract as contract
from . import name_tls_native_runtime as runtime


class AuthorizedNameTLSBackend(AuthorizedFixtureBackend):
    name = "linux-authorized-owned-name-tls-v1"
    launch_mode = "owned_name_tls_v1"
    supported_tools = ("owned_name_dns_v1", "owned_name_http_v1", "owned_name_tls_v1")

    def __init__(self, policy, session_id, limits, lab, *, execute=False):
        from .name_tls_lab import NameTLSLab, ConfinedNameTLSLab
        super().__init__(policy, session_id, limits, execute=execute)
        if (type(lab) not in (NameTLSLab, ConfinedNameTLSLab)
                or lab.session_id != session_id or lab.limits != limits or lab.execute != execute):
            raise ValueError("name_tls_authority_changed")
        self.selection = contract.validate_selection(lab.selection)
        contract.validate_policy(policy.to_dict(), self.selection)
        contract.validate_limits(asdict(limits), self.selection)
        self._name_tls_runtime = runtime.validate_runtime(lab.runtime)
        self.lab = lab
        self._lab_identity = contract.validate_identity(lab.identity, selection=self.selection,
            session_id=session_id, runtime=self._name_tls_runtime)
        self._used = set()
        self._control = None
        self._closure = None

    def check_available(self, action=None):
        if not self._execute:
            raise IsolationUnavailable("Name/TLS execution is disabled")
        if action is not None:
            self._validate_proposal(action)
        LinuxFixtureBackend.check_available(self)
        self.lab._check_available()

    def _validate_proposal(self, action):
        slot = contract.action_selector(action, self.selection)
        if not contract.profile_allows(action, self.selection, session_id=self._session_id):
            raise IsolationUnavailable("Name/TLS action is outside the selected plan")
        parameters = action.parameters.to_dict()
        if any(parameters[key] != self._lab_identity[key] for key in
               ("owner_id", "owner_identity_sha256", "session_id", "runtime_identity_sha256")):
            raise IsolationUnavailable("Name/TLS proposal owner changed")
        if contract.operation(slot) == "dns":
            contract.validate_action(action, self.selection, self._lab_identity)
        return slot

    def run(self, action, policy, *, control=None):
        if type(self) is not ConfinedNameTLSBackend:
            raise IsolationUnavailable("Name/TLS requires the witnessed isolated launcher")
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Name/TLS operation already active")
        try:
            if (not self._execute or type(control) is not ExecutionControl
                    or control.clock is not time.monotonic or type(action) is not Action
                    or type(policy) is not Policy):
                raise IsolationUnavailable("Name/TLS execution control changed")
            control.check()
            action, policy = parse_action(action.to_dict()), parse_policy(policy.to_dict())
            slot = self._validate_proposal(action)
            if contract.operation(slot) != "dns":
                if not self.lab.started:
                    raise IsolationUnavailable("Name/TLS service requires a live DNS binding")
                contract.validate_action(action, self.selection, self._lab_identity,
                                         self.lab.snapshot()["binding"])
            if (slot in self._used or self._sequence >= 3
                    or policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest
                    or policy.evaluate(action).decision == "deny"
                    or self._control is not None and self._control is not control
                    or control.remaining() > 60
                    or self._output + action.parameters.max_output_bytes > self._limits.max_output_bytes
                    or self.lab.identity != self._lab_identity
                    or self.lab.runtime != self._name_tls_runtime
                    or self._closure["name_tls_runtime"] != self._name_tls_runtime):
                raise IsolationUnavailable("Name/TLS authority changed or exhausted")
            self._control = control
            self.check_available(action)
            self._sequence += 1
            before = self._output
            self._output += action.parameters.max_output_bytes
            self._used.add(slot)
            started = time.monotonic()
            self.lab.start(control)
            before_evidence = self.lab.evidence()
            if before_evidence["ledger"]["terminal"]:
                refusal = {"source": "owner_terminal", "reason": before_evidence["ledger"]["terminal_reason"]}
            else:
                armed = self.lab.arm_action(action)
                refusal = None if armed["status"] == "ok" else {"source": "owner_arm", "reason": armed["reason"]}
            if refusal is not None:
                evidence = self.lab.evidence()
                return {"status": "blocked", "backend": self.name, "results": [], "tool_observation": None,
                    "bytes_received": 0, "truncated": False,
                    "name_tls_refusal": {"action": action.to_dict(), "execution_sequence": self._sequence,
                        **refusal, "before": before_evidence},
                    "name_tls_ledger": evidence["ledger"], "name_tls_messages": evidence["messages"],
                    "name_tls_topology": self.lab.topology.identity, "owned_lab": {"identity": self._lab_identity},
                    "name_tls_topology_parent_observation": self.lab.topology.parent_observation,
                    "timing": {"owner_and_action_elapsed_ms": round((time.monotonic() - started) * 1000)}}
            launch = {"schema_version": "1", "mode": self.launch_mode, "execute": True,
                "session_id": self._session_id, "nonce": secrets.token_hex(32),
                "sequence": self._sequence, "action": action.to_dict(), "action_digest": action.digest,
                "policy": policy.to_dict(), "policy_digest": self._policy_digest,
                "limits": asdict(self._limits), "limits_digest": self._limits_digest,
                "deadline": control.deadline, "output_reserved_before": before,
                "output_reserved_after": self._output, "host_namespaces": _namespaces()}
            result = self.lab.services.run_action(action, launch)
            result["backend"] = self.name
            evidence = self.lab.evidence()
            result["name_tls_ledger"] = evidence["ledger"]
            result["name_tls_messages"] = evidence["messages"]
            result["name_tls_topology"] = self.lab.topology.identity
            result["name_tls_topology_parent_observation"] = self.lab.topology.parent_observation
            result["owned_lab"] = {"identity": self._lab_identity}
            result["timing"]["owner_and_action_elapsed_ms"] = round((time.monotonic() - started) * 1000)
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._lock.release()

    def close(self):
        return self.lab.close()


class ConfinedNameTLSBackend(AuthorizedNameTLSBackend):
    def __init__(self, config, closure):
        from .name_tls_lab import ConfinedNameTLSLab
        super().__init__(parse_policy(config["policy"]), config["session_id"],
            SessionLimits(**config["limits"]), ConfinedNameTLSLab(config, closure), execute=config["execute"])
        self._closure = closure

    def check_available(self, action=None):
        if not self._execute:
            raise IsolationUnavailable("Name/TLS execution is disabled")
        if action is not None:
            self._validate_proposal(action)
        self.lab._check_available()
