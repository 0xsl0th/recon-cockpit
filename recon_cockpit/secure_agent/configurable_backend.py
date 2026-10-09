"""Four finite launches bound to an immutable two-endpoint owned scope."""

import base64
from dataclasses import asdict
from copy import deepcopy
import secrets
import time

from .authorized_execution import AuthorizedFixtureBackend
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces
from .models import Action, Policy, parse_action, parse_policy
from .session_limits import SessionLimits
from . import configurable_contract as contract
from .configurable_scope import validate_scope, scope_digest
from .configurable_lab import ConfigurableLab


class AuthorizedConfigurableBackend(AuthorizedFixtureBackend):
    name = contract.BACKEND
    launch_mode = contract.PROFILE
    supported_tools = tuple(dict.fromkeys(contract.TOOL_IDS))
    _closure = None
    _configurable_manifests = None

    def __init__(self, policy, session_id, limits, lab, *, execute=False):
        super().__init__(policy, session_id, limits, execute=execute)
        if (not isinstance(lab, ConfigurableLab) or lab.session_id != session_id or lab.limits != limits
                or lab.execute != execute or any(asdict(limits)[key] > cap for key, cap in contract.LIMITS.items())):
            raise ValueError("invalid_configurable_authority")
        self.lab, self._lab_identity = lab, lab.identity
        self.scope = validate_scope(self._lab_identity["scope"])
        self._scope_digest = scope_digest(self.scope)
        self._previous_context = None
        self._completed_step = 0

    def check_available(self, action=None):
        if not self._execute or (action is not None and not contract.profile_allows(action, self.scope)):
            raise IsolationUnavailable("Configurable owned profile denied")
        LinuxFixtureBackend.check_available(self)
        for name in ("http", "ssh"):
            self.lab.endpoint_lab(name)._check_available()

    def run(self, action, policy, *, control=None):
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Configurable authority already running")
        try:
            if (not self._execute or type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(action) is not Action or type(policy) is not Policy):
                raise IsolationUnavailable("Invalid configurable authority control")
            control.check()
            action, policy = parse_action(action.to_dict()), parse_policy(policy.to_dict())
            step = contract.step_for_action(self.scope, action)
            if (scope_digest(self.scope) != self._scope_digest or self.lab.identity != self._lab_identity
                    or policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or policy.evaluate(action).decision == "deny"
                    or step != self._sequence + 1 or self._completed_step != self._sequence
                    or self._output != contract.OUTPUT_RESERVATIONS[self._sequence]):
                raise IsolationUnavailable("Configurable scope, policy, or predecessor changed")
            if self._control is None:
                if control.remaining() > self._limits.max_runtime_seconds:
                    raise IsolationUnavailable("Configurable deadline exceeds authority")
                self._control = control
            elif control is not self._control:
                raise IsolationUnavailable("Configurable authority cannot be replaced")
            if (step > self._limits.max_steps
                    or contract.OUTPUT_RESERVATIONS[step] > self._limits.max_output_bytes):
                raise IsolationUnavailable("Configurable authority exhausted")
            self.check_available(action)
            from .configurable_runtime import validate_manifests, run_configurable_tool_owned, project_closure
            from .configurable_parser_runtime import parse_isolated_tool_output

            manifests = validate_manifests(self._configurable_manifests)
            if self._closure is not None and validate_manifests(self._closure["configurable_runtime"]) != manifests:
                raise IsolationUnavailable("Configurable runtime pin changed")
            self._sequence, self._output = step, contract.OUTPUT_RESERVATIONS[step]
            endpoint_id = contract.ENDPOINTS[step - 1]
            lab = self.lab.endpoint_lab(endpoint_id)
            lab.start(control)
            launch = {"schema_version": "1", "mode": contract.PROFILE, "execute": True,
                "session_id": self._session_id, "nonce": secrets.token_hex(32), "sequence": step,
                "action": action.to_dict(), "action_digest": action.digest,
                "policy": self._policy.to_dict(), "policy_digest": self._policy_digest,
                "limits": asdict(self._limits), "limits_digest": self._limits_digest,
                "deadline": control.deadline, "output_reserved_before": contract.OUTPUT_RESERVATIONS[step - 1],
                "output_reserved_after": self._output, "host_namespaces": _namespaces()}
            result = run_configurable_tool_owned(lab=lab, launch={"mode": contract.PROFILE,
                "launch": launch, "identity": lab.identity, "namespaces": lab._lab_namespaces,
                "scope": deepcopy(self.scope), "endpoint_id": endpoint_id}, control=control,
                closure=None if self._closure is None else project_closure(self._closure, action.tool_id),
                manifest=manifests.get(action.tool_id))
            result.update(backend=self.name, scope_step=step, scope_sha256=self._scope_digest, tool_observation=None)
            if result["status"] == "succeeded" and result["truncated"] is False:
                try:
                    raw = (result["results"][0]["raw_response"] if action.tool_id == contract.HEADERS
                           else result["raw_output_base64"])
                    result["tool_observation"] = parse_isolated_tool_output(action.tool_id,
                        base64.b64decode(raw, validate=True),
                        base64.b64decode(result.get("raw_stderr_base64", ""), validate=True),
                        scope=self.scope, endpoint_id=endpoint_id, control=control, closure=self._closure)
                except ValueError:
                    pass
            contexts = (deepcopy(self._previous_context["endpoints"]) if self._previous_context else
                {name: {"identity": self._lab_identity["endpoints"][name], "connection_count": 0,
                        "request_count": 0} for name in ("http", "ssh")})
            previous = contexts[endpoint_id]
            settled = result["tool_observation"] is not None
            counts = lab.snapshot(control,
                minimum_connections=previous["connection_count"] + ((2 if step in (1, 3) else 1) if settled else 0),
                minimum_requests=previous["request_count"] + int(settled))
            contexts[endpoint_id] = {"identity": lab.identity, **counts}
            result["owned_lab"] = {"identity": self._lab_identity, "step": step, "endpoints": contexts}
            self._previous_context = contract.validate_result_context(result, self._lab_identity,
                previous=self._previous_context, tool_id=action.tool_id, execution_status=result["status"])
            observation = contract.observation(self.scope, step, result)
            if (observation["classification"] == "observed" and (step not in (1, 3)
                    or contract.predecessor_gate(self.scope, step, observation))):
                self._completed_step = step
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._lock.release()

    def close(self):
        return self.lab.close()


class ConfinedConfigurableBackend(AuthorizedConfigurableBackend):
    def __init__(self, config, closure):
        from .configurable_lab import ConfinedConfigurableLab
        from .configurable_runtime import validate_manifests
        self._closure = closure
        self._configurable_manifests = validate_manifests(closure["configurable_runtime"])
        super().__init__(parse_policy(config["policy"]), config["session_id"], SessionLimits(**config["limits"]),
                         ConfinedConfigurableLab(config, closure), execute=config["execute"])

    def check_available(self, action=None):
        if not self._execute or (action is not None and not contract.profile_allows(action, self.scope)):
            raise IsolationUnavailable("Confined configurable profile denied")
        for name in ("http", "ssh"):
            self.lab.endpoint_lab(name)._check_available()
