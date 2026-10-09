"""One immutable owner and authority for three separately confined capabilities."""

import base64
from dataclasses import asdict
from pathlib import Path
import secrets
import threading
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces, _trusted_program
from .models import Action, Policy, parse_action, parse_policy
from .owned_lab import AuthorizedOwnedLabBackend
from .service_web_contract import (BACKEND, PROFILE, TOOL_IDS, OUTPUT_RESERVATIONS, REQUEST_TOTALS,
                                    action_step, parse_observation, predecessor_gate, profile_allows,
                                    validate_result_context)
from .service_web_lab import ServiceWebLab
from .service_web_lab_contract import validate_identity
from .service_web_runtime import validate_manifests, project_closure
from .session_limits import SessionLimits


class AuthorizedServiceWebBackend(AuthorizedOwnedLabBackend):
    name = BACKEND
    supported_tools = TOOL_IDS
    launch_mode = _envelope_mode = PROFILE
    _executor_mode = "service_web_owned"
    _http_tools = (TOOL_IDS[2],)
    _closure = None
    _service_web_manifests = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._operation_lock = threading.Lock()
        self._completed_step = 0

    def _accept_lab(self, lab):
        return type(lab) is ServiceWebLab

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity["scenario"])):
            raise IsolationUnavailable("Owned service web profile denied")
        LinuxFixtureBackend.check_available(self, action)
        self.lab._check_available()

    def _validate_result_context(self, result, *, action):
        return validate_result_context(result, self._lab_identity, previous=self._previous_context,
                                       tool_id=action.tool_id, execution_status=result["status"])

    def _command(self, stdlib, files, nonce, context_digest):
        argv = super()._command(stdlib, files, nonce, context_digest)
        mounts = []
        for name in ("service_web_execution", "service_web_contract", "service_web_lab_contract",
                     "http_headers_operation", "http_headers_fixture", "service_web_fixture", "web_tools_fixture", "network_tools_fixture"):
            mounts += ["--ro-bind", str(Path(__file__).with_name(name + ".py").resolve()),
                       "/app/recon_cockpit/secure_agent/" + name + ".py"]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        return argv

    def run(self, action, policy, *, control=None):
        if not self._operation_lock.acquire(blocking=False):
            raise IsolationUnavailable("Service web executor is already running")
        try:
            if (type(action) is not Action or not profile_allows(action, self._lab_identity["scenario"])
                    or action_step(action.tool_id) != self._sequence + 1
                    or self._completed_step != self._sequence
                    or self._output != OUTPUT_RESERVATIONS[self._sequence]):
                raise IsolationUnavailable("Service web predecessor or ordered action changed")
            if action.tool_id == TOOL_IDS[2]:
                result = AuthorizedOwnedLabBackend.run(self, action, policy, control=control)
                result["http_headers"] = None
                if result["status"] == "succeeded" and result["truncated"] is False:
                    from .http_headers_parser_runtime import parse_isolated_headers
                    try:
                        result["http_headers"] = parse_isolated_headers(
                            base64.b64decode(result["results"][0]["raw_response"], validate=True),
                            control=control, closure=self._closure)
                    except ValueError:
                        pass
            else:
                result = self._run_native(action, policy, control=control)
            if action.tool_id != TOOL_IDS[2] and predecessor_gate(self._sequence,
                    parse_observation(action.to_dict(), result, execution_status=result["status"])):
                self._completed_step = self._sequence
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._operation_lock.release()

    def _run_native(self, action, policy, *, control):
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Service web authority is already running")
        try:
            if (not self._execute or type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(policy) is not Policy):
                raise IsolationUnavailable("Invalid service web authority context")
            control.check()
            action, policy = parse_action(action.to_dict()), parse_policy(policy.to_dict())
            if (policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or self._policy.evaluate(action).decision == "deny"
                    or self.lab.identity != self._lab_identity):
                raise IsolationUnavailable("Service web authority changed")
            if self._control is None:
                if control.remaining() > self._limits.max_runtime_seconds:
                    raise IsolationUnavailable("Service web deadline exceeds authority")
                self._control = control
            elif control is not self._control:
                raise IsolationUnavailable("Service web authority cannot be replaced")
            if (self._sequence >= self._limits.max_steps
                    or self._output + action.parameters.max_output_bytes > self._limits.max_output_bytes):
                raise IsolationUnavailable("Service web authority budget exhausted")
            self.check_available(action)
            manifests = validate_manifests(self._service_web_manifests)
            manifest = manifests[action.tool_id]
            if self._closure is not None and validate_manifests(self._closure["service_web_runtime"]) != manifests:
                raise IsolationUnavailable("Service web runtime pin changed")
            before = self._output
            self._sequence += 1
            self._output += action.parameters.max_output_bytes
            self.lab.start(control)
            launch = {"schema_version": "1", "mode": self._executor_mode, "execute": True,
                "session_id": self._session_id, "nonce": secrets.token_hex(32), "sequence": self._sequence,
                "action": action.to_dict(), "action_digest": action.digest,
                "policy": self._policy.to_dict(), "policy_digest": self._policy_digest,
                "limits": asdict(self._limits), "limits_digest": self._limits_digest,
                "deadline": control.deadline, "output_reserved_before": before,
                "output_reserved_after": self._output, "host_namespaces": _namespaces()}
            closure = None if self._closure is None else project_closure(self._closure, action.tool_id)
            if action.tool_id == TOOL_IDS[0]:
                from .network_tools_runtime import run_network_tool_owned as runner
                from .network_tools_parser_runtime import parse_isolated_tool_output as parser
            else:
                from .web_tools_runtime import run_web_tool_owned as runner
                from .web_tools_parser_runtime import parse_isolated_tool_output as parser
            result = runner(lab=self.lab,
                launch={"mode": self._envelope_mode, "launch": launch, "identity": self._lab_identity,
                        "namespaces": self.lab._lab_namespaces}, control=control, closure=closure, manifest=manifest)
            result["backend"], result["tool_observation"] = self.name, None
            if result["status"] == "succeeded" and result["truncated"] is False:
                try:
                    arguments = [action.tool_id, base64.b64decode(result["raw_output_base64"], validate=True)]
                    if action.tool_id == TOOL_IDS[0]:
                        arguments.append(base64.b64decode(result["raw_stderr_base64"], validate=True))
                    result["tool_observation"] = parser(*arguments, control=control, closure=self._closure)
                except ValueError:
                    pass
            settled = result["tool_observation"] is not None
            previous = self._previous_context or {"connection_count": 0, "request_count": 0}
            minimum_requests = REQUEST_TOTALS[self._sequence] if settled else previous["request_count"]
            minimum_connections = (minimum_requests + 1 if settled else previous["connection_count"])
            counts = self.lab.snapshot(control, minimum_connections=minimum_connections,
                                       minimum_requests=minimum_requests)
            result["owned_lab"] = {"identity": self._lab_identity, **counts}
            self._previous_context = self._validate_result_context(result, action=action)
            control.check()
            return result
        finally:
            self._lock.release()


class ConfinedServiceWebLab(ServiceWebLab):
    def __init__(self, config, closure):
        super().__init__(config["case"], config["session_id"], SessionLimits(**config["limits"]),
                         execute=config["execute"])
        self._identity = validate_identity(config["owned_lab"], case=config["case"])
        self._closure = closure

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=True)

    def _check_available(self):
        for name in ("bwrap", "nft", "nsenter"):
            _trusted_program(name)


class ConfinedServiceWebBackend(AuthorizedServiceWebBackend):
    def __init__(self, config, closure):
        self._config, self._closure = config, closure
        self._service_web_manifests = validate_manifests(closure["service_web_runtime"])
        lab = ConfinedServiceWebLab(config, closure)
        super().__init__(parse_policy(config["policy"]), config["session_id"], SessionLimits(**config["limits"]),
                         lab, execute=config["execute"])

    def _accept_lab(self, lab):
        return type(lab) is ConfinedServiceWebLab

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=False)

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity["scenario"])):
            raise IsolationUnavailable("Confined service web profile denied")
        self.lab._check_available()
