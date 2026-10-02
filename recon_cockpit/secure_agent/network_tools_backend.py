"""Single-action authority adapter for reviewed network metadata tool profiles."""

import base64
from dataclasses import asdict
import secrets
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces, _trusted_program
from .models import Action, Policy, parse_action, parse_policy
from .owned_lab import AuthorizedOwnedLabBackend
from .session_limits import SessionLimits
from .network_tools_lab import NetworkToolsLab
from .network_tools_lab_contract import BACKEND, validate_context, validate_identity


class AuthorizedNetworkToolsBackend(AuthorizedOwnedLabBackend):
    name = BACKEND
    supported_tools = ("dig_dns_query_v1", "openssl_tls_handshake_v1", "ssh_host_keys_v1", "ldap_rootdse_v1", "smb_share_list_v1",
                       "rpcinfo_dump_v1", "showmount_exports_v1", "curl_ftp_list_v1", "curl_smtp_capabilities_v1",
                       "curl_docker_ping_v1", "curl_docker_version_v1", "curl_winrm_metadata_v1", "nmap_service_identify_v1")
    launch_mode = _envelope_mode = "owned_network_tools_lab"
    _executor_mode = "network_tools_owned"
    _closure = None
    _network_tools_manifest = None

    def _accept_lab(self, lab):
        return type(lab) is NetworkToolsLab

    def check_available(self, action=None):
        from .network_tools_contract import profile_allows
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity["scenario"])):
            raise IsolationUnavailable("Owned network tool profile denied")
        LinuxFixtureBackend.check_available(self, action)
        self.lab._check_available()

    def run(self, action, policy, *, control=None):
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Network tool executor authority is already running")
        try:
            if (not self._execute or type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(action) is not Action or type(policy) is not Policy):
                raise IsolationUnavailable("Invalid network tool authority context")
            control.check()
            action, policy = parse_action(action.to_dict()), parse_policy(policy.to_dict())
            if (policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or self._policy.evaluate(action).decision == "deny"
                    or self.lab.identity != self._lab_identity):
                raise IsolationUnavailable("Network tool authority changed")
            if self._control is None:
                if control.remaining() > self._limits.max_runtime_seconds:
                    raise IsolationUnavailable("Network tool deadline exceeds authority")
                self._control = control
            elif control is not self._control:
                raise IsolationUnavailable("Network tool authority cannot be replaced")
            if (self._sequence >= self._limits.max_steps
                    or self._output + action.parameters.max_output_bytes > self._limits.max_output_bytes):
                raise IsolationUnavailable("Network tool authority budget exhausted")
            self.check_available(action)
            from .network_tools_runtime import run_network_tool_owned, validate_manifest
            manifest = validate_manifest(self._network_tools_manifest, tool_id=action.tool_id)
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
            runtime_closure = self._closure
            if runtime_closure is not None and runtime_closure["network_tools_runtime"] != manifest:
                raise IsolationUnavailable("Network tool runtime pin changed")
            result = run_network_tool_owned(lab=self.lab,
                launch={"mode": self._envelope_mode, "launch": launch, "identity": self._lab_identity,
                        "namespaces": self.lab._lab_namespaces}, control=control, closure=runtime_closure,
                manifest=manifest)
            result["backend"] = self.name
            result["tool_observation"] = None
            if result["status"] == "succeeded" and result["truncated"] is False:
                from .network_tools_parser_runtime import parse_isolated_tool_output
                try:
                    result["tool_observation"] = parse_isolated_tool_output(action.tool_id,
                        base64.b64decode(result["raw_output_base64"], validate=True),
                        base64.b64decode(result["raw_stderr_base64"], validate=True),
                        control=control, closure=runtime_closure)
                except ValueError:
                    # Successful process exit alone cannot establish useful work.
                    result["tool_observation"] = None
            expected = 1
            minimum = expected if result["tool_observation"] is not None else 0
            connections = minimum * (2 if self._lab_identity["scenario"].startswith(("ftp-", "nmap-service-")) else 1)
            counts = self.lab.snapshot(control, minimum_connections=connections, minimum_requests=minimum)
            context = validate_context({"identity": self._lab_identity, **counts}, self._lab_identity)
            if (context["request_count"] > expected
                    or (result["tool_observation"] is not None and context["request_count"] != expected)
                    or (self._lab_identity["scenario"] in {"openssl-untrusted", "openssl-malformed", "openssl-stalled",
                                                          "ssh-malformed", "ssh-stalled", "ftp-denied",
                                                          "ftp-passive-ip", "ftp-passive-port"}
                        and context["request_count"] != 0)):
                raise IsolationUnavailable("Network tool request count mismatched its fixed profile")
            result["owned_lab"] = context
            from .network_tools_contract import validate_result_context
            self._previous_context = validate_result_context(result, self._lab_identity,
                previous=self._previous_context, tool_id=action.tool_id, execution_status=result["status"])
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._lock.release()


class ConfinedNetworkToolsLab(NetworkToolsLab):
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


class ConfinedNetworkToolsBackend(AuthorizedNetworkToolsBackend):
    def __init__(self, config, closure):
        self._config, self._closure = config, closure
        self._network_tools_manifest = closure["network_tools_runtime"]
        lab = ConfinedNetworkToolsLab(config, closure)
        super().__init__(parse_policy(config["policy"]), config["session_id"], SessionLimits(**config["limits"]),
                         lab, execute=config["execute"])

    def _accept_lab(self, lab):
        return type(lab) is ConfinedNetworkToolsLab

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=False)

    def check_available(self, action=None):
        from .network_tools_contract import profile_allows
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity["scenario"])):
            raise IsolationUnavailable("Confined network tool profile denied")
        self.lab._check_available()
