"""Single-action authority adapter for reviewed network metadata tool profiles."""

import base64
from dataclasses import asdict
import secrets
import time
import re

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces, _trusted_program
from .models import Action, Policy, parse_action, parse_policy
from .owned_lab import AuthorizedOwnedLabBackend
from .session_limits import SessionLimits
from .network_tools_lab import NetworkToolsLab
from .network_tools_lab_contract import BACKEND, validate_context, validate_identity
from .network_tools_tls_posture_spec import TOOL_VERSIONS as TLS_POSTURE_TOOLS


def _tls_parser_closure(closure):
    """Project the validated launcher runtime to a networkless Python parser."""
    if closure is None:
        return None
    if (type(closure) is not dict or type(closure.get("stdlib")) is not str
            or type(closure.get("files")) is not list):
        raise IsolationUnavailable("TLS posture parser closure is invalid")
    libraries = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
    files = []
    for path in closure["files"]:
        if type(path) is not str:
            raise IsolationUnavailable("TLS posture parser closure is invalid")
        if path == "/usr/bin/python3" or libraries.fullmatch(path):
            files.append(path)
        elif path not in {"/usr/bin/bwrap", "/usr/bin/nsenter", "/usr/sbin/nft"}:
            raise IsolationUnavailable("TLS posture parser closure contains an unreviewed program")
    return {"stdlib": closure["stdlib"], "files": files}


class AuthorizedNetworkToolsBackend(AuthorizedOwnedLabBackend):
    name = BACKEND
    supported_tools = ("dig_dns_query_v1", "openssl_tls_handshake_v1", "ssh_host_keys_v1", "ldap_rootdse_v1", "smb_share_list_v1",
                       "rpcinfo_dump_v1", "showmount_exports_v1", "curl_ftp_list_v1", "curl_smtp_capabilities_v1",
                       "curl_docker_ping_v1", "curl_docker_version_v1", "curl_winrm_metadata_v1", "nmap_service_identify_v1", "kerbrute_userenum_v1",
                       "redis_server_info_v1", "snmp_system_get_v1",
                       "postgresql_tls_handshake_v1", "mysql_tls_handshake_v1", "smtp_starttls_handshake_v1", "ldap_starttls_handshake_v1", "ftp_starttls_handshake_v1", "whatweb_http_fingerprint_v1", "dig_dns_mx_v1", "dig_dns_srv_v1", "dig_dns_nsid_v1", "dig_dns_axfr_v1", "curl_http_options_v1", "snmp_interface_next_v1", "ssh_transport_algorithms_v1", "openssl_peer_certificate_v1", "nuclei_directory_listing_v1", "nuclei_git_head_v1", "rdp_initial_negotiation_v1", "smb2_negotiate_metadata_v1")
    launch_mode = _envelope_mode = "owned_network_tools_lab"
    supported_tools += tuple(TLS_POSTURE_TOOLS) + ("ssh_transport_policy_v1",)
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
            if action.tool_id in TLS_POSTURE_TOOLS:
                return self._finish_tls_posture(result, action, control, runtime_closure)
            nuclei_counts = (self.lab.snapshot(control) if action.tool_id in ("nuclei_directory_listing_v1", "nuclei_git_head_v1") else None)
            if result["status"] == "succeeded" and result["truncated"] is False:
                from .network_tools_parser_runtime import parse_isolated_tool_output
                try:
                    extra = {}
                    if nuclei_counts is not None:
                        from .network_tools_lab_contract import decode_owner_response
                        extra["owner_response"] = decode_owner_response(nuclei_counts["owner_response"], require_complete=True)
                    result["tool_observation"] = parse_isolated_tool_output(action.tool_id,
                        base64.b64decode(result["raw_output_base64"], validate=True),
                        base64.b64decode(result["raw_stderr_base64"], validate=True),
                        control=control, closure=runtime_closure, **extra)
                except ValueError:
                    # Successful process exit alone cannot establish useful work.
                    result["tool_observation"] = None
            expected = 2 if self._lab_identity["scenario"].startswith("kerberos-") else 1
            minimum = expected if result["tool_observation"] is not None else 0
            connections = minimum * (2 if action.tool_id in ("curl_ftp_list_v1", "nmap_service_identify_v1") else 1)
            counts = (nuclei_counts if nuclei_counts is not None else
                      self.lab.snapshot(control, minimum_connections=connections, minimum_requests=minimum))
            context = validate_context({"identity": self._lab_identity, **counts}, self._lab_identity)
            from .network_tools_fixture import DATABASE_TLS_CASES, DATABASE_TLS_SUCCESS_CASES
            if (context["request_count"] > expected
                    or (result["tool_observation"] is not None and context["request_count"] != expected)
                    or (self._lab_identity["scenario"] in DATABASE_TLS_CASES
                        and self._lab_identity["scenario"] not in DATABASE_TLS_SUCCESS_CASES
                        and context["request_count"] != 0)
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

    def _finish_tls_posture(self, result, action, control, runtime_closure):
        """Keep process status separate from corroborated protocol observations."""
        from .network_tools_tls_posture_receipt import decode_owner_receipt, receipt_counter_context, validate_owner_selection
        from .network_tools_tls_posture_parser_runtime import parse_isolated_tls_posture
        from .network_tools_contract import validate_result_context

        counts = self.lab.snapshot(control)
        if type(counts) is not dict or set(counts) != {"connection_count", "request_count", "tls_posture_owner"}:
            raise IsolationUnavailable("TLS posture owner receipt is missing")
        receipt = counts["tls_posture_owner"]
        raw = decode_owner_receipt(receipt)
        validate_owner_selection(raw, self._lab_identity["scenario"])
        counters = receipt_counter_context(raw)
        if any(type(counts[key]) is not int or counts[key] != counters[key] for key in counters):
            raise IsolationUnavailable("TLS posture owner counters changed")
        context = validate_context({"identity": self._lab_identity, **counters,
            "tls_posture_owner_sha256": receipt["sha256"]}, self._lab_identity)
        result["tls_posture_owner"] = receipt
        result["owned_lab"] = context
        if (result["status"] in {"succeeded", "failed"} and result["truncated"] is False
                and result["provenance"]["stop_reason"] is None):
            try:
                result["tool_observation"] = parse_isolated_tls_posture(action.tool_id,
                    base64.b64decode(result["raw_output_base64"], validate=True),
                    base64.b64decode(result["raw_stderr_base64"], validate=True),
                    owner_raw=raw, exit_code=result["provenance"]["exit_code"],
                    stop_reason=result["provenance"]["stop_reason"], truncated=result["truncated"],
                    control=control, closure=_tls_parser_closure(runtime_closure))
            except ValueError:
                result["tool_observation"] = None
        self._previous_context = validate_result_context(result, self._lab_identity,
            previous=self._previous_context, tool_id=action.tool_id, execution_status=result["status"])
        control.check()
        return result


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
