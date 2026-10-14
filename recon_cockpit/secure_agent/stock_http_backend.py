"""Single-action backend entered only behind the isolated witnessed launcher."""

import base64
from copy import deepcopy
from dataclasses import asdict
import hashlib
import secrets
import time

from .authorized_execution import AuthorizedFixtureBackend
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces
from .models import Action, Policy, parse_action, parse_policy
from .session_limits import SessionLimits
from . import stock_http_contract as contract


class AuthorizedStockHttpBackend(AuthorizedFixtureBackend):
    name = contract.BACKEND
    launch_mode = contract.PROFILE
    supported_tools = ("configurable_nmap_service_v1", "configurable_http_headers_v1")
    _closure = None

    def __init__(self, policy, session_id, limits, lab, *, execute=False):
        from .stock_http_lab import StockHttpLab
        super().__init__(policy, session_id, limits, execute=execute)
        if (not isinstance(lab, StockHttpLab) or lab.session_id != session_id
                or lab.limits != limits or lab.execute != execute):
            raise ValueError("invalid_stock_http_authority")
        self.selection = contract.validate_selection(lab.selection)
        contract.validate_policy(policy.to_dict(), self.selection)
        contract.validate_limits(asdict(limits), self.selection)
        self._stock_http_runtime = contract.validate_runtime(lab.runtime, self.selection)
        self.lab = lab
        self._lab_identity = contract.validate_identity(lab.identity, selection=self.selection,
            session_id=session_id, runtime=self._stock_http_runtime)

    def check_available(self, action=None):
        if not self._execute or (action is not None and not contract.profile_allows(action, self.selection)):
            raise IsolationUnavailable("Stock HTTP diagnostic profile denied")
        LinuxFixtureBackend.check_available(self)
        self.lab._check_available()

    def run(self, action, policy, *, control=None):
        # Host construction is metadata only. Execution is reachable only in the
        # launcher worker after durable audit, required approval and admission.
        if type(self) is not ConfinedStockHttpBackend:
            raise IsolationUnavailable("Stock HTTP diagnostic requires witnessed isolated launcher")
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Stock HTTP diagnostic is already running")
        try:
            if (not self._execute or type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(action) is not Action or type(policy) is not Policy):
                raise IsolationUnavailable("Invalid stock HTTP diagnostic control")
            control.check()
            action, policy = parse_action(action.to_dict()), parse_policy(policy.to_dict())
            if (not contract.profile_allows(action, self.selection) or self._sequence != 0 or self._output != 0
                    or policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or policy.evaluate(action).decision == "deny"
                    or self.lab.identity != self._lab_identity or self.lab.runtime != self._stock_http_runtime):
                raise IsolationUnavailable("Stock HTTP diagnostic authority changed or exhausted")
            if self._control is not None or control.remaining() > self._limits.max_runtime_seconds:
                raise IsolationUnavailable("Stock HTTP diagnostic control changed")
            self._control = control
            self.check_available(action)
            from .stock_http_client_runtime import run_stock_http_tool_owned
            from .configurable_parser_runtime import parse_isolated_tool_output
            runtime = contract.validate_runtime(self._stock_http_runtime, self.selection)
            if self._closure is None or contract.validate_runtime(self._closure["stock_http_runtime"], self.selection) != runtime:
                raise IsolationUnavailable("Stock HTTP runtime commitment changed")
            self._sequence, self._output = 1, action.parameters.max_output_bytes
            self.lab.start(control)
            launch = {"schema_version": "1", "mode": contract.PROFILE, "execute": True,
                "session_id": self._session_id, "nonce": secrets.token_hex(32), "sequence": 1,
                "action": action.to_dict(), "action_digest": action.digest,
                "policy": self._policy.to_dict(), "policy_digest": self._policy_digest,
                "limits": asdict(self._limits), "limits_digest": self._limits_digest,
                "deadline": control.deadline, "output_reserved_before": 0,
                "output_reserved_after": self._output, "host_namespaces": _namespaces()}
            result = run_stock_http_tool_owned(lab=self.lab,
                launch={"mode": contract.PROFILE, "launch": launch, "identity": self._lab_identity,
                        "namespaces": self.lab._lab_namespaces, "selection": deepcopy(self.selection), "runtime": runtime},
                control=control, closure=self._closure, manifest=runtime["client"])
            result.update(backend=self.name, tool_observation=None)
            if result["status"] == "succeeded" and result["truncated"] is False:
                try:
                    raw = (result["results"][0]["raw_response"] if self.selection["case"] not in ("O5", "O6")
                           else result["raw_output_base64"])
                    result["tool_observation"] = parse_isolated_tool_output(action.tool_id,
                        base64.b64decode(raw, validate=True),
                        base64.b64decode(result.get("raw_stderr_base64", ""), validate=True),
                        scope=contract.scope(self.selection), endpoint_id="http", control=control, closure=self._closure)
                except ValueError:
                    pass
            owner = self.lab.snapshot(control)
            result["stock_http_owner"] = owner
            result["owned_lab"] = {"identity": self._lab_identity,
                "connection_count": owner["connection_count"], "request_count": owner["request_count"],
                "owner_receipt_sha256": hashlib.sha256(contract.spec.encode(owner)).hexdigest()}
            result["stock_http_closure"] = self.lab.close()
            contract.validate_result_context(result, self._lab_identity, tool_id=action.tool_id,
                                             execution_status=result["status"])
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._lock.release()

    def close(self):
        return self.lab.close()


class ConfinedStockHttpBackend(AuthorizedStockHttpBackend):
    def __init__(self, config, closure):
        from .stock_http_lab import ConfinedStockHttpLab
        self._closure = closure
        super().__init__(parse_policy(config["policy"]), config["session_id"], SessionLimits(**config["limits"]),
                         ConfinedStockHttpLab(config, closure), execute=config["execute"])

    def check_available(self, action=None):
        if not self._execute or (action is not None and not contract.profile_allows(action, self.selection)):
            raise IsolationUnavailable("Confined stock HTTP diagnostic denied")
        self.lab._check_available()
