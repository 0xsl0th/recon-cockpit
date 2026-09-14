"""Host authority adapter for fresh, independently checked fixture executors.

Only trusted Controller code calls run(), after policy, required human grant,
and durable execution_started. This host adapter remains part of the authority
TCB; its pipe/argv launch binding does not defend against its own compromise.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import secrets
import threading
import time
from types import MappingProxyType
from uuid import UUID

from .execution import ExecutionControl
from .executor_worker import MAX_LAUNCH_BYTES, encode
from .isolation import (IsolationUnavailable, LinuxFixtureBackend, _capture_bounded,
                        _namespaces, _runtime_files, _trusted_program)
from .models import Action, Policy, parse_action, parse_policy
from .session import SessionLimits


class AuthorizedFixtureBackend(LinuxFixtureBackend):
    """One fixed authority session; launch allowances are reserved without refunds."""

    name = "linux-authorized-fixture-executor-v1"

    def __init__(self, policy, session_id, limits, *, execute=False):
        if type(policy) is not Policy or type(limits) is not SessionLimits or type(execute) is not bool:
            raise ValueError("invalid_executor_configuration")
        if type(session_id) is not str or str(UUID(session_id)) != session_id:
            raise ValueError("invalid_executor_session")
        super().__init__(verify_boundary=True)
        self._policy = parse_policy(policy.to_dict())
        self._policy_digest = self._policy.digest
        self._limits = SessionLimits(**asdict(limits))
        self._limits_digest = self._limits.digest
        self._session_id = session_id
        self._execute = execute
        self._lock = threading.Lock()
        self._sequence = 0
        self._output = 0
        self._control = None

    @property
    def snapshot(self):
        return MappingProxyType({"executions_reserved": self._sequence, "output_bytes_reserved": self._output})

    def check_available(self, action=None):
        if not self._execute:
            raise IsolationUnavailable("Executor authority is fixed to dry-run mode")
        super().check_available(action)

    def _command(self, stdlib, files, nonce, context_digest):
        argv = super()._command(stdlib, files)
        directory = Path(__file__).parent
        mounts = []
        for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
            mounts.extend(("--ro-bind", str((directory / "__init__.py").resolve()), destination))
        mounts.extend(("--ro-bind", str((directory / "models.py").resolve()),
                       "/app/recon_cockpit/secure_agent/models.py",
                       "--ro-bind", str((directory / "executor_worker.py").resolve()), "/app/executor_worker.py"))
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-4:] = ["/usr/bin/python3", "-I", "-S", "/app/executor_worker.py", nonce, context_digest]
        return argv

    def run(self, action, policy, *, control=None):
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Executor authority is already running")
        try:
            if (not self._execute or type(control) is not ExecutionControl
                    or control.clock is not time.monotonic or type(action) is not Action or type(policy) is not Policy):
                raise IsolationUnavailable("Invalid executor authority context")
            control.check()
            action = parse_action(action.to_dict())
            supplied_policy = parse_policy(policy.to_dict())
            if (supplied_policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or self._policy.evaluate(action).decision == "deny"):
                raise IsolationUnavailable("Executor action or policy does not match authority")
            if self._control is None:
                if control.remaining() > self._limits.max_runtime_seconds:
                    raise IsolationUnavailable("Executor deadline exceeds fixed authority limits")
                self._control = control
            elif control is not self._control:
                raise IsolationUnavailable("Executor session control cannot be replaced")
            if (self._sequence >= self._limits.max_steps
                    or self._output + action.parameters.max_output_bytes > self._limits.max_output_bytes):
                raise IsolationUnavailable("Executor authority budget exhausted")
            self.check_available(action)
            before = self._output
            self._sequence += 1
            self._output += action.parameters.max_output_bytes
            # All setup and launch failures after reservation retain their full cost.
            nonce = secrets.token_hex(32)
            envelope = {
                "schema_version": "1", "mode": "fixture", "execute": True,
                "session_id": self._session_id, "nonce": nonce, "sequence": self._sequence,
                "action": action.to_dict(), "action_digest": action.digest,
                "policy": self._policy.to_dict(), "policy_digest": self._policy_digest,
                "limits": asdict(self._limits), "limits_digest": self._limits_digest,
                "deadline": control.deadline, "output_reserved_before": before,
                "output_reserved_after": self._output, "host_namespaces": _namespaces(),
            }
            request = encode(envelope)
            if len(request) > MAX_LAUNCH_BYTES:
                raise IsolationUnavailable("Executor launch exceeds its byte bound")
            context_digest = hashlib.sha256(request).hexdigest()
            stdlib, files = _runtime_files("/usr/bin/python3", _trusted_program("nft"), control=control)
            code, stdout, _stderr, reason = _capture_bounded(
                self._command(stdlib, files, nonce, context_digest), request,
                action.parameters.timeout_seconds + 8, action.parameters.max_output_bytes * 6 + 16384,
                control=control,
            )
            control.check()
            if reason is not None:
                return {"status": reason, "backend": self.name, "results": [], "bytes_received": 0,
                        "truncated": reason == "output_limit"}
            if code != 0:
                raise IsolationUnavailable("Executor launch or isolation failed; no fallback")
            try:
                result = json.loads(stdout)
                if (type(result) is not dict or type(result.get("status")) is not str
                        or result["status"] not in {"succeeded", "failed", "timeout", "output_limit"}):
                    raise ValueError("invalid result")
                checks = result.get("boundary_checks")
                expected = {"forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked", "capabilities_dropped"}
                if type(checks) is not dict or set(checks) != expected or any(value is not True for value in checks.values()):
                    raise ValueError("invalid boundary checks")
            except (ValueError, UnicodeError, RecursionError):
                raise IsolationUnavailable("Executor returned invalid bounded evidence") from None
            result["backend"] = self.name
            control.check()
            return result
        finally:
            self._lock.release()
