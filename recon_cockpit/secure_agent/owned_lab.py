"""Trusted single-use lifecycle and authority adapter for a persistent owned lab.

Persistence lasts only for one bounded authority session. Closing, cancellation,
owner failure or an invalid handshake permanently prevents attachment/restart.
The owner exposes a private statistics pipe, not a socket management API.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import threading
import time
from uuid import UUID, uuid4

from .authorized_execution import AuthorizedDiscoveryFixtureBackend
from .execution import ExecutionControl
from .executor_worker import encode
from .isolation import (IsolationUnavailable, LinuxFixtureBackend, _capture_bounded,
                        _namespaces, _runtime_files, _trusted_program)
from .models import Action, Policy, parse_action, parse_policy
from .owned_lab_contract import BACKEND, identity, validate_context, validate_result_context
from .owned_lab_executor import MAX_OWNED_LAUNCH_BYTES
from .routed import _Supervisor, _pin_namespaces
from .session_limits import SessionLimits


_CLOSE_NAMESPACE_FDS = """import os, sys
for name in os.listdir('/proc/self/fd'):
    if name.isdecimal() and int(name) > 2:
        try:
            os.close(int(name))
        except OSError as exc:
            if exc.errno != 9:  # listdir's already closed directory descriptor.
                raise
os.execv(sys.argv[1], sys.argv[1:])
"""


class OwnedLab:
    """An unstarted instance is metadata only; start requires fixed host control."""

    def __init__(self, case, session_id, limits, *, execute=True):
        if (type(session_id) is not str or str(UUID(session_id)) != session_id
                or type(limits) is not SessionLimits or type(execute) is not bool):
            raise ValueError("invalid_owned_lab_configuration")
        self._identity = identity(case, str(uuid4()))
        self.session_id = session_id
        self.limits = SessionLimits(**asdict(limits))
        self.execute = execute
        self._control = None
        self._supervisor = None
        self._namespace_fds = ()
        self._lab_namespaces = {}
        self._closed = False
        self._started = False
        self._sequence = 0
        self._offset = 0
        self._counts = {"connection_count": 0, "request_count": 0}
        self._receipt = None
        self._lock = threading.RLock()

    @property
    def identity(self):
        return dict(self._identity)

    @property
    def started(self):
        return self._started

    def __enter__(self):
        if self._closed:
            raise IsolationUnavailable("Owned lab is permanently closed")
        return self

    def __exit__(self, *_):
        self.close()

    def _owner_command(self, stdlib, files, info_fd):
        argv = LinuxFixtureBackend()._command(stdlib, files)
        argv[1:1] = ["--info-fd", str(info_fd)]
        index = argv.index("--remount-ro")
        argv[index:index] = ["--ro-bind", str(Path(__file__).with_name("owned_lab_worker.py").resolve()),
                              "/app/owned_lab_worker.py"]
        argv[-1] = "/app/owned_lab_worker.py"
        return argv

    def _read_message(self):
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b"\n" in supervisor.buffers["lab_out"][self._offset:])
        buffered = supervisor.buffers["lab_out"]
        end = buffered.index(b"\n", self._offset) + 1
        raw = bytes(buffered[self._offset:end])
        if len(raw) > 4096:
            raise IsolationUnavailable("Owned lab management response exceeds its bound")
        self._offset = end
        try:
            from .models import load_json
            return load_json(raw)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise IsolationUnavailable("Owned lab returned invalid management evidence") from exc

    def _check(self, control):
        if self._closed or not self.execute or type(control) is not ExecutionControl or control.clock is not time.monotonic:
            raise IsolationUnavailable("Owned lab is unavailable or its authority control is invalid")
        control.check()
        if self._control is not None and control is not self._control:
            raise IsolationUnavailable("Owned lab authority control cannot be replaced")
        if self._supervisor is not None:
            self._supervisor.check()
            if self._supervisor.processes["lab"].poll() is not None:
                raise IsolationUnavailable("Owned lab owner exited")

    def _runtime(self, control):
        return _runtime_files("/usr/bin/python3", _trusted_program("nft"), control=control)

    def _check_available(self):
        LinuxFixtureBackend().check_available()
        if Path(_trusted_program("bwrap")).stat().st_mode & stat.S_ISUID:
            raise IsolationUnavailable("Owned lab requires non-setuid Bubblewrap")
        _trusted_program("nsenter")

    def start(self, control):
        with self._lock:
            try:
                self._check(control)
                if self._started:
                    self._verify_pins()
                    return
                if control.remaining() > self.limits.max_runtime_seconds:
                    raise IsolationUnavailable("Owned lab deadline exceeds its fixed lifetime")
                self._control = control
                self._check_available()
                host = _namespaces()
                stdlib, files = self._runtime(control)
                self._supervisor = _Supervisor(control.remaining(), 32768, control=control)
                info_r, info_w = self._supervisor.pipe()
                self._supervisor.watch(info_r, "info")
                proc = self._supervisor.launch("lab", self._owner_command(stdlib, files, info_w),
                                               pass_fds=(info_w,), stdin=subprocess.PIPE)
                self._supervisor.close_fd(info_w)
                proc.stdin.write(encode({"case": self._identity["scenario"], "deadline": control.deadline,
                                         "host_namespaces": host}) + b"\n")
                ready = self._read_message()
                self._supervisor.wait_for(lambda: "info" in self._supervisor.eof)
                if (type(ready) is not dict or set(ready) != {"ready", "namespaces", "witness_baselines", "connection_count", "request_count"}
                        or ready["ready"] is not True or ready["witness_baselines"] is not True
                        or type(ready["connection_count"]) is not int or ready["connection_count"] != 0
                        or type(ready["request_count"]) is not int or ready["request_count"] != 0):
                    raise IsolationUnavailable("Owned lab readiness was not confirmed")
                self._namespace_fds = _pin_namespaces(bytes(self._supervisor.buffers["info"]), host)
                self._supervisor.fds.update(self._namespace_fds)
                metadata = json.loads(bytes(self._supervisor.buffers["info"]))
                observed = {name: os.readlink(f"/proc/{metadata['child-pid']}/ns/{name}") for name in host}
                if ready["namespaces"] != observed or any(observed[name] == host[name] for name in host):
                    raise IsolationUnavailable("Owned lab namespace identity was not confirmed")
                self._lab_namespaces = observed
                self._started = True
                self._verify_pins()
            except BaseException:
                self.close()
                raise

    def _verify_pins(self):
        if len(self._namespace_fds) != 2:
            raise IsolationUnavailable("Owned lab namespace descriptors are missing")
        for name, fd in zip(("user", "net"), self._namespace_fds):
            if os.readlink(f"/proc/self/fd/{fd}") != self._lab_namespaces[name]:
                raise IsolationUnavailable("Owned lab pinned namespace changed")

    def snapshot(self, control, *, minimum_connections=None, minimum_requests=None):
        with self._lock:
            try:
                self._check(control)
                if not self._started:
                    raise IsolationUnavailable("Owned lab has not started")
                self._verify_pins()
                minimum_connections = self._counts["connection_count"] if minimum_connections is None else minimum_connections
                minimum_requests = self._counts["request_count"] if minimum_requests is None else minimum_requests
                if any(type(value) is not int or not 0 <= value <= 16 for value in (minimum_connections, minimum_requests)):
                    raise IsolationUnavailable("Owned lab counter barrier is invalid")
                self._sequence += 1
                self._supervisor.processes["lab"].stdin.write(encode({"sequence": self._sequence,
                    "minimum_connections": minimum_connections, "minimum_requests": minimum_requests}) + b"\n")
                value = self._read_message()
                if (type(value) is not dict or set(value) != {"sequence", "connection_count", "request_count"}
                        or type(value["sequence"]) is not int or value["sequence"] != self._sequence):
                    raise IsolationUnavailable("Owned lab counter acknowledgement is invalid")
                context = validate_context({"identity": self.identity, **{key: value[key] for key in self._counts}}, self.identity)
                if (any(context[key] < self._counts[key] for key in self._counts)
                        or context["connection_count"] < minimum_connections
                        or context["request_count"] < minimum_requests):
                    raise IsolationUnavailable("Owned lab counters regressed or did not settle")
                self._counts = {key: context[key] for key in self._counts}
                self._check(control)
                return dict(self._counts)
            except BaseException:
                self.close()
                raise

    def close(self):
        # These are the last acknowledged service totals. An interrupted action
        # can have reached the service without producing a persisted result;
        # closure confirms cleanup and never invents a final counter sample.
        with self._lock:
            if self._receipt is not None:
                return {**self._receipt, "identity": self.identity}
            self._closed = True
            if self._supervisor is not None:
                self._supervisor.close()
            self._receipt = {"identity": self.identity, "status": "closed", **self._counts}
            return {**self._receipt, "identity": self.identity}


class AuthorizedOwnedLabBackend(AuthorizedDiscoveryFixtureBackend):
    """Fixed-session launches; no supplied action can choose a lab or namespace."""

    name = BACKEND

    def __init__(self, policy, session_id, limits, lab, *, execute=False):
        super().__init__(policy, session_id, limits, execute=execute)
        if (not self._accept_lab(lab) or lab.session_id != session_id or lab.limits != limits
                or lab.execute != execute):
            raise ValueError("owned_lab_authority_mismatch")
        self.lab = lab
        self._lab_identity = lab.identity
        self._previous_context = None

    def _accept_lab(self, lab):
        return type(lab) is OwnedLab

    def _runtime(self, control):
        return _runtime_files("/usr/bin/python3", None, control=control)

    def _validate_result_context(self, result, *, action):
        return validate_result_context(result, self._lab_identity,
            previous=self._previous_context, tool_id=action.tool_id, execution_status=result["status"])

    def check_available(self, action=None):
        super().check_available(action)
        if action is not None and action.tool_id == "http_probe":
            if (action.parameters.path not in {
                    f"/assessment/{self._lab_identity['scenario']}/index.json",
                    f"/assessment/{self._lab_identity['scenario']}/diagnostics.json"}
                    or action.parameters.method != "GET" or action.parameters.timeout_seconds != 1
                    or action.parameters.max_output_bytes != 1024):
                raise IsolationUnavailable("Owned lab action does not match its fixed case/profile")
        _trusted_program("nsenter")

    def _command(self, stdlib, files, nonce, context_digest):
        argv = LinuxFixtureBackend()._command(stdlib, files)
        argv.remove("--unshare-net")
        cap = argv.index("CAP_NET_ADMIN")
        del argv[cap - 1:cap + 1]
        directory = Path(__file__).parent
        mounts = []
        for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
            mounts.extend(("--ro-bind", str((directory / "__init__.py").resolve()), destination))
        for module in ("models.py", "tool_parameters.py", "tool_adapters.py", "executor_worker.py", "owned_lab_contract.py", "assessment_contract.py"):
            mounts.extend(("--ro-bind", str((directory / module).resolve()), "/app/recon_cockpit/secure_agent/" + module))
        # executor_worker imports its sibling worker when loaded as a package.
        mounts.extend(("--ro-bind", str((directory / "worker.py").resolve()), "/app/recon_cockpit/secure_agent/worker.py",
                       "--ro-bind", str((directory / "owned_lab_executor.py").resolve()), "/app/owned_lab_executor.py"))
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-4:] = ["/usr/bin/python3", "-I", "-S", "/app/owned_lab_executor.py", nonce, context_digest]
        user_fd, net_fd = self.lab._namespace_fds
        return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
                "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_NAMESPACE_FDS, *argv]

    def run(self, action, policy, *, control=None):
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable("Executor authority is already running")
        try:
            if (not self._execute or type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(action) is not Action or type(policy) is not Policy):
                raise IsolationUnavailable("Invalid executor authority context")
            control.check()
            action = parse_action(action.to_dict())
            supplied_policy = parse_policy(policy.to_dict())
            if (supplied_policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or self._policy.evaluate(action).decision == "deny"
                    or self.lab.identity != self._lab_identity):
                raise IsolationUnavailable("Executor action, policy or lab does not match authority")
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
            self.lab.start(control)
            nonce = secrets.token_hex(32)
            launch = {"schema_version": "1", "mode": "discovery_fixture", "execute": True,
                "session_id": self._session_id, "nonce": nonce, "sequence": self._sequence,
                "action": action.to_dict(), "action_digest": action.digest,
                "policy": self._policy.to_dict(), "policy_digest": self._policy_digest,
                "limits": asdict(self._limits), "limits_digest": self._limits_digest,
                "deadline": control.deadline, "output_reserved_before": before,
                "output_reserved_after": self._output, "host_namespaces": _namespaces()}
            request = encode({"mode": "owned_lab", "launch": launch, "identity": self._lab_identity,
                              "namespaces": self.lab._lab_namespaces})
            if len(request) > MAX_OWNED_LAUNCH_BYTES:
                raise IsolationUnavailable("Owned lab executor launch exceeds its bound")
            stdlib, files = self._runtime(control)
            code, stdout, _stderr, reason = _capture_bounded(
                self._command(stdlib, files, nonce, hashlib.sha256(request).hexdigest()), request,
                action.parameters.timeout_seconds + 8, action.parameters.max_output_bytes * 6 + 16384,
                control=control, pass_fds=self.lab._namespace_fds)
            control.check()
            if reason is not None or code != 0:
                raise IsolationUnavailable("Owned lab executor failed; instance closed without fallback")
            try:
                from .models import load_json
                result = load_json(stdout)
                if type(result) is not dict or result.get("status") not in {"succeeded", "failed", "timeout", "output_limit"}:
                    raise ValueError("invalid_owned_lab_result")
                checks = result.get("boundary_checks")
                expected = {"forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked", "capabilities_dropped"}
                if type(checks) is not dict or set(checks) != expected or any(value is not True for value in checks.values()):
                    raise ValueError("invalid_owned_lab_boundary")
                result["backend"] = self.name
                previous = self._previous_context or {"connection_count": 0, "request_count": 0}
                # A completed handshake/HTTP exchange must be accepted by the
                # owner before acknowledging continuity, independent of scheduling.
                settled = result["status"] == "succeeded" or result["status"] == "output_limit"
                minimum_connections = previous["connection_count"] + int(settled)
                minimum_requests = previous["request_count"] + int(settled and action.tool_id == "http_probe")
                counts = self.lab.snapshot(control, minimum_connections=minimum_connections,
                                           minimum_requests=minimum_requests)
                result["owned_lab"] = {"identity": self._lab_identity, **counts}
                self._previous_context = self._validate_result_context(result, action=action)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise IsolationUnavailable("Owned lab executor returned invalid evidence") from exc
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._lock.release()
