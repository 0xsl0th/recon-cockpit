"""Trusted launcher for a fixed persistent coordinator without host authority."""

from pathlib import Path
import subprocess
from uuid import UUID

from . import coordinator_ipc
from .audit import AuditUnavailable
from .execution import ExecutionStopped
from .isolation import IsolationUnavailable, _namespaces, _runtime_files, _trusted_program
from .planner_isolation import LinuxIsolatedMockProvider


BOUNDARY_NAMES = coordinator_ipc.BOUNDARY_NAMES
SCENARIOS = ("three_step", "injection_target", "injection_authority", "endless",
             "replay", "wrong_session", "forge_approval", "oversized", "early_exit")


class LinuxCoordinator:
    """Fixed sandbox choice, never an arbitrary executable or plugin path.

The host callback owns request validation and all authority. It is trusted
synchronous code and must cooperate with the supplied cancellation/deadline.
"""

    name = "linux-isolated-coordinator-mock"
    schema_version = "1"
    _max_requests = coordinator_ipc.MAX_REQUESTS

    def __init__(self, scenario="three_step"):
        self.scenario = scenario
        self._validate_scenario()
        self._boundary_checks = None

    @property
    def boundary_checks(self):
        return None if self._boundary_checks is None else dict(self._boundary_checks)

    def _validate_scenario(self):
        if type(self.scenario) is not str or self.scenario not in SCENARIOS:
            raise ValueError("unsupported_coordinator_scenario")

    def check_available(self):
        LinuxIsolatedMockProvider().check_available()

    def _command(self, stdlib, files):
        self._validate_scenario()
        host = _namespaces()
        argv = [
            _trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid",
            "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0",
            "--cap-drop", "ALL", "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "LC_ALL", "C", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
            "--size", "1048576", "--tmpfs", "/tmp", "--ro-bind", stdlib, stdlib,
        ]
        for source, destination in files:
            argv.extend(("--ro-bind", source, destination))
        for name in ("planner_worker", "session_planner", "coordinator_worker", "coordinator_ipc"):
            argv.extend(("--ro-bind", str(Path(__file__).with_name(name + ".py").resolve()), "/app/" + name + ".py"))
        argv.extend(("--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
                     "/usr/bin/python3", "-I", "-S", "/app/coordinator_worker.py", self.scenario,
                     *(host[name] for name in ("user", "net", "mnt", "pid"))))
        return argv

    def run(self, init_payload, exchange, *, control):
        self._boundary_checks = None
        self._validate_scenario()
        control.check()
        coordinator_ipc.frame(coordinator_ipc.INIT, init_payload)
        init = coordinator_ipc.object_payload(init_payload)
        if (set(init) != {"schema_version", "session_id"} or init["schema_version"] != self.schema_version
                or type(init["session_id"]) is not str or str(UUID(init["session_id"])) != init["session_id"]):
            raise ValueError("invalid_coordinator_init")
        if not callable(exchange):
            raise ValueError("invalid_coordinator_exchange")
        self.check_available()

        def verified_exchange(request, *, control):
            # The supervisor cannot reach this callback before valid READY.
            self._boundary_checks = dict.fromkeys(BOUNDARY_NAMES, True)
            return exchange(request, control=control)

        try:
            stdlib, files = _runtime_files("/usr/bin/python3", None, control=control)
            raw = coordinator_ipc.supervise(self._command(stdlib, files), init_payload,
                                            verified_exchange, control=control, max_requests=self._max_requests)
            result = coordinator_ipc.object_payload(raw)
            if (set(result) != {"schema_version", "session_id", "status"}
                    or result["schema_version"] != self.schema_version or result["session_id"] != init["session_id"]
                    or result["status"] != "closed" or self._boundary_checks is None):
                raise ValueError("invalid_coordinator_result")
            control.check()
            return raw
        except (ExecutionStopped, AuditUnavailable):
            self._boundary_checks = None
            raise
        except (OSError, RuntimeError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
            self._boundary_checks = None
            raise IsolationUnavailable("Isolated coordinator failed; no fallback is permitted") from None


class LinuxOfflineCoordinator(LinuxCoordinator):
    """Fixed version-2 relay; provider and authority remain in trusted host code."""

    name = "linux-isolated-coordinator-offline"
    schema_version = "2"
    _max_requests = coordinator_ipc.MAX_OFFLINE_REQUESTS

    def __init__(self):
        super().__init__("offline_provider")

    def _validate_scenario(self):
        if type(self.scenario) is not str or self.scenario != "offline_provider":
            raise ValueError("unsupported_coordinator_scenario")
