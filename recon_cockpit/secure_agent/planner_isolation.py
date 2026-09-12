"""Explicit, network-disabled Linux sandbox for the bundled session planner.

No arbitrary plugin command, model endpoint or credential source is accepted.
This foundation tests the planner's OS boundary; it does not call a model API.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from .execution import ExecutionControl, ExecutionStopped
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _runtime_files, _trusted_program
from .models import load_json
from .session_provider import MAX_OBSERVATION_BYTES, MAX_PROPOSAL_BYTES, SCENARIOS


MAX_TRANSPORT_BYTES = 20480
BOUNDARY_NAMES = frozenset({
    "namespaces_private", "capabilities_dropped", "no_new_privs",
    "socket_creation_blocked", "process_creation_blocked",
    "namespace_creation_blocked", "root_read_only",
})


class LinuxIsolatedMockProvider:
    """Fixed mock adapter; explicit isolation selection never falls back."""

    name = "linux-isolated-session-mock-no-model"

    def __init__(self, scenario: str = "three_step"):
        self.scenario = scenario
        self._validate_scenario()
        self._boundary_checks = None

    @property
    def boundary_checks(self):
        return None if self._boundary_checks is None else dict(self._boundary_checks)

    def _validate_scenario(self):
        if type(self.scenario) is not str or self.scenario not in SCENARIOS:
            raise ValueError("unsupported_session_mock_scenario")

    def check_available(self):
        if sys.platform != "linux" or os.geteuid() == 0:
            raise IsolationUnavailable("Planner isolation requires an unprivileged Linux user")
        for program in ("bwrap", "ldd"):
            _trusted_program(program)
        if Path(_trusted_program("bwrap")).stat().st_mode & stat.S_ISUID:
            raise IsolationUnavailable("Planner isolation requires non-setuid Bubblewrap")
        if not Path("/usr/bin/python3").is_file():
            raise IsolationUnavailable("Planner isolation requires distribution Python")

    def _command(self, stdlib: str, files: list[tuple[str, str]]) -> list[str]:
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
        for name in ("planner_worker.py", "session_planner.py"):
            argv.extend(("--ro-bind", str(Path(__file__).with_name(name).resolve()), "/app/" + name))
        argv.extend(("--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
                     "/usr/bin/python3", "-I", "-S", "/app/planner_worker.py", self.scenario,
                     *(host[name] for name in ("user", "net", "mnt", "pid"))))
        return argv

    def propose(self, observation: bytes, *, control: ExecutionControl) -> bytes:
        self._boundary_checks = None
        control.check()
        self._validate_scenario()
        if type(observation) is not bytes or len(observation) > MAX_OBSERVATION_BYTES:
            raise ValueError("invalid_session_mock_observation")
        try:
            observation.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("invalid_session_mock_observation") from None
        self.check_available()
        try:
            # No nft executable or networking bootstrap is needed by a planner.
            stdlib, files = _runtime_files("/usr/bin/python3", None, control=control)
            code, stdout, _stderr, reason = _capture_bounded(
                self._command(stdlib, files), observation,
                timeout=min(5.0, control.remaining()), limit=MAX_TRANSPORT_BYTES, control=control,
            )
            control.check()
            if code != 0 or reason is not None:
                raise ValueError("planner_process_failed")
            envelope = load_json(stdout)
            if (set(envelope) != {"schema_version", "proposal", "boundary_checks"}
                    or envelope["schema_version"] != "1" or type(envelope["proposal"]) is not dict):
                raise ValueError("invalid_planner_transport")
            checks = envelope["boundary_checks"]
            if (type(checks) is not dict or set(checks) != BOUNDARY_NAMES
                    or any(value is not True for value in checks.values())):
                raise ValueError("planner_boundary_unverified")
            raw = json.dumps(envelope["proposal"], ensure_ascii=True, separators=(",", ":")).encode("ascii")
            if len(raw) > MAX_PROPOSAL_BYTES:
                raise ValueError("planner_proposal_limit")
            control.check()
            self._boundary_checks = dict(checks)
            # The session owns proposal validation, policy and all authority.
            return raw
        except ExecutionStopped:
            raise
        except (OSError, RuntimeError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
            raise IsolationUnavailable("Isolated planner failed; no fallback is permitted") from None
