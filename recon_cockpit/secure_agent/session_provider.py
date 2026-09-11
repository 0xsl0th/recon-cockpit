"""Bounded subprocess adapter for the fixed, trusted session mock.

This is not a sandbox for arbitrary plugins or a model provider. The operator
can select only a bundled scenario, never a command, module, credential, or
network endpoint. Its JSON output remains untrusted at the session boundary.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from .execution import ExecutionControl, ExecutionStopped
from .isolation import _capture_bounded


SCENARIOS = ("three_step", "injection_target", "injection_authority", "endless")
MAX_OBSERVATION_BYTES = 8192
MAX_PROPOSAL_BYTES = 16384


class SessionMockProvider:
    """Trusted mock implementation with only a bounded JSON data interface."""

    name = "deterministic-session-mock-no-model"

    def __init__(self, scenario: str = "three_step"):
        if type(scenario) is not str or scenario not in SCENARIOS:
            raise ValueError("unsupported_session_mock_scenario")
        self.scenario = scenario

    def propose(self, observation: bytes, *, control: ExecutionControl) -> bytes:
        control.check()
        if type(observation) is not bytes or len(observation) > MAX_OBSERVATION_BYTES:
            raise ValueError("invalid_session_mock_observation")
        try:
            observation.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("invalid_session_mock_observation") from None
        # Check again at use, so changing the trusted adapter's configuration
        # cannot turn its single fixed argument into an arbitrary invocation.
        if type(self.scenario) is not str or self.scenario not in SCENARIOS:
            raise ValueError("unsupported_session_mock_scenario")
        script = Path(__file__).with_name("session_planner.py").resolve()
        try:
            returncode, stdout, _stderr, reason = _capture_bounded(
                [sys.executable, "-I", "-S", str(script), self.scenario],
                observation,
                timeout=min(5.0, control.remaining()),
                limit=MAX_PROPOSAL_BYTES,
                control=control,
            )
        except ExecutionStopped:
            raise
        except (OSError, subprocess.SubprocessError, RuntimeError):
            raise RuntimeError("session_provider_failed") from None
        control.check()
        if returncode != 0 or reason is not None or len(stdout) > MAX_PROPOSAL_BYTES:
            raise RuntimeError("session_provider_failed")
        try:
            stdout.decode("utf-8")
        except UnicodeDecodeError:
            raise RuntimeError("session_provider_failed") from None
        # The session, not this adapter, validates every wrapper/action field.
        return stdout
