"""Small data-only interface reserved for future separately isolated providers."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from typing import Protocol


class ProposalProvider(Protocol):
    name: str

    def propose(self) -> str:
        """Return untrusted JSON, with no controller or tool handles."""
        ...


class MockProvider:
    name = "deterministic-mock-no-model"

    def propose(self) -> str:
        script = Path(__file__).with_name("planner.py")
        result = subprocess.run(
            [sys.executable, "-I", str(script)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={"LANG": "C", "LC_ALL": "C"},
            cwd=os.path.dirname(sys.executable), timeout=5, check=True,
            close_fds=True,
        )
        # The executed script is fixed trusted fixture code, not an extensible
        # arbitrary provider command. The controller still validates every byte.
        if len(result.stdout) > 16384:
            raise ValueError("provider_output_limit")
        return result.stdout.decode("utf-8")
