"""Fixed no-network OpenAI codec sandbox with one mediated broker exchange."""

import json
from pathlib import Path
import subprocess

from . import broker_ipc
from .audit import AuditUnavailable
from .execution import ExecutionStopped
from .isolation import IsolationUnavailable, _namespaces, _runtime_files, _trusted_program
from .models import load_json
from .openai_protocol import OpenAIConfig, MAX_PROPOSAL_BYTES, _observation
from .planner_isolation import BOUNDARY_NAMES, LinuxIsolatedMockProvider


class LinuxOpenAIPlanner:
    """Trusted adapter only; no credential access or selectable sandbox code."""

    name = "linux-isolated-openai-codec-offline"

    def __init__(self):
        self._boundary_checks = None

    @property
    def boundary_checks(self):
        return None if self._boundary_checks is None else dict(self._boundary_checks)

    def check_available(self):
        LinuxIsolatedMockProvider().check_available()

    def _command(self, stdlib, files):
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
        directory = Path(__file__).parent
        # The real top-level package imports legacy models. Instead both
        # sandbox packages receive this existing docstring-only initializer.
        for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
            argv.extend(("--ro-bind", str((directory / "__init__.py").resolve()), destination))
        for name in ("models", "session_protocol", "openai_protocol", "broker_ipc"):
            argv.extend(("--ro-bind", str((directory / (name + ".py")).resolve()),
                         "/app/recon_cockpit/secure_agent/" + name + ".py"))
        for name in ("planner_worker", "openai_worker"):
            argv.extend(("--ro-bind", str((directory / (name + ".py")).resolve()), "/app/" + name + ".py"))
        argv.extend(("--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
                     "/usr/bin/python3", "-I", "-S", "/app/openai_worker.py",
                     *(host[name] for name in ("user", "net", "mnt", "pid"))))
        return argv

    def plan(self, config: OpenAIConfig, observation: bytes, exchange, *, control) -> bytes:
        self._boundary_checks = None
        control.check()
        if not callable(exchange):
            raise ValueError("invalid_openai_exchange")
        if type(config) is not OpenAIConfig:
            raise ValueError("invalid_openai_config")
        config.__post_init__()
        init = json.dumps({
            "schema_version": "1", "config": {"model": config.model, "max_output_tokens": config.max_output_tokens},
            "observation": json.loads(_observation(observation)),
        }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        self.check_available()

        try:
            stdlib, files = _runtime_files("/usr/bin/python3", None, control=control)
            raw = broker_ipc.supervise(self._command(stdlib, files), init, exchange, control=control)
            envelope = load_json(raw)
            if (set(envelope) != {"schema_version", "proposal", "boundary_checks"}
                    or envelope["schema_version"] != "1" or type(envelope["proposal"]) is not dict):
                raise ValueError("invalid_openai_result")
            checks = envelope["boundary_checks"]
            if (type(checks) is not dict or set(checks) != BOUNDARY_NAMES
                    or any(value is not True for value in checks.values())):
                raise ValueError("unverified_openai_boundary")
            proposal = json.dumps(envelope["proposal"], ensure_ascii=True, separators=(",", ":")).encode("ascii")
            if len(proposal) > MAX_PROPOSAL_BYTES:
                raise ValueError("openai_proposal_limit")
            control.check()
            self._boundary_checks = dict(checks)
            return proposal
        except (ExecutionStopped, AuditUnavailable):
            raise
        except (OSError, RuntimeError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
            raise IsolationUnavailable("Isolated OpenAI parser failed; no fallback is permitted") from None
