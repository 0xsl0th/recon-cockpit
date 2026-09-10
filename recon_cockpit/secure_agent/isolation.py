"""Fail-closed Linux execution backend for *namespace-owned* HTTP fixtures.

This backend deliberately cannot reach the host's loopback or routed networks.
It is an internal controller component, not an agent-facing execution API.
"""

from __future__ import annotations

import dataclasses
import glob
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from typing import Any


class IsolationUnavailable(RuntimeError):
    code = "isolation_unavailable"


def _trusted_program(name: str) -> str:
    """Ignore the caller's PATH, including virtual environments and cwd."""
    candidate = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if candidate is None:
        raise IsolationUnavailable(f"Linux fixture isolation requires {name}")
    return candidate


def _namespaces() -> dict[str, str]:
    return {name: os.readlink(f"/proc/self/ns/{name}") for name in ("user", "net", "mnt", "pid")}


def _runtime_files(python: str, nft: str) -> tuple[str, list[tuple[str, str]]]:
    """Build an explicit runtime closure, never bind the host /usr or /lib."""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    try:
        probe = subprocess.run(
            [python, "-I", "-S", "-c", "import sysconfig; print(sysconfig.get_path('stdlib'))"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=3, env=env, check=True,
        )
        stdlib = probe.stdout.decode("ascii").strip()
        if not re.fullmatch(r"/usr/lib/python3\.\d+", stdlib) or not Path(stdlib).is_dir():
            raise IsolationUnavailable("Use the distribution Python in /usr/bin (stdlib /usr/lib/python3.x)")
        modules = sorted(str(p) for p in Path(stdlib, "lib-dynload").glob("*.so"))
        seccomp_candidates = [
            p for pattern in ("/lib/*/libseccomp.so.2", "/usr/lib/*/libseccomp.so.2", "/lib64/libseccomp.so.2")
            for p in glob.glob(pattern)
        ]
        if not seccomp_candidates:
            raise IsolationUnavailable("Linux fixture isolation requires libseccomp2")
        seccomp = seccomp_candidates[0]
        dependencies = subprocess.run(
            [_trusted_program("ldd"), python, nft, seccomp, *modules],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5, env=env, check=True,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
        raise IsolationUnavailable("Cannot inspect the trusted Linux runtime") from exc
    listing = dependencies.stdout.decode("utf-8", "replace")
    if "not found" in listing:
        raise IsolationUnavailable("The trusted runtime has missing shared libraries")
    library_paths = set(re.findall(r"(?:=>\s+)?(/[^\s]+)\s+\(", listing))
    library_paths.add(seccomp)
    files = [(str(Path(path).resolve(strict=True)), path) for path in sorted(library_paths)]
    files += [(str(Path(python).resolve(strict=True)), "/usr/bin/python3"),
              (str(Path(nft).resolve(strict=True)), "/usr/sbin/nft")]
    return stdlib, files


def _capture_bounded(argv: list[str], request: bytes, timeout: float, limit: int) -> tuple[int, bytes, bytes, str | None]:
    """Bound both pipes while running, and terminate the sandbox on deadline."""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, close_fds=True, start_new_session=True)
    except OSError as exc:
        raise IsolationUnavailable("Cannot start bubblewrap") from exc
    chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    reason = None
    deadline = time.monotonic() + timeout
    try:
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        try:
            proc.stdin.write(request)
            proc.stdin.close()
        except BrokenPipeError:
            pass
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            total = 0
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.2)):
                    data = os.read(key.fileobj.fileno(), min(8192, limit - total + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    if total > limit:
                        reason = "output_limit"
                        break
                    chunks[key.data].extend(data)
                if reason:
                    break
        if reason is None:
            try:
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                reason = "timeout"
    finally:
        if reason or proc.poll() is None:
            # bwrap's --die-with-parent and private PID namespace also reap tools
            # that made a different process group before their syscall filter.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=2)
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream and not stream.closed:
                    stream.close()
    return proc.returncode, bytes(chunks["stdout"]), bytes(chunks["stderr"]), reason


class LinuxFixtureBackend:
    """Owned fixtures only; instantiate exclusively in trusted controller code."""

    name = "linux-bubblewrap-fixture-v1"

    def __init__(self, *, verify_boundary: bool = False):
        self.verify_boundary = verify_boundary

    def check_available(self, action: Any = None) -> None:
        if sys.platform != "linux":
            raise IsolationUnavailable("Secure fixture execution requires Linux; dry-run remains available")
        if os.geteuid() == 0:
            raise IsolationUnavailable("Run secure fixture execution as an unprivileged Linux user, without sudo")
        for program in ("bwrap", "nft", "python3", "ldd"):
            _trusted_program(program)
        if not Path("/usr/bin/python3").is_file():
            raise IsolationUnavailable("The distribution Python /usr/bin/python3 is required")
        if action is not None:
            targets = tuple(action.targets)
            if targets != ("127.0.0.1",):
                raise IsolationUnavailable("This backend supports only its owned 127.0.0.1 fixture (or /32), never host services")
            if not 1024 <= action.parameters.port <= 65534:
                raise IsolationUnavailable("Fixture ports must be unprivileged and leave one witness port: 1024..65534")

    def _command(self, stdlib: str, files: list[tuple[str, str]]) -> list[str]:
        argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid",
                "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0",
                "--cap-drop", "ALL", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_SETPCAP",
                "--die-with-parent", "--new-session", "--clearenv", "--setenv", "PATH", "/usr/bin:/usr/sbin",
                "--setenv", "LC_ALL", "C", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
                "--size", "1048576", "--tmpfs", "/tmp", "--ro-bind", stdlib, stdlib]
        for source, destination in files:
            argv.extend(("--ro-bind", source, destination))
        argv.extend(("--ro-bind", str(Path(__file__).with_name("worker.py").resolve()), "/app/worker.py",
                     "--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
                     "/usr/bin/python3", "-I", "-S", "/app/worker.py"))
        return argv

    def run(self, action: Any, policy: Any) -> dict[str, Any]:
        # A second policy evaluation protects internal accidental DENY bypasses.
        # Approval verification belongs to the controller, which owns its store.
        from .models import parse_action

        action = parse_action(dataclasses.asdict(action))
        if policy.evaluate(action).decision == "deny":
            raise IsolationUnavailable("The action failed independent policy evaluation")
        self.check_available(action)
        stdlib, runtime = _runtime_files("/usr/bin/python3", _trusted_program("nft"))
        request = json.dumps({"target": "127.0.0.1", "parameters": dataclasses.asdict(action.parameters),
                              "verify_boundary": self.verify_boundary, "host_namespaces": _namespaces()},
                             separators=(",", ":")).encode("utf-8")
        if len(request) > 8192:
            raise IsolationUnavailable("Internal execution request exceeds its bound")
        # Fixed setup allowance + action deadline; stdout/stderr are bounded even
        # if the worker or a tool is compromised. No unbounded communicate().
        budget = action.parameters.max_output_bytes * 6 + 16384
        returncode, stdout, _stderr, reason = _capture_bounded(
            self._command(stdlib, runtime), request,
            action.parameters.timeout_seconds + 8, budget,
        )
        if reason:
            return {"status": reason, "backend": self.name, "results": [], "bytes_received": 0,
                    "truncated": reason == "output_limit", "reason": "sandbox_" + reason}
        if returncode != 0:
            # Never include raw helper diagnostics or fall back to host sockets.
            raise IsolationUnavailable("Sandbox setup failed (user namespaces, nftables or seccomp unavailable); no host fallback")
        try:
            result = json.loads(stdout)
            if (type(result) is not dict or type(result.get("status")) is not str
                    or result["status"] not in {"succeeded", "timeout", "output_limit", "failed"}):
                raise ValueError("bad result")
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise IsolationUnavailable("Sandbox returned an invalid result") from exc
        result["backend"] = self.name
        return result


BubblewrapFixtureBackend = LinuxFixtureBackend
