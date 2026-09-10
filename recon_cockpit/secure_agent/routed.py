"""Single-destination rootless HTTP execution through a supervised transport.

The probe has a private network namespace and an exact nftables allow rule.
Only the separately sandboxed, trusted slirp transport retains the caller's
network namespace. No host firewall, route, sysctl or forwarding setup occurs.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces, _runtime_files, _trusted_program
from .models import parse_action


_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_READY = b"READY\n"


class _BudgetExceeded(RuntimeError):
    def __init__(self, status: str):
        self.status = status


class _Supervisor:
    """One deadline and aggregate output budget, including bootstrap pipes."""

    def __init__(self, timeout: float, limit: int):
        self.deadline = time.monotonic() + timeout
        self.limit = limit
        self.total = 0
        self.selector = selectors.DefaultSelector()
        self.buffers: dict[str, bytearray] = {}
        self.eof: set[str] = set()
        self.processes: dict[str, subprocess.Popen] = {}
        self.fds: set[int] = set()

    def pipe(self) -> tuple[int, int]:
        ends = os.pipe()
        self.fds.update(ends)
        return ends

    def close_fd(self, fd: int) -> None:
        if fd in self.fds:
            os.close(fd)
            self.fds.remove(fd)

    def watch(self, fd: int, name: str) -> None:
        self.buffers[name] = bytearray()
        self.selector.register(fd, selectors.EVENT_READ, name)

    def launch(self, name: str, argv: list[str], *, pass_fds=(), stdin=subprocess.DEVNULL) -> subprocess.Popen:
        proc = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=_ENV, pass_fds=pass_fds, close_fds=True,
                                start_new_session=True, bufsize=0)
        self.processes[name] = proc
        self.watch(proc.stdout.fileno(), name + "_out")
        self.watch(proc.stderr.fileno(), name + "_err")
        return proc

    def wait_for(self, predicate, *, worker_may_exit: bool = False) -> None:
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise _BudgetExceeded("timeout")
            for name, proc in self.processes.items():
                if proc.poll() is not None and not (name == "worker" and worker_may_exit):
                    raise IsolationUnavailable("Routed sandbox or transport exited prematurely")
            if predicate():
                return
            for key, _ in self.selector.select(min(remaining, 0.05)):
                data = os.read(key.fd, min(8192, self.limit - self.total + 1))
                if not data:
                    self.selector.unregister(key.fd)
                    self.eof.add(key.data)
                    continue
                self.total += len(data)
                if self.total > self.limit:
                    raise _BudgetExceeded("output_limit")
                self.buffers[key.data].extend(data)
                if key.data in {"info", "transport_ready"} and len(self.buffers[key.data]) > 4096:
                    raise IsolationUnavailable("Invalid routed setup handshake")

    def close(self) -> None:
        # Only this process holds transport's exit-pipe writer. Closing it also
        # stops slirp on ordinary cancellation; bwrap ties both trees to us.
        failed = False
        for fd in list(self.fds):
            try:
                self.close_fd(fd)
            except OSError:
                failed = True
        for proc in reversed(list(self.processes.values())):
            try:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                # Attempt cleanup of the other sandbox even if one tree is
                # not reapable. Never turn a failed cleanup into success.
                failed = True
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    failed = True
        self.selector.close()
        if failed:
            raise IsolationUnavailable("Routed sandbox cleanup failed")


def _transport_files() -> list[tuple[str, str]]:
    """Explicit native loader/library closure; no host directory mounts."""
    programs = [_trusted_program("slirp4netns"), _trusted_program("prlimit")]
    try:
        result = subprocess.run([_trusted_program("ldd"), *programs], stdin=subprocess.DEVNULL,
                                capture_output=True, check=True, timeout=5, env=_ENV)
        listing = result.stdout.decode("utf-8", "replace")
        if "not found" in listing:
            raise IsolationUnavailable("The transport runtime has missing shared libraries")
        libraries = set(re.findall(r"(?:=>\s+)?(/[^\s]+)\s+\(", listing))
        if not libraries:
            raise IsolationUnavailable("Cannot identify the transport runtime")
        return [(str(Path(p).resolve(strict=True)), p) for p in sorted(libraries)] + [
            (str(Path(p).resolve(strict=True)), "/usr/bin/" + Path(p).name) for p in programs]
    except (OSError, subprocess.SubprocessError) as exc:
        raise IsolationUnavailable("Cannot inspect the trusted transport runtime") from exc


def _pin_namespaces(info: bytes, host: dict[str, str]) -> tuple[int, int]:
    opened = []
    try:
        metadata = json.loads(info)
        pid = metadata["child-pid"]
        if type(pid) is not int or pid <= 1:
            raise ValueError("invalid sandbox pid")
        for name in ("user", "net"):
            fd = os.open(f"/proc/{pid}/ns/{name}", os.O_RDONLY | os.O_CLOEXEC)
            opened.append(fd)
            identity = os.readlink(f"/proc/self/fd/{fd}")
            if not re.fullmatch(name + r":\[\d+\]", identity) or identity == host[name]:
                raise ValueError("nonprivate sandbox namespace")
        return tuple(opened)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        for fd in opened:
            os.close(fd)
        raise IsolationUnavailable("Cannot pin private routed namespaces") from exc


class LinuxRoutedBackend:
    """A trusted backend for one authorized canonical IPv4 literal/TCP port."""

    name = "linux-bubblewrap-slirp-v1"

    def __init__(self, *, boundary_witnesses: dict | None = None):
        # Trusted validation harness only; never read from provider proposals.
        self.boundary_witnesses = dict(boundary_witnesses) if boundary_witnesses is not None else None

    def check_available(self, action=None) -> None:
        LinuxFixtureBackend().check_available()
        for program in ("slirp4netns", "prlimit"):
            _trusted_program(program)
        if Path(_trusted_program("bwrap")).stat().st_mode & stat.S_ISUID:
            raise IsolationUnavailable("Routed execution requires non-setuid Bubblewrap")
        if action is not None:
            from .routed_worker import validate_target
            try:
                validate_target(action.target)
            except ValueError as exc:
                raise IsolationUnavailable("Routed execution requires one supported IPv4 literal, without CIDR") from exc

    def _worker_command(self, stdlib: str, files: list[tuple[str, str]], info_fd: int) -> list[str]:
        argv = LinuxFixtureBackend()._command(stdlib, files)
        # Reuse the validated fixture's namespace/mount/capability construction,
        # while keeping its worker and executable target behavior independent.
        argv[1:1] = ["--info-fd", str(info_fd)]
        mount_index = argv.index("--remount-ro")
        argv[mount_index:mount_index] = ["--ro-bind", str(Path(__file__).with_name("routed_worker.py").resolve()),
                                         "/app/routed_worker.py"]
        argv[-1] = "/app/routed_worker.py"
        return argv

    def _transport_command(self, files: list[tuple[str, str]], user_fd: int, net_fd: int,
                           ready_fd: int, exit_fd: int, timeout: int) -> list[str]:
        # Join the worker's user namespace solely for TAP setup; retain the
        # caller's network namespace for translation. No host NET_ADMIN exists.
        argv = [_trusted_program("bwrap"), "--userns", str(user_fd), "--uid", "0", "--gid", "0",
                "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
                "--cap-drop", "ALL", "--cap-add", "CAP_SYS_ADMIN", "--cap-add", "CAP_NET_ADMIN",
                "--cap-add", "CAP_SETPCAP", "--cap-add", "CAP_NET_BIND_SERVICE",
                "--die-with-parent", "--new-session", "--clearenv", "--setenv", "PATH", "/usr/bin",
                "--setenv", "LC_ALL", "C", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
                "--dev-bind", "/dev/net/tun", "/dev/net/tun", "--dir", "/etc", "--dir", "/run",
                "--size", "1048576", "--tmpfs", "/tmp"]
        for source, destination in files:
            argv.extend(("--ro-bind", source, destination))
        argv.extend(("--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
                     "/usr/bin/prlimit", "--as=268435456", "--fsize=1048576", "--nofile=64",
                     "--core=0", "--nproc=16", f"--cpu={timeout + 10}", "--",
                     "/usr/bin/slirp4netns", "--configure", "--mtu=1500", "--cidr=10.0.2.0/24",
                     "--disable-host-loopback", "--disable-dns", "--enable-sandbox", "--enable-seccomp",
                     "--netns-type=path", f"--ready-fd={ready_fd}", f"--exit-fd={exit_fd}",
                     f"/proc/self/fd/{net_fd}", "tap0"))
        return argv

    def run(self, action, policy) -> dict:
        from .routed_worker import validate_request

        action = parse_action(dataclasses.asdict(action))
        if policy.evaluate(action).decision == "deny":
            raise IsolationUnavailable("The action failed independent policy evaluation")
        self.check_available(action)
        host = _namespaces()
        request = json.dumps({"target": action.target, "parameters": dataclasses.asdict(action.parameters),
                              "host_namespaces": host, "boundary_witnesses": self.boundary_witnesses},
                             separators=(",", ":")).encode("ascii") + b"\n"
        validate_request(request)
        if len(request) > 4096:
            raise IsolationUnavailable("Routed request exceeds pipe bound")
        stdlib, files = _runtime_files("/usr/bin/python3", _trusted_program("nft"))
        transport_files = _transport_files()
        supervisor = _Supervisor(action.parameters.timeout_seconds + 15,
                                 action.parameters.max_output_bytes * 6 + 32768)
        try:
            info_r, info_w = supervisor.pipe()
            supervisor.watch(info_r, "info")
            child = supervisor.launch("worker", self._worker_command(stdlib, files, info_w),
                                      pass_fds=(info_w,), stdin=subprocess.PIPE)
            supervisor.close_fd(info_w)
            child.stdin.write(request)
            supervisor.wait_for(lambda: "info" in supervisor.eof and
                                b"\n" in supervisor.buffers["worker_out"])
            if bytes(supervisor.buffers["worker_out"]) != _READY:
                raise IsolationUnavailable("Routed firewall readiness was not confirmed")
            user_fd, net_fd = _pin_namespaces(bytes(supervisor.buffers["info"]), host)
            supervisor.fds.update((user_fd, net_fd))
            ready_r, ready_w = supervisor.pipe()
            exit_r, exit_w = supervisor.pipe()
            supervisor.watch(ready_r, "transport_ready")
            supervisor.launch("transport", self._transport_command(transport_files, user_fd, net_fd,
                              ready_w, exit_r, action.parameters.timeout_seconds),
                              pass_fds=(user_fd, net_fd, ready_w, exit_r))
            for fd in (user_fd, net_fd, ready_w, exit_r):
                supervisor.close_fd(fd)
            supervisor.wait_for(lambda: "transport_ready" in supervisor.eof)
            if bytes(supervisor.buffers["transport_ready"]) != b"1":
                raise IsolationUnavailable("Routed transport readiness was not confirmed")
            if bytes(supervisor.buffers["worker_out"]) != _READY:
                raise IsolationUnavailable("Worker sent output before release")
            child.stdin.write(b"GO\n")
            child.stdin.close()
            supervisor.wait_for(lambda: child.poll() is not None and
                                {"worker_out", "worker_err"} <= supervisor.eof, worker_may_exit=True)
            if child.returncode != 0:
                raise IsolationUnavailable("Routed execution boundary failed")
            try:
                result = json.loads(bytes(supervisor.buffers["worker_out"])[len(_READY):])
                if (type(result) is not dict or type(result.get("status")) is not str
                        or result["status"] not in {"succeeded", "failed", "timeout", "output_limit"}):
                    raise ValueError("invalid worker result")
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise IsolationUnavailable("Routed worker returned an invalid result") from exc
            result["backend"] = self.name
            return result
        except _BudgetExceeded as exc:
            return {"status": exc.status, "backend": self.name, "results": [], "bytes_received": 0,
                    "truncated": exc.status == "output_limit", "reason": "sandbox_" + exc.status}
        except (OSError, subprocess.SubprocessError) as exc:
            raise IsolationUnavailable("Routed sandbox setup failed; execution refused") from exc
        finally:
            supervisor.close()
