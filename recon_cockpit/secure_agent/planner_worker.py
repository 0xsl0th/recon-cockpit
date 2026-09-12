"""Fixed offline planner bootstrap, entered only through its Linux sandbox.

The parent supplies trusted namespace identities in argv. Only after checking
the sandbox and installing restrictions does this process consume observations
or load the one read-only planner module. No probe worker, credential, network
broker, configurable module or executable is exposed here.
"""

from __future__ import annotations

import ctypes
import errno
import importlib.util
import json
import os
import re
import resource
import signal
import socket
import sys


SCENARIOS = ("three_step", "injection_target", "injection_authority", "endless")
NAMESPACE_NAMES = ("user", "net", "mnt", "pid")
CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
BOUNDARY_NAMES = frozenset({
    "namespaces_private", "capabilities_dropped", "no_new_privs",
    "socket_creation_blocked", "process_creation_blocked",
    "namespace_creation_blocked", "root_read_only",
})
MAX_OBSERVATION_BYTES = 8192
MAX_PROPOSAL_BYTES = 16384
MAX_TRANSPORT_BYTES = 20480
PLANNER_PATH = "/app/session_planner.py"
DENIED_SYSCALLS = (
    "execve", "execveat", "fork", "vfork", "clone", "clone3", "unshare", "setns",
    "mount", "umount2", "pivot_root", "chroot", "ptrace", "process_vm_readv", "process_vm_writev",
    "bpf", "keyctl", "add_key", "request_key", "perf_event_open", "userfaultfd", "io_uring_setup",
    "socket", "socketpair", "socketcall",
)


def _arguments(argv: list[str]) -> tuple[str, dict[str, str]]:
    if len(argv) != 5 or argv[0] not in SCENARIOS:
        raise ValueError("invalid planner configuration")
    host = dict(zip(NAMESPACE_NAMES, argv[1:]))
    for name, identity in host.items():
        if type(identity) is not str or not re.fullmatch(name + r":\[\d+\]", identity):
            raise ValueError("invalid namespace identity")
    return argv[0], host


def _private_namespaces(host: dict[str, str]) -> None:
    if sys.platform != "linux" or set(host) != set(NAMESPACE_NAMES):
        raise RuntimeError("missing Linux isolation")
    if os.getuid() != 0 or os.getgid() != 0:
        raise RuntimeError("invalid namespace-local identity")
    for name, identity in host.items():
        if (type(identity) is not str or not re.fullmatch(name + r":\[\d+\]", identity)
                or os.readlink("/proc/self/ns/" + name) == identity):
            raise RuntimeError("namespace was not isolated")
    with open("/proc/self/uid_map", encoding="ascii") as source:
        mappings = [tuple(map(int, line.split())) for line in source]
    if (len(mappings) != 1 or len(mappings[0]) != 3 or mappings[0][0] != 0
            or mappings[0][1] <= 0 or mappings[0][2] != 1):
        raise RuntimeError("expected one unprivileged host UID")


def _status() -> dict[str, str]:
    with open("/proc/self/status", encoding="ascii") as source:
        return {key: value.strip() for line in source if ":" in line
                for key, value in [line.split(":", 1)]}


def _zero_capabilities() -> None:
    status = _status()
    if any(int(status[name], 16) != 0 for name in CAPABILITY_FIELDS):
        raise RuntimeError("planner capabilities were not dropped")


def _no_new_privileges() -> None:
    # The launcher supplies empty capability sets; no CAP_SETPCAP or securebits
    # manipulation is needed. Setting PR_SET_NO_NEW_PRIVS is unprivileged.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or _status()["NoNewPrivs"] != "1":
        raise RuntimeError("planner no_new_privs unavailable")


def _set_limits() -> None:
    limits = (
        (resource.RLIMIT_AS, 256 * 1024 * 1024),
        (resource.RLIMIT_CPU, 7),
        (resource.RLIMIT_NOFILE, 64),
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_FSIZE, 1024 * 1024),
        (resource.RLIMIT_NPROC, 1),
    )
    for kind, value in limits:
        resource.setrlimit(kind, (value, value))
        if resource.getrlimit(kind) != (value, value):
            raise RuntimeError("planner resource limit was not installed")


def _install_syscall_filter() -> None:
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW; defense in depth.
    if not context:
        raise RuntimeError("planner seccomp allocation failed")
    try:
        if library.seccomp_attr_set(context, 4, 1) != 0:  # SCMP_FLTATR_CTL_TSYNC
            raise RuntimeError("planner seccomp synchronization unavailable")
        for name in DENIED_SYSCALLS:
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            # libseccomp accepts negative pseudo syscall numbers, including
            # architecture-specific alternatives. Only -1 is __NR_SCMP_ERROR.
            if number == -1 or library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) != 0:
                raise RuntimeError("planner seccomp rule failed")
        if library.seccomp_load(context) != 0:
            raise RuntimeError("planner seccomp installation failed")
    finally:
        library.seccomp_release(context)


def _sockets_blocked() -> None:
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            connection = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise RuntimeError("unexpected socket restriction") from None
        else:
            connection.close()
            raise RuntimeError("planner socket creation allowed")
    try:
        pair = socket.socketpair()
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise RuntimeError("unexpected socketpair restriction") from None
    else:
        for connection in pair:
            connection.close()
        raise RuntimeError("planner socketpair creation allowed")


def _process_creation_blocked() -> None:
    try:
        pid = os.fork()
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise RuntimeError("unexpected process restriction") from None
        return
    if pid == 0:
        os._exit(78)
    # Refuse startup if a child could be created, but first terminate and reap
    # the unexpected child. Never leave a test witness running on failure.
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.waitpid(pid, 0)
    raise RuntimeError("planner process creation allowed")


def _namespace_creation_blocked() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    if libc.unshare(0x10000000) != -1 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError("planner namespace creation allowed")


def _root_read_only() -> None:
    witness = "/planner-write-witness"
    try:
        fd = os.open(witness, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise RuntimeError("planner root was not verified read-only") from None
        return
    try:
        os.close(fd)
    finally:
        os.unlink(witness)
    raise RuntimeError("planner root is writable")


def _bootstrap(host: dict[str, str]) -> dict[str, bool]:
    _private_namespaces(host)
    _zero_capabilities()
    _no_new_privileges()
    _set_limits()
    _install_syscall_filter()
    _sockets_blocked()
    _process_creation_blocked()
    _namespace_creation_blocked()
    _root_read_only()
    return {name: True for name in BOUNDARY_NAMES}


def _load_planner():
    spec = importlib.util.spec_from_file_location("secure_fixed_session_planner", PLANNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing fixed planner")
    planner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(planner)
    return planner


def main() -> int:
    try:
        scenario, host = _arguments(sys.argv[1:])
        checks = _bootstrap(host)
        raw = sys.stdin.buffer.read(MAX_OBSERVATION_BYTES + 1)
        if len(raw) > MAX_OBSERVATION_BYTES:
            raise ValueError("planner observation too large")
        planner = _load_planner()
        proposal = planner.proposal(scenario, planner._observation(raw))
        if type(proposal) is not dict:
            raise ValueError("invalid planner proposal")
        encoded = json.dumps(proposal, sort_keys=True, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode("ascii")) > MAX_PROPOSAL_BYTES:
            raise ValueError("planner proposal too large")
        envelope = {"schema_version": "1", "proposal": proposal, "boundary_checks": checks}
        encoded = json.dumps(envelope, sort_keys=True, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode("ascii")) + 1 > MAX_TRANSPORT_BYTES:
            raise ValueError("planner transport too large")
        sys.stdout.write(encoded + "\n")
    except Exception:
        # Static diagnostics only: never echo observations, paths, proposal
        # fragments, environment values or loader/OS exception messages.
        sys.stderr.write("secure_planner_setup_failed\n")
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
