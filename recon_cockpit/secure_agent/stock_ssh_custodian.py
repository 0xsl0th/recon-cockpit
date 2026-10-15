"""Fail-closed Linux x86_64 custody of one fixed OpenSSH inetd instance.

This module issues no authority and starts no host service. The owning launcher
must first create the sealed, disconnected namespace and verify admission.
"""

import base64
import ctypes
import errno
import math
import os
import platform
import resource
import signal
import socket
import struct
import time

from . import stock_ssh_process as process
from . import stock_ssh_runtime as runtime
from . import tool_worker_common as common
from . import worker

TRACEME, PEEKDATA, CONT, GETREGS, SETOPTIONS, GETEVENTMSG = 0, 2, 7, 12, 0x4200, 0x4201
OPTIONS = 0x00100000 | 0x80 | 0x02 | 0x04 | 0x08 | 0x10  # EXITKILL, SECCOMP, FORK/VFORK/CLONE/EXEC
WALL = 0x40000000
SYS_CLONE, SYS_FORK, SYS_EXECVE = 56, 57, 59
MAX_STDERR = 65536
MAX_EVENTS = 128
MAX_ARGUMENT = 256
MAX_VECTOR = 16
_LIBC = None
_SECCOMP = None
_CONFINED = False


def _libc():
    global _LIBC
    if _LIBC is None:
        _LIBC = ctypes.CDLL(None, use_errno=True)
        _LIBC.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        _LIBC.ptrace.restype = ctypes.c_long
    return _LIBC


def ptrace(request, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = _libc().ptrace(request, pid, address, data)
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, "stock_ssh_ptrace_failed")
    return result


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
        ("r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx",
         "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base",
         "gs_base", "ds", "es", "fs", "gs")]


def registers(pid):
    value = Registers()
    ptrace(GETREGS, pid, 0, ctypes.byref(value))
    if value.cs != 0x33:
        raise ValueError("stock_ssh_unreviewed_syscall_abi")
    return value


def _word(pid, address):
    if not 0 < address < 2**47 - 8:
        raise ValueError("stock_ssh_invalid_tracee_pointer")
    return ptrace(PEEKDATA, pid, address) & ((1 << 64) - 1)


def _string(pid, address):
    raw = bytearray()
    while len(raw) <= MAX_ARGUMENT:
        block = _word(pid, address + len(raw)).to_bytes(8, "little")
        end = block.find(b"\0")
        raw += block if end < 0 else block[:end]
        if end >= 0:
            if len(raw) > MAX_ARGUMENT:
                break
            return bytes(raw).decode("ascii")
    raise ValueError("stock_ssh_tracee_argument_limit")


def _vector(pid, address):
    values = []
    for index in range(MAX_VECTOR + 1):
        pointer = _word(pid, address + index * 8)
        if pointer == 0:
            return tuple(values)
        if index == MAX_VECTOR:
            break
        values.append(_string(pid, pointer))
    raise ValueError("stock_ssh_tracee_vector_limit")


def _exec_arguments(pid, regs):
    filename = _string(pid, regs.rdi)
    argv = _vector(pid, regs.rsi)
    environment = {}
    for item in _vector(pid, regs.rdx):
        key, separator, value = item.partition("=")
        if not separator or not key or key in environment:
            raise ValueError("stock_ssh_invalid_tracee_environment")
        environment[key] = value
    return filename, argv, environment


def _seccomp():
    global _SECCOMP
    if _SECCOMP is None:
        _SECCOMP = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    return _SECCOMP


def syscall_filter(*, custodian):
    """Only finite process changes reach the custodian; network creation cannot."""
    class Argument(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

    library = _seccomp()
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                             ctypes.c_uint, ctypes.POINTER(Argument)]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise RuntimeError("stock_ssh_seccomp_init_failed")
    try:
        def rule(name, action, comparisons=()):
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number == -1 or library.seccomp_rule_add_array(context, action, number, len(comparisons),
                    (Argument * len(comparisons))(*comparisons)) != 0:
                raise RuntimeError("stock_ssh_seccomp_rule_failed:" + name)
        deny = 0x00050000 | errno.EPERM
        for name in ("execveat", "vfork", "unshare", "setns", "mount", "umount2", "pivot_root", "chroot",
                     "process_vm_readv", "process_vm_writev", "pidfd_open", "pidfd_getfd", "pidfd_send_signal",
                     "bpf", "keyctl", "add_key",
                     "request_key", "perf_event_open", "userfaultfd", "io_uring_setup", "memfd_create",
                     "open_by_handle_at", "socket", "socketcall", "connect", "bind", "listen", "accept",
                     "accept4", "shmat", "shmget", "shmctl", "shmdt"):
            rule(name, deny)
        rule("clone3", 0x00050000 | errno.ENOSYS)
        # MAP_SHARED and MAP_SHARED_VALIDATE both have bit zero set.
        rule("mmap", deny, (Argument(3, 7, 1, 1),))
        if custodian:
            # Parent is untraced, so its own attempted exec fails ENOSYS.
            # Traced children inherit this and add the finite fork gate.
            rule("execve", 0x7FF00000)
            rule("clone", deny, (Argument(0, 1, process.FORK_CLONE_FLAGS, 0),))
        else:
            rule("ptrace", deny)
            for name in ("clone", "fork", "execve"):
                rule(name, 0x7FF00000)
        rule("socketpair", deny, (Argument(0, 1, socket.AF_UNIX, 0),))
        # Both reviewed OpenSSH internal channels use exactly SOCK_STREAM.
        rule("socketpair", deny, (Argument(1, 1, socket.SOCK_STREAM, 0),))
        rule("socketpair", deny, (Argument(2, 1, 0, 0),))
        if library.seccomp_load(context) != 0:
            raise RuntimeError("stock_ssh_seccomp_load_failed")
    finally:
        library.seccomp_release(context)


def tracee_filter():
    syscall_filter(custodian=False)


def confine_custodian(manifest):
    """Tighten the trusted owner once; children add their stricter filter."""
    global _CONFINED
    if _CONFINED:
        return
    _libc()
    _seccomp()
    # Parent must read private-namespace process identities and immutable files.
    # No writes or general interpreter reads remain. The child removes /proc.
    permissions = {row["destination"]: (5 if row["destination"] in process.EXECUTABLES or
                    row["destination"] == manifest["interpreter"] else 4) for row in manifest["files"]}
    permissions.update({"/proc": 4 | 8, "/dev/null": 6})
    common.apply_landlock(permissions)
    syscall_filter(custodian=True)
    _CONFINED = True


def _identity():
    status = worker._status()
    if (platform.machine() != "x86_64" or os.getpid() != 1
            or os.getresuid() != (65534, 65534, 65534) or os.getresgid() != (65534, 65534, 65534)
            or status["NoNewPrivs"] != "1"
            or any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or common._namespace_task_count() != 1):
        raise ValueError("stock_ssh_custodian_identity_invalid")


def _limits():
    for limit, value in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_NOFILE, 64),
                         (resource.RLIMIT_NPROC, 4), (resource.RLIMIT_CORE, 0),
                         (resource.RLIMIT_FSIZE, 0)):
        resource.setrlimit(limit, (value, value))


def connected_identity(descriptor):
    channel = socket.socket(fileno=os.dup(descriptor))
    try:
        if (channel.family != socket.AF_INET or channel.type != socket.SOCK_STREAM
                or channel.getsockopt(socket.SOL_SOCKET, 38) != socket.IPPROTO_TCP):
            raise ValueError("stock_ssh_requires_connected_tcp")
        local, peer = channel.getsockname(), channel.getpeername()
        if local[0] != "127.0.0.1" or peer[0] != "127.0.0.1" or not local[1] or not peer[1]:
            raise ValueError("stock_ssh_requires_private_tcp")
        return {"inode": os.fstat(descriptor).st_ino, "local": list(local), "peer": list(peer),
                "netns_cookie": struct.unpack("=Q", channel.getsockopt(socket.SOL_SOCKET, 71, 8))[0]}
    finally:
        channel.close()


def _child(connected_fd, error_fd, manifest):
    try:
        os.dup2(connected_fd, 0)
        os.dup2(connected_fd, 1)
        os.dup2(error_fd, 2)
        os.set_blocking(0, True)
        for descriptor in range(3, 64):
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
        ptrace(TRACEME, 0)
        os.kill(os.getpid(), signal.SIGSTOP)
        permissions = {row["destination"]: (5 if row["destination"] in process.EXECUTABLES or
                        row["destination"] == manifest["interpreter"] else 4) for row in manifest["files"]}
        permissions["/dev/null"] = 6
        tracee_filter()
        common.apply_landlock(permissions)
        os.execve(process.ARGV[0][0], process.ARGV[0], process.ENVIRONMENT)
    except BaseException as error:
        os.write(2, ("stock_ssh_tracee_bootstrap_refused:" + type(error).__name__ + ":" + str(error)[:160] + "\n").encode("ascii", "replace"))
    os._exit(78)


def _drain(descriptor, output):
    while True:
        try:
            raw = os.read(descriptor, min(4096, MAX_STDERR + 1 - len(output)))
        except BlockingIOError:
            return
        if not raw:
            return
        output.extend(raw)
        if len(output) > MAX_STDERR:
            raise ValueError("stock_ssh_stderr_limit")


def run_instance(connected_fd, manifest, *, deadline, cancelled=None):
    """Run only inside an admitted owner's namespace; never opens a connection."""
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - time.monotonic() <= 5):
        raise ValueError("stock_ssh_instance_deadline_invalid")
    manifest = runtime.validate_manifest(manifest)
    _identity()
    identity = connected_identity(connected_fd)
    _limits()
    _libc()
    confine_custodian(manifest)
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    child = os.fork()
    if child == 0:
        _child(connected_fd, write_fd, manifest)
    os.close(write_fd)
    ledger = process.ProcessLedger(child)
    stderr = bytearray()
    early_stops = set()
    attached = False
    stop_reason = "processes_exited"
    started = time.monotonic()
    try:
        while len(ledger.exited) < len(ledger.roles) or common._namespace_task_count() != 1:
            if time.monotonic() >= deadline:
                raise TimeoutError("stock_ssh_instance_timeout")
            if cancelled is not None and cancelled():
                raise InterruptedError("stock_ssh_instance_cancelled")
            _drain(read_fd, stderr)
            if len(ledger.events) > MAX_EVENTS:
                raise ValueError("stock_ssh_process_event_limit")
            try:
                pid, status = os.waitpid(-1, os.WNOHANG | WALL)
            except ChildProcessError:
                if set(ledger.roles) == ledger.exited and common._namespace_task_count() == 1:
                    break
                raise
            if pid == 0:
                time.sleep(0.001)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                if pid not in ledger.exited:
                    ledger.exit(pid, os.waitstatus_to_exitcode(status))
                continue
            if not os.WIFSTOPPED(status):
                raise ValueError("stock_ssh_invalid_wait_status")
            event, sig = status >> 16, os.WSTOPSIG(status)
            if not attached:
                if pid != child or event or sig != signal.SIGSTOP:
                    raise ValueError("stock_ssh_initial_stop_invalid")
                ptrace(SETOPTIONS, child, 0, OPTIONS)
                attached = True
            elif pid not in ledger.roles:
                if event or sig != signal.SIGSTOP or early_stops:
                    raise ValueError("stock_ssh_unknown_child_stop")
                early_stops.add(pid)
                continue
            elif event == 7:
                regs = registers(pid)
                if regs.orig_rax == SYS_EXECVE:
                    ledger.request_exec(pid, *_exec_arguments(pid, regs))
                elif regs.orig_rax in (SYS_FORK, SYS_CLONE):
                    ledger.request_fork(pid, syscall="fork" if regs.orig_rax == SYS_FORK else "clone",
                                        flags=0 if regs.orig_rax == SYS_FORK else regs.rdi)
                else:
                    raise ValueError("stock_ssh_unexpected_seccomp_event")
            elif event in (1, 2, 3):
                if event != 1:
                    raise ValueError("stock_ssh_unexpected_clone_event")
                message = ctypes.c_ulonglong()
                ptrace(GETEVENTMSG, pid, 0, ctypes.byref(message))
                ledger.fork_completed(pid, message.value)
                if message.value in early_stops:
                    early_stops.remove(message.value)
                    ptrace(CONT, message.value)
            elif event == 4:
                index = ledger.pending_execs.get(pid)
                if index is None:
                    raise ValueError("stock_ssh_unexpected_exec_event")
                expected = process.EXECUTABLES[index]
                actual_info, pinned_info = os.stat("/proc/" + str(pid) + "/exe"), os.stat(expected)
                if (actual_info.st_dev, actual_info.st_ino) != (pinned_info.st_dev, pinned_info.st_ino):
                    raise ValueError("stock_ssh_exec_inode_changed")
                ledger.exec_completed(pid, expected)
            elif event or sig not in (signal.SIGSTOP, signal.SIGCHLD):
                # Do not deliver arbitrary signals between argument validation
                # and execution. Unexpected events fail closed.
                raise ValueError("stock_ssh_unexpected_trace_stop")
            ptrace(CONT, pid)
        _drain(read_fd, stderr)
    except BaseException as error:
        stop_reason = str(error) if str(error) in process.STOP_REASONS else "stock_ssh_custody_error"
        # No untrusted syscall is resumed on an error. Kill the entire private
        # PID namespace's descendants, including a just-created ptrace child.
        for name in os.listdir("/proc"):
            if name.isdecimal() and int(name) > 1:
                try:
                    os.kill(int(name), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        until = time.monotonic() + 1
        while time.monotonic() < until:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG | WALL)
            except ChildProcessError:
                break
            if pid == 0:
                time.sleep(0.001)
            elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                if pid in ledger.roles and pid not in ledger.exited:
                    ledger.exit(pid, os.waitstatus_to_exitcode(status))
            else:
                try:
                    ptrace(CONT, pid, 0, signal.SIGKILL)
                except OSError:
                    pass
    finally:
        os.close(read_fd)
    if common._namespace_task_count() != 1 or set(ledger.roles) != ledger.exited:
        raise RuntimeError("stock_ssh_process_cleanup_failed")
    return {**ledger.receipt(), "stop_reason": stop_reason, "descriptor": identity,
            "stderr_base64": base64.b64encode(bytes(stderr[:MAX_STDERR])).decode("ascii"),
            "stderr_truncated": len(stderr) > MAX_STDERR,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
