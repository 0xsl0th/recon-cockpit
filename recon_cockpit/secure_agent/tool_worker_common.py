"""Reviewed ELF confinement mechanics; callers supply fixed profile allowlists."""

import ctypes
import errno
import os
from pathlib import Path
import platform
import socket

from . import worker


def apply_landlock(permissions):
    if platform.machine() not in {"x86_64", "aarch64"}:
        raise ValueError("unsupported_web_tool_landlock_architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, ctypes.c_void_p(), 0, 1)
    if abi < 3:
        raise ValueError("web_tool_requires_landlock_abi3")

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class PathRule(ctypes.Structure):
        _pack_ = 1
        _layout_ = "ms"
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    # ABI3 filesystem rights, including REFER and TRUNCATE. No writes allowed.
    ruleset = Ruleset((1 << 15) - 1)
    fd = libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "web_tool_landlock_create")
    try:
        for path, access in permissions.items():
            child = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(access, child)
                if libc.syscall(445, fd, 1, ctypes.byref(rule), 0) != 0:
                    raise OSError(ctypes.get_errno(), "web_tool_landlock_rule")
            finally:
                os.close(child)
        if libc.syscall(446, fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "web_tool_landlock_restrict")
    finally:
        os.close(fd)
    # Loader execution is safe only if a general interpreter cannot be read.
    try:
        blocked = os.open("/usr/bin/python3", os.O_RDONLY)
    except PermissionError:
        pass
    else:
        os.close(blocked)
        raise RuntimeError("web_tool_python_remained_readable")


def clone_denials():
    """Reject missing thread-sharing flags and every non-reviewed clone bit.

    Go and libc may request TLS and parent/child TID bookkeeping in addition to
    the common VM/FS/files/signal/thread/SysV sharing flags. No exit signal,
    process-style clone or namespace creation can pass these comparisons.
    """
    required = 0x00010000 | 0x00000100 | 0x00000800  # THREAD | VM | SIGHAND
    allowed = required | 0x00000200 | 0x00000400 | 0x00040000 | 0x00080000 | 0x00100000 | 0x00200000 | 0x01000000
    return tuple((1 << bit, 0 if required & (1 << bit) else 1 << bit)
                 for bit in range(64) if required & (1 << bit) or not allowed & (1 << bit))


def syscall_filter(*, allow_threads):
    if type(allow_threads) is not bool:
        raise ValueError("invalid_thread_profile")
    class Argument(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
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
        raise RuntimeError("web_tool_seccomp_failed")
    try:
        def deny(name, comparisons=(), error=errno.EPERM):
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number == -1:
                raise RuntimeError("web_tool_seccomp_missing_syscall")
            arguments = (Argument * len(comparisons))(*comparisons)
            if library.seccomp_rule_add_array(context, 0x00050000 | error,
                                              number, len(comparisons), arguments) != 0:
                raise RuntimeError("web_tool_seccomp_rule_failed")
        for name in ("execveat", "fork", "vfork", "unshare", "setns", "mount", "umount2",
                     "pivot_root", "chroot", "ptrace", "process_vm_readv", "process_vm_writev", "bpf", "keyctl",
                     "add_key", "request_key", "perf_event_open", "userfaultfd", "io_uring_setup", "memfd_create",
                     "open_by_handle_at", "socketpair", "socketcall"):
            deny(name)
        if allow_threads:
            # clone3's indirect argument block cannot be safely inspected by
            # classic seccomp. ENOSYS selects libc's reviewed clone fallback.
            deny("clone3", error=errno.ENOSYS)
            for mask, value in clone_denials():
                deny("clone", [Argument(0, 7, mask, value)])
        else:
            deny("clone")
            deny("clone3")
        # Only ordinary IPv4 stream sockets. Destination control remains nftables.
        deny("socket", [Argument(0, 1, socket.AF_INET, 0)])  # SCMP_CMP_NE
        for kind in range(16):
            if kind != socket.SOCK_STREAM:
                deny("socket", [Argument(1, 7, 0xF, kind)])  # SCMP_CMP_MASKED_EQ
        for protocol in range(1, socket.IPPROTO_TCP):
            deny("socket", [Argument(2, 4, protocol, 0)])  # SCMP_CMP_EQ
        deny("socket", [Argument(2, 6, socket.IPPROTO_TCP, 0)])  # SCMP_CMP_GT
        if library.seccomp_load(context) != 0:
            raise RuntimeError("web_tool_seccomp_load_failed")
    finally:
        library.seccomp_release(context)


def _namespace_task_count():
    """Count this private PID namespace's tasks sharing the mapped UID.

    Bubblewrap's PID-1 supervisor can consume a task under the same UID limit,
    in addition to this worker. No host PID is visible in the fresh namespace.
    """
    total = 0
    for name in os.listdir("/proc"):
        if not name.isdecimal():
            continue
        status = Path("/proc", name, "status").read_text(encoding="ascii")
        uids = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
        if uids != [[str(os.getuid())] * 4]:
            raise RuntimeError("web_tool_unexpected_namespace_task_identity")
        total += len(os.listdir("/proc/" + name + "/task"))
    return total


def _thread_bound_witness():
    """Prove a seventeenth mapped-UID task is denied by the kernel.

    Account for the private Bubblewrap supervisor and worker already charged
    to RLIMIT_NPROC. Hold threads until the total reaches sixteen, require one
    more creation to fail, and join all witnesses before the real exec.
    """
    import threading
    threading.stack_size(128 * 1024)
    baseline = _namespace_task_count()
    if not 1 <= baseline <= 4:
        raise RuntimeError("web_tool_unexpected_namespace_task_count")
    available = 16 - baseline
    released = threading.Event()
    threads = []
    denied = False
    try:
        for _ in range(available + 1):
            thread = threading.Thread(target=released.wait)
            try:
                thread.start()
            except RuntimeError:
                denied = True
                break
            threads.append(thread)
        if not denied or len(threads) != available or _namespace_task_count() != 16:
            raise RuntimeError("web_tool_thread_bound_not_verified")
    finally:
        released.set()
        for thread in threads:
            thread.join(timeout=1)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError("web_tool_thread_cleanup_failed")


def _witnesses(*, port=8080):
    # Only the two reviewed fixed owner profiles can select a witness port.
    if type(port) is not int or port not in (8080, 111):
        raise ValueError("unsupported_tool_boundary_port")
    worker.verify_network_boundary(port)
    try:
        process = os.fork()
    except PermissionError:
        pass
    else:
        if process == 0:
            os._exit(78)
        os.waitpid(process, 0)
        raise RuntimeError("web_tool_process_creation_allowed")
    for family in (socket.AF_INET, socket.AF_PACKET):
        try:
            descriptor = socket.socket(family, socket.SOCK_RAW)
        except PermissionError:
            continue
        else:
            descriptor.close()
            raise RuntimeError("web_tool_raw_socket_allowed")
    try:
        descriptor = os.open("/web-tool-write-witness", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise RuntimeError("web_tool_root_not_readonly") from None
    else:
        os.close(descriptor)
        raise RuntimeError("web_tool_root_writable")

