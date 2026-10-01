"""One independently authorized curl/ffuf exec under a distinct confinement profile.

Unlike the existing Python-only workers this profile permits exec of its small
read/execute allowlist. It does not claim seccomp counts or prohibits re-exec.
"""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError:
                continue
            raise ValueError("web_tool_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("web_tool_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import ctypes
import errno
import hashlib
import json
from pathlib import Path
import platform
import resource
import socket
import stat
import time

if __package__:
    from . import web_tools_runtime as runtime, worker
    from .web_tools_execution import consume_launch
    from .owned_lab_executor import assert_lab_namespaces
else:
    from recon_cockpit.secure_agent import web_tools_runtime as runtime, worker
    from recon_cockpit.secure_agent.web_tools_execution import consume_launch
    from recon_cockpit.secure_agent.owned_lab_executor import assert_lab_namespaces


def verify_files(manifest):
    runtime.validate_manifest(manifest)
    for item in manifest["files"]:
        raw = runtime._read_regular(item["destination"])
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("web_tool_mounted_runtime_mismatch")
        if item["destination"] == manifest["executable"] and not raw.startswith(b"\x7fELF"):
            raise ValueError("web_tool_requires_elf")
        if "security.capability" in os.listxattr(item["destination"]):
            raise ValueError("web_tools_runtime_file_capabilities")
    if manifest["tool_id"] == runtime.FFUF and os.listdir(runtime.FFUF_SCRAPER_DIRECTORY):
        raise ValueError("web_tool_scraper_directory_not_empty")


def _landlock_permissions(manifest):
    permissions = {item["destination"]: 4 for item in manifest["files"]}
    permissions[manifest["executable"]] |= 1
    permissions[manifest["interpreter"]] |= 1
    permissions.update({"/dev/null": 6, "/dev/urandom": 4, "/dev/random": 4,
                        "/proc/self/status": 4, "/tool/data": 8})
    if manifest["tool_id"] == runtime.FFUF:
        # READ_DIR only: no config or scraper file can be read or created.
        permissions[runtime.FFUF_SCRAPER_DIRECTORY] = 8
    return permissions


def landlock(manifest):
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
        for path, access in _landlock_permissions(manifest).items():
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


def syscall_filter(tool_id):
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
        if tool_id == runtime.FFUF:
            # clone3's indirect argument block cannot be safely inspected by
            # classic seccomp. ENOSYS selects libc's reviewed clone fallback.
            deny("clone3", error=errno.ENOSYS)
            for mask, value in clone_denials():
                deny("clone", [Argument(0, 7, mask, value)])
        elif tool_id == runtime.CURL:
            deny("clone")
            deny("clone3")
        else:
            raise ValueError("unsupported_web_tool")
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


def _limits(tool_id):
    address_space = (2048 if tool_id == runtime.FFUF else 256) * 1024 * 1024
    threads = 16 if tool_id == runtime.FFUF else 1
    for kind, maximum in ((resource.RLIMIT_AS, address_space), (resource.RLIMIT_CPU, 5),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, threads),
                           (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))


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


def _witnesses():
    worker.verify_network_boundary(8080)
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


def main():
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("web_tool_requires_authority_pipe")
        raw = sys.stdin.buffer.read(32769)
        request, deadline, namespaces, digest = consume_launch(raw, sys.argv[1], sys.argv[2])
        manifest = json.loads(raw)["runtime"]
        if runtime.manifest_digest(manifest) != digest:
            raise ValueError("web_tools_runtime_commitment_mismatch")
        assert_lab_namespaces(request["host_namespaces"], namespaces)
        verify_files(manifest)
        _limits(request["tool_id"])
        worker.drop_privileges()
        syscall_filter(request["tool_id"])
        _witnesses()
        if request["tool_id"] == runtime.FFUF:
            _thread_bound_witness()
        # The authority stdin and any loader-retained descriptors are gone.
        sys.stdin.close()
        for name in os.listdir("/proc/self/fd"):
            if int(name) > 2:
                try:
                    os.close(int(name))
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
        landlock(manifest)
        if time.monotonic() >= deadline:
            raise TimeoutError("web_tool_authority_expired")
        # A closed stdin cannot become a new capability; Web tool reads no input.
        os.write(2, runtime.READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        argv = runtime.FIXED_ARGV[request["tool_id"]]
        os.execve(argv[0], argv, runtime.execution_environment(request["tool_id"]))
        return 78
    except Exception:
        sys.stderr.write("web_tool_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
