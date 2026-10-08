"""Trusted setup for the separately bounded static Nuclei scratch profile.

CAP_SYS_ADMIN exists only until a private fixed tmpfs has been mounted and
measured. No native tool runs before all capabilities, mount authority and
unreviewed file access are removed and the kernel witnesses have passed.
"""

import os
import sys

if __name__ == "__main__":
    try:
        for name in os.listdir("/proc/self/fd"):
            if int(name) > 2:
                try:
                    os.fstat(int(name))
                except OSError:
                    continue
                raise ValueError("nuclei_inherited_descriptor")
    except Exception:
        sys.stderr.write("nuclei_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import ctypes
import errno
import json
from pathlib import Path
import resource
import signal
import stat

from recon_cockpit.secure_agent import network_tools_nuclei_runtime as runtime
from recon_cockpit.secure_agent import network_tools_runtime as shared_runtime
from recon_cockpit.secure_agent import network_tools_worker as shared_worker
from recon_cockpit.secure_agent import tool_worker_common as common, worker
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.network_tools_execution import consume_launch
from recon_cockpit.secure_agent.owned_lab_executor import assert_lab_namespaces


def _limits():
    for kind, maximum in ((resource.RLIMIT_AS, 2 * 1024 * 1024 * 1024), (resource.RLIMIT_CPU, 5),
            (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 16), (resource.RLIMIT_CORE, 0),
            (resource.RLIMIT_FSIZE, runtime.MAX_WRITE_BYTES)):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))


def mount_scratch():
    if not stat.S_ISDIR(os.lstat(runtime.SCRATCH).st_mode) or os.listdir(runtime.SCRATCH):
        raise ValueError("nuclei_scratch_mountpoint")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)
    libc.mount.restype = ctypes.c_int
    options = f"size={runtime.SCRATCH_BYTES},nr_inodes={runtime.SCRATCH_INODES},mode=0700".encode("ascii")
    # MS_NOSUID | MS_NODEV | MS_NOEXEC; never remount a shared or host path.
    if libc.mount(b"tmpfs", runtime.SCRATCH.encode("ascii"), b"tmpfs", 2 | 4 | 8, options) != 0:
        raise OSError(ctypes.get_errno(), "nuclei_private_scratch_mount")
    verify_scratch_mount()


def verify_scratch_mount():
    entries = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[4] == runtime.SCRATCH:
            marker = fields.index("-")
            entries.append((set(fields[5].split(",")), fields[marker + 1]))
    value = os.statvfs(runtime.SCRATCH)
    if (len(entries) != 1 or entries[0][1] != "tmpfs"
            or not {"rw", "nosuid", "nodev", "noexec"} <= entries[0][0]
            or value.f_frsize * value.f_blocks != runtime.SCRATCH_BYTES
            or value.f_files != runtime.SCRATCH_INODES):
        raise ValueError("nuclei_scratch_kernel_limits")


def scratch_allocation_witness(control):
    """Before setting FSIZE, prove the aggregate tmpfs byte and inode ceilings.

The witness writes at most eight MiB plus one attempted page, then removes its
data. A 64 KiB FSIZE cap would otherwise exhaust 128 inodes before eight MiB.
"""
    path = runtime.SCRATCH + "/allocation-witness"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    total, denied = 0, False
    try:
        chunk = b"\0" * 65536
        while total <= runtime.SCRATCH_BYTES:
            control.check()
            try:
                count = os.write(fd, chunk if total < runtime.SCRATCH_BYTES else b"\0")
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                denied = True
                break
            if count <= 0:
                raise RuntimeError("nuclei_scratch_write_stalled")
            total += count
        if not denied or total != runtime.SCRATCH_BYTES:
            raise RuntimeError("nuclei_scratch_byte_limit_unproved")
    finally:
        os.close(fd)
        os.unlink(path)
    paths = []
    denied = False
    try:
        for index in range(runtime.SCRATCH_INODES):
            control.check()
            path = runtime.SCRATCH + "/inode-" + str(index)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                denied = True
                break
            os.close(fd)
            paths.append(path)
        # The mount root consumes precisely one inode before seeding.
        if not denied or len(paths) != runtime.SCRATCH_INODES - 1:
            raise RuntimeError("nuclei_scratch_inode_limit_unproved")
    finally:
        for path in paths:
            os.unlink(path)
    if os.listdir(runtime.SCRATCH):
        raise RuntimeError("nuclei_scratch_witness_cleanup")
    verify_scratch_mount()


def seed_scratch():
    for path in ("/scratch/home/.config/nuclei", "/scratch/config", "/scratch/cache", "/scratch/tmp"):
        os.makedirs(path, mode=0o700)
    for source, destination in runtime.CONFIG_SEEDS:
        raw = Path(source).read_bytes()
        expected = next(data for _, path, data in runtime.COMPILED if path == source)
        if raw != expected:
            raise ValueError("nuclei_config_seed_mismatch")
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            if os.write(descriptor, raw) != len(raw):
                raise ValueError("nuclei_config_seed_truncated")
        finally:
            os.close(descriptor)


def landlock_permissions(value):
    permissions = {row["destination"]: 4 for row in value["files"]}
    permissions[runtime.DESTINATION] |= 1
    # READ_DIR on immutable template/config directories confers no file access.
    permissions.update({"/tool/data": 8, "/dev/null": 4, "/dev/urandom": 4,
                        "/dev/random": 4, "/proc/self/status": 4})
    # Ordinary files/directories and rename only: no execute, devices, sockets,
    # FIFOs or symbolic links. Existing profiles' allowlists remain unchanged.
    permissions[runtime.SCRATCH] = 2 | 4 | 8 | 16 | 32 | 128 | 256 | 8192 | 16384
    return permissions


def scratch_execution_and_file_witness():
    path = runtime.SCRATCH + "/file-witness"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        os.write(fd, b"\0" * 4096)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long)
        libc.mmap.restype = ctypes.c_void_p
        address = libc.mmap(None, 4096, 1 | 4, 2, fd, 0)  # PROT_READ|EXEC, MAP_PRIVATE
        if address != ctypes.c_void_p(-1).value:
            libc.munmap(ctypes.c_void_p(address), 4096)
            raise RuntimeError("nuclei_scratch_executable")
        if ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("nuclei_scratch_noexec_not_witnessed")
        # SIGXFSZ would terminate a Python witness; restore its prior disposition
        # before exec so the native client does not inherit this temporary ignore.
        previous = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        try:
            os.ftruncate(fd, runtime.MAX_WRITE_BYTES)
            try:
                os.ftruncate(fd, runtime.MAX_WRITE_BYTES + 1)
            except OSError as exc:
                if exc.errno != errno.EFBIG:
                    raise
            else:
                raise RuntimeError("nuclei_file_write_limit_unproved")
        finally:
            signal.signal(signal.SIGXFSZ, previous)
    finally:
        os.close(fd)
        os.unlink(path)
    for path in ("/tool/data/config.yaml", "/tool/nuclei", "/dev/urandom"):
        try:
            descriptor = os.open(path, os.O_WRONLY)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
                raise
        else:
            os.close(descriptor)
            raise RuntimeError("nuclei_write_outside_scratch")


def close_authority_descriptors():
    sys.stdin.close()
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.close(int(name))
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
    try:
        os.close(0)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    os.dup2(descriptor, 0, inheritable=True)
    if descriptor != 0:
        os.close(descriptor)
    else:
        os.set_inheritable(0, True)


def main():
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("nuclei_requires_authority_pipe")
        raw = sys.stdin.buffer.read(32769)
        request, deadline, namespaces, digest = consume_launch(raw, sys.argv[1], sys.argv[2])
        if request["tool_id"] != runtime.TOOL_ID:
            raise ValueError("nuclei_worker_cross_profile")
        value = json.loads(raw)["runtime"]
        if shared_runtime.manifest_digest(value) != digest:
            raise ValueError("nuclei_runtime_commitment")
        assert_lab_namespaces(request["host_namespaces"], namespaces)
        control = ExecutionControl(deadline)
        runtime.verify_mounted(value, control)
        mount_scratch()
        scratch_allocation_witness(control)
        seed_scratch()
        _limits()
        worker.drop_privileges()
        common.syscall_filter(allow_threads=True)
        common._witnesses()
        common._thread_bound_witness()
        shared_worker._metadata_transport_witness()
        close_authority_descriptors()
        common.apply_landlock(landlock_permissions(value))
        scratch_execution_and_file_witness()
        control.check()
        os.write(2, shared_runtime.READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        os.execve(runtime.DESTINATION, runtime.FIXED_ARGV, dict(runtime.ENVIRONMENT))
    except Exception:
        sys.stderr.write("nuclei_worker_refused\n")
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
