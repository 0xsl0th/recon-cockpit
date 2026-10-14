"""One authority-bound ffuf exec with no diagnostic or owner modules mounted."""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError as error:
                if error.errno != 9:
                    raise
            else:
                raise ValueError("web_hierarchy_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("network_web_hierarchy_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import hashlib
import resource
import socket
import stat
import time

from recon_cockpit.secure_agent import network_tools_web_hierarchy_runtime as runtime
from recon_cockpit.secure_agent import tool_worker_common as common, worker


def close_private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.close(int(name))
            except OSError as error:
                if error.errno != 9:
                    raise


def namespaces(request):
    if sys.platform != "linux" or os.getuid() != 0 or os.getgid() != 0:
        raise ValueError("invalid_web_hierarchy_namespace_identity")
    for name in ("user", "net", "mnt", "pid"):
        current = os.readlink("/proc/self/ns/" + name)
        if current == request["host_namespaces"][name]:
            raise ValueError("web_hierarchy_host_namespace")
        if ((name == "net" and current != request["lab_namespaces"][name])
                or (name != "net" and current == request["lab_namespaces"][name])):
            raise ValueError("web_hierarchy_owner_namespace_mismatch")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("web_hierarchy_interface_mismatch")
    with open("/proc/self/uid_map", encoding="ascii") as source:
        if [tuple(map(int, line.split())) for line in source] != [(0, 0, 1)]:
            raise ValueError("web_hierarchy_uid_mapping")
    if int(worker._status()["CapEff"], 16) & (1 << 12):
        raise ValueError("web_hierarchy_net_admin_forbidden")


def limits():
    for kind, maximum in ((resource.RLIMIT_AS, 2048 * 1024 * 1024), (resource.RLIMIT_CPU, 5),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 16),
                           (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))


def verify_files(manifest):
    runtime.validate_manifest(manifest)
    for item in manifest["files"]:
        fd = os.open(item["destination"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != item["size"]:
                raise ValueError("web_hierarchy_mounted_size_mismatch")
            with os.fdopen(os.dup(fd), "rb") as source:
                raw = source.read(item["size"] + 1)
            if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ValueError("web_hierarchy_mounted_hash_mismatch")
            if item["destination"] == manifest["executable"] and not raw.startswith(b"\x7fELF"):
                raise ValueError("web_hierarchy_requires_ffuf_elf")
            if "security.capability" in os.listxattr(fd):
                raise ValueError("web_hierarchy_file_capabilities")
        finally:
            os.close(fd)
    if os.listdir(runtime.SCRAPER_DIRECTORY):
        raise ValueError("web_hierarchy_scraper_directory_not_empty")


def permissions(manifest):
    value = {item["destination"]: 4 for item in runtime.validate_manifest(manifest)["files"]}
    value[manifest["executable"]] |= 1
    value[manifest["interpreter"]] |= 1
    value.update({"/dev/null": 6, "/dev/random": 4, "/dev/urandom": 4,
                  "/proc/self/status": 4, "/tool/data": 8, runtime.SCRAPER_DIRECTORY: 8})
    return value


def transport_witnesses():
    try:
        descriptor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except PermissionError as error:
        if error.errno != 1:
            raise
    else:
        descriptor.close()
        raise ValueError("web_hierarchy_udp_allowed")


def main():
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("web_hierarchy_requires_authority_pipe")
        request = runtime.consume_launch(sys.stdin.buffer.read(runtime.MAX_LAUNCH_BYTES + 1),
                                         sys.argv[1], sys.argv[2])
        namespaces(request)
        manifest = request["manifest"]
        verify_files(manifest)
        limits()
        worker.drop_privileges()
        common.syscall_filter(allow_threads=True)
        common._witnesses()
        common._thread_bound_witness()
        transport_witnesses()
        sys.stdin.close()
        close_private_descriptors()
        private_descriptors()
        try:
            os.close(0)
        except OSError as error:
            if error.errno != 9:
                raise
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        common.apply_landlock(permissions(manifest))
        if time.monotonic() >= request["deadline"]:
            raise ValueError("web_hierarchy_authority_expired")
        os.write(2, runtime.READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        os.execve(runtime.FIXED_ARGV[0], runtime.FIXED_ARGV, dict(runtime.ENVIRONMENT))
    except Exception:
        sys.stderr.write("network_web_hierarchy_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
