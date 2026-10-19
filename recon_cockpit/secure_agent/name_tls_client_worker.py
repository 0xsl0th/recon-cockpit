"""One fixed name-bound native client in its independently filtered network."""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        number = int(name)
        if number > 2:
            try:
                os.fstat(number)
            except OSError:
                continue
            raise ValueError("name_tls_client_inherited_descriptor")


ENTRY_VERIFIED = False
if __name__ == "__main__":
    private_descriptors()
    ENTRY_VERIFIED = True
    sys.path.insert(0, "/app")

import ctypes
import errno
import hashlib
import math
import resource
import signal
import socket
import stat
import time

from recon_cockpit.secure_agent import worker, tool_worker_common as common
from recon_cockpit.secure_agent import name_tls_public as public, name_tls_contract as contract
from recon_cockpit.secure_agent import name_tls_role_spec as roles
from recon_cockpit.secure_agent import name_tls_worker_common as boundary
from recon_cockpit.secure_agent.name_tls_execution import consume_launch

READY_PREFIX = b"RECON_NAME_TLS_CLIENT_READY_V1 "
BOUNDARY_NAMES = ("private_namespaces", "routed_namespace", "uid_mapping", "capabilities_dropped",
    "no_new_privs", "read_only_root", "wrong_port_blocked", "other_service_blocked",
    "excluded_blocked", "udp_blocked", "ipv6_blocked", "unix_blocked", "fork_blocked",
    "namespace_creation_blocked", "owner_material_absent", "landlock_applied", "python_unreadable")


def assert_namespaces(host, routed):
    if os.getuid() != 65534 or os.getgid() != 65534:
        raise ValueError("name_tls_client_uid")
    for name in ("user", "net", "mnt", "pid"):
        current = os.readlink("/proc/self/ns/" + name)
        if current == host[name] or name == "net" and current != routed[name]:
            raise ValueError("name_tls_client_namespace")
    for name in ("uid", "gid"):
        rows = [tuple(map(int, row.split())) for row in open("/proc/self/" + name + "_map", encoding="ascii")]
        if len(rows) != 1 or rows[0][0] != 65534 or rows[0][2] != 1:
            raise ValueError("name_tls_client_mapping")


def verify_files(manifest):
    for row in roles.validate_manifest(manifest)["files"]:
        descriptor = os.open(row["destination"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            raw = bytearray()
            while len(raw) <= row["size"]:
                part = os.read(descriptor, min(65536, row["size"] + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            if (not stat.S_ISREG(before.st_mode) or len(raw) != row["size"]
                    or hashlib.sha256(raw).hexdigest() != row["sha256"]
                    or any(getattr(os.fstat(descriptor), field) != getattr(before, field)
                           for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"))):
                raise ValueError("name_tls_client_file_changed")
        finally:
            os.close(descriptor)


def limits(operation):
    for kind, value in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 5),
                        (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 16 if operation == "dns" else 1),
                        (resource.RLIMIT_FSIZE, 0), (resource.RLIMIT_CORE, 0)):
        inherited = resource.getrlimit(kind)[1]
        value = value if inherited == resource.RLIM_INFINITY else min(value, inherited)
        resource.setrlimit(kind, (value, value))


def witnesses(operation, configuration):
    endpoints = public.endpoints(configuration)
    chosen = endpoints["resolver" if operation == "dns" else operation]
    other = endpoints["http" if operation == "dns" else "resolver"]
    for address in ((chosen["target"], chosen["port"] + 1),
                    (other["target"], other["port"]),
                    (endpoints["excluded_address"], chosen["port"])):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(.1)
            if probe.connect_ex(address) == 0:
                raise ValueError("name_tls_client_destination_allowed")
    for family, kind in ((socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_INET6, socket.SOCK_STREAM),
                         (socket.AF_UNIX, socket.SOCK_STREAM)):
        try:
            probe = socket.socket(family, kind)
        except PermissionError:
            continue
        probe.close()
        raise ValueError("name_tls_client_socket_allowed")
    try:
        pid = os.fork()
    except PermissionError:
        pass
    else:
        if not pid:
            os._exit(78)
        os.waitpid(pid, 0)
        raise ValueError("name_tls_client_fork_allowed")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x40000000) == 0 or ctypes.get_errno() != errno.EPERM:
        raise ValueError("name_tls_client_unshare_allowed")
    status = worker._status()
    if status["NoNewPrivs"] != "1" or any(int(status[k], 16) for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise ValueError("name_tls_client_capabilities")
    for path in ("/tool/dnsmasq", "/tool/nginx", "/tool/data/name-tls/server.key",
                 "/tool/data/name-tls/server.pem", "/app/recon_cockpit/secure_agent/name_tls_spec.py",
                 "/app/recon_cockpit/secure_agent/network_tools_tls_certificate_material.py"):
        if os.path.exists(path):
            raise ValueError("name_tls_client_owner_material")
    try:
        fd = os.open("/name-tls-root-write-probe", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise
    else:
        os.close(fd)
        raise ValueError("name_tls_client_writable_root")


def validate_go(raw, nonce, session_deadline, maximum):
    value = public.decode(raw, max_bytes=256)
    if (set(value) != {"nonce", "deadline"} or value["nonce"] != nonce
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not time.monotonic() < value["deadline"] <= session_deadline
            or value["deadline"] - time.monotonic() > maximum):
        raise ValueError("name_tls_client_release")
    return value["deadline"]


def main():
    try:
        boundary.close_import_descriptor(entry_verified=ENTRY_VERIFIED)
        payload_identity = boundary.namespace_identity()
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("name_tls_client_authority_pipe")
        raw = sys.stdin.buffer.readline(32770)
        if not raw.endswith(b"\n") or len(raw) > 32769:
            raise ValueError("name_tls_client_launch_frame")
        value, action = consume_launch(raw[:-1], sys.argv[1], sys.argv[2])
        selected, launch = value["selection"], value["launch"]
        operation = contract.operation(action.parameters.operation_slot)
        assert_namespaces(launch["host_namespaces"], value["namespaces"])
        manifest = value["runtime"]
        if manifest is not None:
            verify_files(manifest)
        limits(operation)
        worker.drop_privileges()
        boundary.seal_group_identity(payload_identity)
        common.syscall_filter(allow_threads=operation == "dns")
        if operation == "http":
            worker.install_syscall_filter()
        witnesses(operation, selected["configuration"])
        if operation == "dns":
            common._thread_bound_witness()
        permissions = {"/dev/null": 6, "/dev/urandom": 4, "/dev/random": 4, "/proc/self/status": 4}
        if manifest:
            permissions.update({row["destination"]: 5 if row["destination"] in
                (manifest["executable"], manifest["interpreter"]) else 4 for row in manifest["files"]})
            permissions["/tool/data/name-tls"] = 8
        common.apply_landlock(permissions)
        try:
            with open(__file__, "rb"):
                raise ValueError("name_tls_client_python_readable")
        except PermissionError:
            pass
        os.write(2, READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        deadline = validate_go(sys.stdin.buffer.readline(257), sys.argv[1], launch["deadline"], action.parameters.timeout_seconds)
        if sys.stdin.buffer.read(1):
            raise ValueError("name_tls_client_extra_input")
        sys.stdin.close()
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        signal.signal(signal.SIGALRM, worker._deadline)
        signal.setitimer(signal.ITIMER_REAL, max(.001, deadline - time.monotonic()))
        if operation == "http":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(max(.001, deadline - time.monotonic()))
                connection.connect((action.target, action.parameters.port))
                connection.sendall(public.request_bytes(selected["configuration"], selected["case"]))
                result = bytearray()
                while len(result) <= 2048:
                    connection.settimeout(max(.001, deadline - time.monotonic()))
                    part = connection.recv(2049 - len(result))
                    if not part:
                        break
                    result.extend(part)
                if len(result) > 2048:
                    raise ValueError("name_tls_http_output_limit")
                sys.stdout.buffer.write(result)
                sys.stdout.buffer.flush()
                return 0
        argv = (public.dns_argv if operation == "dns" else public.tls_argv)(selected["configuration"], selected["case"])
        os.execve(argv[0], argv, dict(public.ENVIRONMENT))
    except Exception as error:
        sys.stderr.write("name_tls_client_refused:" + type(error).__name__ + ":" + str(error)[:2048] + "\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
