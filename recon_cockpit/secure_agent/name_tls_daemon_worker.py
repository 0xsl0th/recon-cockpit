"""Pre-exec setup for one finite daemon in a fresh disconnected namespace."""

import os
import sys

ENTRY_DESCRIPTORS_VERIFIED = False
if __name__ == "__main__":
    for _name in os.listdir("/proc/self/fd"):
        if int(_name) > 2:
            try:
                os.fstat(int(_name))
            except OSError:
                continue
            raise SystemExit(78)
    ENTRY_DESCRIPTORS_VERIFIED = True
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

from recon_cockpit.secure_agent import name_tls_daemon as daemon, name_tls_role_spec as roles
from recon_cockpit.secure_agent import name_tls_topology_worker as setup, worker, tool_worker_common as common
from recon_cockpit.secure_agent import name_tls_worker_common as bootstrap
from recon_cockpit.secure_agent.name_tls_topology_spec import endpoints, validate_namespace_identity
from recon_cockpit.secure_agent.name_tls_transport import (
    receive_packet, send_packet, socket_identity, assert_descriptor_copies)


def namespaces():
    return {name: os.readlink("/proc/self/ns/" + name) for name in ("user", "net", "mnt", "pid")}


def request(value):
    fields = {"selection", "manifest", "runtime_digest", "operation", "deadline", "host_namespaces"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("name_tls_daemon_request_shape")
    operation = value["operation"]
    manifest = roles.validate_manifest(value["manifest"], role=daemon.selected_role(operation))
    if (type(value["selection"]) is not dict or value["selection"].get("configuration") != manifest["configuration"]
            or value["selection"].get("case") != manifest["case"]
            or value["runtime_digest"] != roles.manifest_digest(manifest)
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("name_tls_daemon_request_identity")
    return value


def namespace_identity(host):
    bootstrap.assert_private_namespaces(host)
    if not os.statvfs("/").f_flag & os.ST_RDONLY or [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("name_tls_daemon_attached_namespace")
    result = setup._payload_identity()
    with open("/proc/self/setgroups", encoding="ascii") as source:
        if source.read(6) != "deny\n":
            raise ValueError("name_tls_daemon_mutable_group_mapping")
    return validate_namespace_identity(result)


def limits(deadline):
    for kind, maximum in ((resource.RLIMIT_AS, daemon.BOUNDS["address_space_bytes"]),
            (resource.RLIMIT_NOFILE, daemon.BOUNDS["file_descriptors"]),
            (resource.RLIMIT_FSIZE, daemon.BOUNDS["log_bytes"]), (resource.RLIMIT_CORE, 0),
            (resource.RLIMIT_CPU, daemon.BOUNDS["cpu_seconds"])):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))
    signal.signal(signal.SIGALRM, worker._deadline)
    signal.setitimer(signal.ITIMER_REAL, max(.001, min(2, deadline - time.monotonic())))


def firewall_rules(configuration, operation):
    target, port = endpoints(configuration)[operation]
    request_rule = f'ip daddr {target} tcp dport {port} ct direction original'
    reply_rule = f'ip saddr {target} tcp sport {port} ct direction reply ct state established'
    return ("table inet recon_name_tls_daemon {\n"
        " chain input { type filter hook input priority 0; policy drop;\n"
        f'  iifname "lo" {request_rule} accept\n  iifname "lo" {reply_rule} accept\n' " }\n"
        " chain output { type filter hook output priority 0; policy drop;\n"
        f'  oifname "lo" {request_rule} accept\n  oifname "lo" {reply_rule} accept\n' " }\n"
        " chain forward { type filter hook forward priority 0; policy drop; }\n}\n")


def prepare_network(configuration, operation, deadline):
    daemon.selected_role(operation)
    for name in ("all", "default"):
        with open("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", "w", encoding="ascii") as stream:
            stream.write("1\n")
    netlink = setup.Netlink()
    try:
        netlink.up("lo")
        netlink.address("lo", endpoints(configuration)[operation][0], 32)
    finally:
        netlink.close()
    if not setup._ipv6_disabled():
        raise ValueError("name_tls_daemon_ipv6_enabled")
    setup._nft(firewall_rules(configuration, operation), min(deadline, time.monotonic() + 2))


def socket_filter(operation):
    """No forks/connects; only declared IPv4 listeners and DNS route discovery."""
    daemon.selected_role(operation)
    class Argument(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int), ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]
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
        raise ValueError("name_tls_daemon_seccomp_init")
    try:
        def deny(name, comparisons=()):
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            args = (Argument * len(comparisons))(*comparisons)
            if number < 0 or library.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM, number, len(comparisons), args):
                raise ValueError("name_tls_daemon_seccomp_rule")
        for name in ("connect", "execveat", "fork", "vfork", "clone", "clone3", "unshare", "setns", "mount", "umount2",
                "pivot_root", "chroot", "ptrace", "process_vm_readv", "process_vm_writev", "pidfd_open", "pidfd_getfd",
                "pidfd_send_signal", "bpf", "keyctl", "add_key", "request_key", "perf_event_open", "userfaultfd",
                "io_uring_setup", "socketpair", "socketcall", "memfd_create", "open_by_handle_at"):
            deny(name)
        families = [socket.AF_INET] + ([socket.AF_NETLINK] if operation == "dns" else [])
        for family in range(max(families) + 1):
            if family not in families:
                deny("socket", (Argument(0, 4, family, 0),))
        deny("socket", (Argument(0, 6, max(families), 0),))
        kinds = (socket.SOCK_STREAM, socket.SOCK_DGRAM) if operation == "dns" else (socket.SOCK_STREAM,)
        for kind in range(16):
            if kind not in kinds:
                deny("socket", (Argument(0, 4, socket.AF_INET, 0), Argument(1, 7, 0xF, kind)))
        protocols = (0, socket.IPPROTO_TCP, socket.IPPROTO_UDP) if operation == "dns" else (0, socket.IPPROTO_TCP)
        # libseccomp rejects comparing the same argument twice in one rule.
        # Split the finite protocol holes and use one final greater-than bound.
        for protocol in range(max(protocols) + 1):
            if protocol not in protocols:
                deny("socket", (Argument(0, 4, socket.AF_INET, 0), Argument(2, 4, protocol, 0)))
        deny("socket", (Argument(0, 4, socket.AF_INET, 0), Argument(2, 6, max(protocols), 0)))
        if operation == "dns":
            for kind in range(16):
                if kind not in (socket.SOCK_RAW, socket.SOCK_DGRAM):
                    deny("socket", (Argument(0, 4, socket.AF_NETLINK, 0), Argument(1, 7, 0xF, kind)))
            deny("socket", (Argument(0, 4, socket.AF_NETLINK, 0), Argument(2, 1, socket.NETLINK_ROUTE, 0)))
        if library.seccomp_load(context):
            raise ValueError("name_tls_daemon_seccomp_load")
    finally:
        library.seccomp_release(context)


def confinement_witnesses(private_socket):
    status = worker._status()
    if status["NoNewPrivs"] != "1" or any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise ValueError("name_tls_daemon_privileges_retained")
    if os.getpid() != 1 or common._namespace_task_count() != 1:
        raise ValueError("name_tls_daemon_process_bound")
    for family, kind in ((socket.AF_INET6, socket.SOCK_STREAM), (socket.AF_PACKET, socket.SOCK_RAW), (socket.AF_UNIX, socket.SOCK_STREAM)):
        try:
            probe = socket.socket(family, kind)
        except PermissionError:
            continue
        probe.close()
        raise ValueError("name_tls_daemon_socket_family_allowed")
    if private_socket.connect_ex(("127.0.0.1", 1)) != errno.EPERM:
        raise ValueError("name_tls_daemon_outgoing_connect_allowed")
    try:
        pid = os.fork()
    except PermissionError:
        pass
    else:
        if pid == 0:
            os._exit(78)
        os.waitpid(pid, 0)
        raise ValueError("name_tls_daemon_fork_allowed")


def main():
    channel, private_socket = None, None
    try:
        if not ENTRY_DESCRIPTORS_VERIFIED or len(sys.argv) != 1:
            raise ValueError("name_tls_daemon_entry")
        setup.ENTRY_DESCRIPTORS_VERIFIED = True
        setup._close_import_descriptor()
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError("name_tls_daemon_control_channel")
        # Establish the final network before the parent pins this PID's actual
        # namespaces. Its owner must be this user namespace, not bwrap's
        # intermediate setup namespace; all setup capabilities are later lost.
        if setup.LIBC.unshare(setup.CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), "name_tls_daemon_create_network")
        send_packet(channel, {"bootstrap_waiting": True, "namespaces": namespaces()})
        value, _ = receive_packet(channel, descriptor_required=False)
        value = request(value)
        identity = namespace_identity(value["host_namespaces"])
        manifest, operation = value["manifest"], value["operation"]
        limits(value["deadline"])
        info = os.statvfs("/scratch")
        if info.f_blocks * info.f_frsize > daemon.SCRATCH_BYTES or info.f_flag & os.ST_RDONLY:
            raise ValueError("name_tls_daemon_scratch_bound")
        for row in manifest["files"]:
            descriptor = os.open(row["destination"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                raw = os.read(descriptor, roles.MAX_FILE_BYTES + 1)
                if (not stat.S_ISREG(info.st_mode) or len(raw) != row["size"]
                        or hashlib.sha256(raw).hexdigest() != row["sha256"]
                        or not os.statvfs(row["destination"]).f_flag & os.ST_RDONLY):
                    raise ValueError("name_tls_daemon_runtime_file_changed")
            finally:
                os.close(descriptor)
        prepare_network(manifest["configuration"], operation, value["deadline"])
        private_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        private_socket.setblocking(False)
        worker.drop_privileges()
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
        socket_filter(operation)
        confinement_witnesses(private_socket)
        if setup._payload_identity() != identity:
            raise ValueError("name_tls_daemon_identity_changed")
        try:
            os.setgroups(identity["groups"])
        except PermissionError:
            pass
        else:
            raise ValueError("name_tls_daemon_group_mutation_allowed")
        private_identity = socket_identity(private_socket)
        assert_descriptor_copies(private_identity, (private_socket.fileno(),))
        ready = {"namespaces": namespaces(), "namespace_identity": identity, "bounds": dict(daemon.BOUNDS),
            "runtime_digest": value["runtime_digest"], "operation": operation, "descriptor": private_identity}
        send_packet(channel, ready, private_socket.fileno())
        private_socket.close()
        private_socket = None
        assert_descriptor_copies(private_identity, ())
        channel.close()
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        if descriptor != 0:
            os.dup2(descriptor, 0, inheritable=True)
            os.close(descriptor)
        else:
            os.set_inheritable(0, True)
        for name in os.listdir("/proc/self/fd"):
            if int(name) > 2:
                try:
                    os.close(int(name))
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
        permissions = {row["destination"]: 5 if row["destination"] in (manifest["executable"], manifest["interpreter"]) else 4
                       for row in manifest["files"]}
        permissions.update({"/dev/null": 6, "/scratch": (1 << 15) - 2, "/proc/self/status": 4})
        common.apply_landlock(permissions)
        signal.setitimer(signal.ITIMER_REAL, max(.001, value["deadline"] - time.monotonic()))
        os.write(1, daemon.DAEMON_READY + roles.encode(ready) + b"\n")
        os.execve(daemon.argv_for(operation)[0], daemon.argv_for(operation), dict(daemon.ENVIRONMENT))
    except BaseException as error:
        sys.stderr.write(type(error).__name__ + ":" + str(error)[:2048] + "\n")
        return 78
    finally:
        if private_socket is not None:
            private_socket.close()
        if channel is not None:
            channel.close()


if __name__ == "__main__":
    raise SystemExit(main())
