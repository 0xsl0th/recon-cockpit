"""Private stock HTTP recorder and nginx bootstrap; no host service access.

The recorder creates the disconnected TCP namespace. A private bounded tmpfs
created by the isolated launcher is mounted read-only for the recorder and as
the separate daemon's sole writable scratch. It is never a recorder child.
"""

import errno
import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError as error:
                if error.errno == errno.EBADF:
                    continue
                raise
            raise ValueError("stock_owner_inherited_descriptor")


ENTRY_DESCRIPTORS_VERIFIED = False
if __name__ == "__main__":
    try:
        # Verify inherited capabilities before ctypes/libffi can open a
        # descriptor belonging to its own runtime, as in the launcher.
        private_descriptors()
        ENTRY_DESCRIPTORS_VERIFIED = True
    except Exception:
        sys.stderr.write("stock_http_owner_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import array
import ctypes
import hashlib
import json
import math
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import time

from recon_cockpit.secure_agent import stock_http_spec as spec, stock_http_runtime as runtime
from recon_cockpit.secure_agent import worker, tool_worker_common as common

MAX_PACKET = 65536
SCRATCH_BYTES = 786432
EVIDENCE_BYTES = 262144
PEER_DIRECTORY = "/peer"
PEER_SOCKET = "/peer/nginx.sock"
BOUNDS = {"address_space_bytes": 268435456, "file_descriptors": 64,
          "scratch_bytes": SCRATCH_BYTES, "retained_evidence_bytes": EVIDENCE_BYTES,
          "aggregate_storage_bytes": SCRATCH_BYTES + EVIDENCE_BYTES, "no_children": True}
DAEMON_READY = b"RECON_STOCK_NGINX_READY_V1 "


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_PACKET:
        raise ValueError("stock_owner_packet_limit")
    return raw


def decode(raw):
    from recon_cockpit.secure_agent.models import load_json
    if type(raw) is not bytes or not raw or len(raw) > MAX_PACKET:
        raise ValueError("stock_owner_invalid_packet")
    value = load_json(raw)
    if type(value) is not dict:
        raise ValueError("stock_owner_invalid_packet")
    return value


def request(value, *, daemon=False, now=None):
    fields = {"configuration", "case", "deadline", "host_namespaces", "runtime_digest"}
    if daemon:
        fields.add("manifest")
    if type(value) is not dict or set(value) != fields:
        raise ValueError("stock_owner_invalid_request")
    spec.validate_selection(value["configuration"], value["case"])
    now = time.monotonic() if now is None else now
    if (type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - now <= 60):
        raise ValueError("stock_owner_expired")
    if (type(value["runtime_digest"]) is not str or len(value["runtime_digest"]) != 64
            or any(character not in "0123456789abcdef" for character in value["runtime_digest"])):
        raise ValueError("stock_owner_invalid_runtime")
    if daemon:
        manifest = runtime.validate_manifest(value["manifest"])
        if (manifest["configuration"] != value["configuration"] or manifest["case"] != value["case"]
                or runtime.manifest_digest(manifest) != value["runtime_digest"]):
            raise ValueError("stock_owner_runtime_changed")
    return value


def namespaces():
    return {name: os.readlink("/proc/self/ns/" + name) for name in ("user", "net", "mnt", "pid")}


def scratch_bound(path):
    info, usage = os.stat(path), os.statvfs(path)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or usage.f_blocks * usage.f_frsize != SCRATCH_BYTES):
        raise ValueError("stock_owner_scratch_not_bounded")
    return info.st_dev


def verify_peer_read_only():
    """The recorder can reach nginx's socket but cannot alter its files."""
    if not os.statvfs(PEER_DIRECTORY).f_flag & os.ST_RDONLY:
        raise ValueError("stock_owner_peer_not_read_only")
    try:
        descriptor = os.open(PEER_DIRECTORY + "/.write-witness",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as error:
        if error.errno == errno.EROFS:
            return
        raise
    os.close(descriptor)
    raise ValueError("stock_owner_peer_write_allowed")


def limits(deadline):
    worker._set_limits(worker._remaining(deadline, 60))
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    signal.signal(signal.SIGALRM, worker._deadline)
    signal.setitimer(signal.ITIMER_REAL, worker._remaining(deadline, 60))


def socket_filter(*, daemon):
    """After setup allow only Unix stream creation; no process/namespace creation.

    TCP listeners and management channels already exist. nginx can create only
    its private pathname Unix listener. Recorder connections cannot create TCP.
    """
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
        raise RuntimeError("stock_owner_seccomp_failed")
    try:
        def deny(name, comparisons=()):
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            arguments = (Argument * len(comparisons))(*comparisons)
            if number == -1 or library.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM,
                    number, len(comparisons), arguments) != 0:
                raise RuntimeError("stock_owner_seccomp_rule_failed")
        for name in ("execveat", "fork", "vfork", "clone", "clone3", "unshare", "setns", "mount",
                     "umount2", "pivot_root", "chroot", "ptrace", "process_vm_readv", "process_vm_writev",
                     "bpf", "keyctl", "add_key", "request_key", "perf_event_open", "userfaultfd",
                     "io_uring_setup", "socketpair", "socketcall", "memfd_create", "open_by_handle_at"):
            deny(name)
        if not daemon:
            deny("execve")
            deny("bind")
            deny("listen")
        deny("socket", (Argument(0, 1, socket.AF_UNIX, 0),))
        for kind in range(16):
            if kind != socket.SOCK_STREAM:
                deny("socket", (Argument(1, 7, 0xF, kind),))
        deny("socket", (Argument(2, 1, 0, 0),))
        if library.seccomp_load(context) != 0:
            raise RuntimeError("stock_owner_seccomp_load_failed")
    finally:
        library.seccomp_release(context)


def confinement_witnesses():
    status = worker._status()
    if (status["NoNewPrivs"] != "1" or any(int(status[key], 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))):
        raise RuntimeError("stock_owner_privileges_not_dropped")
    # --as-pid-1 removes Bubblewrap's additional namespace reaper. No service
    # child or thread is needed, and the final seccomp policy prevents either.
    if common._namespace_task_count() != 1 or os.getpid() != 1:
        raise RuntimeError("stock_owner_process_bound_not_verified")
    for family, kind in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_PACKET, socket.SOCK_RAW)):
        try:
            probe = socket.socket(family, kind)
        except PermissionError:
            continue
        probe.close()
        raise RuntimeError("stock_owner_network_socket_creation_allowed")
    try:
        pid = os.fork()
    except PermissionError:
        pass
    else:
        if pid == 0:
            os._exit(78)
        os.waitpid(pid, 0)
        raise RuntimeError("stock_owner_child_creation_allowed")


def prepare_addresses(configuration):
    selected = spec.action(configuration, "O1")
    addresses = tuple(dict.fromkeys((selected["target"], *(row[0] for row in spec.witness_endpoints(configuration)))))
    interface = socket.if_nametoindex("lo")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("stock_owner_network_attached")
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(2)
        channel.bind((0, 0))
        for sequence, address in enumerate(addresses, 1):
            packed = socket.inet_pton(socket.AF_INET, address)
            attribute = struct.pack("=HH", 8, 1) + packed + struct.pack("=HH", 8, 2) + packed
            body = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, interface) + attribute
            message = struct.pack("=IHHII", 16 + len(body), 20, 1 | 4 | 0x400 | 0x200, sequence, 0) + body
            if channel.sendto(message, (0, 0)) != len(message):
                raise ValueError("stock_owner_address_truncated")
            raw, sender = channel.recvfrom(4097)
            if (sender != (0, 0) or len(raw) < 36 or len(raw) > 4096
                    or struct.unpack_from("=IHH", raw)[:2] != (len(raw), 2)
                    or struct.unpack_from("=I", raw, 8)[0] != sequence
                    or struct.unpack_from("=i", raw, 16)[0] != 0 or raw[20:36] != message[:16]):
                raise ValueError("stock_owner_address_ack_invalid")


def firewall_rules(configuration):
    selected = spec.action(configuration, "O1")
    target, port = selected["target"], selected["parameters"]["port"]
    return f'''table inet recon_stock_http {{
 chain output {{ type filter hook output priority 0; policy drop;
  oifname "lo" ip daddr {target} tcp dport {port} ct direction original accept
  oifname "lo" ct direction reply ct state established ct original ip daddr {target} ct original proto-dst {port} accept
 }}
 chain input {{ type filter hook input priority 0; policy drop;
  iifname "lo" ip daddr {target} tcp dport {port} ct direction original accept
  iifname "lo" ct direction reply ct state established ct original ip daddr {target} ct original proto-dst {port} accept
 }}
 chain forward {{ type filter hook forward priority 0; policy drop; }}
}}
'''


def send(channel, value):
    raw = encode(value)
    if channel.send(raw) != len(raw):
        raise ValueError("stock_owner_send_truncated")


def receive(channel):
    raw, ancillary, flags, _ = channel.recvmsg(MAX_PACKET + 1, socket.CMSG_SPACE(4))
    # Recorder never receives descriptors. Close them even on a malformed packet.
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array.array("i")
            descriptors.frombytes(payload[:len(payload) - len(payload) % descriptors.itemsize])
            for descriptor in descriptors:
                os.close(descriptor)
    if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise ValueError("stock_owner_unexpected_descriptor")
    return None if not raw else decode(raw)


def recorder_main():
    from recon_cockpit.secure_agent.stock_http_recorder import Service
    channel = socket.socket(fileno=0)
    listeners, service = [], None
    try:
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError("stock_owner_requires_control_socket")
        value = request(receive(channel))
        worker.assert_private_namespaces(value["host_namespaces"])
        worker._set_limits(worker._remaining(value["deadline"], 60))
        if scratch_bound("/scratch") == scratch_bound(PEER_DIRECTORY):
            raise ValueError("stock_owner_scratch_not_separate")
        verify_peer_read_only()
        prepare_addresses(value["configuration"])
        selected = spec.action(value["configuration"], value["case"])
        for address in ((selected["target"], selected["parameters"]["port"]), *spec.witness_endpoints(value["configuration"])):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(address)
            listener.listen(8)
        for listener in listeners[1:]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(worker._remaining(value["deadline"], 1))
                connection.connect(listener.getsockname())
                accepted, _ = listener.accept()
                accepted.close()
        subprocess.run(["/usr/sbin/nft", "-f", "-"], input=firewall_rules(value["configuration"]).encode("ascii"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, check=True,
            timeout=worker._remaining(value["deadline"], 3), env={"LC_ALL": "C"})
        service = Service(value["configuration"], value["case"], listeners[0],
                          daemon_path=PEER_SOCKET, deadline=value["deadline"])
        worker.drop_privileges()
        limits(value["deadline"])
        socket_filter(daemon=False)
        confinement_witnesses()
        common.apply_landlock({"/dev/null": 6, "/proc/self/status": 4, "/scratch": (1 << 15) - 2,
                               PEER_DIRECTORY: 8})
        send(channel, {"ready": True, "namespaces": namespaces(), "witness_baselines": True,
                       "bounds": BOUNDS, "runtime_digest": value["runtime_digest"]})
        sequence = 0
        while True:
            worker._remaining(value["deadline"], 60)
            ready, _, _ = select.select([channel, *listeners[1:]], [], [], 0)
            if any(listener in ready for listener in listeners[1:]):
                raise RuntimeError("stock_owner_destination_witness_leak")
            if channel in ready:
                command = receive(channel)
                if command is None:
                    return 0
                sequence += 1
                if (type(command.get("sequence")) is not int or command["sequence"] != sequence
                        or sequence > 64 or command.get("operation") not in ("arm", "snapshot", "finish", "ready", "close")):
                    raise ValueError("stock_owner_invalid_command")
                operation = command["operation"]
                if set(command) != {"sequence", "operation"} | ({"deadline"} if operation == "arm" else set()):
                    raise ValueError("stock_owner_invalid_command")
                if operation == "arm":
                    service.arm(command["deadline"])
                elif operation == "ready":
                    ready_deadline = min(value["deadline"], time.monotonic() + 2)
                    while True:
                        try:
                            ready = stat.S_ISSOCK(os.stat(PEER_SOCKET).st_mode)
                        except FileNotFoundError:
                            ready = False
                        if ready:
                            break
                        if time.monotonic() >= ready_deadline:
                            raise ValueError("stock_owner_daemon_socket_missing")
                        service.tick(0.01)
                elif operation in ("finish", "close"):
                    service.close()
                send(channel, {"sequence": sequence, "operation": operation, "recorder": service.snapshot()})
                if operation == "close":
                    return 0
            service.tick(0.01)
    finally:
        if service is not None:
            service.close()
        for listener in listeners:
            listener.close()
        channel.close()


def daemon_main():
    if not stat.S_ISFIFO(os.fstat(0).st_mode):
        raise ValueError("stock_daemon_requires_authority_pipe")
    value = request(decode(sys.stdin.buffer.read(MAX_PACKET + 1)), daemon=True)
    worker.assert_private_namespaces(value["host_namespaces"])
    scratch_bound("/scratch")
    manifest = value["manifest"]
    for item in manifest["files"]:
        descriptor = os.open(item["destination"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            raw = os.read(descriptor, runtime.MAX_FILE_BYTES + 1)
            if (not stat.S_ISREG(info.st_mode) or len(raw) != item["size"]
                    or hashlib.sha256(raw).hexdigest() != item["sha256"]):
                raise ValueError("stock_daemon_file_changed")
        finally:
            os.close(descriptor)
    worker.drop_privileges()
    limits(value["deadline"])
    socket_filter(daemon=True)
    confinement_witnesses()
    permissions = {item["destination"]: 5 if item["destination"] in
                   (manifest["executable"], manifest["interpreter"]) else 4 for item in manifest["files"]}
    permissions.update({"/dev/null": 6, "/scratch": (1 << 15) - 2, "/proc/self/status": 4})
    # The remaining process is nginx itself. The private control pipe is not
    # inherited by the ELF; no namespace, socket-directory or runtime FDs remain.
    os.close(0)
    descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    os.dup2(descriptor, 0, inheritable=True)
    if descriptor != 0:
        os.close(descriptor)
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.close(int(name))
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    common.apply_landlock(permissions)
    os.write(1, DAEMON_READY + encode({"namespaces": namespaces(), "bounds": BOUNDS,
                                      "runtime_digest": value["runtime_digest"]}) + b"\n")
    os.execve("/tool/nginx", ("/tool/nginx", "-p", "/scratch/", "-c", spec.NGINX_CONFIG_PATH,
                             "-e", "stderr"), dict(spec.NGINX_ENVIRONMENT))


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("recorder", "daemon"):
            raise ValueError("stock_owner_invalid_mode")
        if not ENTRY_DESCRIPTORS_VERIFIED:
            raise ValueError("stock_owner_entry_not_verified")
        return recorder_main() if sys.argv[1] == "recorder" else daemon_main()
    except Exception:
        sys.stderr.write("stock_http_owner_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
