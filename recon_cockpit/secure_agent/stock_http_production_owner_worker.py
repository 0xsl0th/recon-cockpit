"""Private production HTTP owners; no host service or arbitrary target access.

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
import math
import resource
import select
import signal
import socket
import stat
import subprocess
import time

from recon_cockpit.secure_agent import stock_http_production_contract as contract
from recon_cockpit.secure_agent import stock_http_spec as spec, stock_apache_spec as apache
from recon_cockpit.secure_agent import stock_http_runtime as nginx_runtime, stock_apache_runtime as apache_runtime
from recon_cockpit.secure_agent import stock_http_owner_worker as existing
from recon_cockpit.secure_agent import worker, tool_worker_common as common
from recon_cockpit.secure_agent.stock_http_production_transport import (
    DescriptorService, receive_packet, send_packet, socket_identity, validate_descriptor_identity, owned_socket)

MAX_PACKET = existing.MAX_PACKET
SCRATCH_BYTES = existing.SCRATCH_BYTES
BOUNDS = existing.BOUNDS
DAEMON_READY = b"RECON_STOCK_HTTP_PRODUCTION_READY_V1 "
encode, decode = existing.encode, existing.decode
namespaces, limits = existing.namespaces, existing.limits


def request(value, *, daemon=False, now=None):
    fields = {"selection", "deadline", "host_namespaces", "runtime_digest", "manifest" if daemon else "descriptor"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("stock_production_invalid_owner_request")
    selected = contract.validate_selection(value["selection"])
    now = time.monotonic() if now is None else now
    if (type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - now <= 60):
        raise ValueError("stock_production_owner_expired")
    digest = value["runtime_digest"]
    if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("stock_production_invalid_runtime_digest")
    apache_selected = selected["implementation"] == "apache"
    if daemon:
        runtime = apache_runtime if apache_selected else nginx_runtime
        manifest = runtime.validate_manifest(value["manifest"])
        if (runtime.manifest_digest(manifest) != digest
                or any(manifest[key] != item for key, item in contract.preparation_selection(selected).items())):
            raise ValueError("stock_production_owner_runtime_changed")
    elif apache_selected:
        validate_descriptor_identity(value["descriptor"])
    elif value["descriptor"] is not None:
        raise ValueError("stock_production_unexpected_private_descriptor")
    return value


def namespace_identity(host, implementation):
    if implementation == "nginx":
        worker.assert_private_namespaces(host)
        uid = gid = 0
    elif implementation == "apache":
        uid = gid = apache.NAMESPACE_UID
        if (type(host) is not dict or set(host) != {"user", "net", "mnt", "pid"}
                or any(type(value) is not str or not __import__("re").fullmatch(name + r":\[\d+\]", value)
                       for name, value in host.items())
                or any(namespaces()[name] == value for name, value in host.items())
                or [name for _, name in socket.if_nameindex()] != ["lo"]
                or os.getuid() != uid or os.getgid() != gid):
            raise ValueError("stock_production_daemon_identity_invalid")
        for name in ("uid", "gid"):
            with open("/proc/self/" + name + "_map", encoding="ascii") as source:
                raw = source.read(1025)
            if len(raw) > 1024:
                raise ValueError("stock_production_mapping_limit")
            rows = [tuple(map(int, line.split())) for line in raw.splitlines()]
            if len(rows) != 1 or len(rows[0]) != 3 or rows[0][0] != uid or rows[0][1] == 0 or rows[0][2] != 1:
                raise ValueError("stock_production_daemon_mapping_invalid")
    else:
        raise ValueError("stock_production_unknown_daemon")
    if os.getuid() != uid or os.getgid() != gid or os.getgroups() != []:
        raise ValueError("stock_production_daemon_groups_invalid")
    return {"uid": uid, "gid": gid, "supplementary_groups": []}


def apache_socket_filter():
    # Reuse the strict no-fork/thread/namespace profile, with TCP listening only.
    common.syscall_filter(allow_threads=False)
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise RuntimeError("stock_production_seccomp_failed")
    try:
        number = library.seccomp_syscall_resolve_name(b"connect")
        if (number == -1 or library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) != 0
                or library.seccomp_load(context) != 0):
            raise RuntimeError("stock_production_connect_filter_failed")
    finally:
        library.seccomp_release(context)


def apache_confinement_witnesses(private_socket):
    status = worker._status()
    if (status["NoNewPrivs"] != "1" or any(int(status[key], 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or common._namespace_task_count() != 1 or os.getpid() != 1):
        raise RuntimeError("stock_production_daemon_privileges_invalid")
    for family, kind in ((socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_PACKET, socket.SOCK_RAW)):
        try:
            probe = socket.socket(family, kind)
        except PermissionError:
            continue
        probe.close()
        raise RuntimeError("stock_production_daemon_socket_family_allowed")
    if private_socket.connect_ex(apache.PRIVATE_ENDPOINT) != errno.EPERM:
        raise RuntimeError("stock_production_daemon_connect_allowed")
    socket_identity(private_socket)
    try:
        pid = os.fork()
    except PermissionError:
        return
    if pid == 0:
        os._exit(78)
    os.waitpid(pid, 0)
    raise RuntimeError("stock_production_daemon_child_allowed")


def recorder_main():
    from recon_cockpit.secure_agent.stock_http_recorder import Service
    channel = socket.socket(fileno=0)
    listeners, service, private_socket = [], None, None
    try:
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError("stock_production_recorder_requires_control_socket")
        # First packet carries metadata only, so descriptor expectations derive
        # from a validated selection rather than attacker-controlled ancillary data.
        value, _ = receive_packet(channel, descriptor_required=False)
        value = request(value)
        selected = value["selection"]
        if selected["implementation"] == "apache":
            transfer, descriptor = receive_packet(channel, descriptor_required=True)
            private_socket = owned_socket(descriptor)
            if (transfer != {"descriptor": value["descriptor"]}
                    or socket_identity(private_socket) != value["descriptor"]):
                raise ValueError("stock_production_recorder_descriptor_changed")
        worker.assert_private_namespaces(value["host_namespaces"])
        worker._set_limits(worker._remaining(value["deadline"], 60))
        own_scratch = existing.scratch_bound("/scratch")
        if selected["implementation"] == "nginx":
            if own_scratch == existing.scratch_bound(existing.PEER_DIRECTORY):
                raise ValueError("stock_production_scratch_not_separate")
            existing.verify_peer_read_only()
        existing.prepare_addresses(selected["configuration"])
        action = spec.action(selected["configuration"], selected["case"])
        for address in ((action["target"], action["parameters"]["port"]), *spec.witness_endpoints(selected["configuration"])):
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
        subprocess.run(["/usr/sbin/nft", "-f", "-"], input=existing.firewall_rules(selected["configuration"]).encode("ascii"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, check=True,
            timeout=worker._remaining(value["deadline"], 3), env={"LC_ALL": "C"})
        if private_socket is None:
            service = Service(selected["configuration"], selected["case"], listeners[0], deadline=value["deadline"])
            descriptor_receipt = None
        else:
            service = DescriptorService(selected["configuration"], selected["case"], listeners[0],
                private_socket=private_socket, identity=value["descriptor"], deadline=value["deadline"])
            descriptor_receipt = {**value["descriptor"], "recorder_netns_cookie": service.recorder_cookie,
                "unconnected_at_transfer": True, "transferred_once": True,
                "daemon_duplicate_closed": True, "connect_denied_in_daemon": True}
            private_socket = None  # service now owns and closes the sole local copy
        worker.drop_privileges()
        limits(value["deadline"])
        existing.socket_filter(daemon=False)
        existing.confinement_witnesses()
        permissions = {"/dev/null": 6, "/proc/self/status": 4, "/scratch": (1 << 15) - 2}
        if selected["implementation"] == "nginx":
            permissions[existing.PEER_DIRECTORY] = 8
        common.apply_landlock(permissions)
        existing.send(channel, {"ready": True, "namespaces": namespaces(), "witness_baselines": True,
            "bounds": BOUNDS, "runtime_digest": value["runtime_digest"], "descriptor": descriptor_receipt})
        sequence = 0
        while True:
            worker._remaining(value["deadline"], 60)
            ready, _, _ = select.select([channel, *listeners[1:]], [], [], 0)
            if any(listener in ready for listener in listeners[1:]):
                raise RuntimeError("stock_production_destination_witness_leak")
            if channel in ready:
                command = existing.receive(channel)
                if command is None:
                    return 0
                sequence += 1
                if (type(command.get("sequence")) is not int or command["sequence"] != sequence
                        or sequence > 64 or command.get("operation") not in ("arm", "snapshot", "finish", "ready", "close")):
                    raise ValueError("stock_production_invalid_command")
                operation = command["operation"]
                if set(command) != {"sequence", "operation"} | ({"deadline"} if operation == "arm" else set()):
                    raise ValueError("stock_production_invalid_command")
                if operation == "arm":
                    service.arm(command["deadline"])
                elif operation == "ready" and selected["implementation"] == "nginx":
                    ready_deadline = min(value["deadline"], time.monotonic() + 2)
                    while True:
                        try:
                            ready = stat.S_ISSOCK(os.stat(existing.PEER_SOCKET).st_mode)
                        except FileNotFoundError:
                            ready = False
                        if ready:
                            break
                        if time.monotonic() >= ready_deadline:
                            raise ValueError("stock_production_daemon_socket_missing")
                        service.tick(0.01)
                elif operation in ("finish", "close"):
                    service.close()
                existing.send(channel, {"sequence": sequence, "operation": operation, "recorder": service.snapshot()})
                if operation == "close":
                    return 0
            service.tick(0.01)
    finally:
        if service is not None:
            service.close()
        if private_socket is not None:
            private_socket.close()
        for listener in listeners:
            listener.close()
        channel.close()


def daemon_main():
    channel = socket.socket(fileno=0)
    private_socket = None
    try:
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError("stock_production_daemon_requires_control_socket")
        value, _ = receive_packet(channel, descriptor_required=False)
        value = request(value, daemon=True)
        selected, manifest = value["selection"], value["manifest"]
        identity = namespace_identity(value["host_namespaces"], selected["implementation"])
        existing.scratch_bound("/scratch")
        runtime = apache_runtime if selected["implementation"] == "apache" else nginx_runtime
        for item in manifest["files"]:
            descriptor = os.open(item["destination"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(descriptor)
                raw = os.read(descriptor, runtime.MAX_FILE_BYTES + 1)
                if (not stat.S_ISREG(info.st_mode) or len(raw) != item["size"]
                        or hashlib.sha256(raw).hexdigest() != item["sha256"]):
                    raise ValueError("stock_production_daemon_file_changed")
            finally:
                os.close(descriptor)
        if selected["implementation"] == "apache":
            private_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            private_socket.setblocking(False)
        worker.drop_privileges()
        limits(value["deadline"])
        if private_socket is not None:
            apache_socket_filter()
            apache_confinement_witnesses(private_socket)
            private_identity = socket_identity(private_socket)
        else:
            existing.socket_filter(daemon=True)
            existing.confinement_witnesses()
            private_identity = None
        ready = {"namespaces": namespaces(), "bounds": BOUNDS, "runtime_digest": value["runtime_digest"],
                 "namespace_identity": identity, "descriptor": private_identity}
        send_packet(channel, ready, None if private_socket is None else private_socket.fileno())
        if private_socket is not None:
            private_socket.close()
            private_socket = None
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
        permissions = {item["destination"]: 5 if item["destination"] in
            (manifest["executable"], manifest["interpreter"]) else 4 for item in manifest["files"]}
        permissions.update({"/dev/null": 6, "/scratch": (1 << 15) - 2, "/proc/self/status": 4})
        common.apply_landlock(permissions)
        os.write(1, DAEMON_READY + encode(ready) + b"\n")
        if selected["implementation"] == "apache":
            os.execve(apache.APACHE_ARGV[0], apache.APACHE_ARGV, dict(apache.APACHE_ENVIRONMENT))
        os.execve("/tool/nginx", ("/tool/nginx", "-p", "/scratch/", "-c", spec.NGINX_CONFIG_PATH,
                                 "-e", "stderr"), dict(spec.NGINX_ENVIRONMENT))
    finally:
        if private_socket is not None:
            private_socket.close()
        channel.close()


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("recorder", "daemon") or not ENTRY_DESCRIPTORS_VERIFIED:
            raise ValueError("stock_production_owner_invalid_mode")
        return recorder_main() if sys.argv[1] == "recorder" else daemon_main()
    except Exception:
        sys.stderr.write("stock_http_production_owner_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
