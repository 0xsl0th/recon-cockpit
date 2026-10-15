"""One exact routed client with no route, firewall or private service authority."""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError:
                continue
            raise ValueError("routing_client_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("routing_client_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import ctypes
import errno
import json
import math
import signal
import socket
import stat
import time

from recon_cockpit.secure_agent import worker, tool_worker_common as common, routing_contract as contract
from recon_cockpit.secure_agent import network_tools_runtime as native
from recon_cockpit.secure_agent.configurable_worker import probe_headers
from recon_cockpit.secure_agent.network_tools_worker import verify_files, _limits, landlock
from recon_cockpit.secure_agent.models import load_json
from recon_cockpit.secure_agent.routing_client_runtime import READY_PREFIX, client_runtime_module, validate_client_runtime


def assert_routed_namespaces(host, routed):
    if sys.platform != "linux" or os.getuid() != 0 or os.getgid() != 0:
        raise ValueError("routing_client_identity_invalid")
    for name in ("user", "net", "mnt", "pid"):
        current = os.readlink("/proc/self/ns/" + name)
        if current == host[name] or (current != routed[name] if name == "net" else current == routed[name]):
            raise ValueError("routing_client_namespace_changed")
    if {name for _, name in socket.if_nameindex()} != {"lo", "eth0"}:
        raise ValueError("routing_client_interfaces_changed")
    for name in ("uid", "gid"):
        with open("/proc/self/" + name + "_map", encoding="ascii") as source:
            raw = source.read(1025)
        if len(raw) > 1024 or [tuple(map(int, line.split())) for line in raw.splitlines()] != [(0, 0, 1)]:
            raise ValueError("routing_client_mapping_changed")
    if int(worker._status()["CapEff"], 16) & ((1 << 12) | (1 << 21)):
        raise ValueError("routing_client_setup_capability_retained")


def witness_endpoints(selector, selected=None):
    from recon_cockpit.secure_agent.routing_topology_spec import endpoints
    chosen = contract.underlying_selection(selector, selected)
    targets = endpoints(chosen["configuration"])
    names = ("ssh", "excluded", "http_wrong") if selector.startswith("http_") else ("http", "excluded", "ssh_wrong")
    return tuple(targets[name] for name in names)


def verify_network_boundary(selector, selected=None):
    checks = {}
    for name, endpoint in zip(("other_service_blocked", "excluded_destination_blocked", "wrong_port_blocked"),
                              witness_endpoints(selector, selected), strict=True):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(.15)
            try:
                connection.connect(endpoint)
            except (TimeoutError, PermissionError):
                checks[name] = True
            else:
                raise RuntimeError("routing_forbidden_listener_reachable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x10000000) == 0 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError("routing_client_namespace_creation_allowed")
    status = worker._status()
    if (any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or status["NoNewPrivs"] != "1"):
        raise RuntimeError("routing_client_privilege_drop_failed")
    try:
        pid = os.fork()
    except PermissionError:
        pass
    else:
        if pid == 0:
            os._exit(78)
        os.waitpid(pid, 0)
        raise RuntimeError("routing_client_process_creation_allowed")
    for family in (socket.AF_INET, socket.AF_PACKET):
        try:
            channel = socket.socket(family, socket.SOCK_RAW)
        except PermissionError:
            continue
        channel.close()
        raise RuntimeError("routing_client_raw_socket_allowed")
    try:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except PermissionError:
        checks["private_socket_blocked"] = True
    else:
        channel.close()
        raise RuntimeError("routing_client_private_socket_allowed")
    for path in ("/scratch", "/peer", "/stock-peer", "/stock-ssh-peer", "/tool/sshd", "/tool/nginx", "/tool/apache2", "/usr/lib/openssh"):
        try:
            os.stat(path)
        except FileNotFoundError:
            continue
        raise RuntimeError("routing_client_private_mount_visible")
    try:
        descriptor = os.open("/routing-client-write-witness", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno != errno.EROFS:
            raise RuntimeError("routing_client_root_not_readonly") from None
    else:
        os.close(descriptor)
        raise RuntimeError("routing_client_root_writable")
    checks.update(dict.fromkeys(("namespace_creation_blocked", "capabilities_dropped", "no_new_privs", "root_read_only",
        "process_creation_blocked", "raw_sockets_blocked", "private_socket_mount_absent", "routed_namespace_verified"), True))
    return checks


def validate_go(raw, nonce, session_deadline, selector, *, now=None):
    if type(raw) is not bytes or len(raw) > 256:
        raise ValueError("invalid_routing_client_go")
    value = load_json(raw)
    now = time.monotonic() if now is None else now
    if (type(value) is not dict or set(value) != {"nonce", "deadline"} or value["nonce"] != nonce
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not now < value["deadline"] <= session_deadline
            or value["deadline"] - now > contract.action_bounds(selector)["timeout_seconds"]):
        raise ValueError("invalid_routing_client_go")
    return value["deadline"]


def argv_for(request):
    selector = contract.validate_selector(request["selector"])
    if selector == "http_headers":
        raise ValueError("routing_headers_have_no_executable")
    action = contract.action(request["selection"], selector)
    if (request["target"] != action["target"] or request["tool_id"] != action["tool_id"]
            or request["parameters"] != action["parameters"]):
        raise ValueError("routing_client_action_changed")
    from recon_cockpit.secure_agent import stock_ssh_spec
    from recon_cockpit.secure_agent.configurable_worker import argv_for as http_argv
    chosen = contract.underlying_selection(selector, request["selection"])
    return http_argv(request) if selector.startswith("http_") else stock_ssh_spec.client_argv(chosen["configuration"], chosen["case"])


def main():
    try:
        from recon_cockpit.secure_agent.routing_execution import consume_launch
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("routing_client_requires_authority_pipe")
        raw = sys.stdin.buffer.readline(32770)
        if not raw.endswith(b"\n") or len(raw) > 32769:
            raise ValueError("routing_client_launch_frame")
        raw = raw[:-1]
        request, session_deadline, namespaces, digest = consume_launch(raw, sys.argv[1], sys.argv[2])
        selector = request["selector"]
        selected = request["selection"]
        manifest = load_json(raw)["runtime"]["client"]
        runtime = client_runtime_module(selector, selected)
        assert_routed_namespaces(request["host_namespaces"], namespaces)
        validate_client_runtime(manifest, selector, selected)
        if selector != "http_headers":
            if runtime.manifest_digest(manifest) != digest:
                raise ValueError("routing_client_runtime_changed")
            (verify_files if runtime is native else runtime.verify_files)(manifest)
            argv = argv_for(request)
        elif manifest is not None or digest is not None:
            raise ValueError("routing_header_runtime_changed")
        _limits(native.SSH if selector == "ssh_keys" else native.NMAP_SERVICE)
        worker.drop_privileges()
        common.syscall_filter(allow_threads=False)
        if selector == "http_headers":
            worker.install_syscall_filter()
        checks = verify_network_boundary(selector, selected)
        if selector == "http_headers":
            common.apply_landlock({"/dev/null": 6, "/proc/self/status": 4})
        else:
            (landlock if runtime is native else runtime.landlock)(manifest)
        checks.update(landlock_applied=True, python_unreadable=True)
        if time.monotonic() >= session_deadline:
            raise TimeoutError("routing_client_session_expired")
        os.write(2, READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        deadline = validate_go(sys.stdin.buffer.readline(257), sys.argv[1], session_deadline, selector)
        if sys.stdin.buffer.read(1):
            raise ValueError("routing_client_extra_release_data")
        sys.stdin.close()
        try:
            os.close(0)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        if selector == "http_headers":
            result = probe_headers(request, deadline)
            if result["status"] == "failed" and result["bytes_received"] == 0 and time.monotonic() >= deadline:
                result["status"] = "timeout"
            result["boundary_checks"] = checks
            print(json.dumps(result, separators=(",", ":")), flush=True)
            return 0
        signal.setitimer(signal.ITIMER_REAL, worker._remaining(deadline, 5))
        os.execve(argv[0], argv, native.execution_environment(manifest["tool_id"]))
    except Exception:
        sys.stderr.write("routing_client_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
