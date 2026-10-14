"""One independently verified stock HTTP action after a private READY/GO gate."""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError:
                continue
            raise ValueError("stock_client_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("stock_client_refused\n")
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

from recon_cockpit.secure_agent import worker, tool_worker_common as common
from recon_cockpit.secure_agent import network_tools_runtime as native, stock_http_spec as spec
from recon_cockpit.secure_agent.configurable_worker import argv_for, probe_headers
from recon_cockpit.secure_agent.configurable_parser import HEADERS
from recon_cockpit.secure_agent.models import load_json
from recon_cockpit.secure_agent.network_tools_worker import verify_files, _limits, landlock
from recon_cockpit.secure_agent.owned_lab_executor import assert_lab_namespaces
from recon_cockpit.secure_agent.stock_http_client_runtime import READY_PREFIX


def validate_go(raw, nonce, session_deadline, case, *, now=None):
    if type(raw) is not bytes or len(raw) > 256:
        raise ValueError("invalid_stock_client_go")
    value = load_json(raw)
    now = time.monotonic() if now is None else now
    if (type(value) is not dict or set(value) != {"nonce", "deadline"} or value["nonce"] != nonce
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not now < value["deadline"] <= session_deadline
            or value["deadline"] - now > spec.budgets(case)["tool_timeout_seconds"]):
        raise ValueError("invalid_stock_client_go")
    return value["deadline"]


def probe_headers_at_deadline(request, deadline):
    result = probe_headers(request, deadline)
    # Owner closure and the reader alarm share one absolute deadline. If EOF
    # wins their race with no response bytes, the exhausted action still timed
    # out; an earlier connection failure remains a failure. Evidence separately
    # requires N3's complete daemon reply and withheld-response owner record.
    if result["status"] == "failed" and result["bytes_received"] == 0 and time.monotonic() >= deadline:
        result["status"] = "timeout"
    return result


def verify_network_boundary(configuration, *, production=False):
    checks = {}
    names = ("other_configuration_blocked", "forbidden_ip_blocked", "forbidden_port_blocked", "excluded_destination_blocked")
    for name, destination in zip(names, spec.witness_endpoints(configuration), strict=True):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.15)
            try:
                connection.connect(destination)
            except (TimeoutError, PermissionError):
                checks[name] = True
            else:
                raise RuntimeError("stock_forbidden_listener_reachable")
    if production:
        # This socket belongs to the recorder/client network namespace, never
        # Apache's private network namespace. No private descriptor is inherited.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.15)
            try:
                connection.connect(("127.0.0.1", 19080))
            except (TimeoutError, PermissionError):
                checks["private_tcp_listener_blocked"] = True
            else:
                raise RuntimeError("production_private_listener_reachable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x10000000) == 0 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError("stock_client_namespace_creation_allowed")
    status = worker._status()
    if (any(int(status[key], 16) != 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or status["NoNewPrivs"] != "1"):
        raise RuntimeError("stock_client_privilege_drop_failed")
    try:
        pid = os.fork()
    except PermissionError:
        pass
    else:
        if pid == 0:
            os._exit(78)
        os.waitpid(pid, 0)
        raise RuntimeError("stock_client_process_creation_allowed")
    for family in (socket.AF_INET, socket.AF_PACKET):
        try:
            descriptor = socket.socket(family, socket.SOCK_RAW)
        except PermissionError:
            continue
        descriptor.close()
        raise RuntimeError("stock_client_raw_socket_allowed")
    try:
        descriptor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except PermissionError:
        checks["private_socket_blocked"] = True
    else:
        descriptor.close()
        raise RuntimeError("stock_client_private_socket_allowed")
    for path in ("/scratch", "/peer", "/stock-peer"):
        try:
            os.stat(path)
        except FileNotFoundError:
            continue
        raise RuntimeError("stock_client_private_socket_mount_visible")
    checks["private_socket_mount_absent"] = True
    try:
        descriptor = os.open("/stock-client-write-witness", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise RuntimeError("stock_client_root_not_readonly") from None
    else:
        os.close(descriptor)
        raise RuntimeError("stock_client_root_writable")
    checks.update(dict.fromkeys(("namespace_creation_blocked", "capabilities_dropped", "no_new_privs",
                                "root_read_only", "process_creation_blocked", "raw_sockets_blocked"), True))
    return checks


def main():
    try:
        from recon_cockpit.secure_agent.stock_http_execution import consume_launch
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("stock_client_requires_authority_pipe")
        raw = sys.stdin.buffer.readline(32770)
        if not raw.endswith(b"\n") or len(raw) > 32769:
            raise ValueError("stock_client_launch_frame")
        raw = raw[:-1]
        production = load_json(raw).get("mode") == "stock_http_compatibility_v1"
        if production:
            from recon_cockpit.secure_agent.stock_http_production_execution import consume_launch
        request, session_deadline, namespaces, digest = consume_launch(raw, sys.argv[1], sys.argv[2])
        manifest = load_json(raw)["runtime"]["client"]
        selected = request["selection"]
        assert_lab_namespaces(request["host_namespaces"], namespaces)
        if request["verify_boundary"] is not True:
            raise ValueError("stock_client_witnesses_required")
        if request["tool_id"] != HEADERS:
            native.validate_manifest(manifest, tool_id=native.NMAP_SERVICE)
            if native.manifest_digest(manifest) != digest:
                raise ValueError("stock_client_runtime_changed")
            verify_files(manifest)
            argv = argv_for(request)
        elif manifest is not None or digest is not None:
            raise ValueError("stock_header_has_native_runtime")
        _limits(native.NMAP_SERVICE)
        worker.drop_privileges()
        common.syscall_filter(allow_threads=False)
        if request["tool_id"] == HEADERS:
            worker.install_syscall_filter()
        checks = verify_network_boundary(selected["configuration"], production=production)
        if request["tool_id"] == HEADERS:
            common.apply_landlock({"/dev/null": 6, "/proc/self/status": 4})
        else:
            landlock(manifest)
        checks.update({"landlock_applied": True, "python_unreadable": True})
        if time.monotonic() >= session_deadline:
            raise TimeoutError("stock_client_session_expired")
        # stdin is the sole authority pipe, not an extra inherited capability.
        os.write(2, READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        go = sys.stdin.buffer.readline(257)
        deadline = validate_go(go, sys.argv[1], session_deadline, selected["case"])
        if sys.stdin.buffer.read(1):
            raise ValueError("stock_client_extra_release_data")
        sys.stdin.close()
        try:
            os.close(0)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        if request["tool_id"] == HEADERS:
            result = probe_headers_at_deadline(request, deadline)
            result["boundary_checks"] = checks
            print(json.dumps(result, separators=(",", ":")), flush=True)
            return 0
        # The native program inherits the remaining action timer; exec resets a
        # caught handler, so expiration terminates it rather than extending work.
        signal.setitimer(signal.ITIMER_REAL, worker._remaining(deadline, 5))
        os.execve(argv[0], argv, native.execution_environment(manifest["tool_id"]))
    except Exception:
        sys.stderr.write("stock_client_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
