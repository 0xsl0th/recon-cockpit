"""One scope-bound action in its selected disconnected endpoint namespace."""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError:
                continue
            raise ValueError("configurable_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("configurable_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import base64
import ctypes
import errno
import hashlib
import json
import resource
import signal
import socket
import stat
import time

from recon_cockpit.secure_agent import worker, tool_worker_common as common
from recon_cockpit.secure_agent import network_tools_runtime as native
from recon_cockpit.secure_agent.network_tools_worker import verify_files, _limits, landlock
from recon_cockpit.secure_agent.owned_lab_executor import assert_lab_namespaces
from recon_cockpit.secure_agent.configurable_scope import endpoint, witness_addresses
from recon_cockpit.secure_agent.configurable_parser import NMAP, HEADERS, SSH

READY_PREFIX = b"RECON_CONFIGURABLE_TOOL_READY_V1 "
BOUNDARY_NAMES = ("cross_service_blocked", "forbidden_ip_blocked", "forbidden_port_blocked",
    "namespace_creation_blocked", "capabilities_dropped", "no_new_privs", "root_read_only",
    "process_creation_blocked", "raw_sockets_blocked", "landlock_applied", "python_unreadable")


def argv_for(request):
    selected = endpoint(request["scope"], request["endpoint_id"])
    tool_id, parameters = request["tool_id"], request["parameters"]
    if request["target"] != selected["target"] or parameters["port"] != selected["port"]:
        raise ValueError("configurable_runtime_endpoint_changed")
    if tool_id == NMAP:
        args = list(native.FIXED_ARGV[native.NMAP_SERVICE])
        args[args.index("--version-intensity") + 1] = "1"
    elif tool_id == SSH and request["endpoint_id"] == "ssh":
        args = list(native.FIXED_ARGV[native.SSH])
    else:
        raise ValueError("invalid_configurable_native_tool")
    args[args.index("-p") + 1] = str(selected["port"])
    args[-1] = selected["target"]
    return tuple(args)


def verify_network_boundary(scope, endpoint_id):
    checks = {}
    names = ("cross_service_blocked", "forbidden_ip_blocked", "forbidden_port_blocked")
    for name, destination in zip(names, witness_addresses(scope, endpoint_id)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.15)
            try:
                connection.connect(destination)
            except (TimeoutError, PermissionError):
                checks[name] = True
            else:
                raise RuntimeError("configurable_forbidden_listener_reachable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x10000000) == 0 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError("configurable_namespace_creation_allowed")
    status = worker._status()
    if (any(int(status[key], 16) != 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or status["NoNewPrivs"] != "1"):
        raise RuntimeError("configurable_privilege_drop_failed")
    try:
        pid = os.fork()
    except PermissionError:
        pass
    else:
        if pid == 0:
            os._exit(78)
        os.waitpid(pid, 0)
        raise RuntimeError("configurable_process_creation_allowed")
    for family in (socket.AF_INET, socket.AF_PACKET):
        try:
            descriptor = socket.socket(family, socket.SOCK_RAW)
        except PermissionError:
            continue
        descriptor.close()
        raise RuntimeError("configurable_raw_socket_allowed")
    try:
        descriptor = os.open("/configurable-write-witness", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise RuntimeError("configurable_root_not_readonly") from None
    else:
        os.close(descriptor)
        raise RuntimeError("configurable_root_writable")
    checks.update(dict.fromkeys(("namespace_creation_blocked", "capabilities_dropped", "no_new_privs",
                               "root_read_only", "process_creation_blocked", "raw_sockets_blocked"), True))
    return checks


def probe_headers(request, deadline):
    selected = endpoint(request["scope"], "http")
    parameters = request["parameters"]
    expected = {"port": selected["port"], "method": "GET", "path": selected["path"],
                "timeout_seconds": 1, "max_output_bytes": 2048}
    if (request["tool_id"] != HEADERS or request["endpoint_id"] != "http"
            or request["target"] != selected["target"] or parameters != expected
            or any(type(parameters[key]) is not int for key in ("port", "timeout_seconds", "max_output_bytes"))):
        raise ValueError("invalid_configurable_headers_operation")
    limit, response = parameters["max_output_bytes"], bytearray()
    timeout = worker._remaining(deadline, parameters["timeout_seconds"])
    previous = signal.signal(signal.SIGALRM, worker._deadline)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    status = "succeeded"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect((selected["target"], selected["port"]))
            connection.sendall(("GET " + selected["path"] + " HTTP/1.1\r\nHost: " + selected["target"]
                                + ":" + str(selected["port"]) + "\r\nConnection: close\r\n\r\n").encode("ascii"))
            while len(response) <= limit:
                chunk = connection.recv(min(4096, limit + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > limit:
                    status = "output_limit"
                    break
            if not response:
                status = "failed"
    except TimeoutError:
        status = "timeout"
    except OSError:
        status = "failed"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    retained = bytes(response[:limit])
    row = {"target": selected["target"], "port": selected["port"], "bytes_received": len(retained),
           "truncated": len(response) > limit, "raw_response": base64.b64encode(retained).decode("ascii"),
           "response_sha256": hashlib.sha256(retained).hexdigest()}
    return {"status": status, "results": [row], "bytes_received": len(retained), "truncated": row["truncated"]}


def main():
    try:
        from recon_cockpit.secure_agent.configurable_execution import consume_launch
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("configurable_requires_authority_pipe")
        raw = sys.stdin.buffer.read(65537)
        request, deadline, namespaces, digest = consume_launch(raw, sys.argv[1], sys.argv[2])
        manifest = json.loads(raw).get("runtime")
        assert_lab_namespaces(request["host_namespaces"], namespaces)
        if request["verify_boundary"] is not True:
            raise ValueError("configurable_boundary_witnesses_required")
        if request["tool_id"] != HEADERS:
            expected = native.NMAP_SERVICE if request["tool_id"] == NMAP else native.SSH
            native.validate_manifest(manifest, tool_id=expected)
            if native.manifest_digest(manifest) != digest:
                raise ValueError("configurable_runtime_commitment_changed")
            verify_files(manifest)
            argv = argv_for(request)
        elif manifest is not None or digest is not None:
            raise ValueError("configurable_headers_has_native_runtime")
        _limits(native.NMAP_SERVICE)
        worker.drop_privileges()
        common.syscall_filter(allow_threads=False)
        if request["tool_id"] == HEADERS:
            worker.install_syscall_filter()
        checks = verify_network_boundary(request["scope"], request["endpoint_id"])
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
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        if request["tool_id"] == HEADERS:
            common.apply_landlock({"/dev/null": 6, "/proc/self/status": 4})
        else:
            landlock(manifest)
        checks.update({"landlock_applied": True, "python_unreadable": True})
        if time.monotonic() >= deadline:
            raise TimeoutError("configurable_authority_expired")
        os.write(2, READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        if request["tool_id"] == HEADERS:
            result = probe_headers(request, deadline)
            result["boundary_checks"] = checks
            print(json.dumps(result, separators=(",", ":")), flush=True)
            return 0
        os.execve(argv[0], argv, native.execution_environment(manifest["tool_id"]))
    except Exception:
        sys.stderr.write("configurable_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
