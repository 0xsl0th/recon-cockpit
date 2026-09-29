"""One received TCP capability; new sockets stay in a disconnected namespace."""

import errno
import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) <= 2:
            continue
        try:
            os.fstat(int(name))
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        raise RuntimeError("inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("pilot_worker_refused\n")
        raise SystemExit(78) from None

import array
import ctypes
import hashlib
import hmac
import math
import resource
import socket
import ssl
import subprocess
import time

if not __package__:
    sys.path.insert(0, "/app")
    import worker
    import planner_worker
    import provider_worker
    from recon_cockpit.secure_agent.provider_pilot_contract import (
        CHECKS, MAX_PACKET, encode, request_bytes, response_summary, validate_credential,
    )
else:
    from . import worker, planner_worker, provider_worker
    from .provider_pilot_contract import (
        CHECKS, MAX_PACKET, encode, request_bytes, response_summary, validate_credential,
    )


def packet(channel, deadline, *, expect_fd=False):
    channel.settimeout(provider_worker._remaining(deadline))
    data, ancillary, flags, _ = channel.recvmsg(MAX_PACKET, socket.CMSG_SPACE(4 * 4))
    received = []
    try:
        for level, kind, raw in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise ValueError("unexpected_ancillary")
            values = array.array("i")
            values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
            received.extend(values)
        if flags or len(received) != int(expect_fd):
            raise ValueError("invalid_packet")
        value = provider_worker._decode(data)
        return value, received.pop() if expect_fd else None
    finally:
        for fd in received:
            os.close(fd)


def isolate(launch):
    worker.assert_private_namespaces(launch["host_namespaces"])
    worker._set_limits(120)
    # Positive witnesses exist before DROP rules, so timeouts prove enforcement.
    listeners = []
    try:
        for address in (("127.0.0.2", 8443), ("127.0.0.1", 8444)):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(listener)
            listener.bind(address)
            listener.listen(4)
            listener.settimeout(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                probe.connect(address)
                accepted, _ = listener.accept()
                accepted.close()
        rules = "table inet pilot {\n" + "\n".join(
            f"chain {name} {{ type filter hook {name} priority 0; policy drop; }}"
            for name in ("input", "output", "forward")) + "\n}\n"
        subprocess.run(["/usr/sbin/nft", "-f", "-"], input=rules.encode("ascii"),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                       timeout=min(3, provider_worker._remaining(launch["deadline"])),
                       env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}, close_fds=True)
        worker.drop_privileges()
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
        worker.install_syscall_filter()
        checks = worker.verify_network_boundary(8443)
    finally:
        for listener in listeners:
            listener.close()
    planner_worker._process_creation_blocked()
    planner_worker._root_read_only()
    # A connected socket belongs to its creating (host) network namespace.
    # DROP in this namespace alone cannot prevent disconnect/reconnect of that
    # capability. Deny connect and socket creation before it can be received.
    planner_worker._install_syscall_filter(extra_denied=(
        "connect", "bind", "listen", "accept", "accept4", "setsockopt", "sendmsg", "sendmmsg"))
    planner_worker._sockets_blocked()
    reconnect_blocked(-1)
    # Inherited descriptors were checked before imports. The runtime loader may
    # retain its own libffi descriptor; it is not an inherited host capability.
    checks.update(namespaces_private=True, witness_baselines=True, process_creation_blocked=True,
                  root_read_only=True, no_new_privs=worker._status()["NoNewPrivs"] == "1",
                  descriptors_private=True, socket_creation_blocked=True, socket_reconnect_blocked=True)
    if set(checks) != CHECKS or any(v is not True for v in checks.values()):
        raise ValueError("boundary_failed")
    return checks


def reconnect_blocked(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    address = ctypes.create_string_buffer(16)  # AF_UNSPEC disconnect attempt.
    ctypes.set_errno(0)
    if libc.connect(fd, address, 16) != -1 or ctypes.get_errno() != errno.EPERM:
        raise ValueError("socket_reconnect_allowed")


def exchange(raw, launch, credential):
    if (raw.family != socket.AF_INET or raw.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or raw.getpeername() != (launch["ip"], launch["port"])):
        raise ValueError("peer_mismatch")
    reconnect_blocked(raw.fileno())
    if raw.getpeername() != (launch["ip"], launch["port"]):
        raise ValueError("peer_changed")
    with open("/run/provider/ca.pem", "rb") as source:
        ca = source.read(524289)
    if len(ca) > 524288 or hashlib.sha256(ca).hexdigest() != launch["ca_digest"]:
        raise ValueError("ca_mismatch")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca.decode("ascii"))
    context.set_alpn_protocols(["http/1.1"])
    name = "api.openai.com" if launch["mode"] == "live" else "provider.owned.invalid"
    deadline = launch["deadline"]
    with context.wrap_socket(raw, server_hostname=name, do_handshake_on_connect=False) as connection:
        connection.settimeout(provider_worker._remaining(deadline))
        connection.do_handshake()
        if connection.selected_alpn_protocol() not in (None, "http/1.1"):
            raise ValueError("alpn_mismatch")
        body = request_bytes()
        headers = (f"POST /v1/responses HTTP/1.1\r\nHost: {name}\r\n"
                   f"Authorization: Bearer {credential}\r\nContent-Type: application/json\r\n"
                   "Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
        connection.settimeout(provider_worker._remaining(deadline))
        connection.sendall(headers + body)
        response = provider_worker.read_response(connection, deadline, credential, allow_chunked=True)
        return response_summary(provider_worker._decode(response))


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError
        launch, _ = packet(channel, time.monotonic() + 10)
        if (not hmac.compare_digest(hashlib.sha256(encode(launch)).hexdigest(), sys.argv[1])
                or set(launch) != {"host_namespaces", "deadline", "ip", "port", "mode", "ca_digest"}
                or type(launch["deadline"]) not in (int, float) or not math.isfinite(launch["deadline"])
                or not 0 < launch["deadline"] - time.monotonic() <= 120
                or launch["mode"] not in {"live", "owned"}):
            raise ValueError
        checks = isolate(launch)
        print(encode({"ready": True, "checks": checks}).decode("ascii"), flush=True)
        payload, fd = packet(channel, launch["deadline"], expect_fd=True)
        with socket.socket(fileno=fd) as raw:
            if set(payload) != {"credential"}:
                raise ValueError
            credential = validate_credential(payload["credential"], launch["mode"])
            channel.close()
            result = {"status": "ok", "http_status": 200, "summary": None}
            try:
                result["summary"] = exchange(raw, launch, credential)
            except provider_worker.TransportFailure as exc:
                result.update(status=exc.code, http_status=exc.http_status)
            except TimeoutError:
                result.update(status="deadline_exceeded", http_status=None)
            except ssl.SSLError:
                result.update(status="tls_error", http_status=None)
            except OSError:
                result.update(status="transport_error", http_status=None)
        print(encode(result).decode("ascii"), flush=True)
        return 0
    except Exception:
        sys.stderr.write("pilot_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
