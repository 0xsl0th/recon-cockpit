"""One disconnected owned TLS endpoint for synthetic provider transport tests.

Its certificate/key are private mounts selected by the host launcher. Requests
and credentials enter only private pipes or verified TLS; nothing is logged.
"""

from __future__ import annotations

import json
import math
import os
import re
import resource
import select
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time

if __package__:
    from . import worker
    from .provider_contract import (
        HOST, MAX_HEADER_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, METHOD,
        PATH, PORT, SCENARIOS, TLS_NAME, success_response, validate_request)
else:
    sys.path.insert(0, "/app")
    import worker
    from recon_cockpit.secure_agent.provider_contract import (
        HOST, MAX_HEADER_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, METHOD,
        PATH, PORT, SCENARIOS, TLS_NAME, success_response, validate_request)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_provider_owner_field")
        result[key] = value
    return result


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_provider_owner_request")
    value = json.loads(raw, object_pairs_hook=_unique)
    if (type(value) is not dict or set(value) != {"scenario", "credential", "deadline", "host_namespaces"}
            or type(value["scenario"]) is not str or value["scenario"] not in SCENARIOS
            or type(value["credential"]) is not str or not re.fullmatch(r"synthetic-[a-f0-9]{64}", value["credential"])
            or type(value["deadline"]) not in {int, float} or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 600):
        raise ValueError("invalid_provider_owner_request")
    identities = value["host_namespaces"]
    if (type(identities) is not dict or set(identities) != {"user", "net", "mnt", "pid"}
            or any(type(identity) is not str or re.fullmatch(name + r":\[\d+\]", identity) is None
                   for name, identity in identities.items())):
        raise ValueError("invalid_provider_owner_namespaces")
    return value


def _listen(address):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(address)
        listener.listen(4)
        return listener
    except BaseException:
        listener.close()
        raise


def _http_request(connection, credential):
    request = bytearray()
    while b"\r\n\r\n" not in request:
        if len(request) >= MAX_HEADER_BYTES:
            raise ValueError("provider_request_header_limit")
        data = connection.recv(min(4096, MAX_HEADER_BYTES - len(request)))
        if not data:
            raise ValueError("incomplete_provider_http_request")
        request.extend(data)
    head, body = bytes(request).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if lines[0] != f"{METHOD} {PATH} HTTP/1.1".encode("ascii"):
        raise ValueError("provider_request_destination_mismatch")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        key = name.lower()
        if (not separator or not re.fullmatch(rb"[a-z-]+", key) or key in headers
                or re.fullmatch(rb"[\x20-\x7e]*", value) is None):
            raise ValueError("provider_request_header_invalid")
        headers[key] = value.strip(b" ")
    required = {b"host", b"authorization", b"content-length", b"content-type", b"accept", b"connection"}
    if (set(headers) != required or headers[b"host"] != f"{TLS_NAME}:{PORT}".encode("ascii")
            or headers[b"authorization"] != b"Bearer " + credential.encode("ascii")
            or headers[b"content-type"] != b"application/json" or headers[b"accept"] != b"application/json"
            or headers[b"connection"].lower() != b"close"
            or not re.fullmatch(rb"[1-9][0-9]{0,4}", headers[b"content-length"])):
        raise ValueError("provider_request_auth_or_headers_invalid")
    length = int(headers[b"content-length"])
    if not 1 <= length <= MAX_REQUEST_BYTES or len(body) > length:
        raise ValueError("provider_request_body_limit")
    while len(body) < length:
        data = connection.recv(min(4096, length - len(body)))
        if not data:
            raise ValueError("incomplete_provider_http_request")
        body += data
    validate_request(body)
    return body


def response(scenario, credential):
    status, body, extra = 200, success_response(), b""
    if scenario == "redirect":
        status, body = 302, b'{"redirect":"owned-witness"}'
        extra = b"Location: https://127.0.0.2:8444/v1/responses\r\n"
    elif scenario == "oversized":
        body = b"x" * (MAX_RESPONSE_BYTES + 1)
    elif scenario == "rate_limit":
        status, body = 429, b'{"error":"synthetic_rate_limit"}'
        extra = b"Retry-After: 0\r\n"
    elif scenario == "credential_echo":
        body = json.dumps({"echo": credential}, separators=(",", ":")).encode("ascii")
    elif scenario == "escaped_credential_echo":
        escaped = "".join("\\u%04x" % ord(character) for character in credential)
        body = ('{"echo":"' + escaped + '"}').encode("ascii")
    elif scenario == "malformed":
        body = b'{"invalid":'
    length = len(body) + (17 if scenario == "truncated" else 0)
    headers = (f"HTTP/1.1 {status} Owned\r\nContent-Length: {length}\r\n"
               "Content-Type: application/json\r\nConnection: close\r\n").encode("ascii")
    return headers + extra + b"\r\n" + body


class Service:
    def __init__(self, listener, context, scenario, credential, deadline):
        self.listener, self.context = listener, context
        self.scenario, self.credential, self.deadline = scenario, credential, deadline
        self.lock = threading.Lock()
        self.connections = self.requests = 0
        self.failed = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            while True:
                connection, _ = self.listener.accept()
                with self.lock:
                    self.connections += 1
                try:
                    connection.settimeout(worker._remaining(self.deadline, 5))
                    with self.context.wrap_socket(connection, server_side=True) as tls:
                        _http_request(tls, self.credential)
                        with self.lock:
                            self.requests += 1
                        if self.scenario == "slow":
                            time.sleep(worker._remaining(self.deadline, 600))
                        tls.sendall(response(self.scenario, self.credential))
                except (OSError, ValueError):
                    connection.close()
        except BaseException:
            with self.lock:
                self.failed = True

    def snapshot(self):
        with self.lock:
            if self.failed or not 0 <= self.requests <= self.connections <= 1:
                raise RuntimeError("provider_service_failed")
            return {"connection_count": self.connections, "request_count": self.requests}


def main():
    listeners = []
    try:
        if not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("provider_owner_requires_private_pipe")
        request = read_request(sys.stdin.buffer)
        worker.assert_private_namespaces(request["host_namespaces"])
        deadline = request["deadline"]
        worker._set_limits(worker._remaining(deadline, 600))
        signal.signal(signal.SIGALRM, worker._deadline)
        signal.setitimer(signal.ITIMER_REAL, worker._remaining(deadline, 600))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain("/run/provider/server.crt", "/run/provider/server.key")
        for address in ((HOST, PORT), ("127.0.0.2", PORT), (HOST, PORT + 1)):
            listeners.append(_listen(address))
        for listener in listeners[1:]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(worker._remaining(deadline, 1))
                connection.connect(listener.getsockname())
                accepted, _ = listener.accept()
                accepted.close()
        subprocess.run(["/usr/sbin/nft", "-f", "-"], input=worker.firewall_rules(HOST, PORT).encode("ascii"),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                       timeout=worker._remaining(deadline, 3), env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}, close_fds=True)
        worker.drop_privileges()
        service = Service(listeners[0], context, request["scenario"], request["credential"], deadline)
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
        worker.install_syscall_filter()
        namespaces = {name: os.readlink(f"/proc/self/ns/{name}") for name in ("user", "net", "mnt", "pid")}
        print(json.dumps({"ready": True, "namespaces": namespaces, "witness_baselines": True}, separators=(",", ":")), flush=True)
        sampled = False
        while True:
            ready, _, _ = select.select([0, *listeners[1:]], [], [], worker._remaining(deadline, 1))
            if any(listener in ready for listener in listeners[1:]):
                raise RuntimeError("provider_witness_leak")
            if 0 not in ready:
                continue
            command = sys.stdin.buffer.readline(8)
            if not command:
                return 0
            if command != b"SNAP\n" or sampled:
                raise ValueError("invalid_provider_owner_command")
            sampled = True
            print(json.dumps(service.snapshot(), separators=(",", ":")), flush=True)
    except Exception:
        sys.stderr.write("owned_provider_owner_refused\n")
        return 78
    finally:
        for listener in listeners:
            listener.close()


if __name__ == "__main__":
    raise SystemExit(main())
