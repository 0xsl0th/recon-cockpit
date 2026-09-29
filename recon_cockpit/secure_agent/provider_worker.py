"""One credential-bearing TLS exchange inside an owned network namespace.

The worker has a fixed destination, method and path. The launcher commits the
entire pipe payload before execution; credentials never enter argv, environment,
diagnostics or successful results. This is an owned-fixture transport, not a
general network client or a live provider integration.
"""

from __future__ import annotations

import os
import sys
import errno


def assert_private_descriptors():
    # Check before importing ctypes/ssl: runtime loaders may keep their own FDs.
    for name in os.listdir("/proc/self/fd"):
        if not name.isdecimal() or int(name) <= 2:
            continue
        try:
            os.fstat(int(name))
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise RuntimeError("provider_descriptor_check_failed") from None
        raise RuntimeError("provider_inherited_descriptor")


if __name__ == "__main__":
    try:
        assert_private_descriptors()
    except Exception:
        sys.stderr.write("provider_worker_refused\n")
        raise SystemExit(78) from None


import base64
import hashlib
import hmac
import json
import math
import re
import resource
import socket
import ssl
import stat
import time

if __package__:
    from . import planner_worker, worker
    from .provider_contract import (
        BOUNDARY_NAMES, HOST, MAX_HEADER_BYTES, MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES, METHOD, PATH, PORT, TLS_NAME, WORKER_STATUSES, validate_request,
    )
else:
    sys.path.insert(0, "/app")
    import planner_worker
    import worker
    from recon_cockpit.secure_agent.provider_contract import (
        BOUNDARY_NAMES, HOST, MAX_HEADER_BYTES, MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES, METHOD, PATH, PORT, TLS_NAME, WORKER_STATUSES, validate_request,
    )


MAX_LAUNCH_BYTES = 65536
MAX_CA_BYTES = 8192
NAMESPACE_NAMES = ("user", "net", "mnt", "pid")
CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")


class TransportFailure(Exception):
    """Static transport code only; never retain an OS or remote error string."""

    def __init__(self, code, http_status=None):
        if (type(code) is not str or code not in WORKER_STATUSES - {"ok"}
                or (http_status is not None
                    and (type(http_status) is not int or not 100 <= http_status <= 599))):
            raise ValueError("provider_invalid_transport_failure")
        self.code = code
        self.http_status = http_status
        super().__init__(code)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("provider_duplicate_field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("provider_invalid_number")


def _decode(raw):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                       parse_constant=_reject_constant)
    if type(value) is not dict:
        raise ValueError("provider_invalid_object")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            raise ValueError("provider_excessive_nesting")
        if type(item) is dict:
            pending.extend((part, depth + 1) for pair in item.items() for part in pair)
        elif type(item) is list:
            pending.extend((part, depth + 1) for part in item)
        elif type(item) is str:
            item.encode("utf-8")
        elif type(item) is float and not math.isfinite(item):
            raise ValueError("provider_invalid_number")
    return value


def _credential_reflected(raw, credential):
    # These are deliberately specific checks, not a universal encoding filter.
    # Matching repeated backslashes also covers a JSON string containing JSON.
    literal = credential.encode("ascii")
    if literal in raw:
        return True
    unescaped = re.sub(rb"\\+u00([a-fA-F0-9]{2})",
                       lambda match: bytes((int(match[1], 16),)), raw)
    return literal in unescaped


def validate_launch(raw, context_digest):
    if (type(raw) is not bytes or len(raw) > MAX_LAUNCH_BYTES
            or type(context_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", context_digest) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError("provider_launch_mismatch")
    launch = _decode(raw)
    if (set(launch) != {"schema_version", "request", "credential", "ca_pem", "deadline",
                        "host_namespaces", "lab_namespaces"}
            or launch["schema_version"] != "1"):
        raise ValueError("provider_invalid_launch")
    credential = launch["credential"]
    if type(credential) is not str or re.fullmatch(r"synthetic-[a-f0-9]{64}", credential) is None:
        raise ValueError("provider_invalid_credential")
    request = launch["request"]
    if type(request) is not str or not 1 <= len(request) <= MAX_REQUEST_BYTES:
        raise ValueError("provider_invalid_request")
    request = request.encode("ascii")
    validate_request(request)
    if _credential_reflected(request, credential):
        raise ValueError("provider_credential_in_request")
    ca = launch["ca_pem"]
    if (type(ca) is not str or not 1 <= len(ca) <= MAX_CA_BYTES
            or not ca.startswith("-----BEGIN CERTIFICATE-----\n")
            or not ca.rstrip().endswith("-----END CERTIFICATE-----")):
        raise ValueError("provider_invalid_ca")
    ca.encode("ascii")
    deadline = launch["deadline"]
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= 0:
        raise ValueError("provider_invalid_deadline")
    for field in ("host_namespaces", "lab_namespaces"):
        identities = launch[field]
        if (type(identities) is not dict or set(identities) != set(NAMESPACE_NAMES)
                or any(type(value) is not str or re.fullmatch(name + r":\[\d+\]", value) is None
                       for name, value in identities.items())):
            raise ValueError("provider_invalid_namespaces")
    if any(launch["host_namespaces"][name] == launch["lab_namespaces"][name]
           for name in NAMESPACE_NAMES):
        raise ValueError("provider_shared_host_namespace")
    return launch


def assert_lab_namespaces(host, lab):
    if sys.platform != "linux" or os.getuid() != 0 or os.getgid() != 0:
        raise RuntimeError("provider_invalid_identity")
    for name in NAMESPACE_NAMES:
        current = os.readlink(f"/proc/self/ns/{name}")
        if current == host[name] or (current != lab[name] if name == "net" else current == lab[name]):
            raise RuntimeError("provider_namespace_mismatch")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise RuntimeError("provider_interface_mismatch")
    with open("/proc/self/uid_map", encoding="ascii") as source:
        if [tuple(map(int, line.split())) for line in source] != [(0, 0, 1)]:
            raise RuntimeError("provider_user_mapping_mismatch")
    if int(worker._status()["CapEff"], 16) & (1 << 12):
        raise RuntimeError("provider_has_net_admin")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportFailure("deadline_exceeded")
    return remaining


def _recv(connection, size, deadline):
    connection.settimeout(_remaining(deadline))
    return connection.recv(size)


def _chunked_body(connection, initial, deadline):
    """Bound both decoded bytes and framing; no extensions, trailers or pipeline."""
    buffer = bytearray(initial)
    result = bytearray()
    wire_bytes = len(initial)

    def more():
        nonlocal wire_bytes
        chunk = _recv(connection, 4096, deadline)
        wire_bytes += len(chunk)
        if not chunk or wire_bytes > 2 * MAX_RESPONSE_BYTES:
            raise TransportFailure("malformed_response", 200)
        buffer.extend(chunk)

    while True:
        while b"\r\n" not in buffer:
            if len(buffer) > 8:
                raise TransportFailure("malformed_response", 200)
            more()
        line, _, rest = buffer.partition(b"\r\n")
        if re.fullmatch(rb"[0-9a-fA-F]{1,8}", line) is None:
            raise TransportFailure("malformed_response", 200)
        size = int(line, 16)
        if len(result) + size > MAX_RESPONSE_BYTES:
            raise TransportFailure("response_too_large", 200)
        buffer[:] = rest
        while len(buffer) < size + 2:
            more()
        if buffer[size:size + 2] != b"\r\n":
            raise TransportFailure("malformed_response", 200)
        result.extend(buffer[:size])
        del buffer[:size + 2]
        if size == 0:
            if buffer or _recv(connection, 1, deadline):
                raise TransportFailure("malformed_response", 200)
            return bytes(result)


def read_response(connection, deadline, credential, *, allow_chunked=False):
    """Consume one bounded, uncompressed HTTP/1.1 JSON response and EOF."""
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) >= MAX_HEADER_BYTES:
            raise TransportFailure("response_too_large")
        chunk = _recv(connection, min(4096, MAX_HEADER_BYTES - len(buffer)), deadline)
        if not chunk:
            raise TransportFailure("malformed_response")
        buffer.extend(chunk)
    header, body = bytes(buffer).split(b"\r\n\r\n", 1)
    lines = header.split(b"\r\n")
    match = re.fullmatch(rb"HTTP/1\.1 ([1-5][0-9]{2}) [\x20-\x7e]*", lines[0])
    if match is None:
        raise TransportFailure("malformed_response")
    status = int(match[1])
    fields = {}
    for line in lines[1:]:
        if b":" not in line:
            raise TransportFailure("malformed_response", status)
        name, value = line.split(b":", 1)
        name = name.lower()
        if (re.fullmatch(rb"[!#$%&'*+.^_`|~0-9a-z-]+", name) is None
                or re.fullmatch(rb"[\x20-\x7e]*", value) is None or name in fields):
            raise TransportFailure("malformed_response", status)
        fields[name] = value.strip(b" ")
    chunked = allow_chunked and fields.get(b"transfer-encoding", b"").lower() == b"chunked"
    if (b"content-encoding" in fields or b"transfer-encoding" in fields and not chunked
            or chunked and b"content-length" in fields):
        raise TransportFailure("malformed_response", status)
    length = fields.get(b"content-length", b"")
    if chunked:
        length = b"0"
    if re.fullmatch(rb"0|[1-9][0-9]{0,9}", length) is None:
        raise TransportFailure("malformed_response", status)
    length = int(length)
    if length > MAX_RESPONSE_BYTES:
        raise TransportFailure("response_too_large", status)
    # Status alone is released for a failure. Bodies, Location and Retry-After
    # are never exposed or acted on; a later attempt needs another reservation.
    if status != 200:
        raise TransportFailure("http_error", status)
    content_type = fields.get(b"content-type", b"").lower()
    if re.fullmatch(rb"application/json(?:; *charset=utf-8)?", content_type) is None:
        raise TransportFailure("malformed_response", status)
    if chunked:
        response = _chunked_body(connection, body, deadline)
        # Reuse the same reflection/JSON validation below; EOF was checked above.
        length = len(response)
    else:
        response = bytearray(body)
    if len(response) > length:
        raise TransportFailure("malformed_response", status)
    while len(response) < length:
        chunk = _recv(connection, min(4096, length - len(response)), deadline)
        if not chunk:
            raise TransportFailure("malformed_response", status)
        response.extend(chunk)
    if not chunked and _recv(connection, 1, deadline):
        raise TransportFailure("malformed_response", status)
    response = bytes(response)
    if _credential_reflected(response, credential):
        raise TransportFailure("credential_reflection", status)
    try:
        _decode(response)
    except (ValueError, UnicodeError, RecursionError):
        raise TransportFailure("malformed_response", status) from None
    _remaining(deadline)
    return response


def tls_exchange(request, credential, ca_pem, deadline):
    """Literal IP connection, one verified TLS handshake, one POST, no retries."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # SSLContext(PROTOCOL_TLS_CLIENT) does not load system roots. No default
    # trust paths, proxies, environment keys, DNS or configurable URL are used.
    context.load_verify_locations(cadata=ca_pem)
    context.set_alpn_protocols(["http/1.1"])
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(_remaining(deadline))
        raw.connect((HOST, PORT))
        with context.wrap_socket(raw, server_hostname=TLS_NAME, do_handshake_on_connect=False) as connection:
            connection.settimeout(_remaining(deadline))
            connection.do_handshake()
            if connection.selected_alpn_protocol() not in (None, "http/1.1"):
                raise TransportFailure("tls_error")
            wire = (f"{METHOD} {PATH} HTTP/1.1\r\nHost: {TLS_NAME}:{PORT}\r\n"
                    f"Authorization: Bearer {credential}\r\n"
                    "Content-Type: application/json\r\nAccept: application/json\r\n"
                    "Connection: close\r\n"
                    f"Content-Length: {len(request)}\r\n\r\n").encode("ascii") + request
            connection.settimeout(_remaining(deadline))
            connection.sendall(wire)
            return read_response(connection, deadline, credential)
    finally:
        raw.close()


def execute(launch):
    assert_lab_namespaces(launch["host_namespaces"], launch["lab_namespaces"])
    worker._set_limits(30)
    worker.drop_privileges()
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    worker.install_syscall_filter()
    checks = worker.verify_network_boundary(PORT)
    planner_worker._process_creation_blocked()
    planner_worker._root_read_only()
    status = worker._status()
    if (any(int(status[name], 16) for name in CAPABILITY_FIELDS)
            or status["NoNewPrivs"] != "1"):
        raise RuntimeError("provider_privilege_boundary_failed")
    checks.update({"namespaces_private": True, "lab_network_shared": True,
                   "process_creation_blocked": True, "root_read_only": True,
                   "no_new_privs": True, "inherited_descriptors_closed": True})
    if set(checks) != set(BOUNDARY_NAMES) or not all(value is True for value in checks.values()):
        raise RuntimeError("provider_boundary_incomplete")
    result = {"schema_version": "1", "status": "ok", "http_status": 200,
              "response": None, "boundary_checks": checks}
    try:
        response = tls_exchange(launch["request"].encode("ascii"), launch["credential"],
                                launch["ca_pem"], launch["deadline"])
        result["response"] = base64.b64encode(response).decode("ascii")
    except TransportFailure as exc:
        result.update(status=exc.code, http_status=exc.http_status)
    except (TimeoutError, socket.timeout):
        result.update(status="deadline_exceeded", http_status=None)
    except ssl.SSLError:
        result.update(status="tls_error", http_status=None)
    except OSError:
        result.update(status="transport_error", http_status=None)
    return result


def main():
    try:
        if len(sys.argv) != 2 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("provider_worker_requires_authority_pipe")
        raw = sys.stdin.buffer.read(MAX_LAUNCH_BYTES + 1)
        sys.stdin.close()
        launch = validate_launch(raw, sys.argv[1])
        result = execute(launch)
        print(json.dumps(result, separators=(",", ":"), allow_nan=False), flush=True)
        return 0
    except Exception:
        sys.stderr.write("provider_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
