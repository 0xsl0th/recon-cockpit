"""Fixed DNS/TLS owner; no upstream queries, credentials or application sessions."""

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import ssl
import struct
import time

if __package__:
    from . import owned_lab_worker as owner, network_tools_fixture as fixture, web_tools_tls_fixture as tls_material
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    owner = _load("network_tools_fixed_owner", "owned_lab_worker.py")
    fixture = _load("network_tools_fixed_fixture", "network_tools_fixture.py")
    tls_material = _load("network_tools_fixed_tls", "web_tools_tls_fixture.py")


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_network_tools_lab_request")
    value = json.loads(raw, object_pairs_hook=owner._unique)
    if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
            or type(value["case"]) is not str or value["case"] not in fixture.CASES
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("invalid_network_tools_lab_request")
    return value


def tls_context(case):
    if fixture.tool_for_case(case) != "openssl_tls_handshake_v1":
        raise ValueError("invalid_network_tools_tls_case")
    cert = tls_material.UNTRUSTED_SERVER_CERT_PEM if case == "openssl-untrusted" else tls_material.SERVER_CERT_PEM
    expected = fixture.UNTRUSTED_SERVER_CERT_SHA256 if case == "openssl-untrusted" else fixture.SERVER_CERT_SHA256
    if hashlib.sha256(cert).hexdigest() != expected:
        raise ValueError("network_tools_tls_certificate_mismatch")
    descriptors = []
    try:
        for label, data in (("public-lab-cert", cert), ("public-lab-key", tls_material.SERVER_KEY_PEM)):
            fd = os.memfd_create(label, os.MFD_CLOEXEC)
            descriptors.append(fd)
            if os.write(fd, data) != len(data):
                raise ValueError("network_tools_tls_material_truncated")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(*(f"/proc/self/fd/{fd}" for fd in descriptors))
        return context
    finally:
        for fd in descriptors:
            os.close(fd)


def _read_exact(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("network_tools_dns_incomplete")
        result.extend(chunk)
    return bytes(result)


def read_dns_query(connection):
    size = struct.unpack("!H", _read_exact(connection, 2))[0]
    if not 12 <= size <= fixture.MAX_DNS_BYTES:
        raise ValueError("network_tools_dns_frame_limit")
    return fixture.validate_dns_query(_read_exact(connection, size))


class NetworkToolsService(owner.Service):
    def __init__(self, request, listener):
        self.deadline = request["deadline"]
        self.context = tls_context(request["case"]) if request["case"].startswith("openssl-") else None
        super().__init__(request["case"], listener)

    def _serve(self):
        try:
            while True:
                raw, _ = self.listener.accept()
                with self.condition:
                    self.connections += 1
                    self.condition.notify_all()
                connection = raw
                try:
                    raw.settimeout(owner.worker._remaining(self.deadline, 2))
                    if self.context is None:
                        query = read_dns_query(connection)
                        with self.condition:
                            self.requests += 1
                            self.condition.notify_all()
                        if self.case.endswith("-stalled"):
                            time.sleep(owner.worker._remaining(self.deadline, 60))
                        else:
                            reply = fixture.dns_response(self.case, query)
                            connection.sendall(struct.pack("!H", len(reply)) + reply)
                    elif self.case == "openssl-stalled":
                        time.sleep(owner.worker._remaining(self.deadline, 60))
                    elif self.case == "openssl-malformed":
                        connection.sendall(fixture.TLS_MALFORMED_BYTES)
                    else:
                        connection = self.context.wrap_socket(raw, server_side=True)
                        with self.condition:
                            self.requests += 1  # Completed server handshake, not HTTP.
                            self.condition.notify_all()
                        # Send close_notify without sending or accepting application data.
                        connection = connection.unwrap()
                except (OSError, ValueError, UnicodeError):
                    pass
                finally:
                    connection.close()
                    raw.close()
        except BaseException:
            with self.condition:
                self.failed = True
                self.condition.notify_all()


class NetworkToolsOwner(owner.Owner):
    def read_request(self, source):
        return read_request(source)

    def create_service(self, request, listener):
        return NetworkToolsService(request, listener)


def main():
    return NetworkToolsOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
