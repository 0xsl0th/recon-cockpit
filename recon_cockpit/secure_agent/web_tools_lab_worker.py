"""Fixed HTTP/TLS specialization of the accepted isolated owner lifecycle."""

import importlib.util
import hashlib
import json
import math
import os
from pathlib import Path
import ssl
import time

if __package__:
    from . import owned_lab_worker as owner, web_tools_fixture as fixture, web_tools_tls_fixture as tls_material
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    owner = _load("web_tools_fixed_owner", "owned_lab_worker.py")
    fixture = _load("web_tools_fixed_fixture", "web_tools_fixture.py")
    tls_material = _load("web_tools_fixed_tls", "web_tools_tls_fixture.py")


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_web_tools_lab_request")
    value = json.loads(raw, object_pairs_hook=owner._unique)
    if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
            or type(value["case"]) is not str or value["case"] not in fixture.CASES
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("invalid_web_tools_lab_request")
    return value


def tls_context(case):
    if case not in fixture.CASES or not case.startswith("curl-"):
        raise ValueError("invalid_web_tools_tls_case")
    cert = (tls_material.UNTRUSTED_SERVER_CERT_PEM if case == "curl-untrusted"
            else tls_material.SERVER_CERT_PEM)
    expected = (fixture.UNTRUSTED_SERVER_CERT_SHA256 if case == "curl-untrusted"
                else fixture.SERVER_CERT_SHA256)
    if hashlib.sha256(cert).hexdigest() != expected:
        raise ValueError("web_tools_tls_certificate_mismatch")
    descriptors = []
    try:
        for label, data in (("public-lab-cert", cert), ("public-lab-key", tls_material.SERVER_KEY_PEM)):
            fd = os.memfd_create(label, os.MFD_CLOEXEC)
            descriptors.append(fd)
            if os.write(fd, data) != len(data):
                raise ValueError("web_tools_tls_material_truncated")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(*(f"/proc/self/fd/{fd}" for fd in descriptors))
        return context
    finally:
        for fd in descriptors:
            os.close(fd)


def read_path(connection):
    request = bytearray()
    while b"\r\n\r\n" not in request:
        if len(request) >= 4096:
            raise ValueError("web_tools_http_request_limit")
        chunk = connection.recv(4096 - len(request))
        if not chunk:
            raise ValueError("web_tools_http_request_incomplete")
        request.extend(chunk)
    head, body = bytes(request).split(b"\r\n\r\n", 1)
    fields = head.split(b"\r\n", 1)[0].split(b" ")
    if (body or len(fields) != 3 or fields[0] != b"GET" or fields[2] != b"HTTP/1.1"
            or not fields[1].startswith(b"/harbordesk/") or len(fields[1]) > 128):
        raise ValueError("web_tools_http_request_invalid")
    return fields[1].decode("ascii")


class WebToolsService(owner.Service):
    def __init__(self, request, listener):
        self.deadline = request["deadline"]
        self.context = tls_context(request["case"]) if request["case"].startswith("curl-") else None
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
                    raw.settimeout(owner.worker._remaining(self.deadline, 1))
                    if self.context is not None:
                        connection = self.context.wrap_socket(raw, server_side=True)
                    path = read_path(connection)
                    with self.condition:
                        self.requests += 1
                        self.condition.notify_all()
                    if self.case.endswith("-stalled"):
                        time.sleep(owner.worker._remaining(self.deadline, 60))
                    else:
                        connection.sendall(fixture.wire_response(self.case, path))
                except (OSError, ValueError, UnicodeError):
                    pass
                finally:
                    connection.close()
                    raw.close()
        except BaseException:
            with self.condition:
                self.failed = True
                self.condition.notify_all()


class WebToolsOwner(owner.Owner):
    def read_request(self, source):
        return read_request(source)

    def create_service(self, request, listener):
        return WebToolsService(request, listener)


def main():
    return WebToolsOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
