"""One service with finite Nmap, content-discovery, and header-query phases."""

import importlib.util
import json
import math
from pathlib import Path
import time

if __package__:
    from . import owned_lab_worker as owner, service_web_fixture as fixture
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    owner = _load("service_web_fixed_owner", "owned_lab_worker.py")
    fixture = _load("service_web_fixed_fixture", "service_web_fixture.py")


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_service_web_lab_request")
    value = json.loads(raw, object_pairs_hook=owner._unique)
    if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
            or type(value["case"]) is not str or value["case"] not in fixture.CASES
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("invalid_service_web_lab_request")
    return value


def read_http(connection, deadline, *, initial_scan=False):
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        if len(raw) >= fixture.MAX_REQUEST_BYTES:
            raise ValueError("service_web_http_request_limit")
        connection.settimeout(owner.worker._remaining(deadline, 2))
        try:
            chunk = connection.recv(fixture.MAX_REQUEST_BYTES - len(raw))
        except ConnectionResetError:
            # Nmap's connect-only scan closes with RST on the native client.
            # Only its first, empty connection has this reviewed meaning.
            # Resets after application bytes or in later phases fail closed.
            if initial_scan and not raw:
                return b""
            raise
        if not chunk:
            if not raw:
                return b""
            raise ValueError("service_web_http_request_incomplete")
        raw.extend(chunk)
    if not raw.endswith(b"\r\n\r\n") or raw.count(b"\r\n\r\n") != 1:
        raise ValueError("service_web_http_request_body_or_pipeline")
    return bytes(raw)


def ffuf_path(raw):
    """Only a bodyless local GET with a finite set of benign client headers."""
    if type(raw) is not bytes or not raw.endswith(b"\r\n\r\n"):
        raise ValueError("service_web_ffuf_request_invalid")
    try:
        lines = raw[:-4].decode("ascii").split("\r\n")
        method, path, version = lines[0].split(" ")
    except (UnicodeError, ValueError):
        raise ValueError("service_web_ffuf_request_invalid") from None
    if method != "GET" or path not in fixture.FFUF_PATHS or version != "HTTP/1.1":
        raise ValueError("service_web_ffuf_request_scope")
    fields = {}
    for line in lines[1:]:
        name, separator, value = line.partition(": ")
        key = name.lower()
        if (not separator or key in fields
                or key not in {"host", "user-agent", "accept-encoding", "connection"}
                or not value or len(value) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("service_web_ffuf_request_headers")
        fields[key] = value
    if (fields.get("host") != "127.0.0.1:8080"
            or ("connection" in fields and fields["connection"].lower() != "close")
            or ("accept-encoding" in fields and fields["accept-encoding"] not in ("gzip", "identity"))):
        raise ValueError("service_web_ffuf_request_headers")
    return path


class ServiceWebService(owner.Service):
    def __init__(self, request, listener):
        self.deadline = request["deadline"]
        self.discovered = set()
        super().__init__(request["case"], listener)

    def _reply(self, raw):
        if self.requests == 0:
            if not raw and self.connections in (1, 2):
                return None
            if self.connections not in (2, 3) or raw != fixture.NMAP_GET:
                raise ValueError("service_web_nmap_phase")
            return fixture.wire_response(self.case, "nmap", "/")
        if self.requests < 9:
            path = ffuf_path(raw)
            if path in self.discovered:
                raise ValueError("service_web_ffuf_repeated_path")
            self.discovered.add(path)
            return fixture.wire_response(self.case, "ffuf", path)
        if self.requests == 9 and len(self.discovered) == 8 and raw == fixture.HEADER_GET:
            return fixture.wire_response(self.case, "headers", fixture.PORTAL_PATH)
        raise ValueError("service_web_header_phase")

    def _serve(self):
        try:
            while True:
                raw, _ = self.listener.accept()
                try:
                    if self.connections >= fixture.MAX_CONNECTIONS or self.requests >= fixture.MAX_REQUESTS:
                        raise ValueError("service_web_exchange_limit")
                    with self.condition:
                        self.connections += 1
                        self.condition.notify_all()
                    reply = self._reply(read_http(raw, self.deadline,
                        initial_scan=self.connections == 1 and self.requests == 0))
                    if reply is not None:
                        with self.condition:
                            self.requests += 1
                            self.condition.notify_all()
                        raw.settimeout(owner.worker._remaining(self.deadline, 2))
                        raw.sendall(reply)
                finally:
                    raw.close()
        except BaseException:
            with self.condition:
                self.failed = True
                self.condition.notify_all()

    def snapshot(self, minimum_connections, minimum_requests, deadline):
        value = super().snapshot(minimum_connections, minimum_requests, deadline)
        if (value["connection_count"] > fixture.MAX_CONNECTIONS
                or value["request_count"] > fixture.MAX_REQUESTS):
            raise RuntimeError("service_web_exchange_limit")
        return value


class ServiceWebOwner(owner.Owner):
    def read_request(self, source):
        return read_request(source)

    def create_service(self, request, listener):
        return ServiceWebService(request, listener)


def main():
    return ServiceWebOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
