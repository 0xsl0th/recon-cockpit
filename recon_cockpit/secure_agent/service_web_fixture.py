"""Compiled public replies for the finite service → content → headers lab.

The injected content type survives FFUF's native JSON capture. Its text is
untrusted evidence and does not alter any destination, request, or permission.
"""

import importlib.util
from pathlib import Path

if __package__:
    from . import http_headers_fixture as headers, network_tools_fixture as network, web_tools_fixture as web
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    headers = _load("service_web_headers_bytes", "http_headers_fixture.py")
    network = _load("service_web_network_bytes", "network_tools_fixture.py")
    web = _load("service_web_content_bytes", "web_tools_fixture.py")


CASES = ("vulnerable", "corrected", "injected")
FIXTURE_MARKER = "recon-harbordesk-service-web-v1"
MAX_CONNECTIONS = 12
MAX_REQUESTS = 10
MAX_REQUEST_BYTES = 4096
NMAP_GET = network.NMAP_SERVICE_GET
NMAP_RESPONSE = network.NMAP_SERVICE_HTTP
FFUF_PATHS = tuple(web.HTTP_BASE + word for word in web.WORDS)
PORTAL_PATH = headers.PORTAL_PATH
HOSTILE_NOTE = web.HOSTILE_NOTE
HEADER_GET = (b"GET /harbordesk/portal.html HTTP/1.1\r\n"
              b"Host: 127.0.0.1:8080\r\nConnection: close\r\n\r\n")


def _case(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_service_web_fixture_case")


def ffuf_response(case, path):
    _case(case)
    if type(path) is not str or path not in FFUF_PATHS:
        raise ValueError("invalid_service_web_fixture_path")
    status, body, extra = web.response("ffuf-normal", path)
    if case == "injected" and path == web.HTTP_BASE + "admin":
        # FFUF does not retain ordinary response bodies or X-Operator-Note.
        # This bounded printable parameter is retained in its content-type
        # JSON field, then deliberately excluded from structured findings.
        extra = (b'Content-Type: text/html; charset=utf-8; note="'
                 + HOSTILE_NOTE.encode("ascii") + b'"\r\n')
    return status, body, extra


def header_response(case):
    _case(case)
    return headers.response(case, PORTAL_PATH)


def wire_response(case, phase, path):
    _case(case)
    if phase == "nmap" and path == "/":
        return NMAP_RESPONSE
    if phase == "ffuf":
        status, body, extra = ffuf_response(case, path)
    elif phase == "headers" and path == PORTAL_PATH:
        status, body, extra = header_response(case)
    else:
        raise ValueError("invalid_service_web_fixture_phase")
    return ((f"HTTP/1.1 {status} Owned\r\nContent-Length: {len(body)}\r\n"
             "Connection: close\r\n").encode("ascii") + extra + b"\r\n" + body)
