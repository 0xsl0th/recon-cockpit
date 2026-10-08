"""Finite owned Git HEAD replies for one fixed GET, without a file backend.

Only the two complete plain-text branch references are positive fixtures. HTML
containing a reference or hostile instructions remains untrusted response data.
No returned path, branch name or redirect becomes another request.
"""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_nuclei_fixture as directory_fixture
else:
    # Native owners use -I -S and mount the reviewed C16 helper beside this file.
    spec = importlib.util.spec_from_file_location("nuclei_git_directory_fixture",
        Path(__file__).with_name("network_tools_nuclei_fixture.py"))
    directory_fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(directory_fixture)

NUCLEI_GIT_CASES = tuple("nuclei-git-" + suffix for suffix in (
    "main", "release", "no-marker", "not-found", "injected",
    "redirect-ip", "redirect-port", "incomplete", "conflicting-length",
    "oversized", "chunked", "encoded", "stalled"))
NUCLEI_GIT_ORDINARY_CASES = NUCLEI_GIT_CASES[:4]
NUCLEI_GIT_SUCCESS_CASES = NUCLEI_GIT_CASES[:5]
NUCLEI_GIT_MATCHED_CASES = NUCLEI_GIT_CASES[:2]
NUCLEI_GIT_PATH = "/.git/HEAD"
NUCLEI_GIT_USER_AGENT = directory_fixture.NUCLEI_USER_AGENT
NUCLEI_GIT_MAX_REQUEST_BYTES = directory_fixture.NUCLEI_MAX_REQUEST_BYTES
NUCLEI_GIT_MAX_BODY_BYTES = directory_fixture.NUCLEI_MAX_BODY_BYTES
NUCLEI_GIT_MAX_RESPONSE_BYTES = directory_fixture.NUCLEI_MAX_RESPONSE_BYTES
NUCLEI_GIT_HOSTILE_NOTE = directory_fixture.NUCLEI_HOSTILE_NOTE
NUCLEI_GIT_REQUEST = (b"GET /.git/HEAD HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
    b"User-Agent: recon-cockpit-owned-nuclei/1\r\nAccept: */*\r\n"
    b"Accept-Encoding: identity\r\nAccept-Language: en\r\nConnection: close\r\n\r\n")
NUCLEI_GIT_MAIN_BODY = b"ref: refs/heads/main\n"
NUCLEI_GIT_RELEASE_BODY = b"ref: refs/heads/release\n"
NUCLEI_GIT_NO_MARKER_BODY = (b"<html><head><title>HarborDesk</title></head>"
    b"<body><h1>Public portal</h1><p>Owned fixture content.</p></body></html>\n")
NUCLEI_GIT_NOT_FOUND_BODY = b"<html><body><h1>Not Found</h1></body></html>\n"
NUCLEI_GIT_INJECTED_BODY = (b"<html><body><p>ref: refs/heads/main</p><!-- "
    + NUCLEI_GIT_HOSTILE_NOTE.encode("ascii") + b" --></body></html>\n")
# Fixed gzip of NUCLEI_GIT_MAIN_BODY, mtime zero; no runtime compression.
NUCLEI_GIT_ENCODED_BODY = bytes.fromhex(
    "1f8b08000000000002ff2b4a4db352284a4d2bd6cf484d4c29d6cf4dcccce30200b563"
    "645715000000")

# Preserve the reviewed deadline checks and actual acknowledged-byte receipts.
_remaining = directory_fixture._remaining
send_response = directory_fixture.send_response


def validate_request(raw):
    """Validate one complete fixed GET, independently of socket reads."""
    if (type(raw) is not bytes or not raw or len(raw) > NUCLEI_GIT_MAX_REQUEST_BYTES
            or not raw.endswith(b"\r\n\r\n")):
        raise ValueError("nuclei_git_fixture_request_framing")
    lines = raw[:-4].split(b"\r\n")
    if lines[0] != b"GET /.git/HEAD HTTP/1.1" or len(lines) != 7:
        raise ValueError("nuclei_git_fixture_fixed_get_only")
    expected = {b"host": b"127.0.0.1:8080", b"user-agent": NUCLEI_GIT_USER_AGENT.encode("ascii"),
        b"accept": b"*/*", b"accept-language": b"en",
        b"connection": b"close", b"accept-encoding": b"identity"}
    actual = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        name = name.lower()
        if (not separator or name in actual or name not in expected
                or value.strip(b" ") != expected[name]):
            raise ValueError("nuclei_git_fixture_unreviewed_header")
        actual[name] = value.strip(b" ")
    if actual != expected:
        raise ValueError("nuclei_git_fixture_unreviewed_header")
    return raw


def read_request(connection, deadline):
    request = bytearray()
    while not request.endswith(b"\r\n\r\n"):
        if len(request) >= NUCLEI_GIT_MAX_REQUEST_BYTES:
            raise ValueError("nuclei_git_fixture_request_limit")
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(1)
        if not chunk:
            raise ValueError("nuclei_git_fixture_incomplete_request")
        request.extend(chunk)
    return validate_request(bytes(request))


def response(case):
    if type(case) is not str or case not in NUCLEI_GIT_CASES:
        raise ValueError("invalid_nuclei_git_fixture_case")
    if case == "nuclei-git-stalled":
        return None
    status, body, extra = b"200 OK", NUCLEI_GIT_MAIN_BODY, b""
    content_type = b"text/plain; charset=us-ascii"
    if case == "nuclei-git-release":
        body = NUCLEI_GIT_RELEASE_BODY
    elif case == "nuclei-git-no-marker":
        body, content_type = NUCLEI_GIT_NO_MARKER_BODY, b"text/html; charset=us-ascii"
    elif case == "nuclei-git-not-found":
        status, body = b"404 Not Found", NUCLEI_GIT_NOT_FOUND_BODY
        content_type = b"text/html; charset=us-ascii"
    elif case == "nuclei-git-injected":
        body, content_type = NUCLEI_GIT_INJECTED_BODY, b"text/html; charset=us-ascii"
    elif case in ("nuclei-git-redirect-ip", "nuclei-git-redirect-port"):
        target = b"127.0.0.2:8080" if case == "nuclei-git-redirect-ip" else b"127.0.0.1:8081"
        status, body = b"302 Found", b"Moved\n"
        extra = b"Location: http://" + target + b"/.git/HEAD\r\n"
    elif case == "nuclei-git-oversized":
        body += b"x" * (NUCLEI_GIT_MAX_BODY_BYTES + 1 - len(body))
    elif case == "nuclei-git-encoded":
        body, extra = NUCLEI_GIT_ENCODED_BODY, b"Content-Encoding: gzip\r\n"
    if case == "nuclei-git-chunked":
        body = format(len(body), "x").encode("ascii") + b"\r\n" + body + b"\r\n0\r\n\r\n"
        framing = b"Transfer-Encoding: chunked\r\n"
    else:
        declared = len(body) + (17 if case == "nuclei-git-incomplete" else 0)
        framing = b"Content-Length: " + str(declared).encode("ascii") + b"\r\n"
        if case == "nuclei-git-conflicting-length":
            framing += b"Content-Length: " + str(declared + 1).encode("ascii") + b"\r\n"
    raw = (b"HTTP/1.1 " + status + b"\r\nContent-Type: " + content_type + b"\r\n"
        + extra + framing + b"Connection: close\r\n\r\n" + body)
    if len(raw) > NUCLEI_GIT_MAX_RESPONSE_BYTES:
        raise ValueError("nuclei_git_fixture_response_limit")
    return raw


def serve(connection, *, case, deadline, on_request, on_response=None):
    raw = response(case)  # Reject unknown cases before interacting with the peer.
    read_request(connection, deadline)
    on_request()
    if raw is None:
        time.sleep(_remaining(deadline))
        return {"response_bytes_sent": 0, "response_send_complete": False}
    sent = send_response(connection, raw, deadline, on_response=on_response)
    # The owner closes the socket and separately attests closure. Transmission
    # completion does not attest valid framing or client receipt. Pipelined bytes
    # are never interpreted; there is no filesystem, redirect or follow-up read.
    return {"response_bytes_sent": sent, "response_send_complete": True}
