"""Owner-only finite HTTP metadata server; no Docker or WinRM backend exists."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    # The isolated owner runs Python with -I -S, so sibling source files are
    # not importable through sys.path. Load only the mounted public fixture.
    spec = importlib.util.spec_from_file_location("http_metadata_public_fixture",
                                                 Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("http_metadata_fixture_deadline")
    return remaining


def _read_request(connection, case, deadline):
    request = bytearray()
    while not request.endswith(b"\r\n\r\n"):
        if len(request) >= fixture.HTTP_METADATA_MAX_REQUEST_BYTES:
            raise ValueError("http_metadata_fixture_request_limit")
        connection.settimeout(min(2, _remaining(deadline)))
        char = connection.recv(1)
        if not char:
            raise ValueError("http_metadata_fixture_incomplete_request")
        request.extend(char)
    lines = bytes(request[:-4]).split(b"\r\n")
    path = fixture.HTTP_METADATA_PATHS[fixture.tool_for_case(case)]
    if lines[0] != ("GET " + path + " HTTP/1.1").encode("ascii") or len(lines) != 5:
        raise ValueError("http_metadata_fixture_fixed_get_only")
    expected = {b"host": b"127.0.0.1:8080", b"user-agent": fixture.HTTP_METADATA_USER_AGENT.encode("ascii"),
                b"accept": b"*/*", b"connection": b"close"}
    fields = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        name = name.lower()
        if not separator or name in fields or name not in expected or value.strip(b" ") != expected[name]:
            raise ValueError("http_metadata_fixture_unreviewed_header")
        fields[name] = value.strip(b" ")
    if fields != expected:
        raise ValueError("http_metadata_fixture_unreviewed_header")


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.HTTP_METADATA_CASES:
        raise ValueError("invalid_http_metadata_case")
    _read_request(connection, case, deadline)
    on_request()
    if case.endswith("-stalled"):
        time.sleep(_remaining(deadline))
        return
    payload = fixture.http_metadata_response(case)
    connection.settimeout(min(2, _remaining(deadline)))
    connection.sendall(payload)
