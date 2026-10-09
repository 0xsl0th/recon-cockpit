"""Owner-only finite OPTIONS metadata; no advertised method is executable."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    # Native owners use -I -S and mount the public fixture beside this file.
    spec = importlib.util.spec_from_file_location("http_options_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("http_options_fixture_deadline")
    return remaining


def read_request(connection, deadline):
    request = bytearray()
    while not request.endswith(b"\r\n\r\n"):
        if len(request) >= fixture.HTTP_OPTIONS_MAX_REQUEST_BYTES:
            raise ValueError("http_options_fixture_request_limit")
        connection.settimeout(min(2, _remaining(deadline)))
        char = connection.recv(1)
        if not char:
            raise ValueError("http_options_fixture_incomplete_request")
        request.extend(char)
    lines = bytes(request[:-4]).split(b"\r\n")
    if lines[0] != ("OPTIONS " + fixture.HTTP_OPTIONS_PATH + " HTTP/1.1").encode("ascii") or len(lines) != 5:
        raise ValueError("http_options_fixture_fixed_options_only")
    expected = {b"host": b"127.0.0.1:8080", b"user-agent": fixture.HTTP_OPTIONS_USER_AGENT.encode("ascii"),
                b"accept": b"*/*", b"connection": b"close"}
    fields = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        name = name.lower()
        if not separator or name in fields or name not in expected or value.strip(b" ") != expected[name]:
            raise ValueError("http_options_fixture_unreviewed_header")
        fields[name] = value.strip(b" ")
    if fields != expected:
        raise ValueError("http_options_fixture_unreviewed_header")


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.HTTP_OPTIONS_CASES:
        raise ValueError("invalid_http_options_case")
    read_request(connection, deadline)
    # This witnesses one validated OPTIONS request, not a successful result.
    on_request()
    response = fixture.http_options_response(case)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    width = 7 if case == "http-options-fragmented" else len(response)
    for start in range(0, len(response), width):
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(response[start:start + width])
    # The owner closes this connection on return. Pipelined bytes are never
    # interpreted; there is no redirect, authentication or method follow-up.
