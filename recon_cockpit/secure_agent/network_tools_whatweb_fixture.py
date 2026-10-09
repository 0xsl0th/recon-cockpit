"""Owner-only fixed HTTP response for passive fingerprinting; no web backend."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("whatweb_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("whatweb_fixture_deadline")
    return remaining


def read_request(connection, deadline):
    request = bytearray()
    while b"\r\n\r\n" not in request:
        if len(request) >= fixture.WHATWEB_MAX_REQUEST_BYTES:
            raise ValueError("whatweb_fixture_request_limit")
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(fixture.WHATWEB_MAX_REQUEST_BYTES - len(request))
        if not chunk:
            raise ValueError("whatweb_fixture_incomplete_request")
        request.extend(chunk)
    if len(request) > fixture.WHATWEB_MAX_REQUEST_BYTES or not request.endswith(b"\r\n\r\n"):
        raise ValueError("whatweb_fixture_request_limit")
    lines = bytes(request[:-4]).split(b"\r\n")
    if lines[0] != ("GET " + fixture.WHATWEB_PATH + " HTTP/1.1").encode("ascii") or len(lines) != 6:
        raise ValueError("whatweb_fixture_fixed_get_only")
    expected = {b"host": b"127.0.0.1:8080", b"user-agent": fixture.WHATWEB_USER_AGENT.encode("ascii"),
                b"accept": b"*/*", b"connection": b"close", b"accept-encoding": b"identity"}
    fields = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        name = name.lower()
        if not separator or name in fields or name not in expected or value.strip(b" ") != expected[name]:
            raise ValueError("whatweb_fixture_unreviewed_header")
        fields[name] = value.strip(b" ")
    if fields != expected:
        raise ValueError("whatweb_fixture_unreviewed_header")


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.WHATWEB_CASES:
        raise ValueError("invalid_whatweb_fixture_case")
    read_request(connection, deadline)
    # Counts the validated GET, including a refused, empty, or invalid reply;
    # useful fingerprinting still requires the separately parsed native result.
    on_request()
    response = fixture.whatweb_response(case)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    connection.settimeout(min(2, _remaining(deadline)))
    if response:
        connection.sendall(response)
    # The owner closes this socket on return. There is no second request,
    # redirect handler, script fetch, login, cookie store or application backend.
