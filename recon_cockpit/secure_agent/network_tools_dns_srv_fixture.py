"""Owner-only finite TCP DNS SRV reply; no resolver or upstream transport."""

import importlib.util
from pathlib import Path
import struct
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("dns_srv_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("dns_srv_fixture_deadline")
    return remaining


def _read_exact(connection, count, deadline):
    result = bytearray()
    while len(result) < count:
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("dns_srv_fixture_incomplete")
        result.extend(chunk)
    return bytes(result)


def read_request(connection, deadline):
    size = struct.unpack("!H", _read_exact(connection, 2, deadline))[0]
    if not 12 <= size <= fixture.DNS_SRV_MAX_QUERY_BYTES:
        raise ValueError("dns_srv_fixture_frame_limit")
    return fixture.validate_dns_srv_query(_read_exact(connection, size, deadline))


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.DNS_SRV_CASES:
        raise ValueError("invalid_dns_srv_fixture_case")
    query = read_request(connection, deadline)
    on_request()  # A complete fixed question, even for a negative response.
    response = fixture.dns_srv_response(case, query)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    connection.settimeout(min(2, _remaining(deadline)))
    connection.sendall(struct.pack("!H", len(response)) + response)
    # The owner closes this socket on return. No second question is read and
    # no returned SRV target, TXT instruction or other network is consulted.
