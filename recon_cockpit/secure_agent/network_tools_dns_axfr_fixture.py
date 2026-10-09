"""Owner-only finite synthetic AXFR replies; no upstream or returned-host transport."""

import importlib.util
from pathlib import Path
import struct
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("dns_axfr_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("dns_axfr_fixture_deadline")
    return remaining


def _read_exact(connection, count, deadline):
    result = bytearray()
    while len(result) < count:
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("dns_axfr_fixture_incomplete")
        result.extend(chunk)
    return bytes(result)


def read_request(connection, deadline):
    size = struct.unpack("!H", _read_exact(connection, 2, deadline))[0]
    if not 12 <= size <= fixture.DNS_AXFR_MAX_QUERY_BYTES:
        raise ValueError("dns_axfr_fixture_frame_limit")
    return fixture.validate_dns_axfr_query(_read_exact(connection, size, deadline))


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.DNS_AXFR_CASES:
        raise ValueError("invalid_dns_axfr_fixture_case")
    query = read_request(connection, deadline)
    on_request()  # One complete fixed question, including before every negative.
    wire = fixture.dns_axfr_wire(case, query)
    if wire is None:
        time.sleep(_remaining(deadline))
        return
    chunks = (wire[index:index + 7] for index in range(0, len(wire), 7)) if case == "dig-axfr-fragmented" else (wire,)
    for chunk in chunks:
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(chunk)
        if case == "dig-axfr-fragmented":
            time.sleep(min(0.001, _remaining(deadline)))
    # The owner closes on return, never reading a second or pipelined question.
