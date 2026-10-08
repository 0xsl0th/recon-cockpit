"""Owner-only one-question SNMP GetNext fixture without walks or a MIB backend."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
    from . import network_tools_redis_snmp_fixture as snmp_owner
else:
    # Isolated owners use -I -S. Both siblings are sealed owner-only mounts;
    # reuse the accepted bounded BER Reader without broadening its GET parser.
    spec = importlib.util.spec_from_file_location("snmp_next_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    spec = importlib.util.spec_from_file_location("snmp_next_ber_owner",
        Path(__file__).with_name("network_tools_redis_snmp_fixture.py"))
    snmp_owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(snmp_owner)

Reader = snmp_owner.Reader


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("snmp_next_fixture_deadline")
    return remaining


def parse_request(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= fixture.SNMP_NEXT_MAX_REQUEST_BYTES:
        raise ValueError("snmp_next_fixture_request_limit")
    outer = Reader(raw)
    message = Reader(outer.expect(0x30))
    outer.end()
    message.expect(2, b"\x01")
    message.expect(4, fixture.SNMP_COMMUNITY)
    request = Reader(message.expect(0xa1))  # GetNext only; accepted GET is unchanged.
    message.end()
    request_id = request.expect(2)
    fixture._snmp_next_request_id(request_id)
    request.expect(2, b"\0")
    request.expect(2, b"\0")
    bindings = Reader(request.expect(0x30))
    request.end()
    binding = Reader(bindings.expect(0x30))
    binding.expect(6, fixture.SNMP_NEXT_SEED_OID_BYTES)
    binding.expect(5, b"")
    binding.end()
    bindings.end()
    return request_id


def read_request(connection, deadline):
    # The accepted reader checks the deadline for each fragment. Frame length
    # is validated before reading the announced payload or allocating for it.
    header = snmp_owner._read_exact(connection, 2, deadline)
    if header[0] != 0x30:
        raise ValueError("snmp_next_fixture_message_sequence")
    size = header[1]
    if size & 0x80:
        count = size & 0x7f
        if count not in (1, 2):
            raise ValueError("snmp_next_fixture_length")
        encoded = snmp_owner._read_exact(connection, count, deadline)
        size = int.from_bytes(encoded, "big")
        if encoded[0] == 0 or size < 128 or count == 2 and size <= 255:
            raise ValueError("snmp_next_fixture_noncanonical_length")
        header += encoded
    if not 1 <= size <= fixture.SNMP_NEXT_MAX_REQUEST_BYTES - len(header):
        raise ValueError("snmp_next_fixture_frame_limit")
    return parse_request(header + snmp_owner._read_exact(connection, size, deadline))


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.SNMP_NEXT_CASES:
        raise ValueError("invalid_snmp_next_case")
    request_id = read_request(connection, deadline)
    on_request()  # A valid request is progress, not proof of a useful response.
    response = fixture.snmp_next_response(case, request_id)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    width = 3 if case == "snmp-next-fragmented" else len(response)
    for start in range(0, len(response), width):
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(response[start:start + width])
    # The owner closes on return. Buffered follow-ups never become a second
    # query; neither a returned OID nor text changes scope or selects work.
