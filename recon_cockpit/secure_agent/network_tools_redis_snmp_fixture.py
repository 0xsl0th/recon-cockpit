"""Owner-only, finite Redis INFO and SNMP Get fixtures without data backends.

A single fixed query is validated before counting work. No AUTH, keys, HELLO,
SNMP mutation, walks, retransmission or subsequent command is implemented.
"""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("redis_snmp_public_fixture",
                                                 Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("redis_snmp_fixture_deadline")
    return remaining


def _read_exact(connection, size, deadline):
    data = bytearray()
    while len(data) < size:
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ValueError("redis_snmp_fixture_incomplete_request")
        data.extend(chunk)
    return bytes(data)


def read_redis_request(connection, deadline):
    # Compare the canonical RESP2 query as it arrives. No caller-supplied bulk
    # length is used for allocation, and an unreviewed command fails early.
    for expected in fixture.REDIS_INFO_REQUEST:
        if _read_exact(connection, 1, deadline) != bytes([expected]):
            raise ValueError("redis_fixture_info_server_only")
    return fixture.REDIS_INFO_REQUEST


class Reader:
    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    def tlv(self):
        if self.offset + 2 > len(self.raw):
            raise ValueError("snmp_fixture_incomplete_tlv")
        tag, size = self.raw[self.offset:self.offset + 2]
        self.offset += 2
        if size & 0x80:
            count = size & 0x7f
            if count not in (1, 2) or self.offset + count > len(self.raw):
                raise ValueError("snmp_fixture_length")
            encoded = self.raw[self.offset:self.offset + count]
            size = int.from_bytes(encoded, "big")
            if encoded[0] == 0 or size < 128 or count == 2 and size <= 255:
                raise ValueError("snmp_fixture_noncanonical_length")
            self.offset += count
        if size > fixture.SNMP_MAX_REQUEST_BYTES or self.offset + size > len(self.raw):
            raise ValueError("snmp_fixture_tlv_limit")
        value = self.raw[self.offset:self.offset + size]
        self.offset += size
        return tag, value

    def expect(self, tag, value=None):
        actual_tag, actual_value = self.tlv()
        if actual_tag != tag or value is not None and actual_value != value:
            raise ValueError("snmp_fixture_unreviewed_field")
        return actual_value

    def end(self):
        if self.offset != len(self.raw):
            raise ValueError("snmp_fixture_trailing_fields")


def parse_snmp_request(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= fixture.SNMP_MAX_REQUEST_BYTES:
        raise ValueError("snmp_fixture_request_limit")
    outer = Reader(raw)
    message = Reader(outer.expect(0x30))
    outer.end()
    message.expect(2, b"\x01")  # v2c, not v1/v3.
    message.expect(4, fixture.SNMP_COMMUNITY)
    request = Reader(message.expect(0xa0))  # GetRequest only.
    message.end()
    request_id = request.expect(2)
    if (not 1 <= len(request_id) <= 4 or request_id[0] & 0x80
            or len(request_id) > 1 and request_id[0] == 0 and request_id[1] < 128):
        raise ValueError("snmp_fixture_request_id")
    request.expect(2, b"\0")  # No error/fix-up state in an initial request.
    request.expect(2, b"\0")
    bindings = Reader(request.expect(0x30))
    request.end()
    for oid in fixture.SNMP_SYSTEM_OID_BYTES:
        binding = Reader(bindings.expect(0x30))
        binding.expect(6, oid)
        binding.expect(5, b"")
        binding.end()
    bindings.end()
    return request_id


def read_snmp_request(connection, deadline):
    header = _read_exact(connection, 2, deadline)
    if header[0] != 0x30:
        raise ValueError("snmp_fixture_message_sequence")
    size = header[1]
    if size & 0x80:
        count = size & 0x7f
        if count not in (1, 2):
            raise ValueError("snmp_fixture_length")
        encoded = _read_exact(connection, count, deadline)
        size = int.from_bytes(encoded, "big")
        if encoded[0] == 0 or size < 128 or count == 2 and size <= 255:
            raise ValueError("snmp_fixture_noncanonical_length")
        header += encoded
    if not 1 <= size <= fixture.SNMP_MAX_REQUEST_BYTES - len(header):
        raise ValueError("snmp_fixture_frame_limit")
    return parse_snmp_request(header + _read_exact(connection, size, deadline))


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.REDIS_SNMP_CASES:
        raise ValueError("invalid_redis_snmp_fixture_case")
    if case.startswith("redis-"):
        read_redis_request(connection, deadline)
        response = fixture.redis_response(case)
    else:
        request_id = read_snmp_request(connection, deadline)
        response = fixture.snmp_response(case, request_id)
    on_request()
    if response is None:
        time.sleep(_remaining(deadline))
        return
    connection.settimeout(min(2, _remaining(deadline)))
    connection.sendall(response)
    # Returning closes this connection in the owner. There is no command loop,
    # correction request, next-OID operation or redirection follow-up.
