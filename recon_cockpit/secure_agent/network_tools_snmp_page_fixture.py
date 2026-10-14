"""Owner-only single GETBULK fixture: one seed, four repetitions, no paging."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_snmp_page_spec as spec
else:
    _definition = importlib.util.spec_from_file_location("snmp_page_spec",
        Path(__file__).with_name("network_tools_snmp_page_spec.py"))
    spec = importlib.util.module_from_spec(_definition)
    _definition.loader.exec_module(spec)


def _shared(name):
    # Defer owner dependencies until a request/response is handled. Shared
    # fixture registration may import the pure specification without a cycle.
    if __package__:
        return __import__(__package__ + "." + name, fromlist=[name])
    definition = importlib.util.spec_from_file_location("snmp_page_" + name,
        Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(module)
    return module


def _request_id(value):
    if (type(value) is not bytes or not 1 <= len(value) <= 4 or value[0] & 0x80
            or len(value) > 1 and value[0] == 0 and value[1] < 128):
        raise ValueError("invalid_snmp_page_request_id")
    return value


def request(request_id=b"\x01"):
    """Compile the only allowed GetBulk question; only its canonical ID varies."""
    request_id = _request_id(request_id)
    tlv = _shared("network_tools_fixture").snmp_tlv
    binding = tlv(0x30, tlv(6, spec.SEED_OID_BYTES) + tlv(5, b""))
    pdu = tlv(0xa5, tlv(2, request_id) + tlv(2, b"\0") + tlv(2, b"\x04") + tlv(0x30, binding))
    return tlv(0x30, tlv(2, b"\x01") + tlv(4, spec.COMMUNITY) + pdu)


def response(case, request_id=b"\x01"):
    """Finite synthetic responses, including deliberately unsupported pages."""
    if type(case) is not str or case not in spec.CASES:
        raise ValueError("invalid_snmp_page_case")
    request_id = _request_id(request_id)
    if case == "snmp-page-stalled":
        return None
    if case == "snmp-page-malformed":
        return b"\x30\x80\x00\x00"
    rows = [(spec.SEED_OID_BYTES + bytes([index]), 4, description.encode("ascii"))
        for index, description in enumerate(spec.DESCRIPTIONS, 1)]
    outside = [(spec.SEED_OID_BYTES[:-1] + b"\x03" + bytes([index]), 2, b"\x06")
        for index in range(1, 5)]
    status, error_index = b"\0", b"\0"
    if case == "snmp-page-empty":
        rows = [(oid, tag, b"") for oid, tag, value in rows]
    elif case == "snmp-page-end-of-view":
        rows = [(spec.SEED_OID_BYTES, 0x82, b"")]
    elif case == "snmp-page-outside-subtree":
        rows = outside
    elif case == "snmp-page-mixed-boundary":
        rows = rows[:2] + outside[:2]
    elif case == "snmp-page-end-after-rows":
        rows = rows[:2] + [(rows[1][0], 0x82, b"")] * 2
    elif case == "snmp-page-injected":
        rows[1] = (rows[1][0], 4, spec.HOSTILE_NOTE.encode("ascii"))
    elif case == "snmp-page-short":
        rows = rows[:3]
    elif case == "snmp-page-empty-page":
        rows = []
    elif case == "snmp-page-nonincreasing":
        rows[1], rows[2] = rows[2], rows[1]
    elif case == "snmp-page-duplicate":
        rows[1] = rows[0]
    elif case == "snmp-page-wrong-type":
        rows[1] = (rows[1][0], 2, b"\x06")
    elif case == "snmp-page-extra-varbind":
        rows.append((spec.SEED_OID_BYTES + b"\x05", 4, b"excess interface"))
    elif case == "snmp-page-after-end":
        rows[1] = (rows[0][0], 0x82, b"")
    elif case == "snmp-page-denied":
        rows = [(spec.SEED_OID_BYTES, 5, b"")]
        status, error_index = b"\x10", b"\x01"
    elif case == "snmp-page-output-limit":
        rows[0] = (rows[0][0], 4, b"X" * 12000)
    tlv = _shared("network_tools_fixture").snmp_tlv
    bindings = b"".join(tlv(0x30, tlv(6, oid) + tlv(tag, value)) for oid, tag, value in rows)
    pdu = tlv(0xa2, tlv(2, request_id) + tlv(2, status) + tlv(2, error_index) + tlv(0x30, bindings))
    raw = tlv(0x30, tlv(2, b"\x01") + tlv(4, spec.COMMUNITY) + pdu)
    if case == "snmp-page-truncated":
        raw = raw[:-1]
    if len(raw) > spec.MAX_RESPONSE_BYTES:
        raise ValueError("snmp_page_fixture_response_limit")
    return raw


def parse_request(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= spec.MAX_REQUEST_BYTES:
        raise ValueError("snmp_page_fixture_request_limit")
    Reader = _shared("network_tools_redis_snmp_fixture").Reader
    outer = Reader(raw)
    message = Reader(outer.expect(0x30))
    outer.end()
    message.expect(2, b"\x01")
    message.expect(4, spec.COMMUNITY)
    pdu = Reader(message.expect(0xa5))
    message.end()
    request_id = _request_id(pdu.expect(2))
    pdu.expect(2, b"\0")  # Non-repeaters zero, not error-status.
    pdu.expect(2, b"\x04")  # Exactly four maximum repetitions.
    bindings = Reader(pdu.expect(0x30))
    pdu.end()
    binding = Reader(bindings.expect(0x30))
    binding.expect(6, spec.SEED_OID_BYTES)
    binding.expect(5, b"")
    binding.end()
    bindings.end()
    return request_id


def read_request(connection, deadline):
    owner = _shared("network_tools_redis_snmp_fixture")
    header = owner._read_exact(connection, 2, deadline)
    if header[0] != 0x30:
        raise ValueError("snmp_page_fixture_message_sequence")
    size = header[1]
    if size & 0x80:
        count = size & 0x7f
        if count not in (1, 2):
            raise ValueError("snmp_page_fixture_length")
        encoded = owner._read_exact(connection, count, deadline)
        size = int.from_bytes(encoded, "big")
        if encoded[0] == 0 or size < 128 or count == 2 and size <= 255:
            raise ValueError("snmp_page_fixture_noncanonical_length")
        header += encoded
    if not 1 <= size <= spec.MAX_REQUEST_BYTES - len(header):
        raise ValueError("snmp_page_fixture_frame_limit")
    return parse_request(header + owner._read_exact(connection, size, deadline))


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("snmp_page_fixture_deadline")
    return remaining


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in spec.CASES:
        raise ValueError("invalid_snmp_page_case")
    request_id = read_request(connection, deadline)
    on_request()
    raw = response(case, request_id)
    if raw is None:
        time.sleep(_remaining(deadline))
        return
    width = 3 if case == "snmp-page-fragmented" else len(raw)
    for offset in range(0, len(raw), width):
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(raw[offset:offset + width])
    # The owner closes on return. No response OID or buffered second question
    # can select another request, continuation, target or community.
