"""Owner-only finite TCP AAAA/PTR replies; no resolver or returned-host access."""

from ipaddress import IPv6Address
import struct
import time

try:
    from . import network_tools_dns_address_spec as spec
except ImportError:
    import importlib.util
    from pathlib import Path
    _definition = importlib.util.spec_from_file_location("fixed_dns_address_spec",
        Path(__file__).with_name("network_tools_dns_address_spec.py"))
    spec = importlib.util.module_from_spec(_definition)
    _definition.loader.exec_module(spec)


def _tool(tool_id):
    if type(tool_id) is not str or tool_id not in spec.TOOL_IDS:
        raise ValueError("invalid_dns_address_tool")
    return tool_id


def _name(value):
    # Only compiled public fixture names enter this encoder, including the
    # deliberately unsupported underscore/root PTR cases.
    return b"".join(bytes([len(label)]) + label.encode("ascii")
                    for label in value.rstrip(".").split(".") if label) + b"\0"


def _question(tool_id):
    return _name(spec.QUERY_NAMES[_tool(tool_id)]) + struct.pack("!HH", spec.QUERY_TYPE_NUMBERS[tool_id], 1)


def query(tool_id, transaction_id=b"\0\0"):
    _tool(tool_id)
    if type(transaction_id) is not bytes or len(transaction_id) != 2:
        raise ValueError("invalid_dns_address_transaction_id")
    return transaction_id + struct.pack("!HHHHH", 0, 1, 0, 0, 0) + _question(tool_id)


def validate_query(value, tool_id):
    _tool(tool_id)
    if type(value) is not bytes or len(value) < 2 or value != query(tool_id, value[:2]):
        raise ValueError("invalid_dns_address_question")
    return value


def records(case):
    """The predeclared record values; malformed wire cases have no useful claim."""
    tool_id = spec.tool_for_case(case)
    suffix = case[len(spec.PREFIXES[tool_id]):]
    ordinary = spec.RECORDS_BY_TOOL[tool_id]
    if suffix in ("nodata", "nxdomain", "refused", "stalled"):
        return ()
    if suffix == "single":
        return ordinary[:1]
    if suffix in ("four", "record-limit"):
        count = 4 if suffix == "four" else 5
        return tuple(("2001:db8::" + str(index) if tool_id == spec.AAAA else
                      "host" + str(index) + ".harbordesk.test.", 60)
                     for index in range(1, count + 1))
    if suffix == "mapped":
        return (spec.MAPPED_RECORD,)
    if suffix == "root":
        return ((".", 60),)
    if suffix == "injected":
        return ordinary + (spec.FOREIGN_RECORD_BY_TOOL[tool_id],)
    if suffix == "duplicate":
        return (ordinary[0], (ordinary[0][0], ordinary[0][1] + 1))
    if suffix == "malformed-value" and tool_id == spec.PTR:
        return (("_bad.harbordesk.test.", 60),)
    return ordinary


def _record(tool_id, record, suffix):
    value, ttl = record
    kind = spec.QUERY_TYPE_NUMBERS[tool_id]
    data = IPv6Address(value).packed if tool_id == spec.AAAA else _name(value)
    if suffix == "wrong-type":
        kind, data = 1, b"\xc0\x00\x02\x01"
    elif suffix == "alias":
        kind, data = 5, _name("outside.invalid.")
    elif suffix == "malformed-value" and tool_id == spec.AAAA:
        data = data[:-1]  # AAAA RDATA must contain exactly sixteen bytes.
    return b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, ttl, len(data)) + data


def response(case, raw_query):
    tool_id = spec.tool_for_case(case)
    validate_query(raw_query, tool_id)
    suffix = case[len(spec.PREFIXES[tool_id]):]
    if suffix == "stalled":
        return None
    selected = records(case)
    rcode = 3 if suffix == "nxdomain" else 5 if suffix == "refused" else 0
    additional = b""
    if suffix in ("injected", "output-limit"):
        note = spec.HOSTILE_NOTE.encode("ascii")
        # The wire response remains below 4096 bytes. Native dig's escaped TXT
        # rendering expands this finite data beyond the 8192-byte capture cap.
        text = ((bytes([255]) + b"\x01" * 255) * 12 if suffix == "output-limit"
                else bytes([len(note)]) + note)
        additional = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(text)) + text
    header = raw_query[:2] + struct.pack("!HHHHH", 0x8400 | rcode, 1, len(selected), 0, int(bool(additional)))
    question = _question(tool_id)
    if suffix == "wrong-question":
        question = question[:-4] + struct.pack("!HH", 1, 1)
    answers = b"\xc0" if suffix == "malformed" else b"".join(
        _record(tool_id, record, suffix) for record in selected)
    result = header + question + answers + additional
    if suffix == "truncated":
        result = result[:-1]
    if len(result) > spec.MAX_RESPONSE_BYTES:
        raise ValueError("dns_address_response_limit")
    return result


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("dns_address_fixture_deadline")
    return remaining


def _read_exact(connection, count, deadline):
    result = bytearray()
    while len(result) < count:
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("dns_address_fixture_incomplete")
        result.extend(chunk)
    return bytes(result)


def read_request(connection, deadline, tool_id):
    _tool(tool_id)
    size = struct.unpack("!H", _read_exact(connection, 2, deadline))[0]
    if not 12 <= size <= spec.MAX_QUERY_BYTES:
        raise ValueError("dns_address_fixture_frame_limit")
    return validate_query(_read_exact(connection, size, deadline), tool_id)


def serve(connection, *, case, deadline, on_request):
    tool_id = spec.tool_for_case(case)
    raw_query = read_request(connection, deadline, tool_id)
    on_request()  # Progress requires the complete exact fixed question first.
    raw_response = response(case, raw_query)
    if raw_response is None:
        time.sleep(_remaining(deadline))
        return
    framed = struct.pack("!H", len(raw_response)) + raw_response
    chunks = (framed[index:index + 3] for index in range(0, len(framed), 3)) if case.endswith("-fragmented") else (framed,)
    for chunk in chunks:
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(chunk)
    # The owner closes the connection on return. No second question is read;
    # neither address/name records nor TXT instructions trigger another lookup.
