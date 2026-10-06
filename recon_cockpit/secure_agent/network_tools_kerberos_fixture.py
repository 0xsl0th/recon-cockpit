"""Owner-only finite KDC errors for two synthetic, unauthenticated AS requests."""

import datetime
import importlib.util
from pathlib import Path
import re
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("kerberos_public_fixture",
                                                 Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _tlv(raw, offset=0):
    if offset + 2 > len(raw):
        raise ValueError("incomplete_kerberos_der")
    tag, size = raw[offset:offset + 2]
    offset += 2
    if tag & 0x1f == 0x1f or size == 0x80:
        raise ValueError("unsupported_kerberos_der_tag_or_length")
    if size & 0x80:
        count = size & 0x7f
        if count not in (1, 2) or offset + count > len(raw) or raw[offset] == 0:
            raise ValueError("invalid_kerberos_der_length")
        size = int.from_bytes(raw[offset:offset + count], "big")
        offset += count
        if size < 128 or count == 2 and size < 256:
            raise ValueError("noncanonical_kerberos_der_length")
    if size > fixture.KERBEROS_MAX_REQUEST_BYTES or offset + size > len(raw):
        raise ValueError("incomplete_kerberos_der_payload")
    return tag, raw[offset:offset + size], offset + size


def _one(raw, tag):
    actual, payload, end = _tlv(raw)
    if actual != tag or end != len(raw):
        raise ValueError("unexpected_kerberos_der_field")
    return payload


def _fields(raw, tags):
    sequence, offset, values = _one(raw, 0x30), 0, []
    for expected in tags:
        tag, value, offset = _tlv(sequence, offset)
        if tag != expected:
            raise ValueError("unsupported_kerberos_request_field")
        values.append(value)
    if offset != len(sequence):
        raise ValueError("extra_kerberos_request_field")
    return values


def _integer(raw):
    value = _one(raw, 2)
    if (not 1 <= len(value) <= 4 or value[0] & 128
            or len(value) > 1 and value[0] == 0 and not value[1] & 128):
        raise ValueError("invalid_kerberos_integer")
    return int.from_bytes(value, "big")


def _principal(raw, kind, names):
    name_type, sequence = _fields(raw, (0xa0, 0xa1))
    if _integer(name_type) != kind:
        raise ValueError("invalid_kerberos_principal_type")
    values = _fields(sequence, (0x1b,) * len(names))
    if values != [name.encode("ascii") for name in names]:
        raise ValueError("unapproved_kerberos_principal")


def validate_as_req(raw):
    """Accept initial AS-REQ only; an empty PA-DATA container carries no credentials."""
    if type(raw) is not bytes or not 1 <= len(raw) <= fixture.KERBEROS_MAX_REQUEST_BYTES:
        raise ValueError("invalid_kerberos_request_size")
    request = _one(raw, 0x6a)
    try:
        version, message, padata, body = _fields(request, (0xa1, 0xa2, 0xa3, 0xa4))
    except ValueError:
        version, message, body = _fields(request, (0xa1, 0xa2, 0xa4))
    else:
        # The pinned Go serializer preserves its non-nil empty PAData slice.
        # No entry, encrypted timestamp, AP-REQ or other credential is accepted.
        if padata != b"\x30\x00":
            raise ValueError("kerberos_preauthentication_credentials_forbidden")
    if _integer(version) != 5 or _integer(message) != 10:
        raise ValueError("kerberos_as_req_only")
    options, cname, realm, sname, till, nonce, etypes = _fields(body,
        (0xa0, 0xa1, 0xa2, 0xa3, 0xa5, 0xa7, 0xa8))
    if _one(options, 3) != b"\x00\x00\x00\x00\x10":
        raise ValueError("unsupported_kerberos_options")
    if _one(realm, 0x1b) != fixture.KERBEROS_REALM.encode("ascii"):
        raise ValueError("unapproved_kerberos_realm")
    _principal(sname, 2, ("krbtgt", fixture.KERBEROS_REALM))
    principal = None
    for name in fixture.KERBEROS_PRINCIPALS:
        try:
            _principal(cname, 1, (name,))
            principal = name
            break
        except ValueError:
            continue
    if principal is None:
        raise ValueError("unapproved_kerberos_client")
    timestamp = _one(till, 0x18)
    if re.fullmatch(rb"[0-9]{14}Z", timestamp) is None:
        raise ValueError("invalid_kerberos_till_time")
    try:
        datetime.datetime.strptime(timestamp.decode("ascii"), "%Y%m%d%H%M%SZ")
    except (ValueError, UnicodeError):
        raise ValueError("invalid_kerberos_till_time") from None
    if _integer(nonce) > 2147483646 or _fields(etypes, (2, 2, 2)) != [b"\x12", b"\x11", b"\x17"]:
        raise ValueError("unsupported_kerberos_nonce_or_etypes")
    return principal


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("kerberos_fixture_deadline")
    return remaining


def _read_exact(connection, size, deadline):
    value = bytearray()
    while len(value) < size:
        connection.settimeout(min(2, _remaining(deadline)))
        part = connection.recv(size - len(value))
        if not part:
            raise ValueError("incomplete_kerberos_frame")
        value.extend(part)
    return bytes(value)


class Exchange:
    def __init__(self, case, on_request):
        if type(case) is not str or case not in fixture.KERBEROS_CASES:
            raise ValueError("invalid_kerberos_case")
        self.case, self.on_request, self.requests = case, on_request, 0


def serve(connection, exchange, deadline):
    if type(exchange) is not Exchange or exchange.requests >= fixture.KERBEROS_MAX_REQUESTS:
        raise ValueError("kerberos_fixture_request_limit")
    size = int.from_bytes(_read_exact(connection, 4, deadline), "big")
    if not 1 <= size <= fixture.KERBEROS_MAX_REQUEST_BYTES:
        raise ValueError("invalid_kerberos_frame_size")
    principal = validate_as_req(_read_exact(connection, size, deadline))
    if principal != fixture.KERBEROS_PRINCIPALS[exchange.requests]:
        raise ValueError("kerberos_fixture_principal_order")
    exchange.requests += 1
    exchange.on_request()
    response = fixture.response_for(exchange.case, principal)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    connection.settimeout(min(2, _remaining(deadline)))
    connection.sendall(len(response).to_bytes(4, "big") + response)
