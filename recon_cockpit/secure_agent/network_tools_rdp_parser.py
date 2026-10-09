"""One bounded RDP connection confirmation, without a security handshake.

The fixed request offers TLS (PROTOCOL_SSL). Protocol selection and failure
fields are untrusted peer reports, never verified service or session security.
"""

import struct


TOOL_ID = "rdp_initial_negotiation_v1"
PARSER_VERSION = "rdp-initial-negotiation-v1"
SEMANTICS = "untrusted_rdp_negotiation_metadata"
MAX_OUTPUT_BYTES = 19
# MS-RDPBCGR 2.2.1.2.1 includes the reserved 0x04 bit, which clients ignore.
RESPONSE_FLAGS_MASK = 0x1f
PROTOCOLS = {0: "standard_rdp", 1: "tls"}
FAILURES = {
    1: "SSL_REQUIRED_BY_SERVER",
    2: "SSL_NOT_ALLOWED_BY_SERVER",
    3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS",
    5: "HYBRID_REQUIRED_BY_SERVER",
    6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
    7: "ENTRA_AUTH_REQUIRED_BY_SERVER",
}
_FIELDS = {"parser_version", "kind", "semantics", "response_type",
    "selected_protocol", "response_flags", "failure_code", "failure_name",
    "security_handshake_performed", "authenticated_session", "service_identity_verified"}


def validate_result(value):
    """Return detached, closed metadata that cannot imply TLS or authentication."""
    if (type(value) is not dict or set(value) != _FIELDS
            or value["parser_version"] != PARSER_VERSION
            or value["kind"] != "rdp_initial_negotiation"
            or value["semantics"] != SEMANTICS
            or value["security_handshake_performed"] is not False
            or value["authenticated_session"] is not False
            or value["service_identity_verified"] is not False):
        raise ValueError("invalid_rdp_negotiation_observation")
    kind, flags, code = value["response_type"], value["response_flags"], value["failure_code"]
    if kind == "selection":
        valid = (value["selected_protocol"] in ("standard_rdp", "tls")
            and type(flags) is int and 0 <= flags <= RESPONSE_FLAGS_MASK
            and code is None and value["failure_name"] is None)
    elif kind == "legacy":
        valid = (value["selected_protocol"] == "standard_rdp" and flags is None
            and code is None and value["failure_name"] is None)
    elif kind == "failure":
        valid = (value["selected_protocol"] is None and type(flags) is int and flags == 0
            and type(code) is int and code in FAILURES and value["failure_name"] == FAILURES[code])
    else:
        valid = False
    if not valid:
        raise ValueError("invalid_rdp_negotiation_fields")
    return dict(value)


def parse_output(raw, stderr=b""):
    """Parse exactly one complete supported TPKT; trailing bytes are unsupported."""
    if type(raw) is not bytes or type(stderr) is not bytes or stderr or len(raw) not in (11, 19):
        raise ValueError("invalid_rdp_negotiation_capture")
    if (raw[:2] != b"\x03\x00" or int.from_bytes(raw[2:4], "big") != len(raw)
            or raw[4] != len(raw) - 5 or raw[5] != 0xd0 or raw[10] != 0):
        raise ValueError("invalid_rdp_connection_confirm")
    # Source and destination references are intentionally ignored per the
    # connection-confirm processing rules in MS-RDPBCGR 3.2.5.3.2.
    result = {"parser_version": PARSER_VERSION, "kind": "rdp_initial_negotiation",
        "semantics": SEMANTICS, "response_type": "legacy",
        "selected_protocol": "standard_rdp", "response_flags": None,
        "failure_code": None, "failure_name": None, "security_handshake_performed": False,
        "authenticated_session": False, "service_identity_verified": False}
    if len(raw) == 19:
        kind, flags, length, value = struct.unpack("<BBHI", raw[11:])
        if length != 8:
            raise ValueError("invalid_rdp_negotiation_length")
        if kind == 2 and value in PROTOCOLS and flags & ~RESPONSE_FLAGS_MASK == 0:
            result.update(response_type="selection", selected_protocol=PROTOCOLS[value], response_flags=flags)
        elif kind == 3 and flags == 0 and value in FAILURES:
            result.update(response_type="failure", selected_protocol=None, response_flags=0,
                failure_code=value, failure_name=FAILURES[value])
        else:
            raise ValueError("unsupported_rdp_negotiation_response")
    return validate_result(result)
