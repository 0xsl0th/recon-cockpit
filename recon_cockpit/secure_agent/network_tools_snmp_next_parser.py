"""One untrusted SNMP successor, with no inventory or follow-up authority."""

import re


TOOL_ID = "snmp_interface_next_v1"
PARSER_VERSION = "snmp-interface-next-text-v1"
SEMANTICS = "untrusted_snmp_successor_metadata"
QUERY_OID = ".1.3.6.1.2.1.2.2.1.2"
MAX_OUTPUT_BYTES = 8192
MAX_OID_ARCS = 128
MAX_DESCRIPTION_BYTES = 255
END_OF_MIB_VIEW = "No more variables left in this MIB View (It is past the end of the MIB tree)"
_ARC = re.compile(r"0|[1-9][0-9]{0,9}")
_INTEGER = re.compile(r"0|-?[1-9][0-9]{0,9}")
_HEX_LINE = re.compile(r"(?:[0-9A-F]{2} ){1,16}")


def _oid(value):
    if type(value) is not str or not value.startswith(".") or len(value) > MAX_OID_ARCS * 11:
        raise ValueError("invalid_snmp_next_oid")
    parts = value[1:].split(".")
    if not 2 <= len(parts) <= MAX_OID_ARCS or any(_ARC.fullmatch(part) is None for part in parts):
        raise ValueError("invalid_snmp_next_oid")
    arcs = tuple(int(part) for part in parts)
    if (any(arc > 4294967295 for arc in arcs) or arcs[0] > 2
            or (arcs[0] < 2 and arcs[1] > 39)):
        raise ValueError("invalid_snmp_next_oid")
    return arcs


def _description(value):
    return (type(value) is str and len(value) <= MAX_DESCRIPTION_BYTES
            and all(32 <= ord(char) <= 126 for char in value))


def validate_result(value):
    """Validate the closed summary; only a single reported successor is known."""
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics",
            "query_oid", "returned_oid", "outcome", "interface_index", "description",
            "service_identity_verified"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "snmp_interface_next_metadata"
            or value["semantics"] != SEMANTICS or value["query_oid"] != QUERY_OID
            or type(value["outcome"]) is not str or value["outcome"] not in {
                "interface_description", "end_of_mib_view", "outside_ifdescr_subtree"}
            or value["service_identity_verified"] is not False):
        raise ValueError("invalid_snmp_next_observation")
    seed, returned = _oid(QUERY_OID), _oid(value["returned_oid"])
    if value["outcome"] == "end_of_mib_view":
        if returned != seed or value["interface_index"] is not None or value["description"] is not None:
            raise ValueError("invalid_snmp_next_end_of_view")
    else:
        if returned <= seed:
            raise ValueError("nonincreasing_snmp_next_oid")
        inside = returned[:len(seed)] == seed
        if value["outcome"] == "interface_description":
            if (not inside or len(returned) != len(seed) + 1
                    or type(value["interface_index"]) is not int
                    or not 1 <= value["interface_index"] <= 2147483647
                    or value["interface_index"] != returned[-1] or not _description(value["description"])):
                raise ValueError("invalid_snmp_next_interface")
        elif inside or value["interface_index"] is not None or value["description"] is not None:
            raise ValueError("invalid_snmp_next_outside_subtree")
    return dict(value)


def _hex_description(lines):
    if not 1 <= len(lines) <= 16:
        raise ValueError("invalid_snmp_next_hex_lines")
    chunks = []
    for index, line in enumerate(lines):
        if _HEX_LINE.fullmatch(line) is None:
            raise ValueError("invalid_snmp_next_hex_string")
        chunk = bytes.fromhex(line)
        if index < len(lines) - 1 and len(chunk) != 16:
            raise ValueError("invalid_snmp_next_hex_wrapping")
        chunks.append(chunk)
    try:
        value = b"".join(chunks).decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("unsupported_snmp_next_description") from None
    if not _description(value):
        raise ValueError("unsupported_snmp_next_description")
    return value


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw or stderr
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES):
        raise ValueError("invalid_snmp_next_output")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_snmp_next_encoding") from None
    lines = text.split("\n")
    if not 2 <= len(lines) <= 17 or lines[-1] != "":
        raise ValueError("incomplete_snmp_next_output")
    lines.pop()
    returned_oid, separator, rendered = lines[0].partition(" = ")
    if not separator:
        raise ValueError("invalid_snmp_next_variable")
    seed, returned = _oid(QUERY_OID), _oid(returned_oid)
    description, interface_index = None, None
    if rendered == END_OF_MIB_VIEW and len(lines) == 1:
        outcome = "end_of_mib_view"
    elif returned <= seed:
        raise ValueError("nonincreasing_snmp_next_oid")
    elif returned[:len(seed)] == seed:
        outcome, interface_index = "interface_description", returned[-1]
        if rendered == '""' and len(lines) == 1:
            description = ""  # Net-SNMP emits bare quotes for a zero-length OCTET STRING, even with -Ox.
        elif rendered.startswith("Hex-STRING: "):
            description = _hex_description([rendered[12:], *lines[1:]])
        else:
            raise ValueError("unsupported_snmp_next_description_type")
    else:
        # Finite supported successor type; validate it even though its value is
        # not released. No exception or arbitrary text becomes an outside result.
        value = rendered.removeprefix("INTEGER: ")
        if (len(lines) != 1 or not rendered.startswith("INTEGER: ")
                or _INTEGER.fullmatch(value) is None or not -2147483648 <= int(value) <= 2147483647):
            raise ValueError("unsupported_snmp_next_outside_value")
        outcome = "outside_ifdescr_subtree"
    return validate_result({"parser_version": PARSER_VERSION, "kind": "snmp_interface_next_metadata",
        "semantics": SEMANTICS, "query_oid": QUERY_OID, "returned_oid": returned_oid,
        "outcome": outcome, "interface_index": interface_index, "description": description,
        "service_identity_verified": False})
