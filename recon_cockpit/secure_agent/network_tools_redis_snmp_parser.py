"""Bounded, unauthenticated service reports from fixed Redis/SNMP commands.

The service controls every reported value. These observations establish neither
server identity nor vulnerability or authorization for another action.
"""

import re


REDIS_TOOL_ID = "redis_server_info_v1"
SNMP_TOOL_ID = "snmp_system_get_v1"
REDIS_PARSER_VERSION = "redis-info-server-v1"
SNMP_PARSER_VERSION = "snmp-system-text-v1"
MAX_OUTPUT_BYTES = 8192
SEMANTICS = "untrusted_service_report"
SNMP_OIDS = (".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0")
_REDIS_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,15})?")
_INFO_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,9}")
_NO_SUCH_OBJECT = "No Such Object available on this agent at this OID"
_HEX_LINE = re.compile(r"(?:[0-9A-F]{2} ){1,16}")


def _printable(value, maximum, *, empty=False):
    return (type(value) is str and (empty or bool(value)) and len(value) <= maximum
            and all(32 <= ord(char) <= 126 for char in value))


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _bytes(raw, stderr):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or stderr):
        raise ValueError("invalid_redis_snmp_output")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_redis_snmp_encoding") from None


def validate_result(tool_id, value):
    """Validate and detach the complete closed observation schema."""
    if tool_id == REDIS_TOOL_ID:
        if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics", "metadata"}
                or value["parser_version"] != REDIS_PARSER_VERSION or value["kind"] != "redis_server_info"
                or value["semantics"] != SEMANTICS or type(value["metadata"]) is not dict):
            raise ValueError("invalid_redis_server_info")
        metadata = value["metadata"]
        if (set(metadata) != {"version", "mode", "arch_bits", "tcp_port"}
                or type(metadata["version"]) is not str or _REDIS_VERSION.fullmatch(metadata["version"]) is None
                or type(metadata["mode"]) is not str or metadata["mode"] not in {"standalone", "sentinel", "cluster"}
                or type(metadata["arch_bits"]) is not int or metadata["arch_bits"] not in {32, 64}
                or not _integer(metadata["tcp_port"], 1, 65535)):
            raise ValueError("invalid_redis_server_metadata")
        return {**value, "metadata": dict(metadata)}
    if tool_id == SNMP_TOOL_ID:
        if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics", "variables"}
                or value["parser_version"] != SNMP_PARSER_VERSION or value["kind"] != "snmp_system_metadata"
                or value["semantics"] != SEMANTICS or type(value["variables"]) is not list
                or len(value["variables"]) != len(SNMP_OIDS)):
            raise ValueError("invalid_snmp_system_metadata")
        rows = []
        for index, (oid, row) in enumerate(zip(SNMP_OIDS, value["variables"])):
            if (type(row) is not dict or set(row) != {"oid", "type", "value"}
                    or row["oid"] != oid or type(row["type"]) is not str):
                raise ValueError("invalid_snmp_variable")
            if row["type"] == "no_such_object":
                if row["value"] is not None:
                    raise ValueError("invalid_snmp_absence")
            elif index == 1:
                if row["type"] != "timeticks" or not _integer(row["value"], 0, 4294967295):
                    raise ValueError("invalid_snmp_timeticks")
            elif row["type"] != "octet_string" or not _printable(row["value"], 256):
                raise ValueError("invalid_snmp_octet_string")
            rows.append(dict(row))
        return {**value, "variables": rows}
    raise ValueError("unsupported_redis_snmp_parser")


def parse_redis_output(raw, stderr=b""):
    text = _bytes(raw, stderr)
    # The captured RESP2 --raw profile preserves the INFO bulk value's CRLF
    # records without appending a separate newline.
    if not text.startswith("# Server\r\n") or not text.endswith("\r\n"):
        raise ValueError("incomplete_redis_info")
    lines = text.split("\r\n")
    if not 6 <= len(lines) <= 66 or lines[-1] != "":
        raise ValueError("invalid_redis_info_lines")
    fields = {}
    for line in lines[1:-1]:
        if ":" not in line:
            raise ValueError("invalid_redis_info_field")
        key, value = line.split(":", 1)
        if (_INFO_KEY.fullmatch(key) is None or key in fields
                or not _printable(value, 512, empty=True)):
            raise ValueError("invalid_redis_info_field")
        fields[key] = value
    if not {"redis_version", "redis_mode", "arch_bits", "tcp_port"} <= set(fields):
        raise ValueError("incomplete_redis_server_metadata")
    if any(_DECIMAL.fullmatch(fields[key]) is None for key in ("arch_bits", "tcp_port")):
        raise ValueError("invalid_redis_server_integer")
    return validate_result(REDIS_TOOL_ID, {"parser_version": REDIS_PARSER_VERSION,
        "kind": "redis_server_info", "semantics": SEMANTICS,
        "metadata": {"version": fields["redis_version"], "mode": fields["redis_mode"],
                     "arch_bits": int(fields["arch_bits"]), "tcp_port": int(fields["tcp_port"])}})


def _snmp_string(lines):
    # -Ox makes OCTET STRING bytes unambiguous even when a malicious value
    # contains newlines or strings that resemble another OID's printed row.
    if not 1 <= len(lines) <= 16:
        raise ValueError("invalid_snmp_hex_lines")
    parts = []
    for index, line in enumerate(lines):
        if _HEX_LINE.fullmatch(line) is None:
            raise ValueError("invalid_snmp_hex_string")
        chunk = bytes.fromhex(line)
        if index < len(lines) - 1 and len(chunk) != 16:
            raise ValueError("invalid_snmp_hex_wrapping")
        parts.append(chunk)
    try:
        value = b"".join(parts).decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("unsupported_snmp_string") from None
    if not _printable(value, 256):
        raise ValueError("unsupported_snmp_string")
    return value


def parse_snmp_output(raw, stderr=b""):
    text = _bytes(raw, stderr)
    lines = text.split("\n")
    if not 4 <= len(lines) <= 34 or lines[-1] != "":
        raise ValueError("incomplete_snmp_variables")
    rows, offset = [], 0
    for index, oid in enumerate(SNMP_OIDS):
        if offset >= len(lines) - 1:
            raise ValueError("incomplete_snmp_variables")
        line = lines[offset]
        offset += 1
        prefix = oid + " = "
        if not line.startswith(prefix):
            raise ValueError("unexpected_snmp_oid")
        value = line[len(prefix):]
        if value == _NO_SUCH_OBJECT:
            kind, value = "no_such_object", None
        elif index == 1:
            # -Ot prints only the raw ticks at this one fixed requested OID.
            if _DECIMAL.fullmatch(value) is None:
                raise ValueError("invalid_snmp_timeticks")
            kind, value = "timeticks", int(value)
        else:
            if not value.startswith("Hex-STRING: "):
                raise ValueError("invalid_snmp_string_type")
            chunks = [value[12:]]
            while offset < len(lines) - 1 and not lines[offset].startswith("."):
                chunks.append(lines[offset])
                offset += 1
            kind, value = "octet_string", _snmp_string(chunks)
        rows.append({"oid": oid, "type": kind, "value": value})
    if offset != len(lines) - 1:
        raise ValueError("unexpected_snmp_variables")
    return validate_result(SNMP_TOOL_ID, {"parser_version": SNMP_PARSER_VERSION,
        "kind": "snmp_system_metadata", "semantics": SEMANTICS, "variables": rows})
