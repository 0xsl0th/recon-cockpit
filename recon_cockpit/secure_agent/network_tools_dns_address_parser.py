"""Finite untrusted AAAA/PTR observations, without resolution or follow-up authority."""

from ipaddress import IPv6Address
import json
import re

if __package__:
    from . import network_tools_dns_address_spec as spec
else:
    import network_tools_dns_address_spec as spec


MAX_OUTPUT_BYTES = 8192
MAX_NORMALIZED_BYTES = 3000
DIG_DENIED_PROBE = b"net.c:136:try_proto(): socket(): Operation not permitted (1)\n"
KINDS = {spec.AAAA: "dns_ipv6_metadata", spec.PTR: "dns_reverse_metadata"}
SEMANTICS = {spec.AAAA: "untrusted_dns_ipv6_metadata", spec.PTR: "untrusted_dns_reverse_metadata"}
_FIELDS = {spec.AAAA: "address", spec.PTR: "target"}
_HEADER = re.compile(r";; ->>HEADER<<- opcode: QUERY, status: (NOERROR|NXDOMAIN), id: ([0-9]{1,5})")
_COUNTS = re.compile(r";; flags: ([a-z ]+); QUERY: 1, ANSWER: ([0-4]), AUTHORITY: 0, ADDITIONAL: ([01])")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ADDRESS = re.compile(r"[0-9A-Fa-f:.]{2,45}")
_TXT_VALUE = r'"(?:[^"\\\x00-\x1f\x7f]|\\(?:[01][0-9]{2}|2[0-4][0-9]|25[0-5]|["\\])){0,1024}"'


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _canonical(tool_id, value):
    if type(value) is not str:
        raise ValueError("invalid_dns_address_value")
    if tool_id == spec.AAAA:
        if _ADDRESS.fullmatch(value) is None:
            raise ValueError("invalid_dns_ipv6_address")
        address = IPv6Address(value)
        # Python 3.14 renders mapped addresses with dotted decimal, whereas
        # earlier runtimes use hex. Keep saved/replayed metadata identical.
        if address.ipv4_mapped is not None:
            mapped = int(address.ipv4_mapped)
            return f"::ffff:{mapped >> 16:x}:{mapped & 65535:x}"
        return str(address)
    if (not 2 <= len(value) <= 253 or not value.endswith(".")
            or any(_LABEL.fullmatch(label) is None for label in value[:-1].split("."))):
        raise ValueError("unsupported_dns_ptr_hostname")
    return value


def _tool(tool_id):
    if type(tool_id) is not str or tool_id not in spec.TOOL_IDS:
        raise ValueError("invalid_dns_address_tool")
    return tool_id


def validate_result(value, tool_id=None):
    """Detach only closed, canonical metadata; omitted tool comes from an exact version."""
    if type(value) is not dict:
        raise ValueError("invalid_dns_address_observation")
    if tool_id is None:
        tool_id = next((tool for tool, version in spec.PARSER_VERSIONS.items()
                        if value.get("parser_version") == version), None)
    _tool(tool_id)
    if (set(value) != {"parser_version", "kind", "semantics", "query_name", "query_type",
            "transport", "status", "records", "additional_txt_count"}
            or value["parser_version"] != spec.PARSER_VERSIONS[tool_id]
            or value["kind"] != KINDS[tool_id] or value["semantics"] != SEMANTICS[tool_id]
            or value["query_name"] != spec.QUERY_NAMES[tool_id]
            or value["query_type"] != spec.QUERY_TYPES[tool_id] or value["transport"] != "tcp"
            or value["status"] not in ("NOERROR", "NXDOMAIN")
            or not _integer(value["additional_txt_count"], 1)
            or type(value["records"]) is not list or len(value["records"]) > spec.MAX_RECORDS):
        raise ValueError("invalid_dns_address_observation")
    field, records, keys = _FIELDS[tool_id], [], []
    for row in value["records"]:
        if (type(row) is not dict or set(row) != {field, "ttl"}
                or not _integer(row["ttl"], 2147483647)
                or _canonical(tool_id, row[field]) != row[field]):
            raise ValueError("invalid_dns_address_record")
        records.append(dict(row))
        keys.append((row[field], row["ttl"]))
    if (keys != sorted(keys) or len({key[0] for key in keys}) != len(keys)
            or (value["status"] == "NXDOMAIN" and (records or value["additional_txt_count"]))):
        raise ValueError("invalid_dns_address_order_or_status")
    result = {**value, "records": records}
    if len(json.dumps(result, ensure_ascii=True).encode("ascii")) > MAX_NORMALIZED_BYTES:
        raise ValueError("dns_address_observation_too_large")
    return result


def parse_output(tool_id, raw, stderr=b""):
    _tool(tool_id)
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or stderr not in (b"", DIG_DENIED_PROBE)):
        raise ValueError("invalid_dns_address_output")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_dns_address_text") from None
    if (not text.endswith("\n") or any(ord(char) < 32 and char not in "\n\t" or ord(char) == 127 for char in text)
            or len(text.split("\n")) > 64 or any(len(line) > 2048 for line in text.split("\n"))):
        raise ValueError("invalid_dns_address_text")
    lines = [line for line in text.split("\n") if line]
    if len(lines) < 5 or lines[0] != ";; Got answer:":
        raise ValueError("invalid_dns_address_transcript")
    header, counts = _HEADER.fullmatch(lines[1]), _COUNTS.fullmatch(lines[2])
    if header is None or counts is None or int(header.group(2)) > 65535:
        raise ValueError("invalid_dns_address_header")
    flags = counts.group(1).split()
    if len(flags) != 2 or set(flags) != {"qr", "aa"}:
        raise ValueError("unsupported_dns_address_flags")
    name, query_type = re.escape(spec.QUERY_NAMES[tool_id]), spec.QUERY_TYPES[tool_id]
    if (lines[3] != ";; QUESTION SECTION:"
            or re.fullmatch(r";" + name + r"[ \t]+IN[ \t]+" + query_type, lines[4]) is None):
        raise ValueError("invalid_dns_address_question")
    answer = re.compile(name + r"[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+" + query_type + r"[ \t]+([^ \t]+)")
    additional = re.compile(name + r"[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+TXT[ \t]+" + _TXT_VALUE)
    answer_count, additional_count = int(counts.group(2)), int(counts.group(3))
    cursor, records, field = 5, [], _FIELDS[tool_id]
    if answer_count:
        if len(lines) < cursor + 1 + answer_count or lines[cursor] != ";; ANSWER SECTION:":
            raise ValueError("invalid_dns_address_answer_count")
        cursor += 1
        for line in lines[cursor:cursor + answer_count]:
            match = answer.fullmatch(line)
            if match is None:
                raise ValueError("invalid_dns_address_answer")
            ttl, advertised = match.groups()
            records.append({field: _canonical(tool_id, advertised), "ttl": int(ttl)})
        cursor += answer_count
    if additional_count:
        if len(lines) < cursor + 2 or lines[cursor] != ";; ADDITIONAL SECTION:":
            raise ValueError("invalid_dns_address_additional_count")
        match = additional.fullmatch(lines[cursor + 1])
        if match is None or int(match.group(1)) > 2147483647:
            raise ValueError("invalid_dns_address_additional_record")
        cursor += 2
    if cursor != len(lines):
        raise ValueError("unexpected_dns_address_output")
    records.sort(key=lambda row: (row[field], row["ttl"]))
    return validate_result({"parser_version": spec.PARSER_VERSIONS[tool_id], "kind": KINDS[tool_id],
        "semantics": SEMANTICS[tool_id], "query_name": spec.QUERY_NAMES[tool_id],
        "query_type": query_type, "transport": "tcp", "status": header.group(1),
        "records": records, "additional_txt_count": additional_count}, tool_id)
