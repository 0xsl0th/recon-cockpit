"""Bounded opaque NSID metadata from one fixed nonrecursive DNS question.

NSID bytes and the presence of EDNS are untrusted response metadata. They are
never decoded into a server identity, instructions or follow-up authority.
"""

import re


TOOL_ID = "dig_dns_nsid_v1"
PARSER_VERSION = "dig-dns-nsid-text-v1"
QUERY_NAME = "harbordesk.test."
SEMANTICS = "untrusted_dns_server_metadata"
MAX_NSID_BYTES = 64
MAX_OUTPUT_BYTES = 8192
DIG_DENIED_PROBE = b"net.c:136:try_proto(): socket(): Operation not permitted (1)\n"
_HEADER = re.compile(r";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ([0-9]{1,5})")
_COUNTS = re.compile(r";; flags: ([a-z ]+); QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: ([01])")
_QUESTION = re.compile(r";harbordesk\.test\.[ \t]+IN[ \t]+A")
_HEX = re.compile(r"(?:[0-9a-f]{2}){0,64}")
_NSID = re.compile(r'; NSID: ((?:[0-9a-f]{2} ){1,64})\("[ -~]*"\)')
_EDNS = "; EDNS: version: 0, flags:; udp: 1232"


def validate_result(value):
    """Return a detached closed result, preserving empty versus absent NSID."""
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics",
            "query_name", "query_type", "transport", "status", "edns_present", "nsid_present",
            "nsid_hex", "nsid_bytes", "service_identity_verified"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "dns_nsid_metadata"
            or value["semantics"] != SEMANTICS or value["query_name"] != QUERY_NAME
            or value["query_type"] != "A" or value["transport"] != "tcp" or value["status"] != "NOERROR"
            or type(value["edns_present"]) is not bool or type(value["nsid_present"]) is not bool
            or type(value["nsid_bytes"]) is not int or not 0 <= value["nsid_bytes"] <= MAX_NSID_BYTES
            or value["service_identity_verified"] is not False):
        raise ValueError("invalid_dns_nsid_observation")
    if value["nsid_present"]:
        if (not value["edns_present"] or type(value["nsid_hex"]) is not str
                or _HEX.fullmatch(value["nsid_hex"]) is None
                or len(value["nsid_hex"]) != value["nsid_bytes"] * 2):
            raise ValueError("invalid_dns_nsid_bytes")
    elif value["nsid_hex"] is not None or value["nsid_bytes"] != 0:
        raise ValueError("invalid_dns_nsid_absence")
    return dict(value)


def _nsid_bytes(line):
    if line == "; NSID:":
        return b""
    match = _NSID.fullmatch(line)
    if match is None:
        raise ValueError("invalid_dns_nsid_option")
    value = bytes.fromhex(match.group(1))
    # BIND's LC_ALL=C renderer does not escape printable quotes/backslashes.
    # Regenerate the complete line rather than trusting its lossy annotation.
    annotation = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in value)
    expected = "; NSID: " + "".join(f"{byte:02x} " for byte in value) + '("' + annotation + '")'
    if line != expected:
        raise ValueError("inconsistent_dns_nsid_annotation")
    return value


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or stderr not in (b"", DIG_DENIED_PROBE)):
        raise ValueError("invalid_dns_nsid_output")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_dns_nsid_text") from None
    if (not text.endswith("\n") or any(ord(char) < 32 and char not in "\n\t" or ord(char) == 127 for char in text)
            or len(text.split("\n")) > 64 or any(len(line) > 2048 for line in text.split("\n"))):
        raise ValueError("invalid_dns_nsid_text")
    lines = [line for line in text.split("\n") if line]
    if len(lines) < 5 or lines[0] != ";; Got answer:":
        raise ValueError("invalid_dns_nsid_transcript")
    header, counts = _HEADER.fullmatch(lines[1]), _COUNTS.fullmatch(lines[2])
    if header is None or counts is None or int(header.group(1)) > 65535:
        raise ValueError("invalid_dns_nsid_header")
    flags = counts.group(1).split()
    if len(flags) != 2 or set(flags) != {"qr", "aa"}:
        raise ValueError("unsupported_dns_nsid_flags")
    edns_present = counts.group(2) == "1"
    cursor, nsid = 3, None
    if edns_present:
        if lines[cursor:cursor + 2] != [";; OPT PSEUDOSECTION:", _EDNS]:
            raise ValueError("invalid_dns_nsid_edns")
        cursor += 2
        if cursor < len(lines) and lines[cursor].startswith("; NSID:"):
            nsid = _nsid_bytes(lines[cursor])
            cursor += 1
    if (len(lines) != cursor + 2 or lines[cursor] != ";; QUESTION SECTION:"
            or _QUESTION.fullmatch(lines[cursor + 1]) is None):
        raise ValueError("unexpected_dns_nsid_output")
    return validate_result({"parser_version": PARSER_VERSION, "kind": "dns_nsid_metadata",
        "semantics": SEMANTICS, "query_name": QUERY_NAME, "query_type": "A", "transport": "tcp",
        "status": "NOERROR", "edns_present": edns_present, "nsid_present": nsid is not None,
        "nsid_hex": nsid.hex() if nsid is not None else None, "nsid_bytes": len(nsid) if nsid is not None else 0,
        "service_identity_verified": False})
