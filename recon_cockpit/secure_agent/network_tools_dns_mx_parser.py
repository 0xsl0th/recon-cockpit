"""Finite MX advertisements from one fixed owned DNS question.

Exchanges, preferences, TTLs and null MX are untrusted response metadata.
They never authorize address resolution, SMTP connections or mail delivery.
"""

import json
import re


TOOL_ID = "dig_dns_mx_v1"
PARSER_VERSION = "dig-dns-mx-text-v1"
QUERY_NAME = "harbordesk.test."
SEMANTICS = "untrusted_dns_mail_metadata"
MAX_OUTPUT_BYTES = 8192
MAX_NORMALIZED_BYTES = 3000
DIG_DENIED_PROBE = b"net.c:136:try_proto(): socket(): Operation not permitted (1)\n"
_NAME = re.escape(QUERY_NAME)
_HEADER = re.compile(r";; ->>HEADER<<- opcode: QUERY, status: (NOERROR|NXDOMAIN), id: ([0-9]{1,5})")
_COUNTS = re.compile(r";; flags: ([a-z ]+); QUERY: 1, ANSWER: ([0-4]), AUTHORITY: 0, ADDITIONAL: ([01])")
_QUESTION = re.compile(r";" + _NAME + r"[ \t]+IN[ \t]+MX")
_ANSWER = re.compile(_NAME + r"[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+MX[ \t]+"
    r"([0-9]{1,5})[ \t]+([a-z0-9.-]{1,253})")
_TXT = re.compile(_NAME + r'[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+TXT[ \t]+"(?:[^"\\\x00-\x1f\x7f]|\\(?:[01][0-9]{2}|2[0-4][0-9]|25[0-5]|["\\])){0,1024}"')
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_FIELDS = ("preference", "exchange", "ttl")


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _exchange(value):
    return (type(value) is str and 1 <= len(value) <= 253
        and (value == "." or (value.endswith(".")
            and all(_LABEL.fullmatch(label) is not None for label in value[:-1].split(".")))))


def validate_result(value):
    """Detach a closed result, keeping NODATA distinct from a sole null MX."""
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics",
            "query_name", "query_type", "transport", "status", "records", "additional_txt_count"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "dns_mail_metadata"
            or value["semantics"] != SEMANTICS or value["query_name"] != QUERY_NAME
            or value["query_type"] != "MX" or value["transport"] != "tcp"
            or value["status"] not in ("NOERROR", "NXDOMAIN")
            or not _integer(value["additional_txt_count"], 1)
            or type(value["records"]) is not list or len(value["records"]) > 4):
        raise ValueError("invalid_dns_mx_observation")
    records, keys = [], []
    for row in value["records"]:
        if (type(row) is not dict or set(row) != set(_FIELDS)
                or not _integer(row["preference"], 65535)
                or not _integer(row["ttl"], 2147483647) or not _exchange(row["exchange"])
                or (row["exchange"] == "." and (len(value["records"]) != 1
                    or row["preference"] != 0))):
            raise ValueError("invalid_dns_mx_record")
        records.append(dict(row))
        keys.append(tuple(row[field] for field in _FIELDS))
    if (keys != sorted(keys) or len({key[:2] for key in keys}) != len(keys)
            or (value["status"] == "NXDOMAIN" and (records or value["additional_txt_count"]))):
        raise ValueError("invalid_dns_mx_record_order_or_status")
    result = {**value, "records": records}
    if len(json.dumps(result, ensure_ascii=True).encode("ascii")) > MAX_NORMALIZED_BYTES:
        raise ValueError("dns_mx_observation_too_large")
    return result


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or stderr not in (b"", DIG_DENIED_PROBE)):
        raise ValueError("invalid_dns_mx_output")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_dns_mx_text") from None
    if (not text.endswith("\n") or any(ord(char) < 32 and char not in "\n\t" or ord(char) == 127 for char in text)
            or len(text.split("\n")) > 64 or any(len(line) > 2048 for line in text.split("\n"))):
        raise ValueError("invalid_dns_mx_text")
    lines = [line for line in text.split("\n") if line]
    if len(lines) < 5 or lines[0] != ";; Got answer:":
        raise ValueError("invalid_dns_mx_transcript")
    header, counts = _HEADER.fullmatch(lines[1]), _COUNTS.fullmatch(lines[2])
    if header is None or counts is None or int(header.group(2)) > 65535:
        raise ValueError("invalid_dns_mx_header")
    flags = counts.group(1).split()
    if len(flags) != 2 or set(flags) != {"qr", "aa"}:
        raise ValueError("unsupported_dns_mx_flags")
    if lines[3] != ";; QUESTION SECTION:" or _QUESTION.fullmatch(lines[4]) is None:
        raise ValueError("invalid_dns_mx_question")
    answer_count, additional_count = int(counts.group(2)), int(counts.group(3))
    cursor, records = 5, []
    if answer_count:
        if len(lines) < cursor + 1 + answer_count or lines[cursor] != ";; ANSWER SECTION:":
            raise ValueError("invalid_dns_mx_answer_count")
        cursor += 1
        for line in lines[cursor:cursor + answer_count]:
            match = _ANSWER.fullmatch(line)
            if match is None:
                raise ValueError("invalid_dns_mx_answer")
            ttl, preference, exchange = match.groups()
            records.append({"preference": int(preference), "exchange": exchange, "ttl": int(ttl)})
        cursor += answer_count
    if additional_count:
        if len(lines) < cursor + 2 or lines[cursor] != ";; ADDITIONAL SECTION:":
            raise ValueError("invalid_dns_mx_additional_count")
        match = _TXT.fullmatch(lines[cursor + 1])
        if match is None or int(match.group(1)) > 2147483647:
            raise ValueError("invalid_dns_mx_additional_record")
        cursor += 2
    if cursor != len(lines):
        raise ValueError("unexpected_dns_mx_output")
    records.sort(key=lambda row: tuple(row[field] for field in _FIELDS))
    return validate_result({"parser_version": PARSER_VERSION, "kind": "dns_mail_metadata",
        "semantics": SEMANTICS, "query_name": QUERY_NAME, "query_type": "MX", "transport": "tcp",
        "status": header.group(1), "records": records, "additional_txt_count": additional_count})
