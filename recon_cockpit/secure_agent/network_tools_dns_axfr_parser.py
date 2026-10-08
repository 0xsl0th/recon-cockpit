"""Finite AXFR transcript summaries without transferred data or authority."""

import ipaddress
import re


TOOL_ID = "dig_dns_axfr_v1"
PARSER_VERSION = "dig-dns-axfr-text-v1"
QUERY_NAME = "harbordesk.test."
SEMANTICS = "untrusted_dns_zone_transfer_metadata"
MAX_OUTPUT_BYTES = 8192
MAX_MESSAGES = 4
MAX_RECORDS = 16
MAX_TXT_CHUNKS = 4
MAX_TXT_BYTES = 1024
DIG_DENIED_PROBE = b"net.c:136:try_proto(): socket(): Operation not permitted (1)\n"
_HEADER = re.compile(r";; ->>HEADER<<- opcode: QUERY, status: (NOERROR|REFUSED), id: ([0-9]{1,5})")
_COUNTS = re.compile(r";; flags: ([a-z ]+); QUERY: ([01]), ANSWER: ([0-9]{1,2}), AUTHORITY: 0, ADDITIONAL: 0")
_QUESTION = re.compile(r";harbordesk\.test\.[ \t]+IN[ \t]+AXFR")
_RECORD = re.compile(r"([a-z0-9.-]{1,253})[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+(SOA|NS|A|TXT)[ \t]+([^\t]+)")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMBER = re.compile(r"0|[1-9][0-9]{0,9}")


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def validate_result(value):
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics",
            "query_name", "query_type", "transport", "status", "transfer_complete", "message_count",
            "answer_record_count", "soa_serial", "service_identity_verified"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "dns_axfr_metadata"
            or value["semantics"] != SEMANTICS or value["query_name"] != QUERY_NAME
            or value["query_type"] != "AXFR" or value["transport"] != "tcp"
            or value["status"] not in ("NOERROR", "REFUSED")
            or type(value["transfer_complete"]) is not bool
            or not _integer(value["message_count"], MAX_MESSAGES) or value["message_count"] < 1
            or not _integer(value["answer_record_count"], MAX_RECORDS)
            or value["service_identity_verified"] is not False):
        raise ValueError("invalid_dns_axfr_observation")
    if value["status"] == "REFUSED":
        if (value["transfer_complete"] or value["message_count"] != 1
                or value["answer_record_count"] != 0 or value["soa_serial"] is not None):
            raise ValueError("invalid_dns_axfr_refusal")
    elif (not value["transfer_complete"] or value["answer_record_count"] < 2
            or value["message_count"] > value["answer_record_count"]
            or not _integer(value["soa_serial"], 4294967295)):
        raise ValueError("invalid_dns_axfr_completion")
    return dict(value)


def _name(value):
    if (not 1 <= len(value) <= 253 or not value.endswith(".")
            or any(_LABEL.fullmatch(label) is None for label in value[:-1].split("."))):
        raise ValueError("unsupported_dns_axfr_name")
    return value


def _number(value, maximum):
    if _NUMBER.fullmatch(value) is None or int(value) > maximum:
        raise ValueError("invalid_dns_axfr_number")
    return int(value)


def _txt(value):
    # Inspect bounded DNS character strings only. Their bytes are not released.
    cursor, chunks, total = 0, 0, 0
    while cursor < len(value):
        if value[cursor] != '"' or chunks >= MAX_TXT_CHUNKS:
            raise ValueError("invalid_dns_axfr_txt")
        cursor += 1
        size = 0
        while cursor < len(value) and value[cursor] != '"':
            char = value[cursor]
            if char == "\\":
                cursor += 1
                if cursor >= len(value):
                    raise ValueError("invalid_dns_axfr_txt")
                if value[cursor] in ('"', "\\"):
                    cursor += 1
                else:
                    escape = value[cursor:cursor + 3]
                    if len(escape) != 3 or not escape.isascii() or not escape.isdigit() or int(escape) > 255:
                        raise ValueError("invalid_dns_axfr_txt")
                    cursor += 3
            else:
                if not 32 <= ord(char) <= 126:
                    raise ValueError("invalid_dns_axfr_txt")
                cursor += 1
            size += 1
            if size > 255:
                raise ValueError("dns_axfr_txt_limit")
        if cursor >= len(value):
            raise ValueError("incomplete_dns_axfr_txt")
        cursor += 1
        chunks += 1
        total += size
        if total > MAX_TXT_BYTES:
            raise ValueError("dns_axfr_txt_limit")
        if cursor < len(value):
            if value[cursor:cursor + 2] != ' "':
                raise ValueError("invalid_dns_axfr_txt_separator")
            cursor += 1
    if not chunks:
        raise ValueError("invalid_dns_axfr_txt")


def _record(line):
    match = _RECORD.fullmatch(line)
    if match is None:
        raise ValueError("unsupported_dns_axfr_record")
    owner, ttl, kind, data = match.groups()
    _name(owner)
    if owner != QUERY_NAME and not owner.endswith("." + QUERY_NAME):
        raise ValueError("dns_axfr_owner_outside_zone")
    ttl = _number(ttl, 2147483647)
    if kind == "SOA":
        fields = data.split(" ")
        if owner != QUERY_NAME or len(fields) != 7:
            raise ValueError("invalid_dns_axfr_soa")
        return kind, (owner, ttl, _name(fields[0]), _name(fields[1]),
            *(_number(item, 4294967295) for item in fields[2:]))
    if kind == "NS":
        _name(data)
    elif kind == "A":
        try:
            if str(ipaddress.IPv4Address(data)) != data:
                raise ValueError("noncanonical_dns_axfr_address")
        except ipaddress.AddressValueError:
            raise ValueError("invalid_dns_axfr_address") from None
    else:
        _txt(data)
    return kind, None


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or stderr not in (b"", DIG_DENIED_PROBE)):
        raise ValueError("invalid_dns_axfr_output")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_dns_axfr_text") from None
    split = text.split("\n")
    if (not text.endswith("\n") or len(split) > 128 or any(len(line) > 2048 for line in split)
            or any(ord(char) < 32 and char not in "\n\t" or ord(char) == 127 for char in text)):
        raise ValueError("invalid_dns_axfr_text")
    lines = [line for line in split if line]
    cursor, messages, records, transaction = 0, 0, [], None
    refused = False
    while cursor < len(lines):
        if messages >= MAX_MESSAGES or len(lines) < cursor + 3 or lines[cursor] != ";; Got answer:":
            raise ValueError("invalid_dns_axfr_message")
        header, counts = _HEADER.fullmatch(lines[cursor + 1]), _COUNTS.fullmatch(lines[cursor + 2])
        if header is None or counts is None:
            raise ValueError("invalid_dns_axfr_header")
        status, txid = header.groups()
        txid = _number(txid, 65535)
        if transaction is not None and transaction != txid:
            raise ValueError("dns_axfr_transaction_changed")
        transaction = txid
        flags = counts.group(1).split()
        if len(flags) != 2 or set(flags) != {"qr", "aa"}:
            raise ValueError("unsupported_dns_axfr_flags")
        question, answers = int(counts.group(2)), _number(counts.group(3), MAX_RECORDS)
        if (not messages and question != 1) or len(records) + answers > MAX_RECORDS:
            raise ValueError("invalid_dns_axfr_counts")
        cursor += 3
        if question:
            if (len(lines) < cursor + 2 or lines[cursor] != ";; QUESTION SECTION:"
                    or _QUESTION.fullmatch(lines[cursor + 1]) is None):
                raise ValueError("invalid_dns_axfr_question")
            cursor += 2
        messages += 1
        if status == "REFUSED":
            if messages != 1 or answers or lines[cursor:] != ["; Transfer failed."]:
                raise ValueError("invalid_dns_axfr_refusal")
            refused = True
            cursor += 1
            break
        if not answers or len(lines) < cursor + answers + 1 or lines[cursor] != ";; ANSWER SECTION:":
            raise ValueError("invalid_dns_axfr_answers")
        cursor += 1
        records.extend(_record(line) for line in lines[cursor:cursor + answers])
        cursor += answers
        if sum(kind == "SOA" for kind, _ in records) >= 2 and cursor != len(lines):
            raise ValueError("dns_axfr_data_after_closing_soa")
    if not messages:
        raise ValueError("empty_dns_axfr_transcript")
    serial = None
    if not refused:
        if (len(records) < 2 or records[0][0] != "SOA" or records[-1][0] != "SOA"
                or sum(kind == "SOA" for kind, _ in records) != 2 or records[0] != records[-1]):
            raise ValueError("incomplete_or_mismatched_dns_axfr_boundaries")
        serial = records[0][1][4]
    return validate_result({"parser_version": PARSER_VERSION, "kind": "dns_axfr_metadata",
        "semantics": SEMANTICS, "query_name": QUERY_NAME, "query_type": "AXFR", "transport": "tcp",
        "status": "REFUSED" if refused else "NOERROR", "transfer_complete": not refused,
        "message_count": messages, "answer_record_count": len(records), "soa_serial": serial,
        "service_identity_verified": False})
