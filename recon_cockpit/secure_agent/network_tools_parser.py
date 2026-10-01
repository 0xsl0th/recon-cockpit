"""Bounded DNS and verified TLS transcript facts for fixed owned profiles."""

from __future__ import annotations

import ipaddress
import re


DIG_TOOL_ID = "dig_dns_query_v1"
OPENSSL_TOOL_ID = "openssl_tls_handshake_v1"
PARSER_VERSIONS = {DIG_TOOL_ID: "dig-dns-text-v1", OPENSSL_TOOL_ID: "openssl-tls-brief-v1"}
MAX_OUTPUT_BYTES = 8192
QUERY_NAME = "harbordesk.test."
TLS_NAME = "harbordesk.test"
TLS_PROTOCOLS = frozenset({"TLSv1.3"})
TLS_CIPHERS = frozenset({"TLS_AES_256_GCM_SHA384"})
# The pinned BIND build probes a denied socket family during startup. This
# exact nonfatal diagnostic is retained in raw evidence, never released as data.
DIG_DENIED_PROBE = b"net.c:136:try_proto(): socket(): Operation not permitted (1)\n"
_HEADER = re.compile(r";; ->>HEADER<<- opcode: QUERY, status: (NOERROR|NXDOMAIN), id: ([0-9]{1,5})")
_COUNTS = re.compile(r";; flags: ([a-z ]+); QUERY: 1, ANSWER: ([01]), AUTHORITY: 0, ADDITIONAL: ([01])")
_ANSWER = re.compile(r"harbordesk\.test\.[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+A[ \t]+([0-9.]+)")
_TXT = re.compile(r'harbordesk\.test\.[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+TXT[ \t]+"(?:[^"\\\x00-\x1f\x7f]|\\(?:[0-9]{3}|["\\])){0,1024}"')


def parser_version(tool_id):
    if type(tool_id) is not str or tool_id not in PARSER_VERSIONS:
        raise ValueError("unsupported_network_tool_parser")
    return PARSER_VERSIONS[tool_id]


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def validate_result(tool_id, value):
    """The complete closed schema released by the networkless parser."""
    version = parser_version(tool_id)
    if type(value) is not dict or value.get("parser_version") != version:
        raise ValueError("invalid_network_tool_observation")
    if tool_id == OPENSSL_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "protocol", "cipher", "verification", "peer_name"}
                or value["kind"] != "tls_handshake" or type(value["protocol"]) is not str
                or value["protocol"] not in TLS_PROTOCOLS or type(value["cipher"]) is not str
                or value["cipher"] not in TLS_CIPHERS
                or value["verification"] != "verified" or value["peer_name"] != TLS_NAME):
            raise ValueError("invalid_network_tool_observation")
        return dict(value)
    if (set(value) != {"parser_version", "kind", "query_name", "query_type", "transport", "status", "answers", "additional_txt_count"}
            or value["kind"] != "dns_query" or value["query_name"] != QUERY_NAME
            or value["query_type"] != "A" or value["transport"] != "tcp"
            or value["status"] not in ("NOERROR", "NXDOMAIN")
            or type(value["answers"]) is not list or len(value["answers"]) > 1
            or not _integer(value["additional_txt_count"], 1)
            or (value["status"] == "NXDOMAIN" and (value["answers"] or value["additional_txt_count"]))):
        raise ValueError("invalid_network_tool_observation")
    answers = []
    for row in value["answers"]:
        if (type(row) is not dict or set(row) != {"name", "type", "address", "ttl"}
                or row["name"] != QUERY_NAME or row["type"] != "A"
                or type(row["address"]) is not str or not _integer(row["ttl"], 2147483647)):
            raise ValueError("invalid_dns_answer")
        try:
            if str(ipaddress.IPv4Address(row["address"])) != row["address"]:
                raise ValueError("invalid_dns_answer")
        except ValueError:
            raise ValueError("invalid_dns_answer") from None
        answers.append(dict(row))
    return {**value, "answers": answers}


def _lines(raw):
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise ValueError("invalid_network_tool_text") from None
    if not text.endswith("\n") or any(ord(char) < 32 and char not in "\n\t" or ord(char) == 127 for char in text):
        raise ValueError("invalid_network_tool_text")
    lines = text.split("\n")
    if len(lines) > 64 or any(len(line) > 2048 for line in lines):
        raise ValueError("invalid_network_tool_text")
    return [line for line in lines if line]


def _parse_dns(output, stderr):
    if stderr not in (b"", DIG_DENIED_PROBE):
        raise ValueError("unexpected_dig_diagnostics")
    lines = _lines(output)
    if len(lines) < 5 or lines[0] != ";; Got answer:":
        raise ValueError("invalid_dig_transcript")
    header, counts = _HEADER.fullmatch(lines[1]), _COUNTS.fullmatch(lines[2])
    if header is None or counts is None or int(header.group(2)) > 65535:
        raise ValueError("invalid_dig_header")
    flags = counts.group(1).split()
    if len(flags) != 2 or set(flags) != {"qr", "aa"}:
        raise ValueError("unsupported_dig_flags")
    if lines[3] != ";; QUESTION SECTION:" or re.fullmatch(r";harbordesk\.test\.[ \t]+IN[ \t]+A", lines[4]) is None:
        raise ValueError("invalid_dig_question")
    answer_count, additional_count = int(counts.group(2)), int(counts.group(3))
    cursor, answers = 5, []
    if answer_count:
        if len(lines) < cursor + 2 or lines[cursor] != ";; ANSWER SECTION:":
            raise ValueError("invalid_dig_answer_count")
        match = _ANSWER.fullmatch(lines[cursor + 1])
        if match is None:
            raise ValueError("invalid_dig_answer")
        answers.append({"name": QUERY_NAME, "type": "A", "ttl": int(match.group(1)), "address": match.group(2)})
        cursor += 2
    if additional_count:
        if len(lines) < cursor + 2 or lines[cursor] != ";; ADDITIONAL SECTION:":
            raise ValueError("invalid_dig_additional_count")
        match = _TXT.fullmatch(lines[cursor + 1])
        if match is None or int(match.group(1)) > 2147483647:
            raise ValueError("invalid_dig_additional_record")
        cursor += 2
    if cursor != len(lines):
        raise ValueError("unexpected_dig_output")
    return validate_result(DIG_TOOL_ID, {"parser_version": parser_version(DIG_TOOL_ID), "kind": "dns_query",
        "query_name": QUERY_NAME, "query_type": "A", "transport": "tcp", "status": header.group(1),
        "answers": answers, "additional_txt_count": additional_count})


def _parse_tls(output, stderr):
    if output:
        raise ValueError("unexpected_openssl_stdout")
    lines = _lines(stderr)
    if lines and lines[0] == "Connecting to 127.0.0.1":
        lines = lines[1:]
    if not lines or lines[0] != "CONNECTION ESTABLISHED":
        raise ValueError("invalid_tls_transcript")
    lines = lines[1:]
    if lines and lines[-1] == "DONE":
        lines = lines[:-1]
    required = {"Protocol version", "Ciphersuite", "Peer certificate", "Verification", "Verified peername"}
    optional = {"Hash used", "Signature type", "Server Temp Key", "Peer signing digest", "Peer signature type",
                "Negotiated TLS1.3 group"}
    fields = {}
    for line in lines:
        key, separator, value = line.partition(": ")
        if not separator or key not in required | optional or key in fields or not value or len(value) > 1024:
            raise ValueError("invalid_tls_transcript")
        fields[key] = value
    if (not required <= fields.keys() or fields["Protocol version"] not in TLS_PROTOCOLS
            or fields["Verification"] != "OK" or fields["Verified peername"] != TLS_NAME
            or re.fullmatch(r"[A-Z0-9_-]{1,96}", fields["Ciphersuite"]) is None):
        raise ValueError("unverified_tls_transcript")
    cipher = fields["Ciphersuite"]
    return validate_result(OPENSSL_TOOL_ID, {"parser_version": parser_version(OPENSSL_TOOL_ID), "kind": "tls_handshake",
        "protocol": fields["Protocol version"], "cipher": cipher,
        "verification": "verified", "peer_name": TLS_NAME})


def parse_tool_output(tool_id, output: bytes, stderr: bytes = b"", *, truncated=False):
    parser_version(tool_id)
    if (type(output) is not bytes or type(stderr) is not bytes or not output + stderr
            or len(output) + len(stderr) > MAX_OUTPUT_BYTES or type(truncated) is not bool or truncated):
        raise ValueError("invalid_network_tool_output_size")
    return _parse_dns(output, stderr) if tool_id == DIG_TOOL_ID else _parse_tls(output, stderr)
