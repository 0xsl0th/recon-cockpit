"""Bounded DNS, TLS, SSH, LDAP and SMB facts for fixed owned tool profiles."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re


DIG_TOOL_ID = "dig_dns_query_v1"
OPENSSL_TOOL_ID = "openssl_tls_handshake_v1"
SSH_TOOL_ID = "ssh_host_keys_v1"
LDAP_TOOL_ID = "ldap_rootdse_v1"
SMB_TOOL_ID = "smb_share_list_v1"
PARSER_VERSIONS = {DIG_TOOL_ID: "dig-dns-text-v1", OPENSSL_TOOL_ID: "openssl-tls-brief-v1",
    SSH_TOOL_ID: "ssh-keyscan-rsa-v1", LDAP_TOOL_ID: "ldap-rootdse-ldif-v1", SMB_TOOL_ID: "smb-share-list-v1"}
MAX_OUTPUT_BYTES = 8192
QUERY_NAME = "harbordesk.test."
TLS_NAME = "harbordesk.test"
TLS_PROTOCOLS = frozenset({"TLSv1.3"})
TLS_CIPHERS = frozenset({"TLS_AES_256_GCM_SHA384"})
LDAP_VALUES = {"naming_contexts": ("dc=harbordesk,dc=test",), "supported_ldap_versions": ("3",),
    "supported_sasl_mechanisms": ("PLAIN",)}
LDAP_VENDOR = "HarborDesk synthetic directory"
SMB_SHARES = {"PUBLIC": "Disk", "IPC$": "IPC"}
# The minimal native closure omits optional legacy charset modules. This exact
# startup warning is nonfatal; arbitrary diagnostics cannot become observations.
SMB_CHARSET_WARNING = b"dos charset 'CP850' unavailable - using ASCII\n"
SMB_LISTING_FOOTER = "SMB1 disabled -- no workgroup available"
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


def _base64(value, maximum):
    if type(value) is not str or not value or len(value) > maximum:
        raise ValueError("invalid_network_tool_base64")
    try:
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode("ascii") != value:
            raise ValueError("invalid_network_tool_base64")
        return raw
    except (ValueError, UnicodeError):
        raise ValueError("invalid_network_tool_base64") from None


def _ssh_key_facts(encoded):
    """Validate the fixed RSA serialization; no host-authenticity assertion."""
    raw = _base64(encoded, 1024)
    values, offset = [], 0
    for _ in range(3):
        if len(raw) - offset < 4:
            raise ValueError("invalid_ssh_key_blob")
        size = int.from_bytes(raw[offset:offset + 4], "big")
        offset += 4
        if not 1 <= size <= 257 or offset + size > len(raw):
            raise ValueError("invalid_ssh_key_blob")
        values.append(raw[offset:offset + size])
        offset += size
    if offset != len(raw) or values[0] != b"ssh-rsa":
        raise ValueError("invalid_ssh_key_blob")
    integers = []
    for value in values[1:]:
        # RFC4251 positive mpints have one sign byte only when needed.
        if value[0] & 128 or (value[0] == 0 and (len(value) == 1 or not value[1] & 128)):
            raise ValueError("invalid_ssh_key_integer")
        integers.append(int.from_bytes(value, "big"))
    exponent, modulus = integers
    if exponent != 65537 or modulus.bit_length() != 2048 or modulus % 2 != 1:
        raise ValueError("unsupported_ssh_rsa_profile")
    return {"key_bits": modulus.bit_length(),
        "fingerprint_sha256": "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")}


def validate_result(tool_id, value):
    """The complete closed schema released by the networkless parser."""
    version = parser_version(tool_id)
    if type(value) is not dict or value.get("parser_version") != version:
        raise ValueError("invalid_network_tool_observation")
    if tool_id == SMB_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "status", "shares"}
                or value["kind"] != "smb_share_list" or value["status"] != "listed"
                or type(value["shares"]) is not list or len(value["shares"]) != len(SMB_SHARES)):
            raise ValueError("invalid_network_tool_observation")
        names = []
        for row in value["shares"]:
            if (type(row) is not dict or set(row) != {"name", "type"}
                    or type(row["name"]) is not str or row["name"] not in SMB_SHARES
                    or row["type"] != SMB_SHARES[row["name"]]):
                raise ValueError("invalid_smb_share")
            names.append(row["name"])
        if names != sorted(set(names)):
            raise ValueError("invalid_smb_share_order")
        return {**value, "shares": [dict(row) for row in value["shares"]]}
    if tool_id == SSH_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "key_type", "key_base64", "key_bits", "fingerprint_sha256", "trust"}
                or value["kind"] != "ssh_host_keys" or value["key_type"] != "ssh-rsa"
                or value["trust"] != "unverified" or type(value["key_bits"]) is not int):
            raise ValueError("invalid_network_tool_observation")
        facts = _ssh_key_facts(value["key_base64"])
        if any(value[key] != item for key, item in facts.items()):
            raise ValueError("invalid_ssh_key_facts")
        return dict(value)
    if tool_id == LDAP_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "rootdse_present", "naming_contexts",
                "supported_ldap_versions", "supported_sasl_mechanisms", "vendor_name"}
                or value["kind"] != "ldap_rootdse" or value["rootdse_present"] is not True
                or value["vendor_name"] not in (None, LDAP_VENDOR)):
            raise ValueError("invalid_network_tool_observation")
        for field, allowed in LDAP_VALUES.items():
            rows = value[field]
            if (type(rows) is not list or len(rows) > len(allowed)
                    or any(type(item) is not str or item not in allowed for item in rows)
                    or rows != sorted(set(rows))):
                raise ValueError("invalid_ldap_attribute")
        return {**value, **{field: list(value[field]) for field in LDAP_VALUES}}
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


def _parse_ssh(output, stderr):
    banner = re.compile(r"# 127\.0\.0\.1:8080 SSH-2\.0-[\x20-\x7e]{1,200}")
    if stderr:
        diagnostic = _lines(stderr)
        if (len(diagnostic) != 1 or len(stderr.splitlines()) != 1
                or banner.fullmatch(diagnostic[0]) is None):
            raise ValueError("unexpected_ssh_diagnostics")
    lines = _lines(output)
    if len(lines) != len(output.splitlines()):
        raise ValueError("invalid_ssh_keyscan_output")
    if len(lines) == 2 and banner.fullmatch(lines[0]) is not None:
        if stderr:
            raise ValueError("duplicate_ssh_banner")
        lines = lines[1:]
    if len(lines) != 1:
        raise ValueError("invalid_ssh_key_count")
    match = re.fullmatch(r"\[127\.0\.0\.1\]:8080 ssh-rsa ([A-Za-z0-9+/=]{1,1024})", lines[0])
    if match is None:
        raise ValueError("invalid_ssh_keyscan_output")
    encoded = match.group(1)
    return validate_result(SSH_TOOL_ID, {"parser_version": parser_version(SSH_TOOL_ID),
        "kind": "ssh_host_keys", "key_type": "ssh-rsa", "key_base64": encoded,
        **_ssh_key_facts(encoded), "trust": "unverified"})


def _parse_ldap(output, stderr):
    if (stderr or not output.endswith(b"\n\n")
            or b"" in output.split(b"\n")[:-2]):
        raise ValueError("invalid_ldap_ldif")
    lines = _lines(output)
    if not lines or lines[0] not in ("dn:", "dn: "):
        raise ValueError("invalid_ldap_rootdse")
    attributes = {"namingContexts": "naming_contexts", "supportedLDAPVersion": "supported_ldap_versions",
        "supportedSASLMechanisms": "supported_sasl_mechanisms", "vendorName": "vendor_name"}
    result = {"parser_version": parser_version(LDAP_TOOL_ID), "kind": "ldap_rootdse", "rootdse_present": True,
        "naming_contexts": [], "supported_ldap_versions": [], "supported_sasl_mechanisms": [], "vendor_name": None}
    seen = set()
    for line in lines[1:]:
        match = re.fullmatch(r"([A-Za-z]+)(: |:: )([^\r\n]{1,1400})", line)
        if match is None or match.group(1) not in set(attributes) | {"description"}:
            raise ValueError("unsupported_ldap_attribute")
        name, separator, text = match.groups()
        if name in seen:
            raise ValueError("duplicate_ldap_attribute")
        seen.add(name)
        if separator == ":: ":
            try:
                text = _base64(text, 1400).decode("ascii")
            except UnicodeError:
                raise ValueError("unsupported_ldap_attribute_value") from None
        if not 1 <= len(text) <= 1024 or any(not 32 <= ord(char) <= 126 for char in text):
            raise ValueError("unsupported_ldap_attribute_value")
        if name == "description":
            continue  # Retain only in hashed raw evidence, never as instructions.
        field = attributes[name]
        result[field] = text if field == "vendor_name" else [text]
    return validate_result(LDAP_TOOL_ID, result)


def _parse_smb(output, stderr):
    if stderr not in (b"", SMB_CHARSET_WARNING):
        raise ValueError("unexpected_smb_diagnostics")
    lines = _lines(output)
    if (len(lines) != len(output.splitlines()) or not lines
            or lines[-1] != SMB_LISTING_FOOTER or len(lines) > len(SMB_SHARES) + 1):
        raise ValueError("invalid_smb_share_transcript")
    shares = []
    for line in lines[:-1]:
        fields = line.split("|", 2)
        if (len(fields) != 3 or fields[1] not in SMB_SHARES
                or fields[0] != SMB_SHARES[fields[1]] or len(fields[2]) > 1024
                or any(not 32 <= ord(char) <= 126 for char in fields[2])):
            raise ValueError("unsupported_smb_share_row")
        # Server-supplied comments remain only in the bounded raw evidence.
        shares.append({"name": fields[1], "type": fields[0]})
    if len(shares) != len(SMB_SHARES):
        # The native client can suppress RPC errors and exit zero with this
        # footer alone or an incomplete list. Only the complete reviewed fixture
        # listing establishes useful success; absence remains inconclusive.
        raise ValueError("smb_share_listing_unconfirmed")
    return validate_result(SMB_TOOL_ID, {"parser_version": parser_version(SMB_TOOL_ID),
        "kind": "smb_share_list", "status": "listed",
        "shares": sorted(shares, key=lambda item: item["name"])})


def parse_tool_output(tool_id, output: bytes, stderr: bytes = b"", *, truncated=False):
    parser_version(tool_id)
    if (type(output) is not bytes or type(stderr) is not bytes or not output + stderr
            or len(output) + len(stderr) > MAX_OUTPUT_BYTES or type(truncated) is not bool or truncated):
        raise ValueError("invalid_network_tool_output_size")
    return {DIG_TOOL_ID: _parse_dns, OPENSSL_TOOL_ID: _parse_tls,
            SSH_TOOL_ID: _parse_ssh, LDAP_TOOL_ID: _parse_ldap, SMB_TOOL_ID: _parse_smb}[tool_id](output, stderr)
