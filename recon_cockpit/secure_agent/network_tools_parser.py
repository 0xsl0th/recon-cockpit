"""Bounded protocol metadata for fixed owned native tool profiles."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re


DIG_TOOL_ID = "dig_dns_query_v1"
OPENSSL_TOOL_ID = "openssl_tls_handshake_v1"
SSH_TOOL_ID = "ssh_host_keys_v1"
LDAP_TOOL_ID = "ldap_rootdse_v1"
SMB_TOOL_ID = "smb_share_list_v1"
RPCINFO_TOOL_ID = "rpcinfo_dump_v1"
SHOWMOUNT_TOOL_ID = "showmount_exports_v1"
FTP_TOOL_ID = "curl_ftp_list_v1"
SMTP_TOOL_ID = "curl_smtp_capabilities_v1"
DOCKER_PING_TOOL_ID = "curl_docker_ping_v1"
DOCKER_VERSION_TOOL_ID = "curl_docker_version_v1"
WINRM_TOOL_ID = "curl_winrm_metadata_v1"
NMAP_SERVICE_TOOL_ID = "nmap_service_identify_v1"
KERBRUTE_TOOL_ID = "kerbrute_userenum_v1"
REDIS_TOOL_ID = "redis_server_info_v1"
SNMP_TOOL_ID = "snmp_system_get_v1"
POSTGRESQL_TLS_TOOL_ID = "postgresql_tls_handshake_v1"
MYSQL_TLS_TOOL_ID = "mysql_tls_handshake_v1"
WHATWEB_TOOL_ID = "whatweb_http_fingerprint_v1"
DNS_SRV_TOOL_ID = "dig_dns_srv_v1"
DATABASE_TLS_SERVICES = {POSTGRESQL_TLS_TOOL_ID: "postgresql", MYSQL_TLS_TOOL_ID: "mysql"}
PARSER_VERSIONS = {DIG_TOOL_ID: "dig-dns-text-v1", OPENSSL_TOOL_ID: "openssl-tls-brief-v1",
    SSH_TOOL_ID: "ssh-keyscan-rsa-v1", LDAP_TOOL_ID: "ldap-rootdse-ldif-v1", SMB_TOOL_ID: "smb-share-list-v1",
    RPCINFO_TOOL_ID: "rpcinfo-dump-v1", SHOWMOUNT_TOOL_ID: "showmount-exports-v1",
    FTP_TOOL_ID: "curl-ftp-list-v1", SMTP_TOOL_ID: "curl-smtp-capabilities-v1", DOCKER_PING_TOOL_ID: "curl-docker-ping-v1",
    DOCKER_VERSION_TOOL_ID: "curl-docker-version-v1", WINRM_TOOL_ID: "curl-winrm-metadata-v1",
    NMAP_SERVICE_TOOL_ID: "nmap-service-xml-v1", KERBRUTE_TOOL_ID: "kerbrute-userenum-text-v1",
    REDIS_TOOL_ID: "redis-info-server-v1", SNMP_TOOL_ID: "snmp-system-text-v1",
    POSTGRESQL_TLS_TOOL_ID: "postgresql-tls-brief-v1", MYSQL_TLS_TOOL_ID: "mysql-tls-brief-v1",
    WHATWEB_TOOL_ID: "whatweb-json-v1", DNS_SRV_TOOL_ID: "dig-dns-srv-text-v1"}
MAX_OUTPUT_BYTES = 8192
QUERY_NAME = "harbordesk.test."
TLS_NAME = "harbordesk.test"
TLS_PROTOCOLS = frozenset({"TLSv1.3"})
TLS_CIPHERS = frozenset({"TLS_AES_256_GCM_SHA384"})
LDAP_VALUES = {"naming_contexts": ("dc=harbordesk,dc=test",), "supported_ldap_versions": ("3",),
    "supported_sasl_mechanisms": ("PLAIN",)}
LDAP_VENDOR = "HarborDesk synthetic directory"
RPC_HEADER = "   program vers proto   port  service"
NFS_PATHS = frozenset({"/srv/harbordesk/public", "/srv/harbordesk/reports"})
NFS_GROUPS = frozenset({"127.0.0.1"})
FTP_NAMES = frozenset({"public.txt", "reports"})
SMTP_CAPABILITIES = frozenset({"8BITMIME", "PIPELINING", "SIZE 1048576"})
FTP_COMPLETE_CONTROL = (b"220 HarborDesk synthetic FTP\r\n"
    b"331 Anonymous identity only\r\n230 Anonymous fixture session\r\n"
    b'257 "/" is the fixture directory\r\n'
    b"227 Entering Passive Mode (127,0,0,1,31,144)\r\n"
    b"200 ASCII listing mode\r\n150 Opening finite name listing\r\n226 Listing complete\r\n")
DOCKER_FIELDS = {"Version": "version", "ApiVersion": "api_version", "MinAPIVersion": "min_api_version",
    "Os": "os", "Arch": "arch"}
DOCKER_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,15})?")
DOCKER_API_VERSION = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}")
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
    if tool_id == DNS_SRV_TOOL_ID:
        return _dns_srv_parser().validate_result(value)
    if tool_id == WHATWEB_TOOL_ID:
        return _whatweb_parser().validate_result(value)
    if tool_id == NMAP_SERVICE_TOOL_ID:
        return _nmap_service_parser().validate_result(value)
    if tool_id == KERBRUTE_TOOL_ID:
        return _kerberos_parser().validate_result(value)
    if tool_id in (REDIS_TOOL_ID, SNMP_TOOL_ID):
        return _redis_snmp_parser().validate_result(tool_id, value)
    if tool_id in DATABASE_TLS_SERVICES:
        if (set(value) != {"parser_version", "kind", "service", "semantics", "authenticated_database_session",
                "protocol", "cipher", "verification", "peer_name"}
                or value["kind"] != "database_tls_handshake"
                or value["service"] != DATABASE_TLS_SERVICES[tool_id]
                or value["semantics"] != "verified_tls_handshake_only"
                or value["authenticated_database_session"] is not False):
            raise ValueError("invalid_database_tls_observation")
        # Reuse the accepted TLS validation without changing its public schema.
        # The service identifies the selected pre-auth protocol, not a verified
        # database product, available account, or completed database login.
        validate_result(OPENSSL_TOOL_ID, {"parser_version": parser_version(OPENSSL_TOOL_ID),
            "kind": "tls_handshake", **{key: value[key]
                for key in ("protocol", "cipher", "verification", "peer_name")}})
        return dict(value)
    if tool_id == DOCKER_PING_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "status_code", "health"}
                or value["kind"] != "docker_ping" or type(value["status_code"]) is not int
                or value["status_code"] != 200 or value["health"] != "ok"):
            raise ValueError("invalid_docker_ping")
        return dict(value)
    if tool_id == DOCKER_VERSION_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "status_code", "metadata"}
                or value["kind"] != "docker_version" or type(value["status_code"]) is not int
                or value["status_code"] != 200 or type(value["metadata"]) is not dict):
            raise ValueError("invalid_docker_version")
        metadata = value["metadata"]
        if metadata and (set(metadata) != set(DOCKER_FIELDS.values())
                or any(type(item) is not str for item in metadata.values())
                or DOCKER_VERSION.fullmatch(metadata["version"]) is None
                or DOCKER_API_VERSION.fullmatch(metadata["api_version"]) is None
                or DOCKER_API_VERSION.fullmatch(metadata["min_api_version"]) is None
                or metadata["os"] not in {"linux", "windows"} or metadata["arch"] not in {"amd64", "arm64"}):
            raise ValueError("invalid_docker_version_metadata")
        return {**value, "metadata": dict(metadata)}
    if tool_id == WINRM_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "status_code", "auth_schemes"}
                or value["kind"] != "winrm_metadata" or type(value["status_code"]) is not int
                or type(value["auth_schemes"]) is not list
                or (value["status_code"], value["auth_schemes"]) not in
                   ((401, ["negotiate", "ntlm"]), (405, []))):
            raise ValueError("invalid_winrm_metadata")
        return {**value, "auth_schemes": list(value["auth_schemes"])}
    if tool_id == FTP_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "entries"} or value["kind"] != "ftp_listing"
                or type(value["entries"]) is not list or len(value["entries"]) > len(FTP_NAMES)):
            raise ValueError("invalid_network_tool_observation")
        names = []
        for row in value["entries"]:
            if (type(row) is not dict or set(row) != {"name"}
                    or type(row["name"]) is not str or row["name"] not in FTP_NAMES):
                raise ValueError("invalid_ftp_name")
            names.append(row["name"])
        if names != sorted(set(names)):
            raise ValueError("invalid_ftp_name_order")
        return {**value, "entries": [dict(row) for row in value["entries"]]}
    if tool_id == SMTP_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "capabilities"} or value["kind"] != "smtp_capabilities"
                or type(value["capabilities"]) is not list or len(value["capabilities"]) > len(SMTP_CAPABILITIES)
                or any(type(item) is not str or item not in SMTP_CAPABILITIES for item in value["capabilities"])
                or value["capabilities"] != sorted(set(value["capabilities"]))):
            raise ValueError("invalid_smtp_capabilities")
        return {**value, "capabilities": list(value["capabilities"])}
    if tool_id == RPCINFO_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "registrations"}
                or value["kind"] != "rpc_registrations" or type(value["registrations"]) is not list
                or len(value["registrations"]) > 16):
            raise ValueError("invalid_network_tool_observation")
        rows = []
        for row in value["registrations"]:
            if (type(row) is not dict or set(row) != {"program", "version", "transport", "port"}
                    or not _integer(row["program"], 4294967295)
                    or not _integer(row["version"], 4294967295)
                    or row["transport"] not in ("tcp", "udp")
                    or not _integer(row["port"], 65535) or row["port"] == 0):
                raise ValueError("invalid_rpc_registration")
            rows.append((row["program"], row["version"], row["transport"], row["port"]))
        if rows != sorted(set(rows)):
            raise ValueError("invalid_rpc_registration_order")
        return {**value, "registrations": [dict(row) for row in value["registrations"]]}
    if tool_id == SHOWMOUNT_TOOL_ID:
        if (set(value) != {"parser_version", "kind", "exports"}
                or value["kind"] != "nfs_exports" or type(value["exports"]) is not list
                or len(value["exports"]) > len(NFS_PATHS)):
            raise ValueError("invalid_network_tool_observation")
        paths = []
        for row in value["exports"]:
            if (type(row) is not dict or set(row) != {"path", "groups"}
                    or type(row["path"]) is not str or row["path"] not in NFS_PATHS
                    or type(row["groups"]) is not list or len(row["groups"]) > len(NFS_GROUPS)
                    or any(type(group) is not str or group not in NFS_GROUPS for group in row["groups"])
                    or row["groups"] != sorted(set(row["groups"]))):
                raise ValueError("invalid_nfs_export")
            paths.append(row["path"])
        if paths != sorted(set(paths)):
            raise ValueError("invalid_nfs_export_order")
        return {**value, "exports": [{"path": row["path"], "groups": list(row["groups"])}
                                      for row in value["exports"]]}
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


def _parse_database_tls(tool_id, output, stderr):
    tls = _parse_tls(output, stderr)
    return validate_result(tool_id, {**tls, "parser_version": parser_version(tool_id),
        "kind": "database_tls_handshake", "service": DATABASE_TLS_SERVICES[tool_id],
        "semantics": "verified_tls_handshake_only", "authenticated_database_session": False})


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


def _parse_rpcinfo(output, stderr):
    if stderr:
        raise ValueError("unexpected_rpcinfo_diagnostics")
    if output == b"No remote programs registered.\n":
        return validate_result(RPCINFO_TOOL_ID, {"parser_version": parser_version(RPCINFO_TOOL_ID),
            "kind": "rpc_registrations", "registrations": []})
    lines = _lines(output)
    if (len(lines) != len(output.splitlines()) or not 2 <= len(lines) <= 17
            or lines[0] != RPC_HEADER):
        raise ValueError("invalid_rpcinfo_transcript")
    rows = []
    for line in lines[1:]:
        match = re.fullmatch(r"[ \t]+(0|[1-9][0-9]{0,9})[ \t]+(0|[1-9][0-9]{0,9})"
            r"[ \t]+(tcp|udp)[ \t]+([1-9][0-9]{0,4})", line)
        if match is None:
            raise ValueError("unsupported_rpcinfo_registration")
        program, version, transport, port = match.groups()
        rows.append({"program": int(program), "version": int(version), "transport": transport, "port": int(port)})
    return validate_result(RPCINFO_TOOL_ID, {"parser_version": parser_version(RPCINFO_TOOL_ID),
        "kind": "rpc_registrations", "registrations": sorted(rows,
            key=lambda row: (row["program"], row["version"], row["transport"], row["port"]))})


def _parse_showmount(output, stderr):
    if stderr:
        raise ValueError("unexpected_showmount_diagnostics")
    lines = _lines(output)
    if (len(lines) != len(output.splitlines()) or not 1 <= len(lines) <= len(NFS_PATHS) + 1
            or lines[0] != "Export list for 127.0.0.1:"):
        raise ValueError("invalid_showmount_transcript")
    exports = []
    for line in lines[1:]:
        match = re.fullmatch(r"(/srv/harbordesk/(?:public|reports)) +(127\.0\.0\.1|\(everyone\))", line)
        if match is None:
            raise ValueError("unsupported_nfs_export")
        path, group = match.groups()
        exports.append({"path": path, "groups": [] if group == "(everyone)" else [group]})
    return validate_result(SHOWMOUNT_TOOL_ID, {"parser_version": parser_version(SHOWMOUNT_TOOL_ID),
        "kind": "nfs_exports", "exports": sorted(exports, key=lambda row: row["path"])})


def _parse_ftp(output, stderr):
    # curl's pinned --dump-header channel retains the complete successful
    # anonymous control exchange. Empty stdout alone never establishes absence.
    if stderr != FTP_COMPLETE_CONTROL:
        raise ValueError("invalid_ftp_control_transcript")
    names = [] if output == b"" else _lines(output)
    if (len(names) != len(output.splitlines()) or len(names) > len(FTP_NAMES)
            or any(name not in FTP_NAMES for name in names)):
        raise ValueError("unsupported_ftp_listing")
    return validate_result(FTP_TOOL_ID, {"parser_version": parser_version(FTP_TOOL_ID),
        "kind": "ftp_listing", "entries": [{"name": name} for name in sorted(names)]})


def _parse_smtp(output, stderr):
    if stderr or not output.endswith(b"\r\n"):
        raise ValueError("invalid_smtp_transcript")
    lines = output[:-2].split(b"\r\n")
    if (not 3 <= len(lines) <= 6 or lines[0] != b"220 harbordesk.test ESMTP synthetic fixture"
            or lines[-1] != b"221 Goodbye"):
        raise ValueError("invalid_smtp_transcript")
    if len(lines) == 3:
        if lines[1] != b"250 harbordesk.test":
            raise ValueError("invalid_smtp_empty_reply")
        return validate_result(SMTP_TOOL_ID, {"parser_version": parser_version(SMTP_TOOL_ID),
            "kind": "smtp_capabilities", "capabilities": []})
    if lines[1] != b"250-harbordesk.test":
        raise ValueError("invalid_smtp_reply_sequence")
    capabilities = []
    for index, line in enumerate(lines[2:-1]):
        prefix = b"250 " if index == len(lines) - 4 else b"250-"
        if not line.startswith(prefix):
            raise ValueError("invalid_smtp_reply_sequence")
        try:
            capabilities.append(line[4:].decode("ascii"))
        except UnicodeError:
            raise ValueError("invalid_smtp_capability") from None
    return validate_result(SMTP_TOOL_ID, {"parser_version": parser_version(SMTP_TOOL_ID),
        "kind": "smtp_capabilities", "capabilities": sorted(capabilities)})


def _metadata_http_response(output, stderr):
    """One complete fixed-format HTTP response; every retained byte is checked."""
    if stderr or output.count(b"\r\n\r\n") != 1:
        raise ValueError("invalid_metadata_http_response")
    head, body = output.split(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not 4 <= len(lines) <= 5 or len(head) > 2048:
        raise ValueError("invalid_metadata_http_headers")
    statuses = {b"HTTP/1.1 200 OK": 200, b"HTTP/1.1 401 Unauthorized": 401,
        b"HTTP/1.1 405 Method Not Allowed": 405}
    if lines[0] not in statuses:
        raise ValueError("unsupported_metadata_http_status")
    headers = {}
    for line in lines[1:]:
        if (b": " not in line or any(byte < 32 or byte > 126 for byte in line)
                or line.startswith(b" ")):
            raise ValueError("invalid_metadata_http_header")
        name, value = line.split(b": ", 1)
        name = name.lower()
        if name not in {b"content-type", b"content-length", b"connection", b"www-authenticate", b"allow"} or name in headers:
            raise ValueError("unsupported_metadata_http_header")
        headers[name] = value
    if (not {b"content-type", b"content-length", b"connection"} <= set(headers)
            or headers[b"connection"] != b"close"
            or re.fullmatch(rb"0|[1-9][0-9]{0,3}", headers[b"content-length"]) is None
            or int(headers[b"content-length"]) != len(body)):
        raise ValueError("incomplete_metadata_http_response")
    return statuses[lines[0]], headers, body


def _parse_docker_ping(output, stderr):
    status, headers, body = _metadata_http_response(output, stderr)
    if (status != 200 or set(headers) != {b"content-type", b"content-length", b"connection"}
            or headers[b"content-type"] != b"text/plain" or body != b"OK"):
        raise ValueError("invalid_docker_ping_response")
    return validate_result(DOCKER_PING_TOOL_ID, {"parser_version": parser_version(DOCKER_PING_TOOL_ID),
        "kind": "docker_ping", "status_code": status, "health": "ok"})


def _json_unique_object(pairs):
    result = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate_docker_version_field")
        result[key] = item
    return result


def _parse_docker_version(output, stderr):
    status, headers, body = _metadata_http_response(output, stderr)
    if (status != 200 or set(headers) != {b"content-type", b"content-length", b"connection"}
            or headers[b"content-type"] != b"application/json"):
        raise ValueError("invalid_docker_version_response")
    try:
        raw = json.loads(body.decode("ascii"), object_pairs_hook=_json_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_docker_version_json") from None
    if type(raw) is not dict or (raw and set(raw) != set(DOCKER_FIELDS)):
        raise ValueError("unsupported_docker_version_fields")
    return validate_result(DOCKER_VERSION_TOOL_ID, {"parser_version": parser_version(DOCKER_VERSION_TOOL_ID),
        "kind": "docker_version", "status_code": status,
        "metadata": {DOCKER_FIELDS[key]: value for key, value in raw.items()}})


def _parse_winrm_metadata(output, stderr):
    status, headers, body = _metadata_http_response(output, stderr)
    extra = b"www-authenticate" if status == 401 else b"allow"
    if (body or headers[b"content-type"] != b"text/plain"
            or set(headers) != {b"content-type", b"content-length", b"connection", extra}):
        raise ValueError("invalid_winrm_metadata_response")
    if status == 401 and headers[extra] == b"Negotiate, NTLM":
        schemes = ["negotiate", "ntlm"]
    elif status == 405 and headers[extra] == b"POST":
        schemes = []
    else:
        raise ValueError("unsupported_winrm_metadata")
    return validate_result(WINRM_TOOL_ID, {"parser_version": parser_version(WINRM_TOOL_ID),
        "kind": "winrm_metadata", "status_code": status, "auth_schemes": schemes})


def _nmap_service_parser():
    # The networkless worker imports the mounted parser as a standalone module.
    if __package__:
        from . import network_tools_nmap_parser
    else:
        import network_tools_nmap_parser
    return network_tools_nmap_parser


def _parse_nmap_service(output, stderr):
    if stderr:
        raise ValueError("unexpected_nmap_service_stderr")
    return _nmap_service_parser().parse_nmap_service_xml(output)


def _kerberos_parser():
    if __package__:
        from . import network_tools_kerberos_parser
    else:
        import network_tools_kerberos_parser
    return network_tools_kerberos_parser


def _parse_kerbrute(output, stderr):
    if stderr:
        raise ValueError("unexpected_kerbrute_stderr")
    return _kerberos_parser().parse_kerbrute_output(output)


def _redis_snmp_parser():
    if __package__:
        from . import network_tools_redis_snmp_parser
    else:
        import network_tools_redis_snmp_parser
    return network_tools_redis_snmp_parser


def _parse_redis(output, stderr):
    return _redis_snmp_parser().parse_redis_output(output, stderr)


def _parse_snmp(output, stderr):
    return _redis_snmp_parser().parse_snmp_output(output, stderr)


def _dns_srv_parser():
    if __package__:
        from . import network_tools_dns_srv_parser
    else:
        import network_tools_dns_srv_parser
    return network_tools_dns_srv_parser


def _parse_dns_srv(output, stderr):
    return _dns_srv_parser().parse_output(output, stderr)


def _whatweb_parser():
    if __package__:
        from . import network_tools_whatweb_parser
    else:
        import network_tools_whatweb_parser
    return network_tools_whatweb_parser


def _parse_whatweb(output, stderr):
    return _whatweb_parser().parse_output(output, stderr)


def parse_tool_output(tool_id, output: bytes, stderr: bytes = b"", *, truncated=False):
    parser_version(tool_id)
    if (type(output) is not bytes or type(stderr) is not bytes or not output + stderr
            or len(output) + len(stderr) > MAX_OUTPUT_BYTES or type(truncated) is not bool or truncated):
        raise ValueError("invalid_network_tool_output_size")
    if tool_id in DATABASE_TLS_SERVICES:
        return _parse_database_tls(tool_id, output, stderr)
    return {DIG_TOOL_ID: _parse_dns, OPENSSL_TOOL_ID: _parse_tls,
            SSH_TOOL_ID: _parse_ssh, LDAP_TOOL_ID: _parse_ldap, SMB_TOOL_ID: _parse_smb,
            RPCINFO_TOOL_ID: _parse_rpcinfo, SHOWMOUNT_TOOL_ID: _parse_showmount,
            FTP_TOOL_ID: _parse_ftp, SMTP_TOOL_ID: _parse_smtp, DOCKER_PING_TOOL_ID: _parse_docker_ping,
            DOCKER_VERSION_TOOL_ID: _parse_docker_version, WINRM_TOOL_ID: _parse_winrm_metadata,
            NMAP_SERVICE_TOOL_ID: _parse_nmap_service, KERBRUTE_TOOL_ID: _parse_kerbrute,
            REDIS_TOOL_ID: _parse_redis, SNMP_TOOL_ID: _parse_snmp,
            WHATWEB_TOOL_ID: _parse_whatweb, DNS_SRV_TOOL_ID: _parse_dns_srv}[tool_id](output, stderr)
