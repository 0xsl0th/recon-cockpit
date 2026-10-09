"""Finite X.509 metadata from one retained, fixture-verified TLS transcript.

This module does not validate signatures, trust paths, revocation or current
expiry. The fixed native OpenSSL invocation and successful owned execution are
separate evidence requirements. Unknown extension values and names stay raw.
"""

import base64
from datetime import datetime
import hashlib
import ipaddress
import json
import re

TOOL_ID = "openssl_peer_certificate_v1"
PARSER_VERSION = "openssl-peer-certificate-v1"
SEMANTICS = "certificate_metadata_from_fixture_verified_tls"
MAX_OUTPUT_BYTES = 8192
MAX_DER_BYTES = 4096
MAX_EXTENSIONS = 16
MAX_SANS = 8
MAX_DNS_BYTES = 253
MAX_SUMMARY_BYTES = 3072
TLS = {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
       "verified_server_name": "harbordesk.test", "certificate_verified": True}


def _tlv(raw, offset=0):
    if offset + 2 > len(raw):
        raise ValueError("incomplete_certificate_tlv")
    tag, size = raw[offset:offset + 2]
    start = offset
    offset += 2
    if tag == 0 or tag & 31 == 31:
        raise ValueError("unsupported_certificate_tag")
    if size & 128:
        width = size & 127
        if not 1 <= width <= 2 or offset + width > len(raw) or raw[offset] == 0:
            raise ValueError("noncanonical_certificate_length")
        size = int.from_bytes(raw[offset:offset + width], "big")
        if size < 128:
            raise ValueError("noncanonical_certificate_length")
        offset += width
    end = offset + size
    if end > len(raw):
        raise ValueError("incomplete_certificate_value")
    return tag, raw[offset:end], end, raw[start:end]


def _items(raw, maximum=64):
    values, offset = [], 0
    while offset < len(raw):
        tag, value, offset, encoded = _tlv(raw, offset)
        values.append((tag, value, encoded))
        if len(values) > maximum:
            raise ValueError("excess_certificate_items")
    return values


def _one(raw, tag):
    actual, value, end, _ = _tlv(raw)
    if actual != tag or end != len(raw):
        raise ValueError("invalid_certificate_field")
    return value


def _integer(raw):
    if (not raw or len(raw) > 20 or raw[0] & 128
            or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 128)):
        raise ValueError("invalid_certificate_integer")
    return int.from_bytes(raw, "big")


def _oid(raw):
    if not raw or len(raw) > 32:
        raise ValueError("invalid_certificate_oid")
    beginning = True
    for byte in raw:
        if beginning and byte == 128:
            raise ValueError("noncanonical_certificate_oid")
        beginning = not byte & 128
    if not beginning:
        raise ValueError("incomplete_certificate_oid")
    return raw


def _bit_string(raw):
    if not raw or not 0 <= raw[0] <= 7 or (len(raw) == 1 and raw[0]):
        raise ValueError("invalid_certificate_bit_string")
    if len(raw) > 1 and raw[0] and raw[-1] & ((1 << raw[0]) - 1):
        raise ValueError("noncanonical_certificate_bit_string")


def _time(tag, raw):
    try:
        text = raw.decode("ascii")
        if tag == 23 and re.fullmatch(r"[0-9]{12}Z", text):
            year = int(text[:2])
            text = str(1900 + year if year >= 50 else 2000 + year) + text[2:]
        elif tag != 24 or not re.fullmatch(r"[0-9]{14}Z", text):
            raise ValueError("invalid_certificate_time")
        value = datetime(int(text[:4]), int(text[4:6]), int(text[6:8]),
                         int(text[8:10]), int(text[10:12]), int(text[12:14]))
        return value.isoformat(timespec="seconds") + "Z"
    except (ValueError, UnicodeError):
        raise ValueError("invalid_certificate_time") from None


def _generic(raw, depth=0):
    """Check canonical DER parameters without interpreting their meaning."""
    if depth > 8:
        raise ValueError("excess_certificate_depth")
    for tag, value, encoded in _items(raw):
        if tag in (48, 49):
            children = _items(value)
            if tag == 49 and [x[2] for x in children] != sorted(x[2] for x in children):
                raise ValueError("noncanonical_certificate_set")
            _generic(value, depth + 1)
        elif tag == 2:
            _integer(value)
        elif tag == 6:
            _oid(value)
        elif tag == 3:
            _bit_string(value)
        elif tag == 1:
            if value not in (b"\0", b"\xff"):
                raise ValueError("noncanonical_certificate_boolean")
        elif tag == 5:
            if value:
                raise ValueError("invalid_certificate_null")
        elif tag in (23, 24):
            _time(tag, value)
        elif tag == 12:
            try:
                value.decode("utf-8")
            except UnicodeError:
                raise ValueError("invalid_certificate_utf8") from None
        elif tag == 19:
            if re.fullmatch(rb"[A-Za-z0-9 '()+,./:=?-]*", value) is None:
                raise ValueError("invalid_certificate_printable_string")
        elif tag == 22:
            if any(byte > 127 for byte in value):
                raise ValueError("invalid_certificate_ia5_string")
        elif tag in (28, 30):
            try:
                if tag == 30 and any(0xd800 <= int.from_bytes(value[i:i + 2], "big") <= 0xdfff
                                    for i in range(0, len(value), 2)):
                    raise ValueError("unsupported_certificate_bmp_surrogate")
                value.decode("utf-32-be" if tag == 28 else "utf-16-be")
            except UnicodeError:
                raise ValueError("invalid_certificate_wide_string") from None
        elif tag not in (4, 20):
            raise ValueError("unsupported_certificate_parameter")


def _algorithm(raw):
    items = _items(raw, 2)
    if not items or items[0][0] != 6:
        raise ValueError("invalid_certificate_algorithm")
    _oid(items[0][1])
    if len(items) == 2:
        _generic(items[1][2])


def _name(raw):
    for tag, value, encoded in _items(raw, 32):
        if tag != 49 or not value:
            raise ValueError("invalid_certificate_name")
        attributes = _items(value, 16)
        if [x[2] for x in attributes] != sorted(x[2] for x in attributes):
            raise ValueError("noncanonical_certificate_name")
        for attribute_tag, attribute, _ in attributes:
            fields = _items(attribute, 2)
            if (attribute_tag != 48 or len(fields) != 2 or fields[0][0] != 6
                    or fields[1][0] not in (12, 19, 20, 22, 28, 30)):
                raise ValueError("invalid_certificate_name_attribute")
            _oid(fields[0][1])
            _generic(fields[1][2])


def _dns(value):
    if type(value) is not str or not 1 <= len(value) <= MAX_DNS_BYTES:
        raise ValueError("invalid_certificate_dns_name")
    name = value[2:] if value.startswith("*.") else value
    if any(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is None
           for label in name.split(".")):
        raise ValueError("unsupported_certificate_dns_name")
    return value


def _sans(raw):
    values = {"dns": [], "ip": []}
    for tag, name, _ in _items(_one(raw, 48), MAX_SANS):
        if tag == 130:
            try:
                value = _dns(name.decode("ascii"))
            except UnicodeError:
                raise ValueError("invalid_certificate_dns_encoding") from None
            kind = "dns"
        elif tag == 135 and len(name) in (4, 16):
            kind, value = "ip", str(ipaddress.ip_address(name))
        else:
            raise ValueError("unsupported_certificate_general_name")
        if value in values[kind]:
            raise ValueError("duplicate_certificate_general_name")
        values[kind].append(value)
    return values


def parse_der(raw):
    """Extract finite certificate metadata; this is not signature verification."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DER_BYTES:
        raise ValueError("invalid_certificate_der_size")
    certificate = _items(_one(raw, 48), 3)
    if len(certificate) != 3 or [x[0] for x in certificate] != [48, 48, 3]:
        raise ValueError("invalid_certificate_structure")
    tbs = _items(certificate[0][1], 10)
    version = 0
    if tbs and tbs[0][0] == 160:
        version = _integer(_one(tbs.pop(0)[1], 2))
        if version not in (1, 2):
            raise ValueError("unsupported_certificate_version")
    if len(tbs) < 6 or [x[0] for x in tbs[:6]] != [2, 48, 48, 48, 48, 48]:
        raise ValueError("invalid_certificate_tbs")
    if not _integer(tbs[0][1]):
        raise ValueError("invalid_certificate_serial")
    _algorithm(tbs[1][1])
    _algorithm(certificate[1][1])
    if tbs[1][2] != certificate[1][2]:
        raise ValueError("inconsistent_certificate_signature_algorithm")
    _name(tbs[2][1])
    _name(tbs[4][1])
    validity = _items(tbs[3][1], 2)
    if len(validity) != 2:
        raise ValueError("invalid_certificate_validity")
    before, after = (_time(tag, value) for tag, value, _ in validity)
    if before > after:
        raise ValueError("reversed_certificate_validity")
    key = _items(tbs[5][1], 2)
    if len(key) != 2 or [x[0] for x in key] != [48, 3]:
        raise ValueError("invalid_certificate_public_key")
    _algorithm(key[0][1])
    for bitstring in (key[1][1], certificate[2][1]):
        _bit_string(bitstring)
        if len(bitstring) < 2 or bitstring[0] != 0:
            raise ValueError("unsupported_certificate_key_or_signature")
    sans, last = None, 128
    for tag, value, _ in tbs[6:]:
        if tag not in (129, 130, 163) or tag <= last:
            raise ValueError("invalid_certificate_optional_fields")
        last = tag
        if tag in (129, 130):
            if version == 0:
                raise ValueError("invalid_certificate_unique_id_version")
            _bit_string(value)
            continue
        if version != 2:
            raise ValueError("invalid_certificate_extensions_version")
        extensions = _items(_one(value, 48), MAX_EXTENSIONS)
        if not extensions:
            raise ValueError("empty_certificate_extensions")
        seen = set()
        for ext_tag, extension, _ in extensions:
            fields = _items(extension, 3)
            if (ext_tag != 48 or len(fields) not in (2, 3) or fields[0][0] != 6
                    or fields[-1][0] != 4 or (len(fields) == 3 and fields[1][:2] != (1, b"\xff"))):
                raise ValueError("invalid_certificate_extension")
            oid = _oid(fields[0][1])
            if oid in seen:
                raise ValueError("duplicate_certificate_extension")
            seen.add(oid)
            if oid == b"\x55\x1d\x11":
                sans = _sans(fields[-1][1])
    return {"leaf_der_sha256": hashlib.sha256(raw).hexdigest(), "not_before_utc": before,
            "not_after_utc": after, "subject_alt_names": sans}


def _utc(value):
    if type(value) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
        raise ValueError("invalid_certificate_utc_summary")
    _time(24, value.translate(str.maketrans("", "", "-:T")).encode("ascii"))


def validate_result(value):
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics", "tls",
            "leaf_der_sha256", "not_before_utc", "not_after_utc", "subject_alt_names",
            "revocation_checked", "authenticated_application_session"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "tls_peer_certificate"
            or value["semantics"] != SEMANTICS or type(value["tls"]) is not dict
            or value["tls"] != TLS or value["tls"].get("certificate_verified") is not True
            or value["revocation_checked"] is not False or value["authenticated_application_session"] is not False
            or type(value["leaf_der_sha256"]) is not str
            or re.fullmatch(r"[a-f0-9]{64}", value["leaf_der_sha256"]) is None):
        raise ValueError("invalid_tls_certificate_result")
    for field in ("not_before_utc", "not_after_utc"):
        _utc(value[field])
    if value["not_before_utc"] > value["not_after_utc"]:
        raise ValueError("reversed_certificate_validity")
    names = value["subject_alt_names"]
    if names is not None:
        if (type(names) is not dict or set(names) != {"dns", "ip"}
                or any(type(names[kind]) is not list for kind in ("dns", "ip"))
                or len(names["dns"]) + len(names["ip"]) > MAX_SANS):
            raise ValueError("invalid_certificate_san_summary")
        for name in names["dns"]:
            _dns(name)
        for name in names["ip"]:
            if type(name) is not str or "%" in name:
                raise ValueError("invalid_certificate_ip_summary")
            try:
                if str(ipaddress.ip_address(name)) != name:
                    raise ValueError("noncanonical_certificate_ip_summary")
            except ValueError:
                raise ValueError("invalid_certificate_ip_summary") from None
        if any(len(set(names[kind])) != len(names[kind]) for kind in names):
            raise ValueError("duplicate_certificate_san_summary")
        names = {kind: list(names[kind]) for kind in ("dns", "ip")}
    result = {**value, "tls": dict(TLS), "subject_alt_names": names}
    if len(json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("ascii")) > MAX_SUMMARY_BYTES:
        raise ValueError("excess_tls_certificate_summary")
    return result


# Exact reviewed full s_client display, with only bounded presentation fields
# variable. This accepts the observed P-256/ECDSA and group display only; other
# native formatting is inconclusive. Repeated names stay raw and are not identity.
_TRANSCRIPT = re.compile(
    rb"CONNECTED\([0-9A-F]{8}\)\n---\nCertificate chain\n"
    rb" 0 s:(?P<subject>[\x20-\x7e]{1,512})\n"
    rb"   i:(?P<issuer>[\x20-\x7e]{1,512})\n"
    rb"   a:PKEY: EC, \(prime256v1\); sigalg: ecdsa-with-SHA256\n"
    rb"   v:NotBefore: (?P<before>[A-Za-z0-9 :]{24}); NotAfter: (?P<after>[A-Za-z0-9 :]{24})\n"
    rb"-----BEGIN CERTIFICATE-----\n(?P<pem>(?:[A-Za-z0-9+/=]{1,64}\n){1,86})"
    rb"-----END CERTIFICATE-----\n---\nServer certificate\n"
    rb"subject=(?P=subject)\nissuer=(?P=issuer)\n---\n"
    rb"No client certificate CA names sent\nPeer signing digest: SHA256\n"
    rb"Peer signature type: ecdsa_secp256r1_sha256\n"
    rb"Negotiated TLS1.3 group: X25519MLKEM768\n---\n"
    rb"SSL handshake has read (?P<read>[1-9][0-9]{0,4}) bytes and written (?P<written>[1-9][0-9]{0,4}) bytes\n"
    rb"Verification: OK\nVerified peername: harbordesk\.test\n---\n"
    rb"New, TLSv1\.3, Cipher is TLS_AES_256_GCM_SHA384\nProtocol: TLSv1\.3\n"
    rb"Server public key is 256 bit\nThis TLS version forbids renegotiation\.\n"
    rb"Compression: NONE\nExpansion: NONE\nNo ALPN negotiated\nEarly data was not sent\n"
    rb"Verify return code: 0 \(ok\)\n---\n")


def _display_time(value):
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return (f"{months[int(value[5:7]) - 1]} {int(value[8:10]):2d} {value[11:19]} {value[:4]} GMT").encode("ascii")


def parse_output(stdout, stderr=b""):
    if (type(stdout) is not bytes or type(stderr) is not bytes or not stdout
            or len(stdout) + len(stderr) > MAX_OUTPUT_BYTES
            or stderr != b"Connecting to 127.0.0.1\nDONE\n"):
        raise ValueError("invalid_tls_certificate_output")
    match = _TRANSCRIPT.fullmatch(stdout)
    if match is None or any(int(match[name]) > 65535 for name in ("read", "written")):
        raise ValueError("unsupported_tls_certificate_transcript")
    encoded = match["pem"].replace(b"\n", b"")
    if len(encoded) > 4 * ((MAX_DER_BYTES + 2) // 3):
        raise ValueError("excess_certificate_pem")
    try:
        der = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise ValueError("invalid_certificate_pem") from None
    canonical = base64.b64encode(der)
    if match["pem"] != b"".join(canonical[i:i + 64] + b"\n" for i in range(0, len(canonical), 64)):
        raise ValueError("noncanonical_certificate_pem")
    facts = parse_der(der)
    if (match["before"] != _display_time(facts["not_before_utc"])
            or match["after"] != _display_time(facts["not_after_utc"])):
        raise ValueError("certificate_display_validity_mismatch")
    return validate_result({"parser_version": PARSER_VERSION, "kind": "tls_peer_certificate",
        "semantics": SEMANTICS, "tls": dict(TLS), **facts,
        "revocation_checked": False, "authenticated_application_session": False})
