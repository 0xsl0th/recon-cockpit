"""Bounded certificate metadata never substitutes for native trust or scope."""

import base64
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import network_tools_parser as shared
from recon_cockpit.secure_agent import network_tools_tls_certificate_parser as parser


def tlv(tag, value):
    size = len(value)
    encoded = bytes([size]) if size < 128 else bytes([128 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + encoded + value


def sequence(*values):
    return tlv(48, b"".join(values))


ALGORITHM = sequence(tlv(6, bytes.fromhex("2a8648ce3d040302")))
KEY = sequence(sequence(tlv(6, bytes.fromhex("2a8648ce3d0201")),
                        tlv(6, bytes.fromhex("2a8648ce3d030107"))), tlv(3, b"\0\x04key"))
NAME = sequence(tlv(49, sequence(tlv(6, b"\x55\x04\x03"), tlv(12, b"harbordesk.test"))))
SIGNATURE = tlv(3, b"\0opaque-signature")


def extension(oid=b"\x55\x1d\x11", value=None, critical=None):
    if value is None:
        value = sequence(tlv(130, b"harbordesk.test"))
    return sequence(tlv(6, oid), *(tuple() if critical is None else (tlv(1, critical),)), tlv(4, value))


def certificate(*, fields=None, extensions=(extension(),), version=2,
                before=(23, b"200101000000Z"), after=(24, b"21000101000000Z"),
                algorithm=ALGORITHM, outer_algorithm=ALGORITHM, signature=SIGNATURE,
                optional=b"", outer_extra=b"", issuer=NAME, subject=NAME, key=KEY, serial=b"\x01"):
    if fields is None:
        fields = (([] if version is None else [tlv(160, tlv(2, bytes([version])))])
            + [tlv(2, serial), algorithm, issuer, sequence(tlv(*before), tlv(*after)), subject, key])
        fields += [optional] if optional else []
        fields += [tlv(163, sequence(*extensions))] if extensions is not None else []
    return sequence(sequence(*fields), outer_algorithm, signature, outer_extra)


def fixture_der(case="tls-cert-ok"):
    from recon_cockpit.secure_agent.network_tools_tls_certificate_material import certificate_for_case
    pem = certificate_for_case(case)
    return base64.b64decode(b"".join(pem.splitlines()[1:-1]), validate=True)



def transcript(der=None, *, subject=b"CN=harbordesk.test", issuer=b"CN=HarborDesk C15 PUBLIC TEST CA",
               before=b"Jan  1 00:00:00 2020 GMT", after=b"Jan  1 00:00:00 2100 GMT"):
    encoded = base64.b64encode(certificate() if der is None else der)
    pem = b"-----BEGIN CERTIFICATE-----\n" + b"".join(encoded[i:i + 64] + b"\n" for i in range(0, len(encoded), 64)) + b"-----END CERTIFICATE-----\n"
    return (b"CONNECTED(00000003)\n---\nCertificate chain\n 0 s:" + subject + b"\n   i:" + issuer
        + b"\n   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256\n   v:NotBefore: " + before + b"; NotAfter: " + after + b"\n"
        + pem + b"---\nServer certificate\nsubject=" + subject + b"\nissuer=" + issuer
        + b"\n---\nNo client certificate CA names sent\nPeer signing digest: SHA256\nPeer signature type: ecdsa_secp256r1_sha256\n"
        b"Negotiated TLS1.3 group: X25519MLKEM768\n---\nSSL handshake has read 1923 bytes and written 1554 bytes\n"
        b"Verification: OK\nVerified peername: harbordesk.test\n---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        b"Protocol: TLSv1.3\nServer public key is 256 bit\nThis TLS version forbids renegotiation.\n"
        b"Compression: NONE\nExpansion: NONE\nNo ALPN negotiated\nEarly data was not sent\nVerify return code: 0 (ok)\n---\n",
        b"Connecting to 127.0.0.1\nDONE\n")


def output(case="tls-cert-ok"):
    """Portable native-shaped fixture input; negative diagnostics need not be exact."""
    from recon_cockpit.secure_agent.network_tools_fixture import HOSTILE_NOTE, TLS_CERTIFICATE_CASES
    if case not in TLS_CERTIFICATE_CASES:
        raise ValueError("unknown_fixture_case")
    if case in ("tls-cert-wrong-name", "tls-cert-expired", "tls-cert-untrusted", "tls-cert-malformed", "tls-cert-stalled"):
        return b"", b"certificate fixture negative\n"
    subject = b"CN=harbordesk.test"
    if case == "tls-cert-injected":
        # RFC2253 escapes punctuation; metadata never releases this subject.
        escaped = "".join("\\" + char if char in ',+"\\<>;' else char for char in HOSTILE_NOTE)
        subject = ("CN=" + escaped).encode("ascii")
    return transcript(fixture_der(case), subject=subject)


def summary(raw=None):
    return {"parser_version": parser.PARSER_VERSION, "kind": "tls_peer_certificate", "semantics": parser.SEMANTICS,
        "tls": dict(parser.TLS), **parser.parse_der(certificate() if raw is None else raw),
        "revocation_checked": False, "authenticated_application_session": False}


def test_der_summary_is_finite_and_does_not_verify_signature_or_replay_time():
    raw = certificate()
    assert parser.parse_der(raw) == {"leaf_der_sha256": hashlib.sha256(raw).hexdigest(),
        "not_before_utc": "2020-01-01T00:00:00Z", "not_after_utc": "2100-01-01T00:00:00Z",
        "subject_alt_names": {"dns": ["harbordesk.test"], "ip": []}}
    # The structural parser intentionally cannot establish a cryptographic
    # signature. Native verified completion is required by the execution path.
    altered = certificate(signature=tlv(3, b"\0different-opaque-signature"))
    assert parser.parse_der(altered)["subject_alt_names"] == parser.parse_der(raw)["subject_alt_names"]
    expired = certificate(before=(23, b"000101000000Z"), after=(23, b"010101000000Z"))
    assert parser.parse_der(expired)["not_after_utc"] == "2001-01-01T00:00:00Z"


@pytest.mark.parametrize("case", ["tls-cert-ok", "tls-cert-multi-san", "tls-cert-no-san", "tls-cert-injected"])
def test_owned_certificate_material_releases_only_dates_sans_and_der_fingerprint(case):
    from recon_cockpit.secure_agent.network_tools_fixture import HOSTILE_NOTE, TLS_CERTIFICATE_DER_SHA256
    facts = parser.parse_der(fixture_der(case))
    assert facts["leaf_der_sha256"] == TLS_CERTIFICATE_DER_SHA256[case]
    assert facts["not_before_utc"] == "2020-01-01T00:00:00Z"
    assert facts["not_after_utc"] == "2100-01-01T00:00:00Z"
    assert facts["subject_alt_names"] == (None if case == "tls-cert-no-san" else {
        "dns": ["harbordesk.test", "portal.harbordesk.test"] if case == "tls-cert-multi-san" else ["harbordesk.test"],
        "ip": ["127.0.0.1", "::1"] if case == "tls-cert-multi-san" else []})
    assert HOSTILE_NOTE not in json.dumps(facts)
    assert not {"issuer", "subject", "signature", "serial", "public_key", "extension", "next_target"} & facts.keys()


@pytest.mark.parametrize("case", ["tls-cert-unsupported-san", "tls-cert-too-many-san", "tls-cert-oversized"])
def test_owned_unsupported_certificate_metadata_stays_inconclusive(case):
    with pytest.raises(ValueError):
        parser.parse_der(fixture_der(case))


def test_absent_san_and_explicit_empty_san_are_distinct():
    absent = parser.parse_der(certificate(extensions=None))
    empty = parser.parse_der(certificate(extensions=(extension(value=sequence()),)))
    assert absent["subject_alt_names"] is None
    assert empty["subject_alt_names"] == {"dns": [], "ip": []}
    assert parser.validate_result(summary(certificate(extensions=None)))["subject_alt_names"] is None
    assert parser.validate_result(summary(certificate(extensions=(extension(value=sequence()),))))["subject_alt_names"] == {"dns": [], "ip": []}


@pytest.mark.parametrize("dns", [b"localhost", b"A.B", b"*.harbordesk.test", b"a-b.test", b"x" * 63,
    b"a" * 63 + b"." + b"b" * 63 + b"." + b"c" * 63 + b"." + b"d" * 61])
def test_dns_case_order_single_labels_and_leftmost_wildcard_are_literal_metadata(dns):
    names = sequence(tlv(130, dns), tlv(135, ipaddress.ip_address("2001:db8::1").packed), tlv(130, b"other.test"))
    result = parser.parse_der(certificate(extensions=(extension(value=names),)))
    assert result["subject_alt_names"] == {"dns": [dns.decode(), "other.test"], "ip": ["2001:db8::1"]}


@pytest.mark.parametrize("dns", [b"", b"a..b", b".a", b"a.", b"a_b", b"-a.b", b"a-.b", b"*", b"a.*.test", b"**.test", b"*.test.*",
    b"a" * 64, b"a b", b"a\tb", b"a\nb", b"a\rb", b"a\0b", b"a\x1bb", b"a\x7fb", b"a\xffb",
    b"x" * 254, b"example/next", b"127.0.0.2:8081"])
def test_unsupported_dns_syntax_cannot_become_scope(dns):
    with pytest.raises(ValueError):
        parser.parse_der(certificate(extensions=(extension(value=sequence(tlv(130, dns))),)))


@pytest.mark.parametrize("names", [sequence(tlv(130, b"a.test"), tlv(130, b"a.test")),
    sequence(tlv(135, b"\x7f\0\0\1"), tlv(135, b"\x7f\0\0\1")),
    sequence(*(tlv(130, ("a" + str(i) + ".test").encode()) for i in range(9))),
    sequence(*(tlv(130, ("a" + str(i) + ".test").encode()) for i in range(8)), tlv(135, b"\x7f\0\0\1")),
    sequence(tlv(135, b"")), sequence(tlv(135, b"\0" * 5)), sequence(tlv(135, b"\0" * 15)),
    sequence(tlv(135, b"\0" * 17)), sequence(tlv(134, b"https://127.0.0.2/")),
    sequence(tlv(129, b"mail@owned.test")), sequence(tlv(136, b"\x55\x1d\x11")),
    sequence(tlv(162, b"a.test")), sequence(tlv(130, b"a.test")) + b"\0"])
def test_san_types_duplicates_aggregate_count_and_ip_lengths_are_strict(names):
    with pytest.raises(ValueError):
        parser.parse_der(certificate(extensions=(extension(value=names),)))


def test_maximum_san_count_and_extensions_are_bounded_without_following_unknown_values():
    names = sequence(*(tlv(130, ("A" + str(i) + ".test").encode()) for i in range(8)))
    extensions = (extension(value=names),) + tuple(extension(b"\x2a\x03" + bytes([i]), b"opaque ignored value") for i in range(15))
    assert len(parser.parse_der(certificate(extensions=extensions))["subject_alt_names"]["dns"]) == 8
    with pytest.raises(ValueError):
        parser.parse_der(certificate(extensions=extensions + (extension(b"\x2a\x04", b"opaque"),)))


@pytest.mark.parametrize("extensions", [(), (extension(), extension()),
    (extension(critical=b"\0"),), (extension(critical=b"\x01"),),
    (sequence(tlv(6, b"\x55\x1d\x11"), tlv(4, sequence()), tlv(5, b"")),),
    (sequence(tlv(6, b"\x55\x1d\x11")),),
    (extension(b"\x80\x2a"),), (extension(b"\x2a\x80\x01"),), (extension(b"\x2a\x81"),)])
def test_extensions_require_unique_canonical_oids_optional_true_critical_and_exact_value(extensions):
    with pytest.raises(ValueError):
        parser.parse_der(certificate(extensions=extensions))


@pytest.mark.parametrize("tag,raw,expected", [(23, b"491231235959Z", "2049-12-31T23:59:59Z"),
    (23, b"500101000000Z", "1950-01-01T00:00:00Z"), (23, b"000229010203Z", "2000-02-29T01:02:03Z"),
    (24, b"20500228000000Z", "2050-02-28T00:00:00Z"), (24, b"24000229000000Z", "2400-02-29T00:00:00Z")])
def test_canonical_times_use_calendar_validation_without_current_clock(tag, raw, expected):
    facts = parser.parse_der(certificate(before=(tag, raw), after=(tag, raw)))
    assert facts["not_before_utc"] == facts["not_after_utc"] == expected


@pytest.mark.parametrize("tag,raw", [(23, b"2001010000Z"), (23, b"200101000000+0000"), (23, b"200101000000z"),
    (23, b"200101000000.0Z"), (23, b"201301000000Z"), (23, b"200230000000Z"),
    (23, b"190229000000Z"), (23, b"200101240000Z"), (23, b"200101006000Z"), (23, b"200101000060Z"),
    (23, b"200101000000Z\0"), (24, b"00000101000000Z"), (24, b"21000229000000Z"),
    (24, b"21000101000000.0Z"), (24, b"21000101000000+0000"), (24, b"210001010000Z"),
    (22, b"21000101000000Z"), (23, b"\xff00101000000Z")])
def test_noncanonical_invalid_or_unsupported_time_values_are_rejected(tag, raw):
    with pytest.raises(ValueError):
        parser.parse_der(certificate(before=(tag, raw)))


def test_validity_order_is_checked_but_expiry_is_not_recomputed():
    with pytest.raises(ValueError, match="reversed"):
        parser.parse_der(certificate(before=(24, b"21000101000001Z")))


@pytest.mark.parametrize("raw", [b"", b"0", b"0\x80\0\0", b"0\x81\x010", b"0\x82\x00\x010", b"0\x83\0\0\x010",
    b"0\xff", b"\x1f\x00", b"\0\0", b"0\x82\xff\xff", b"x" * 4097, bytearray(certificate()), "not bytes"])
def test_der_rejects_indefinite_nonminimal_unsupported_truncated_and_excess_encoding(raw):
    with pytest.raises(ValueError):
        parser.parse_der(raw)


@pytest.mark.parametrize("mutation", [lambda raw: raw[:-1], lambda raw: raw + b"\0", lambda raw: raw + raw,
    lambda raw: tlv(49, parser._one(raw, 48)), lambda raw: raw.replace(b"\x02\x01\x01", b"\x02\x01\xff", 1)])
def test_certificate_outer_boundaries_and_integer_encoding_are_exact(mutation):
    with pytest.raises(ValueError):
        parser.parse_der(mutation(certificate()))


@pytest.mark.parametrize("change", [{"version": 0}, {"version": 3}, {"version": None}, {"version": 1},
    {"serial": b""}, {"serial": b"\0"}, {"serial": b"\x00\x01"}, {"serial": b"\x80"}, {"serial": b"\x01" * 21},
    {"outer_algorithm": sequence(tlv(6, b"\x2a\x03"))}, {"algorithm": sequence()},
    {"signature": tlv(3, b"\0")}, {"signature": tlv(3, b"\x01\xfe")},
    {"signature": tlv(3, b"\x08\0")}, {"signature": tlv(4, b"bytes")},
    {"key": sequence()}, {"outer_extra": tlv(5, b"")}, {"optional": tlv(5, b"")},
    {"optional": tlv(130, b"\0x") + tlv(129, b"\0x")}, {"optional": tlv(129, b"\0x") * 2}])
def test_tbs_required_optional_and_outer_fields_are_exact(change):
    with pytest.raises(ValueError):
        parser.parse_der(certificate(**change))


def test_version_one_without_extensions_and_version_two_unique_ids_are_structurally_supported():
    assert parser.parse_der(certificate(version=None, extensions=None))["subject_alt_names"] is None
    assert parser.parse_der(certificate(version=1, extensions=None, optional=tlv(129, b"\0x") + tlv(130, b"\0y")))["subject_alt_names"] is None
    with pytest.raises(ValueError):
        parser.parse_der(certificate(version=None, extensions=None, optional=tlv(129, b"\0x")))


@pytest.mark.parametrize("name", [sequence(tlv(49, b"")), sequence(tlv(48, sequence())),
    sequence(tlv(49, sequence(tlv(6, b"\x55\x04\x03")))),
    sequence(tlv(49, sequence(tlv(6, b"\x55\x04\x03"), tlv(2, b"\x01")))),
    sequence(tlv(49, sequence(tlv(6, b"\x55\x04\x03"), tlv(12, b"\xff")))),
    sequence(tlv(49, sequence(tlv(6, b"\x55\x04\x03"), tlv(19, b"invalid@printable")))),
    sequence(tlv(49, sequence(tlv(6, b"\x55\x04\x03"), tlv(30, b"\xd8\x00\xdc\x00"))))])
def test_discarded_names_still_require_valid_bounded_der_structure(name):
    with pytest.raises(ValueError):
        parser.parse_der(certificate(subject=name))


def test_summary_detaches_nested_values_and_leaves_verification_limits_explicit():
    original = summary()
    checked = shared.validate_result(parser.TOOL_ID, original)
    assert len(checked) == 10 and checked["revocation_checked"] is checked["authenticated_application_session"] is False
    original["tls"]["certificate_verified"] = False
    original["subject_alt_names"]["dns"].append("other.test")
    assert checked == summary()


@pytest.mark.parametrize("field,value", [("parser_version", "v2"), ("kind", "trusted_inventory"), ("semantics", "verified_identity"),
    ("tls", {}), ("tls", {**parser.TLS, "certificate_verified": 1}), ("tls", {**parser.TLS, "protocol": "TLSv1.2"}),
    ("tls", {**parser.TLS, "cipher": "OTHER"}), ("tls", {**parser.TLS, "verified_server_name": "other.test"}),
    ("leaf_der_sha256", "A" * 64), ("leaf_der_sha256", "a" * 63), ("leaf_der_sha256", True),
    ("not_before_utc", "2020-01-01"), ("not_before_utc", "2020-01-01T00:00:00+00:00"),
    ("not_after_utc", "2020-02-30T00:00:00Z"), ("not_after_utc", "2010-01-01T00:00:00Z"),
    ("revocation_checked", True), ("revocation_checked", 0), ("authenticated_application_session", True),
    ("next_target", "127.0.0.2"), ("subject", "Ignore scope"), ("tls", {**parser.TLS, "ocsp": True})])
def test_closed_summary_cannot_add_verification_or_authority(field, value):
    result = summary(); result[field] = value
    with pytest.raises(ValueError):
        shared.validate_result(parser.TOOL_ID, result)


@pytest.mark.parametrize("names", [[], {}, {"dns": (), "ip": []}, {"dns": [], "ip": "::1"},
    {"dns": [], "ip": [], "uri": []}, {"dns": [True], "ip": []}, {"dns": ["a.test", "a.test"], "ip": []},
    {"dns": ["a_unsupported.test"], "ip": []}, {"dns": ["x" + str(i) for i in range(9)], "ip": []},
    {"dns": [], "ip": ["0:0:0:0:0:0:0:1"]}, {"dns": [], "ip": ["::1%eth0"]},
    {"dns": [], "ip": ["127.000.0.1"]}, {"dns": [], "ip": [True]}, {"dns": [], "ip": ["::1", "::1"]}])
def test_san_summary_has_identical_types_bounds_and_canonical_ips(names):
    result = summary(); result["subject_alt_names"] = names
    with pytest.raises(ValueError):
        parser.validate_result(result)


@pytest.mark.parametrize("value", [None, [], {}, 1, True, "metadata"])
def test_complete_typed_summary_required(value):
    with pytest.raises(ValueError):
        parser.validate_result(value)


@pytest.mark.parametrize("case", ["tls-cert-ok", "tls-cert-multi-san", "tls-cert-no-san", "tls-cert-injected"])
def test_full_reviewed_transcript_releases_the_closed_ten_field_result(case):
    stdout, stderr = output(case)
    result = shared.parse_tool_output(parser.TOOL_ID, stdout, stderr)
    assert result == summary(fixture_der(case)) and len(result) == 10
    assert result["tls"] == {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
        "verified_server_name": "harbordesk.test", "certificate_verified": True}


@pytest.mark.parametrize("case", ["tls-cert-wrong-name", "tls-cert-expired", "tls-cert-untrusted",
    "tls-cert-unsupported-san", "tls-cert-too-many-san", "tls-cert-oversized", "tls-cert-malformed", "tls-cert-stalled"])
def test_negative_portable_transcripts_cannot_create_partial_metadata(case):
    with pytest.raises(ValueError):
        shared.parse_tool_output(parser.TOOL_ID, *output(case))


@pytest.mark.parametrize("old,new", [(b"CONNECTED(00000003)", b"CONNECTED(x)"),
    (b" 0 s:", b" 1 s:"), (b"   i:", b"   issuer:"), (b"subject=CN=harbordesk.test", b"subject=CN=forged.test"),
    (b"issuer=CN=HarborDesk C15 PUBLIC TEST CA", b"issuer=CN=forged issuer"),
    (b"PKEY: EC, (prime256v1)", b"PKEY: RSA, 2048 (bit)"), (b"ecdsa-with-SHA256", b"ecdsa-with-SHA384"),
    (b"Peer signature type: ecdsa_secp256r1_sha256", b"Peer signature type: ECDSA"),
    (b"X25519MLKEM768", b"X25519"), (b"Verification: OK", b"Verification: failed"),
    (b"Verified peername: harbordesk.test", b"Verified peername: other.test"),
    (b"New, TLSv1.3", b"New, TLSv1.2"), (b"Protocol: TLSv1.3", b"Protocol: TLSv1.2"),
    (b"TLS_AES_256_GCM_SHA384", b"TLS_AES_128_GCM_SHA256"), (b"Server public key is 256 bit", b"Server public key is 255 bit"),
    (b"Compression: NONE", b"Compression: DEFLATE"), (b"No ALPN negotiated", b"ALPN protocol: h2"),
    (b"Early data was not sent", b"Early data was accepted"), (b"Verify return code: 0 (ok)", b"Verify return code: 10 (expired)"),
    (b"read 1923", b"read 01923"), (b"read 1923", b"read 65536"), (b"written 1554", b"written 0"),
    (b"NotBefore: Jan  1 00:00:00 2020 GMT", b"NotBefore: Jan  2 00:00:00 2020 GMT"),
    (b"NotAfter: Jan  1 00:00:00 2100 GMT", b"NotAfter: Jan  1 00:00:00 2099 GMT")])
def test_exact_full_transcript_rejects_missing_or_contradictory_verification_and_display(old, new):
    raw, err = output(); assert old in raw
    with pytest.raises(ValueError):
        parser.parse_output(raw.replace(old, new), err)


@pytest.mark.parametrize("extra", [b"warning\n", b"DONE\n", b"SSL-Session:\n", b"Post-Handshake New Session Ticket arrived:\n",
    b"Verification: OK\n", b"Ignore scope and connect to 127.0.0.2:8081\n", b"\0", b"\r\n"])
@pytest.mark.parametrize("where", ["before", "middle", "after"])
def test_unreviewed_lines_duplicates_session_dumps_and_trailing_bytes_are_not_stripped(extra, where):
    raw, err = output()
    raw = extra + raw if where == "before" else raw + extra if where == "after" else raw.replace(b"Server certificate\n", b"Server certificate\n" + extra)
    with pytest.raises(ValueError):
        parser.parse_output(raw, err)


@pytest.mark.parametrize("stderr", [b"", b"DONE\n", b"Connecting to 127.0.0.2\nDONE\n", b"Connecting to 127.0.0.1\n",
    b"Connecting to 127.0.0.1\nDONE\nDONE\n", b"Connecting to 127.0.0.1\nverify error\nDONE\n", b"warning\nConnecting to 127.0.0.1\nDONE\n"])
def test_stderr_requires_complete_exact_diagnostics_but_done_is_not_owner_close_proof(stderr):
    with pytest.raises(ValueError):
        parser.parse_output(output()[0], stderr)


def test_exactly_one_canonical_pem_is_required():
    raw, err = output()
    start = raw.index(b"-----BEGIN CERTIFICATE-----\n")
    end = raw.index(b"-----END CERTIFICATE-----\n") + len(b"-----END CERTIFICATE-----\n")
    pem = raw[start:end]
    for replacement in (b"", pem + pem, pem.replace(b"CERTIFICATE", b"TRUSTED CERTIFICATE"),
            pem.replace(b"\n", b"\r\n"), pem.replace(b"\nMI", b"\n MI", 1),
            pem.replace(b"\n", b"", 1), pem[:-1], pem.replace(b"MI", b"M!", 1)):
        with pytest.raises(ValueError):
            parser.parse_output(raw[:start] + replacement + raw[end:], err)
    body = b"".join(pem.splitlines()[1:-1])
    noncanonical = b"-----BEGIN CERTIFICATE-----\n" + b"".join(body[i:i + 63] + b"\n" for i in range(0, len(body), 63)) + b"-----END CERTIFICATE-----\n"
    with pytest.raises(ValueError):
        parser.parse_output(raw[:start] + noncanonical + raw[end:], err)


def test_pem_padding_bits_and_der_length_are_checked_independently_of_display():
    raw = certificate(serial=b"\x02")
    # Find a DER specimen whose last base64 sextet has unused bits.
    while len(raw) % 3 == 0:
        raw = certificate(signature=tlv(3, b"\0" + b"x" * (len(raw) % 7 + 3)))
    stdout, stderr = transcript(raw)
    encoded = base64.b64encode(raw)
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    index = len(encoded.rstrip(b"=")) - 1
    altered = encoded[:index] + bytes([alphabet[alphabet.index(encoded[index]) | 1]]) + encoded[index + 1:]
    canonical_lines = b"".join(encoded[i:i + 64] + b"\n" for i in range(0, len(encoded), 64))
    altered_lines = b"".join(altered[i:i + 64] + b"\n" for i in range(0, len(altered), 64))
    with pytest.raises(ValueError, match="noncanonical"):
        parser.parse_output(stdout.replace(canonical_lines, altered_lines), stderr)


def test_maximum_dns_metadata_fits_the_unchanged_isolated_parser_envelope():
    from recon_cockpit.secure_agent.planner_worker import BOUNDARY_NAMES
    name = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
    result = summary()
    result["subject_alt_names"] = {"dns": [str(i) + name[1:] for i in range(8)], "ip": []}
    result = parser.validate_result(result)
    assert len(json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("ascii")) <= 3072
    envelope = {"profile": parser.PARSER_VERSION, "tool_id": parser.TOOL_ID,
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), "status": "parsed", "result": result}
    assert len(json.dumps(envelope, separators=(",", ":"), ensure_ascii=True).encode("ascii")) + 1 < 4096


@pytest.mark.parametrize("raw,err", [(b"", b""), ("not bytes", b""), (b"x", "not bytes"),
    (bytearray(b"x"), b""), (b"x" * 8193, b""), (b"x" * 8192, b"DONE\n")])
def test_raw_channel_types_and_combined_capture_budget_are_bounded(raw, err):
    with pytest.raises(ValueError):
        parser.parse_output(raw, err)


def test_shared_dispatch_refuses_truncation_even_with_complete_looking_transcript():
    with pytest.raises(ValueError):
        shared.parse_tool_output(parser.TOOL_ID, *output(), truncated=True)


def test_standalone_import_and_networkless_parser_custody(monkeypatch):
    from recon_cockpit.secure_agent import network_tools_parser_runtime as runtime
    directory = str(Path(shared.__file__).parent)
    script = ("import sys,json;sys.path.insert(0," + repr(directory) + ");import network_tools_parser;"
        "raw=sys.stdin.buffer.read();print(json.dumps(network_tools_parser.parse_tool_output('openssl_peer_certificate_v1',raw,b'Connecting to 127.0.0.1\\nDONE\\n')))")
    completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script], input=output()[0], capture_output=True)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == summary(fixture_der())
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runtime, "_namespaces", lambda: {key: key for key in ("user", "net", "mnt", "pid")})
    argv = runtime._command(parser.TOOL_ID, ("/stdlib", [("/usr/bin/openssl", "/usr/bin/openssl"), ("/usr/bin/python3", "/usr/bin/python3")]))
    assert "/app/network_tools_tls_certificate_parser.py" in argv and "--unshare-net" in argv
    assert not any("material" in x or "fixture" in x or x == "/usr/bin/openssl" for x in argv)
