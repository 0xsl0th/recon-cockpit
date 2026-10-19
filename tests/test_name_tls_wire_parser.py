"""Portable byte vectors, not native daemon or cryptographic execution claims."""

from copy import deepcopy
import hashlib
import ipaddress
import json
import struct

import pytest

from recon_cockpit.secure_agent import name_tls_parser as parser, name_tls_wire as wire
from recon_cockpit.secure_agent import name_tls_spec as preparation

PROBE_DENIED_TEXT = b"net.c:136:try_proto(): socket(): Operation not permitted (1)\n"


def recorded_dig_frame(stderr=PROBE_DENIED_TEXT):
    # Exact O1 bytes retained by failed native diagnostic 8542293; no replayed
    # fixture execution or syscall claim is made by these portable vectors.
    request = bytes.fromhex("0021ac83000000010000000000000a686172626f726465736b04746573740000010001")
    response = bytes.fromhex("0031ac83848000010001000000000a686172626f726465736b04746573740000010001c00c000100010000003c00040a4d000a")
    stdout = (b";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44163\n"
              b";; flags: qr aa ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n\n"
              b";; QUESTION SECTION:\n;harbordesk.test.\t\tIN\tA\n\n;; ANSWER SECTION:\n"
              b"harbordesk.test.\t60\tIN\tA\t10.77.0.10\n\n;; Query time: 24 msec\n"
              b";; SERVER: 10.77.0.53#5353(10.77.0.53) (TCP)\n"
              b";; WHEN: Mon Oct 19 19:16:41 UTC 2026\n;; MSG SIZE  rcvd: 49\n\n")
    return parser.encode_input("dns", configuration="A", case="O1", request=request, delivered_request=request,
        original_response=response, proposed_response=response, delivered_response=response,
        stdout=stdout, stderr=stderr, exit_code=0, stop_reason=None)


def dns_exchange(configuration="A", *, ttl=60, address=None):
    query = struct.pack("!6H", 419, 0, 1, 0, 0, 0) + wire.QUESTION
    response = (struct.pack("!6H", 419, 0x8480, 1, 1, 0, 0) + wire.QUESTION
                + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4)
                + ipaddress.IPv4Address(address or wire.ROWS[configuration][2]).packed)
    return len(query).to_bytes(2, "big") + query, len(response).to_bytes(2, "big") + response


def dig_output(response, configuration="A"):
    facts = wire.parse_dns_frame(response)
    flags = "qr" + (" aa" if facts["flags"] & 0x400 else "") + (" ra" if facts["flags"] & 0x80 else "")
    groups = [[r for r in facts["records"] if r["section"] == s] for s in ("answer", "authority", "additional")]
    lines = [";; Got answer:", f";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {facts['transaction_id']}",
             f";; flags: {flags}; QUERY: 1, ANSWER: {len(groups[0])}, AUTHORITY: {len(groups[1])}, ADDITIONAL: {len(groups[2])}",
             "", ";; QUESTION SECTION:", ";harbordesk.test.\t\tIN\tA", ""]
    for name, records in zip(("ANSWER", "AUTHORITY", "ADDITIONAL"), groups):
        if records:
            lines += [f";; {name} SECTION:"]
            for r in records:
                kind = {1: "A", 2: "NS", 5: "CNAME", 28: "AAAA"}[r["type"]]
                lines += [f"{r['name']}\t{r['ttl']}\tIN\t{kind}\t{r['data']}"]
            lines += [""]
    row = wire.ROWS[configuration]
    lines += [";; Query time: 0 msec", f";; SERVER: {row[0]}#{row[1]}({row[0]}) (TCP)",
              ";; WHEN: Mon Oct 19 12:00:00 UTC 2026", f";; MSG SIZE  rcvd: {len(response) - 2}"]
    return ("\n".join(lines) + "\n").encode("ascii")


def frame(operation="dns", configuration="A", case="O1", **changes):
    request, response = dns_exchange(configuration, ttl=1 if case == "N14" else 60)
    values = dict(configuration=configuration, case=case, request=request, delivered_request=request,
                  original_response=response, proposed_response=response, delivered_response=response,
                  stdout=dig_output(response, configuration), stderr=b"", exit_code=0, stop_reason=None)
    values.update(changes)
    return parser.encode_input(operation, **values)


def client_hello():
    def vector(raw, width=2):
        return len(raw).to_bytes(width, "big") + raw
    def extension(kind, raw):
        return kind.to_bytes(2, "big") + vector(raw)
    name = b"harbordesk.test"
    extensions = b"".join((extension(0, vector(b"\0" + vector(name))), extension(10, b"\0\2\0\x17"),
                           extension(13, b"\0\2\4\3"), extension(43, b"\2\3\4"),
                           extension(51, vector(b"\0\x17" + vector(b"\4" + b"k" * 64)))))
    body = b"\3\3" + b"r" * 32 + b"\0" + b"\0\2\x13\2" + b"\1\0" + vector(extensions)
    handshake = b"\1" + len(body).to_bytes(3, "big") + body
    return b"\x16\3\1" + vector(handshake)


def server_hello():
    extensions = b"\0+\0\2\3\4" + b"\0\x33\0E\0\x17\0A\4" + b"k" * 64
    body = b"\3\3" + b"s" * 32 + b"\0\x13\2\0" + len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\2" + len(body).to_bytes(3, "big") + body
    return b"\x16\3\3" + len(handshake).to_bytes(2, "big") + handshake


def brief(configuration="A"):
    return (f"Connecting to {wire.ROWS[configuration][2]}\nCONNECTION ESTABLISHED\nProtocol version: TLSv1.3\n"
            "Ciphersuite: TLS_AES_256_GCM_SHA384\nPeer certificate: CN=harbordesk.test\n"
            "Hash used: SHA256\nSignature type: ECDSA\nVerification: OK\nVerified peername: harbordesk.test\n"
            "Server Temp Key: ECDH, prime256v1, 256 bits\nDONE\n").encode("ascii")


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", wire.CASES)
def test_prepared_public_request_and_transform_bytes_unchanged(configuration, case):
    assert wire.http_request(configuration, case) == preparation._http_bytes(configuration, f"harbordesk.test:{wire.ROWS[configuration][3]}")
    request, original = dns_exchange(configuration)
    if case in ("N6", "N7", "N8"):
        expected = bytearray(preparation._transformed_frame(configuration, case))
        expected[2:4] = request[2:4]
        assert wire.transformed_dns_response(configuration, case, request, original) == bytes(expected)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", ("O1", "O2", "O3", "O4", "R2", "N14"))
def test_dns_native_wire_semantics_agree_without_grant(configuration, case):
    result = parser.parse_input(frame(configuration=configuration, case=case))
    assert result["binding_candidate"] and result["useful_task_completed"]
    assert result["observation"] == result["native"]["semantic"]
    assert result["observation_sha256"] == wire.semantic_digest(result["observation"])
    assert not {"owner", "grant", "observed_us", "expires_us"} & result.keys()


@pytest.mark.parametrize("stderr,marker", ((b"", None), (PROBE_DENIED_TEXT, "socket_probe_denied_text")))
def test_recorded_dig_stderr_exact_grammar_preserves_wire_agreement(stderr, marker):
    raw = recorded_dig_frame(stderr)
    if stderr:
        assert hashlib.sha256(raw).hexdigest() == "0adda09a3d783fcca07f7e325b0c1cd3c864844695aee54e8eec8e2bb6bce996"
    result = parser.parse_input(raw)
    assert result["native"]["stderr_diagnostic"] == marker
    assert result["native"]["semantic"] == result["observation"]
    assert result["useful_task_completed"] and result["binding_candidate"]
    assert result["streams"]["stderr"] == {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()}
    assert parser.validate_result(result) == result


@pytest.mark.parametrize("stderr", (PROBE_DENIED_TEXT * 2, b" " + PROBE_DENIED_TEXT,
    PROBE_DENIED_TEXT + b" ", PROBE_DENIED_TEXT + b"\n", PROBE_DENIED_TEXT + b"other warning\n",
    PROBE_DENIED_TEXT[:-1], PROBE_DENIED_TEXT[:-1] + b"\r\n",
    PROBE_DENIED_TEXT.replace(b":136:", b":137:"), PROBE_DENIED_TEXT.replace(b"(1)", b"(13)"),
    PROBE_DENIED_TEXT.replace(b"not permitted", b"not supported"), PROBE_DENIED_TEXT + b"\0"))
def test_recorded_dig_stderr_repetition_mutation_and_trailing_bytes_refused(stderr):
    with pytest.raises(ValueError, match="^name_tls_dig_stderr$"):
        parser.parse_input(recorded_dig_frame(stderr))


@pytest.mark.parametrize("field,value", (("marker", None), ("marker", True), ("marker", "socket_probe_allowed"),
                                        ("sha256", "f" * 64), ("bytes", 60)))
def test_dig_diagnostic_marker_is_bound_to_exact_stderr_commitment(field, value):
    result = parser.parse_input(recorded_dig_frame())
    if field == "marker":
        result["native"]["stderr_diagnostic"] = value
    else:
        result["streams"]["stderr"][field] = value
    with pytest.raises(ValueError):
        parser.validate_result(result)


@pytest.mark.parametrize("change", ("native_failure", "answer_changed"))
def test_exact_dig_diagnostic_cannot_replace_success_or_independent_wire_agreement(change):
    header, streams = parser.decode_input(recorded_dig_frame())
    if change == "answer_changed":
        streams["stdout"] = streams["stdout"].replace(b"10.77.0.10", b"10.77.0.99")
    raw = parser.encode_input("dns", configuration="A", case="O1", exit_code=1 if change == "native_failure" else 0,
                              stop_reason=None, **streams)
    with pytest.raises(ValueError, match="^name_tls_(dig_execution_failed|dns_native_wire_disagreement)$"):
        parser.parse_input(raw)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", ("N6", "N7"))
def test_transformed_negative_retains_independent_original(configuration, case):
    request, original = dns_exchange(configuration)
    delivered = wire.transformed_dns_response(configuration, case, request, original)
    result = parser.parse_input(frame(configuration=configuration, case=case, proposed_response=delivered,
                                     delivered_response=delivered, stdout=dig_output(delivered, configuration)))
    assert result["expected_negative"] and not result["useful_task_completed"]
    assert result["streams"]["original_response"]["sha256"] != result["streams"]["delivered_response"]["sha256"]


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_exact_truncated_frame_is_negative_only_with_native_failure(configuration):
    request, original = dns_exchange(configuration)
    response = wire.transformed_dns_response(configuration, "N8", request, original)
    raw = frame(configuration=configuration, case="N8", proposed_response=response, delivered_response=response,
                exit_code=9, stdout=b"", stderr=PROBE_DENIED_TEXT)
    assert parser.parse_input(raw)["expected_negative"]
    with pytest.raises(ValueError):
        parser.parse_input(frame(configuration=configuration, case="N8", proposed_response=response,
                                delivered_response=response, stdout=b""))
    with pytest.raises(ValueError, match="^name_tls_dig_stderr$"):
        parser.parse_input(frame(configuration=configuration, case="N8", proposed_response=response,
                                delivered_response=response, exit_code=9, stdout=b"", stderr=b"other warning\n"))


@pytest.mark.parametrize("mutation", (lambda r: r[:-1], lambda r: r + b"x", lambda r: r + r,
                                      lambda r: r[:4] + b"\x85\x80" + r[6:],
                                      lambda r: r[:14] + b"\xc0\x0c" + r[16:]))
def test_dns_malformed_frames_are_refused(mutation):
    _, response = dns_exchange()
    with pytest.raises(ValueError):
        wire.parse_dns_frame(mutation(response))


@pytest.mark.parametrize("field,value", (("transaction_id", True), ("flags", True), ("records", {}), ("schema_version", 1)))
def test_dns_semantic_type_confusion(field, value):
    _, response = dns_exchange()
    semantic = wire.parse_dns_frame(response)
    semantic[field] = value
    with pytest.raises(ValueError):
        wire.validate_dns_semantic(semantic)


@pytest.mark.parametrize("mutation", (lambda s: s.replace(b"419", b"420"),
                                      lambda s: s.replace(b"\t60\t", b"\t59\t"),
                                      lambda s: s.replace(b"10.77.0.10", b"10.77.0.99"),
                                      lambda s: s.replace(b"(TCP)", b"(UDP)"),
                                      lambda s: s + b"untrusted instruction\n"))
def test_dig_native_wire_disagreement(mutation):
    _, response = dns_exchange()
    with pytest.raises(ValueError):
        parser.parse_input(frame(stdout=mutation(dig_output(response))))


def test_no_implicit_binding_from_duplicate_answers():
    _, response = dns_exchange()
    semantic = wire.parse_dns_frame(response)
    semantic["records"].append(deepcopy(semantic["records"][0]))
    assert not wire.binding_candidate(semantic, "A", "O1")


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_http_exact_response_crosscheck_and_untrusted_metadata(configuration):
    request = wire.http_request(configuration, "O5")
    response = b"HTTP/1.1 302 Found\r\nContent-Length: 4\r\nLocation: http://untrusted.invalid/\r\n\r\ndata"
    raw = frame("http", configuration, "O5", request=request, delivered_request=request,
                original_response=response, proposed_response=response, delivered_response=response, stdout=response)
    result = parser.parse_input(raw)
    assert result["observation"]["status_code"] == 302
    assert result["observation"]["location_sha256"] == hashlib.sha256(b"http://untrusted.invalid/").hexdigest()
    assert "untrusted.invalid" not in json.dumps(result)
    header, streams = parser.decode_input(raw)
    streams["stdout"] = response.replace(b"data", b"evil")
    with pytest.raises(ValueError):
        parser.parse_input(parser.encode_input("http", configuration=configuration, case="O5", exit_code=0,
                                               stop_reason=None, **streams))


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_tls_hello_and_native_verification_are_separate(configuration):
    request, response = client_hello(), server_hello() + b"\x17\3\3\0\x11" + b"x" * 17
    result = parser.parse_input(frame("tls", configuration, "O3", request=request, delivered_request=request,
                                     original_response=response, proposed_response=response, delivered_response=response,
                                     stdout=b"", stderr=brief(configuration)))
    assert result["useful_task_completed"]
    assert result["native"]["verification"] == "verified"
    assert result["observation"]["encrypted_contents_verified"] is False


@pytest.mark.parametrize("operation", ("http", "tls"))
def test_dns_diagnostic_rule_does_not_relax_other_native_grammars(operation):
    if operation == "http":
        request, response = wire.http_request("A", "O1"), b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata"
        stdout, stderr = response, PROBE_DENIED_TEXT
    else:
        request, response = client_hello(), server_hello() + b"\x17\3\3\0\x11" + b"x" * 17
        stdout, stderr = b"", brief() + PROBE_DENIED_TEXT
    raw = frame(operation, case="O1", request=request, delivered_request=request, original_response=response,
                proposed_response=response, delivered_response=response, stdout=stdout, stderr=stderr)
    with pytest.raises(ValueError):
        parser.parse_input(raw)


@pytest.mark.parametrize("mutation", (lambda r: r + client_hello(), lambda r: r.replace(b"harbordesk.test", b"otherdesk.test"),
                                      lambda r: r[:-1]))
def test_tls_hello_is_complete_and_exact(mutation):
    with pytest.raises(ValueError):
        wire.validate_tls_client_hello(mutation(client_hello()))


CAPTURED_CLIENT_HELLO = bytes.fromhex(
    "160301010c010001080303dd9e36e5d85a107447cb977d702aed031d84ba7ab3bfe4c5501386aee60b8d55"
    "20f45fd77fd77500ad0c882e93c2c1b6c75a4a44f378e3127ad6340e4534a4385700021302010000bd0000"
    "0014001200000f686172626f726465736b2e74657374000b00020100000a0004000200170016000000170000"
    "000d002a002809050906090404030503060308070808081a081b081c0809080a080b080408050806040105010601"
    "002b0003020304002d000201010033004700450017004104e948b7adf57ae191746544873c2b04be8bed59dc92"
    "eedfe735404fddebe63a367eeed4d39f77d4c781ce7a1038b54bc40f434083452134338d639264d29f4559001b"
    "00050400010003")


def changed_hello_extensions(transform):
    reader = wire._Reader(CAPTURED_CLIENT_HELLO[9:])
    reader.take(34)
    reader.vector(1)
    reader.vector(2)
    reader.vector(1)
    prefix = reader.raw[:reader.position]
    extensions = wire._Reader(reader.vector(2))
    rows = []
    while extensions.position < len(extensions.raw):
        rows.append((int.from_bytes(extensions.take(2), "big"), extensions.vector(2)))
    encoded = b"".join(kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
                       for kind, value in transform(rows))
    body = prefix + len(encoded).to_bytes(2, "big") + encoded
    handshake = b"\1" + len(body).to_bytes(3, "big") + body
    return CAPTURED_CLIENT_HELLO[:3] + len(handshake).to_bytes(2, "big") + handshake


def test_captured_native_hello_has_profile_only_exact_compression_advertisement():
    from recon_cockpit.secure_agent.tls_posture_hello import validate_client_hello
    # Original public wire bytes retained from diagnostic 9f52c37, without
    # normalizing extension inventory or replacing its random/session/key data.
    assert len(CAPTURED_CLIENT_HELLO) == 273
    digest = "a4a4fe66f13c567aa08226b0f2057921bea1dc1f91bf240326c2763c6d715f59"
    result = wire.validate_tls_client_hello(CAPTURED_CLIENT_HELLO)
    assert result["sha256"] == hashlib.sha256(CAPTURED_CLIENT_HELLO).hexdigest() == digest
    assert result["extension_types"] == [0, 10, 11, 13, 22, 23, 27, 43, 45, 51]
    assert (result["version"], result["cipher"], result["group"], result["sni"]) == (
        "tls1_3", 0x1302, 23, "harbordesk.test")
    with pytest.raises(ValueError, match="tls_posture_client_hello_extension"):
        validate_client_hello(CAPTURED_CLIENT_HELLO, "tls1_3")
    without = changed_hello_extensions(lambda rows: [row for row in rows if row[0] != 27])
    old = validate_client_hello(without, "tls1_3")
    assert wire.validate_tls_client_hello(without) == {**old, "sni": "harbordesk.test", "group": 23}


@pytest.mark.parametrize("payload", (b"", b"\0", b"\2\0\1", b"\2\0\3", b"\4\0\3\0\1",
    b"\4\0\1\0\1", b"\4\0\1\0\2", b"\4\0\1\0\xff", b"\3\0\1\0\3", b"\4\0\1\0\3\0"))
def test_certificate_compression_advertisement_is_one_exact_finite_vector(payload):
    raw = changed_hello_extensions(lambda rows: [(kind, payload if kind == 27 else value) for kind, value in rows])
    with pytest.raises(ValueError, match="certificate_compression"):
        wire.validate_tls_client_hello(raw)


@pytest.mark.parametrize("kind,value", ((27, b"\4\0\1\0\3"), (35, b""), (41, b""), (42, b""),
                                       (44, b"\0\1x"), (0x1234, b"")))
def test_duplicate_compression_cookie_ticket_psk_early_data_and_unknown_extensions_refused(kind, value):
    raw = changed_hello_extensions(lambda rows: [*rows, (kind, value)])
    with pytest.raises(ValueError):
        wire.validate_tls_client_hello(raw)


@pytest.mark.parametrize("kind,value", ((11, b"\2\0\0"), (13, b"\0\1\4"), (22, b"x"), (23, b"x"),
                                       (43, b"\2\3\3"), (45, b"\1\0"), (51, b"\0\4\0\x18\0\0")))
def test_profile_specialization_retains_existing_extension_checks(kind, value):
    raw = changed_hello_extensions(lambda rows: [(k, value if k == kind else v) for k, v in rows])
    with pytest.raises(ValueError):
        wire.validate_tls_client_hello(raw)


@pytest.mark.parametrize("kind", (0, 10, 13, 43, 51))
def test_profile_specialization_requires_every_original_mandatory_extension(kind):
    raw = changed_hello_extensions(lambda rows: [row for row in rows if row[0] != kind])
    with pytest.raises(ValueError):
        wire.validate_tls_client_hello(raw)


def test_tls_hrr_and_second_server_handshake_refused():
    raw = server_hello()
    with pytest.raises(ValueError):
        wire.parse_tls_wire(client_hello(), raw + raw, configuration="A", case="O3")
    hrr = raw[:11] + bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c") + raw[43:]
    with pytest.raises(ValueError):
        wire.parse_tls_wire(client_hello(), hrr, configuration="A", case="O3")


@pytest.mark.parametrize("changed", (b"\x13\x01", b"\x13\x03"))
def test_tls_negotiation_mismatch_rejected_even_with_successful_text(changed):
    request, response = client_hello(), server_hello().replace(b"\x13\2\0", changed + b"\0")
    with pytest.raises(ValueError):
        parser.parse_input(frame("tls", case="O3", request=request, delivered_request=request, original_response=response,
                                proposed_response=response, delivered_response=response, stdout=b"", stderr=brief()))


@pytest.mark.parametrize("suffix", (b"x", b"\0" * 131073))
def test_input_frame_exact_consumption(suffix):
    with pytest.raises(ValueError):
        parser.parse_input(frame() + suffix)


def test_runtime_sources_are_key_free():
    import ast
    from pathlib import Path
    from recon_cockpit.secure_agent import name_tls_parser_runtime as runtime
    root = Path(parser.__file__).parent
    forbidden = {"name_tls_spec", "network_tools_fixture", "network_tools_tls_certificate_material"}
    for name in runtime.MODULES:
        parsed = ast.parse((root / (name + ".py")).read_text())
        for node in ast.walk(parsed):
            if isinstance(node, ast.ImportFrom):
                assert not set((node.module or "").split(".")) & forbidden
                assert not {alias.name for alias in node.names} & forbidden
            elif isinstance(node, ast.Import):
                assert not {alias.name.split(".")[-1] for alias in node.names} & forbidden
