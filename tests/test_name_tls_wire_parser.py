"""Portable byte vectors, not native daemon or cryptographic execution claims."""

from copy import deepcopy
import hashlib
import ipaddress
import json
import struct

import pytest

from recon_cockpit.secure_agent import name_tls_parser as parser, name_tls_wire as wire
from recon_cockpit.secure_agent import name_tls_spec as preparation


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
                exit_code=9, stdout=b"", stderr=b"bounded native EOF failure\n")
    assert parser.parse_input(raw)["expected_negative"]
    with pytest.raises(ValueError):
        parser.parse_input(frame(configuration=configuration, case="N8", proposed_response=response,
                                delivered_response=response, stdout=b""))


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


@pytest.mark.parametrize("mutation", (lambda r: r + client_hello(), lambda r: r.replace(b"harbordesk.test", b"otherdesk.test"),
                                      lambda r: r[:-1]))
def test_tls_hello_is_complete_and_exact(mutation):
    with pytest.raises(ValueError):
        wire.validate_tls_client_hello(mutation(client_hello()))


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
