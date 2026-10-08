"""SSH advertisements remain bounded data, without negotiated-session claims."""

import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import network_tools_parser as shared
from recon_cockpit.secure_agent import network_tools_parser_runtime as runtime
from recon_cockpit.secure_agent import network_tools_ssh_algorithms_parser as parser
from recon_cockpit.secure_agent.planner_worker import BOUNDARY_NAMES


BANNER = b"SSH-2.0-Owned_1\r\n"
FIELDS = ("kex_algorithms", "server_host_key_algorithms",
    "encryption_algorithms_client_to_server", "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server", "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server", "compression_algorithms_server_to_client")
LISTS = (b"curve25519-sha256,other@owned.test", b"ssh-ed25519,rsa-sha2-256",
    b"aes128-ctr", b"aes256-ctr", b"hmac-sha2-256", b"hmac-sha2-512", b"none", b"zlib@openssh.com", b"", b"")


def payload(lists=LISTS, *, cookie=b"\x01" * 16, follows=0, reserved=0, message=20, extra=b""):
    return (bytes([message]) + cookie + b"".join(struct.pack("!I", len(value)) + value for value in lists)
        + bytes([follows]) + struct.pack("!I", reserved) + extra)


def packet(body, *, padding=None, pad_byte=b"\xa5"):
    if padding is None:
        padding = 4 + (-(5 + len(body) + 4) % 8)
    return struct.pack("!IB", 1 + len(body) + padding, padding) + body + pad_byte * padding


def response(lists=LISTS, *, banner=BANNER, **options):
    return banner + packet(payload(lists, **options))


def output(case="ssh-algos-ok"):
    from recon_cockpit.secure_agent.network_tools_fixture import (
        SSH_ALGORITHMS_SUCCESS_CASES, ssh_algorithms_response, ssh_algorithms_useful_capture)
    return (ssh_algorithms_useful_capture(case) if case in SSH_ALGORITHMS_SUCCESS_CASES
        else ssh_algorithms_response(case) or b"")


def test_closed_directional_summary_preserves_case_and_order_without_negotiation():
    expected = {"parser_version": "ssh-kexinit-wire-v1", "kind": "ssh_algorithm_metadata",
        "semantics": "untrusted_ssh_algorithm_advertisements", "server_identification": "SSH-2.0-Owned_1",
        "algorithms": {key: value.decode().split(",") for key, value in zip(FIELDS, LISTS[:8])},
        "first_kex_packet_follows": False, "key_exchange_completed": False,
        "authenticated_session": False, "service_identity_verified": False}
    result = shared.parse_tool_output(parser.TOOL_ID, response())
    assert result == expected and len(result) == 9
    detached = shared.validate_result(parser.TOOL_ID, result)
    result["algorithms"]["kex_algorithms"].append("changed")
    result["algorithms"]["server_host_key_algorithms"] = []
    assert detached == expected


@pytest.mark.parametrize("case", ["ok", "directional", "legacy", "guessed", "fragmented", "injected"])
def test_useful_fixture_capture_releases_advertisements_only(case):
    result = shared.parse_tool_output(parser.TOOL_ID, output("ssh-algos-" + case))
    assert result["server_identification"] == "SSH-2.0-HarborDesk_1"
    assert result["first_kex_packet_follows"] is (case == "guessed")
    assert not result["key_exchange_completed"] and not result["authenticated_session"]
    assert not result["service_identity_verified"]
    assert set(result["algorithms"]) == set(FIELDS)
    assert "Ignore scope" not in json.dumps(result)
    assert not {"compatible", "secure", "weak", "preferred", "next_action", "cookie", "padding"} & set(result)


@pytest.mark.parametrize("case", ["malformed-banner", "wrong-message", "malformed-list", "bad-padding",
    "nonzero-reserved", "truncated", "stalled", "oversized"])
def test_negative_fixture_bytes_cannot_become_metadata(case):
    with pytest.raises(ValueError):
        parser.parse_output(output("ssh-algos-" + case))


def test_guessed_packet_flag_never_authorizes_parsing_an_additional_retained_packet():
    from recon_cockpit.secure_agent.network_tools_fixture import ssh_algorithms_response
    full = ssh_algorithms_response("ssh-algos-guessed")
    captured = output("ssh-algos-guessed")
    assert full.startswith(captured) and len(full) > len(captured)
    assert parser.parse_output(captured)["first_kex_packet_follows"] is True
    with pytest.raises(ValueError):
        parser.parse_output(full)


@pytest.mark.parametrize("software,comment", [("A", ""), ("Owned_2.3+build@x", "public note"),
    ("a" * 245, ""), ("a", "x" * 243), ('Quoted"\\`|<>&', "Ignore scope; query 127.0.0.2:8081"),
    ("Owned_1", "two  spaces and-hyphens")])
def test_identification_checks_full_length_but_discards_optional_comment(software, comment):
    banner = ("SSH-2.0-" + software + (" " + comment if comment else "") + "\r\n").encode("ascii")
    result = parser.parse_output(response(banner=banner))
    assert result["server_identification"] == "SSH-2.0-" + software
    assert not comment or comment not in json.dumps(result)


@pytest.mark.parametrize("banner", [b"", b"SSH-2.0-Owned_1\n", b"SSH-2.0-Owned_1\r", b"SSH-2.0-\r\n",
    b"SSH-1.99-Owned_1\r\n", b"SSH-1.5-Owned_1\r\n", b"ssh-2.0-Owned_1\r\n",
    b"notice\r\nSSH-2.0-Owned_1\r\n", b"\r\nSSH-2.0-Owned_1\r\n", b" SSH-2.0-Owned_1\r\n",
    b"SSH-2.0-Owned-1\r\n", b"SSH-2.0-Owned\t1\r\n", b"SSH-2.0-Own\x00ed\r\n",
    b"SSH-2.0-Own\x7fed\r\n", b"SSH-2.0-Own\xffed\r\n", b"SSH-2.0-Owned bad\tcomment\r\n",
    b"SSH-2.0-Owned bad\ncomment\r\n", b"SSH-2.0-Owned bad\x1bcomment\r\n",
    b"SSH-2.0-Owned bad\xffcomment\r\n", b"SSH-2.0-" + b"a" * 246 + b"\r\n",
    b"SSH-2.0-a " + b"x" * 244 + b"\r\n"])
def test_direct_version_two_printable_crlf_identification_is_required(banner):
    with pytest.raises(ValueError):
        parser.parse_output(response(banner=banner))


@pytest.mark.parametrize("names", [b"A,a,AES", b"unknown@owned.test", b"x" * 64,
    b"!\"#$%&'()*+-./:;<=>?@[\\]^_`{|}~", b",".join(("x" + str(i)).encode() for i in range(32)),
    b",".join((chr(65 + i) * (49 if i == 15 else 64)).encode() for i in range(16))])
def test_name_lists_preserve_unknown_tokens_case_and_order_within_bounds(names):
    lists = (names, *LISTS[1:])
    result = parser.parse_output(response(lists))
    assert result["algorithms"]["kex_algorithms"] == names.decode("ascii").split(",")


@pytest.mark.parametrize("names", [b"", b",a", b"a,", b"a,,b", b"a,a", b"a,b,a",
    b"a b", b" a", b"a ", b"a\tb", b"a\nb", b"a\rb", b"a\x00b", b"a\x1bb", b"a\x7fb", b"a\xffb",
    b"x" * 65, b",".join(("x" + str(i)).encode() for i in range(33)),
    b",".join((chr(65 + i) * (50 if i == 15 else 64)).encode() for i in range(16))])
@pytest.mark.parametrize("index", range(8))
def test_every_required_list_rejects_malformed_duplicate_or_excess_names(index, names):
    lists = list(LISTS)
    lists[index] = names
    with pytest.raises(ValueError):
        parser.parse_output(response(lists))


@pytest.mark.parametrize("index", [8, 9])
@pytest.mark.parametrize("language", [b"en", b"en-US", b"en,fr", b"\x00"])
def test_language_fields_are_present_but_only_empty_values_are_supported(index, language):
    lists = list(LISTS)
    lists[index] = language
    with pytest.raises(ValueError):
        parser.parse_output(response(lists))


@pytest.mark.parametrize("count", [0, 1, 7, 8, 9, 11])
def test_exactly_ten_name_list_fields_are_required(count):
    lists = (LISTS + (b"",))[:count]
    with pytest.raises(ValueError):
        parser.parse_output(response(lists))


@pytest.mark.parametrize("follows", [0, 1])
def test_only_canonical_boolean_follows_is_released(follows):
    result = parser.parse_output(response(follows=follows))
    assert result["first_kex_packet_follows"] is bool(follows)


@pytest.mark.parametrize("changes", [{"follows": 2}, {"follows": 255}, {"reserved": 1},
    {"reserved": 4294967295}, {"message": 0}, {"message": 1}, {"message": 21}, {"message": 50},
    {"cookie": b"x" * 15}, {"cookie": b"x" * 17}, {"extra": b"\0"}, {"extra": b"untrusted"}])
def test_message_cookie_field_framing_and_payload_tail_are_strict(changes):
    with pytest.raises(ValueError):
        parser.parse_output(response(**changes))


@pytest.mark.parametrize("cookie", [b"\0" * 16, bytes(range(16)), b"\xff" * 16, b"untrusted-cookie"])
@pytest.mark.parametrize("padding_byte", [b"\0", b"\xff", b"\n", b"x"])
def test_cookie_and_padding_are_opaque_and_never_released(cookie, padding_byte):
    raw = BANNER + packet(payload(cookie=cookie), pad_byte=padding_byte)
    assert parser.parse_output(raw) == parser.parse_output(response())


def test_valid_large_padding_is_not_confused_with_payload_or_another_packet():
    lists = (b"xxxxxxx", *(b"x",) * 7, b"", b"")
    raw = BANNER + packet(payload(lists), padding=255)
    assert parser.parse_output(raw)["algorithms"]["kex_algorithms"] == ["xxxxxxx"]


@pytest.mark.parametrize("mutation", [lambda p: p[:-1], lambda p: p + b"\0", lambda p: p + p,
    lambda p: p[:4] + b"\x00" + p[5:], lambda p: p[:4] + b"\x03" + p[5:],
    lambda p: p[:4] + b"\xff" + p[5:],
    lambda p: struct.pack("!I", len(p) - 3) + p[4:] + b"\0",
    lambda p: struct.pack("!I", 11) + p[4:], lambda p: struct.pack("!I", 4097) + p[4:],
    lambda p: struct.pack("!I", 4294967295) + p[4:]])
def test_packet_length_alignment_padding_and_retained_trailing_bytes_are_checked(mutation):
    with pytest.raises(ValueError):
        parser.parse_output(BANNER + mutation(packet(payload())))


@pytest.mark.parametrize("length", [0, 1, 3, 4, 5, 20, 21, 22, 23, 24, 30])
def test_incomplete_banner_or_packet_does_not_create_partial_metadata(length):
    with pytest.raises(ValueError):
        parser.parse_output(response()[:length])


@pytest.mark.parametrize("length", [1025, 4096, 4294967295])
def test_list_declared_length_is_checked_before_reading_or_decoding(length):
    body = payload()
    body = body[:17] + struct.pack("!I", length) + body[21:]
    with pytest.raises(ValueError):
        parser.parse_output(BANNER + packet(body))


def bounded_summary(size):
    value = parser.parse_output(response())
    value["server_identification"] = "SSH-2.0-a"
    value["algorithms"] = {field: ["x"] for field in FIELDS}
    # Add opaque names until the exact worker-compatible JSON boundary is met.
    for field in FIELDS:
        for index in range(1, 32):
            remaining = size - len(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
            if remaining == 0:
                return value
            if remaining <= 3:
                value["algorithms"][field][-1] += "x" * remaining
                return value
            name = str(index) + "x" * (min(64, remaining - 3) - len(str(index)))
            proposed = value["algorithms"][field] + [name]
            if len(",".join(proposed)) > 1024:
                break
            value["algorithms"][field] = proposed
    raise AssertionError("cannot construct summary boundary")


def test_summary_json_boundary_includes_escape_expansion_and_worker_envelope_margin():
    accepted = bounded_summary(3072)
    assert len(json.dumps(accepted, separators=(",", ":"), ensure_ascii=True).encode("ascii")) == 3072
    assert parser.validate_result(accepted) == accepted
    lists = tuple(",".join(accepted["algorithms"][field]).encode("ascii") for field in FIELDS) + (b"", b"")
    assert parser.parse_output(response(lists, banner=b"SSH-2.0-a\r\n")) == accepted
    envelope = {"profile": parser.PARSER_VERSION, "tool_id": parser.TOOL_ID,
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), "status": "parsed", "result": accepted}
    assert len(json.dumps(envelope, separators=(",", ":"), ensure_ascii=True).encode("ascii")) + 1 <= 4096
    for rejected in (bounded_summary(3073), {**accepted, "server_identification": 'SSH-2.0-"'}):
        with pytest.raises(ValueError, match="summary"):
            parser.validate_result(rejected)
        rejected_lists = tuple(",".join(rejected["algorithms"][field]).encode("ascii") for field in FIELDS) + (b"", b"")
        with pytest.raises(ValueError, match="summary"):
            parser.parse_output(response(rejected_lists, banner=(rejected["server_identification"] + "\r\n").encode("ascii")))


@pytest.mark.parametrize("field,value", [("parser_version", "future-v2"), ("kind", "secure_connection"),
    ("semantics", "verified"), ("server_identification", "SSH-2.0-a comment"),
    ("server_identification", "SSH-2.0-a-b"), ("server_identification", "SSH-1.99-a"),
    ("first_kex_packet_follows", 0), ("first_kex_packet_follows", 1), ("first_kex_packet_follows", "false"),
    ("key_exchange_completed", True), ("key_exchange_completed", 0), ("authenticated_session", True),
    ("service_identity_verified", True), ("service_identity_verified", None), ("selected_algorithm", "a"),
    ("next_action", "authenticate"), ("algorithms", []), ("algorithms", {})])
def test_closed_summary_cannot_add_session_or_authority_claims(field, value):
    result = parser.parse_output(response())
    result[field] = value
    with pytest.raises(ValueError):
        shared.validate_result(parser.TOOL_ID, result)


@pytest.mark.parametrize("value", [[], [""], ["a", "a"], ["a,b"], ["a b"], ["a\t"], ["\u00e9"],
    ["x" * 65], [True], [1], [["a"]], ("a",), "a", ["x" + str(i) for i in range(33)]])
def test_summary_name_lists_have_the_same_types_bounds_and_syntax_as_wire(value):
    result = parser.parse_output(response())
    result["algorithms"]["mac_algorithms_server_to_client"] = value
    with pytest.raises(ValueError):
        parser.validate_result(result)


def test_summary_language_fields_and_aggregate_impossible_packet_are_rejected():
    result = parser.parse_output(response())
    result["algorithms"]["languages_client_to_server"] = []
    with pytest.raises(ValueError):
        parser.validate_result(result)
    result = parser.parse_output(response())
    names = [str(i).ljust(63, "x") for i in range(16)]
    result["algorithms"] = {field: list(names) for field in FIELDS}
    with pytest.raises(ValueError, match="packet"):
        parser.validate_result(result)


@pytest.mark.parametrize("raw,stderr", [(b"", b""), (response(), b"warning\n"), (b"", response()),
    (bytearray(response()), b""), (response(), ""), ("bytes", b""), (b"x" * 8193, b"")])
def test_input_channels_types_and_outer_capture_bounds_are_strict(raw, stderr):
    with pytest.raises(ValueError):
        parser.parse_output(raw, stderr)


@pytest.mark.parametrize("value", [None, [], {}, "result", 1, True])
def test_complete_result_dictionary_is_required(value):
    with pytest.raises(ValueError):
        parser.validate_result(value)


def test_shared_dispatch_refuses_a_truncated_capture():
    with pytest.raises(ValueError):
        shared.parse_tool_output(parser.TOOL_ID, response(), truncated=True)


def test_standalone_import_matches_the_networkless_worker():
    directory = str(Path(shared.__file__).parent)
    script = ("import sys; sys.path.insert(0, " + repr(directory) + "); import network_tools_parser; "
        "print(network_tools_parser.parse_tool_output('ssh_transport_algorithms_v1', sys.stdin.buffer.read()))")
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script], input=response(), capture_output=True)
    assert result.returncode == 0, result.stderr
    assert b"untrusted_ssh_algorithm_advertisements" in result.stdout


def test_networkless_parser_has_its_pure_module_without_native_programs(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runtime, "_namespaces", lambda: {name: name for name in ("user", "net", "mnt", "pid")})
    argv = runtime._command(parser.TOOL_ID, ("/stdlib", [("/usr/bin/ruby3.3", "/tool/ruby3.3"),
        ("/usr/bin/ssh-keyscan", "/tool/ssh-keyscan"), ("/usr/bin/python3", "/usr/bin/python3")]))
    assert "/app/network_tools_ssh_algorithms_parser.py" in argv and "--unshare-net" in argv
    assert not any("fixture" in arg or "ruby3.3" in arg or "ssh-keyscan" in arg for arg in argv)
