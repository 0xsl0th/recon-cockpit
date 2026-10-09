"""A single reported successor cannot authorize a walk or establish inventory."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import network_tools_parser as shared
from recon_cockpit.secure_agent import network_tools_parser_runtime as runtime
from recon_cockpit.secure_agent import network_tools_snmp_next_parser as parser


SEED = ".1.3.6.1.2.1.2.2.1.2"
INTERFACE = SEED + ".1"
OUTSIDE = ".1.3.6.1.2.1.2.2.1.3.1"
END = "No more variables left in this MIB View (It is past the end of the MIB tree)"


def rendered_string(value):
    if not value:
        return '""'
    return "Hex-STRING: " + "\n".join("".join(f"{byte:02X} " for byte in value[start:start + 16])
        for start in range(0, len(value), 16))


def row(oid=INTERFACE, value=b"HarborDesk synthetic interface"):
    return (oid + " = " + (rendered_string(value) if isinstance(value, bytes) else value) + "\n").encode("ascii")


def output(case="snmp-next-ok"):
    # Portable fixture captures; malformed/transport cases only provide invalid
    # parser inputs, not a claim about the native client's exact diagnostic.
    from recon_cockpit.secure_agent.network_tools_fixture import (
        HOSTILE_NOTE, SNMP_NEXT_CASES, SNMP_NEXT_DESCRIPTION)
    if case not in SNMP_NEXT_CASES:
        raise ValueError("invalid_snmp_next_test_case")
    if case == "snmp-next-empty":
        return row(value=b"")
    if case == "snmp-next-end-of-view":
        return row(SEED, END)
    if case == "snmp-next-outside-subtree":
        return row(OUTSIDE, "INTEGER: 6")
    if case == "snmp-next-injected":
        return row(value=HOSTILE_NOTE.encode("ascii"))
    if case == "snmp-next-nonincreasing":
        return row(SEED)
    if case == "snmp-next-wrong-type":
        return row(value="INTEGER: 6")
    if case == "snmp-next-extra-varbind":
        return row() * 2
    if case == "snmp-next-malformed":
        return b"malformed SNMP response\n"
    if case == "snmp-next-truncated":
        return row()[:-1]
    if case == "snmp-next-denied":
        return b"Error in packet.\nReason: authorizationError (access denied to that object)\n"
    if case == "snmp-next-stalled":
        return b""
    if case == "snmp-next-output-limit":
        return row(value=b"x" * 3000)
    return row(value=SNMP_NEXT_DESCRIPTION.encode("ascii"))


@pytest.mark.parametrize("case,outcome,oid,index,description", [
    ("ok", "interface_description", INTERFACE, 1, "HarborDesk synthetic interface"),
    ("empty", "interface_description", INTERFACE, 1, ""),
    ("end-of-view", "end_of_mib_view", SEED, None, None),
    ("outside-subtree", "outside_ifdescr_subtree", OUTSIDE, None, None),
    ("fragmented", "interface_description", INTERFACE, 1, "HarborDesk synthetic interface"),
])
def test_closed_summary_preserves_distinct_successor_meanings(case, outcome, oid, index, description):
    expected = {"parser_version": "snmp-interface-next-text-v1", "kind": "snmp_interface_next_metadata",
        "semantics": "untrusted_snmp_successor_metadata", "query_oid": SEED, "returned_oid": oid,
        "outcome": outcome, "interface_index": index, "description": description,
        "service_identity_verified": False}
    value = shared.parse_tool_output(parser.TOOL_ID, output("snmp-next-" + case))
    assert value == expected and len(value) == 9
    detached = shared.validate_result(parser.TOOL_ID, value)
    value["description"] = "changed"
    assert detached == expected


def test_hostile_description_remains_literal_data_without_followup_or_identity():
    from recon_cockpit.secure_agent.network_tools_fixture import HOSTILE_NOTE
    result = shared.parse_tool_output(parser.TOOL_ID, output("snmp-next-injected"))
    assert result["description"] == HOSTILE_NOTE
    assert result["semantics"] == "untrusted_snmp_successor_metadata"
    assert result["service_identity_verified"] is False
    assert not {"next_action", "target", "inventory", "interfaces", "absence", "credentials"} & set(result)


@pytest.mark.parametrize("case", ["nonincreasing", "wrong-type", "extra-varbind", "malformed",
    "truncated", "denied", "stalled", "output-limit"])
def test_negative_fixture_capture_cannot_create_a_successor(case):
    with pytest.raises(ValueError):
        shared.parse_tool_output(parser.TOOL_ID, output("snmp-next-" + case))


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 240, 254, 255])
def test_exact_hex_wrapping_and_empty_octet_string_are_distinct_from_missing_data(size):
    description = (b'quoted " /path\\ with `| markers ' * 10)[:size]
    result = parser.parse_output(row(value=description))
    assert result["description"] == description.decode("ascii")
    assert result["outcome"] == "interface_description"


@pytest.mark.parametrize("value", [b"x" * 256, b"\x00", b"\t", b"\n", b"\r", b"\x1b[2J", b"\x7f", b"\x80", b"\xff",
    b"line\n.1.3.6.1.2.1.2.2.1.2.2 = INTEGER: 1"])
def test_octets_cannot_inject_rows_or_controls_and_description_has_a_byte_bound(value):
    with pytest.raises(ValueError):
        parser.parse_output(row(value=value))


@pytest.mark.parametrize("value", ['STRING: "owned"', 'STRING: ""', "Hex-STRING: ", 'Hex-STRING: ""',
    "Hex-STRING: 41", "Hex-STRING: 4a ", "Hex-STRING: GG ", "Hex-STRING: 4 ",
    "Hex-STRING: 41  ", "Hex-STRING: 41\t", "Hex-STRING: \t41 ",
    "Hex-STRING: 41 \n42 ", "Hex-STRING: " + "41 " * 17,
    "Hex-STRING: " + "41 " * 16 + "\n", "INTEGER: 6", "NULL",
    "No Such Object available on this agent at this OID", "No Such Instance currently exists at this OID"])
def test_noncanonical_or_wrong_typed_description_is_inconclusive(value):
    with pytest.raises(ValueError):
        parser.parse_output(row(value=value))


@pytest.mark.parametrize("mutation", [lambda raw: raw[:-1], lambda raw: raw + b"\n",
    lambda raw: b"\n" + raw, lambda raw: raw.replace(b"\n", b"\r\n"),
    lambda raw: raw.replace(b" = ", b"= "), lambda raw: raw.replace(b" = ", b" =  "),
    lambda raw: raw + row(OUTSIDE, "INTEGER: 6"), lambda raw: b"warning\n" + raw,
    lambda raw: raw + b"warning\n", lambda raw: raw.replace(b"Hex-STRING:", b"\xff:"),
    lambda raw: raw.replace(INTERFACE.encode(), (SEED + ".\u0661").encode("utf-8"))])
def test_entire_transcript_is_checked_without_ignoring_unrecognized_lines(mutation):
    with pytest.raises(ValueError):
        parser.parse_output(mutation(row()))


@pytest.mark.parametrize("oid", [SEED, ".1.3.6.1.2.1.2.2.1.1.99", ".1.3.6.1.2.1.2.2.1",
    SEED + ".0", SEED + ".2147483648", SEED + ".1.1", SEED + ".01", SEED + ".-1",
    SEED + ".+1", SEED + ".1.", SEED + "..1", INTERFACE[1:], "iso.3.6.1.2.1.2.2.1.2.1",
    ".3.0", ".1.40", ".0.40", ".2.4294967296", ".2.0." + ".".join(["1"] * 127),
    ".2.0." + "1" * 1000, "", ".", ".1"])
def test_returned_oid_must_be_canonical_increasing_and_have_exact_interface_index_shape(oid):
    with pytest.raises(ValueError):
        parser.parse_output(row(oid))


@pytest.mark.parametrize("index", [1, 9, 10, 99, 2147483647])
def test_ifdescr_index_is_one_positive_bounded_arc(index):
    result = parser.parse_output(row(SEED + "." + str(index)))
    assert result["interface_index"] == index


@pytest.mark.parametrize("oid", [OUTSIDE, ".1.3.6.1.2.1.2.2.1.10.1", ".1.3.6.1.2.1.2.2.1.20.1",
    ".1.3.6.1.2.1.20", ".2.4294967295", ".2.0." + ".".join(["4294967295"] * 126)])
def test_successor_order_uses_numeric_arcs_and_outside_value_is_discarded(oid):
    result = parser.parse_output(row(oid, "INTEGER: 6"))
    assert result["outcome"] == "outside_ifdescr_subtree" and result["returned_oid"] == oid
    assert result["description"] is None and result["interface_index"] is None
    assert "INTEGER" not in json.dumps(result)


@pytest.mark.parametrize("integer", [-2147483648, -1, 0, 1, 6, 2147483647])
def test_supported_outside_integer_is_validated_but_not_released(integer):
    assert parser.parse_output(row(OUTSIDE, "INTEGER: " + str(integer))) == parser.parse_output(row(OUTSIDE, "INTEGER: 6"))


@pytest.mark.parametrize("value", ["INTEGER: -2147483649", "INTEGER: 2147483648", "INTEGER: -0", "INTEGER: 06",
    "INTEGER: +6", "INTEGER: 6 ", "INTEGER:  6", "INTEGER: 6.0", "INTEGER: 6\n", "6",
    "INTEGER: ethernetCsmacd(6)", "Counter32: 6", "Gauge32: 6", "Timeticks: 6", "NULL", '""',
    "Hex-STRING: 41 ", END, "No Such Object available on this agent at this OID"])
def test_outside_oid_alone_cannot_hide_unsupported_or_malformed_values(value):
    with pytest.raises(ValueError):
        parser.parse_output(row(OUTSIDE, value))


@pytest.mark.parametrize("oid,value", [(INTERFACE, END), (OUTSIDE, END), (SEED, END + " "),
    (SEED, END + "\n"), (SEED, "No more variables left in this MIB View"), (SEED, "endOfMibView"),
    (SEED, "No Such Object available on this agent at this OID")])
def test_end_of_view_requires_exact_seed_and_complete_native_exception_text(oid, value):
    with pytest.raises(ValueError):
        parser.parse_output(row(oid, value))


@pytest.mark.parametrize("case", ["ok", "empty", "end-of-view", "outside-subtree"])
@pytest.mark.parametrize("field,value", [("parser_version", "future"), ("kind", "inventory"),
    ("semantics", "verified"), ("query_oid", INTERFACE), ("returned_oid", None),
    ("outcome", []), ("outcome", "absent"), ("service_identity_verified", True),
    ("service_identity_verified", 0), ("next_action", "query another OID")])
def test_closed_summary_rejects_tampering_or_authority_fields(case, field, value):
    result = parser.parse_output(output("snmp-next-" + case))
    result[field] = value
    with pytest.raises(ValueError):
        shared.validate_result(parser.TOOL_ID, result)


@pytest.mark.parametrize("field,value", [("interface_index", True), ("interface_index", "1"),
    ("interface_index", 0), ("interface_index", 2), ("interface_index", 2147483648),
    ("description", None), ("description", b"owned"), ("description", "x" * 256),
    ("description", "line\nline"), ("description", "caf\u00e9"), ("returned_oid", OUTSIDE),
    ("returned_oid", SEED + ".1.1"), ("returned_oid", SEED)])
def test_interface_summary_requires_description_and_exact_index(field, value):
    result = parser.parse_output(row())
    result[field] = value
    with pytest.raises(ValueError):
        parser.validate_result(result)


@pytest.mark.parametrize("case", ["end-of-view", "outside-subtree"])
@pytest.mark.parametrize("field,value", [("interface_index", 1), ("description", ""),
    ("description", "hidden"), ("returned_oid", INTERFACE)])
def test_exception_and_outside_summary_cannot_hide_interface_data(case, field, value):
    result = parser.parse_output(output("snmp-next-" + case))
    result[field] = value
    with pytest.raises(ValueError):
        parser.validate_result(result)


@pytest.mark.parametrize("raw,stderr", [(b"", b""), (row(), b"warning\n"), (b"", row()),
    (bytearray(row()), b""), (row(), ""), ("text", b""), (b"x" * 8193, b"")])
def test_channels_and_capture_bounds_are_strict(raw, stderr):
    with pytest.raises(ValueError):
        parser.parse_output(raw, stderr)


@pytest.mark.parametrize("value", [None, [], {}, "result", 1, True])
def test_result_must_be_a_complete_dictionary(value):
    with pytest.raises(ValueError):
        parser.validate_result(value)


def test_truncated_capture_cannot_become_an_observation():
    with pytest.raises(ValueError):
        shared.parse_tool_output(parser.TOOL_ID, row(), truncated=True)


def test_standalone_import_supports_the_isolated_parser_worker():
    directory = str(Path(shared.__file__).parent)
    script = ("import sys; sys.path.insert(0, " + repr(directory) + "); import network_tools_parser; "
        "print(network_tools_parser.parse_tool_output('snmp_interface_next_v1', sys.stdin.buffer.read()))")
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script], input=row(), capture_output=True)
    assert result.returncode == 0, result.stderr
    assert b"untrusted_snmp_successor_metadata" in result.stdout


def test_networkless_parser_mounts_pure_module_without_snmp_client_or_fixture(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runtime, "_namespaces", lambda: {name: name for name in ("user", "net", "mnt", "pid")})
    argv = runtime._command(parser.TOOL_ID, ("/stdlib", [("/usr/bin/snmpgetnext", "/tool/snmpgetnext"),
        ("/usr/bin/python3", "/usr/bin/python3")]))
    assert "/app/network_tools_snmp_next_parser.py" in argv and "--unshare-net" in argv
    assert not any("fixture" in arg or "snmpgetnext" in arg for arg in argv)
