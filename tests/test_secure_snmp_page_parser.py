"""A finite GETBULK page never establishes inventory or permits follow-up."""

from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import network_tools_snmp_page_parser as parser
from recon_cockpit.secure_agent import network_tools_snmp_page_spec as spec
from test_secure_snmp_next_parser import row


SEED = parser.QUERY_OID
OUTSIDE = ".1.3.6.1.2.1.2.2.1.3."
END = parser.END_OF_MIB_VIEW


def output(case="snmp-page-ok"):
    """Portable rendered captures; negative diagnostics are not native receipts."""
    if case not in spec.CASES:
        raise ValueError("invalid_snmp_page_test_case")
    rows = [row(SEED + "." + str(index), text.encode("ascii"))
            for index, text in enumerate(spec.DESCRIPTIONS, 1)]
    outside = [row(OUTSIDE + str(index), "INTEGER: 6") for index in range(1, 5)]
    if case == "snmp-page-empty":
        rows = [row(SEED + "." + str(index), b"") for index in range(1, 5)]
    elif case == "snmp-page-end-of-view": rows = [row(SEED, END)]
    elif case == "snmp-page-outside-subtree": rows = outside
    elif case == "snmp-page-mixed-boundary": rows = rows[:2] + outside[:2]
    elif case == "snmp-page-end-after-rows": rows = rows[:2] + [row(SEED + ".2", END)] * 2
    elif case == "snmp-page-injected": rows[1] = row(SEED + ".2", spec.HOSTILE_NOTE.encode("ascii"))
    elif case == "snmp-page-short": rows = rows[:3]
    elif case == "snmp-page-empty-page": rows = []
    elif case == "snmp-page-nonincreasing": rows[1], rows[2] = rows[2], rows[1]
    elif case == "snmp-page-duplicate": rows[1] = rows[0]
    elif case == "snmp-page-wrong-type": rows[1] = row(SEED + ".2", "INTEGER: 6")
    elif case == "snmp-page-extra-varbind": rows.append(row(SEED + ".5", b"excess interface"))
    elif case == "snmp-page-after-end": rows[1] = row(SEED + ".1", END)
    elif case == "snmp-page-malformed": return b"malformed SNMP response\n"
    elif case == "snmp-page-truncated": return b"".join(rows)[:-1]
    elif case == "snmp-page-denied": return b"Error in packet.\nReason: authorizationError\n"
    elif case == "snmp-page-stalled": return b""
    elif case == "snmp-page-output-limit": return row(SEED + ".1", b"X" * 12000)
    return b"".join(rows)


@pytest.mark.parametrize("case", spec.SUCCESS_CASES)
def test_successful_page_has_closed_typed_rows_and_no_inventory_claim(case):
    value = parser.parse_output(output(case))
    assert value["parser_version"] == spec.PARSER_VERSION == "snmp-interface-page-text-v1"
    assert value["kind"] == "snmp_interface_page_metadata"
    assert value["semantics"] == "untrusted_snmp_interface_page_metadata"
    assert value["query_oid"] == spec.QUERY_OID and value["max_repetitions"] == 4
    assert value["inventory_complete"] is value["service_identity_verified"] is False
    assert not {"next_oid", "next_action", "target", "absence", "credentials"} & set(value)
    assert len(value["rows"]) == (1 if case == "snmp-page-end-of-view" else 4)
    detached = parser.validate_result(value)
    value["rows"][0]["description"] = "changed"
    assert detached != value


@pytest.mark.parametrize("case,outcome,boundary,oid", [
    ("ok", "interface_page", None, None),
    ("empty", "interface_page", None, None),
    ("end-of-view", "end_of_mib_view", "end_of_mib_view", SEED),
    ("outside-subtree", "outside_ifdescr_subtree", "outside_ifdescr_subtree", OUTSIDE + "1"),
    ("mixed-boundary", "outside_ifdescr_subtree", "outside_ifdescr_subtree", OUTSIDE + "1"),
    ("end-after-rows", "end_of_mib_view", "end_of_mib_view", SEED + ".2"),
])
def test_boundary_is_explicit_and_page_full_is_not_inventory_complete(case, outcome, boundary, oid):
    value = parser.parse_output(output("snmp-page-" + case))
    assert value["outcome"] == outcome
    assert value["end_boundary"] == (None if boundary is None else {"kind": boundary, "returned_oid": oid})
    assert value["page_full"] is (boundary is None)
    if case == "empty":
        assert [entry["description"] for entry in value["rows"]] == [""] * 4
    assert value["inventory_complete"] is False


@pytest.mark.parametrize("case", spec.NEGATIVE_CASES)
def test_negative_capture_cannot_become_a_completed_page(case):
    with pytest.raises(ValueError):
        parser.parse_output(output(case))


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 240, 254, 255])
def test_empty_and_maximum_printable_descriptions_reuse_c13_rendering(size):
    text = (b'quoted " /path\\ with `| markers ' * 10)[:size]
    value = parser.parse_output(b"".join(row(SEED + "." + str(index), text) for index in range(1, 5)))
    assert [entry["description"] for entry in value["rows"]] == [text.decode("ascii")] * 4


@pytest.mark.parametrize("description", [b"x" * 256, b"\x00", b"\t", b"\n", b"\r", b"\x1b[2J",
    b"\x7f", b"\x80", b"\xff", b"line\n.1.3.6.1.2.1.2.2.1.2.2 = INTEGER: 1"])
def test_nonprintable_or_long_descriptions_fail_in_any_row(description):
    with pytest.raises(ValueError):
        parser.parse_output(row(SEED + ".1", b"good") + row(SEED + ".2", description)
            + row(SEED + ".3", b"good") + row(SEED + ".4", b"good"))


@pytest.mark.parametrize("value", ['STRING: "owned"', 'STRING: ""', "Hex-STRING: ", 'Hex-STRING: ""',
    "Hex-STRING: 41", "Hex-STRING: 4a ", "Hex-STRING: GG ", "Hex-STRING: 4 ",
    "Hex-STRING: 41  ", "Hex-STRING: 41\t", "Hex-STRING: \t41 ",
    "Hex-STRING: 41 \n42 ", "Hex-STRING: " + "41 " * 17, "INTEGER: 6", "NULL",
    "No Such Object available on this agent at this OID", "No Such Instance currently exists at this OID"])
def test_wrong_type_or_noncanonical_hex_does_not_hide_among_valid_rows(value):
    with pytest.raises(ValueError):
        parser.parse_output(row(SEED + ".1", value) + row(SEED + ".2", END))


@pytest.mark.parametrize("count", [1, 2, 3])
def test_short_nonterminal_page_is_explicitly_unsupported(count):
    raw = b"".join(row(SEED + "." + str(index), b"good") for index in range(1, count + 1))
    with pytest.raises(ValueError, match="unsupported_short_snmp_page"):
        parser.parse_output(raw)


@pytest.mark.parametrize("count", [1, 2, 3, 4])
def test_repeated_end_of_mib_at_last_returned_oid_is_a_valid_terminal_page(count):
    value = parser.parse_output(row(SEED, END) * count)
    assert len(value["rows"]) == count and value["outcome"] == "end_of_mib_view"
    assert value["page_full"] is False


def test_outside_boundary_then_eom_preserves_first_boundary_and_discards_integer_value():
    value = parser.parse_output(row(OUTSIDE + "1", "INTEGER: -2147483648") + row(OUTSIDE + "1", END) * 3)
    assert value["outcome"] == "outside_ifdescr_subtree"
    assert value["end_boundary"] == {"kind": "outside_ifdescr_subtree", "returned_oid": OUTSIDE + "1"}
    assert all(entry["interface_index"] is entry["description"] is None for entry in value["rows"])


@pytest.mark.parametrize("count", [1, 2, 3, 4])
def test_explicit_outside_boundary_supports_short_terminal_pages(count):
    result = parser.parse_output(b"".join(row(OUTSIDE + str(i), "INTEGER: 6") for i in range(1, count + 1)))
    assert result["outcome"] == "outside_ifdescr_subtree" and result["page_full"] is False
    assert len(result["rows"]) == count


@pytest.mark.parametrize("integer", [-2147483648, -1, 0, 1, 6, 2147483647])
def test_valid_outside_integer_is_checked_but_never_released(integer):
    assert parser.parse_output(row(OUTSIDE + "1", "INTEGER: " + str(integer))) == parser.parse_output(
        row(OUTSIDE + "1", "INTEGER: 6"))


@pytest.mark.parametrize("oid", [SEED, SEED + ".0", SEED + ".2147483648", SEED + ".1.1",
    SEED + ".01", SEED + ".-1", SEED + ".+1", SEED + ".1.", SEED + "..1",
    SEED[1:] + ".1", "iso.3.6.1.2.1.2.2.1.2.1", ".3.0", ".1.40", ".0.40",
    ".2.4294967296", ".2.0." + ".".join(["1"] * 127), "", ".", ".1"])
def test_interface_oid_requires_canonical_positive_bounded_single_index(oid):
    with pytest.raises(ValueError):
        parser.parse_output(row(oid) + row(SEED + ".2", END))


def test_oid_order_uses_numeric_arcs_and_does_not_require_contiguous_indexes():
    value = parser.parse_output(b"".join(row(SEED + "." + str(index)) for index in (1, 9, 10, 2147483647)))
    assert [entry["interface_index"] for entry in value["rows"]] == [1, 9, 10, 2147483647]


@pytest.mark.parametrize("value", ["INTEGER: -2147483649", "INTEGER: 2147483648", "INTEGER: -0",
    "INTEGER: 06", "INTEGER: +6", "INTEGER: 6 ", "INTEGER:  6", "INTEGER: 6.0",
    "INTEGER: ethernetCsmacd(6)", "Counter32: 6", "Gauge32: 6", "NULL", '""', "Hex-STRING: 41 "])
def test_all_outside_values_are_validated_even_after_first_terminal_boundary(value):
    with pytest.raises(ValueError):
        parser.parse_output(row(OUTSIDE + "1", "INTEGER: 6") + row(OUTSIDE + "2", value))


@pytest.mark.parametrize("raw", [row(SEED + ".1", END), row(SEED + ".1") + row(SEED, END),
    row(SEED, END) + row(SEED + ".1"), row(SEED, END) + row(OUTSIDE + "1", "INTEGER: 6"),
    row(OUTSIDE + "1", "INTEGER: 6") * 2, row(OUTSIDE + "2", "INTEGER: 6") + row(OUTSIDE + "1", "INTEGER: 6"),
    row(OUTSIDE + "1", "INTEGER: 6") + row(SEED + ".1"),
    row(SEED, END) + row(SEED + ".1", END), row(SEED, END + " "),
    row(SEED, "No more variables left in this MIB View")])
def test_end_and_order_rules_apply_to_the_entire_page(raw):
    with pytest.raises(ValueError):
        parser.parse_output(raw)


@pytest.mark.parametrize("mutate", [lambda r: r[:-1], lambda r: r + b"\n", lambda r: b"\n" + r,
    lambda r: r.replace(b"\n", b"\r\n"), lambda r: r.replace(b" = ", b"= "),
    lambda r: r.replace(b" = ", b" =  "), lambda r: b"warning\n" + r, lambda r: r + b"warning\n",
    lambda r: r + row(OUTSIDE + "1", "INTEGER: 6"), lambda r: r.replace(b"Hex-STRING:", b"\xff:")])
def test_unrecognized_lines_and_trailing_bytes_are_not_ignored(mutate):
    with pytest.raises(ValueError):
        parser.parse_output(mutate(output()))


@pytest.mark.parametrize("field,value", [("parser_version", "future"), ("kind", "inventory"),
    ("semantics", "verified"), ("query_oid", SEED + ".1"), ("max_repetitions", 3),
    ("max_repetitions", 4.0), ("outcome", "absent"), ("page_full", False), ("page_full", 1),
    ("inventory_complete", True), ("inventory_complete", 0), ("service_identity_verified", True),
    ("service_identity_verified", 0), ("end_boundary", {}), ("rows", []), ("next_oid", SEED + ".5")])
def test_summary_rejects_tampering_and_authority_fields(field, value):
    result = parser.parse_output(output())
    result[field] = value
    with pytest.raises(ValueError):
        parser.validate_result(result)


@pytest.mark.parametrize("field,value", [("interface_index", True), ("interface_index", "1"),
    ("interface_index", 0), ("interface_index", 2), ("description", None), ("description", b"owned"),
    ("description", "x" * 256), ("description", "line\nline"), ("description", "caf\u00e9"),
    ("returned_oid", OUTSIDE + "1"), ("kind", "end_of_mib_view"), ("next_action", "walk")])
def test_typed_row_validation_is_repeated_for_saved_observations(field, value):
    result = parser.parse_output(output())
    result["rows"][0][field] = value
    with pytest.raises(ValueError):
        parser.validate_result(result)


@pytest.mark.parametrize("case", ["snmp-page-end-of-view", "snmp-page-outside-subtree", "snmp-page-mixed-boundary"])
@pytest.mark.parametrize("field,value", [("description", ""), ("interface_index", 1),
    ("kind", "unknown"), ("returned_oid", SEED + ".1")])
def test_boundary_bindings_cannot_hide_description_or_rewrite_terminal_oid(case, field, value):
    result = parser.parse_output(output(case))
    index = next(i for i, entry in enumerate(result["rows"]) if entry["kind"] != "interface_description")
    result["rows"][index][field] = value
    with pytest.raises(ValueError):
        parser.validate_result(result)


@pytest.mark.parametrize("raw,stderr", [(b"", b""), (output(), b"warning\n"), (b"", output()),
    (bytearray(output()), b""), (output(), ""), ("text", b""), (b"x" * 8193, b"")])
def test_channel_types_and_combined_capture_bound_are_strict(raw, stderr):
    with pytest.raises(ValueError):
        parser.parse_output(raw, stderr)


def test_hostile_text_is_literal_and_never_changes_row_or_request_selection():
    result = parser.parse_output(output("snmp-page-injected"))
    assert result["rows"][1]["description"] == spec.HOSTILE_NOTE
    assert [entry["returned_oid"] for entry in result["rows"]] == [SEED + "." + str(i) for i in range(1, 5)]


def test_standalone_pure_parser_loads_only_its_c13_dependency():
    directory = str(Path(parser.__file__).parent)
    script = ("import sys; sys.path.insert(0, " + repr(directory) + "); import network_tools_snmp_page_parser as p; "
        "print(p.parse_output(sys.stdin.buffer.read())); "
        "assert not any('fixture' in name or 'runtime' in name for name in sys.modules)")
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script], input=output(), capture_output=True)
    assert result.returncode == 0, result.stderr
    assert b"untrusted_snmp_interface_page_metadata" in result.stdout


def test_shared_dispatch_uses_the_same_closed_parser_and_refuses_truncated_capture():
    from recon_cockpit.secure_agent import network_tools_parser as shared
    assert shared.parse_tool_output(parser.TOOL_ID, output()) == parser.parse_output(output())
    with pytest.raises(ValueError):
        shared.parse_tool_output(parser.TOOL_ID, output(), truncated=True)


def test_networkless_parser_mounts_both_pure_modules_without_native_client_or_fixture(monkeypatch):
    from recon_cockpit.secure_agent import network_tools_parser_runtime as runtime
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runtime, "_namespaces", lambda: {name: name for name in ("user", "net", "mnt", "pid")})
    argv = runtime._command(parser.TOOL_ID, ("/stdlib", [("/usr/bin/snmpbulkget", "/tool/snmpbulkget"),
        ("/usr/bin/python3", "/usr/bin/python3")]))
    assert "/app/network_tools_snmp_page_parser.py" in argv
    assert "/app/network_tools_snmp_next_parser.py" in argv and "--unshare-net" in argv
    assert not any("fixture" in arg or "snmpbulkget" in arg for arg in argv)
