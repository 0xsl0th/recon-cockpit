"""One bounded untrusted SNMP page, with no walk or inventory authority."""

import copy

if __package__:
    from . import network_tools_snmp_next_parser as previous
else:
    import network_tools_snmp_next_parser as previous


TOOL_ID = "snmp_interface_page_v1"
PARSER_VERSION = "snmp-interface-page-text-v1"
SEMANTICS = "untrusted_snmp_interface_page_metadata"
QUERY_OID = previous.QUERY_OID
MAX_REPETITIONS = 4
MAX_OUTPUT_BYTES = previous.MAX_OUTPUT_BYTES
END_OF_MIB_VIEW = previous.END_OF_MIB_VIEW
_KINDS = frozenset({"interface_description", "end_of_mib_view", "outside_ifdescr_subtree"})


def _page(rows):
    """Validate every binding, including values after the first column boundary."""
    if type(rows) is not list or not 1 <= len(rows) <= MAX_REPETITIONS:
        raise ValueError("invalid_snmp_page_rows")
    seed = last = previous._oid(QUERY_OID)
    boundary, ended = None, False
    for row in rows:
        if (type(row) is not dict or set(row) != {"returned_oid", "kind", "interface_index", "description"}
                or type(row["kind"]) is not str or row["kind"] not in _KINDS):
            raise ValueError("invalid_snmp_page_row")
        returned, kind = previous._oid(row["returned_oid"]), row["kind"]
        if kind == "end_of_mib_view":
            if returned != last or row["interface_index"] is not None or row["description"] is not None:
                raise ValueError("invalid_snmp_page_end_of_view")
            ended = True
        else:
            if ended or returned <= last:
                raise ValueError("nonincreasing_snmp_page_oid")
            inside = returned[:len(seed)] == seed
            if kind == "interface_description":
                if (boundary is not None or not inside or len(returned) != len(seed) + 1
                        or type(row["interface_index"]) is not int
                        or not 1 <= row["interface_index"] <= 2147483647
                        or row["interface_index"] != returned[-1]
                        or not previous._description(row["description"])):
                    raise ValueError("invalid_snmp_page_interface")
            elif inside or row["interface_index"] is not None or row["description"] is not None:
                raise ValueError("invalid_snmp_page_outside_subtree")
            last = returned
        if boundary is None and kind != "interface_description":
            boundary = {"kind": kind, "returned_oid": row["returned_oid"]}
    if boundary is None and len(rows) != MAX_REPETITIONS:
        # A short successful GETBULK response can be protocol-valid. This finite
        # profile supports only a full page or an explicit terminal boundary.
        raise ValueError("unsupported_short_snmp_page")
    return boundary, "interface_page" if boundary is None else boundary["kind"]


def validate_result(value):
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics",
            "query_oid", "max_repetitions", "outcome", "rows", "end_boundary", "page_full",
            "inventory_complete", "service_identity_verified"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "snmp_interface_page_metadata"
            or value["semantics"] != SEMANTICS or value["query_oid"] != QUERY_OID
            or type(value["max_repetitions"]) is not int or value["max_repetitions"] != MAX_REPETITIONS
            or type(value["page_full"]) is not bool or value["inventory_complete"] is not False
            or value["service_identity_verified"] is not False):
        raise ValueError("invalid_snmp_page_observation")
    boundary, outcome = _page(value["rows"])
    if (value["end_boundary"] != boundary or value["outcome"] != outcome
            or value["page_full"] != (boundary is None)):
        raise ValueError("inconsistent_snmp_page_observation")
    return copy.deepcopy(value)


def _row(lines):
    returned_oid, separator, rendered = lines[0].partition(" = ")
    if not separator:
        raise ValueError("invalid_snmp_page_variable")
    seed, returned = previous._oid(QUERY_OID), previous._oid(returned_oid)
    description, interface_index = None, None
    if rendered == END_OF_MIB_VIEW and len(lines) == 1:
        kind = "end_of_mib_view"
    elif returned[:len(seed)] == seed:
        kind, interface_index = "interface_description", returned[-1]
        if rendered == '""' and len(lines) == 1:
            description = ""
        elif rendered.startswith("Hex-STRING: "):
            description = previous._hex_description([rendered[12:], *lines[1:]])
        else:
            raise ValueError("unsupported_snmp_page_description_type")
    else:
        value = rendered.removeprefix("INTEGER: ")
        if (len(lines) != 1 or not rendered.startswith("INTEGER: ")
                or previous._INTEGER.fullmatch(value) is None
                or not -2147483648 <= int(value) <= 2147483647):
            raise ValueError("unsupported_snmp_page_outside_value")
        kind = "outside_ifdescr_subtree"
    return {"returned_oid": returned_oid, "kind": kind,
            "interface_index": interface_index, "description": description}


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw or stderr
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES):
        raise ValueError("invalid_snmp_page_output")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_snmp_page_encoding") from None
    lines = text.split("\n")
    if not 2 <= len(lines) <= 16 * MAX_REPETITIONS + 1 or lines[-1] != "":
        raise ValueError("incomplete_snmp_page_output")
    blocks = []
    for line in lines[:-1]:
        if " = " in line:
            blocks.append([line])
            if len(blocks) > MAX_REPETITIONS:
                raise ValueError("excess_snmp_page_bindings")
        elif not blocks:
            raise ValueError("invalid_snmp_page_variable")
        else:
            blocks[-1].append(line)
    rows = [_row(block) for block in blocks]
    boundary, outcome = _page(rows)
    return validate_result({"parser_version": PARSER_VERSION, "kind": "snmp_interface_page_metadata",
        "semantics": SEMANTICS, "query_oid": QUERY_OID, "max_repetitions": MAX_REPETITIONS,
        "outcome": outcome, "rows": rows, "end_boundary": boundary, "page_full": boundary is None,
        "inventory_complete": False, "service_identity_verified": False})
