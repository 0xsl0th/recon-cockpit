"""Bounded Kerbrute reports, explicitly distinct from authenticated KDC facts."""

import re


PARSER_VERSION = "kerbrute-userenum-text-v1"
MAX_OUTPUT_BYTES = 8192
PRINCIPALS = ("fixture-a", "fixture-b")
REALM = "HARBORDESK.TEST"
# Exact upstream ASCII banner, including its otherwise insignificant spaces.
BANNER = (b"\n    __             __               __     \n"
          b"   / /_____  _____/ /_  _______  __/ /____ \n"
          b"  / //_/ _ \\/ ___/ __ \\/ ___/ / / / __/ _ \\\n"
          b" / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/\n"
          b"/_/|_|\\___/_/  /_.___/_/   \\__,_/\\__/\\___/" + b" " * 40 + b"\n")
_TIME = (rb"[0-9]{4}/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01]) "
         rb"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]")
_VERSION = rb"(?:dev|v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
_BUILD_DATE = rb"(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{2}"
_RESET = rb"\x1b\[0m"
_HEADER = re.compile(re.escape(BANNER) + rb"\nVersion: " + _VERSION
    + rb" \((?:[0-9a-f]{7,40}|n/a)\) - " + _BUILD_DATE + rb" - Ronnie Flathers @ropnop\n\n"
    + _TIME + rb" >  Using KDC\(s\):" + _RESET + rb"\n"
    + _TIME + rb" >  \t127\.0\.0\.1:8080\n" + _RESET + rb"\n")
_EXISTS = re.compile(rb"\x1b\[32m" + _TIME
    + rb" >  \[\+\] VALID USERNAME:\t (fixture-[ab])@harbordesk\.test" + _RESET)
_UNKNOWN = re.compile(rb"\x1b\[36m" + _TIME
    + rb" >  \[!\] (fixture-[ab])@harbordesk\.test - User does not exist" + _RESET)
_SUMMARY = re.compile(_TIME + rb" >  Done! Tested 2 usernames \(([0-2]) valid\) in "
    + rb"[0-9]{1,3}\.[0-9]{3} seconds" + _RESET)


def validate_result(value):
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "realm", "semantics",
            "principals", "authentication_verified"} or value["parser_version"] != PARSER_VERSION
            or value["kind"] != "kerberos_principal_reports" or value["realm"] != REALM
            or value["semantics"] != "tool_report_only" or value["authentication_verified"] is not False
            or type(value["principals"]) is not list or len(value["principals"]) != 2):
        raise ValueError("invalid_kerberos_principal_reports")
    reports = []
    for principal, row in zip(PRINCIPALS, value["principals"]):
        if (type(row) is not dict or set(row) != {"principal", "reported_status"}
                or type(row["principal"]) is not str or row["principal"] != principal
                or type(row["reported_status"]) is not str
                or row["reported_status"] not in {"exists", "unknown"}):
            raise ValueError("invalid_kerberos_principal_report")
        reports.append(dict(row))
    return {**value, "principals": reports}


def parse_kerbrute_output(raw):
    """Require complete fixed userenum logs; preserve the tool's ambiguity.

    Kerbrute classifies unknown users by an error-text substring. A different
    Kerberos error containing that substring can produce the same complete
    stdout as a genuine unknown-principal reply. This parser cannot distinguish
    those wire replies and releases only the tool's reported status.
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("invalid_kerbrute_output_size")
    header = _HEADER.match(raw)
    if header is None:
        raise ValueError("invalid_kerbrute_header")
    lines = raw[header.end():].split(b"\n")
    if len(lines) != 4 or lines[-1] != b"":
        raise ValueError("incomplete_kerbrute_reports")
    reports = []
    for principal, line in zip(PRINCIPALS, lines[:2]):
        match, status = _EXISTS.fullmatch(line), "exists"
        if match is None:
            match, status = _UNKNOWN.fullmatch(line), "unknown"
        if match is None or match[1].decode("ascii") != principal:
            raise ValueError("unsupported_kerbrute_report")
        reports.append({"principal": principal, "reported_status": status})
    summary = _SUMMARY.fullmatch(lines[2])
    if summary is None or int(summary[1]) != sum(row["reported_status"] == "exists" for row in reports):
        raise ValueError("inconsistent_kerbrute_summary")
    return validate_result({"parser_version": PARSER_VERSION, "kind": "kerberos_principal_reports",
        "realm": REALM, "semantics": "tool_report_only", "principals": reports,
        "authentication_verified": False})
