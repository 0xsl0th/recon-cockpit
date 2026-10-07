"""Closed passive WhatWeb hints from one fixed owned HTTP response.

Every hint is peer-controlled text. Neither presence nor absence proves a
technology, version, vulnerability, or permission for another request.
"""

import json
import re


TOOL_ID = "whatweb_http_fingerprint_v1"
PARSER_VERSION = "whatweb-json-v1"
TARGET = "http://127.0.0.1:8080/harbordesk/portal.html"
HEADERS = {"Connection": "close", "Accept-Encoding": "identity", "User-Agent": "recon-cockpit-c3/1"}
PLUGINS = ("Title", "HTTPServer", "X-Powered-By", "MetaGenerator", "JQuery")
MAX_OUTPUT_BYTES = 8192
MAX_NORMALIZED_BYTES = 3000
SEMANTICS = "untrusted_application_hints"
_VERSION = re.compile(r"[0-9][0-9.]{0,63}")


def _strings(values, maximum=256, *, versions=False):
    if (type(values) is not list or not 1 <= len(values) <= 8
            or any(type(value) is not str or not 1 <= len(value) <= maximum
                   or any(not 32 <= ord(char) <= 126 for char in value)
                   or (versions and _VERSION.fullmatch(value) is None) for value in values)
            or values != sorted(set(values))):
        raise ValueError("invalid_whatweb_hint_values")
    return list(values)


def validate_result(value):
    """Detach only bounded untrusted hints; no fields can imply authority."""
    if (type(value) is not dict or set(value) != {
            "parser_version", "kind", "semantics", "status_code", "hints"}
            or value["parser_version"] != PARSER_VERSION
            or value["kind"] != "http_fingerprint" or value["semantics"] != SEMANTICS
            or type(value["status_code"]) is not int or value["status_code"] != 200
            or type(value["hints"]) is not list or len(value["hints"]) > len(PLUGINS)):
        raise ValueError("invalid_whatweb_observation")
    hints, previous = [], -1
    for row in value["hints"]:
        if (type(row) is not dict or set(row) != {"plugin", "strings", "versions"}
                or type(row["plugin"]) is not str or row["plugin"] not in PLUGINS
                or PLUGINS.index(row["plugin"]) <= previous):
            raise ValueError("invalid_whatweb_hint")
        previous = PLUGINS.index(row["plugin"])
        if row["plugin"] == "JQuery":
            if type(row["strings"]) is not list or row["strings"] != []:
                raise ValueError("invalid_whatweb_jquery_hint")
            strings = []
            versions = [] if type(row["versions"]) is list and row["versions"] == [] else _strings(row["versions"], 64, versions=True)
        else:
            if type(row["versions"]) is not list or row["versions"] != []:
                raise ValueError("invalid_whatweb_string_hint")
            strings, versions = _strings(row["strings"]), []
        hints.append({"plugin": row["plugin"], "strings": strings, "versions": versions})
    result = {**value, "hints": hints}
    # Preserve the existing isolated parser's 4 KiB complete reply ceiling.
    if len(json.dumps(result, ensure_ascii=True).encode("ascii")) > MAX_NORMALIZED_BYTES:
        raise ValueError("whatweb_observation_too_large")
    return result


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_whatweb_json_key")
        value[key] = item
    return value


def _invalid_constant(value):
    raise ValueError("invalid_whatweb_json_constant")


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or stderr):
        raise ValueError("invalid_whatweb_output")
    try:
        decoded = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object,
                             parse_constant=_invalid_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("invalid_whatweb_json") from None
    if (type(decoded) is not list or len(decoded) != 1 or type(decoded[0]) is not dict
            or set(decoded[0]) != {"target", "http_status", "request_config", "plugins"}):
        raise ValueError("invalid_whatweb_report")
    report = decoded[0]
    if (report["target"] != TARGET or type(report["http_status"]) is not int
            or report["http_status"] != 200 or report["request_config"] != {"headers": HEADERS}
            or type(report["plugins"]) is not dict or not set(report["plugins"]) <= set(PLUGINS)):
        raise ValueError("unsupported_whatweb_report")
    hints = []
    for plugin in PLUGINS:
        if plugin not in report["plugins"]:
            continue
        fields = report["plugins"][plugin]
        if type(fields) is not dict:
            raise ValueError("invalid_whatweb_plugin")
        if plugin == "JQuery":
            if not set(fields) <= {"version"}:
                raise ValueError("invalid_whatweb_jquery_plugin")
            strings, versions = [], _strings(fields["version"], 64, versions=True) if "version" in fields else []
        else:
            allowed = {"string", "os"} if plugin == "HTTPServer" else {"string", "module"} if plugin == "Title" else {"string"}
            if "string" not in fields or not set(fields) <= allowed:
                raise ValueError("invalid_whatweb_string_plugin")
            strings, versions = _strings(fields["string"]), []
            if "os" in fields:
                _strings(fields["os"])
            if "module" in fields and fields["module"] != ["Title element contains newline(s)!"]:
                raise ValueError("invalid_whatweb_title_warning")
        hints.append({"plugin": plugin, "strings": strings, "versions": versions})
    return validate_result({"parser_version": PARSER_VERSION, "kind": "http_fingerprint",
        "semantics": SEMANTICS, "status_code": 200, "hints": hints})
