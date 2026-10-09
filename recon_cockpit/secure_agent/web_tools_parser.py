"""Bounded observations from fixed curl and ffuf output; no executable input."""

from __future__ import annotations

import base64
import json

try:
    from .http_headers_parser import _parse_bounded_http_headers, validate_result as validate_headers
except ImportError:  # Fixed networkless worker imports its read-only /app mount.
    from http_headers_parser import _parse_bounded_http_headers, validate_result as validate_headers


CURL_TOOL_ID = "curl_https_get_v1"
FFUF_TOOL_ID = "ffuf_content_discovery_v1"
PARSER_VERSIONS = {CURL_TOOL_ID: "curl-https-http-v1", FFUF_TOOL_ID: "ffuf-content-json-v1"}
MAX_OUTPUT_BYTES = 8192
WORDS = ("portal.html", "health", "robots.txt", "admin", "api", "backup", "status", "missing-control")
PATHS = tuple("/harbordesk/" + word for word in WORDS)
_FFUF_FIELDS = {"input", "position", "status", "length", "words", "lines", "content-type",
                "redirectlocation", "scraper", "duration", "resultfile", "url", "host"}


def parser_version(tool_id):
    if type(tool_id) is not str or tool_id not in PARSER_VERSIONS:
        raise ValueError("unsupported_web_tool_parser")
    return PARSER_VERSIONS[tool_id]


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_web_tool_json_key")
        value[key] = item
    return value


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def validate_result(tool_id, value):
    """Validate every field released from the networkless parser."""
    version = parser_version(tool_id)
    if type(value) is not dict or value.get("parser_version") != version:
        raise ValueError("invalid_web_tool_observation")
    if tool_id == CURL_TOOL_ID:
        if set(value) != {"parser_version", "kind", "headers"} or value["kind"] != "curl_https":
            raise ValueError("invalid_web_tool_observation")
        return {"parser_version": version, "kind": "curl_https", "headers": validate_headers(value["headers"])}
    if (set(value) != {"parser_version", "kind", "coverage", "baseline", "responses"}
            or value["kind"] != "ffuf_content" or value["coverage"] != "complete"
            or value["baseline"] not in ("not_found", "wildcard_or_unexpected")
            or type(value["responses"]) is not list or len(value["responses"]) != len(PATHS)):
        raise ValueError("invalid_web_tool_observation")
    rows = []
    for path, row in zip(PATHS, value["responses"]):
        if (type(row) is not dict or set(row) != {"path", "status_code", "bytes"}
                or row["path"] != path or not _integer(row["status_code"], 200, 599)
                or not _integer(row["bytes"], 0, 65536)):
            raise ValueError("invalid_web_tool_observation")
        rows.append(dict(row))
    baseline = "not_found" if rows[-1]["status_code"] == 404 else "wildcard_or_unexpected"
    if value["baseline"] != baseline:
        raise ValueError("invalid_web_tool_baseline")
    return {"parser_version": version, "kind": "ffuf_content", "coverage": "complete",
            "baseline": baseline, "responses": rows}


def _ffuf_row(row):
    if type(row) is not dict or set(row) != _FFUF_FIELDS:
        raise ValueError("invalid_ffuf_row")
    position = row["position"]
    if not _integer(position, 1, len(WORDS)):
        raise ValueError("invalid_ffuf_position")
    word, path = WORDS[position - 1], PATHS[position - 1]
    if (row["input"] != {"FUZZ": base64.b64encode(word.encode("ascii")).decode("ascii"),
                         "FFUFHASH": base64.b64encode(str(position).encode("ascii")).decode("ascii")}
            or row["url"] != "http://127.0.0.1:8080" + path
            or row["host"] != "127.0.0.1:8080"
            or not _integer(row["status"], 200, 599) or not _integer(row["length"], 0, 65536)
            or not _integer(row["words"], 0, 65536) or not _integer(row["lines"], 0, 65536)
            or not _integer(row["duration"], 0, 10_000_000_000)
            or row["scraper"] != {} or row["resultfile"] != ""):
        raise ValueError("invalid_ffuf_row")
    for key in ("content-type", "redirectlocation"):
        if (type(row[key]) is not str or len(row[key]) > 1024
                or any(ord(char) < 32 or ord(char) == 127 for char in row[key])):
            raise ValueError("invalid_ffuf_row")
    return {"path": path, "status_code": row["status"], "bytes": row["length"]}


def parse_tool_output(tool_id, raw: bytes, *, truncated=False):
    """Require full bounded wire framing or exactly eight complete JSON rows."""
    version = parser_version(tool_id)
    if (type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT_BYTES
            or type(truncated) is not bool or truncated):
        raise ValueError("invalid_web_tool_output_size")
    if tool_id == CURL_TOOL_ID:
        return validate_result(tool_id, {"parser_version": version, "kind": "curl_https",
            "headers": _parse_bounded_http_headers(raw, maximum=MAX_OUTPUT_BYTES)})
    if not raw.endswith(b"\n"):
        raise ValueError("incomplete_ffuf_output")
    lines = raw.splitlines()
    if len(lines) != len(WORDS):
        raise ValueError("incomplete_ffuf_coverage")
    rows = {}
    try:
        for line in lines:
            if not line or len(line) > 2048:
                raise ValueError("invalid_ffuf_row_size")
            row = _ffuf_row(json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_ffuf_constant"))))
            if row["path"] in rows:
                raise ValueError("duplicate_ffuf_path")
            rows[row["path"]] = row
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, KeyError):
        raise ValueError("invalid_ffuf_output") from None
    ordered = [rows[path] for path in PATHS]
    return validate_result(tool_id, {"parser_version": version, "kind": "ffuf_content", "coverage": "complete",
        "baseline": "not_found" if ordered[-1]["status_code"] == 404 else "wildcard_or_unexpected",
        "responses": ordered})


parse_web_tool_output = parse_tool_output
