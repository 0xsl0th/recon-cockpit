"""Pure, bounded reconciliation for the unregistered T04 native diagnostic.

These observations confer no authority and are not production evidence. The
owner ledger corroborates complete client output; it never fills missing rows.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

from .web_hierarchy_spec import (
    CONTROL_NAMES, MAX_OUTPUT_BYTES, MAX_OWNER_MESSAGE, MAX_REQUEST_BYTES,
    MAX_WIRE_BYTES, PARSER_VERSION, PATHS, PREFIXES, RESOURCE_NAMES, WORDS,
)

_FIELDS = {"input", "position", "status", "length", "words", "lines", "content-type",
           "redirectlocation", "scraper", "duration", "resultfile", "url", "host"}
_HOST = "127.0.0.1:8080"
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _text(value, maximum):
    return (type(value) is str and len(value) <= maximum
            and all(32 <= ord(char) <= 126 for char in value))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_client_json_key")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("invalid_client_constant")


def _client_row(value):
    if type(value) is not dict or set(value) != _FIELDS:
        raise ValueError("invalid_client_row")
    position = value["position"]
    if not _integer(position, 1, len(WORDS)):
        raise ValueError("invalid_client_position")
    word, path = WORDS[position - 1], PATHS[position - 1]
    if (value["input"] != {
            "FUZZ": base64.b64encode(word.encode("ascii")).decode("ascii"),
            "FFUFHASH": base64.b64encode(format(position, "x").encode("ascii")).decode("ascii")}
            or value["url"] != "http://" + _HOST + path or value["host"] != _HOST
            or not _integer(value["status"], 200, 599)
            or not _integer(value["length"], 0, MAX_WIRE_BYTES)
            or not _integer(value["words"], 0, MAX_WIRE_BYTES)
            or not _integer(value["lines"], 0, MAX_WIRE_BYTES)
            or not _integer(value["duration"], 0, 10_000_000_000)
            or type(value["scraper"]) is not dict or value["scraper"]
            or value["resultfile"] != ""
            or not _text(value["content-type"], 1024)
            or not _text(value["redirectlocation"], 1024)):
        raise ValueError("invalid_client_row")
    return {"path": path, "status_code": value["status"], "bytes": value["length"]}


def parse_client_output(raw, *, truncated=False):
    """Require all twelve unique complete JSON rows, in any emission order."""
    if (type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT_BYTES
            or type(truncated) is not bool or truncated):
        raise ValueError("invalid_client_output_size")
    if not raw.endswith(b"\n"):
        raise ValueError("incomplete_client_output")
    lines = raw.split(b"\n")[:-1]
    if len(lines) != len(PATHS):
        raise ValueError("incomplete_client_coverage")
    rows = {}
    try:
        for line in lines:
            if not line or len(line) > 2048:
                raise ValueError("invalid_client_row_size")
            row = _client_row(json.loads(line.decode("utf-8"), object_pairs_hook=_unique,
                                         parse_constant=_constant))
            if row["path"] in rows:
                raise ValueError("duplicate_client_path")
            rows[row["path"]] = row
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, KeyError):
        raise ValueError("invalid_client_output") from None
    return [rows[path] for path in PATHS]


def _decode(value, maximum):
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError("invalid_owner_wire")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid_owner_wire") from None
    if (not raw or len(raw) > maximum
            or base64.b64encode(raw).decode("ascii") != value):
        raise ValueError("invalid_owner_wire")
    return raw


def _headers(raw):
    if b"\r\n\r\n" not in raw:
        raise ValueError("invalid_owner_framing")
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    headers = {}
    if not lines[0] or any(byte < 32 or byte > 126 for byte in lines[0]):
        raise ValueError("invalid_owner_framing")
    for line in lines[1:]:
        if b":" not in line or any(byte < 32 or byte > 126 for byte in line):
            raise ValueError("invalid_owner_framing")
        key, value = line.split(b":", 1)
        key = key.lower()
        if not _HEADER_NAME.fullmatch(key) or key in headers:
            raise ValueError("invalid_owner_framing")
        headers[key] = value.strip(b" ")
    if b"transfer-encoding" in headers:
        raise ValueError("invalid_owner_framing")
    return lines[0], headers, body


def _request(raw, path):
    first, headers, body = _headers(raw)
    if (first != ("GET " + path + " HTTP/1.1").encode("ascii") or body
            or headers.get(b"host") != _HOST.encode("ascii")
            or any(name in headers for name in (b"content-length", b"transfer-encoding",
                    b"authorization", b"proxy-authorization", b"cookie"))):
        raise ValueError("invalid_owner_request")


def _response(raw):
    first, headers, body = _headers(raw)
    match = re.fullmatch(rb"HTTP/1\.1 ([2-5][0-9]{2}) [\x20-\x7e]+", first)
    length = headers.get(b"content-length", b"")
    if (match is None or not re.fullmatch(rb"0|[1-9][0-9]{0,3}", length)
            or int(length) != len(body)):
        raise ValueError("invalid_owner_response")
    return int(match[1]), len(body)


def _reconcile(rows, owner):
    try:
        serialized = json.dumps(owner, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise ValueError("invalid_owner_evidence") from None
    if (len(serialized.encode("utf-8")) > MAX_OWNER_MESSAGE or type(owner) is not dict
            or set(owner) != {"connection_count", "request_count", "diagnostic"}
            or type(owner["connection_count"]) is not int or owner["connection_count"] != len(PATHS)
            or type(owner["request_count"]) is not int or owner["request_count"] != len(PATHS)):
        raise ValueError("invalid_owner_accounting")
    data = owner["diagnostic"]
    if (type(data) is not dict
            or set(data) != {"case", "ledger", "max_active_requests", "errors"}
            or not _text(data["case"], 64) or not data["case"]
            or type(data["max_active_requests"]) is not int or data["max_active_requests"] != 1
            or type(data["errors"]) is not list or data["errors"]
            or type(data["ledger"]) is not list or len(data["ledger"]) != len(PATHS)):
        raise ValueError("invalid_owner_accounting")
    by_path = {row["path"]: row for row in rows}
    seen = set()
    for item in data["ledger"]:
        if (type(item) is not dict or set(item) != {"raw_request_base64", "response_base64",
                "method", "path", "status_code", "completed"}
                or item["method"] != "GET" or type(item["path"]) is not str
                or item["path"] not in by_path or item["path"] in seen
                or type(item["status_code"]) is not int or item["completed"] is not True):
            raise ValueError("invalid_owner_ledger")
        path = item["path"]
        _request(_decode(item["raw_request_base64"], MAX_REQUEST_BYTES), path)
        status, length = _response(_decode(item["response_base64"], MAX_WIRE_BYTES))
        if (status != item["status_code"] or status != by_path[path]["status_code"]
                or length != by_path[path]["bytes"]):
            raise ValueError("owner_client_mismatch")
        seen.add(path)


def _conclusions(rows):
    by_path = {row["path"]: row for row in rows}
    prefixes, classified = [], {}
    for prefix in PREFIXES:
        controls = [by_path[prefix + name]["status_code"] for name in CONTROL_NAMES]
        baseline_ok = controls == [404, 404]
        observations, ambiguous = [], not baseline_ok
        for name in CONTROL_NAMES:
            row = by_path[prefix + name]
            classified[row["path"]] = {**row, "classification": "control"}
        for name in RESOURCE_NAMES:
            row = by_path[prefix + name]
            code = row["status_code"]
            if not baseline_ok:
                classification = "ambiguous"
            elif 200 <= code <= 299:
                classification = "positive_response"
            elif code in (401, 403):
                classification = "restricted_response"
            elif code == 404:
                classification = "not_found"
            elif 300 <= code <= 399:
                classification, ambiguous = "redirect", True
            else:
                classification, ambiguous = "ambiguous", True
            if classification in ("positive_response", "restricted_response"):
                observations.append(row["path"])
            classified[row["path"]] = {**row, "classification": classification}
        prefixes.append({"prefix": prefix, "control_statuses": controls,
            "baseline": "not_found" if baseline_ok else "ambiguous",
            "outcome": "ambiguous" if ambiguous else "observed_responses" if observations else "empty",
            "observed_paths": observations})
    ambiguous = any(row["outcome"] == "ambiguous" for row in prefixes)
    observed = any(row["observed_paths"] for row in prefixes)
    outcome = "ambiguous" if ambiguous else "observed_responses" if observed else "empty"
    return [classified[path] for path in PATHS], prefixes, outcome


def assess(raw, owner_snapshot, *, exit_code, stop_reason, truncated=False):
    """Return facts or explicit inconclusive/ambiguity, never an execution grant."""
    if ((exit_code is not None and not _integer(exit_code, -255, 255))
            or (stop_reason is not None and (not _text(stop_reason, 64) or not stop_reason))
            or type(truncated) is not bool):
        raise ValueError("invalid_execution_metadata")
    result = {"parser_version": PARSER_VERSION, "kind": "web_hierarchy_diagnostic",
        "production_evidence": False, "useful_completion": False, "outcome": "inconclusive",
        "reason": "execution_incomplete", "rows": [], "prefixes": [],
        "execution": {"exit_code": exit_code, "stop_reason": stop_reason, "truncated": truncated}}
    if exit_code != 0 or stop_reason is not None or truncated:
        return result
    try:
        rows = parse_client_output(raw)
        _reconcile(rows, owner_snapshot)
    except ValueError as error:
        result["reason"] = str(error)
        return result
    rows, prefixes, outcome = _conclusions(rows)
    return {**result, "rows": rows, "prefixes": prefixes, "outcome": outcome,
        "useful_completion": outcome != "ambiguous",
        "reason": "ambiguous_responses" if outcome == "ambiguous" else "complete_finite_universe"}
