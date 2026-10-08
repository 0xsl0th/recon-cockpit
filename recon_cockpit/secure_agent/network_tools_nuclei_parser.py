"""Bounded signature observations from reviewed owned Nuclei JSONL captures.

An HTTP dump alone cannot establish the original response framing: independent
owner response bytes must agree before a native observation can be useful.
Execution success, owner counters and authority remain separate evidence gates.
"""

from datetime import datetime
import hashlib
import json
import math
import re


TOOL_ID = "nuclei_directory_listing_v1"
PARSER_VERSION = "nuclei-directory-listing-v1"
TEMPLATE_ID = "recon-owned-directory-listing-v1"
MATCHER_NAME = "directory-listing-signature"
SEMANTICS = "signature_from_bounded_owned_http_response"
REQUEST = {"method": "GET", "url": "http://127.0.0.1:8080/public/"}
_REQUEST_DUMP = ("GET /public/ HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
    "User-Agent: recon-cockpit-owned-nuclei/1\r\nAccept: */*\r\n"
    "Accept-Encoding: identity\r\nAccept-Language: en\r\nConnection: close\r\n\r\n")
# Inert observed display text only. This module never executes a command.
_CURL_DISPLAY = ("curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Encoding: identity' "
    "-H 'Accept-Language: en' -H 'Connection: close' "
    "-H 'User-Agent: recon-cockpit-owned-nuclei/1' 'http://127.0.0.1:8080/public/'")
_FIXED_EVENT = {"template": "directory-listing.yaml", "template-id": TEMPLATE_ID,
    "template-path": "/tool/data/directory-listing.yaml",
    "info": {"name": "Owned directory-listing signature", "author": ["recon-cockpit"],
        "tags": None, "severity": "info"},
    "type": "http", "host": "127.0.0.1", "port": "8080", "scheme": "http",
    "url": REQUEST["url"], "path": "/public/", "request": _REQUEST_DUMP, "ip": "127.0.0.1"}
MAX_OUTPUT_BYTES = 8192
MAX_RESPONSE_BYTES = 4096
MAX_HEADER_BYTES = 1024
MAX_BODY_BYTES = 2048
_FIELDS = frozenset({"connection", "content-length", "content-type"})
_SIGNATURE_PARTS = (
    b"<title>Index of /public/</title>",
    b"<h1>Index of /public/</h1>",
    b'href="../"',
)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_nuclei_json_key")
        value[key] = item
    return value


def _nonfinite_number(value):
    raise ValueError("nonfinite_nuclei_json_number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite_nuclei_json_number")
    return number


def _json_object(raw):
    """Require one bounded JSONL object without claiming a native event schema."""
    if (type(raw) is not bytes or not 1 <= len(raw) <= MAX_OUTPUT_BYTES
            or not raw.startswith(b"{") or not raw.endswith(b"}\n")
            or raw.count(b"\n") != 1 or b"\r" in raw):
        raise ValueError("invalid_nuclei_jsonl_framing")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object,
            parse_constant=_nonfinite_number, parse_float=_finite_float)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("invalid_nuclei_jsonl_object") from None
    if type(value) is not dict:
        raise ValueError("invalid_nuclei_jsonl_object")
    return value


def _response(raw):
    """Check a finite complete HTTP representation, never infer wire fidelity."""
    if type(raw) is not bytes or not 1 <= len(raw) < MAX_RESPONSE_BYTES:
        raise ValueError("invalid_nuclei_response_size")
    if b"***" in raw:
        raise ValueError("possible_nuclei_response_redaction")
    head, separator, body = raw.partition(b"\r\n\r\n")
    # Strictly below either native cap: equality cannot prove an uncut capture.
    if not separator or len(head) > MAX_HEADER_BYTES or len(body) >= MAX_BODY_BYTES:
        raise ValueError("incomplete_or_excess_nuclei_response")
    lines = head.split(b"\r\n")
    statuses = {b"HTTP/1.1 200 OK": 200, b"HTTP/1.1 404 Not Found": 404}
    if lines[0] not in statuses or len(lines) != len(_FIELDS) + 1:
        raise ValueError("unsupported_nuclei_response_headers")
    headers = {}
    for line in lines[1:]:
        if re.fullmatch(rb"[A-Za-z][A-Za-z0-9-]{0,63}: [\x20-\x7e]{1,512}", line) is None:
            raise ValueError("invalid_nuclei_response_field")
        name, value = line.split(b": ", 1)
        name = name.decode("ascii").lower()
        if name not in _FIELDS or name in headers:
            raise ValueError("unsupported_or_duplicate_nuclei_response_field")
        headers[name] = value
    if set(headers) != _FIELDS or headers["connection"] != b"close":
        raise ValueError("unsupported_nuclei_response_connection")
    if headers["content-type"] != b"text/html; charset=us-ascii":
        raise ValueError("unsupported_nuclei_response_content_type")
    length = headers["content-length"]
    if re.fullmatch(rb"0|[1-9][0-9]{0,3}", length) is None or int(length) != len(body):
        raise ValueError("incomplete_nuclei_response_body")
    if any(byte not in (9, 10, 13) and not 32 <= byte <= 126 for byte in body):
        raise ValueError("unsupported_nuclei_response_body")
    return statuses[lines[0]], body


def _signature(status, body):
    """Recompute the single compiled DSL conjunction, without following links."""
    return status == 200 and all(part in body for part in _SIGNATURE_PARTS)


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _timestamp(value):
    # Go RFC3339Nano UTC display; validate calendar fields without reading a clock.
    if (type(value) is not str or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value) is None):
        raise ValueError("invalid_nuclei_timestamp")
    try:
        datetime(int(value[:4]), int(value[5:7]), int(value[8:10]),
            int(value[11:13]), int(value[14:16]), int(value[17:19]))
    except ValueError:
        raise ValueError("invalid_nuclei_timestamp") from None


def validate_result(value):
    fields = {"parser_version", "kind", "semantics", "template_id", "request",
        "status_code", "matcher_status", "outcome", "response_dump_sha256",
        "owner_response_sha256", "response_body_sha256", "vulnerability_verified"}
    if (type(value) is not dict or set(value) != fields
            or value["parser_version"] != PARSER_VERSION
            or value["kind"] != "http_template_signature" or value["semantics"] != SEMANTICS
            or value["template_id"] != TEMPLATE_ID or type(value["request"]) is not dict
            or value["request"] != REQUEST or type(value["status_code"]) is not int
            or value["status_code"] not in (200, 404)
            or type(value["matcher_status"]) is not bool
            or (value["matcher_status"] and value["status_code"] != 200)
            or value["outcome"] != ("signature_present" if value["matcher_status"] else "signature_absent")
            or not _digest(value["response_dump_sha256"])
            or not _digest(value["owner_response_sha256"])
            or not _digest(value["response_body_sha256"])
            or value["vulnerability_verified"] is not False):
        raise ValueError("invalid_nuclei_signature_result")
    return {**value, "request": dict(REQUEST)}


def _summarize(response, matcher_status, *, owner_response):
    """Reconcile retained dumps with independently retained owner response bytes."""
    owner_status, owner_body = _response(owner_response)
    status, body = _response(response)
    if (status, body) != (owner_status, owner_body):
        raise ValueError("nuclei_owner_response_disagreement")
    if type(matcher_status) is not bool or matcher_status != _signature(status, body):
        raise ValueError("nuclei_matcher_disagreement")
    return validate_result({"parser_version": PARSER_VERSION, "kind": "http_template_signature",
        "semantics": SEMANTICS, "template_id": TEMPLATE_ID, "request": dict(REQUEST),
        "status_code": status, "matcher_status": matcher_status,
        "outcome": "signature_present" if matcher_status else "signature_absent",
        "response_dump_sha256": hashlib.sha256(response).hexdigest(),
        "owner_response_sha256": hashlib.sha256(owner_response).hexdigest(),
        "response_body_sha256": hashlib.sha256(body).hexdigest(),
        "vulnerability_verified": False})


def parse_output(stdout, stderr=b"", *, owner_response):
    """Parse one observed event and independently reconcile original HTTP bytes."""
    if (type(stdout) is not bytes or type(stderr) is not bytes or stderr
            or len(stdout) + len(stderr) > MAX_OUTPUT_BYTES):
        raise ValueError("invalid_nuclei_output")
    event = _json_object(stdout)
    matched = event.get("matcher-status")
    if type(matched) is not bool:
        raise ValueError("invalid_nuclei_matcher_status")
    expected = dict(_FIXED_EVENT)
    if matched:
        expected.update({"matcher-name": MATCHER_NAME, "matched-at": REQUEST["url"],
            "curl-command": _CURL_DISPLAY})
    if (set(event) != set(expected) | {"response", "timestamp", "matcher-status"}
            or any(event[key] != value for key, value in expected.items())
            or type(event["response"]) is not str):
        raise ValueError("unsupported_nuclei_native_event")
    _timestamp(event["timestamp"])
    try:
        response = event["response"].encode("ascii")
    except UnicodeError:
        raise ValueError("unsupported_nuclei_response_encoding") from None
    return _summarize(response, matched, owner_response=owner_response)
