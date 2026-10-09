"""Bounded Git HEAD marker observations from owned Nuclei JSONL captures.

Independent owner bytes must agree with the native HTTP dump before this
parser reports its finite marker predicate. A marker is not a vulnerability
claim, and neither a returned reference nor response content leaves the parser.
"""

import hashlib
import re

if __package__:
    from . import network_tools_nuclei_parser as _common
else:
    import network_tools_nuclei_parser as _common

MAX_BODY_BYTES = _common.MAX_BODY_BYTES
MAX_HEADER_BYTES = _common.MAX_HEADER_BYTES
MAX_OUTPUT_BYTES = _common.MAX_OUTPUT_BYTES
MAX_RESPONSE_BYTES = _common.MAX_RESPONSE_BYTES
SEMANTICS = _common.SEMANTICS
_digest = _common._digest
_json_object = _common._json_object
_timestamp = _common._timestamp


TOOL_ID = "nuclei_git_head_v1"
PARSER_VERSION = "nuclei-git-head-v1"
TEMPLATE_ID = "recon-owned-git-head-v1"
MATCHER_NAME = "git-head-signature"
REQUEST = {"method": "GET", "url": "http://127.0.0.1:8080/.git/HEAD"}
_REQUEST_DUMP = ("GET /.git/HEAD HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
    "User-Agent: recon-cockpit-owned-nuclei/1\r\nAccept: */*\r\n"
    "Accept-Encoding: identity\r\nAccept-Language: en\r\nConnection: close\r\n\r\n")
# Inert native display text only. This module never executes a command.
_CURL_DISPLAY = ("curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Encoding: identity' "
    "-H 'Accept-Language: en' -H 'Connection: close' "
    "-H 'User-Agent: recon-cockpit-owned-nuclei/1' 'http://127.0.0.1:8080/.git/HEAD'")
_FIXED_EVENT = {"template": "git-head.yaml", "template-id": TEMPLATE_ID,
    "template-path": "/tool/data/git-head.yaml",
    "info": {"name": "Owned Git HEAD marker", "author": ["recon-cockpit"],
        "tags": None, "severity": "info"},
    "type": "http", "host": "127.0.0.1", "port": "8080", "scheme": "http",
    "url": REQUEST["url"], "path": "/.git/HEAD", "request": _REQUEST_DUMP,
    "ip": "127.0.0.1"}
_FIELDS = frozenset({"connection", "content-length", "content-type"})
_PLAIN_CONTENT_TYPE = b"text/plain; charset=us-ascii"
_CONTENT_TYPES = frozenset({_PLAIN_CONTENT_TYPE, b"text/html; charset=us-ascii"})
_SIGNATURE_BODIES = frozenset({b"ref: refs/heads/main\n", b"ref: refs/heads/release\n"})


def _response(raw):
    """Require one finite complete HTTP representation with an explicit type."""
    if type(raw) is not bytes or not 1 <= len(raw) < MAX_RESPONSE_BYTES:
        raise ValueError("invalid_nuclei_response_size")
    if b"***" in raw:
        raise ValueError("possible_nuclei_response_redaction")
    head, separator, body = raw.partition(b"\r\n\r\n")
    # Equality with a native cap cannot establish that a capture was uncut.
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
    content_type = headers["content-type"]
    if content_type not in _CONTENT_TYPES:
        raise ValueError("unsupported_nuclei_response_content_type")
    length = headers["content-length"]
    if re.fullmatch(rb"0|[1-9][0-9]{0,3}", length) is None or int(length) != len(body):
        raise ValueError("incomplete_nuclei_response_body")
    if any(byte not in (9, 10, 13) and not 32 <= byte <= 126 for byte in body):
        raise ValueError("unsupported_nuclei_response_body")
    return statuses[lines[0]], content_type, body


def _signature(status, content_type, body):
    """Recompute the finite compiled marker predicate without interpreting refs."""
    return (status == 200 and content_type == _PLAIN_CONTENT_TYPE
        and body in _SIGNATURE_BODIES)


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
    """Reconcile status, content type and body against independent owner bytes."""
    owner_status, owner_type, owner_body = _response(owner_response)
    status, content_type, body = _response(response)
    if (status, content_type, body) != (owner_status, owner_type, owner_body):
        raise ValueError("nuclei_owner_response_disagreement")
    if (type(matcher_status) is not bool
            or matcher_status != _signature(status, content_type, body)):
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
    """Parse one native event and independently reconcile original HTTP bytes."""
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
