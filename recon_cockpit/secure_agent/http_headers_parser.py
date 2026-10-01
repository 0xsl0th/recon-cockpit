"""Bounded HTTP/1.x response facts for the fixed owned HTML request.

This intentionally supports a strict subset of RFC 9112 sections 2, 5 and 6:
one final response, CRLF fields and exactly one decimal Content-Length. It
never decodes a body, follows a redirect or returns an untrusted field value.
Unsupported or ambiguous representations are inconclusive, not findings.
"""

from __future__ import annotations

import re


PARSER_VERSION = "http-headers-v1"
MAX_RESPONSE_BYTES = 2048
MAX_FIELDS = 32
MAX_LINE_BYTES = 1024
_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_FIELD_NAME = re.compile(_TOKEN)
_MEDIA_TYPE = re.compile(_TOKEN + rb"/" + _TOKEN)
_PARAMETER = re.compile(
    rb"[ \t]*;[ \t]*(" + _TOKEN + rb")=(?:" + _TOKEN
    + rb'|"(?:[\t\x20\x21\x23-\x5b\x5d-\xff]|\\[\t\x20-\x7e\x80-\xff])*")'
)
_CRITICAL = frozenset({
    b"content-length", b"content-type", b"content-security-policy",
    b"x-frame-options", b"x-content-type-options", b"connection",
    b"transfer-encoding", b"content-encoding", b"trailer", b"upgrade",
})
_FIELDS = frozenset({
    "parser_version", "status_code", "content_type", "csp",
    "x_frame_options", "x_content_type_options",
})


def validate_result(value: object) -> dict:
    """Validate the complete finite schema released by the isolated parser."""
    if (type(value) is not dict or set(value) != _FIELDS
            or type(value["parser_version"]) is not str or value["parser_version"] != PARSER_VERSION
            or type(value["status_code"]) is not int
            or not 200 <= value["status_code"] <= 599 or value["status_code"] in {204, 304}):
        raise ValueError("invalid_http_headers_result")
    for key, allowed in (
        ("content_type", {"text/html", "other", "absent"}),
        ("csp", {"present", "absent"}),
        ("x_frame_options", {"deny", "sameorigin", "absent", "invalid"}),
        ("x_content_type_options", {"nosniff", "absent", "invalid"}),
    ):
        if type(value[key]) is not str or value[key] not in allowed:
            raise ValueError("invalid_http_headers_result")
    return {key: value[key] for key in (
        "parser_version", "status_code", "content_type", "csp",
        "x_frame_options", "x_content_type_options",
    )}


def _content_type(value: bytes | None) -> str:
    if value is None:
        return "absent"
    match = _MEDIA_TYPE.match(value)
    if match is None:
        raise ValueError("invalid_http_headers_content_type")
    position = match.end()
    parameters = set()
    while position < len(value):
        parameter = _PARAMETER.match(value, position)
        if parameter is None or parameter.group(1).lower() in parameters:
            raise ValueError("invalid_http_headers_content_type")
        parameters.add(parameter.group(1).lower())
        position = parameter.end()
    return "text/html" if match.group().lower() == b"text/html" else "other"


def parse_http_headers(raw: bytes, *, truncated: bool = False) -> dict:
    """Parse only a fully captured, bounded response; failures never echo input.

    Duplicated critical fields are refused even when equal. Transfer/content
    encodings and close-delimited responses are outside this capability.
    CSP is a presence observation only; its policy strength is not evaluated.
    """
    if (type(raw) is not bytes or not raw or len(raw) > MAX_RESPONSE_BYTES
            or type(truncated) is not bool or truncated):
        raise ValueError("invalid_http_headers_size")
    header, marker, body = raw.partition(b"\r\n\r\n")
    if not marker:
        raise ValueError("invalid_http_headers_framing")
    lines = header.split(b"\r\n")
    if (len(lines) > MAX_FIELDS + 1 or len(lines[0]) > 128
            or any(len(line) > MAX_LINE_BYTES for line in lines)):
        raise ValueError("invalid_http_headers_framing")
    status = re.fullmatch(rb"HTTP/1\.[01] ([2-5][0-9]{2}) [\t\x20-\x7e\x80-\xff]*", lines[0])
    if status is None or int(status.group(1)) in {204, 304}:
        raise ValueError("unsupported_http_headers_status")
    fields = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if (not separator or _FIELD_NAME.fullmatch(name) is None
                or any(byte < 32 and byte != 9 or byte == 127 for byte in value)):
            raise ValueError("invalid_http_headers_field")
        name = name.lower()
        if name in _CRITICAL:
            if name in fields:
                raise ValueError("duplicate_http_headers_field")
            fields[name] = value.strip(b" \t")
    if any(name in fields for name in (b"transfer-encoding", b"content-encoding", b"trailer", b"upgrade")):
        raise ValueError("unsupported_http_headers_encoding")
    connection = fields.get(b"connection")
    if connection is not None:
        options = [item.strip(b" \t").lower() for item in connection.split(b",")]
        if any(item not in {b"close", b"keep-alive"} for item in options) or len(set(options)) != len(options):
            raise ValueError("unsupported_http_headers_connection")
    length = fields.get(b"content-length", b"")
    if re.fullmatch(rb"[0-9]{1,4}", length) is None or int(length) != len(body):
        raise ValueError("invalid_http_headers_length")
    xfo = fields.get(b"x-frame-options")
    xcto = fields.get(b"x-content-type-options")
    return validate_result({
        "parser_version": PARSER_VERSION,
        "status_code": int(status.group(1)),
        "content_type": _content_type(fields.get(b"content-type")),
        "csp": "present" if fields.get(b"content-security-policy") else "absent",
        "x_frame_options": ("absent" if xfo is None else
                            {b"deny": "deny", b"sameorigin": "sameorigin"}.get(xfo.lower(), "invalid")),
        "x_content_type_options": ("absent" if xcto is None else
                                  "nosniff" if xcto.lower() == b"nosniff" else "invalid"),
    })
