"""Bounded HTTP OPTIONS advertisements; no authentication or method authority."""

import re


TOOL_ID = "curl_http_options_v1"
PARSER_VERSION = "curl-http-options-v1"
SEMANTICS = "untrusted_http_options_metadata"
MAX_OUTPUT_BYTES = 8192
MAX_HEADER_BYTES = 4096
MAX_BODY_BYTES = 4096
MAX_HEADER_FIELDS = 32
MAX_METHODS = 16
MAX_TOKEN_BYTES = 32
MAX_AUTH_SCHEMES = 8
MAX_AUTH_CHALLENGES = 16
MAX_AUTH_PARAMETERS = 16
MAX_AUTH_VALUE_BYTES = 512
MAX_LIST_ITEMS = 64
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_TOKEN68 = re.compile(r"[A-Za-z0-9._~+/-]+=*")
_STATUS = re.compile(r"HTTP/1\.1 (200|204|401|405) [ -~]{0,128}")
_LENGTH = re.compile(r"0|[1-9][0-9]{0,3}")
_FORBIDDEN_HEADERS = frozenset({"transfer-encoding", "content-encoding", "trailer",
    "upgrade", "proxy-authenticate", "proxy-connection"})


def _bounded_token(value, maximum=MAX_TOKEN_BYTES):
    return type(value) is str and 1 <= len(value) <= maximum and _TOKEN.fullmatch(value) is not None


def validate_result(value):
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics",
            "status_code", "allow_present", "allowed_methods", "auth_schemes", "service_identity_verified"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "http_options_metadata"
            or value["semantics"] != SEMANTICS or type(value["status_code"]) is not int
            or value["status_code"] not in (200, 204, 401, 405)
            or type(value["allow_present"]) is not bool or value["service_identity_verified"] is not False):
        raise ValueError("invalid_http_options_observation")
    methods, schemes = value["allowed_methods"], value["auth_schemes"]
    if (type(methods) is not list or len(methods) > MAX_METHODS
            or any(not _bounded_token(item) for item in methods)
            or methods != sorted(set(methods))
            or type(schemes) is not list or len(schemes) > MAX_AUTH_SCHEMES
            or any(not _bounded_token(item) or item != item.lower() for item in schemes)
            or schemes != sorted(set(schemes))
            or (not value["allow_present"] and methods)
            or (value["status_code"] == 405 and not value["allow_present"])
            or (value["status_code"] == 401 and not schemes)):
        raise ValueError("invalid_http_options_advertisements")
    return {**value, "allowed_methods": list(methods), "auth_schemes": list(schemes)}


def _methods(values):
    # RFC 9110 Allow is a list field. Repeated fields combine; method case matters.
    items = ",".join(values).split(",")
    if len(items) > MAX_LIST_ITEMS:
        raise ValueError("http_options_allow_limit")
    methods = set()
    for item in items:
        item = item.strip(" \t")
        if not item:  # Bounded empty list members carry no method advertisement.
            continue
        if not _bounded_token(item):
            raise ValueError("invalid_http_options_method")
        methods.add(item)
    if len(methods) > MAX_METHODS:
        raise ValueError("http_options_allow_limit")
    return sorted(methods)


def _ows(text, cursor):
    while cursor < len(text) and text[cursor] in " \t":
        cursor += 1
    return cursor


def _token_at(text, cursor, maximum):
    match = _TOKEN.match(text, cursor)
    if match is None or len(match[0]) > maximum:
        raise ValueError("invalid_http_options_auth_token")
    return match[0], match.end()


def _parameter_value(text, cursor):
    if cursor >= len(text):
        raise ValueError("missing_http_options_auth_value")
    if text[cursor] != '"':
        _, cursor = _token_at(text, cursor, MAX_AUTH_VALUE_BYTES)
        return cursor
    cursor += 1
    size = 0
    while cursor < len(text):
        char = text[cursor]
        cursor += 1
        if char == '"':
            return cursor
        if char == "\\":
            if cursor >= len(text):
                raise ValueError("incomplete_http_options_auth_escape")
            cursor += 1  # Global header checks constrain quoted-pair to ASCII/HTAB.
        size += 1
        if size > MAX_AUTH_VALUE_BYTES:
            raise ValueError("http_options_auth_value_limit")
    raise ValueError("incomplete_http_options_auth_quote")


def _auth_schemes(values):
    # Parse the whole field within a bounded RFC 9110 grammar subset; no scheme semantics.
    # In particular, a quoted comma cannot introduce a new authentication scheme.
    text = ",".join(values)
    if len(text) > 2048:
        raise ValueError("http_options_auth_limit")
    schemes, cursor, challenges, commas = set(), 0, 0, 0

    def separator(position):
        nonlocal commas
        position = _ows(text, position)
        while position < len(text) and text[position] == ",":
            commas += 1
            if commas > MAX_LIST_ITEMS:
                raise ValueError("http_options_auth_list_limit")
            position = _ows(text, position + 1)
        return position

    cursor = separator(cursor)
    while cursor < len(text):
        scheme, cursor = _token_at(text, cursor, MAX_TOKEN_BYTES)
        schemes.add(scheme.lower())
        challenges += 1
        if challenges > MAX_AUTH_CHALLENGES or len(schemes) > MAX_AUTH_SCHEMES:
            raise ValueError("http_options_auth_limit")
        end = _ows(text, cursor)
        if end == len(text) or text[end] == ",":
            cursor = separator(end)
            continue
        # challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
        if text[cursor] != " ":
            raise ValueError("invalid_http_options_auth_separator")
        while cursor < len(text) and text[cursor] == " ":
            cursor += 1
        if cursor == len(text) or text[cursor] == ",":
            cursor = separator(cursor)
            continue
        token68 = _TOKEN68.match(text, cursor)
        if token68 is not None:
            end = _ows(text, token68.end())
            if end == len(text) or text[end] == ",":
                if len(token68[0]) > MAX_AUTH_VALUE_BYTES:
                    raise ValueError("http_options_auth_value_limit")
                cursor = separator(end)
                continue
        parameters = set()
        while cursor < len(text):
            name, cursor = _token_at(text, cursor, 64)
            name = name.lower()
            if name in parameters or len(parameters) >= MAX_AUTH_PARAMETERS:
                raise ValueError("duplicate_or_excess_http_options_auth_parameter")
            parameters.add(name)
            cursor = _ows(text, cursor)
            if cursor == len(text) or text[cursor] != "=":
                raise ValueError("invalid_http_options_auth_parameter")
            cursor = _parameter_value(text, _ows(text, cursor + 1))
            cursor = _ows(text, cursor)
            if cursor == len(text):
                break
            if text[cursor] != ",":
                raise ValueError("invalid_http_options_auth_parameter_separator")
            cursor = separator(cursor)
            if cursor == len(text):
                break
            _, end = _token_at(text, cursor, 64)
            end = _ows(text, end)
            if end == len(text) or text[end] != "=":
                break  # Next list element is a challenge, not an auth-param.
    return sorted(schemes)


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or stderr or not raw
            or len(raw) > MAX_OUTPUT_BYTES):
        raise ValueError("invalid_http_options_output")
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator or len(head) > MAX_HEADER_BYTES or len(body) > MAX_BODY_BYTES:
        raise ValueError("incomplete_or_excess_http_options_response")
    try:
        lines = head.decode("ascii").split("\r\n")
    except UnicodeDecodeError:
        raise ValueError("unsupported_http_options_headers") from None
    if (not 1 <= len(lines) <= MAX_HEADER_FIELDS + 1
            or any(len(line) > 1024 or any(ord(char) < 32 and char != "\t" or ord(char) == 127
                for char in line) for line in lines)):
        raise ValueError("invalid_http_options_headers")
    status = _STATUS.fullmatch(lines[0])
    if status is None:
        raise ValueError("unsupported_http_options_status")
    status = int(status[1])
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not _bounded_token(name, 64):
            raise ValueError("invalid_http_options_field")
        name, value = name.lower(), value.strip(" \t")
        if name in _FORBIDDEN_HEADERS or (name in headers and name not in {"allow", "www-authenticate"}):
            raise ValueError("unsupported_or_duplicate_http_options_field")
        headers.setdefault(name, []).append(value)
    if "connection" in headers and headers["connection"][0].lower() != "close":
        raise ValueError("unsupported_http_options_connection")
    if status == 204:
        if "content-length" in headers or body:
            raise ValueError("invalid_http_options_no_content")
    else:
        length = headers.get("content-length", [""])[0]
        if _LENGTH.fullmatch(length) is None or int(length) != len(body):
            raise ValueError("incomplete_http_options_body")
    return validate_result({"parser_version": PARSER_VERSION, "kind": "http_options_metadata",
        "semantics": SEMANTICS, "status_code": status, "allow_present": "allow" in headers,
        "allowed_methods": _methods(headers.get("allow", [])),
        "auth_schemes": _auth_schemes(headers.get("www-authenticate", [])),
        "service_identity_verified": False})
