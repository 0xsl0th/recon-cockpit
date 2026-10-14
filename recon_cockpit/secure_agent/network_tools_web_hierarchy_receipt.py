"""Bounded original owner-management bytes; this codec grants no authority."""

import base64
import binascii
import hashlib
import json

if __package__:
    from .network_tools_web_hierarchy_spec import MAX_OWNER_BYTES, MAX_CONNECTIONS, VARIANTS, case_parts
else:
    import importlib.util
    from pathlib import Path
    _definition = importlib.util.spec_from_file_location("hierarchy_receipt_spec",
        Path(__file__).with_name("network_tools_web_hierarchy_spec.py"))
    _module = importlib.util.module_from_spec(_definition)
    _definition.loader.exec_module(_module)
    MAX_OWNER_BYTES, MAX_CONNECTIONS = _module.MAX_OWNER_BYTES, _module.MAX_CONNECTIONS
    VARIANTS, case_parts = _module.VARIANTS, _module.case_parts

MAX_MANAGEMENT_BYTES = MAX_OWNER_BYTES
MAX_OWNER_BASE64_BYTES = 4 * ((MAX_OWNER_BYTES + 2) // 3)
_ERRORS = frozenset({"duplicate_path", "unexpected_path", "invalid_request", "request_limit",
    "request_read", "empty_connection", "extra_request_bytes", "response_write", "service_failed"})
_ENTRY_FIELDS = frozenset({"raw_request_base64", "response_base64", "method", "path",
                           "status_code", "completed"})


def encode_owner_receipt(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_OWNER_BYTES:
        raise ValueError("invalid_web_hierarchy_owner_size")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_base64": base64.b64encode(raw).decode("ascii")}


def decode_owner_receipt(value):
    if (type(value) is not dict or set(value) != {"bytes", "sha256", "raw_base64"}
            or type(value["bytes"]) is not int or not 1 <= value["bytes"] <= MAX_OWNER_BYTES
            or type(value["sha256"]) is not str or type(value["raw_base64"]) is not str
            or len(value["raw_base64"]) > MAX_OWNER_BASE64_BYTES):
        raise ValueError("invalid_web_hierarchy_owner_receipt")
    try:
        raw = base64.b64decode(value["raw_base64"], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid_web_hierarchy_owner_receipt") from error
    if (len(raw) != value["bytes"] or base64.b64encode(raw).decode("ascii") != value["raw_base64"]
            or hashlib.sha256(raw).hexdigest() != value["sha256"]):
        raise ValueError("invalid_web_hierarchy_owner_receipt")
    return raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_web_hierarchy_owner_key")
        result[key] = value
    return result


def _not_number(value):
    raise ValueError("invalid_web_hierarchy_owner_number")


def _wire(value):
    if type(value) is not str or len(value) > 4 * ((1024 + 2) // 3):
        raise ValueError("invalid_web_hierarchy_owner_wire")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid_web_hierarchy_owner_wire") from error
    if len(raw) > 1024 or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("invalid_web_hierarchy_owner_wire")
    return raw


def parse_owner(raw):
    """Validate envelope/finite ledger only, independently of fixture outcomes."""
    if (type(raw) is not bytes or not 1 <= len(raw) <= MAX_OWNER_BYTES
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1):
        raise ValueError("invalid_web_hierarchy_owner_size")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_not_number,
                           parse_float=_not_number)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid_web_hierarchy_owner_json") from error
    if (type(value) is not dict
            or set(value) != {"sequence", "connection_count", "request_count", "diagnostic"}
            or type(value["sequence"]) is not int or value["sequence"] != 1
            or type(value["connection_count"]) is not int
            or not 0 <= value["connection_count"] <= MAX_CONNECTIONS
            or type(value["request_count"]) is not int
            or not 0 <= value["request_count"] <= value["connection_count"]
            or type(value["diagnostic"]) is not dict):
        raise ValueError("invalid_web_hierarchy_owner_context")
    diagnostic = value["diagnostic"]
    if (set(diagnostic) != {"case", "ledger", "max_active_requests", "errors"}
            or type(diagnostic["case"]) is not str or diagnostic["case"] not in VARIANTS
            or type(diagnostic["ledger"]) is not list
            or len(diagnostic["ledger"]) != value["request_count"]
            or type(diagnostic["max_active_requests"]) is not int
            or not (1 if value["request_count"] else 0) <= diagnostic["max_active_requests"] <= value["request_count"]
            or type(diagnostic["errors"]) is not list or len(diagnostic["errors"]) > len(_ERRORS)
            or any(type(error) is not str or error not in _ERRORS for error in diagnostic["errors"])
            or len(set(diagnostic["errors"])) != len(diagnostic["errors"])):
        raise ValueError("invalid_web_hierarchy_owner_diagnostic")
    for entry in diagnostic["ledger"]:
        if (type(entry) is not dict or set(entry) != _ENTRY_FIELDS
                or type(entry["method"]) is not str or entry["method"] not in {"", "GET"}
                or type(entry["path"]) is not str or len(entry["path"]) > 1024
                or type(entry["status_code"]) is not int
                or not (entry["status_code"] == 0 or 100 <= entry["status_code"] <= 599)
                or type(entry["completed"]) is not bool):
            raise ValueError("invalid_web_hierarchy_owner_ledger")
        request, response = _wire(entry["raw_request_base64"]), _wire(entry["response_base64"])
        if not request or (entry["completed"] and not response):
            raise ValueError("invalid_web_hierarchy_owner_ledger")
    return value


def receipt_counter_context(raw):
    value = parse_owner(raw)
    return {key: value[key] for key in ("connection_count", "request_count")}


def validate_owner_selection(raw, case):
    variant = case_parts(case)
    value = parse_owner(raw)
    if value["diagnostic"]["case"] != variant:
        raise ValueError("web_hierarchy_owner_selection_mismatch")
    return value
