"""Bounded bytes and commitment for an owned TLS peer/mediator receipt.

This codec does not infer a successful TLS observation or grant authority.
"""

import base64
import binascii
import hashlib
import json

if __package__:
    from .network_tools_tls_posture_spec import MAX_OWNER_BYTES, case_parts
else:
    # Standalone owner has the same reviewed source mounted beside this module.
    import importlib.util
    from pathlib import Path
    _spec = importlib.util.spec_from_file_location("tls_posture_receipt_spec",
        Path(__file__).with_name("network_tools_tls_posture_spec.py"))
    _module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_module)
    MAX_OWNER_BYTES = _module.MAX_OWNER_BYTES
    case_parts = _module.case_parts

MAX_OWNER_BASE64_BYTES = 4 * ((MAX_OWNER_BYTES + 2) // 3)
MAX_MANAGEMENT_BYTES = MAX_OWNER_BASE64_BYTES + 2048


def encode_owner_receipt(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_OWNER_BYTES:
        raise ValueError("invalid_tls_posture_owner_size")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_base64": base64.b64encode(raw).decode("ascii")}


def decode_owner_receipt(value):
    if (type(value) is not dict or set(value) != {"bytes", "sha256", "raw_base64"}
            or type(value["bytes"]) is not int or not 1 <= value["bytes"] <= MAX_OWNER_BYTES
            or type(value["sha256"]) is not str or type(value["raw_base64"]) is not str
            or len(value["raw_base64"]) > MAX_OWNER_BASE64_BYTES):
        raise ValueError("invalid_tls_posture_owner_receipt")
    try:
        raw = base64.b64decode(value["raw_base64"], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid_tls_posture_owner_receipt") from error
    if (len(raw) != value["bytes"] or base64.b64encode(raw).decode("ascii") != value["raw_base64"]
            or hashlib.sha256(raw).hexdigest() != value["sha256"]):
        raise ValueError("invalid_tls_posture_owner_receipt")
    return raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_tls_posture_owner_key")
        result[key] = value
    return result


def _not_number(value):
    raise ValueError("invalid_tls_posture_owner_number")


def _owner_envelope(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_OWNER_BYTES:
        raise ValueError("invalid_tls_posture_owner_size")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_not_number,
                           parse_float=_not_number)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid_tls_posture_owner_json") from error
    if (type(value) is not dict
            or set(value) != {"connection_count", "request_count", "diagnostic", "mediation"}
            or type(value["connection_count"]) is not int or not 0 <= value["connection_count"] <= 2
            or type(value["request_count"]) is not int or not 0 <= value["request_count"] <= 1
            or value["request_count"] > value["connection_count"]
            or type(value["diagnostic"]) is not dict or type(value["mediation"]) is not dict):
        raise ValueError("invalid_tls_posture_owner_context")
    return value


def receipt_counter_context(raw):
    value = _owner_envelope(raw)
    return {key: value[key] for key in ("connection_count", "request_count")}


def validate_owner_selection(raw, case):
    """Bind captured peer selection to the trusted authority's fixture identity."""
    version, variant = case_parts(case)
    value = _owner_envelope(raw)
    peer = value["diagnostic"]
    if peer.get("case") != variant or peer.get("expected_version") != version:
        raise ValueError("tls_posture_owner_selection_mismatch")
    return value
