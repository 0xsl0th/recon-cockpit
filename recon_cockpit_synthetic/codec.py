"""Bounded intrinsic result codec, with no I/O or runtime authorization.

Callers must independently establish trusted subject identity, actual progress,
current authority, cancellation/expiry and cleanup before using a result.
Rejections expose fixed codes only; callers must not log input or traceback locals.
"""

import json
import re

import recon_cockpit_synthetic.contract as contract


class ResultCodecError(ValueError):
    """A fixed intrinsic rejection code, never input or parser diagnostics."""


def _expected_subject(value):
    if type(value) is not str:
        raise ResultCodecError('invalid_shape')
    if len(value) != 36 or re.fullmatch(contract.UUID4_PATTERN, value) is None:
        raise ResultCodecError('invalid_value')


def _record(value):
    if type(value) is not dict or len(value) != 6:
        raise ResultCodecError('invalid_shape')
    for key in value:
        if type(key) is not str or len(key) > 18 or key not in contract.RESULT_FIELDS:
            raise ResultCodecError('invalid_shape')
    # Six distinct allowed built-in string keys imply exact field membership.
    for key, item in value.items():
        if key == 'http_status':
            if item is not None and type(item) is not int:
                raise ResultCodecError('invalid_value')
        elif item is None and key in ('service_identifier', 'service_status'):
            continue
        elif type(item) is not str or len(item) > 36:
            raise ResultCodecError('invalid_value')
    if value['schema_version'] != '1':
        raise ResultCodecError('invalid_value')
    if re.fullmatch(contract.UUID4_PATTERN, value['operation_id']) is None:
        raise ResultCodecError('invalid_value')
    if value['outcome'] not in tuple(row[0] for row in contract.RESULT_RELATIONS):
        raise ResultCodecError('invalid_value')
    if value['service_identifier'] not in (None, 'recon-owned-status-v1'):
        raise ResultCodecError('invalid_value')
    if value['service_status'] not in (None, 'ready', 'degraded'):
        raise ResultCodecError('invalid_value')
    if value['http_status'] not in (None, 200, 401, 403):
        raise ResultCodecError('invalid_value')
    relation = tuple(value[k] for k in ('outcome', 'service_identifier', 'service_status', 'http_status'))
    if relation not in contract.RESULT_RELATIONS:
        raise ResultCodecError('invalid_result')
    return dict(value)


def _canonical(record):
    return json.dumps(record, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _depth(text):
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > contract.RESULT_MAX_DEPTH:
                raise ResultCodecError('invalid_encoding')
        elif char in ']}':
            depth -= 1
            if depth < 0:
                raise ResultCodecError('invalid_encoding')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ResultCodecError('invalid_shape')
        result[key] = value
    return result


def _reject_number(_value):
    raise ResultCodecError('invalid_value')


def decode_public_result(frame: bytes, expected_operation_id: str) -> dict:
    """Validate bounded canonical bytes and intrinsic subject equality only."""
    _expected_subject(expected_operation_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RESULT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text)
    # Raise outside the handler so raw JSONDecodeError details are not chained.
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if record['operation_id'] != expected_operation_id:
        raise ResultCodecError('wrong_subject')
    return record


def encode_public_result(record: dict, expected_operation_id: str) -> bytes:
    """Encode an exact built-in record; this grants no authority to publish it."""
    _expected_subject(expected_operation_id)
    validated = _record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RESULT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if validated['operation_id'] != expected_operation_id:
        raise ResultCodecError('wrong_subject')
    return encoded
