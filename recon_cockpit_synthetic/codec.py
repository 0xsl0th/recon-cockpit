"""Bounded intrinsic result codec, with no I/O or runtime authorization.

Callers must independently establish trusted subject identity, actual progress,
current authority, cancellation/expiry and cleanup before using a result.
Rejections expose fixed codes only; callers must not log input or traceback locals.
"""

import datetime
import json
import re

import recon_cockpit_synthetic.contract as contract


class ResultCodecError(ValueError):
    """Fixed public-record rejection; retained name for result API compatibility."""


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


def _depth(text, maximum=contract.RESULT_MAX_DEPTH):
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
            if depth > maximum:
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


def _roe_calendar(value):
    match = re.fullmatch(contract.ROE_UTC_PATTERN, value)
    if match is None:
        raise ResultCodecError('invalid_value')
    valid = None
    try:
        valid = datetime.datetime(*(int(part) for part in match.groups()))
    except ValueError:
        pass
    if valid is None:
        raise ResultCodecError('invalid_value')
    return valid


def _roe_record(value):
    if type(value) is not dict or len(value) != 14:
        raise ResultCodecError('invalid_shape')
    for key in value:
        if type(key) is not str or len(key) > 24 or key not in contract.ROE_FIELDS:
            raise ResultCodecError('invalid_shape')
    for key in ('schema_version', 'engagement_id', 'operation_profile_sha256',
                'runtime_lock_sha256', 'trust_sha256', 'not_before_utc', 'expires_utc'):
        if type(value[key]) is not str or len(value[key]) > 64:
            raise ResultCodecError('invalid_value')
    if value['schema_version'] != 's43-roe-v1':
        raise ResultCodecError('invalid_value')
    if re.fullmatch(contract.UUID4_PATTERN, value['engagement_id']) is None:
        raise ResultCodecError('invalid_value')
    for key in ('operation_profile_sha256', 'runtime_lock_sha256', 'trust_sha256'):
        if re.fullmatch(contract.SHA256_PATTERN, value[key]) is None:
            raise ResultCodecError('invalid_value')
    if value['operation_profile_sha256'] != contract.ROE_PROFILE_SHA256:
        raise ResultCodecError('invalid_value')
    revision = value['revision']
    if type(revision) is not int or not 1 <= revision <= 2147483647:
        raise ResultCodecError('invalid_value')
    if type(value['active_operation_limit']) is not int or value['active_operation_limit'] != 1:
        raise ResultCodecError('invalid_value')
    predecessor = value['previous_revision_sha256']
    if predecessor is not None:
        if type(predecessor) is not str or len(predecessor) != 64:
            raise ResultCodecError('invalid_value')
        if re.fullmatch(contract.SHA256_PATTERN, predecessor) is None:
            raise ResultCodecError('invalid_value')
    if (revision == 1) != (predecessor is None):
        raise ResultCodecError('invalid_result')
    if _roe_calendar(value['not_before_utc']) >= _roe_calendar(value['expires_utc']):
        raise ResultCodecError('invalid_result')
    for key, minimum, maximum in (('included_operations', 1, 1),
                                  ('excluded_operations', 0, 1),
                                  ('allowed_fixture_ids', 0, 3)):
        items = value[key]
        if type(items) is not list or not minimum <= len(items) <= maximum:
            raise ResultCodecError('invalid_value')
        for item in items:
            if type(item) is not str or len(item) > 27:
                raise ResultCodecError('invalid_value')
            allowed = contract.ROE_FIXTURES if key == 'allowed_fixture_ids' else (contract.ROE_OPERATION,)
            if item not in allowed:
                raise ResultCodecError('invalid_value')
    fixtures = value['allowed_fixture_ids']
    if fixtures != [item for item in contract.ROE_FIXTURES if item in fixtures]:
        raise ResultCodecError('invalid_result')
    budgets = value['budgets']
    if type(budgets) is not dict or len(budgets) != 5:
        raise ResultCodecError('invalid_shape')
    for key in budgets:
        if type(key) is not str or len(key) > 18 or key not in tuple(k for k, _ in contract.ROE_BUDGET_MAXIMA):
            raise ResultCodecError('invalid_shape')
    for key, maximum in contract.ROE_BUDGET_MAXIMA:
        amount = budgets[key]
        if type(amount) is not int or not 0 <= amount <= maximum:
            raise ResultCodecError('invalid_value')
    record = dict(value)
    record['budgets'] = dict(budgets)
    for key in ('included_operations', 'excluded_operations', 'allowed_fixture_ids'):
        record[key] = list(value[key])
    return record


def decode_public_roe(frame: bytes, expected_engagement_id: str) -> dict:
    """Validate a declared policy; never adopt revisions or confer admission."""
    _expected_subject(expected_engagement_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.ROE_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.ROE_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _roe_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if record['engagement_id'] != expected_engagement_id:
        raise ResultCodecError('wrong_subject')
    return record


def encode_public_roe(record: dict, expected_engagement_id: str) -> bytes:
    """Encode declared policy without checking live trust, usage or ownership."""
    _expected_subject(expected_engagement_id)
    validated = _roe_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.ROE_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if validated['engagement_id'] != expected_engagement_id:
        raise ResultCodecError('wrong_subject')
    return encoded
