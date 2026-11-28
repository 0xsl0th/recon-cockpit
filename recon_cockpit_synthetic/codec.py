"""Bounded intrinsic result codec, with no I/O or runtime authorization.

Callers must independently establish trusted subject identity, actual progress,
current authority, cancellation/expiry and cleanup before using a result.
Rejections expose fixed codes only; callers must not log input or traceback locals.
"""

import datetime
import hashlib
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


def _lease_state(value):
    times = contract.LEASE_TIME_FIELDS
    state = value['state']
    if state == 'prepared':
        present = ()
        empty = contract.LEASE_LINK_FIELDS + times + ('close_kind',)
    elif state in ('reserved', 'released'):
        present = ('reservation_id',) + times
        empty = ('completion_event_id', 'closure_event_id', 'close_kind')
        if state == 'released':
            present += ('release_event_id',)
        else:
            empty += ('release_event_id',)
    else:
        present = ('closure_event_id', 'close_kind')
        kind = value['close_kind']
        if kind == 'unadmitted':
            empty = ('reservation_id', 'release_event_id', 'completion_event_id') + times
        else:
            present += ('reservation_id',) + times
            if kind == 'unreleased':
                empty = ('release_event_id', 'completion_event_id')
            elif kind == 'completed':
                present += ('completion_event_id',)
                empty = ()
            else:
                empty = ('completion_event_id',)
    if any(value[key] is None for key in present) or any(value[key] is not None for key in empty):
        raise ResultCodecError('invalid_result')
    start = value['operation_started_ns']
    if start is not None:
        work, cleanup = value['work_deadline_ns'], value['cleanup_deadline_ns']
        if not start < work < cleanup or cleanup - start > 5000000000:
            raise ResultCodecError('invalid_result')
        # Bounded differences avoid overflowing a signed-64-bit timestamp sum.
        if work - start != min(4000000000, cleanup - start - 1000000000):
            raise ResultCodecError('invalid_result')


def _lease_record(value):
    if type(value) is not dict or len(value) != 33:
        raise ResultCodecError('invalid_shape')
    for key in value:
        if type(key) is not str or len(key) > 24 or key not in contract.LEASE_FIELDS:
            raise ResultCodecError('invalid_shape')
    for key, item in value.items():
        if key == 'cancel_requested':
            if type(item) is not bool:
                raise ResultCodecError('invalid_value')
        elif key in ('revision', 'generation') + contract.LEASE_TIME_FIELDS:
            if item is None and key in contract.LEASE_TIME_FIELDS:
                continue
            minimum = 1 if key == 'revision' else 0
            maximum = 2147483647 if key in ('revision', 'generation') else 9223372036854775807
            if type(item) is not int or not minimum <= item <= maximum:
                raise ResultCodecError('invalid_value')
        elif item is None and key in contract.LEASE_LINK_FIELDS + ('close_kind',):
            continue
        elif type(item) is not str or len(item) > 64:
            raise ResultCodecError('invalid_value')
    for key in contract.LEASE_UUID_FIELDS + contract.LEASE_LINK_FIELDS:
        if value[key] is not None and re.fullmatch(contract.UUID4_PATTERN, value[key]) is None:
            raise ResultCodecError('invalid_value')
    for key in contract.LEASE_HASH_FIELDS:
        if re.fullmatch(contract.SHA256_PATTERN, value[key]) is None:
            raise ResultCodecError('invalid_value')
    if value['schema_version'] != 's43-lease-v1' or value['operation_profile_sha256'] != contract.ROE_PROFILE_SHA256:
        raise ResultCodecError('invalid_value')
    if value['fixture_id'] not in ('allowed', 'invalid', 'restricted') or value['review_view'] not in ('terminal', 'graphical'):
        raise ResultCodecError('invalid_value')
    if value['state'] not in ('prepared', 'reserved', 'released', 'closed'):
        raise ResultCodecError('invalid_value')
    if value['close_kind'] not in (None, 'unadmitted', 'unreleased', 'completed', 'interrupted_unknown'):
        raise ResultCodecError('invalid_value')
    interval = _roe_calendar(value['expires_utc']) - _roe_calendar(value['prepared_utc'])
    microseconds = (interval.days * 86400 + interval.seconds) * 1000000 + interval.microseconds
    if not 0 < microseconds <= 30000000:
        raise ResultCodecError('invalid_result')
    _lease_state(value)
    return dict(value)


def decode_public_lease(frame: bytes, expected_engagement_id: str,
                        expected_operation_id: str, expected_lease_id: str) -> dict:
    """Validate a lease snapshot; no live authority, history or cleanup proof."""
    for subject in (expected_engagement_id, expected_operation_id, expected_lease_id):
        _expected_subject(subject)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.LEASE_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.LEASE_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _lease_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if (record['engagement_id'], record['operation_id'], record['lease_id']) != (
            expected_engagement_id, expected_operation_id, expected_lease_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_public_lease(record: dict, expected_engagement_id: str,
                        expected_operation_id: str, expected_lease_id: str) -> bytes:
    """Encode intrinsic bindings only; stored deadlines never authorize resumption."""
    for subject in (expected_engagement_id, expected_operation_id, expected_lease_id):
        _expected_subject(subject)
    validated = _lease_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.LEASE_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if (validated['engagement_id'], validated['operation_id'], validated['lease_id']) != (
            expected_engagement_id, expected_operation_id, expected_lease_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _event_closed(value, fields):
    if type(value) is not dict or len(value) != len(fields):
        raise ResultCodecError('invalid_shape')
    for key in value:
        if type(key) is not str or len(key) > 32 or key not in fields:
            raise ResultCodecError('invalid_shape')


def _event_scalar(value, kind):
    if kind.endswith('?'):
        if value is None:
            return
        kind = kind[:-1]
    if kind in ('generation', 'revision', 'event_sequence', 'monotonic_ns'):
        minimum = 1 if kind in ('revision', 'event_sequence') else 0
        maximum = 9223372036854775807 if kind == 'monotonic_ns' else 2147483647
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
        return
    if type(value) is not str or len(value) > 64:
        raise ResultCodecError('invalid_value')
    if kind == 'uuid4':
        valid = re.fullmatch(contract.UUID4_PATTERN, value) is not None
    elif kind == 'sha256':
        valid = re.fullmatch(contract.SHA256_PATTERN, value) is not None
    elif kind == 'utc':
        _roe_calendar(value)
        valid = True
    elif kind == 'event_kind':
        valid = value in contract.EVENT_VARIANTS
    elif kind == 'cancel_reason':
        valid = value in ('operator_cancel', 'lease_revoked', 'expired', 'runtime_failure')
    elif kind == 'close_kind':
        valid = value in ('unadmitted', 'unreleased', 'completed', 'interrupted_unknown')
    elif kind in ('s43-event-v1', 'pre_write'):
        valid = value == kind
    else:
        valid = False
    if not valid:
        raise ResultCodecError('invalid_value')


def _event_budgets(value, vector):
    _event_closed(value, tuple(key for key, _ in contract.ROE_BUDGET_MAXIMA))
    for key, maximum in contract.ROE_BUDGET_MAXIMA:
        amount = value[key]
        if type(amount) is not int or not 0 <= amount <= maximum:
            raise ResultCodecError('invalid_value')
    if vector and any(value[key] != amount for key, amount in contract.EVENT_BUDGET_VECTOR):
        raise ResultCodecError('invalid_result')
    return dict(value)


def _event_details(value, schema):
    _event_closed(value, tuple(key for key, _ in schema))
    nested = {}
    for key, kind in schema:
        if kind in ('budget_vector', 'budget_totals'):
            nested[key] = _event_budgets(value[key], kind == 'budget_vector')
        elif kind == 'public_result':
            nested[key] = _record(value[key])
        else:
            _event_scalar(value[key], kind)
    details = dict(value)
    details.update(nested)
    return details


def _event_record(value):
    _event_closed(value, contract.EVENT_FIELDS)
    for key, kind in contract.EVENT_SCALARS:
        _event_scalar(value[key], kind)
    kind = value['kind']
    scope, schema = contract.EVENT_VARIANTS[kind]
    details = _event_details(value['details'], schema)
    if (value['sequence'] == 1) != (value['previous_event_sha256'] is None):
        raise ResultCodecError('invalid_result')
    for key in ('operation_id', 'lease_id'):
        if (scope == 'engagement') != (value[key] is None):
            raise ResultCodecError('invalid_result')
    if kind == 'allowance_reserved':
        if any(details['usage_after'][key] < amount for key, amount in contract.EVENT_BUDGET_VECTOR):
            raise ResultCodecError('invalid_result')
        start, work, cleanup = (details[key] for key in contract.LEASE_TIME_FIELDS)
        if not start < work < cleanup or cleanup - start > 5000000000:
            raise ResultCodecError('invalid_result')
        if work - start != min(4000000000, cleanup - start - 1000000000):
            raise ResultCodecError('invalid_result')
    elif kind == 'engagement_revoked':
        if value['generation'] - details['previous_generation'] != 1:
            raise ResultCodecError('invalid_result')
    elif kind == 'roe_adopted':
        if (value['revision'] == 1) != (details['previous_revision_sha256'] is None):
            raise ResultCodecError('invalid_result')
        if (value['revision'] == 1) != (value['generation'] == 0):
            raise ResultCodecError('invalid_result')
    elif kind == 'lease_closed':
        if (details['close_kind'] == 'completed') != (details['completion_event_id'] is not None):
            raise ResultCodecError('invalid_result')
    elif kind == 'result_observed':
        if details['result']['operation_id'] != value['operation_id']:
            raise ResultCodecError('invalid_result')
    record = dict(value)
    record['details'] = details
    return record


def _event_subjects(engagement, operation, lease, event):
    _expected_subject(engagement)
    _expected_subject(event)
    if (operation is None) != (lease is None):
        raise ResultCodecError('invalid_shape')
    if operation is not None:
        _expected_subject(operation)
        _expected_subject(lease)


def decode_public_event(frame: bytes, expected_engagement_id: str,
                        expected_operation_id: str | None, expected_lease_id: str | None,
                        expected_event_id: str) -> dict:
    """Validate one event; no ledger order, transaction or observation proof."""
    _event_subjects(expected_engagement_id, expected_operation_id, expected_lease_id, expected_event_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.EVENT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.EVENT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _event_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('engagement_id', 'operation_id', 'lease_id', 'event_id')) != (
            expected_engagement_id, expected_operation_id, expected_lease_id, expected_event_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_public_event(record: dict, expected_engagement_id: str,
                        expected_operation_id: str | None, expected_lease_id: str | None,
                        expected_event_id: str) -> bytes:
    """Encode intrinsic event bindings; no audit commit or execution authority."""
    _event_subjects(expected_engagement_id, expected_operation_id, expected_lease_id, expected_event_id)
    validated = _event_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.EVENT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('engagement_id', 'operation_id', 'lease_id', 'event_id')) != (
            expected_engagement_id, expected_operation_id, expected_lease_id, expected_event_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _observation_scalar(value, kind):
    if kind in ('true', 'false'):
        if type(value) is not bool or value is not (kind == 'true'):
            raise ResultCodecError('invalid_value')
    elif kind in contract.OBSERVATION_ENUMS or kind in contract.OBSERVATION_LITERALS or kind == 'observation_kind':
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if kind in contract.OBSERVATION_ENUMS:
            valid = value in contract.OBSERVATION_ENUMS[kind]
        elif kind == 'observation_kind':
            valid = value in contract.OBSERVATION_VARIANTS
        else:
            valid = value == kind
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _observation_record(value):
    _event_closed(value, contract.OBSERVATION_FIELDS)
    for key, kind in contract.OBSERVATION_SCALARS:
        _observation_scalar(value[key], kind)
    kind = value['kind']
    role, scope, schema = contract.OBSERVATION_VARIANTS[kind]
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in schema))
    nested = {}
    for key, scalar in schema:
        if scalar == 'public_result':
            nested[key] = _record(payload[key])
        else:
            _observation_scalar(payload[key], scalar)
    if value['issuer_role'] != role:
        raise ResultCodecError('invalid_result')
    if scope == 'operation_or_owner_graph':
        scope = payload['scope']
    for key in contract.OBSERVATION_SUBJECT_FIELDS:
        must_be_null = scope == 'owner_graph' or (scope == 'operation_before_lease' and key == 'lease_id')
        if (value[key] is None) != must_be_null:
            raise ResultCodecError('invalid_result')
    if kind == 'approval_recorded' and payload['reviewed_action_sha256'] != value['action_sha256']:
        raise ResultCodecError('invalid_result')
    if kind == 'result_released' and nested['result']['operation_id'] != value['operation_id']:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    result['payload'].update(nested)
    return result


def _observation_subjects(engagement, operation, lease, reference):
    _expected_subject(engagement)
    _expected_subject(reference)
    if lease is not None and operation is None:
        raise ResultCodecError('invalid_shape')
    for value in (operation, lease):
        if value is not None:
            _expected_subject(value)


def decode_observation_record(frame: bytes, expected_engagement_id: str,
                              expected_operation_id: str | None, expected_lease_id: str | None,
                              expected_reference_id: str) -> dict:
    """Validate a record; no producer authentication, reference registration,
    physical evidence or authorization of any operation is established.
    """
    _observation_subjects(expected_engagement_id, expected_operation_id, expected_lease_id, expected_reference_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.OBSERVATION_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.OBSERVATION_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _observation_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('engagement_id', 'operation_id', 'lease_id', 'reference_id')) != (
            expected_engagement_id, expected_operation_id, expected_lease_id, expected_reference_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_observation_record(record: dict, expected_engagement_id: str,
                              expected_operation_id: str | None, expected_lease_id: str | None,
                              expected_reference_id: str) -> bytes:
    """Encode a record; no producer authentication, reference registration,
    physical evidence or authorization of any operation is established.
    """
    _observation_subjects(expected_engagement_id, expected_operation_id, expected_lease_id, expected_reference_id)
    validated = _observation_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.OBSERVATION_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('engagement_id', 'operation_id', 'lease_id', 'reference_id')) != (
            expected_engagement_id, expected_operation_id, expected_lease_id, expected_reference_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _custody_receipt_scalar(value, kind):
    if kind in contract.CUSTODY_RECEIPT_INTEGER_BOUNDS:
        minimum, maximum = contract.CUSTODY_RECEIPT_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind == 'true':
        if type(value) is not bool or value is not True:
            raise ResultCodecError('invalid_value')
    elif kind in contract.CUSTODY_RECEIPT_ENUMS or kind in contract.CUSTODY_RECEIPT_LITERALS or kind == 'custody_receipt_kind':
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if kind in contract.CUSTODY_RECEIPT_ENUMS:
            valid = value in contract.CUSTODY_RECEIPT_ENUMS[kind]
        elif kind == 'custody_receipt_kind':
            valid = value in contract.CUSTODY_RECEIPT_VARIANTS
        else:
            valid = value == kind
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _custody_receipt_record(value):
    _event_closed(value, contract.CUSTODY_RECEIPT_FIELDS)
    for key, kind in contract.CUSTODY_RECEIPT_SCALARS:
        _custody_receipt_scalar(value[key], kind)
    schema = contract.CUSTODY_RECEIPT_VARIANTS[value['kind']]
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in schema))
    for key, kind in schema:
        _custody_receipt_scalar(payload[key], kind)
    if value['issuer_role'] != 'operation_worker':
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def _custody_receipt_subjects(owner, operation, graph, receipt):
    for value in (owner, graph, receipt):
        _expected_subject(value)
    if operation is not None:
        _expected_subject(operation)


def decode_custody_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                  expected_operation_id: str | None,
                                  expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse socket/source records only; no producer authentication, receipt
    registration/resolution, physical custody/closure proof or operation authorization.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.CUSTODY_RECEIPT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.CUSTODY_RECEIPT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _custody_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_custody_receipt_record(record: dict, expected_subject_owner_id: str,
                                  expected_operation_id: str | None,
                                  expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode socket/source records only; no producer authentication, receipt
    registration/resolution, physical custody/closure proof or operation authorization.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _custody_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.CUSTODY_RECEIPT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _descriptor_receipt_scalar(value, kind):
    if kind == 'fd':
        minimum, maximum = contract.DESCRIPTOR_RECEIPT_FD_BOUNDS
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.DESCRIPTOR_RECEIPT_ENUMS or kind == 'descriptor_identity':
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = (value == 'descriptor_identity' if kind == 'descriptor_identity'
                 else value in contract.DESCRIPTOR_RECEIPT_ENUMS[kind])
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _descriptor_receipt_record(value):
    _event_closed(value, contract.DESCRIPTOR_RECEIPT_FIELDS)
    for key, kind in contract.DESCRIPTOR_RECEIPT_SCALARS:
        _descriptor_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.DESCRIPTOR_RECEIPT_PAYLOAD))
    for key, kind in contract.DESCRIPTOR_RECEIPT_PAYLOAD:
        _descriptor_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.DESCRIPTOR_RECEIPT_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_descriptor_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                     expected_operation_id: str | None,
                                     expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse descriptor syntax; no producer authentication, receipt registration/
    resolution, descriptor identity/live custody, nullability eligibility proof
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.DESCRIPTOR_RECEIPT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.DESCRIPTOR_RECEIPT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _descriptor_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_descriptor_receipt_record(record: dict, expected_subject_owner_id: str,
                                     expected_operation_id: str | None,
                                     expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode descriptor syntax; no producer authentication, receipt registration/
    resolution, descriptor identity/live custody, nullability eligibility proof
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _descriptor_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.DESCRIPTOR_RECEIPT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _process_receipt_scalar(value, kind):
    if kind in contract.PROCESS_RECEIPT_INTEGER_BOUNDS:
        minimum, maximum = contract.PROCESS_RECEIPT_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind == 'cap_mask':
        if type(value) is not str or len(value) != 16 or re.fullmatch(contract.PROCESS_RECEIPT_CAP_MASK_PATTERN, value) is None:
            raise ResultCodecError('invalid_value')
    elif kind == 'process_identity':
        if type(value) is not str or len(value) > 64 or value != 'process_identity':
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _process_receipt_record(value):
    _event_closed(value, contract.PROCESS_RECEIPT_FIELDS)
    for key, kind in contract.PROCESS_RECEIPT_SCALARS:
        _process_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.PROCESS_RECEIPT_PAYLOAD))
    for key, kind in contract.PROCESS_RECEIPT_PAYLOAD:
        _process_receipt_scalar(payload[key], kind)
    rule = contract.PROCESS_RECEIPT_ROLE_RULES.get(payload['role'])
    if rule is None or value['issuer_role'] != rule[0] or payload['task_count'] > rule[1]:
        raise ResultCodecError('invalid_result')
    if payload['role'] != 'supervisor' and payload['effective_capabilities'] != '0000000000000000':
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_process_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                     expected_operation_id: str | None,
                                     expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse process claims only; no producer authentication, receipt registration/
    resolution, live process identity/runtime eligibility, termination/reaping
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.PROCESS_RECEIPT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.PROCESS_RECEIPT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _process_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_process_receipt_record(record: dict, expected_subject_owner_id: str,
                                     expected_operation_id: str | None,
                                     expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode process claims only; no producer authentication, receipt registration/
    resolution, live process identity/runtime eligibility, termination/reaping
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _process_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.PROCESS_RECEIPT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _termination_receipt_scalar(value, kind):
    if kind in contract.TERMINATION_RECEIPT_INTEGER_BOUNDS:
        minimum, maximum = contract.TERMINATION_RECEIPT_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.TERMINATION_RECEIPT_ENUMS or kind in contract.TERMINATION_RECEIPT_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = (value in contract.TERMINATION_RECEIPT_ENUMS[kind]
                 if kind in contract.TERMINATION_RECEIPT_ENUMS
                 else value == contract.TERMINATION_RECEIPT_LITERALS[kind])
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _termination_receipt_record(value):
    _event_closed(value, contract.TERMINATION_RECEIPT_FIELDS)
    for key, kind in contract.TERMINATION_RECEIPT_SCALARS:
        _termination_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.TERMINATION_RECEIPT_PAYLOAD))
    for key, kind in contract.TERMINATION_RECEIPT_PAYLOAD:
        _termination_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.TERMINATION_RECEIPT_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_termination_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse termination claims only; no producer authentication, receipt
    registration/resolution, actual termination/reaping or live custody,
    successful source/connector closure or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.TERMINATION_RECEIPT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.TERMINATION_RECEIPT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _termination_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_termination_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode termination claims only; no producer authentication, receipt
    registration/resolution, actual termination/reaping or live custody,
    successful source/connector closure or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _termination_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.TERMINATION_RECEIPT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _graph_closure_receipt_scalar(value, kind):
    if kind == 'receipt_id_set':
        if type(value) is not list:
            raise ResultCodecError('invalid_shape')
        if len(value) > contract.GRAPH_CLOSURE_RECEIPT_MAX_MEMBERS:
            raise ResultCodecError('invalid_value')
        for item in value:
            _event_scalar(item, 'uuid4')
        if len(set(value)) != len(value):
            raise ResultCodecError('invalid_value')
    elif kind in contract.GRAPH_CLOSURE_RECEIPT_INTEGER_BOUNDS:
        minimum, maximum = contract.GRAPH_CLOSURE_RECEIPT_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.GRAPH_CLOSURE_RECEIPT_ENUMS or kind == 'graph_closure':
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = (value in contract.GRAPH_CLOSURE_RECEIPT_ENUMS[kind]
                 if kind in contract.GRAPH_CLOSURE_RECEIPT_ENUMS else value == kind)
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _graph_closure_receipt_record(value):
    _event_closed(value, contract.GRAPH_CLOSURE_RECEIPT_FIELDS)
    for key, kind in contract.GRAPH_CLOSURE_RECEIPT_SCALARS:
        _graph_closure_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.GRAPH_CLOSURE_RECEIPT_PAYLOAD))
    for key, kind in contract.GRAPH_CLOSURE_RECEIPT_PAYLOAD:
        _graph_closure_receipt_scalar(payload[key], kind)
    members = payload['member_process_receipt_ids']
    if (value['issuer_role'] not in contract.GRAPH_CLOSURE_RECEIPT_ISSUER_ROLES
            or not payload['expected_processes'] == payload['reaped_processes'] == len(members)
            or payload['graph_id'] != value['graph_id']
            or (payload['scope'] == 'owner_graph') != (value['operation_id'] is None)):
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    result['payload']['member_process_receipt_ids'] = list(members)
    return result


def decode_graph_closure_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse closure claims only; no producer authentication, receipt registration
    or resolution, actual membership/reaping/descriptor closure, successful cleanup,
    recovery eligibility or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.GRAPH_CLOSURE_RECEIPT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.GRAPH_CLOSURE_RECEIPT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _graph_closure_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_graph_closure_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode closure claims only; no producer authentication, receipt registration
    or resolution, actual membership/reaping/descriptor closure, successful cleanup,
    recovery eligibility or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _graph_closure_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.GRAPH_CLOSURE_RECEIPT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_closure_binding_scalar(value, kind):
    if kind == 'uuid_list10':
        if type(value) is not list:
            raise ResultCodecError('invalid_shape')
        minimum, maximum = contract.RECOVERY_BINDING_LIST_BOUNDS
        if not minimum <= len(value) <= maximum:
            raise ResultCodecError('invalid_value')
        for item in value:
            _event_scalar(item, 'uuid4')
        if len(set(value)) != len(value) or value != sorted(value):
            raise ResultCodecError('invalid_value')
    elif kind == 'recovery_closure_binding':
        if type(value) is not str or len(value) > 64 or value != kind:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _recovery_closure_binding_record(value):
    _event_closed(value, contract.RECOVERY_BINDING_FIELDS)
    for key, kind in contract.RECOVERY_BINDING_SCALARS:
        _recovery_closure_binding_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_BINDING_PAYLOAD))
    for key, kind in contract.RECOVERY_BINDING_PAYLOAD:
        _recovery_closure_binding_scalar(payload[key], kind)
    if (value['issuer_role'] not in contract.RECOVERY_BINDING_ISSUER_ROLES
            or value['phase'] != contract.RECOVERY_BINDING_PHASE
            or value['observer_session_id'] != payload['consumer_session_id']
            or value['graph_id'] != payload['subject_graph_id']
            or value['observed_monotonic_ns'] != payload['evaluated_monotonic_ns']):
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    result['payload']['termination_receipt_ids'] = list(payload['termination_receipt_ids'])
    return result


def decode_recovery_closure_binding_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse recovery binding claims only; no producer authentication, receipt
    registration/resolution, actual historical membership/reaping or continuous
    live custody, successful cleanup/recovery eligibility or operation authorization.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_BINDING_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_BINDING_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_closure_binding_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_closure_binding_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode recovery binding claims only; no producer authentication, receipt
    registration/resolution, actual historical membership/reaping or continuous
    live custody, successful cleanup/recovery eligibility or operation authorization.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_closure_binding_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_BINDING_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_lifecycle_scalar(value, kind):
    if kind in contract.RECOVERY_LIFECYCLE_INTEGER_BOUNDS:
        minimum, maximum = contract.RECOVERY_LIFECYCLE_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_LIFECYCLE_ENUMS or kind in contract.RECOVERY_LIFECYCLE_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = (value in contract.RECOVERY_LIFECYCLE_ENUMS[kind]
                 if kind in contract.RECOVERY_LIFECYCLE_ENUMS
                 else value == contract.RECOVERY_LIFECYCLE_LITERALS[kind])
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _recovery_lifecycle_record(value):
    _event_closed(value, contract.RECOVERY_LIFECYCLE_FIELDS)
    for key, kind in contract.RECOVERY_LIFECYCLE_SCALARS:
        _recovery_lifecycle_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_LIFECYCLE_PAYLOAD))
    for key, kind in contract.RECOVERY_LIFECYCLE_PAYLOAD:
        _recovery_lifecycle_scalar(payload[key], kind)
    if (value['issuer_role'] not in contract.RECOVERY_LIFECYCLE_ISSUER_ROLES
            or tuple(payload[key] for key in ('state', 'wait_code', 'signal'))
            not in contract.RECOVERY_LIFECYCLE_VALID_TUPLES
            or value['observed_monotonic_ns'] != payload['observed_monotonic_ns']):
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_recovery_lifecycle_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse lifecycle claims only; no producer authentication, receipt
    registration/resolution, actual wait/stop/continue or installed-filter proof,
    live custody/recovery eligibility or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_LIFECYCLE_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_LIFECYCLE_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_lifecycle_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_lifecycle_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode lifecycle claims only; no producer authentication, receipt
    registration/resolution, actual wait/stop/continue or installed-filter proof,
    live custody/recovery eligibility or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_lifecycle_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_LIFECYCLE_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_prepared_receipt_scalar(value, kind):
    if kind in contract.RECOVERY_PREPARED_INTEGER_BOUNDS:
        minimum, maximum = contract.RECOVERY_PREPARED_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind == 'false':
        if type(value) is not bool or value is not False:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_PREPARED_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value == contract.RECOVERY_PREPARED_LITERALS[kind]
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _recovery_prepared_receipt_record(value):
    _event_closed(value, contract.RECOVERY_PREPARED_FIELDS)
    for key, kind in contract.RECOVERY_PREPARED_SCALARS:
        _recovery_prepared_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_PREPARED_PAYLOAD))
    for key, kind in contract.RECOVERY_PREPARED_PAYLOAD:
        _recovery_prepared_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.RECOVERY_PREPARED_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_recovery_prepared_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse prepared claims only; no producer/peer authentication, receipt
    registration/resolution, actual packet receive/prepared barrier, installed-filter
    or bootstrap proof, unopened database proof, live custody/recovery eligibility
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_PREPARED_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_PREPARED_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_prepared_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_prepared_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode prepared claims only; no producer/peer authentication, receipt
    registration/resolution, actual packet receive/prepared barrier, installed-filter
    or bootstrap proof, unopened database proof, live custody/recovery eligibility
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_prepared_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_PREPARED_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_activate_receipt_scalar(value, kind):
    if kind in contract.RECOVERY_ACTIVATE_INTEGER_BOUNDS:
        minimum, maximum = contract.RECOVERY_ACTIVATE_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_ACTIVATE_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value == contract.RECOVERY_ACTIVATE_LITERALS[kind]
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _recovery_activate_receipt_record(value):
    _event_closed(value, contract.RECOVERY_ACTIVATE_FIELDS)
    for key, kind in contract.RECOVERY_ACTIVATE_SCALARS:
        _recovery_activate_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_ACTIVATE_PAYLOAD))
    for key, kind in contract.RECOVERY_ACTIVATE_PAYLOAD:
        _recovery_activate_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.RECOVERY_ACTIVATE_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_recovery_activate_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse activation claims only; no producer/peer authentication, receipt
    registration/resolution, actual activation receive/continuation/owner closure,
    commit-witness or persisted-history proof, live custody/recovery eligibility
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_ACTIVATE_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_ACTIVATE_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_activate_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_activate_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode activation claims only; no producer/peer authentication, receipt
    registration/resolution, actual activation receive/continuation/owner closure,
    commit-witness or persisted-history proof, live custody/recovery eligibility
    or operation authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_activate_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_ACTIVATE_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_challenge_receipt_scalar(value, kind):
    if kind in contract.RECOVERY_CHALLENGE_INTEGER_BOUNDS:
        minimum, maximum = contract.RECOVERY_CHALLENGE_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_CHALLENGE_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value == contract.RECOVERY_CHALLENGE_LITERALS[kind]
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _recovery_challenge_receipt_record(value):
    _event_closed(value, contract.RECOVERY_CHALLENGE_FIELDS)
    for key, kind in contract.RECOVERY_CHALLENGE_SCALARS:
        _recovery_challenge_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_CHALLENGE_PAYLOAD))
    for key, kind in contract.RECOVERY_CHALLENGE_PAYLOAD:
        _recovery_challenge_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.RECOVERY_CHALLENGE_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_recovery_challenge_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse challenge claims only; no producer/peer authentication, receipt
    registration/resolution, actual challenge receive or freshness/consumption,
    activation or closure proof, live custody/recovery eligibility or operation
    authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_CHALLENGE_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_CHALLENGE_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_challenge_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_challenge_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode challenge claims only; no producer/peer authentication, receipt
    registration/resolution, actual challenge receive or freshness/consumption,
    activation or closure proof, live custody/recovery eligibility or operation
    authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_challenge_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_CHALLENGE_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_response_receipt_uuid_list3(value):
    if type(value) is not list:
        raise ResultCodecError('invalid_shape')
    minimum, maximum = contract.RECOVERY_RESPONSE_LIST_BOUNDS
    if not minimum <= len(value) <= maximum:
        raise ResultCodecError('invalid_value')
    for item in value:
        _event_scalar(item, 'uuid4')
    if len(set(value)) != len(value) or value != sorted(value):
        raise ResultCodecError('invalid_value')
    return list(value)


def _recovery_response_receipt_scalar(value, kind):
    if kind == 'uuid_list3':
        return _recovery_response_receipt_uuid_list3(value)
    if kind in contract.RECOVERY_RESPONSE_INTEGER_BOUNDS:
        minimum, maximum = contract.RECOVERY_RESPONSE_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_RESPONSE_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value == contract.RECOVERY_RESPONSE_LITERALS[kind]
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)
    return value


def _recovery_response_receipt_record(value):
    _event_closed(value, contract.RECOVERY_RESPONSE_FIELDS)
    for key, kind in contract.RECOVERY_RESPONSE_SCALARS:
        _recovery_response_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_RESPONSE_PAYLOAD))
    validated_payload = {}
    for key, kind in contract.RECOVERY_RESPONSE_PAYLOAD:
        validated_payload[key] = _recovery_response_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.RECOVERY_RESPONSE_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = validated_payload
    return result


def decode_recovery_response_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse response claims only; no producer/peer authentication, receipt
    registration/resolution, actual response receive or complete binding/ancestor
    validation, live custody, successful recovery eligibility or operation
    authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_RESPONSE_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_RESPONSE_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_response_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_response_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode response claims only; no producer/peer authentication, receipt
    registration/resolution, actual response receive or complete binding/ancestor
    validation, live custody, successful recovery eligibility or operation
    authorization is established.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_response_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_RESPONSE_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_refused_receipt_scalar(value, kind):
    if kind in contract.RECOVERY_REFUSED_INTEGER_BOUNDS:
        minimum, maximum = contract.RECOVERY_REFUSED_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_REFUSED_ENUMS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if value not in contract.RECOVERY_REFUSED_ENUMS[kind]:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_REFUSED_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value == contract.RECOVERY_REFUSED_LITERALS[kind]
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _recovery_refused_receipt_record(value):
    _event_closed(value, contract.RECOVERY_REFUSED_FIELDS)
    for key, kind in contract.RECOVERY_REFUSED_SCALARS:
        _recovery_refused_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_REFUSED_PAYLOAD))
    for key, kind in contract.RECOVERY_REFUSED_PAYLOAD:
        _recovery_refused_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.RECOVERY_REFUSED_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_recovery_refused_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse refusal claims only; no producer/peer authentication, receipt
    registration/resolution, actual refusal receive, valid preceding challenge,
    truth of the failure reason, live custody, completed witness/recovery
    eligibility or operation authorization is established. A refusal is failed
    evidence, not successful recovery.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_REFUSED_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_REFUSED_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_refused_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_refused_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode refusal claims only; no producer/peer authentication, receipt
    registration/resolution, actual refusal receive, valid preceding challenge,
    truth of the failure reason, live custody, completed witness/recovery
    eligibility or operation authorization is established. A refusal is failed
    evidence, not successful recovery.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_refused_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_REFUSED_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _recovery_fixed_failure_receipt_scalar(value, kind):
    if kind in contract.RECOVERY_FIXED_FAILURE_INTEGER_BOUNDS:
        minimum, maximum = contract.RECOVERY_FIXED_FAILURE_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_FIXED_FAILURE_ENUMS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if value not in contract.RECOVERY_FIXED_FAILURE_ENUMS[kind]:
            raise ResultCodecError('invalid_value')
    elif kind in contract.RECOVERY_FIXED_FAILURE_LITERALS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value == contract.RECOVERY_FIXED_FAILURE_LITERALS[kind]
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _custody_receipt_scalar(value, kind)


def _recovery_fixed_failure_receipt_record(value):
    _event_closed(value, contract.RECOVERY_FIXED_FAILURE_FIELDS)
    for key, kind in contract.RECOVERY_FIXED_FAILURE_SCALARS:
        _recovery_fixed_failure_receipt_scalar(value[key], kind)
    payload = value['payload']
    _event_closed(payload, tuple(key for key, _ in contract.RECOVERY_FIXED_FAILURE_PAYLOAD))
    for key, kind in contract.RECOVERY_FIXED_FAILURE_PAYLOAD:
        _recovery_fixed_failure_receipt_scalar(payload[key], kind)
    if value['issuer_role'] not in contract.RECOVERY_FIXED_FAILURE_ISSUER_ROLES:
        raise ResultCodecError('invalid_result')
    result = dict(value)
    result['payload'] = dict(payload)
    return result


def decode_recovery_fixed_failure_receipt_record(frame: bytes, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> dict:
    """Parse fixed-failure claims only; no producer/peer authentication,
    receipt registration/resolution, actual fixed-failure receive or authenticated
    bootstrap context, truth of cause/stage, live custody, completed witness,
    recovery eligibility or operation authorization is established. Parsed
    failure claims earn no successful-witness credit.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.RECOVERY_FIXED_FAILURE_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.RECOVERY_FIXED_FAILURE_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _recovery_fixed_failure_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_recovery_fixed_failure_receipt_record(record: dict, expected_subject_owner_id: str,
                                      expected_operation_id: str | None,
                                      expected_graph_id: str, expected_receipt_id: str) -> bytes:
    """Encode fixed-failure claims only; no producer/peer authentication,
    receipt registration/resolution, actual fixed-failure receive or authenticated
    bootstrap context, truth of cause/stage, live custody, completed witness,
    recovery eligibility or operation authorization is established. Parsed
    failure claims earn no successful-witness credit.
    """
    _custody_receipt_subjects(expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id)
    validated = _recovery_fixed_failure_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.RECOVERY_FIXED_FAILURE_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id')) != (
            expected_subject_owner_id, expected_operation_id, expected_graph_id, expected_receipt_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _progress_scalar(value, kind):
    if value is None and kind in contract.PROGRESS_NULLABLE_TYPES:
        return
    if kind in contract.PROGRESS_INTEGER_BOUNDS:
        minimum, maximum = contract.PROGRESS_INTEGER_BOUNDS[kind]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ResultCodecError('invalid_value')
    elif kind in contract.PROGRESS_ENUMS:
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if value not in contract.PROGRESS_ENUMS[kind]:
            raise ResultCodecError('invalid_value')
    elif kind == 's43-progress-v1':
        if type(value) is not str or len(value) > 64 or value != kind:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _progress_record(value):
    _event_closed(value, contract.PROGRESS_FIELDS)
    for key, kind in contract.PROGRESS_SCALARS:
        _progress_scalar(value[key], kind)
    perspective = value['perspective']
    if perspective != contract.PROGRESS_ROLE_PERSPECTIVES[value['issuer_role']]:
        raise ResultCodecError('invalid_result')
    for key in contract.PROGRESS_COUNTER_FIELDS:
        if key not in contract.PROGRESS_KNOWN_FIELDS[perspective] and value[key] is not None:
            raise ResultCodecError('invalid_result')
    for key, maximum in contract.PROGRESS_BYTE_CAPS[perspective]:
        if value[key] is not None and value[key] > maximum:
            raise ResultCodecError('invalid_result')
    return dict(value)


def _progress_subjects(owner, operation, graph, record):
    for value in (owner, operation, graph, record):
        _expected_subject(value)


def decode_progress_record(frame: bytes, expected_owner_id: str, expected_operation_id: str,
                           expected_graph_id: str, expected_record_id: str) -> dict:
    """Parse progress claims only; no producer/peer authentication, registry
    membership, freshness, actual stage/counter truth, interval coverage, remote
    delivery, physical closure, successful witness or operation/recovery
    authorization is established. Recovery-profile size eligibility is external.
    """
    _progress_subjects(expected_owner_id, expected_operation_id, expected_graph_id, expected_record_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.PROGRESS_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.PROGRESS_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _progress_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('owner_id', 'operation_id', 'graph_id', 'record_id')) != (
            expected_owner_id, expected_operation_id, expected_graph_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_progress_record(record: dict, expected_owner_id: str, expected_operation_id: str,
                           expected_graph_id: str, expected_record_id: str) -> bytes:
    """Encode progress claims only; no producer/peer authentication, registry
    membership, freshness, actual stage/counter truth, interval coverage, remote
    delivery, physical closure, successful witness or operation/recovery
    authorization is established. Recovery-profile size eligibility is external.
    """
    _progress_subjects(expected_owner_id, expected_operation_id, expected_graph_id, expected_record_id)
    validated = _progress_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.PROGRESS_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('owner_id', 'operation_id', 'graph_id', 'record_id')) != (
            expected_owner_id, expected_operation_id, expected_graph_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _public_binding_scalar(value, kind):
    if kind in ('binding_kind', 's43-public-binding-v1'):
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value in contract.PUBLIC_BINDING_KINDS if kind == 'binding_kind' else value == kind
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _public_binding_related_ids(value):
    if type(value) is not list:
        raise ResultCodecError('invalid_shape')
    if len(value) > contract.PUBLIC_BINDING_MAX_RELATED_IDS:
        raise ResultCodecError('invalid_value')
    for item in value:
        _event_scalar(item, 'uuid4')
    if len(set(value)) != len(value):
        raise ResultCodecError('invalid_value')
    return list(value)


def _public_binding_record(value):
    _event_closed(value, contract.PUBLIC_BINDING_FIELDS)
    for key, kind in contract.PUBLIC_BINDING_SCALARS:
        _public_binding_scalar(value[key], kind)
    related_ids = _public_binding_related_ids(value['related_ids'])
    result = dict(value)
    result['related_ids'] = related_ids
    return result


def decode_public_binding_record(frame: bytes, expected_subject_id: str, expected_record_id: str) -> dict:
    """Parse public-manifest claims only; no producer/peer authentication,
    manifest/input resolution, digest verification, live registry membership,
    provenance/freshness, physical custody/closure, completed witness or
    operation/recovery authority is established. Profile eligibility is external.
    """
    _expected_subject(expected_subject_id)
    _expected_subject(expected_record_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.PUBLIC_BINDING_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.PUBLIC_BINDING_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _public_binding_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if (record['subject_id'], record['record_id']) != (expected_subject_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_public_binding_record(record: dict, expected_subject_id: str, expected_record_id: str) -> bytes:
    """Encode public-manifest claims only; no producer/peer authentication,
    manifest/input resolution, digest verification, live registry membership,
    provenance/freshness, physical custody/closure, completed witness or
    operation/recovery authority is established. Profile eligibility is external.
    """
    _expected_subject(expected_subject_id)
    _expected_subject(expected_record_id)
    validated = _public_binding_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.PUBLIC_BINDING_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if (validated['subject_id'], validated['record_id']) != (expected_subject_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _lookup_observed_scalar(value, kind):
    if kind in ('lookup_status', 's43-lookup-observed-v1'):
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        valid = value in contract.LOOKUP_OBSERVED_STATUSES if kind == 'lookup_status' else value == kind
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _lookup_observed_record(value):
    _event_closed(value, contract.LOOKUP_OBSERVED_FIELDS)
    for key, kind in contract.LOOKUP_OBSERVED_SCALARS:
        _lookup_observed_scalar(value[key], kind)
    if value['status'] == 'closed':
        if value['lease_id'] is None or value['closure_event_id'] is None:
            raise ResultCodecError('invalid_result')
        if (value['completion_event_id'] is None) != (value['result_operation_id'] is None):
            raise ResultCodecError('invalid_result')
        if value['result_operation_id'] is not None and value['result_operation_id'] != value['operation_id']:
            raise ResultCodecError('invalid_result')
    elif any(value[key] is not None for key in contract.LOOKUP_OBSERVED_REFERENCES):
        raise ResultCodecError('invalid_result')
    return dict(value)


def _lookup_observed_subjects(owner, operation, record):
    for value in (owner, operation, record):
        _expected_subject(value)


def decode_lookup_observed_record(frame: bytes, expected_owner_id: str,
                                  expected_operation_id: str, expected_record_id: str) -> dict:
    """Parse intrinsic lookup claims only; no actual lookup, producer/broker/peer
    authentication, issuer/session/epoch/runtime binding, provenance/freshness,
    history uniqueness, persisted lease/event/result resolution, physical custody/
    closure, completed witness or operation/recovery authority is established.
    Recovery-profile size eligibility and live broker provenance remain external.
    """
    _lookup_observed_subjects(expected_owner_id, expected_operation_id, expected_record_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.LOOKUP_OBSERVED_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.LOOKUP_OBSERVED_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _lookup_observed_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('owner_id', 'operation_id', 'record_id')) != (
            expected_owner_id, expected_operation_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_lookup_observed_record(record: dict, expected_owner_id: str,
                                  expected_operation_id: str, expected_record_id: str) -> bytes:
    """Encode intrinsic lookup claims only; no actual lookup, producer/broker/peer
    authentication, issuer/session/epoch/runtime binding, provenance/freshness,
    history uniqueness, persisted lease/event/result resolution, physical custody/
    closure, completed witness or operation/recovery authority is established.
    Recovery-profile size eligibility and live broker provenance remain external.
    """
    _lookup_observed_subjects(expected_owner_id, expected_operation_id, expected_record_id)
    validated = _lookup_observed_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.LOOKUP_OBSERVED_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('owner_id', 'operation_id', 'record_id')) != (
            expected_owner_id, expected_operation_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _transaction_result_scalar(value, kind):
    if kind == 'transaction_reason?' and value is None:
        return
    if kind in ('transaction_status', 'transaction_reason?', 's43-txn-result-v1'):
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if kind == 'transaction_status':
            valid = value in contract.TRANSACTION_RESULT_STATUSES
        elif kind == 'transaction_reason?':
            valid = value in contract.TRANSACTION_RESULT_REASONS
        else:
            valid = value == kind
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _transaction_result_record(value):
    _event_closed(value, contract.TRANSACTION_RESULT_FIELDS)
    for key, kind in contract.TRANSACTION_RESULT_SCALARS:
        _transaction_result_scalar(value[key], kind)
    status = value['status']
    if value['reason'] not in contract.TRANSACTION_RESULT_STATUS_REASONS[status]:
        raise ResultCodecError('invalid_result')
    if status == 'committed':
        if value['transaction_id'] is None or value['last_event_sequence'] is None:
            raise ResultCodecError('invalid_result')
        if (value['operation_id'] is None) != (value['lease_id'] is None):
            raise ResultCodecError('invalid_result')
    elif any(value[key] is not None for key in contract.TRANSACTION_RESULT_COMMIT_FIELDS):
        raise ResultCodecError('invalid_result')
    return dict(value)


def decode_transaction_result(frame: bytes, expected_call_id: str) -> dict:
    """Parse intrinsic claims only; no actual transaction, commit/rollback proof,
    broker authentication/trusted-call origin, persisted sequence/event or scope
    resolution, provenance/freshness, physical custody/closure, completed witness
    or operation/recovery authority is established. A receipt grants no live
    signal, permission, mutation retry or deadline reset.
    """
    _expected_subject(expected_call_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.TRANSACTION_RESULT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.TRANSACTION_RESULT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _transaction_result_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if record['call_id'] != expected_call_id:
        raise ResultCodecError('wrong_subject')
    return record


def encode_transaction_result(record: dict, expected_call_id: str) -> bytes:
    """Encode intrinsic claims only; no actual transaction, commit/rollback proof,
    broker authentication/trusted-call origin, persisted sequence/event or scope
    resolution, provenance/freshness, physical custody/closure, completed witness
    or operation/recovery authority is established. A receipt grants no live
    signal, permission, mutation retry or deadline reset.
    """
    _expected_subject(expected_call_id)
    validated = _transaction_result_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.TRANSACTION_RESULT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if validated['call_id'] != expected_call_id:
        raise ResultCodecError('wrong_subject')
    return encoded


def _transaction_witness_scalar(value, kind):
    if kind == 'positive_int':
        if type(value) is not int or not 1 <= value <= 2147483647:
            raise ResultCodecError('invalid_value')
    elif kind in ('transaction_method', 'transaction_barrier', 's43-transaction-witness-v1'):
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if kind == 'transaction_method':
            valid = value in contract.TRANSACTION_WITNESS_METHODS
        elif kind == 'transaction_barrier':
            valid = value in contract.TRANSACTION_WITNESS_BARRIERS
        else:
            valid = value == kind
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _transaction_witness_event_ids(value):
    if type(value) is not list:
        raise ResultCodecError('invalid_shape')
    if len(value) > contract.TRANSACTION_WITNESS_MAX_EVENT_IDS:
        raise ResultCodecError('invalid_value')
    for item in value:
        _event_scalar(item, 'uuid4')
    if len(set(value)) != len(value):
        raise ResultCodecError('invalid_value')
    return list(value)


def _transaction_witness_record(value):
    _event_closed(value, contract.TRANSACTION_WITNESS_FIELDS)
    for key, kind in contract.TRANSACTION_WITNESS_SCALARS:
        _transaction_witness_scalar(value[key], kind)
    event_ids = _transaction_witness_event_ids(value['event_ids'])
    nested = value['transaction_result']
    if nested is not None:
        if type(nested) is not dict:
            raise ResultCodecError('invalid_shape')
        nested = _transaction_result_record(nested)
        if len(_canonical(nested)) > contract.TRANSACTION_RESULT_MAX_BYTES:
            raise ResultCodecError('invalid_encoding')
        if nested['call_id'] != value['call_id']:
            raise ResultCodecError('invalid_result')
    result = dict(value)
    result['event_ids'] = event_ids
    result['transaction_result'] = nested
    return result


def _transaction_witness_subjects(writer, call, record):
    for value in (writer, call, record):
        _expected_subject(value)


def decode_transaction_witness_record(frame: bytes, expected_writer_id: str,
                                      expected_call_id: str, expected_record_id: str) -> dict:
    """Parse intrinsic claims only; no actual SQL/atomicity, trusted writer/call,
    contender order, result availability, persisted event validity, provenance/
    freshness, physical custody/closure, completed witness or operation/recovery
    authority is established. Barrier/result/event-count relations and recovery
    eligibility remain external. Parsing grants no signal, retry or deadline reset.
    """
    _transaction_witness_subjects(expected_writer_id, expected_call_id, expected_record_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.TRANSACTION_WITNESS_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.TRANSACTION_WITNESS_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _transaction_witness_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if tuple(record[key] for key in ('writer_id', 'call_id', 'record_id')) != (
            expected_writer_id, expected_call_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_transaction_witness_record(record: dict, expected_writer_id: str,
                                      expected_call_id: str, expected_record_id: str) -> bytes:
    """Encode intrinsic claims only; no actual SQL/atomicity, trusted writer/call,
    contender order, result availability, persisted event validity, provenance/
    freshness, physical custody/closure, completed witness or operation/recovery
    authority is established. Barrier/result/event-count relations and recovery
    eligibility remain external. Parsing grants no signal, retry or deadline reset.
    """
    _transaction_witness_subjects(expected_writer_id, expected_call_id, expected_record_id)
    validated = _transaction_witness_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.TRANSACTION_WITNESS_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if tuple(validated[key] for key in ('writer_id', 'call_id', 'record_id')) != (
            expected_writer_id, expected_call_id, expected_record_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _case_context_scalar(value, kind):
    if kind in ('uuid4', 'sha256'):
        _event_scalar(value, kind)
        return
    maximum = 256 if kind == 'planned_node_id' else 64
    if type(value) is not str or len(value) > maximum or not value.isascii():
        raise ResultCodecError('invalid_value')
    if value not in contract.CASE_CONTEXT_VALUES[kind]:
        raise ResultCodecError('invalid_value')


def _case_context_record(value):
    _event_closed(value, contract.CASE_CONTEXT_FIELDS)
    for key, kind in contract.CASE_CONTEXT_SCALARS:
        _case_context_scalar(value[key], kind)
    mapping = tuple(value[key] for key in ('parent_id', 'variant_id', 'node_id'))
    if mapping not in contract.CASE_CONTEXT_NATIVE_MAPPINGS:
        raise ResultCodecError('invalid_result')
    return dict(value)


def decode_case_context_record(frame: bytes, expected_case_id: str,
                               expected_bundle_id: str) -> dict:
    """Parse intrinsic planned-case claims only; no actual native execution,
    fixture/view/status correspondence, authenticated identity, public metadata
    provenance/freshness, bundle membership, custody/closure or completed witness
    is proved. Parsing grants no authority, live signal, retry or deadline reset.
    """
    _expected_subject(expected_case_id)
    _expected_subject(expected_bundle_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.CASE_CONTEXT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.CASE_CONTEXT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _case_context_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if (record['case_id'], record['bundle_id']) != (expected_case_id, expected_bundle_id):
        raise ResultCodecError('wrong_subject')
    return record


def encode_case_context_record(record: dict, expected_case_id: str,
                               expected_bundle_id: str) -> bytes:
    """Encode intrinsic planned-case claims only; no actual native execution,
    fixture/view/status correspondence, authenticated identity, public metadata
    provenance/freshness, bundle membership, custody/closure or completed witness
    is proved. Encoding grants no authority, live signal, retry or deadline reset.
    """
    _expected_subject(expected_case_id)
    _expected_subject(expected_bundle_id)
    validated = _case_context_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.CASE_CONTEXT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if (validated['case_id'], validated['bundle_id']) != (expected_case_id, expected_bundle_id):
        raise ResultCodecError('wrong_subject')
    return encoded


def _reader_receipt_scalar(value, kind):
    if kind in contract.READER_RECEIPT_COUNT_MAXIMA:
        if type(value) is not int or not 0 <= value <= contract.READER_RECEIPT_COUNT_MAXIMA[kind]:
            raise ResultCodecError('invalid_value')
    elif kind in ('reader_kind', 'inspection_reason', 'inspection_status', 's43-inspection-v1'):
        if type(value) is not str or len(value) > 64:
            raise ResultCodecError('invalid_value')
        if kind == 'reader_kind':
            valid = value in contract.READER_RECEIPT_KINDS
        elif kind == 'inspection_reason':
            valid = value in contract.READER_RECEIPT_REASONS
        elif kind == 'inspection_status':
            valid = value in contract.READER_RECEIPT_STATUSES
        else:
            valid = value == kind
        if not valid:
            raise ResultCodecError('invalid_value')
    else:
        _event_scalar(value, kind)


def _reader_receipt_record(value):
    _event_closed(value, contract.READER_RECEIPT_FIELDS)
    for key, kind in contract.READER_RECEIPT_SCALARS:
        _reader_receipt_scalar(value[key], kind)
    if value['status'] == 'valid':
        valid = (value['bundle_id'] is not None and value['manifest_sha256'] is not None
                 and value['reason'] == 'none')
    else:
        valid = (value['bundle_id'] is None and value['manifest_sha256'] is None
                 and value['reason'] != 'none')
    if not valid:
        raise ResultCodecError('invalid_result')
    return dict(value)


def _reader_receipt_subject(value):
    if value is not None:
        _expected_subject(value)


def decode_reader_receipt_record(frame: bytes, expected_bundle_id: str | None) -> dict:
    """Parse intrinsic receipt claims; expected None matches only a null bundle.
    No bundle files are read/hashed and no actual inspection, validated counts, complete
    bundle, immutable Python/CLI pair, reader/public metadata provenance or freshness, trusted
    harness case association or witness is proved. These remain external gates;
    parsing grants no live authority, signal, retry or deadline reset.
    """
    _reader_receipt_subject(expected_bundle_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.READER_RECEIPT_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.READER_RECEIPT_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _reader_receipt_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if record['bundle_id'] != expected_bundle_id:
        raise ResultCodecError('wrong_subject')
    return record


def encode_reader_receipt_record(record: dict, expected_bundle_id: str | None) -> bytes:
    """Encode intrinsic receipt claims; expected None matches only a null bundle.
    No bundle files are read/hashed and no actual inspection, validated counts, complete
    bundle, immutable Python/CLI pair, reader/public metadata provenance or freshness, trusted
    harness case association or witness is proved. These remain external gates;
    encoding grants no live authority, signal, retry or deadline reset.
    """
    _reader_receipt_subject(expected_bundle_id)
    validated = _reader_receipt_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.READER_RECEIPT_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if validated['bundle_id'] != expected_bundle_id:
        raise ResultCodecError('wrong_subject')
    return encoded


def _public_manifest_count(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ResultCodecError('invalid_value')


def _public_manifest_record(value):
    _event_closed(value, contract.PUBLIC_MANIFEST_FIELDS)
    for key, kind in contract.PUBLIC_MANIFEST_SCALARS:
        item = value[key]
        if kind == 'bounded_bundle_bytes':
            _public_manifest_count(item, contract.PUBLIC_MANIFEST_TOTAL_BYTES_MAX)
        elif kind == 's43-public-bundle-v1':
            if type(item) is not str or len(item) > 64 or item != kind:
                raise ResultCodecError('invalid_value')
        else:
            _event_scalar(item, kind)
    members = value['members']
    if type(members) is not list:
        raise ResultCodecError('invalid_shape')
    if len(members) != len(contract.PUBLIC_MANIFEST_NAMES):
        raise ResultCodecError('invalid_value')
    for entry in members:
        _event_closed(entry, contract.PUBLIC_MANIFEST_ENTRY_FIELDS)
        name = entry['name']
        if type(name) is not str or len(name) > 18 or name not in contract.PUBLIC_MANIFEST_NAMES:
            raise ResultCodecError('invalid_value')
        byte_cap, record_cap = contract.PUBLIC_MANIFEST_MEMBER_LIMITS[name]
        _public_manifest_count(entry['bytes'], byte_cap)
        _event_scalar(entry['sha256'], 'sha256')
        _public_manifest_count(entry['records'], record_cap)
    if tuple(entry['name'] for entry in members) != contract.PUBLIC_MANIFEST_NAMES:
        raise ResultCodecError('invalid_value')
    result = dict(value)
    result['members'] = [dict(entry) for entry in members]
    return result


def decode_public_manifest_record(frame: bytes, expected_bundle_id: str) -> dict:
    """Parse bounded manifest grammar and caller-supplied subject equality only.
    No files, actual counts/hashes, accounting, digest links, provenance, inspection,
    valid bundle, completed witness or live authority are proved. Actual exporter/
    reader and bundle consistency require reviewed total_bytes/context_sha256
    semantics and all existing aggregate, owned-file, time and acceptance gates.
    No signal, retry or deadline reset is granted.
    """
    _expected_subject(expected_bundle_id)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if not 0 < len(frame) <= contract.PUBLIC_MANIFEST_MAX_BYTES or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    text = frame.decode('ascii')
    _depth(text, contract.PUBLIC_MANIFEST_MAX_DEPTH)
    malformed = False
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except json.JSONDecodeError:
        malformed = True
    if malformed:
        raise ResultCodecError('invalid_encoding')
    record = _public_manifest_record(value)
    if _canonical(record) != frame:
        raise ResultCodecError('invalid_encoding')
    if record['bundle_id'] != expected_bundle_id:
        raise ResultCodecError('wrong_subject')
    return record


def encode_public_manifest_record(record: dict, expected_bundle_id: str) -> bytes:
    """Encode intrinsic grammar claims only; no files, actual counts/hashes,
    accounting, digest links, provenance, inspection, valid bundle or witness.
    Actual exporter/reader and bundle consistency require reviewed total_bytes/
    context_sha256 semantics and all aggregate, owned-file, time and acceptance
    gates. Caller-supplied equality grants no live authority, signal, retry or
    deadline reset.
    """
    _expected_subject(expected_bundle_id)
    validated = _public_manifest_record(record)
    encoded = _canonical(validated)
    if len(encoded) > contract.PUBLIC_MANIFEST_MAX_BYTES:
        raise ResultCodecError('invalid_encoding')
    if validated['bundle_id'] != expected_bundle_id:
        raise ResultCodecError('wrong_subject')
    return encoded


def decode_public_manifest_claims(frame: bytes, expected_bundle_id: str) -> dict:
    """Check two manifest claim relations after bounded grammar validation.

    Agreement proves no actual payload bytes/counts, validated SHA256 input,
    digest-to-file equality, all-nine aggregate, ownership, provenance, valid
    bundle, completed witness or inspection. Claims never authorize reads,
    allocation or acceptance; all external reader and runtime gates remain.
    """
    record = decode_public_manifest_record(frame, expected_bundle_id)
    if record['total_bytes'] != sum(entry['bytes'] for entry in record['members']):
        raise ResultCodecError('invalid_result')
    if record['context_sha256'] != record['members'][2]['sha256']:
        raise ResultCodecError('invalid_result')
    return record


def decode_public_result_member(manifest_frame: bytes, result_frame: bytes,
                                expected_bundle_id: str, expected_operation_id: str) -> dict:
    """Link one validated result buffer to unauthenticated manifest claims.

    Caller-supplied identities do not prove a trusted bundle-operation association.
    No other payload, context hash, actual total/all-nine accounting, file ownership,
    provenance, authority, useful completion, reader/exporter, valid bundle or
    acceptance is proved. Only exact canonical result bytes reach hashing.
    """
    _expected_subject(expected_bundle_id)
    _expected_subject(expected_operation_id)
    manifest = decode_public_manifest_claims(manifest_frame, expected_bundle_id)
    result = decode_public_result(result_frame, expected_operation_id)
    entry = manifest['members'][6]  # The manifest decoder proves result.json's position.
    if entry['records'] != 1:
        raise ResultCodecError('invalid_result')
    if entry['bytes'] != len(result_frame):
        raise ResultCodecError('invalid_result')
    if entry['sha256'] != hashlib.sha256(result_frame).hexdigest():
        raise ResultCodecError('invalid_result')
    return result


def decode_progress_jsonl(frame: bytes, expected_subjects: tuple) -> list[dict]:
    """Parse bounded framing and intrinsic progress claims with positional IDs.

    Caller equality proves no authenticated chronology, producer/sample limits,
    uniqueness, sequence/counter consistency, registry/session/clock/runtime
    provenance, actual progress, interval coverage, remote delivery, physical
    closure, recovery eligibility or authority. Empty means zero grammatical
    records, never a valid witness. No file read/ownership, hashing, manifest or
    bundle proof, reader/exporter or acceptance is granted.
    """
    byte_cap, record_cap = contract.PUBLIC_MANIFEST_MEMBER_LIMITS['progress.jsonl']
    if type(expected_subjects) is not tuple:
        raise ResultCodecError('invalid_shape')
    if len(expected_subjects) > record_cap:
        raise ResultCodecError('invalid_value')
    for expected in expected_subjects:
        if type(expected) is not tuple or len(expected) != 4:
            raise ResultCodecError('invalid_shape')
        _progress_subjects(*expected)
    if type(frame) is not bytes:
        raise ResultCodecError('invalid_shape')
    if len(frame) > byte_cap or not frame.isascii():
        raise ResultCodecError('invalid_encoding')
    lines = []
    if frame:
        if not frame.endswith(b'\n') or b'\r' in frame or frame.count(b'\n') > record_cap:
            raise ResultCodecError('invalid_encoding')
        lines = frame[:-1].split(b'\n')
        if any(not line or len(line) > contract.PROGRESS_MAX_BYTES for line in lines):
            raise ResultCodecError('invalid_encoding')
    if len(lines) != len(expected_subjects):
        raise ResultCodecError('invalid_result')
    return [decode_progress_record(line, *expected)
            for line, expected in zip(lines, expected_subjects)]


def decode_progress_producer_claims(frame: bytes, expected_subjects: tuple) -> list[dict]:
    """Check sequence/counter consistency within one claimed producer identity.

    Expected owner/operation/graph/record tuples follow decode_progress_jsonl.
    Agreement authenticates no producer, registry/session/clock/runtime identity,
    complete progress, milestone/interval coverage, closure or authority. Grouping,
    aggregate48 compliance, recovery budgets and record-ID uniqueness remain
    external. Empty claims are not a witness. No hashing, export or acceptance is
    granted; nulls remain unknown and never reset a prior cumulative claim.
    """
    records = decode_progress_jsonl(frame, expected_subjects)
    if len(records) > 16:
        raise ResultCodecError('invalid_result')
    if not records:
        return records
    fields = ('owner_id', 'operation_id', 'graph_id', 'issuer_instance_id', 'issuer_role',
              'session_id', 'clock_epoch_id', 'runtime_lock_sha256', 'perspective')
    identity = tuple(records[0][key] for key in fields)
    previous_sequence = 0
    last_known = {}
    for record in records:
        if tuple(record[key] for key in fields) != identity:
            raise ResultCodecError('invalid_result')
        if record['sample_sequence'] <= previous_sequence:
            raise ResultCodecError('invalid_result')
        previous_sequence = record['sample_sequence']
        for key in contract.PROGRESS_COUNTER_FIELDS:
            value = record[key]
            if value is not None:
                if key in last_known and value < last_known[key]:
                    raise ResultCodecError('invalid_result')
                last_known[key] = value
    return records
