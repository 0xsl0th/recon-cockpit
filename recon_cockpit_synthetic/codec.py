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
