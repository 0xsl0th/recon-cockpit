"""Seventy-six codec unit nodes; these do not satisfy any formal S4.3 acceptance node."""

import json

import pytest

import recon_cockpit_synthetic.codec as codec


SUBJECT = '12345678-1234-4234-9234-123456789abc'
OTHER = '22345678-1234-4234-9234-123456789abc'
# Independent expectations: do not import the production contract tables.
RELATIONS = (
    ('ready', 'recon-owned-status-v1', 'ready', 200),
    ('degraded', 'recon-owned-status-v1', 'degraded', 200),
    ('authentication_refused', None, None, 401),
    ('authorization_refused', None, None, 403),
    ('authority_refused', None, None, None),
    ('tls_refused', None, None, None),
    ('invalid_response', None, None, None),
    ('unsupported_response', None, None, None),
    ('limit_exceeded', None, None, None),
    ('cancelled', None, None, None),
    ('interrupted_unknown', None, None, None),
    ('cleanup_failed', None, None, None),
)
READY_BYTES = (
    b'{"http_status":200,"operation_id":"12345678-1234-4234-9234-123456789abc",'
    b'"outcome":"ready","schema_version":"1",'
    b'"service_identifier":"recon-owned-status-v1","service_status":"ready"}'
)


def _record(row=RELATIONS[0]):
    outcome, identifier, status, http = row
    return dict(schema_version='1', operation_id=SUBJECT, outcome=outcome,
                service_identifier=identifier, service_status=status, http_status=http)


def _wire(record):
    return json.dumps(record, sort_keys=True, separators=(',', ':')).encode('ascii')


def _reject(call, code):
    with pytest.raises(codec.ResultCodecError) as caught:
        call()
    assert str(caught.value) == code
    assert caught.value.args == (code,)
    assert 'RAW_SENTINEL' not in str(caught.value)
    return caught.value


def _reject_record(record, code):
    _reject(lambda: codec.encode_public_result(record, SUBJECT), code)
    _reject(lambda: codec.decode_public_result(_wire(record), SUBJECT), code)


def test_public_result_canonical_examples():
    assert codec.encode_public_result(_record(), SUBJECT) == READY_BYTES
    assert codec.decode_public_result(READY_BYTES, SUBJECT) == _record()
    for row in RELATIONS:
        record = _record(row)
        wire = _wire(record)
        assert codec.encode_public_result(record, SUBJECT) == wire
        first = codec.decode_public_result(wire, SUBJECT)
        second = codec.decode_public_result(wire, SUBJECT)
        assert first == second == record and first is not second
        first['outcome'] = 'mutated'
        assert second == record
    # Insertion order is immaterial to encode, but bytes from decode are exact.
    assert codec.encode_public_result(dict(reversed(list(_record().items()))), SUBJECT) == READY_BYTES


def test_public_result_shape_and_scalar_rejections():
    for value in (None, True, 1, 'RAW_SENTINEL', [], [1]):
        _reject_record(value, 'invalid_shape')
    _reject(lambda: codec.encode_public_result(1.5, SUBJECT), 'invalid_shape')
    _reject(lambda: codec.decode_public_result(b'1.5', SUBJECT), 'invalid_value')
    for field in _record():
        record = _record()
        del record[field]
        _reject_record(record, 'invalid_shape')
        record = _record()
        record['RAW_SENTINEL'] = record.pop(field)
        _reject_record(record, 'invalid_shape')
    _reject_record(dict(_record(), extra='RAW_SENTINEL'), 'invalid_shape')
    oversized = {'X' * 1025: 0}
    _reject(lambda: codec.encode_public_result(oversized, SUBJECT), 'invalid_shape')
    _reject(lambda: codec.decode_public_result(_wire(oversized), SUBJECT), 'invalid_encoding')
    invalid = {
        'schema_version': [None, 1, True, '2', '', [], {}],
        'operation_id': [None, 1, True, '', SUBJECT.upper(), 'not-a-uuid', [], {}],
        'outcome': [None, True, 1, '', 'RAW_SENTINEL', [], {}],
        'service_identifier': [True, 1, '', 'RAW_SENTINEL', [], {}],
        'service_status': [True, 1, '', 'RAW_SENTINEL', [], {}],
        'http_status': [True, False, 200.0, '200', 0, 201, [], {}],
    }
    for field, values in invalid.items():
        for value in values:
            _reject_record(dict(_record(), **{field: value}), 'invalid_value')
    for field in _record():
        _reject(lambda: codec.encode_public_result(dict(_record(), **{field: 'x' * 2048}), SUBJECT),
                'invalid_value')
    for field in _record():
        wire = _wire(_record())
        duplicate = b'{' + json.dumps(field).encode() + b':null,' + wire[1:]
        _reject(lambda: codec.decode_public_result(duplicate, SUBJECT), 'invalid_shape')
    duplicate_escaped = b'{"outcom\\u0065":"ready",' + READY_BYTES[1:]
    _reject(lambda: codec.decode_public_result(duplicate_escaped, SUBJECT), 'invalid_shape')


def test_public_result_relation_rejections():
    # Exhaustive finite combinations of allowed enums/nulls, separately from types.
    for row in RELATIONS:
        for identifier in (None, 'recon-owned-status-v1'):
            for status in (None, 'ready', 'degraded'):
                for http in (None, 200, 401, 403):
                    candidate = (row[0], identifier, status, http)
                    if candidate != row:
                        _reject_record(_record(candidate), 'invalid_result')


def test_public_result_encoding_and_bounds():
    malformed = (
        b'', b' ', b'RAW_SENTINEL', b'{', b'}', b'[]]',
        b'{"outcome":"RAW_SENTINEL', b'{"outcome":"\\q"}',
        b'\xef\xbb\xbf' + READY_BYTES, b'\xff',
        READY_BYTES + b'\n', b' ' + READY_BYTES, READY_BYTES + b'{}',
        READY_BYTES.replace(b':200', b': 200'),
        READY_BYTES.replace(b'"ready"', b'"re\\u0061dy"'),
        json.dumps(_record(), sort_keys=False, separators=(',', ':')).encode(),
    )
    for frame in malformed:
        err = _reject(lambda: codec.decode_public_result(frame, SUBJECT), 'invalid_encoding')
        assert err.__context__ is None
    for number in (b'200.0', b'2e2', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_public_result(READY_BYTES.replace(b'200', number), SUBJECT),
                'invalid_value')
    huge = READY_BYTES.replace(b'200', b'9' * 800)
    assert len(huge) <= 1024
    _reject(lambda: codec.decode_public_result(huge, SUBJECT), 'invalid_value')
    for frame in (bytearray(READY_BYTES), memoryview(READY_BYTES), READY_BYTES.decode(), None):
        _reject(lambda: codec.decode_public_result(frame, SUBJECT), 'invalid_shape')
    original_loads = json.loads
    calls = []

    def observed_loads(*args, **kwargs):
        calls.append(1)
        return original_loads(*args, **kwargs)

    json.loads = observed_loads
    try:
        for frame in (b'x' * 1025, b'[' * 13 + b']' * 13,
                      b'{"x":' + b'[' * 12 + b'0' + b']' * 12 + b'}'):
            _reject(lambda: codec.decode_public_result(frame, SUBJECT), 'invalid_encoding')
            assert not calls
        # At the depth/byte boundaries the parser may run; shape still fails.
        _reject(lambda: codec.decode_public_result(b'[' * 12 + b'0' + b']' * 12, SUBJECT),
                'invalid_shape')
        assert len(calls) == 1
        _reject(lambda: codec.decode_public_result(b' ' * 1024, SUBJECT), 'invalid_encoding')
        assert len(calls) == 2
        for value in ('[' * 40, '\\"' + '[' * 40, '\\\\' + ']' * 40):
            frame = _wire(dict(_record(), outcome=value))
            _reject(lambda: codec.decode_public_result(frame, SUBJECT), 'invalid_value')
        assert len(calls) == 5
    finally:
        json.loads = original_loads


def test_public_result_subject_binding():
    _reject(lambda: codec.decode_public_result(READY_BYTES, OTHER), 'wrong_subject')
    _reject(lambda: codec.encode_public_result(_record(), OTHER), 'wrong_subject')
    _reject(lambda: codec.decode_public_result(READY_BYTES + b' ', OTHER), 'invalid_encoding')
    invalid_subjects = ('', 'x' * 2048, SUBJECT.upper(), SUBJECT.replace('-4234-', '-1234-'),
                        SUBJECT.replace('-9234-', '-7234-'), '{' + SUBJECT + '}', SUBJECT + '\n')
    for value in invalid_subjects:
        _reject(lambda: codec.decode_public_result(READY_BYTES, value), 'invalid_value')
        _reject(lambda: codec.encode_public_result(_record(), value), 'invalid_value')
        if len(value) < 100:
            _reject_record(dict(_record(), operation_id=value), 'invalid_value')
    for value in (None, True, 1, [], {}):
        _reject(lambda: codec.decode_public_result(READY_BYTES, value), 'invalid_shape')
        _reject(lambda: codec.encode_public_result(_record(), value), 'invalid_shape')


def test_public_result_type_hooks():
    def forbidden(*args, **kwargs):
        raise AssertionError('Untrusted object hook executed')

    class HostileString(str):
        __len__ = __eq__ = __str__ = forbidden
        __hash__ = str.__hash__

    class HostileInt(int):
        __eq__ = __str__ = forbidden

    class HostileDict(dict):
        __len__ = __iter__ = __getitem__ = forbidden

    class HostileBytes(bytes):
        __len__ = isascii = decode = forbidden

    class HostileObject:
        __eq__ = __str__ = __repr__ = forbidden

    for obj in (HostileDict(_record()), HostileObject()):
        _reject(lambda: codec.encode_public_result(obj, SUBJECT), 'invalid_shape')
    for field in _record():
        for obj in (HostileString('ready'), HostileInt(200), HostileObject()):
            _reject(lambda: codec.encode_public_result(dict(_record(), **{field: obj}), SUBJECT),
                    'invalid_value')
    for obj in (HostileString(SUBJECT), HostileObject()):
        _reject(lambda: codec.encode_public_result(_record(), obj), 'invalid_shape')
        _reject(lambda: codec.decode_public_result(READY_BYTES, obj), 'invalid_shape')
    _reject(lambda: codec.decode_public_result(HostileBytes(READY_BYTES), SUBJECT), 'invalid_shape')
    record = _record()
    value = record.pop('outcome')
    record[HostileString('outcome')] = value
    _reject(lambda: codec.encode_public_result(record, SUBJECT), 'invalid_shape')


def _roe():
    return {
        'active_operation_limit': 1, 'allowed_fixture_ids': ['allowed'],
        'budgets': {'actions': 64, 'connections': 64, 'inbound_tls_bytes': 1048576,
                    'outbound_tls_bytes': 524288, 'runtime_ms': 320000},
        'engagement_id': SUBJECT, 'excluded_operations': [],
        'expires_utc': '2026-11-19T00:00:00.000000Z',
        'included_operations': ['synthetic-service-status-v1'],
        'not_before_utc': '2026-11-18T00:00:00.000000Z',
        'operation_profile_sha256': 'b0e32be82eb77085db8fed7a165cab5c13ca2219247958f69dfe0ed8fc47d5e2',
        'previous_revision_sha256': None, 'revision': 1,
        'runtime_lock_sha256': 'b' * 64, 'schema_version': 's43-roe-v1',
        'trust_sha256': 'c' * 64,
    }


def _roe_roundtrip(record):
    expected = _wire(record)
    assert codec.encode_public_roe(record, SUBJECT) == expected
    assert codec.decode_public_roe(expected, SUBJECT) == record


def _roe_reject(record, code, decode_code=None):
    _reject(lambda: codec.encode_public_roe(record, SUBJECT), code)
    _reject(lambda: codec.decode_public_roe(_wire(record), SUBJECT), decode_code or code)


def test_public_roe_canonical_examples():
    literal = (
        b'{"active_operation_limit":1,"allowed_fixture_ids":["allowed"],'
        b'"budgets":{"actions":64,"connections":64,"inbound_tls_bytes":1048576,'
        b'"outbound_tls_bytes":524288,"runtime_ms":320000},'
        b'"engagement_id":"12345678-1234-4234-9234-123456789abc",'
        b'"excluded_operations":[],"expires_utc":"2026-11-19T00:00:00.000000Z",'
        b'"included_operations":["synthetic-service-status-v1"],'
        b'"not_before_utc":"2026-11-18T00:00:00.000000Z",'
        b'"operation_profile_sha256":"b0e32be82eb77085db8fed7a165cab5c13ca2219247958f69dfe0ed8fc47d5e2",'
        b'"previous_revision_sha256":null,"revision":1,"runtime_lock_sha256":"'
        + b'b' * 64 + b'","schema_version":"s43-roe-v1","trust_sha256":"'
        + b'c' * 64 + b'"}'
    )
    assert codec.encode_public_roe(_roe(), SUBJECT) == literal
    assert codec.decode_public_roe(literal, SUBJECT) == _roe()
    first = codec.decode_public_roe(literal, SUBJECT)
    second = codec.decode_public_roe(literal, SUBJECT)
    first['budgets']['actions'] = 0
    first['allowed_fixture_ids'].clear()
    first['included_operations'].clear()
    first['excluded_operations'].append('synthetic-service-status-v1')
    assert second == _roe()
    for fixtures in ([], ['allowed'], ['invalid'], ['restricted'], ['allowed', 'invalid'],
                     ['allowed', 'restricted'], ['invalid', 'restricted'],
                     ['allowed', 'invalid', 'restricted']):
        for excluded in ([], ['synthetic-service-status-v1']):
            record = _roe()
            record['allowed_fixture_ids'] = fixtures
            record['excluded_operations'] = excluded
            record['budgets'] = {key: 0 for key in record['budgets']}
            _roe_roundtrip(record)  # Empty/excluded/unfunded policies are still valid records.
    record = _roe()
    record.update(revision=2147483647, previous_revision_sha256='d' * 64,
                  not_before_utc='0001-01-01T00:00:00.000000Z',
                  expires_utc='9999-12-31T23:59:59.999999Z')
    _roe_roundtrip(record)


def test_public_roe_shape_and_type_rejections():
    for value in (None, True, 1, [], 'RAW_SENTINEL'):
        _roe_reject(value, 'invalid_shape')
    for field in _roe():
        value = _roe()
        del value[field]
        _roe_reject(value, 'invalid_shape')
        value['RAW_SENTINEL'] = None
        _roe_reject(value, 'invalid_shape')
    _roe_reject(dict(_roe(), extra='RAW_SENTINEL'), 'invalid_shape')
    for field in ('schema_version', 'engagement_id', 'operation_profile_sha256',
                  'runtime_lock_sha256', 'trust_sha256', 'not_before_utc', 'expires_utc'):
        for value in (None, True, 1, '', [], {}, 'RAW_SENTINEL'):
            _roe_reject(dict(_roe(), **{field: value}), 'invalid_value')
    for field in ('revision', 'active_operation_limit'):
        for value in (None, True, False, 1.0, '1', [], {}):
            _roe_reject(dict(_roe(), **{field: value}), 'invalid_value')
    for field in ('allowed_fixture_ids', 'included_operations', 'excluded_operations'):
        for value in (None, 'allowed', 1, True, {}, [1], [True], ['RAW_SENTINEL']):
            _roe_reject(dict(_roe(), **{field: value}), 'invalid_value')
    for value in (None, True, 1, [], {}, dict(_roe()['budgets'], extra=1)):
        _roe_reject(dict(_roe(), budgets=value), 'invalid_shape')
    for field in _roe()['budgets']:
        record = _roe()
        record['budgets']['RAW_SENTINEL'] = record['budgets'].pop(field)
        _roe_reject(record, 'invalid_shape')
    # Reject hostile subclasses before any user-defined hooks, also when nested.
    def forbidden(*args, **kwargs):
        raise AssertionError('Untrusted ROE hook executed')

    class HostileDict(dict):
        __len__ = __iter__ = __getitem__ = forbidden

    class HostileList(list):
        __len__ = __iter__ = __eq__ = forbidden

    class HostileString(str):
        __len__ = __eq__ = __str__ = forbidden
        __hash__ = str.__hash__

    class HostileInt(int):
        __eq__ = __lt__ = __le__ = forbidden

    _reject(lambda: codec.encode_public_roe(HostileDict(_roe()), SUBJECT), 'invalid_shape')
    _reject(lambda: codec.encode_public_roe(dict(_roe(), budgets=HostileDict()), SUBJECT), 'invalid_shape')
    for field in ('included_operations', 'excluded_operations', 'allowed_fixture_ids'):
        _reject(lambda: codec.encode_public_roe(dict(_roe(), **{field: HostileList()}), SUBJECT), 'invalid_value')
        _reject(lambda: codec.encode_public_roe(dict(_roe(), **{field: [HostileString('allowed')]}), SUBJECT), 'invalid_value')
    for field in ('schema_version', 'engagement_id', 'previous_revision_sha256'):
        _reject(lambda: codec.encode_public_roe(dict(_roe(), **{field: HostileString('x')}), SUBJECT), 'invalid_value')
    record = _roe()
    record['budgets']['actions'] = HostileInt(1)
    _reject(lambda: codec.encode_public_roe(record, SUBJECT), 'invalid_value')
    record = _roe()
    value = record.pop('revision')
    record[HostileString('revision')] = value
    _reject(lambda: codec.encode_public_roe(record, SUBJECT), 'invalid_shape')


def test_public_roe_bounds_and_fixture_order():
    for field, maximum in (('actions', 64), ('connections', 64), ('inbound_tls_bytes', 1048576),
                           ('outbound_tls_bytes', 524288), ('runtime_ms', 320000)):
        for value in (0, maximum):
            record = _roe()
            record['budgets'][field] = value
            _roe_roundtrip(record)
        for value in (-1, maximum + 1, True, float(maximum), str(maximum)):
            record = _roe()
            record['budgets'][field] = value
            _roe_reject(record, 'invalid_value')
    for value in (0, -1, 2147483648):
        _roe_reject(dict(_roe(), revision=value), 'invalid_value')
    for value in (0, 2, -1):
        _roe_reject(dict(_roe(), active_operation_limit=value), 'invalid_value')
    for fixtures in (['allowed', 'allowed'], ['invalid', 'allowed'], ['restricted', 'invalid'],
                     ['allowed', 'restricted', 'invalid']):
        _roe_reject(dict(_roe(), allowed_fixture_ids=fixtures), 'invalid_result')
    _roe_reject(dict(_roe(), allowed_fixture_ids=['allowed'] * 4), 'invalid_value')
    _roe_reject(dict(_roe(), included_operations=[]), 'invalid_value')
    for field in ('included_operations', 'excluded_operations'):
        _roe_reject(dict(_roe(), **{field: ['synthetic-service-status-v1'] * 2}), 'invalid_value')
    for field in ('trust_sha256', 'runtime_lock_sha256', 'operation_profile_sha256'):
        for value in ('a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, 'a' * 63 + '\n'):
            _roe_reject(dict(_roe(), **{field: value}), 'invalid_value')
    _roe_reject(dict(_roe(), operation_profile_sha256='a' * 64), 'invalid_value')
    for field in ('engagement_id', 'runtime_lock_sha256', 'not_before_utc'):
        _reject(lambda: codec.encode_public_roe(dict(_roe(), **{field: 'x' * 4097}), SUBJECT), 'invalid_value')
    _reject(lambda: codec.encode_public_roe(dict(_roe(), allowed_fixture_ids=['allowed'] * 4097), SUBJECT), 'invalid_value')


def test_public_roe_calendar_and_revision_relations():
    invalid_dates = (
        '0000-01-01T00:00:00.000000Z', '1900-02-29T00:00:00.000000Z',
        '2100-02-29T00:00:00.000000Z', '2025-02-29T00:00:00.000000Z',
        '2026-04-31T00:00:00.000000Z', '2026-00-01T00:00:00.000000Z',
        '2026-13-01T00:00:00.000000Z', '2026-01-00T00:00:00.000000Z',
        '2026-01-01T24:00:00.000000Z', '2026-01-01T00:60:00.000000Z',
        '2026-01-01T00:00:60.000000Z', '2026-01-01T00:00:00.00000Z',
        '2026-01-01T00:00:00.0000000Z', '2026-01-01T00:00:00.000000+00:00',
        '2026-1-01T00:00:00.000000Z', '2026-01-01 00:00:00.000000Z',
        '2026-01-01T00:00:00.000000z', '10000-01-01T00:00:00.000000Z',
    )
    for field in ('not_before_utc', 'expires_utc'):
        for value in invalid_dates:
            record = dict(_roe(), **{field: value})
            err = _reject(lambda: codec.encode_public_roe(record, SUBJECT), 'invalid_value')
            assert err.__context__ is None
            _reject(lambda: codec.decode_public_roe(_wire(record), SUBJECT), 'invalid_value')
    for start in ('2000-02-29T00:00:00.000000Z', '2024-02-29T00:00:00.000000Z'):
        _roe_roundtrip(dict(_roe(), not_before_utc=start))
    record = _roe()
    _roe_reject(dict(record, expires_utc=record['not_before_utc']), 'invalid_result')
    _roe_reject(dict(record, not_before_utc=record['expires_utc'], expires_utc=record['not_before_utc']), 'invalid_result')
    _roe_roundtrip(dict(record, expires_utc='2026-11-18T00:00:00.000001Z'))
    _roe_reject(dict(record, previous_revision_sha256='a' * 64), 'invalid_result')
    _roe_reject(dict(record, revision=2), 'invalid_result')
    _roe_roundtrip(dict(record, revision=2, previous_revision_sha256='a' * 64))
    for value in (True, 1, [], {}, '', 'a' * 63, 'A' * 64):
        _roe_reject(dict(record, revision=2, previous_revision_sha256=value), 'invalid_value')


def test_public_roe_encoding_and_depth():
    wire = _wire(_roe())
    for frame in (wire + b'\n', b' ' + wire, wire + b'{}', wire.replace(b':1,', b': 1,'),
                  wire.replace(b's43-roe-v1', b's43-roe-v\\u0031'), b'\xef\xbb\xbf' + wire,
                  b'\xff', b'{"RAW_SENTINEL":', b'{"x":"\\q"}'):
        err = _reject(lambda: codec.decode_public_roe(frame, SUBJECT), 'invalid_encoding')
        assert err.__context__ is None
    for field in _roe():
        duplicate = b'{' + json.dumps(field).encode() + b':null,' + wire[1:]
        _reject(lambda: codec.decode_public_roe(duplicate, SUBJECT), 'invalid_shape')
    _reject(lambda: codec.decode_public_roe(wire.replace(b'"actions":64', b'"actions":64,"actions":64'), SUBJECT), 'invalid_shape')
    for number in (b'1.0', b'1e0', b'NaN', b'Infinity'):
        _reject(lambda: codec.decode_public_roe(wire.replace(b'"revision":1', b'"revision":' + number), SUBJECT), 'invalid_value')
    for frame in (None, bytearray(wire), memoryview(wire), wire.decode()):
        _reject(lambda: codec.decode_public_roe(frame, SUBJECT), 'invalid_shape')
    original_loads = json.loads
    calls = []

    def observed_loads(*args, **kwargs):
        calls.append(1)
        return original_loads(*args, **kwargs)

    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'[[[]]]', b'{"x":{"y":{}}}'):
            _reject(lambda: codec.decode_public_roe(frame, SUBJECT), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_public_roe(b' ' * 4096, SUBJECT), 'invalid_encoding')
        assert len(calls) == 1
        for value in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _reject(lambda: codec.decode_public_roe(_wire(dict(_roe(), schema_version=value)), SUBJECT), 'invalid_value')
        assert len(calls) == 4
        assert codec.decode_public_roe(wire, SUBJECT) == _roe()
    finally:
        json.loads = original_loads


def test_public_roe_subject_binding():
    wire = _wire(_roe())
    _reject(lambda: codec.decode_public_roe(wire, OTHER), 'wrong_subject')
    _reject(lambda: codec.encode_public_roe(_roe(), OTHER), 'wrong_subject')
    _reject(lambda: codec.decode_public_roe(wire + b' ', OTHER), 'invalid_encoding')
    for value in ('', SUBJECT.upper(), SUBJECT.replace('-4234-', '-1234-'),
                  SUBJECT.replace('-9234-', '-7234-'), SUBJECT + '\n'):
        _reject(lambda: codec.decode_public_roe(wire, value), 'invalid_value')
        _reject(lambda: codec.encode_public_roe(_roe(), value), 'invalid_value')
        _roe_reject(dict(_roe(), engagement_id=value), 'invalid_value')
    for value in (None, True, 1, [], {}):
        _reject(lambda: codec.decode_public_roe(wire, value), 'invalid_shape')
        _reject(lambda: codec.encode_public_roe(_roe(), value), 'invalid_shape')


LEASE_ID = '32345678-1234-4234-9234-123456789abc'
LEASE_UUID_KEYS = (
    'approval_id', 'broker_id', 'clock_epoch_id', 'credential_reference',
    'engagement_id', 'lease_id', 'operation_id', 'reviewer_id', 'session_id', 'store_owner_id',
)
LEASE_LINK_KEYS = ('closure_event_id', 'completion_event_id', 'release_event_id', 'reservation_id')
LEASE_HASH_KEYS = ('action_sha256', 'operation_profile_sha256', 'request_template_sha256',
                   'roe_sha256', 'runtime_lock_sha256', 'trust_sha256')
LEASE_TIME_KEYS = ('operation_started_ns', 'work_deadline_ns', 'cleanup_deadline_ns')
LEASE_STATES = (
    ('prepared', None, False), ('reserved', None, False), ('released', None, True),
    ('closed', 'unadmitted', False), ('closed', 'unreleased', False),
    ('closed', 'completed', False), ('closed', 'completed', True),
    ('closed', 'interrupted_unknown', False), ('closed', 'interrupted_unknown', True),
)


def _lease(state='prepared', kind=None, released=False):
    record = {
        'action_sha256': 'a' * 64,
        'approval_id': SUBJECT, 'broker_id': SUBJECT, 'cancel_requested': False,
        'cleanup_deadline_ns': None, 'clock_epoch_id': SUBJECT, 'close_kind': kind,
        'closure_event_id': None, 'completion_event_id': None,
        'credential_reference': SUBJECT, 'engagement_id': SUBJECT,
        'expires_utc': '2024-02-29T23:59:59.123456Z', 'fixture_id': 'allowed',
        'generation': 0, 'lease_id': LEASE_ID, 'operation_id': OTHER,
        'operation_profile_sha256': 'b0e32be82eb77085db8fed7a165cab5c13ca2219247958f69dfe0ed8fc47d5e2',
        'operation_started_ns': None, 'prepared_utc': '2024-02-29T23:59:29.123456Z',
        'release_event_id': None, 'request_template_sha256': 'b' * 64,
        'reservation_id': None, 'review_view': 'terminal', 'reviewer_id': SUBJECT,
        'revision': 1, 'roe_sha256': 'c' * 64, 'runtime_lock_sha256': 'd' * 64,
        'schema_version': 's43-lease-v1', 'session_id': SUBJECT, 'state': state,
        'store_owner_id': SUBJECT, 'trust_sha256': 'e' * 64, 'work_deadline_ns': None,
    }
    if state in ('reserved', 'released') or (state == 'closed' and kind != 'unadmitted'):
        record.update(reservation_id=SUBJECT, operation_started_ns=0,
                      work_deadline_ns=4000000000, cleanup_deadline_ns=5000000000)
    if state == 'released' or released:
        record['release_event_id'] = SUBJECT
    if state == 'closed':
        record['closure_event_id'] = SUBJECT
        if kind == 'completed':
            record['completion_event_id'] = SUBJECT
    return record


def _lease_accept(record):
    wire = _wire(record)
    assert codec.encode_public_lease(record, SUBJECT, OTHER, LEASE_ID) == wire
    decoded = codec.decode_public_lease(wire, SUBJECT, OTHER, LEASE_ID)
    assert decoded == record and type(decoded) is dict and decoded is not record
    return decoded


def _lease_reject(record, code):
    _reject(lambda: codec.encode_public_lease(record, SUBJECT, OTHER, LEASE_ID), code)
    return _reject(lambda: codec.decode_public_lease(_wire(record), SUBJECT, OTHER, LEASE_ID), code)


def test_public_lease_canonical_examples():
    for state, kind, released in LEASE_STATES:
        for cancel in (False, True):
            for fixture in ('allowed', 'invalid', 'restricted'):
                for view in ('terminal', 'graphical'):
                    record = dict(_lease(state, kind, released), cancel_requested=cancel,
                                  fixture_id=fixture, review_view=view)
                    decoded = _lease_accept(record)
                    decoded['revision'] = 99
                    assert record['revision'] == 1
                    assert _lease_accept(record)['revision'] == 1
    # Identical syntactic IDs in unrelated reference fields are not a new ban.
    assert _lease_accept(_lease())['approval_id'] == SUBJECT


def test_public_lease_shape_and_type_rejections():
    for value in (None, True, 1, 'RAW_SENTINEL', [], {}):
        _lease_reject(value, 'invalid_shape')
    record = _lease()
    for key in record:
        missing = dict(record)
        del missing[key]
        _lease_reject(missing, 'invalid_shape')
        wrong = (0, 1, 'false', None) if key == 'cancel_requested' else (True, 1.0)
        for bad in wrong:
            _lease_reject(dict(record, **{key: bad}), 'invalid_value')
        if key not in LEASE_LINK_KEYS + LEASE_TIME_KEYS + ('close_kind',):
            _lease_reject(dict(record, **{key: None}), 'invalid_value')
        for bad in ([], {}, object()):
            _reject(lambda: codec.encode_public_lease(dict(record, **{key: bad}), SUBJECT, OTHER, LEASE_ID), 'invalid_value')
    _lease_reject(dict(record, extra='RAW_SENTINEL'), 'invalid_shape')
    renamed = dict(record)
    renamed['RAW_SENTINEL'] = renamed.pop('revision')
    _lease_reject(renamed, 'invalid_shape')
    for key in (1, 'x' * 10000):
        bad = dict(record)
        del bad['revision']
        bad[key] = 1
        _reject(lambda: codec.encode_public_lease(bad, SUBJECT, OTHER, LEASE_ID), 'invalid_shape')

    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')

    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')

    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')

    _reject(lambda: codec.encode_public_lease(DictHook(record), SUBJECT, OTHER, LEASE_ID), 'invalid_shape')
    for key in record:
        bad = IntHook(1) if key in LEASE_TIME_KEYS + ('revision', 'generation') else StringHook('x')
        _reject(lambda: codec.encode_public_lease(dict(record, **{key: bad}), SUBJECT, OTHER, LEASE_ID), 'invalid_value')
    keys = dict(record)
    keys[StringHook('revision')] = keys.pop('revision')
    _reject(lambda: codec.encode_public_lease(keys, SUBJECT, OTHER, LEASE_ID), 'invalid_shape')


def test_public_lease_scalar_bounds():
    for key, minimum in (('revision', 1), ('generation', 0)):
        for good in (minimum, 2147483647):
            _lease_accept(dict(_lease(), **{key: good}))
        for bad in (minimum - 1, 2147483648, 10 ** 200, '1', True, 1.0):
            _lease_reject(dict(_lease(), **{key: bad}), 'invalid_value')
    for key in LEASE_TIME_KEYS:
        for bad in (-1, 9223372036854775808, 10 ** 200, '1', True, 1.0):
            _lease_reject(dict(_lease('reserved'), **{key: bad}), 'invalid_value')
    for key in LEASE_UUID_KEYS + LEASE_LINK_KEYS:
        for bad in ('', SUBJECT.upper(), SUBJECT + '\n', SUBJECT[:-1],
                    SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-')):
            _lease_reject(dict(_lease('closed', 'completed', True), **{key: bad}), 'invalid_value')
    for key in LEASE_HASH_KEYS:
        for bad in ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, 'a' * 64 + '\n'):
            _lease_reject(dict(_lease(), **{key: bad}), 'invalid_value')
    _lease_reject(dict(_lease(), operation_profile_sha256='a' * 64), 'invalid_value')
    for key in ('schema_version', 'fixture_id', 'review_view', 'state', 'close_kind'):
        for bad in ('RAW_SENTINEL', 'x' * 65, '', 'prepared\n'):
            _lease_reject(dict(_lease(), **{key: bad}), 'invalid_value')


def test_public_lease_calendar_and_deadlines():
    for start, end in (
        ('0001-01-01T00:00:00.000000Z', '0001-01-01T00:00:00.000001Z'),
        ('2000-02-28T23:59:59.999999Z', '2000-02-29T00:00:00.000000Z'),
        ('2024-12-31T23:59:45.000000Z', '2025-01-01T00:00:15.000000Z'),
        ('9999-12-31T23:59:29.999999Z', '9999-12-31T23:59:59.999999Z'),
    ):
        _lease_accept(dict(_lease(), prepared_utc=start, expires_utc=end))
    invalid = ('0000-01-01T00:00:00.000000Z', '10000-01-01T00:00:00.000000Z',
               '1900-02-29T00:00:00.000000Z', '2100-02-29T00:00:00.000000Z',
               '2023-02-29T00:00:00.000000Z', '2024-04-31T00:00:00.000000Z',
               '2024-00-01T00:00:00.000000Z', '2024-13-01T00:00:00.000000Z',
               '2024-01-00T00:00:00.000000Z', '2024-01-01T24:00:00.000000Z',
               '2024-01-01T00:60:00.000000Z', '2024-01-01T00:00:60.000000Z',
               '2024-01-01T00:00:00.00000Z', '2024-01-01T00:00:00.0000000Z',
               '2024-01-01T00:00:00.000000+00:00', '2024-01-01T00:00:00.000000Z\n')
    for key in ('prepared_utc', 'expires_utc'):
        for bad in invalid:
            error = _lease_reject(dict(_lease(), **{key: bad}), 'invalid_value')
            assert error.__context__ is None
    for end in ('2024-02-29T23:59:29.123456Z', '2024-02-29T23:59:29.123455Z',
                '2024-02-29T23:59:59.123457Z', '2025-02-28T23:59:59.123456Z'):
        _lease_reject(dict(_lease(), expires_utc=end), 'invalid_result')
    for start, work, cleanup in (
        (0, 4000000000, 5000000000), (0, 1, 1000000001),
        (7, 2000000007, 3000000007),
        (9223372031854775807, 9223372035854775807, 9223372036854775807),
        (9223372035854775806, 9223372035854775807, 9223372036854775807),
    ):
        _lease_accept(dict(_lease('reserved'), operation_started_ns=start,
                           work_deadline_ns=work, cleanup_deadline_ns=cleanup))
    for start, work, cleanup in (
        (0, 0, 1000000000), (0, 1, 1000000000), (0, 5000000000, 5000000000),
        (0, 4000000001, 5000000001), (0, 3999999999, 5000000000),
        (0, 1, 5000000000), (5, 4, 3), (1, 2, 2),
    ):
        _lease_reject(dict(_lease('reserved'), operation_started_ns=start,
                           work_deadline_ns=work, cleanup_deadline_ns=cleanup), 'invalid_result')


def test_public_lease_state_relations():
    # Independent state truth table: nullable links, times and terminal kind.
    for state, kind, released in LEASE_STATES:
        record = _lease(state, kind, released)
        _lease_accept(record)
        for key in LEASE_LINK_KEYS + LEASE_TIME_KEYS + ('close_kind',):
            # Release is optional in completed/unknown snapshots; all other
            # null/non-null flips violate a required presence/absence relation.
            if state == 'closed' and kind in ('completed', 'interrupted_unknown') and key == 'release_event_id':
                _lease_accept(dict(record, release_event_id=None if released else SUBJECT))
                continue
            value = None if record[key] is not None else (
                'completed' if key == 'close_kind' else (1 if key in LEASE_TIME_KEYS else SUBJECT))
            _lease_reject(dict(record, **{key: value}), 'invalid_result')
        _lease_accept(dict(record, cancel_requested=True))
    for state in ('prepared', 'reserved', 'released'):
        for kind in ('unadmitted', 'unreleased', 'completed', 'interrupted_unknown'):
            _lease_reject(dict(_lease(state), close_kind=kind), 'invalid_result')
    for mask in range(1, 8):
        record = _lease('reserved')
        for index, key in enumerate(LEASE_TIME_KEYS):
            if mask & (1 << index):
                record[key] = None
        _lease_reject(record, 'invalid_result')


def test_public_lease_encoding_and_depth():
    wire = _wire(_lease())
    unsorted = json.dumps(dict(reversed(tuple(_lease().items()))), separators=(',', ':')).encode('ascii')
    for frame in (unsorted, wire + b'\n', b' ' + wire, wire.replace(b':', b': ', 1),
                  wire.replace(b'"s43-lease-v1"', b'"\\u007343-lease-v1"'),
                  wire.replace(b'"revision":1', b'"revision":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\x80', b'', b'{}x', b'{',
                  b'x' * 4097, b'{"x":{}}', b'[[0]]'):
        # -0 is outside revision bounds and fails scalar validation first.
        code = 'invalid_value' if b'"revision":-0' in frame else 'invalid_encoding'
        error = _reject(lambda: codec.decode_public_lease(frame, SUBJECT, OTHER, LEASE_ID), code)
        assert error.__context__ is None
    _reject(lambda: codec.decode_public_lease(b'{"revision":1,' + wire[1:], SUBJECT, OTHER, LEASE_ID), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        frame = wire.replace(b'"revision":1', b'"revision":' + scalar)
        _reject(lambda: codec.decode_public_lease(frame, SUBJECT, OTHER, LEASE_ID), 'invalid_value')
    _reject(lambda: codec.decode_public_lease(wire.replace(b'"generation":0', b'"generation":-0'), SUBJECT, OTHER, LEASE_ID), 'invalid_encoding')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None):
        _reject(lambda: codec.decode_public_lease(frame, SUBJECT, OTHER, LEASE_ID), 'invalid_shape')
    calls = []
    original_loads = json.loads

    def observed_loads(*args, **kwargs):
        calls.append(1)
        return original_loads(*args, **kwargs)

    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'{"x":{}}', b'[[0]]'):
            _reject(lambda: codec.decode_public_lease(frame, SUBJECT, OTHER, LEASE_ID), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_public_lease(b' ' * 4096, SUBJECT, OTHER, LEASE_ID), 'invalid_encoding')
        assert len(calls) == 1
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _lease_reject(dict(_lease(), schema_version=text), 'invalid_value')
        assert len(calls) == 4
    finally:
        json.loads = original_loads


def test_public_lease_subject_binding():
    record = _lease()
    wire = _wire(record)
    for index, key in enumerate(('engagement_id', 'operation_id', 'lease_id')):
        args = [SUBJECT, OTHER, LEASE_ID]
        args[index] = '42345678-1234-4234-9234-123456789abc'
        _reject(lambda: codec.decode_public_lease(wire, *args), 'wrong_subject')
        _reject(lambda: codec.encode_public_lease(record, *args), 'wrong_subject')
        _reject(lambda: codec.decode_public_lease(wire + b' ', *args), 'invalid_encoding')
        _lease_reject(dict(record, **{key: args[index]}), 'wrong_subject')
        for bad in ('', SUBJECT.upper(), SUBJECT + '\n', SUBJECT.replace('-4234-', '-1234-'),
                    SUBJECT.replace('-9234-', '-7234-'), None, True, 1, [], {}):
            args[index] = bad
            code = 'invalid_value' if type(bad) is str else 'invalid_shape'
            _reject(lambda: codec.decode_public_lease(wire, *args), code)
            _reject(lambda: codec.encode_public_lease(record, *args), code)


EVENT_ID = '42345678-1234-4234-9234-123456789abc'
EVENT_ENVELOPE_KEYS = (
    'actor_owner_id', 'actor_session_id', 'details', 'engagement_id', 'event_id',
    'generation', 'kind', 'lease_id', 'operation_id', 'previous_event_sha256',
    'recorded_utc', 'revision', 'schema_version', 'sequence', 'transaction_id',
)
EVENT_DETAIL_TYPES = {
    'allowance_reserved': (('cleanup_deadline_ns', 'integer'), ('operation_started_ns', 'integer'),
                           ('reservation_id', 'uuid'), ('reserved', 'vector'),
                           ('usage_after', 'totals'), ('work_deadline_ns', 'integer')),
    'cancellation_requested': (('reason', 'enum'),),
    'credential_released': (('reservation_id', 'uuid'), ('tls_observation_id', 'uuid')),
    'engagement_revoked': (('previous_generation', 'integer'),),
    'exchange_observed': (('phase', 'enum'), ('progress_observation_id', 'uuid'), ('release_event_id', 'uuid')),
    'lease_closed': (('cleanup_observation_id', 'uuid'), ('close_kind', 'enum'), ('completion_event_id', 'uuid?')),
    'lease_prepared': (('lease_binding_sha256', 'hash'),),
    'owner_recovered': (('cleanup_observation_id', 'uuid'), ('previous_owner_id', 'uuid')),
    'result_observed': (('result', 'result'),),
    'result_recorded': (('observation_event_id', 'uuid'), ('result_sha256', 'hash')),
    'roe_adopted': (('previous_revision_sha256', 'hash?'), ('roe_sha256', 'hash')),
}


def _event(kind='lease_prepared'):
    bodies = {
        'allowance_reserved': {
            'cleanup_deadline_ns': 5000000000, 'operation_started_ns': 0,
            'reservation_id': SUBJECT,
            'reserved': {'actions': 1, 'connections': 1, 'inbound_tls_bytes': 16384,
                         'outbound_tls_bytes': 8192, 'runtime_ms': 5000},
            'usage_after': {'actions': 1, 'connections': 1, 'inbound_tls_bytes': 16384,
                            'outbound_tls_bytes': 8192, 'runtime_ms': 5000},
            'work_deadline_ns': 4000000000,
        },
        'cancellation_requested': {'reason': 'operator_cancel'},
        'credential_released': {'reservation_id': SUBJECT, 'tls_observation_id': SUBJECT},
        'engagement_revoked': {'previous_generation': 0},
        'exchange_observed': {'phase': 'pre_write', 'progress_observation_id': SUBJECT, 'release_event_id': SUBJECT},
        'lease_closed': {'cleanup_observation_id': SUBJECT, 'close_kind': 'unadmitted', 'completion_event_id': None},
        'lease_prepared': {'lease_binding_sha256': 'a' * 64},
        'owner_recovered': {'cleanup_observation_id': SUBJECT, 'previous_owner_id': SUBJECT},
        'result_observed': {'result': dict(_record(), operation_id=OTHER)},
        'result_recorded': {'observation_event_id': SUBJECT, 'result_sha256': 'a' * 64},
        'roe_adopted': {'previous_revision_sha256': None, 'roe_sha256': 'b' * 64},
    }
    engagement = kind in ('engagement_revoked', 'owner_recovered', 'roe_adopted')
    return {
        'actor_owner_id': SUBJECT, 'actor_session_id': SUBJECT, 'details': bodies[kind],
        'engagement_id': SUBJECT, 'event_id': EVENT_ID,
        'generation': 1 if kind == 'engagement_revoked' else 0, 'kind': kind,
        'lease_id': None if engagement else LEASE_ID, 'operation_id': None if engagement else OTHER,
        'previous_event_sha256': None, 'recorded_utc': '2024-02-29T23:59:59.123456Z',
        'revision': 1, 'schema_version': 's43-event-v1', 'sequence': 1, 'transaction_id': SUBJECT,
    }


def _event_args(kind):
    if kind in ('engagement_revoked', 'owner_recovered', 'roe_adopted'):
        return SUBJECT, None, None, EVENT_ID
    return SUBJECT, OTHER, LEASE_ID, EVENT_ID


def _event_accept(record):
    args = _event_args(record['kind'])
    wire = _wire(record)
    assert codec.encode_public_event(record, *args) == wire
    decoded = codec.decode_public_event(wire, *args)
    assert decoded == record and decoded is not record
    assert decoded['details'] is not record['details']
    return decoded


def _event_reject(record, code, kind='lease_prepared'):
    args = _event_args(kind)
    _reject(lambda: codec.encode_public_event(record, *args), code)
    return _reject(lambda: codec.decode_public_event(_wire(record), *args), code)


def test_public_event_canonical_examples():
    for kind in EVENT_DETAIL_TYPES:
        record = _event(kind)
        assert tuple(sorted(record)) == EVENT_ENVELOPE_KEYS
        decoded = _event_accept(record)
        decoded['details']['RAW_SENTINEL'] = 1
        assert 'RAW_SENTINEL' not in record['details']
        assert 'RAW_SENTINEL' not in _event_accept(record)['details']
    for row in RELATIONS:
        record = _event('result_observed')
        record['details']['result'] = dict(_record(row), operation_id=OTHER)
        decoded = _event_accept(record)
        decoded['details']['result']['outcome'] = 'RAW_SENTINEL'
        assert record['details']['result']['outcome'] == row[0]
        assert _event_accept(record)['details']['result']['outcome'] == row[0]
    record = _event('allowance_reserved')
    decoded = _event_accept(record)
    for key in ('reserved', 'usage_after'):
        decoded['details'][key]['actions'] = 99
        assert record['details'][key]['actions'] == 1
        assert _event_accept(record)['details'][key]['actions'] == 1


def test_public_event_shape_and_type_rejections():
    for value in (None, True, 1, 'RAW_SENTINEL', [], {}):
        _event_reject(value, 'invalid_shape')
    for key in EVENT_ENVELOPE_KEYS:
        record = _event()
        del record[key]
        _event_reject(record, 'invalid_shape')
        for bad in (True, 'RAW_SENTINEL' if key in ('generation', 'revision', 'sequence') else 1):
            _event_reject(dict(_event(), **{key: bad}), 'invalid_shape' if key == 'details' else 'invalid_value')
        if key not in ('lease_id', 'operation_id', 'previous_event_sha256'):
            _event_reject(dict(_event(), **{key: None}), 'invalid_shape' if key == 'details' else 'invalid_value')
        if key != 'details':
            _event_reject(dict(_event(), **{key: 1.0}), 'invalid_value')
    _event_reject(dict(_event(), RAW_SENTINEL=1), 'invalid_shape')
    for key in (1, 'x' * 10000):
        record = _event()
        del record['revision']
        record[key] = 1
        _reject(lambda: codec.encode_public_event(record, *_event_args('lease_prepared')), 'invalid_shape')

    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')

    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')

    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')

    _reject(lambda: codec.encode_public_event(DictHook(_event()), *_event_args('lease_prepared')), 'invalid_shape')
    for key in EVENT_ENVELOPE_KEYS:
        bad = DictHook() if key == 'details' else (IntHook(1) if key in ('revision', 'generation', 'sequence') else StringHook('x'))
        _reject(lambda: codec.encode_public_event(dict(_event(), **{key: bad}), *_event_args('lease_prepared')), 'invalid_shape' if key == 'details' else 'invalid_value')
    for kind, schema in EVENT_DETAIL_TYPES.items():
        for key, value_type in schema:
            record = _event(kind)
            container = value_type in ('vector', 'totals', 'result')
            for bad in (None, True, 'RAW_SENTINEL'):
                if bad is None and value_type.endswith('?'):
                    continue
                record['details'][key] = bad
                _event_reject(record, 'invalid_shape' if container else 'invalid_value', kind)
            record['details'][key] = DictHook() if container else (IntHook(1) if value_type == 'integer' else StringHook('x'))
            _reject(lambda: codec.encode_public_event(record, *_event_args(kind)), 'invalid_shape' if container else 'invalid_value')
        record = _event(kind)
        record['details'] = DictHook(record['details'])
        _reject(lambda: codec.encode_public_event(record, *_event_args(kind)), 'invalid_shape')
    for level in ('envelope', 'details', 'reserved'):
        record = _event('allowance_reserved')
        target = record if level == 'envelope' else (record['details'] if level == 'details' else record['details']['reserved'])
        key = next(iter(target))
        value = target.pop(key)
        target[StringHook(key)] = value
        _reject(lambda: codec.encode_public_event(record, *_event_args('allowance_reserved')), 'invalid_shape')


def test_public_event_variant_schemas():
    for kind, schema in EVENT_DETAIL_TYPES.items():
        record = _event(kind)
        assert set(record['details']) == {key for key, _ in schema}
        for key, _ in schema:
            bad = _event(kind)
            del bad['details'][key]
            _event_reject(bad, 'invalid_shape', kind)
        bad = _event(kind)
        bad['details']['RAW_SENTINEL'] = 1
        _event_reject(bad, 'invalid_shape', kind)
        for other in EVENT_DETAIL_TYPES:
            if other != kind:
                _event_reject(dict(record, details=_event(other)['details']), 'invalid_shape', kind)
    for key in ('reserved', 'usage_after', 'result'):
        kind = 'result_observed' if key == 'result' else 'allowance_reserved'
        record = _event(kind)
        for field in record['details'][key]:
            bad = _event(kind)
            del bad['details'][key][field]
            _event_reject(bad, 'invalid_shape', kind)
        record['details'][key]['RAW_SENTINEL'] = 1
        _event_reject(record, 'invalid_shape', kind)
    for reason in ('operator_cancel', 'lease_revoked', 'expired', 'runtime_failure'):
        _event_accept(dict(_event('cancellation_requested'), details={'reason': reason}))
    for key, bad in (('kind', 'unknown'), ('schema_version', 's43-event-v2')):
        _event_reject(dict(_event(), **{key: bad}), 'invalid_value')


def test_public_event_scalar_and_calendar_bounds():
    for key, minimum in (('revision', 1), ('generation', 0), ('sequence', 1)):
        for value in (minimum, 2147483647):
            record = dict(_event(), **{key: value})
            if key == 'sequence' and value != 1:
                record['previous_event_sha256'] = 'a' * 64
            _event_accept(record)
        for bad in (minimum - 1, 2147483648, 10 ** 200, True, 1.0, '1'):
            _event_reject(dict(_event(), **{key: bad}), 'invalid_value')
    bad_uuids = ('', SUBJECT.upper(), SUBJECT + '\n', SUBJECT[:-1],
                 SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
    bad_hashes = ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, 'a' * 64 + '\n')
    for key in ('actor_owner_id', 'actor_session_id', 'engagement_id', 'event_id', 'lease_id', 'operation_id', 'transaction_id'):
        for bad in bad_uuids:
            _event_reject(dict(_event(), **{key: bad}), 'invalid_value')
    for bad in bad_hashes:
        _event_reject(dict(_event(), previous_event_sha256=bad), 'invalid_value')
    for kind, schema in EVENT_DETAIL_TYPES.items():
        for key, typ in schema:
            if typ in ('uuid', 'uuid?', 'hash', 'hash?'):
                for bad in bad_uuids if typ.startswith('uuid') else bad_hashes:
                    record = _event(kind)
                    record['details'][key] = bad
                    _event_reject(record, 'invalid_value', kind)
            if typ == 'enum':
                for bad in ('', 'RAW_SENTINEL', 'pre_write\n', 'x' * 65):
                    record = _event(kind)
                    record['details'][key] = bad
                    _event_reject(record, 'invalid_value', kind)
    for good in ('0001-01-01T00:00:00.000000Z', '2000-02-29T23:59:59.999999Z', '9999-12-31T23:59:59.999999Z'):
        _event_accept(dict(_event(), recorded_utc=good))
    for bad in ('0000-01-01T00:00:00.000000Z', '10000-01-01T00:00:00.000000Z',
                '1900-02-29T00:00:00.000000Z', '2100-02-29T00:00:00.000000Z',
                '2023-02-29T00:00:00.000000Z', '2024-04-31T00:00:00.000000Z',
                '2024-00-01T00:00:00.000000Z', '2024-13-01T00:00:00.000000Z',
                '2024-01-00T00:00:00.000000Z', '2024-01-01T24:00:00.000000Z',
                '2024-01-01T00:60:00.000000Z', '2024-01-01T00:00:60.000000Z',
                '2024-01-01T00:00:00.00000Z', '2024-01-01T00:00:00.0000000Z',
                '2024-01-01T00:00:00.000000+00:00', '2024-01-01T00:00:00.000000Z\n'):
        error = _event_reject(dict(_event(), recorded_utc=bad), 'invalid_value')
        assert error.__context__ is None


def test_public_event_sequence_and_subject_binding():
    for sequence, previous in ((1, None), (2, 'a' * 64), (2147483647, 'b' * 64)):
        _event_accept(dict(_event(), sequence=sequence, previous_event_sha256=previous))
    for sequence, previous in ((1, 'a' * 64), (2, None), (2147483647, None)):
        _event_reject(dict(_event(), sequence=sequence, previous_event_sha256=previous), 'invalid_result')
    for kind in EVENT_DETAIL_TYPES:
        record = _event(kind)
        args = _event_args(kind)
        wire = _wire(record)
        for key in ('operation_id', 'lease_id'):
            _event_reject(dict(record, **{key: SUBJECT if record[key] is None else None}), 'invalid_result', kind)
        for index, key in enumerate(('engagement_id', 'operation_id', 'lease_id', 'event_id')):
            changed = list(args)
            changed[index] = '52345678-1234-4234-9234-123456789abc'
            code = 'invalid_shape' if index in (1, 2) and args[index] is None else 'wrong_subject'
            _reject(lambda: codec.decode_public_event(wire, *changed), code)
            _reject(lambda: codec.encode_public_event(record, *changed), code)
            if code == 'wrong_subject':
                _reject(lambda: codec.decode_public_event(wire + b' ', *changed), 'invalid_encoding')
        changed = list(args)
        changed[1:3] = (None, None) if args[1] is not None else (OTHER, LEASE_ID)
        _reject(lambda: codec.decode_public_event(wire, *changed), 'wrong_subject')
        _reject(lambda: codec.encode_public_event(record, *changed), 'wrong_subject')
    record = _event()
    wire = _wire(record)
    for index in range(4):
        for bad in ('', SUBJECT.upper(), SUBJECT + '\n', SUBJECT.replace('-4234-', '-1234-'),
                    SUBJECT.replace('-9234-', '-7234-'), None, True, 1, [], {}):
            args = list(_event_args('lease_prepared'))
            args[index] = bad
            code = 'invalid_value' if type(bad) is str else 'invalid_shape'
            _reject(lambda: codec.decode_public_event(wire, *args), code)
            _reject(lambda: codec.encode_public_event(record, *args), code)


def test_public_event_budget_and_deadline_relations():
    dimensions = (('actions', 1, 64), ('connections', 1, 64),
                  ('inbound_tls_bytes', 16384, 1048576), ('outbound_tls_bytes', 8192, 524288),
                  ('runtime_ms', 5000, 320000))
    for key, minimum, maximum in dimensions:
        for good in (minimum, maximum):
            record = _event('allowance_reserved')
            record['details']['usage_after'][key] = good
            _event_accept(record)
        for container in ('reserved', 'usage_after'):
            for bad in (-1, maximum + 1, True, 1.0, '1', None):
                record = _event('allowance_reserved')
                record['details'][container][key] = bad
                _event_reject(record, 'invalid_value', 'allowance_reserved')
        for container, bad in (('reserved', 0), ('reserved', minimum + 1), ('usage_after', minimum - 1)):
            record = _event('allowance_reserved')
            record['details'][container][key] = bad
            _event_reject(record, 'invalid_result', 'allowance_reserved')
    for good, cases in ((True, (
        (0, 4000000000, 5000000000), (0, 1, 1000000001), (7, 2000000007, 3000000007),
        (9223372031854775807, 9223372035854775807, 9223372036854775807),
        (9223372035854775806, 9223372035854775807, 9223372036854775807),
    )), (False, (
        (0, 0, 1000000000), (0, 1, 1000000000), (0, 5000000000, 5000000000),
        (0, 4000000001, 5000000001), (0, 3999999999, 5000000000), (0, 1, 5000000000),
        (5, 4, 3), (1, 2, 2),
    ))):
        for start, work, cleanup in cases:
            record = _event('allowance_reserved')
            record['details'].update(operation_started_ns=start, work_deadline_ns=work, cleanup_deadline_ns=cleanup)
            if good:
                _event_accept(record)
            else:
                _event_reject(record, 'invalid_result', 'allowance_reserved')
    for key in ('operation_started_ns', 'work_deadline_ns', 'cleanup_deadline_ns'):
        for bad in (-1, 9223372036854775808, 10 ** 200, None, True, 1.0, '1'):
            record = _event('allowance_reserved')
            record['details'][key] = bad
            _event_reject(record, 'invalid_value', 'allowance_reserved')


def test_public_event_intrinsic_relations():
    for previous, generation in ((0, 1), (2147483646, 2147483647)):
        record = _event('engagement_revoked')
        record['generation'] = generation
        record['details']['previous_generation'] = previous
        _event_accept(record)
    for previous, generation in ((0, 0), (0, 2), (1, 0), (2147483647, 2147483647), (2147483647, 0)):
        record = _event('engagement_revoked')
        record['generation'] = generation
        record['details']['previous_generation'] = previous
        _event_reject(record, 'invalid_result', 'engagement_revoked')
    for bad in (-1, 2147483648, True, 1.0, '1'):
        record = _event('engagement_revoked')
        record['details']['previous_generation'] = bad
        _event_reject(record, 'invalid_value', 'engagement_revoked')
    for good, cases in ((True, ((1, None, 0), (2, 'a' * 64, 1), (2147483647, 'b' * 64, 2147483647))),
                        (False, ((1, 'a' * 64, 0), (1, None, 1), (2, None, 1), (2, 'a' * 64, 0)))):
        for revision, previous, generation in cases:
            record = _event('roe_adopted')
            record.update(revision=revision, generation=generation)
            record['details']['previous_revision_sha256'] = previous
            if good:
                _event_accept(record)
            else:
                _event_reject(record, 'invalid_result', 'roe_adopted')
    for kind in ('unadmitted', 'unreleased', 'completed', 'interrupted_unknown'):
        record = _event('lease_closed')
        record['details'].update(close_kind=kind, completion_event_id=SUBJECT if kind == 'completed' else None)
        _event_accept(record)
        record['details']['completion_event_id'] = None if kind == 'completed' else SUBJECT
        _event_reject(record, 'invalid_result', 'lease_closed')
    record = _event('result_observed')
    record['details']['result']['operation_id'] = SUBJECT
    _event_reject(record, 'invalid_result', 'result_observed')
    record = _event('result_observed')
    record['details']['result']['http_status'] = 401
    _event_reject(record, 'invalid_result', 'result_observed')
    record['details']['result']['http_status'] = True
    _event_reject(record, 'invalid_value', 'result_observed')


def test_public_event_encoding_and_depth():
    record = _event('allowance_reserved')
    wire = _wire(record)
    args = _event_args('allowance_reserved')
    reversed_root = json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii')
    budget = record['details']['reserved']
    reversed_budget = json.dumps(dict(reversed(tuple(budget.items()))), separators=(',', ':')).encode('ascii')
    for frame in (reversed_root, wire.replace(_wire(budget), reversed_budget, 1),
                  wire + b'\n', b' ' + wire, wire.replace(b':', b': ', 1),
                  wire.replace(b'"s43-event-v1"', b'"\\u007343-event-v1"'),
                  wire.replace(b'"generation":0', b'"generation":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\x80', b'', b'{', b'{}x', b'x' * 4097,
                  b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
        error = _reject(lambda: codec.decode_public_event(frame, *args), 'invalid_encoding')
        assert error.__context__ is None
    for frame in (b'{"sequence":1,' + wire[1:],
                  wire.replace(b'"details":{', b'"details":{"work_deadline_ns":4000000000,'),
                  wire.replace(b'"reserved":{', b'"reserved":{"actions":1,')):
        _reject(lambda: codec.decode_public_event(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_public_event(wire.replace(b'"revision":1', b'"revision":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None):
        _reject(lambda: codec.decode_public_event(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads

    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)

    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            _reject(lambda: codec.decode_public_event(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_public_event(b' ' * 4096, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_public_event(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        assert codec.decode_public_event(wire, *args) == record
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _event_reject(dict(_event(), schema_version=text), 'invalid_value')
        assert len(calls) == 6
    finally:
        json.loads = original_loads


# Independent observation expectations; never derive them from codec tables.
OBS_ENGAGEMENT = '32345678-1234-4234-9234-123456789abc'
OBS_LEASE = '42345678-1234-4234-9234-123456789abc'
OBS_REFERENCE = '52345678-1234-4234-9234-123456789abc'
OBS_ENVELOPE_TYPES = (
    ('action_sha256', 'hash?'), ('clock_epoch_id', 'uuid'), ('engagement_id', 'uuid'),
    ('issuer_instance_id', 'uuid'), ('issuer_role', 'enum'), ('kind', 'enum'),
    ('lease_id', 'uuid?'), ('observed_monotonic_ns', 'time'), ('observer_owner_id', 'uuid'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('reference_id', 'uuid'), ('runtime_lock_sha256', 'hash'), ('schema_version', 'enum'),
    ('subject_generation', 'generation?'), ('subject_owner_id', 'uuid'),
)
OBS_PAYLOAD_TYPES = {
    'action_prepared': (
        ('credential_reference', 'uuid'), ('fixture_id', 'enum'), ('operation_profile_sha256', 'hash'),
        ('request_template_sha256', 'hash'), ('revision', 'revision'), ('roe_sha256', 'hash'), ('trust_sha256', 'hash'),
    ),
    'approval_recorded': (
        ('action_reference_id', 'uuid'), ('approval_id', 'uuid'), ('decision', 'enum'),
        ('review_view', 'enum'), ('reviewed_action_sha256', 'hash'),
    ),
    'graph_closed': (
        ('descriptors_closed', 'true'), ('graph_id', 'uuid'), ('physical_receipt_id', 'uuid'),
        ('processes_reaped', 'true'), ('scope', 'enum'),
    ),
    'pre_write_reached': (('phase', 'enum'), ('release_event_id', 'uuid'), ('socket_observation_id', 'uuid')),
    'result_released': (('result', 'result'),),
    'tls_verified': (
        ('negotiated_alpn', 'enum'), ('negotiated_cipher', 'enum'), ('negotiated_version', 'enum'),
        ('peer_certificate_sha256', 'hash'), ('session_reused', 'false'),
        ('socket_observation_id', 'uuid'), ('trust_sha256', 'hash'),
    ),
}
OBS_ROLES = {
    'action_prepared': 'broker', 'approval_recorded': 'reviewer',
    'graph_closed': 'lifecycle_monitor', 'pre_write_reached': 'operation_worker',
    'result_released': 'release_guard', 'tls_verified': 'operation_worker',
}


def _observation(kind='tls_verified', owner=False):
    payloads = {
        'action_prepared': dict(credential_reference=OTHER, fixture_id='allowed',
            operation_profile_sha256='a' * 64, request_template_sha256='b' * 64,
            revision=1, roe_sha256='c' * 64, trust_sha256='d' * 64),
        'approval_recorded': dict(action_reference_id=OTHER, approval_id=OBS_REFERENCE,
            decision='approved', review_view='terminal', reviewed_action_sha256='a' * 64),
        'graph_closed': dict(descriptors_closed=True, graph_id=OTHER,
            physical_receipt_id=OBS_REFERENCE, processes_reaped=True,
            scope='owner_graph' if owner else 'operation_graph'),
        'pre_write_reached': dict(phase='pre_write', release_event_id=OTHER, socket_observation_id=OBS_REFERENCE),
        'result_released': dict(result=_record()),
        'tls_verified': dict(negotiated_alpn='http/1.1', negotiated_cipher='ECDHE-RSA-AES128-GCM-SHA256',
            negotiated_version='TLSv1.2', peer_certificate_sha256='b' * 64,
            session_reused=False, socket_observation_id=OTHER, trust_sha256='c' * 64),
    }
    return dict(action_sha256=None if owner else 'a' * 64, clock_epoch_id=OTHER,
        engagement_id=OBS_ENGAGEMENT, issuer_instance_id=OTHER, issuer_role=OBS_ROLES[kind],
        kind=kind, lease_id=None if owner or kind in ('action_prepared', 'approval_recorded') else OBS_LEASE,
        observed_monotonic_ns=0, observer_owner_id=SUBJECT, observer_session_id=OTHER,
        operation_id=None if owner else SUBJECT, payload=payloads[kind], reference_id=OBS_REFERENCE,
        runtime_lock_sha256='d' * 64, schema_version='s43-observation-v1',
        subject_generation=None if owner else 0, subject_owner_id=OTHER)


def _observation_args(kind='tls_verified', owner=False):
    return (OBS_ENGAGEMENT, None if owner else SUBJECT,
            None if owner or kind in ('action_prepared', 'approval_recorded') else OBS_LEASE, OBS_REFERENCE)


def _observation_accept(record):
    args = tuple(record[key] for key in ('engagement_id', 'operation_id', 'lease_id', 'reference_id'))
    wire = _wire(record)
    assert codec.encode_observation_record(record, *args) == wire
    decoded = codec.decode_observation_record(wire, *args)
    assert decoded == record and decoded is not record
    assert decoded['payload'] is not record['payload']
    return decoded


def _observation_reject(record, code, kind='tls_verified', owner=False, decode_code=None):
    args = _observation_args(kind, owner)
    _reject(lambda: codec.encode_observation_record(record, *args), code)
    return _reject(lambda: codec.decode_observation_record(_wire(record), *args), decode_code or code)


def test_observation_record_canonical_examples():
    assert len(OBS_ENVELOPE_TYPES) == 17 and len(OBS_PAYLOAD_TYPES) == 6
    assert len(set(OBS_ROLES.values())) == 5
    for kind in OBS_PAYLOAD_TYPES:
        record = _observation(kind)
        assert set(record) == {key for key, _ in OBS_ENVELOPE_TYPES}
        assert record['issuer_role'] == OBS_ROLES[kind]
        first = _observation_accept(record)
        second = _observation_accept(record)
        first['payload'].clear()
        first['issuer_role'] = 'mutated'
        assert second == record
        assert codec.encode_observation_record(dict(reversed(tuple(record.items()))), *_observation_args(kind)) == _wire(record)
    for row in RELATIONS:
        record = _observation('result_released')
        record['payload']['result'] = _record(row)
        first = _observation_accept(record)
        second = _observation_accept(record)
        assert first['payload']['result'] is not record['payload']['result']
        first['payload']['result']['outcome'] = 'mutated'
        assert second == record
    # Fresh observer may name an old subject owner, for either graph scope.
    for owner in (False, True):
        record = _observation('graph_closed', owner)
        assert record['subject_owner_id'] != record['observer_owner_id']
        _observation_accept(record)


def test_observation_record_shape_and_type_rejections():
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _observation_reject(value, 'invalid_shape')
    for key, typ in OBS_ENVELOPE_TYPES:
        record = _observation()
        del record[key]
        _observation_reject(record, 'invalid_shape')
        record = _observation()
        record['RAW_SENTINEL'] = record.pop(key)
        _observation_reject(record, 'invalid_shape')
        for bad in (None, True, [], {}, 'RAW_SENTINEL'):
            if bad is None and typ.endswith('?'):
                continue
            _observation_reject(dict(_observation(), **{key: bad}), 'invalid_shape' if typ == 'object' else 'invalid_value')
    _observation_reject(dict(_observation(), extra='RAW_SENTINEL'), 'invalid_shape')
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class BoolHook:
        def __bool__(self):
            raise AssertionError('hook reached')
    _reject(lambda: codec.encode_observation_record(DictHook(_observation()), *_observation_args()), 'invalid_shape')
    for key, typ in OBS_ENVELOPE_TYPES:
        bad = DictHook() if typ == 'object' else (IntHook(1) if typ in ('time', 'generation?') else StringHook('x'))
        _reject(lambda: codec.encode_observation_record(dict(_observation(), **{key: bad}), *_observation_args()), 'invalid_shape' if typ == 'object' else 'invalid_value')
    for kind, schema in OBS_PAYLOAD_TYPES.items():
        for key, typ in schema:
            bad_values = (None, True, [], {}, 'RAW_SENTINEL', 0, 1, 1.0)
            for bad in bad_values:
                if typ == 'true' and bad is True or typ == 'revision' and type(bad) is int and bad == 1:
                    continue
                record = _observation(kind)
                record['payload'][key] = bad
                _observation_reject(record, 'invalid_shape' if typ == 'result' else 'invalid_value', kind,
                                    decode_code='invalid_value' if type(bad) is float else None)
            record = _observation(kind)
            record['payload'][key] = (DictHook() if typ == 'result' else BoolHook() if typ in ('true', 'false')
                                      else IntHook(1) if typ == 'revision' else StringHook('x'))
            _reject(lambda: codec.encode_observation_record(record, *_observation_args(kind)), 'invalid_shape' if typ == 'result' else 'invalid_value')
        record = _observation(kind)
        record['payload'] = DictHook(record['payload'])
        _reject(lambda: codec.encode_observation_record(record, *_observation_args(kind)), 'invalid_shape')
    for level in ('envelope', 'payload', 'result'):
        record = _observation('result_released')
        target = record if level == 'envelope' else record['payload'] if level == 'payload' else record['payload']['result']
        key = next(iter(target))
        target[StringHook(key)] = target.pop(key)
        _reject(lambda: codec.encode_observation_record(record, *_observation_args('result_released')), 'invalid_shape')
    huge = dict(_observation())
    huge['X' * 10000] = 'RAW_SENTINEL'
    _reject(lambda: codec.encode_observation_record(huge, *_observation_args()), 'invalid_shape')


def test_observation_record_variant_schemas():
    for kind, schema in OBS_PAYLOAD_TYPES.items():
        record = _observation(kind)
        assert set(record['payload']) == {key for key, _ in schema}
        for key, _ in schema:
            bad = _observation(kind)
            del bad['payload'][key]
            _observation_reject(bad, 'invalid_shape', kind)
        record['payload']['RAW_SENTINEL'] = 1
        _observation_reject(record, 'invalid_shape', kind)
        for other in OBS_PAYLOAD_TYPES:
            if other != kind:
                _observation_reject(dict(_observation(kind), payload=_observation(other)['payload']), 'invalid_shape', kind)
        for role in ('broker', 'reviewer', 'lifecycle_monitor', 'operation_worker', 'release_guard'):
            record = dict(_observation(kind), issuer_role=role)
            if role == OBS_ROLES[kind]:
                _observation_accept(record)
            else:
                _observation_reject(record, 'invalid_result', kind)
    for field in _record():
        record = _observation('result_released')
        del record['payload']['result'][field]
        _observation_reject(record, 'invalid_shape', 'result_released')
    record = _observation('result_released')
    record['payload']['result']['RAW_SENTINEL'] = 1
    _observation_reject(record, 'invalid_shape', 'result_released')
    for kind, field, values in (
            ('action_prepared', 'fixture_id', ('allowed', 'invalid', 'restricted')),
            ('approval_recorded', 'review_view', ('terminal', 'graphical'))):
        for value in values:
            record = _observation(kind)
            record['payload'][field] = value
            _observation_accept(record)
    for key in ('kind', 'issuer_role', 'schema_version'):
        for bad in ('', 'RAW_SENTINEL', 's43-observation-v2', 'x' * 65):
            _observation_reject(dict(_observation(), **{key: bad}), 'invalid_value')
    for key, bad in (('negotiated_alpn', 'h2'), ('negotiated_cipher', 'TLS_AES_128_GCM_SHA256'),
                     ('negotiated_version', 'TLSv1.3'), ('session_reused', True)):
        record = _observation()
        record['payload'][key] = bad
        _observation_reject(record, 'invalid_value')
    for key in ('processes_reaped', 'descriptors_closed'):
        record = _observation('graph_closed')
        record['payload'][key] = False
        _observation_reject(record, 'invalid_value', 'graph_closed')


def test_observation_record_scalar_bounds():
    for key, minimum, maximum, kind, in_payload in (
            ('observed_monotonic_ns', 0, 9223372036854775807, 'tls_verified', False),
            ('subject_generation', 0, 2147483647, 'tls_verified', False),
            ('revision', 1, 2147483647, 'action_prepared', True)):
        for value in (minimum, maximum):
            record = _observation(kind)
            (record['payload'] if in_payload else record)[key] = value
            _observation_accept(record)
        for bad in (minimum - 1, maximum + 1, 10 ** 200, True, False, 1.0, '1'):
            record = _observation(kind)
            (record['payload'] if in_payload else record)[key] = bad
            _observation_reject(record, 'invalid_value', kind)
    bad_uuids = ('', SUBJECT.upper(), SUBJECT + '\n', SUBJECT[:-1],
                 SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
    bad_hashes = ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, 'a' * 64 + '\n')
    for key, typ in OBS_ENVELOPE_TYPES:
        if typ.startswith(('uuid', 'hash')):
            for bad in bad_uuids if typ.startswith('uuid') else bad_hashes:
                _observation_reject(dict(_observation(), **{key: bad}), 'invalid_value')
    for kind, schema in OBS_PAYLOAD_TYPES.items():
        for key, typ in schema:
            for bad in bad_uuids if typ == 'uuid' else bad_hashes if typ == 'hash' else ('', 'RAW_SENTINEL', 'x' * 65) if typ == 'enum' else ():
                record = _observation(kind)
                record['payload'][key] = bad
                _observation_reject(record, 'invalid_value', kind)
    # Profile hash is syntax-only here; no unimplemented external binding is inferred.
    record = _observation('action_prepared')
    record['payload']['operation_profile_sha256'] = 'f' * 64
    _observation_accept(record)


def test_observation_record_subject_and_intrinsic_relations():
    fields = ('operation_id', 'lease_id', 'action_sha256', 'subject_generation')
    nonnull = (SUBJECT, OBS_LEASE, 'a' * 64, 0)
    for kind in OBS_PAYLOAD_TYPES:
        for owner in ((False, True) if kind == 'graph_closed' else (False,)):
            expected = tuple(_observation(kind, owner)[key] is not None for key in fields)
            for mask in range(16):
                present = tuple(bool(mask & (1 << i)) for i in range(4))
                record = _observation(kind, owner)
                for key, value, enabled in zip(fields, nonnull, present):
                    record[key] = value if enabled else None
                if present == expected:
                    _observation_accept(record)
                else:
                    _observation_reject(record, 'invalid_result', kind, owner)
    record = _observation('approval_recorded')
    record['payload']['reviewed_action_sha256'] = 'b' * 64
    _observation_reject(record, 'invalid_result', 'approval_recorded')
    record = _observation('result_released')
    record['payload']['result']['operation_id'] = OTHER
    _observation_reject(record, 'invalid_result', 'result_released')
    record = _observation('result_released')
    record['payload']['result']['http_status'] = None
    _observation_reject(record, 'invalid_result', 'result_released')


def test_observation_record_encoding_and_depth():
    record = _observation('result_released')
    wire = _wire(record)
    args = _observation_args('result_released')
    nested = record['payload']['result']
    reversed_nested = json.dumps(dict(reversed(tuple(nested.items()))), separators=(',', ':')).encode('ascii')
    for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                  wire.replace(_wire(nested), reversed_nested), wire + b'\n', b' ' + wire,
                  wire.replace(b':', b': ', 1), wire.replace(b'"s43-observation-v1"', b'"\\u007343-observation-v1"'),
                  wire.replace(b'"subject_generation":0', b'"subject_generation":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x',
                  b'{"x":"\\q"}', b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
        error = _reject(lambda: codec.decode_observation_record(frame, *args), 'invalid_encoding')
        assert error.__context__ is None
    for frame in (b'{"reference_id":null,' + wire[1:],
                  wire.replace(b'"payload":{', b'"payload":{"result":null,'),
                  wire.replace(b'"result":{', b'"result":{"outcome":null,'),
                  b'{"referenc\\u0065_id":null,' + wire[1:]):
        _reject(lambda: codec.decode_observation_record(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_observation_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None):
        _reject(lambda: codec.decode_observation_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            _reject(lambda: codec.decode_observation_record(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_observation_record(b' ' * 4096, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_observation_record(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        assert codec.decode_observation_record(wire, *args) == record
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _observation_reject(dict(_observation(), schema_version=text), 'invalid_value')
        assert len(calls) == 6
    finally:
        json.loads = original_loads


def test_observation_record_expected_subject_binding():
    for kind in OBS_PAYLOAD_TYPES:
        for owner in ((False, True) if kind == 'graph_closed' else (False,)):
            record = _observation(kind, owner)
            wire = _wire(record)
            args = _observation_args(kind, owner)
            for index in range(4):
                changed = list(args)
                changed[index] = '62345678-1234-4234-9234-123456789abc'
                code = 'invalid_shape' if changed[1] is None and changed[2] is not None else 'wrong_subject'
                _reject(lambda: codec.decode_observation_record(wire, *changed), code)
                _reject(lambda: codec.encode_observation_record(record, *changed), code)
                for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n'):
                    changed = list(args)
                    changed[index] = bad
                    code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                    if index == 2 and changed[1] is None:
                        code = 'invalid_shape'
                    _reject(lambda: codec.decode_observation_record(wire, *changed), code)
                    _reject(lambda: codec.encode_observation_record(record, *changed), code)
            for operation, lease in ((None, None), (SUBJECT, None), (SUBJECT, OBS_LEASE), (None, OBS_LEASE)):
                changed = (OBS_ENGAGEMENT, operation, lease, OBS_REFERENCE)
                if changed == args:
                    assert codec.decode_observation_record(wire, *changed) == record
                else:
                    code = 'invalid_shape' if operation is None and lease is not None else 'wrong_subject'
                    _reject(lambda: codec.decode_observation_record(wire, *changed), code)
                    _reject(lambda: codec.encode_observation_record(record, *changed), code)
            for index in (0, 3):
                changed = list(args)
                changed[index] = None
                _reject(lambda: codec.decode_observation_record(wire, *changed), 'invalid_shape')
                _reject(lambda: codec.encode_observation_record(record, *changed), 'invalid_shape')
    # Intrinsic and canonical failures precede trusted-ID mismatch.
    record = _observation()
    wrong = (OTHER, SUBJECT, OBS_LEASE, OBS_REFERENCE)
    _reject(lambda: codec.decode_observation_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
    record['issuer_role'] = 'reviewer'
    _reject(lambda: codec.encode_observation_record(record, *wrong), 'invalid_result')
    _reject(lambda: codec.decode_observation_record(_wire(record), *wrong), 'invalid_result')


# Independent custody receipt expectations, separate from production schemas.
CUST_OWNER = '62345678-1234-4234-9234-123456789abc'
CUST_GRAPH = '72345678-1234-4234-9234-123456789abc'
CUST_RECEIPT = '82345678-1234-4234-9234-123456789abc'
CUST_ENVELOPE_TYPES = (
    ('clock_epoch_id', 'uuid'), ('graph_id', 'uuid'), ('issuer_instance_id', 'uuid'),
    ('issuer_role', 'enum'), ('kind', 'enum'), ('observed_monotonic_ns', 'integer'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('phase', 'enum'), ('receipt_id', 'uuid'), ('runtime_lock_sha256', 'hash'),
    ('schema_version', 'enum'), ('subject_owner_id', 'uuid'),
)
CUST_PAYLOAD_TYPES = {
    'socket_custody': (
        ('local_address', 'enum'), ('local_port', 'integer'), ('network_namespace_inode', 'integer'),
        ('peer_address', 'enum'), ('peer_port', 'integer'), ('protocol', 'enum'),
        ('receiver_descriptor_receipt_id', 'uuid'), ('receiver_instance_id', 'uuid'),
        ('sender_aliases_closed', 'true'), ('sender_descriptor_receipt_id', 'uuid'),
        ('sender_instance_id', 'uuid'), ('socket_observation_id', 'uuid'), ('transfer_id', 'uuid'),
    ),
    'source_custody': (
        ('access_mode', 'enum'), ('fixture_id', 'enum'), ('receiver_descriptor_receipt_id', 'uuid'),
        ('receiver_instance_id', 'uuid'), ('release_event_id', 'uuid'), ('seals', 'enum'),
        ('size_bytes', 'integer'), ('source_aliases_closed', 'true'),
        ('source_descriptor_receipt_id', 'uuid'), ('source_instance_id', 'uuid'),
        ('transfer_id', 'uuid'), ('writable_aliases_closed', 'true'),
    ),
}
CUST_PHASES = ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed')
CUST_ROLES = ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
              'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')


def _custody(kind='socket_custody', operation=SUBJECT):
    payloads = {
        'socket_custody': dict(local_address='127.0.0.1', local_port=1, network_namespace_inode=0,
            peer_address='127.0.0.1', peer_port=9443, protocol='tcp', receiver_descriptor_receipt_id=OTHER,
            receiver_instance_id=OTHER, sender_aliases_closed=True, sender_descriptor_receipt_id=SUBJECT,
            sender_instance_id=SUBJECT, socket_observation_id=OTHER, transfer_id=SUBJECT),
        'source_custody': dict(access_mode='read_only', fixture_id='allowed',
            receiver_descriptor_receipt_id=OTHER, receiver_instance_id=OTHER, release_event_id=SUBJECT,
            seals='write_grow_shrink_seal', size_bytes=1, source_aliases_closed=True,
            source_descriptor_receipt_id=SUBJECT, source_instance_id=SUBJECT,
            transfer_id=OTHER, writable_aliases_closed=True),
    }
    return dict(clock_epoch_id=OTHER, graph_id=CUST_GRAPH, issuer_instance_id=SUBJECT,
        issuer_role='operation_worker', kind=kind, observed_monotonic_ns=0, observer_session_id=OTHER,
        operation_id=operation, payload=payloads[kind], phase='ready', receipt_id=CUST_RECEIPT,
        runtime_lock_sha256='a' * 64, schema_version='s43-physical-receipt-v1', subject_owner_id=CUST_OWNER)


def _custody_args(operation=SUBJECT):
    return CUST_OWNER, operation, CUST_GRAPH, CUST_RECEIPT


def _custody_accept(record):
    args = tuple(record[key] for key in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id'))
    wire = _wire(record)
    assert codec.encode_custody_receipt_record(record, *args) == wire
    decoded = codec.decode_custody_receipt_record(wire, *args)
    assert decoded == record and decoded is not record
    assert type(decoded) is dict and type(decoded['payload']) is dict
    assert decoded['payload'] is not record['payload']
    return decoded


def _custody_reject(record, code, operation=SUBJECT, decode_code=None):
    args = _custody_args(operation)
    _reject(lambda: codec.encode_custody_receipt_record(record, *args), code)
    return _reject(lambda: codec.decode_custody_receipt_record(_wire(record), *args), decode_code or code)


def test_custody_receipt_record_canonical_examples():
    assert len(CUST_ENVELOPE_TYPES) == 14
    assert [len(v) for v in CUST_PAYLOAD_TYPES.values()] == [13, 12]
    assert len(CUST_ROLES) == 11
    for kind in CUST_PAYLOAD_TYPES:
        for operation in (None, SUBJECT):
            for phase in CUST_PHASES:
                record = dict(_custody(kind, operation), phase=phase)
                assert set(record) == {k for k, _ in CUST_ENVELOPE_TYPES}
                assert set(record['payload']) == {k for k, _ in CUST_PAYLOAD_TYPES[kind]}
                first, second = _custody_accept(record), _custody_accept(record)
                first['payload'].clear()
                first['receipt_id'] = 'changed'
                assert second == record
                reversed_record = dict(reversed(tuple(record.items())))
                reversed_record['payload'] = dict(reversed(tuple(record['payload'].items())))
                assert codec.encode_custody_receipt_record(reversed_record, *_custody_args(operation)) == _wire(record)
        record = _custody(kind)
        assert record['issuer_instance_id'] != record['payload']['receiver_instance_id']
        _custody_accept(record)
        record['issuer_instance_id'] = record['payload']['receiver_instance_id']
        _custody_accept(record)
        # Repeated UUIDs are representable; this parser does not prove live bindings.
        for key, typ in CUST_PAYLOAD_TYPES[kind]:
            if typ == 'uuid':
                record['payload'][key] = SUBJECT
        _custody_accept(record)
    for fixture in ('allowed', 'invalid', 'restricted'):
        record = _custody('source_custody', None)
        record['payload']['fixture_id'] = fixture
        _custody_accept(record)


def test_custody_receipt_record_shape_and_type_rejections():
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class BoolHook:
        def __bool__(self):
            raise AssertionError('hook reached')
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _custody_reject(value, 'invalid_shape')
    _reject(lambda: codec.encode_custody_receipt_record(DictHook(_custody()), *_custody_args()), 'invalid_shape')
    for kind, schema in CUST_PAYLOAD_TYPES.items():
        for nested, fields in ((False, CUST_ENVELOPE_TYPES), (True, schema)):
            record = _custody(kind)
            target = record['payload'] if nested else record
            target['RAW_SENTINEL'] = 'extra'
            _custody_reject(record, 'invalid_shape')
            for key, typ in fields:
                for mutation in ('missing', 'unknown'):
                    record = _custody(kind)
                    target = record['payload'] if nested else record
                    value = target.pop(key)
                    if mutation == 'unknown':
                        target['RAW_SENTINEL'] = value
                    _custody_reject(record, 'invalid_shape')
                bad_values = (None, True, False, 1.0, [], {}, 'RAW_SENTINEL')
                if typ == 'true':
                    bad_values += (0, 1)
                for bad in bad_values:
                    if bad is None and typ.endswith('?') or bad is True and typ == 'true':
                        continue
                    record = _custody(kind)
                    target = record['payload'] if nested else record
                    target[key] = bad
                    # Float parsing precedes object-shape validation on decode.
                    _custody_reject(record, 'invalid_shape' if typ == 'object' else 'invalid_value',
                                    decode_code='invalid_value' if typ == 'object' and type(bad) is float else None)
                record = _custody(kind)
                target = record['payload'] if nested else record
                target[key] = (DictHook() if typ == 'object' else IntHook(1) if typ == 'integer'
                               else BoolHook() if typ == 'true' else StringHook('RAW_SENTINEL'))
                _reject(lambda: codec.encode_custody_receipt_record(record, *_custody_args()),
                        'invalid_shape' if typ == 'object' else 'invalid_value')
            for bad_key in (StringHook('x'), 'x' * 100000, 1):
                record = _custody(kind)
                target = record['payload'] if nested else record
                target[bad_key] = target.pop(fields[0][0])
                _reject(lambda: codec.encode_custody_receipt_record(record, *_custody_args()), 'invalid_shape')


def test_custody_receipt_record_variant_schemas():
    for kind in CUST_PAYLOAD_TYPES:
        for role in CUST_ROLES:
            record = dict(_custody(kind), issuer_role=role)
            if role == 'operation_worker':
                _custody_accept(record)
            else:
                _custody_reject(record, 'invalid_result')
        for key, bad in (('issuer_role', 'lifecycle_monitor'), ('phase', 'pre_write'),
                         ('schema_version', 's43-observation-v1')):
            _custody_reject(dict(_custody(kind), **{key: bad}), 'invalid_value')
        for bad in ('descriptor_identity', 'graph_closure', 'recovery_lifecycle', 'RAW_SENTINEL', ''):
            _custody_reject(dict(_custody(kind), kind=bad), 'invalid_value')
        other = 'source_custody' if kind == 'socket_custody' else 'socket_custody'
        _custody_reject(dict(_custody(kind), payload=_custody(other)['payload']), 'invalid_shape')
    mutations = {
        'socket_custody': {'protocol': ('udp', 'TCP'), 'local_address': ('localhost', '127.0.0.2'),
            'peer_address': ('::1', '127.0.0.2'), 'peer_port': (9442, 9444, True, 9443.0),
            'sender_aliases_closed': (False, 1, 'true')},
        'source_custody': {'fixture_id': ('unknown', 'Allowed'), 'access_mode': ('write_only', 'read_write'),
            'seals': ('none', 'write_grow_shrink'), 'source_aliases_closed': (False, 1, 'true'),
            'writable_aliases_closed': (False, 1, 'true')},
    }
    for kind, fields in mutations.items():
        for key, values in fields.items():
            for bad in values:
                record = _custody(kind)
                record['payload'][key] = bad
                _custody_reject(record, 'invalid_value')


def test_custody_receipt_record_scalar_bounds():
    for kind in CUST_PAYLOAD_TYPES:
        for value in (0, 9223372036854775807):
            _custody_accept(dict(_custody(kind), observed_monotonic_ns=value))
        for value in (-1, 9223372036854775808, True, 0.0):
            _custody_reject(dict(_custody(kind), observed_monotonic_ns=value), 'invalid_value')
        for nested, fields in ((False, CUST_ENVELOPE_TYPES), (True, CUST_PAYLOAD_TYPES[kind])):
            for key, typ in fields:
                if typ not in ('uuid', 'uuid?', 'hash'):
                    continue
                valid = 'f' * 64 if typ == 'hash' else SUBJECT
                malformed = (valid.upper(), valid + '\n', valid + 'x', 'x' + valid, valid[:-1], '')
                if typ != 'hash':
                    malformed += (SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
                for bad in malformed:
                    record = _custody(kind)
                    target = record['payload'] if nested else record
                    target[key] = bad
                    _custody_reject(record, 'invalid_value')
        _custody_accept(dict(_custody(kind), runtime_lock_sha256='0' * 64))
        _custody_accept(dict(_custody(kind), runtime_lock_sha256='f' * 64))
    for kind, key, lo, hi in (('socket_custody', 'local_port', 1, 65535),
                             ('socket_custody', 'network_namespace_inode', 0, 18446744073709551615),
                             ('socket_custody', 'peer_port', 9443, 9443),
                             ('source_custody', 'size_bytes', 1, 64)):
        for value in (lo, hi):
            record = _custody(kind)
            record['payload'][key] = value
            _custody_accept(record)
        for value in (lo - 1, hi + 1, True, False, float(lo)):
            record = _custody(kind)
            record['payload'][key] = value
            _custody_reject(record, 'invalid_value')


def test_custody_receipt_record_expected_subject_binding():
    class StringSubclass(str):
        pass
    for kind in CUST_PAYLOAD_TYPES:
        for operation in (None, SUBJECT):
            record = _custody(kind, operation)
            args = _custody_args(operation)
            for index in range(4):
                changed = list(args)
                changed[index] = OTHER
                _reject(lambda: codec.encode_custody_receipt_record(record, *changed), 'wrong_subject')
                _reject(lambda: codec.decode_custody_receipt_record(_wire(record), *changed), 'wrong_subject')
                for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n', StringSubclass(SUBJECT)):
                    changed = list(args)
                    changed[index] = bad
                    code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                    _reject(lambda: codec.encode_custody_receipt_record(record, *changed), code)
                    _reject(lambda: codec.decode_custody_receipt_record(_wire(record), *changed), code)
                    # Trusted-expectation validation precedes even bad frame/record shape.
                    _reject(lambda: codec.encode_custody_receipt_record(None, *changed), code)
                    _reject(lambda: codec.decode_custody_receipt_record(b'', *changed), code)
                changed = list(args)
                changed[index] = None
                if index != 1 or operation is not None:
                    code = 'wrong_subject' if index == 1 else 'invalid_shape'
                    _reject(lambda: codec.encode_custody_receipt_record(record, *changed), code)
                    _reject(lambda: codec.decode_custody_receipt_record(_wire(record), *changed), code)
            wrong = (OTHER, operation, CUST_GRAPH, CUST_RECEIPT)
            _reject(lambda: codec.decode_custody_receipt_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
            record['issuer_role'] = 'driver'
            _reject(lambda: codec.encode_custody_receipt_record(record, *wrong), 'invalid_result')
            _reject(lambda: codec.decode_custody_receipt_record(_wire(record), *wrong), 'invalid_result')


def test_custody_receipt_record_encoding_and_depth():
    class BytesSubclass(bytes):
        pass
    for kind in CUST_PAYLOAD_TYPES:
        record = _custody(kind)
        wire = _wire(record)
        args = _custody_args()
        reverse_payload = json.dumps(dict(reversed(tuple(record['payload'].items()))), separators=(',', ':')).encode('ascii')
        for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                      wire.replace(_wire(record['payload']), reverse_payload), wire + b'\n', b' ' + wire,
                      wire.replace(b':', b': ', 1), wire.replace(b'"s43-physical-receipt-v1"', b'"\\u007343-physical-receipt-v1"'),
                      wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":-0'),
                      b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x', b'{"x":"\\q"}',
                      b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            error = _reject(lambda: codec.decode_custody_receipt_record(frame, *args), 'invalid_encoding')
            assert error.__context__ is None and error.__cause__ is None
        for frame in (b'{"receipt_id":null,' + wire[1:], b'{"receip\\u0074_id":null,' + wire[1:],
                      wire.replace(b'"payload":{', b'"payload":{"transfer_id":null,')):
            _reject(lambda: codec.decode_custody_receipt_record(frame, *args), 'invalid_shape')
        for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
            _reject(lambda: codec.decode_custody_receipt_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
        for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None, BytesSubclass(wire)):
            _reject(lambda: codec.decode_custody_receipt_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*args, **kwargs):
        calls.append(1)
        return original_loads(*args, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            _reject(lambda: codec.decode_custody_receipt_record(frame, *_custody_args()), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_custody_receipt_record(b' ' * 4096, *_custody_args()), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_custody_receipt_record(b'{"a":{"b":{}}}', *_custody_args()), 'invalid_shape')
        assert len(calls) == 2
        _custody_accept(_custody())
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _custody_reject(dict(_custody(), schema_version=text), 'invalid_value')
        oversized = dict(_custody(), schema_version='x' * 100000)
        _reject(lambda: codec.encode_custody_receipt_record(oversized, *_custody_args()), 'invalid_value')
        _reject(lambda: codec.decode_custody_receipt_record(_wire(oversized), *_custody_args()), 'invalid_encoding')
    finally:
        json.loads = original_loads


# Independent descriptor expectations; do not import production schema tables.
DESC_ENVELOPE_TYPES = (
    ('clock_epoch_id', 'uuid'), ('graph_id', 'uuid'), ('issuer_instance_id', 'uuid'),
    ('issuer_role', 'enum'), ('kind', 'enum'), ('observed_monotonic_ns', 'integer'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('phase', 'enum'), ('receipt_id', 'uuid'), ('runtime_lock_sha256', 'hash'),
    ('schema_version', 'enum'), ('subject_owner_id', 'uuid'),
)
DESC_PAYLOAD_TYPES = (
    ('access_mode', 'enum'), ('close_on_exec', 'true'), ('device', 'integer'), ('fd_number', 'integer'),
    ('holder_instance_id', 'uuid'), ('inode', 'integer'), ('object_kind', 'enum'),
    ('peer_instance_id', 'uuid?'), ('process_receipt_id', 'uuid'), ('seals', 'enum'), ('transfer_id', 'uuid?'),
)
DESC_OBJECTS = ('credential_memfd', 'connected_socket', 'seqpacket', 'pipe', 'null_sink',
                'authority_file', 'display_socket', 'other_pinned_bootstrap_object')
DESC_ALLOWED_ROLES = ('supervisor', 'driver', 'fixture_source', 'connector', 'operation_worker')
DESC_KNOWN_ROLES = ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
                    'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')
DESC_PHASES = ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed')


def _descriptor(operation=SUBJECT):
    return dict(clock_epoch_id=OTHER, graph_id=CUST_GRAPH, issuer_instance_id=SUBJECT,
        issuer_role='supervisor', kind='descriptor_identity', observed_monotonic_ns=0,
        observer_session_id=OTHER, operation_id=operation, phase='ready', receipt_id=CUST_RECEIPT,
        runtime_lock_sha256='a' * 64, schema_version='s43-physical-receipt-v1', subject_owner_id=CUST_OWNER,
        payload=dict(access_mode='read_only', close_on_exec=True, device=0, fd_number=0,
            holder_instance_id=OTHER, inode=0, object_kind='pipe', peer_instance_id=None,
            process_receipt_id=SUBJECT, seals='none', transfer_id=None))


def _descriptor_args(operation=SUBJECT):
    return CUST_OWNER, operation, CUST_GRAPH, CUST_RECEIPT


def _descriptor_accept(record):
    args = tuple(record[k] for k in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id'))
    wire = _wire(record)
    assert codec.encode_descriptor_receipt_record(record, *args) == wire
    decoded = codec.decode_descriptor_receipt_record(wire, *args)
    assert decoded == record and decoded is not record
    assert type(decoded) is dict and type(decoded['payload']) is dict
    assert decoded['payload'] is not record['payload']
    return decoded


def _descriptor_reject(record, code, operation=SUBJECT, decode_code=None):
    args = _descriptor_args(operation)
    _reject(lambda: codec.encode_descriptor_receipt_record(record, *args), code)
    return _reject(lambda: codec.decode_descriptor_receipt_record(_wire(record), *args), decode_code or code)


def test_descriptor_receipt_record_canonical_examples():
    assert len(DESC_ENVELOPE_TYPES) == 14 and len(DESC_PAYLOAD_TYPES) == 11
    assert len(DESC_KNOWN_ROLES) == 11 and len(DESC_ALLOWED_ROLES) == 5
    for operation in (None, SUBJECT):
        for phase in DESC_PHASES:
            record = dict(_descriptor(operation), phase=phase)
            assert set(record) == {k for k, _ in DESC_ENVELOPE_TYPES}
            assert set(record['payload']) == {k for k, _ in DESC_PAYLOAD_TYPES}
            first, second = _descriptor_accept(record), _descriptor_accept(record)
            first['payload'].clear()
            first['receipt_id'] = 'changed'
            assert second == record
            reversed_record = dict(reversed(tuple(record.items())))
            reversed_record['payload'] = dict(reversed(tuple(record['payload'].items())))
            assert codec.encode_descriptor_receipt_record(reversed_record, *_descriptor_args(operation)) == _wire(record)
    record = _descriptor()
    assert record['issuer_instance_id'] != record['payload']['holder_instance_id']
    _descriptor_accept(record)
    record['issuer_instance_id'] = record['payload']['holder_instance_id']
    _descriptor_accept(record)
    for key, typ in DESC_PAYLOAD_TYPES:
        if typ.startswith('uuid'):
            record['payload'][key] = SUBJECT
    _descriptor_accept(record)


def test_descriptor_receipt_record_shape_and_type_rejections():
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class BoolHook:
        def __bool__(self):
            raise AssertionError('hook reached')
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _descriptor_reject(value, 'invalid_shape')
    _reject(lambda: codec.encode_descriptor_receipt_record(DictHook(_descriptor()), *_descriptor_args()), 'invalid_shape')
    for nested, fields in ((False, DESC_ENVELOPE_TYPES), (True, DESC_PAYLOAD_TYPES)):
        record = _descriptor()
        target = record['payload'] if nested else record
        target['RAW_SENTINEL'] = 'extra'
        _descriptor_reject(record, 'invalid_shape')
        for key, typ in fields:
            for mutation in ('missing', 'unknown'):
                record = _descriptor()
                target = record['payload'] if nested else record
                value = target.pop(key)
                if mutation == 'unknown':
                    target['RAW_SENTINEL'] = value
                _descriptor_reject(record, 'invalid_shape')
            bad_values = (None, True, False, 1.0, [], {}, 'RAW_SENTINEL')
            if typ != 'integer':
                bad_values += (0, 1)
            for bad in bad_values:
                if bad is None and typ.endswith('?') or bad is True and typ == 'true':
                    continue
                record = _descriptor()
                target = record['payload'] if nested else record
                target[key] = bad
                _descriptor_reject(record, 'invalid_shape' if typ == 'object' else 'invalid_value',
                                   decode_code='invalid_value' if typ == 'object' and type(bad) is float else None)
            record = _descriptor()
            target = record['payload'] if nested else record
            target[key] = (DictHook() if typ == 'object' else IntHook(1) if typ == 'integer'
                           else BoolHook() if typ == 'true' else StringHook('RAW_SENTINEL'))
            _reject(lambda: codec.encode_descriptor_receipt_record(record, *_descriptor_args()),
                    'invalid_shape' if typ == 'object' else 'invalid_value')
        for bad_key in (StringHook('x'), 'x' * 100000, 1):
            record = _descriptor()
            target = record['payload'] if nested else record
            target[bad_key] = target.pop(fields[0][0])
            _reject(lambda: codec.encode_descriptor_receipt_record(record, *_descriptor_args()), 'invalid_shape')


def test_descriptor_receipt_record_variant_and_nullability():
    for role in DESC_KNOWN_ROLES:
        record = dict(_descriptor(), issuer_role=role)
        if role in DESC_ALLOWED_ROLES:
            _descriptor_accept(record)
        else:
            _descriptor_reject(record, 'invalid_result')
    for key, bad in (('issuer_role', 'lifecycle_monitor'), ('phase', 'pre_write'),
                     ('schema_version', 's43-observation-v1')):
        _descriptor_reject(dict(_descriptor(), **{key: bad}), 'invalid_value')
    for kind in ('process_identity', 'socket_custody', 'source_custody', 'graph_closure', 'RAW_SENTINEL', ''):
        _descriptor_reject(dict(_descriptor(), kind=kind), 'invalid_value')
    for kind in DESC_OBJECTS:
        for access in ('read_only', 'write_only', 'read_write'):
            for seals in ('none', 'write_grow_shrink_seal'):
                record = _descriptor()
                record['payload'].update(object_kind=kind, access_mode=access, seals=seals)
                _descriptor_accept(record)
        # Syntax acceptance does not prove the required manifest/slot eligibility.
        for peer in (None, SUBJECT):
            for transfer in (None, OTHER):
                record = _descriptor()
                record['payload'].update(object_kind=kind, peer_instance_id=peer, transfer_id=transfer)
                _descriptor_accept(record)
    for key, values in {'object_kind': ('socket', 'RAW_SENTINEL'), 'access_mode': ('readonly', 'READ_ONLY'),
                        'seals': ('write_grow_shrink', ''), 'close_on_exec': (False, 0, 1, 'true')}.items():
        for bad in values:
            record = _descriptor()
            record['payload'][key] = bad
            _descriptor_reject(record, 'invalid_value')


def test_descriptor_receipt_record_scalar_bounds():
    for value in (0, 9223372036854775807):
        _descriptor_accept(dict(_descriptor(), observed_monotonic_ns=value))
    for value in (-1, 9223372036854775808, True, 0.0):
        _descriptor_reject(dict(_descriptor(), observed_monotonic_ns=value), 'invalid_value')
    for nested, fields in ((False, DESC_ENVELOPE_TYPES), (True, DESC_PAYLOAD_TYPES)):
        for key, typ in fields:
            if typ not in ('uuid', 'uuid?', 'hash'):
                continue
            valid = 'f' * 64 if typ == 'hash' else SUBJECT
            bad_values = (valid.upper(), valid + '\n', valid + 'x', 'x' + valid, valid[:-1], '')
            if typ != 'hash':
                bad_values += (SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
            for bad in bad_values:
                record = _descriptor()
                target = record['payload'] if nested else record
                target[key] = bad
                _descriptor_reject(record, 'invalid_value')
    for value in ('0' * 64, 'f' * 64):
        _descriptor_accept(dict(_descriptor(), runtime_lock_sha256=value))
    for key, maximum in (('fd_number', 2147483647), ('device', 18446744073709551615),
                         ('inode', 18446744073709551615)):
        for value in (0, 204, 205, maximum):
            record = _descriptor()
            record['payload'][key] = value
            _descriptor_accept(record)
        for value in (-1, maximum + 1, True, False, 0.0):
            record = _descriptor()
            record['payload'][key] = value
            _descriptor_reject(record, 'invalid_value')


def test_descriptor_receipt_record_expected_subject_binding():
    class StringSubclass(str):
        pass
    for operation in (None, SUBJECT):
        record = _descriptor(operation)
        args = _descriptor_args(operation)
        for index in range(4):
            changed = list(args)
            changed[index] = OTHER
            _reject(lambda: codec.encode_descriptor_receipt_record(record, *changed), 'wrong_subject')
            _reject(lambda: codec.decode_descriptor_receipt_record(_wire(record), *changed), 'wrong_subject')
            for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n', StringSubclass(SUBJECT)):
                changed = list(args)
                changed[index] = bad
                code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                _reject(lambda: codec.encode_descriptor_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_descriptor_receipt_record(_wire(record), *changed), code)
                _reject(lambda: codec.encode_descriptor_receipt_record(None, *changed), code)
                _reject(lambda: codec.decode_descriptor_receipt_record(b'', *changed), code)
            changed = list(args)
            changed[index] = None
            if index != 1 or operation is not None:
                code = 'wrong_subject' if index == 1 else 'invalid_shape'
                _reject(lambda: codec.encode_descriptor_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_descriptor_receipt_record(_wire(record), *changed), code)
        wrong = (OTHER, operation, CUST_GRAPH, CUST_RECEIPT)
        _reject(lambda: codec.decode_descriptor_receipt_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
        record['issuer_role'] = 'broker'
        _reject(lambda: codec.encode_descriptor_receipt_record(record, *wrong), 'invalid_result')
        _reject(lambda: codec.decode_descriptor_receipt_record(_wire(record), *wrong), 'invalid_result')


def test_descriptor_receipt_record_encoding_and_depth():
    class BytesSubclass(bytes):
        pass
    record = _descriptor()
    wire = _wire(record)
    args = _descriptor_args()
    reverse_payload = json.dumps(dict(reversed(tuple(record['payload'].items()))), separators=(',', ':')).encode('ascii')
    for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                  wire.replace(_wire(record['payload']), reverse_payload), wire + b'\n', b' ' + wire,
                  wire.replace(b':', b': ', 1), wire.replace(b'"s43-physical-receipt-v1"', b'"\\u007343-physical-receipt-v1"'),
                  wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x', b'{"x":"\\q"}',
                  b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
        error = _reject(lambda: codec.decode_descriptor_receipt_record(frame, *args), 'invalid_encoding')
        assert error.__context__ is None and error.__cause__ is None
    for frame in (b'{"receipt_id":null,' + wire[1:], b'{"receip\\u0074_id":null,' + wire[1:],
                  wire.replace(b'"payload":{', b'"payload":{"transfer_id":null,')):
        _reject(lambda: codec.decode_descriptor_receipt_record(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_descriptor_receipt_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None, BytesSubclass(wire)):
        _reject(lambda: codec.decode_descriptor_receipt_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            _reject(lambda: codec.decode_descriptor_receipt_record(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_descriptor_receipt_record(b' ' * 4096, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_descriptor_receipt_record(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        _descriptor_accept(record)
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _descriptor_reject(dict(_descriptor(), schema_version=text), 'invalid_value')
        oversized = dict(_descriptor(), schema_version='x' * 100000)
        _reject(lambda: codec.encode_descriptor_receipt_record(oversized, *args), 'invalid_value')
        _reject(lambda: codec.decode_descriptor_receipt_record(_wire(oversized), *args), 'invalid_encoding')
    finally:
        json.loads = original_loads


# Independent process expectations; no production schema-derived expected values.
PROC_ENVELOPE_TYPES = (
    ('clock_epoch_id', 'uuid'), ('graph_id', 'uuid'), ('issuer_instance_id', 'uuid'),
    ('issuer_role', 'enum'), ('kind', 'enum'), ('observed_monotonic_ns', 'integer'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('phase', 'enum'), ('receipt_id', 'uuid'), ('runtime_lock_sha256', 'hash'),
    ('schema_version', 'enum'), ('subject_owner_id', 'uuid'),
)
PROC_PAYLOAD_TYPES = (
    ('boot_id', 'uuid'), ('effective_capabilities', 'mask'), ('gid', 'integer'),
    ('instance_id', 'uuid'), ('no_new_privileges', 'true'),
    ('observer_pid_namespace_inode', 'integer'), ('parent_instance_id', 'uuid?'),
    ('pid_in_observer_namespace', 'integer'), ('pid_in_subject_namespace', 'integer'),
    ('pidfd_reference', 'uuid'), ('role', 'enum'), ('runtime_image_sha256', 'hash'),
    ('start_ticks', 'integer'), ('subject_pid_namespace_inode', 'integer'),
    ('task_count', 'integer'), ('uid', 'integer'),
)
PROC_KNOWN_ROLES = ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
                    'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')
PROC_CHILD_ROLES = ('broker', 'reviewer', 'fixture_source', 'connector', 'operation_worker',
                    'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')
PROC_TASK_MAXIMA = {'supervisor': 1, 'broker': 2, 'reviewer': 2, 'fixture_source': 1,
                   'connector': 1, 'operation_worker': 1, 'release_guard': 1,
                   'owned_service': 1, 'graphical_display': 8, 'fixture_probe': 1}
PROC_PHASES = ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed')


def _process(operation=SUBJECT):
    return dict(clock_epoch_id=OTHER, graph_id=CUST_GRAPH, issuer_instance_id=SUBJECT,
        issuer_role='supervisor', kind='process_identity', observed_monotonic_ns=0,
        observer_session_id=OTHER, operation_id=operation, phase='ready', receipt_id=CUST_RECEIPT,
        runtime_lock_sha256='a' * 64, schema_version='s43-physical-receipt-v1', subject_owner_id=CUST_OWNER,
        payload=dict(boot_id=OTHER, effective_capabilities='0000000000000000', gid=0,
            instance_id=OTHER, no_new_privileges=True, observer_pid_namespace_inode=0,
            parent_instance_id=None, pid_in_observer_namespace=1, pid_in_subject_namespace=1,
            pidfd_reference=SUBJECT, role='broker', runtime_image_sha256='f' * 64,
            start_ticks=0, subject_pid_namespace_inode=0, task_count=1, uid=0))


PROC_CANONICAL_BYTES = (
    b'{"clock_epoch_id":"22345678-1234-4234-9234-123456789abc","graph_id":"72345678-1234-4234-9234-1234567'
    b'89abc","issuer_instance_id":"12345678-1234-4234-9234-123456789abc","issuer_role":"supervisor","kind"'
    b':"process_identity","observed_monotonic_ns":0,"observer_session_id":"22345678-1234-4234-9234-1234567'
    b'89abc","operation_id":"12345678-1234-4234-9234-123456789abc","payload":{"boot_id":"22345678-1234-423'
    b'4-9234-123456789abc","effective_capabilities":"0000000000000000","gid":0,"instance_id":"22345678-123'
    b'4-4234-9234-123456789abc","no_new_privileges":true,"observer_pid_namespace_inode":0,"parent_instance'
    b'_id":null,"pid_in_observer_namespace":1,"pid_in_subject_namespace":1,"pidfd_reference":"12345678-123'
    b'4-4234-9234-123456789abc","role":"broker","runtime_image_sha256":"ffffffffffffffffffffffffffffffffff'
    b'ffffffffffffffffffffffffffffff","start_ticks":0,"subject_pid_namespace_inode":0,"task_count":1,"uid"'
    b':0},"phase":"ready","receipt_id":"82345678-1234-4234-9234-123456789abc","runtime_lock_sha256":"aaaaa'
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":"s43-physical-receipt-'
    b'v1","subject_owner_id":"62345678-1234-4234-9234-123456789abc"}'
)


def _process_args(operation=SUBJECT):
    return CUST_OWNER, operation, CUST_GRAPH, CUST_RECEIPT


def _process_accept(record):
    args = tuple(record[k] for k in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id'))
    wire = _wire(record)
    assert codec.encode_process_receipt_record(record, *args) == wire
    decoded = codec.decode_process_receipt_record(wire, *args)
    assert decoded == record and decoded is not record
    assert type(decoded) is dict and type(decoded['payload']) is dict
    assert decoded['payload'] is not record['payload']
    return decoded


def _process_reject(record, code, operation=SUBJECT, decode_code=None):
    args = _process_args(operation)
    _reject(lambda: codec.encode_process_receipt_record(record, *args), code)
    return _reject(lambda: codec.decode_process_receipt_record(_wire(record), *args), decode_code or code)


def test_process_receipt_record_canonical_examples():
    assert len(PROC_ENVELOPE_TYPES) == 14 and len(PROC_PAYLOAD_TYPES) == 16
    assert len(PROC_KNOWN_ROLES) == 11 and len(PROC_CHILD_ROLES) == 9
    assert codec.encode_process_receipt_record(_process(), *_process_args()) == PROC_CANONICAL_BYTES
    assert codec.decode_process_receipt_record(PROC_CANONICAL_BYTES, *_process_args()) == _process()
    for operation in (None, SUBJECT):
        for parent in (None, SUBJECT):
            for phase in PROC_PHASES:
                record = dict(_process(operation), phase=phase)
                record['payload']['parent_instance_id'] = parent
                assert set(record) == {k for k, _ in PROC_ENVELOPE_TYPES}
                assert set(record['payload']) == {k for k, _ in PROC_PAYLOAD_TYPES}
                first, second = _process_accept(record), _process_accept(record)
                first['payload'].clear()
                first['receipt_id'] = 'changed'
                assert second == record
                reversed_record = dict(reversed(tuple(record.items())))
                reversed_record['payload'] = dict(reversed(tuple(record['payload'].items())))
                assert codec.encode_process_receipt_record(reversed_record, *_process_args(operation)) == _wire(record)
    record = _process()
    for key, typ in PROC_PAYLOAD_TYPES:
        if typ.startswith('uuid'):
            record['payload'][key] = SUBJECT
    # Equal/repeated IDs and nullable parents are syntax, not proved live parentage.
    _process_accept(record)
    record['payload']['parent_instance_id'] = OTHER
    _process_accept(record)


def test_process_receipt_record_shape_and_type_rejections():
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class BoolHook:
        def __bool__(self):
            raise AssertionError('hook reached')
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _process_reject(value, 'invalid_shape')
    _reject(lambda: codec.encode_process_receipt_record(DictHook(_process()), *_process_args()), 'invalid_shape')
    for nested, fields in ((False, PROC_ENVELOPE_TYPES), (True, PROC_PAYLOAD_TYPES)):
        record = _process()
        target = record['payload'] if nested else record
        target['RAW_SENTINEL'] = 'extra'
        _process_reject(record, 'invalid_shape')
        for key, typ in fields:
            for mutation in ('missing', 'unknown'):
                record = _process()
                target = record['payload'] if nested else record
                value = target.pop(key)
                if mutation == 'unknown':
                    target['RAW_SENTINEL'] = value
                _process_reject(record, 'invalid_shape')
            bad_values = (None, True, False, 1.0, [], {}, 'RAW_SENTINEL')
            if typ != 'integer':
                bad_values += (0, 1)
            for bad in bad_values:
                if bad is None and typ.endswith('?') or bad is True and typ == 'true':
                    continue
                record = _process()
                target = record['payload'] if nested else record
                target[key] = bad
                _process_reject(record, 'invalid_shape' if typ == 'object' else 'invalid_value',
                                   decode_code='invalid_value' if typ == 'object' and type(bad) is float else None)
            record = _process()
            target = record['payload'] if nested else record
            target[key] = (DictHook() if typ == 'object' else IntHook(1) if typ == 'integer'
                           else BoolHook() if typ == 'true' else StringHook('RAW_SENTINEL'))
            _reject(lambda: codec.encode_process_receipt_record(record, *_process_args()),
                    'invalid_shape' if typ == 'object' else 'invalid_value')
        for bad_key in (StringHook('x'), 'x' * 100000, 1):
            record = _process()
            target = record['payload'] if nested else record
            target[bad_key] = target.pop(fields[0][0])
            _reject(lambda: codec.encode_process_receipt_record(record, *_process_args()), 'invalid_shape')


def test_process_receipt_record_role_capability_and_task_relations():
    accepted = []
    for issuer in PROC_KNOWN_ROLES:
        for role in PROC_KNOWN_ROLES:
            record = dict(_process(), issuer_role=issuer)
            record['payload']['role'] = role
            permitted = (issuer == 'driver' and role == 'supervisor'
                         or issuer == 'supervisor' and role in PROC_CHILD_ROLES)
            if permitted:
                _process_accept(record)
                accepted.append((issuer, role))
            else:
                _process_reject(record, 'invalid_result')
    assert len(accepted) == 10
    for key, bad in (('issuer_role', 'lifecycle_monitor'), ('phase', 'pre_write'),
                     ('schema_version', 's43-observation-v1')):
        _process_reject(dict(_process(), **{key: bad}), 'invalid_value')
    for issuer in PROC_KNOWN_ROLES:
        record = dict(_process(), issuer_role=issuer)
        record['payload']['role'] = 'unknown'
        _process_reject(record, 'invalid_value')
    for kind in ('descriptor_identity', 'socket_custody', 'source_custody', 'graph_closure', 'RAW_SENTINEL', ''):
        _process_reject(dict(_process(), kind=kind), 'invalid_value')
    for role, maximum in PROC_TASK_MAXIMA.items():
        record = dict(_process(), issuer_role='driver' if role == 'supervisor' else 'supervisor')
        record['payload']['role'] = role
        for count in (1, maximum):
            record['payload']['task_count'] = count
            _process_accept(record)
        record['payload']['task_count'] = maximum + 1
        _process_reject(record, 'invalid_value' if maximum == 8 else 'invalid_result')
        record['payload']['task_count'] = 1
        for mask in ('0000000000000000', '0000000000000001', '0123456789abcdef', 'ffffffffffffffff'):
            record['payload']['effective_capabilities'] = mask
            if role == 'supervisor' or mask == '0000000000000000':
                _process_accept(record)
            else:
                _process_reject(record, 'invalid_result')
        for mask in ('', '0' * 15, '0' * 17, 'F' * 16, 'g' * 16, '0' * 16 + '\n',
                     '0x' + '0' * 14, '0' * 16 + 'x', 'x' + '0' * 16, '0' * 100000):
            record['payload']['effective_capabilities'] = mask
            _reject(lambda: codec.encode_process_receipt_record(record, *_process_args()), 'invalid_value')
            _reject(lambda: codec.decode_process_receipt_record(_wire(record), *_process_args()),
                    'invalid_encoding' if len(mask) > 4096 else 'invalid_value')
    record = _process()
    record['payload']['task_count'] = 2
    _process_accept(record)  # Broker2 does not grant concurrent/recovery eligibility.
    record['payload']['role'] = 'graphical_display'
    for count in (1, 8):
        record['payload']['task_count'] = count
        _process_accept(record)
    for count in (0, 9, True, False, 1.0):
        record['payload']['task_count'] = count
        _process_reject(record, 'invalid_value')


def test_process_receipt_record_scalar_bounds():
    for value in (0, 9223372036854775807):
        _process_accept(dict(_process(), observed_monotonic_ns=value))
    for value in (-1, 9223372036854775808, True, 0.0):
        _process_reject(dict(_process(), observed_monotonic_ns=value), 'invalid_value')
    for nested, fields in ((False, PROC_ENVELOPE_TYPES), (True, PROC_PAYLOAD_TYPES)):
        for key, typ in fields:
            if typ not in ('uuid', 'uuid?', 'hash'):
                continue
            valid = 'f' * 64 if typ == 'hash' else SUBJECT
            bad_values = (valid.upper(), valid + '\n', valid + 'x', 'x' + valid, valid[:-1], '')
            if typ != 'hash':
                bad_values += (SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
            for bad in bad_values:
                record = _process()
                target = record['payload'] if nested else record
                target[key] = bad
                _process_reject(record, 'invalid_value')
    for value in ('0' * 64, 'f' * 64):
        _process_accept(dict(_process(), runtime_lock_sha256=value))
    for key, minimum, maximum in (
            ('pid_in_observer_namespace', 1, 2147483647), ('pid_in_subject_namespace', 1, 2147483647),
            ('observer_pid_namespace_inode', 0, 18446744073709551615),
            ('subject_pid_namespace_inode', 0, 18446744073709551615), ('start_ticks', 0, 18446744073709551615),
            ('uid', 0, 4294967294), ('gid', 0, 4294967294)):
        for value in (minimum, 11, 12, maximum):
            record = _process()
            record['payload'][key] = value
            _process_accept(record)
        for value in (minimum - 1, maximum + 1, True, False, 1.0):
            record = _process()
            record['payload'][key] = value
            _process_reject(record, 'invalid_value')
    for value in ('0' * 64, 'f' * 64):
        record = _process()
        record['payload']['runtime_image_sha256'] = value
        _process_accept(record)
    # Runtime PID1/namespace binding is not inferred from a claimed supervisor role.
    record = dict(_process(), issuer_role='driver')
    record['payload'].update(role='supervisor', pid_in_subject_namespace=2147483647)
    _process_accept(record)


def test_process_receipt_record_expected_subject_binding():
    class StringSubclass(str):
        pass
    for operation in (None, SUBJECT):
        record = _process(operation)
        args = _process_args(operation)
        for index in range(4):
            changed = list(args)
            changed[index] = OTHER
            _reject(lambda: codec.encode_process_receipt_record(record, *changed), 'wrong_subject')
            _reject(lambda: codec.decode_process_receipt_record(_wire(record), *changed), 'wrong_subject')
            for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n', StringSubclass(SUBJECT)):
                changed = list(args)
                changed[index] = bad
                code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                _reject(lambda: codec.encode_process_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_process_receipt_record(_wire(record), *changed), code)
                _reject(lambda: codec.encode_process_receipt_record(None, *changed), code)
                _reject(lambda: codec.decode_process_receipt_record(b'', *changed), code)
            changed = list(args)
            changed[index] = None
            if index != 1 or operation is not None:
                code = 'wrong_subject' if index == 1 else 'invalid_shape'
                _reject(lambda: codec.encode_process_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_process_receipt_record(_wire(record), *changed), code)
        wrong = (OTHER, operation, CUST_GRAPH, CUST_RECEIPT)
        _reject(lambda: codec.decode_process_receipt_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
        record['issuer_role'] = 'broker'
        _reject(lambda: codec.encode_process_receipt_record(record, *wrong), 'invalid_result')
        _reject(lambda: codec.decode_process_receipt_record(_wire(record), *wrong), 'invalid_result')


def test_process_receipt_record_encoding_and_depth():
    class BytesSubclass(bytes):
        pass
    record = _process()
    wire = _wire(record)
    args = _process_args()
    reverse_payload = json.dumps(dict(reversed(tuple(record['payload'].items()))), separators=(',', ':')).encode('ascii')
    for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                  wire.replace(_wire(record['payload']), reverse_payload), wire + b'\n', b' ' + wire,
                  wire.replace(b':', b': ', 1), wire.replace(b'"s43-physical-receipt-v1"', b'"\\u007343-physical-receipt-v1"'),
                  wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x', b'{"x":"\\q"}',
                  b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
        error = _reject(lambda: codec.decode_process_receipt_record(frame, *args), 'invalid_encoding')
        assert error.__context__ is None and error.__cause__ is None
    for frame in (b'{"receipt_id":null,' + wire[1:], b'{"receip\\u0074_id":null,' + wire[1:],
                  wire.replace(b'"payload":{', b'"payload":{"parent_instance_id":null,')):
        _reject(lambda: codec.decode_process_receipt_record(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_process_receipt_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None, BytesSubclass(wire)):
        _reject(lambda: codec.decode_process_receipt_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            _reject(lambda: codec.decode_process_receipt_record(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_process_receipt_record(b' ' * 4096, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_process_receipt_record(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        _process_accept(record)
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _process_reject(dict(_process(), schema_version=text), 'invalid_value')
        oversized = dict(_process(), schema_version='x' * 100000)
        _reject(lambda: codec.encode_process_receipt_record(oversized, *args), 'invalid_value')
        _reject(lambda: codec.decode_process_receipt_record(_wire(oversized), *args), 'invalid_encoding')
    finally:
        json.loads = original_loads


# Independent termination expectations; do not import production schema tables.
TERM_ENVELOPE_TYPES = (
    ('clock_epoch_id', 'uuid'), ('graph_id', 'uuid'), ('issuer_instance_id', 'uuid'),
    ('issuer_role', 'enum'), ('kind', 'enum'), ('observed_monotonic_ns', 'integer'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('phase', 'enum'), ('receipt_id', 'uuid'), ('runtime_lock_sha256', 'hash'),
    ('schema_version', 'enum'), ('subject_owner_id', 'uuid'),
)
TERM_PAYLOAD_TYPES = (
    ('birth_process_receipt_id', 'uuid'), ('exit_code', 'enum'), ('exit_status', 'integer'),
    ('instance_id', 'uuid'), ('monitor_session_id', 'uuid'), ('pidfd_reference', 'uuid'),
    ('reaped_monotonic_ns', 'integer'), ('si_pid', 'integer'), ('si_signo', 'enum'), ('si_uid', 'integer'),
)
TERM_KNOWN_ROLES = ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
                   'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')
TERM_ALLOWED_ROLES = ('driver', 'supervisor')
TERM_EXIT_CODES = ('CLD_EXITED', 'CLD_KILLED', 'CLD_DUMPED')
TERM_PHASES = ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed')


def _termination(operation=SUBJECT):
    return dict(clock_epoch_id=OTHER, graph_id=CUST_GRAPH, issuer_instance_id=SUBJECT,
        issuer_role='supervisor', kind='monitor_termination', observed_monotonic_ns=0,
        observer_session_id=OTHER, operation_id=operation, phase='ready', receipt_id=CUST_RECEIPT,
        runtime_lock_sha256='a' * 64, schema_version='s43-physical-receipt-v1', subject_owner_id=CUST_OWNER,
        payload=dict(birth_process_receipt_id=OTHER, exit_code='CLD_EXITED', exit_status=0,
            instance_id=OTHER, monitor_session_id=SUBJECT, pidfd_reference=SUBJECT,
            reaped_monotonic_ns=0, si_pid=1, si_signo='SIGCHLD', si_uid=0))


TERM_CANONICAL_BYTES = (
    b'{"clock_epoch_id":"22345678-1234-4234-9234-123456789abc","graph_id":"72345678-1234-4234-9234-1234567'
    b'89abc","issuer_instance_id":"12345678-1234-4234-9234-123456789abc","issuer_role":"supervisor","kind"'
    b':"monitor_termination","observed_monotonic_ns":0,"observer_session_id":"22345678-1234-4234-9234-1234'
    b'56789abc","operation_id":"12345678-1234-4234-9234-123456789abc","payload":{"birth_process_receipt_id'
    b'":"22345678-1234-4234-9234-123456789abc","exit_code":"CLD_EXITED","exit_status":0,"instance_id":"223'
    b'45678-1234-4234-9234-123456789abc","monitor_session_id":"12345678-1234-4234-9234-123456789abc","pidf'
    b'd_reference":"12345678-1234-4234-9234-123456789abc","reaped_monotonic_ns":0,"si_pid":1,"si_signo":"S'
    b'IGCHLD","si_uid":0},"phase":"ready","receipt_id":"82345678-1234-4234-9234-123456789abc","runtime_loc'
    b'k_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":"s43-p'
    b'hysical-receipt-v1","subject_owner_id":"62345678-1234-4234-9234-123456789abc"}'
)


def _termination_args(operation=SUBJECT):
    return CUST_OWNER, operation, CUST_GRAPH, CUST_RECEIPT


def _termination_accept(record):
    args = tuple(record[k] for k in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id'))
    wire = _wire(record)
    assert codec.encode_termination_receipt_record(record, *args) == wire
    decoded = codec.decode_termination_receipt_record(wire, *args)
    assert decoded == record and decoded is not record
    assert type(decoded) is dict and type(decoded['payload']) is dict
    assert decoded['payload'] is not record['payload']
    return decoded


def _termination_reject(record, code, operation=SUBJECT, decode_code=None):
    args = _termination_args(operation)
    _reject(lambda: codec.encode_termination_receipt_record(record, *args), code)
    return _reject(lambda: codec.decode_termination_receipt_record(_wire(record), *args), decode_code or code)


def test_termination_receipt_record_canonical_examples():
    assert len(TERM_ENVELOPE_TYPES) == 14 and len(TERM_PAYLOAD_TYPES) == 10
    assert len(TERM_KNOWN_ROLES) == 11 and len(TERM_ALLOWED_ROLES) == 2
    assert codec.encode_termination_receipt_record(_termination(), *_termination_args()) == TERM_CANONICAL_BYTES
    assert codec.decode_termination_receipt_record(TERM_CANONICAL_BYTES, *_termination_args()) == _termination()
    for operation in (None, SUBJECT):
        for phase in TERM_PHASES:
            record = dict(_termination(operation), phase=phase)
            assert set(record) == {k for k, _ in TERM_ENVELOPE_TYPES}
            assert set(record['payload']) == {k for k, _ in TERM_PAYLOAD_TYPES}
            first, second = _termination_accept(record), _termination_accept(record)
            first['payload'].clear()
            first['receipt_id'] = 'changed'
            assert second == record
            reversed_record = dict(reversed(tuple(record.items())))
            reversed_record['payload'] = dict(reversed(tuple(record['payload'].items())))
            assert codec.encode_termination_receipt_record(reversed_record, *_termination_args(operation)) == _wire(record)
    record = _termination()
    assert record['payload']['monitor_session_id'] != record['observer_session_id']
    _termination_accept(record)
    record['payload']['monitor_session_id'] = record['observer_session_id']
    _termination_accept(record)
    for key, typ in TERM_PAYLOAD_TYPES:
        if typ == 'uuid':
            record['payload'][key] = SUBJECT
    # Repeated/equal IDs are representable claims, not live ancestry evidence.
    _termination_accept(record)
    for observed, reaped in ((0, 0), (0, 1), (1, 0), (0, 9223372036854775807),
                             (9223372036854775807, 0), (9223372036854775807, 9223372036854775807)):
        record = dict(_termination(), observed_monotonic_ns=observed)
        record['payload']['reaped_monotonic_ns'] = reaped
        _termination_accept(record)


def test_termination_receipt_record_shape_and_type_rejections():
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class BoolHook:
        def __bool__(self):
            raise AssertionError('hook reached')
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _termination_reject(value, 'invalid_shape')
    _reject(lambda: codec.encode_termination_receipt_record(DictHook(_termination()), *_termination_args()), 'invalid_shape')
    for nested, fields in ((False, TERM_ENVELOPE_TYPES), (True, TERM_PAYLOAD_TYPES)):
        record = _termination()
        target = record['payload'] if nested else record
        target['RAW_SENTINEL'] = 'extra'
        _termination_reject(record, 'invalid_shape')
        for key, typ in fields:
            for mutation in ('missing', 'unknown'):
                record = _termination()
                target = record['payload'] if nested else record
                value = target.pop(key)
                if mutation == 'unknown':
                    target['RAW_SENTINEL'] = value
                _termination_reject(record, 'invalid_shape')
            bad_values = (None, True, False, 1.0, [], {}, 'RAW_SENTINEL')
            if typ != 'integer':
                bad_values += (0, 1)
            for bad in bad_values:
                if bad is None and typ.endswith('?') or bad is True and typ == 'true':
                    continue
                record = _termination()
                target = record['payload'] if nested else record
                target[key] = bad
                _termination_reject(record, 'invalid_shape' if typ == 'object' else 'invalid_value',
                                   decode_code='invalid_value' if typ == 'object' and type(bad) is float else None)
            record = _termination()
            target = record['payload'] if nested else record
            target[key] = (DictHook() if typ == 'object' else IntHook(1) if typ == 'integer'
                           else BoolHook() if typ == 'true' else StringHook('RAW_SENTINEL'))
            _reject(lambda: codec.encode_termination_receipt_record(record, *_termination_args()),
                    'invalid_shape' if typ == 'object' else 'invalid_value')
        for bad_key in (StringHook('x'), 'x' * 100000, 1):
            record = _termination()
            target = record['payload'] if nested else record
            target[bad_key] = target.pop(fields[0][0])
            _reject(lambda: codec.encode_termination_receipt_record(record, *_termination_args()), 'invalid_shape')


def test_termination_receipt_record_issuer_and_exit_codes():
    for issuer in TERM_KNOWN_ROLES:
        record = dict(_termination(), issuer_role=issuer)
        if issuer in TERM_ALLOWED_ROLES:
            _termination_accept(record)
        else:
            _termination_reject(record, 'invalid_result')
    for key, bad in (('issuer_role', 'lifecycle_monitor'), ('phase', 'pre_write'),
                     ('schema_version', 's43-observation-v1')):
        _termination_reject(dict(_termination(), **{key: bad}), 'invalid_value')
    for kind in ('process_identity', 'descriptor_identity', 'socket_custody', 'source_custody',
                 'graph_closure', 'recovery_lifecycle', 'RAW_SENTINEL', ''):
        _termination_reject(dict(_termination(), kind=kind), 'invalid_value')
    for issuer in TERM_ALLOWED_ROLES:
        for code in TERM_EXIT_CODES:
            for status in (0, 1, 127, 255):
                record = dict(_termination(), issuer_role=issuer)
                record['payload'].update(exit_code=code, exit_status=status)
                _termination_accept(record)
    # These claims never establish successful source/connector closure.
    for key, values in {
            'exit_code': ('CLD_STOPPED', 'CLD_CONTINUED', 'CLD_TRAPPED', 'cld_exited', 'RAW_SENTINEL', ''),
            'si_signo': ('SIGTERM', 'SIGKILL', 'sigchld', '17', 17, 0, '', 'SIGCHLD\n')}.items():
        for bad in values:
            record = _termination()
            record['payload'][key] = bad
            _termination_reject(record, 'invalid_value')
    record = dict(_termination(), issuer_role='broker')
    record['payload']['exit_code'] = 'unknown'
    _termination_reject(record, 'invalid_value')


def test_termination_receipt_record_scalar_bounds():
    for value in (0, 9223372036854775807):
        _termination_accept(dict(_termination(), observed_monotonic_ns=value))
    for value in (-1, 9223372036854775808, True, 0.0):
        _termination_reject(dict(_termination(), observed_monotonic_ns=value), 'invalid_value')
    for nested, fields in ((False, TERM_ENVELOPE_TYPES), (True, TERM_PAYLOAD_TYPES)):
        for key, typ in fields:
            if typ not in ('uuid', 'uuid?', 'hash'):
                continue
            valid = 'f' * 64 if typ == 'hash' else SUBJECT
            bad_values = (valid.upper(), valid + '\n', valid + 'x', 'x' + valid, valid[:-1], '')
            if typ != 'hash':
                bad_values += (SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
            for bad in bad_values:
                record = _termination()
                target = record['payload'] if nested else record
                target[key] = bad
                _termination_reject(record, 'invalid_value')
    for value in ('0' * 64, 'f' * 64):
        _termination_accept(dict(_termination(), runtime_lock_sha256=value))
    for key, minimum, maximum in (
            ('exit_status', 0, 255), ('reaped_monotonic_ns', 0, 9223372036854775807),
            ('si_pid', 1, 2147483647), ('si_uid', 0, 4294967294)):
        for value in (minimum, 10, 11, maximum):
            record = _termination()
            record['payload'][key] = value
            _termination_accept(record)
        for value in (minimum - 1, maximum + 1, True, False, 1.0):
            record = _termination()
            record['payload'][key] = value
            _termination_reject(record, 'invalid_value')


def test_termination_receipt_record_expected_subject_binding():
    class StringSubclass(str):
        pass
    for operation in (None, SUBJECT):
        record = _termination(operation)
        args = _termination_args(operation)
        for index in range(4):
            changed = list(args)
            changed[index] = OTHER
            _reject(lambda: codec.encode_termination_receipt_record(record, *changed), 'wrong_subject')
            _reject(lambda: codec.decode_termination_receipt_record(_wire(record), *changed), 'wrong_subject')
            for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n', StringSubclass(SUBJECT)):
                changed = list(args)
                changed[index] = bad
                code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                _reject(lambda: codec.encode_termination_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_termination_receipt_record(_wire(record), *changed), code)
                _reject(lambda: codec.encode_termination_receipt_record(None, *changed), code)
                _reject(lambda: codec.decode_termination_receipt_record(b'', *changed), code)
            changed = list(args)
            changed[index] = None
            if index != 1 or operation is not None:
                code = 'wrong_subject' if index == 1 else 'invalid_shape'
                _reject(lambda: codec.encode_termination_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_termination_receipt_record(_wire(record), *changed), code)
        wrong = (OTHER, operation, CUST_GRAPH, CUST_RECEIPT)
        _reject(lambda: codec.decode_termination_receipt_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
        record['issuer_role'] = 'broker'
        _reject(lambda: codec.encode_termination_receipt_record(record, *wrong), 'invalid_result')
        _reject(lambda: codec.decode_termination_receipt_record(_wire(record), *wrong), 'invalid_result')


def test_termination_receipt_record_encoding_and_depth():
    class BytesSubclass(bytes):
        pass
    record = _termination()
    wire = _wire(record)
    args = _termination_args()
    reverse_payload = json.dumps(dict(reversed(tuple(record['payload'].items()))), separators=(',', ':')).encode('ascii')
    for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                  wire.replace(_wire(record['payload']), reverse_payload), wire + b'\n', b' ' + wire,
                  wire.replace(b':', b': ', 1), wire.replace(b'"s43-physical-receipt-v1"', b'"\\u007343-physical-receipt-v1"'),
                  wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x', b'{"x":"\\q"}',
                  b'x' * 2049, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
        error = _reject(lambda: codec.decode_termination_receipt_record(frame, *args), 'invalid_encoding')
        assert error.__context__ is None and error.__cause__ is None
    for frame in (b'{"receipt_id":null,' + wire[1:], b'{"receip\\u0074_id":null,' + wire[1:],
                  wire.replace(b'"payload":{', b'"payload":{"birth_process_receipt_id":null,')):
        _reject(lambda: codec.decode_termination_receipt_record(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_termination_receipt_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None, BytesSubclass(wire)):
        _reject(lambda: codec.decode_termination_receipt_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 2049, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            _reject(lambda: codec.decode_termination_receipt_record(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_termination_receipt_record(b' ' * 2048, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_termination_receipt_record(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        _termination_accept(record)
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _termination_reject(dict(_termination(), schema_version=text), 'invalid_value')
        oversized = dict(_termination(), schema_version='x' * 100000)
        _reject(lambda: codec.encode_termination_receipt_record(oversized, *args), 'invalid_value')
        _reject(lambda: codec.decode_termination_receipt_record(_wire(oversized), *args), 'invalid_encoding')
    finally:
        json.loads = original_loads


# Independent literal graph-closure expectations; no production-table imports.
GC_ENVELOPE_TYPES = (
    ('clock_epoch_id', 'uuid'), ('graph_id', 'uuid'), ('issuer_instance_id', 'uuid'),
    ('issuer_role', 'enum'), ('kind', 'enum'), ('observed_monotonic_ns', 'integer'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('phase', 'enum'), ('receipt_id', 'uuid'), ('runtime_lock_sha256', 'hash'),
    ('schema_version', 'enum'), ('subject_owner_id', 'uuid'),
)
GC_PAYLOAD_TYPES = (
    ('expected_processes', 'integer'), ('graph_id', 'uuid'), ('graph_manifest_sha256', 'hash'),
    ('member_process_receipt_ids', 'list'), ('outstanding_transfers', 'integer'),
    ('reaped_processes', 'integer'), ('reason', 'enum'), ('remaining_descriptors', 'integer'),
    ('scope', 'enum'), ('validated_receipt_set_sha256', 'hash'),
)
GC_ROLES = ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
            'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')
GC_PHASES = ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed')
GC_REASONS = ('operation_terminal', 'owner_recovery')


def _graph_closure(operation=SUBJECT):
    return dict(clock_epoch_id=OTHER, graph_id=CUST_GRAPH, issuer_instance_id=SUBJECT,
        issuer_role='supervisor', kind='graph_closure', observed_monotonic_ns=0,
        observer_session_id=OTHER, operation_id=operation, phase='ready', receipt_id=CUST_RECEIPT,
        runtime_lock_sha256='a' * 64, schema_version='s43-physical-receipt-v1', subject_owner_id=CUST_OWNER,
        payload=dict(expected_processes=2, graph_id=CUST_GRAPH, graph_manifest_sha256='b' * 64,
            member_process_receipt_ids=[OTHER, SUBJECT], outstanding_transfers=0, reaped_processes=2,
            reason='operation_terminal', remaining_descriptors=0,
            scope='owner_graph' if operation is None else 'operation_graph',
            validated_receipt_set_sha256='c' * 64))


GC_CANONICAL_BYTES = (
    b'{"clock_epoch_id":"22345678-1234-4234-9234-123456789abc","graph_id":"72345678-1234-4234-9234-123'
    b'456789abc","issuer_instance_id":"12345678-1234-4234-9234-123456789abc","issuer_role":"supervisor'
    b'","kind":"graph_closure","observed_monotonic_ns":0,"observer_session_id":"22345678-1234-4234-923'
    b'4-123456789abc","operation_id":"12345678-1234-4234-9234-123456789abc","payload":{"expected_proce'
    b'sses":2,"graph_id":"72345678-1234-4234-9234-123456789abc","graph_manifest_sha256":"bbbbbbbbbbbbb'
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","member_process_receipt_ids":["22345678-123'
    b'4-4234-9234-123456789abc","12345678-1234-4234-9234-123456789abc"],"outstanding_transfers":0,"rea'
    b'ped_processes":2,"reason":"operation_terminal","remaining_descriptors":0,"scope":"operation_grap'
    b'h","validated_receipt_set_sha256":"ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    b'ccc"},"phase":"ready","receipt_id":"82345678-1234-4234-9234-123456789abc","runtime_lock_sha256":'
    b'"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":"s43-physica'
    b'l-receipt-v1","subject_owner_id":"62345678-1234-4234-9234-123456789abc"}'
)


def _graph_closure_args(operation=SUBJECT):
    return CUST_OWNER, operation, CUST_GRAPH, CUST_RECEIPT


def _graph_closure_accept(record):
    args = tuple(record[k] for k in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id'))
    wire = _wire(record)
    assert codec.encode_graph_closure_receipt_record(record, *args) == wire
    decoded = codec.decode_graph_closure_receipt_record(wire, *args)
    assert decoded == record and decoded is not record
    assert type(decoded) is dict and type(decoded['payload']) is dict
    assert type(decoded['payload']['member_process_receipt_ids']) is list
    assert decoded['payload'] is not record['payload']
    assert decoded['payload']['member_process_receipt_ids'] is not record['payload']['member_process_receipt_ids']
    return decoded


def _graph_closure_reject(record, code, operation=SUBJECT, decode_code=None):
    args = _graph_closure_args(operation)
    _reject(lambda: codec.encode_graph_closure_receipt_record(record, *args), code)
    return _reject(lambda: codec.decode_graph_closure_receipt_record(_wire(record), *args), decode_code or code)


def test_graph_closure_receipt_record_canonical_examples():
    assert len(GC_ENVELOPE_TYPES) == 14 and len(GC_PAYLOAD_TYPES) == 10 and len(GC_ROLES) == 11
    assert codec.encode_graph_closure_receipt_record(_graph_closure(), *_graph_closure_args()) == GC_CANONICAL_BYTES
    assert codec.decode_graph_closure_receipt_record(GC_CANONICAL_BYTES, *_graph_closure_args()) == _graph_closure()
    for operation in (None, SUBJECT):
        for reason in GC_REASONS:
            for phase in GC_PHASES:
                record = dict(_graph_closure(operation), phase=phase)
                record['payload']['reason'] = reason
                assert set(record) == {k for k, _ in GC_ENVELOPE_TYPES}
                assert set(record['payload']) == {k for k, _ in GC_PAYLOAD_TYPES}
                first, second = _graph_closure_accept(record), _graph_closure_accept(record)
                first['payload']['member_process_receipt_ids'].clear()
                first['receipt_id'] = 'changed'
                assert second == record and record['payload']['member_process_receipt_ids'] == [OTHER, SUBJECT]
                reversed_record = dict(reversed(tuple(record.items())))
                reversed_record['payload'] = dict(reversed(tuple(record['payload'].items())))
                assert codec.encode_graph_closure_receipt_record(reversed_record, *_graph_closure_args(operation)) == _wire(record)
    record = _graph_closure()
    record['payload']['graph_manifest_sha256'] = record['payload']['validated_receipt_set_sha256']
    # Equal digests and IDs across unlike domains are representable, not live proof.
    _graph_closure_accept(record)
    record['payload']['member_process_receipt_ids'] = [SUBJECT, OTHER]
    assert _wire(record) != GC_CANONICAL_BYTES
    assert _graph_closure_accept(record)['payload']['member_process_receipt_ids'] == [SUBJECT, OTHER]


def test_graph_closure_receipt_record_shape_and_type_rejections():
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class ListHook(list):
        def __len__(self):
            raise AssertionError('hook reached')
        def __iter__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class ElementHook(str):
        def __hash__(self):
            raise AssertionError('hash hook reached')
        def __eq__(self, other):
            raise AssertionError('equality hook reached')
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _graph_closure_reject(value, 'invalid_shape')
    _reject(lambda: codec.encode_graph_closure_receipt_record(DictHook(_graph_closure()), *_graph_closure_args()), 'invalid_shape')
    for nested, fields in ((False, GC_ENVELOPE_TYPES), (True, GC_PAYLOAD_TYPES)):
        record = _graph_closure()
        target = record['payload'] if nested else record
        target['RAW_SENTINEL'] = 'extra'
        _graph_closure_reject(record, 'invalid_shape')
        for key, typ in fields:
            for mutation in ('missing', 'unknown'):
                record = _graph_closure()
                target = record['payload'] if nested else record
                value = target.pop(key)
                if mutation == 'unknown':
                    target['RAW_SENTINEL'] = value
                _graph_closure_reject(record, 'invalid_shape')
            bad_values = (None, True, False, 1.0, [], {}, 'RAW_SENTINEL')
            if typ != 'integer':
                bad_values += (0, 1)
            for bad in bad_values:
                if bad is None and typ.endswith('?') or typ == 'list' and bad == []:
                    continue
                record = _graph_closure()
                target = record['payload'] if nested else record
                target[key] = bad
                code = 'invalid_shape' if typ in ('object', 'list') else 'invalid_value'
                _graph_closure_reject(record, code,
                    decode_code='invalid_value' if typ in ('object', 'list') and type(bad) is float else None)
            record = _graph_closure()
            target = record['payload'] if nested else record
            target[key] = (DictHook() if typ == 'object' else ListHook() if typ == 'list'
                           else IntHook(1) if typ == 'integer' else StringHook('RAW_SENTINEL'))
            _reject(lambda: codec.encode_graph_closure_receipt_record(record, *_graph_closure_args()),
                    'invalid_shape' if typ in ('object', 'list') else 'invalid_value')
        for bad_key in (StringHook('x'), 'x' * 100000, 1):
            record = _graph_closure()
            target = record['payload'] if nested else record
            target[bad_key] = target.pop(fields[0][0])
            _reject(lambda: codec.encode_graph_closure_receipt_record(record, *_graph_closure_args()), 'invalid_shape')
    record = _graph_closure()
    record['payload']['member_process_receipt_ids'] = (OTHER, SUBJECT)
    _reject(lambda: codec.encode_graph_closure_receipt_record(record, *_graph_closure_args()), 'invalid_shape')
    for item in (None, True, 1, 1.0, [], {}, 'RAW_SENTINEL'):
        record = _graph_closure()
        record['payload']['member_process_receipt_ids'][0] = item
        _graph_closure_reject(record, 'invalid_value',
            decode_code='invalid_encoding' if type(item) in (list, dict) else None)
    for item in (StringHook(SUBJECT), ElementHook(SUBJECT), IntHook(1)):
        record = _graph_closure()
        record['payload']['member_process_receipt_ids'] = [item, item]
        _reject(lambda: codec.encode_graph_closure_receipt_record(record, *_graph_closure_args()), 'invalid_value')


def test_graph_closure_receipt_record_membership_and_scope_relations():
    for role in GC_ROLES:
        record = dict(_graph_closure(), issuer_role=role)
        if role == 'supervisor':
            _graph_closure_accept(record)
        else:
            _graph_closure_reject(record, 'invalid_result')
    for operation in (None, SUBJECT):
        record = _graph_closure(operation)
        record['payload']['scope'] = 'operation_graph' if operation is None else 'owner_graph'
        _graph_closure_reject(record, 'invalid_result', operation)
        for expected, reaped in ((1, 2), (2, 1), (1, 1), (0, 2), (2, 0), (11, 11)):
            record = _graph_closure(operation)
            record['payload'].update(expected_processes=expected, reaped_processes=reaped)
            _graph_closure_reject(record, 'invalid_result', operation)
    record = _graph_closure()
    record['payload']['graph_id'] = OTHER
    _graph_closure_reject(record, 'invalid_result')
    for members in ([SUBJECT, SUBJECT], [SUBJECT, OTHER, SUBJECT]):
        record = _graph_closure()
        record['payload'].update(member_process_receipt_ids=members,
            expected_processes=len(members), reaped_processes=len(members))
        _graph_closure_reject(record, 'invalid_value')
    for key, bad in (('issuer_role', 'lifecycle_monitor'), ('phase', 'pre_write'),
                     ('schema_version', 's43-observation-v1')):
        _graph_closure_reject(dict(_graph_closure(), **{key: bad}), 'invalid_value')
    for kind in ('process_identity', 'descriptor_identity', 'socket_custody', 'source_custody',
                 'monitor_termination', 'recovery_closure_binding', 'RAW_SENTINEL', ''):
        _graph_closure_reject(dict(_graph_closure(), kind=kind), 'invalid_value')
    for key, bad in (('scope', 'execution_graph'), ('scope', 'OWNER_GRAPH'),
                     ('reason', 'completed'), ('reason', 'OWNER_RECOVERY')):
        record = _graph_closure()
        record['payload'][key] = bad
        _graph_closure_reject(record, 'invalid_value')
    record = dict(_graph_closure(), issuer_role='broker')
    record['payload']['reason'] = 'unknown'
    _graph_closure_reject(record, 'invalid_value')


def test_graph_closure_receipt_record_scalar_bounds():
    for value in (0, 9223372036854775807):
        _graph_closure_accept(dict(_graph_closure(), observed_monotonic_ns=value))
    for value in (-1, 9223372036854775808, True, 0.0):
        _graph_closure_reject(dict(_graph_closure(), observed_monotonic_ns=value), 'invalid_value')
    for count in range(12):
        for operation in (None, SUBJECT):
            record = _graph_closure(operation)
            members = [f'{index:08x}-1234-4234-9234-123456789abc' for index in reversed(range(count))]
            record['payload'].update(expected_processes=count, reaped_processes=count, member_process_receipt_ids=members)
            assert _graph_closure_accept(record)['payload']['member_process_receipt_ids'] == members
    for key, maximum in (('expected_processes', 11), ('reaped_processes', 11),
                         ('remaining_descriptors', 0), ('outstanding_transfers', 0)):
        for bad in (-1, maximum + 1, True, False, 0.0):
            record = _graph_closure()
            record['payload'][key] = bad
            _graph_closure_reject(record, 'invalid_value')
    for count in (12, 100000):
        record = _graph_closure()
        record['payload']['member_process_receipt_ids'] = [None] * count
        _reject(lambda: codec.encode_graph_closure_receipt_record(record, *_graph_closure_args()), 'invalid_value')
        if count == 12:
            _graph_closure_reject(record, 'invalid_value')
    for nested, fields in ((False, GC_ENVELOPE_TYPES), (True, GC_PAYLOAD_TYPES)):
        for key, typ in fields:
            if typ not in ('uuid', 'uuid?', 'hash', 'list'):
                continue
            valid = 'f' * 64 if typ == 'hash' else SUBJECT
            bad_values = (valid.upper(), valid + '\n', valid + 'x', 'x' + valid, valid[:-1], '')
            if typ != 'hash':
                bad_values += (SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
            for bad in bad_values:
                record = _graph_closure()
                target = record['payload'] if nested else record
                target[key] = [bad, OTHER] if typ == 'list' else bad
                _graph_closure_reject(record, 'invalid_value')
            if typ == 'hash':
                for value in ('0' * 64, 'f' * 64):
                    record = _graph_closure()
                    target = record['payload'] if nested else record
                    target[key] = value
                    _graph_closure_accept(record)


def test_graph_closure_receipt_record_expected_subject_binding():
    class StringSubclass(str):
        pass
    for operation in (None, SUBJECT):
        record = _graph_closure(operation)
        args = _graph_closure_args(operation)
        for index in range(4):
            changed = list(args)
            changed[index] = OTHER
            _reject(lambda: codec.encode_graph_closure_receipt_record(record, *changed), 'wrong_subject')
            _reject(lambda: codec.decode_graph_closure_receipt_record(_wire(record), *changed), 'wrong_subject')
            for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n', StringSubclass(SUBJECT)):
                changed = list(args)
                changed[index] = bad
                code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                _reject(lambda: codec.encode_graph_closure_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_graph_closure_receipt_record(_wire(record), *changed), code)
                _reject(lambda: codec.encode_graph_closure_receipt_record(None, *changed), code)
                _reject(lambda: codec.decode_graph_closure_receipt_record(b'', *changed), code)
            changed = list(args)
            changed[index] = None
            if index != 1 or operation is not None:
                code = 'wrong_subject' if index == 1 else 'invalid_shape'
                _reject(lambda: codec.encode_graph_closure_receipt_record(record, *changed), code)
                _reject(lambda: codec.decode_graph_closure_receipt_record(_wire(record), *changed), code)
        wrong = (OTHER, operation, CUST_GRAPH, CUST_RECEIPT)
        _reject(lambda: codec.decode_graph_closure_receipt_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
        record['payload']['graph_id'] = OTHER
        _reject(lambda: codec.encode_graph_closure_receipt_record(record, *wrong), 'invalid_result')
        _reject(lambda: codec.decode_graph_closure_receipt_record(_wire(record), *wrong), 'invalid_result')


def test_graph_closure_receipt_record_encoding_and_depth():
    class BytesSubclass(bytes):
        pass
    record = _graph_closure()
    wire = _wire(record)
    args = _graph_closure_args()
    reverse_payload = json.dumps(dict(reversed(tuple(record['payload'].items()))), separators=(',', ':')).encode('ascii')
    for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                  wire.replace(_wire(record['payload']), reverse_payload), wire + b'\n', b' ' + wire,
                  wire.replace(b':', b': ', 1), wire.replace(b'"s43-physical-receipt-v1"', b'"\\u007343-physical-receipt-v1"'),
                  wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x', b'{"x":"\\q"}',
                  b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]', wire.replace(_wire(record['payload']['member_process_receipt_ids']), b'[[]]')):
        error = _reject(lambda: codec.decode_graph_closure_receipt_record(frame, *args), 'invalid_encoding')
        assert error.__context__ is None and error.__cause__ is None
    for frame in (b'{"receipt_id":null,' + wire[1:], b'{"receip\\u0074_id":null,' + wire[1:],
                  wire.replace(b'"payload":{', b'"payload":{"expected_processes":null,')):
        _reject(lambda: codec.decode_graph_closure_receipt_record(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_graph_closure_receipt_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None, BytesSubclass(wire)):
        _reject(lambda: codec.decode_graph_closure_receipt_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 4097, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]', wire.replace(_wire(record['payload']['member_process_receipt_ids']), b'[[]]')):
            _reject(lambda: codec.decode_graph_closure_receipt_record(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_graph_closure_receipt_record(b' ' * 4096, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_graph_closure_receipt_record(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        _graph_closure_accept(record)
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _graph_closure_reject(dict(_graph_closure(), schema_version=text), 'invalid_value')
        oversized = dict(_graph_closure(), schema_version='x' * 100000)
        _reject(lambda: codec.encode_graph_closure_receipt_record(oversized, *args), 'invalid_value')
        _reject(lambda: codec.decode_graph_closure_receipt_record(_wire(oversized), *args), 'invalid_encoding')
    finally:
        json.loads = original_loads


# Independent recovery-binding expectations; no production-table imports.
RB_ENVELOPE_TYPES = (
    ('clock_epoch_id', 'uuid'), ('graph_id', 'uuid'), ('issuer_instance_id', 'uuid'),
    ('issuer_role', 'enum'), ('kind', 'enum'), ('observed_monotonic_ns', 'integer'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('phase', 'enum'), ('receipt_id', 'uuid'), ('runtime_lock_sha256', 'hash'),
    ('schema_version', 'enum'), ('subject_owner_id', 'uuid'),
)
RB_PAYLOAD_TYPES = (
    ('activation_id', 'uuid'), ('challenge_id', 'uuid'), ('consumer_owner_id', 'uuid'),
    ('consumer_session_id', 'uuid'), ('evaluated_monotonic_ns', 'integer'),
    ('graph_closure_receipt_id', 'uuid'), ('monitor_session_id', 'uuid'),
    ('root_aliases_closed', 'true'), ('subject_graph_id', 'uuid'),
    ('terminal_pidfds_verified', 'true'), ('termination_receipt_ids', 'list'),
    ('transfers_empty', 'true'),
)
RB_ROLES = ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
            'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')
RB_PHASES = ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed')


def _recovery_binding(operation=SUBJECT):
    return dict(clock_epoch_id=OTHER, graph_id=CUST_GRAPH, issuer_instance_id=SUBJECT,
        issuer_role='supervisor', kind='recovery_closure_binding', observed_monotonic_ns=0,
        observer_session_id=OTHER, operation_id=operation, phase='closed', receipt_id=CUST_RECEIPT,
        runtime_lock_sha256='a' * 64, schema_version='s43-physical-receipt-v1', subject_owner_id=CUST_OWNER,
        payload=dict(activation_id=SUBJECT, challenge_id=OTHER, consumer_owner_id=SUBJECT,
            consumer_session_id=OTHER, evaluated_monotonic_ns=0, graph_closure_receipt_id=OTHER,
            monitor_session_id=SUBJECT, root_aliases_closed=True, subject_graph_id=CUST_GRAPH,
            terminal_pidfds_verified=True, termination_receipt_ids=[SUBJECT, OTHER], transfers_empty=True))


RB_CANONICAL_BYTES = (
    b'{"clock_epoch_id":"22345678-1234-4234-9234-123456789abc","graph_id":"72345678-1234-4234-9234-123'
    b'456789abc","issuer_instance_id":"12345678-1234-4234-9234-123456789abc","issuer_role":"supervisor'
    b'","kind":"recovery_closure_binding","observed_monotonic_ns":0,"observer_session_id":"22345678-12'
    b'34-4234-9234-123456789abc","operation_id":"12345678-1234-4234-9234-123456789abc","payload":{"act'
    b'ivation_id":"12345678-1234-4234-9234-123456789abc","challenge_id":"22345678-1234-4234-9234-12345'
    b'6789abc","consumer_owner_id":"12345678-1234-4234-9234-123456789abc","consumer_session_id":"22345'
    b'678-1234-4234-9234-123456789abc","evaluated_monotonic_ns":0,"graph_closure_receipt_id":"22345678'
    b'-1234-4234-9234-123456789abc","monitor_session_id":"12345678-1234-4234-9234-123456789abc","root_'
    b'aliases_closed":true,"subject_graph_id":"72345678-1234-4234-9234-123456789abc","terminal_pidfds_'
    b'verified":true,"termination_receipt_ids":["12345678-1234-4234-9234-123456789abc","22345678-1234-'
    b'4234-9234-123456789abc"],"transfers_empty":true},"phase":"closed","receipt_id":"82345678-1234-42'
    b'34-9234-123456789abc","runtime_lock_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    b'aaaaaaaaaaaaa","schema_version":"s43-physical-receipt-v1","subject_owner_id":"62345678-1234-4234'
    b'-9234-123456789abc"}'
)


def _recovery_binding_args(operation=SUBJECT):
    return CUST_OWNER, operation, CUST_GRAPH, CUST_RECEIPT


def _recovery_binding_accept(record):
    args = tuple(record[k] for k in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id'))
    wire = _wire(record)
    assert codec.encode_recovery_closure_binding_record(record, *args) == wire
    decoded = codec.decode_recovery_closure_binding_record(wire, *args)
    assert decoded == record and decoded is not record
    assert type(decoded) is dict and type(decoded['payload']) is dict
    assert type(decoded['payload']['termination_receipt_ids']) is list
    assert decoded['payload'] is not record['payload']
    assert decoded['payload']['termination_receipt_ids'] is not record['payload']['termination_receipt_ids']
    return decoded


def _recovery_binding_reject(record, code, operation=SUBJECT, decode_code=None):
    args = _recovery_binding_args(operation)
    _reject(lambda: codec.encode_recovery_closure_binding_record(record, *args), code)
    return _reject(lambda: codec.decode_recovery_closure_binding_record(_wire(record), *args), decode_code or code)


def test_recovery_closure_binding_record_canonical_examples():
    assert len(RB_ENVELOPE_TYPES) == 14 and len(RB_PAYLOAD_TYPES) == 12 and len(RB_ROLES) == 11
    assert codec.encode_recovery_closure_binding_record(_recovery_binding(), *_recovery_binding_args()) == RB_CANONICAL_BYTES
    assert codec.decode_recovery_closure_binding_record(RB_CANONICAL_BYTES, *_recovery_binding_args()) == _recovery_binding()
    for operation in (None, SUBJECT):
        for value in (0, 1, 9223372036854775807):
            record = dict(_recovery_binding(operation), observed_monotonic_ns=value)
            record['payload']['evaluated_monotonic_ns'] = value
            assert set(record) == {k for k, _ in RB_ENVELOPE_TYPES}
            assert set(record['payload']) == {k for k, _ in RB_PAYLOAD_TYPES}
            first, second = _recovery_binding_accept(record), _recovery_binding_accept(record)
            first['payload']['termination_receipt_ids'].clear()
            first['receipt_id'] = 'changed'
            assert second == record and record['payload']['termination_receipt_ids'] == [SUBJECT, OTHER]
            reversed_record = dict(reversed(tuple(record.items())))
            reversed_record['payload'] = dict(reversed(tuple(record['payload'].items())))
            assert codec.encode_recovery_closure_binding_record(reversed_record, *_recovery_binding_args(operation)) == _wire(record)
    # These representable equal/distinct claims are not live recovery eligibility.
    for owner in (SUBJECT, CUST_OWNER):
        for monitor in (SUBJECT, OTHER):
            record = _recovery_binding()
            record['payload'].update(consumer_owner_id=owner, monitor_session_id=monitor,
                activation_id=SUBJECT, challenge_id=SUBJECT, graph_closure_receipt_id=SUBJECT)
            _recovery_binding_accept(record)


def test_recovery_closure_binding_record_shape_and_type_rejections():
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class ListHook(list):
        def __len__(self):
            raise AssertionError('hook reached')
        def __iter__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class BoolHook:
        def __bool__(self):
            raise AssertionError('bool hook reached')
    class ElementHook(str):
        def __hash__(self):
            raise AssertionError('hash hook reached')
        def __eq__(self, other):
            raise AssertionError('equality hook reached')
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _recovery_binding_reject(value, 'invalid_shape')
    _reject(lambda: codec.encode_recovery_closure_binding_record(DictHook(_recovery_binding()), *_recovery_binding_args()), 'invalid_shape')
    for nested, fields in ((False, RB_ENVELOPE_TYPES), (True, RB_PAYLOAD_TYPES)):
        record = _recovery_binding()
        target = record['payload'] if nested else record
        target['RAW_SENTINEL'] = 'extra'
        _recovery_binding_reject(record, 'invalid_shape')
        for key, typ in fields:
            for mutation in ('missing', 'unknown'):
                record = _recovery_binding()
                target = record['payload'] if nested else record
                value = target.pop(key)
                if mutation == 'unknown':
                    target['RAW_SENTINEL'] = value
                _recovery_binding_reject(record, 'invalid_shape')
            bad_values = (None, True, False, 1.0, [], {}, 'RAW_SENTINEL')
            if typ != 'integer':
                bad_values += (0, 1)
            for bad in bad_values:
                if (bad is None and typ.endswith('?') or typ == 'list' and bad == []
                        or typ == 'true' and bad is True):
                    continue
                record = _recovery_binding()
                target = record['payload'] if nested else record
                target[key] = bad
                code = 'invalid_shape' if typ in ('object', 'list') else 'invalid_value'
                _recovery_binding_reject(record, code,
                    decode_code='invalid_value' if typ in ('object', 'list') and type(bad) is float else None)
            record = _recovery_binding()
            target = record['payload'] if nested else record
            target[key] = (DictHook() if typ == 'object' else ListHook() if typ == 'list'
                           else IntHook(1) if typ == 'integer' else BoolHook() if typ == 'true'
                           else StringHook('RAW_SENTINEL'))
            _reject(lambda: codec.encode_recovery_closure_binding_record(record, *_recovery_binding_args()),
                    'invalid_shape' if typ in ('object', 'list') else 'invalid_value')
        for bad_key in (StringHook('x'), 'x' * 100000, 1):
            record = _recovery_binding()
            target = record['payload'] if nested else record
            target[bad_key] = target.pop(fields[0][0])
            _reject(lambda: codec.encode_recovery_closure_binding_record(record, *_recovery_binding_args()), 'invalid_shape')
    record = _recovery_binding()
    record['payload']['termination_receipt_ids'] = (OTHER, SUBJECT)
    _reject(lambda: codec.encode_recovery_closure_binding_record(record, *_recovery_binding_args()), 'invalid_shape')
    for item in (None, True, 1, 1.0, [], {}, 'RAW_SENTINEL'):
        record = _recovery_binding()
        record['payload']['termination_receipt_ids'][0] = item
        _recovery_binding_reject(record, 'invalid_value',
            decode_code='invalid_encoding' if type(item) in (list, dict) else None)
    for item in (StringHook(SUBJECT), ElementHook(SUBJECT), IntHook(1)):
        record = _recovery_binding()
        record['payload']['termination_receipt_ids'] = [item, item]
        _reject(lambda: codec.encode_recovery_closure_binding_record(record, *_recovery_binding_args()), 'invalid_value')


def test_recovery_closure_binding_record_relations_and_order():
    for role in RB_ROLES:
        record = dict(_recovery_binding(), issuer_role=role)
        if role == 'supervisor':
            _recovery_binding_accept(record)
        else:
            _recovery_binding_reject(record, 'invalid_result')
    for phase in RB_PHASES:
        record = dict(_recovery_binding(), phase=phase)
        if phase == 'closed':
            _recovery_binding_accept(record)
        else:
            _recovery_binding_reject(record, 'invalid_result')
    for operation in (None, SUBJECT):
        for key, value in (('consumer_session_id', SUBJECT), ('subject_graph_id', OTHER),
                           ('evaluated_monotonic_ns', 1)):
            record = _recovery_binding(operation)
            record['payload'][key] = value
            _recovery_binding_reject(record, 'invalid_result', operation)
        for key, value in (('observer_session_id', SUBJECT), ('graph_id', OTHER), ('observed_monotonic_ns', 1)):
            _recovery_binding_reject(dict(_recovery_binding(operation), **{key: value}), 'invalid_result', operation)
    for members in ([SUBJECT, SUBJECT], [SUBJECT, OTHER, SUBJECT], [OTHER, SUBJECT],
                    [OTHER, SUBJECT, CUST_OWNER], [SUBJECT, CUST_OWNER, OTHER]):
        record = _recovery_binding()
        record['payload']['termination_receipt_ids'] = members
        _recovery_binding_reject(record, 'invalid_value')
        assert record['payload']['termination_receipt_ids'] == members
    for key in ('root_aliases_closed', 'terminal_pidfds_verified', 'transfers_empty'):
        for bad in (False, 0, 1, 'true', 'True', None, 1.0):
            record = _recovery_binding()
            record['payload'][key] = bad
            _recovery_binding_reject(record, 'invalid_value')
    for key, bad in (('issuer_role', 'lifecycle_monitor'), ('phase', 'pre_write'),
                     ('schema_version', 's43-observation-v1')):
        _recovery_binding_reject(dict(_recovery_binding(), **{key: bad}), 'invalid_value')
    for kind in ('process_identity', 'descriptor_identity', 'socket_custody', 'source_custody',
                 'monitor_termination', 'graph_closure', 'recovery_lifecycle', 'RAW_SENTINEL', ''):
        _recovery_binding_reject(dict(_recovery_binding(), kind=kind), 'invalid_value')
    record = dict(_recovery_binding(), issuer_role='broker', phase='ready')
    record['payload']['root_aliases_closed'] = False
    _recovery_binding_reject(record, 'invalid_value')


def test_recovery_closure_binding_record_scalar_bounds():
    for key, nested in (('observed_monotonic_ns', False), ('evaluated_monotonic_ns', True)):
        for bad in (-1, 9223372036854775808, True, False, 0.0):
            record = _recovery_binding()
            target = record['payload'] if nested else record
            target[key] = bad
            _recovery_binding_reject(record, 'invalid_value')
    for count in range(1, 11):
        for operation in (None, SUBJECT):
            record = _recovery_binding(operation)
            members = [f'{index:08x}-1234-4234-9234-123456789abc' for index in range(count)]
            record['payload']['termination_receipt_ids'] = members
            assert _recovery_binding_accept(record)['payload']['termination_receipt_ids'] == members
    for count in (0, 11, 100000):
        record = _recovery_binding()
        record['payload']['termination_receipt_ids'] = [None] * count
        _reject(lambda: codec.encode_recovery_closure_binding_record(record, *_recovery_binding_args()), 'invalid_value')
        if count != 100000:
            _recovery_binding_reject(record, 'invalid_value')
    for nested, fields in ((False, RB_ENVELOPE_TYPES), (True, RB_PAYLOAD_TYPES)):
        for key, typ in fields:
            if typ not in ('uuid', 'uuid?', 'hash', 'list'):
                continue
            valid = 'f' * 64 if typ == 'hash' else SUBJECT
            bad_values = (valid.upper(), valid + '\n', valid + 'x', 'x' + valid, valid[:-1], '')
            if typ != 'hash':
                bad_values += (SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
            for bad in bad_values:
                record = _recovery_binding()
                target = record['payload'] if nested else record
                target[key] = [bad, OTHER] if typ == 'list' else bad
                _recovery_binding_reject(record, 'invalid_value')
    for value in ('0' * 64, 'f' * 64):
        _recovery_binding_accept(dict(_recovery_binding(), runtime_lock_sha256=value))


def test_recovery_closure_binding_record_expected_subject_binding():
    class StringSubclass(str):
        pass
    for operation in (None, SUBJECT):
        record = _recovery_binding(operation)
        args = _recovery_binding_args(operation)
        for index in range(4):
            changed = list(args)
            changed[index] = OTHER
            _reject(lambda: codec.encode_recovery_closure_binding_record(record, *changed), 'wrong_subject')
            _reject(lambda: codec.decode_recovery_closure_binding_record(_wire(record), *changed), 'wrong_subject')
            for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n', StringSubclass(SUBJECT)):
                changed = list(args)
                changed[index] = bad
                code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                _reject(lambda: codec.encode_recovery_closure_binding_record(record, *changed), code)
                _reject(lambda: codec.decode_recovery_closure_binding_record(_wire(record), *changed), code)
                _reject(lambda: codec.encode_recovery_closure_binding_record(None, *changed), code)
                _reject(lambda: codec.decode_recovery_closure_binding_record(b'', *changed), code)
            changed = list(args)
            changed[index] = None
            if index != 1 or operation is not None:
                code = 'wrong_subject' if index == 1 else 'invalid_shape'
                _reject(lambda: codec.encode_recovery_closure_binding_record(record, *changed), code)
                _reject(lambda: codec.decode_recovery_closure_binding_record(_wire(record), *changed), code)
        wrong = (OTHER, operation, CUST_GRAPH, CUST_RECEIPT)
        _reject(lambda: codec.decode_recovery_closure_binding_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
        record['payload']['subject_graph_id'] = OTHER
        _reject(lambda: codec.encode_recovery_closure_binding_record(record, *wrong), 'invalid_result')
        _reject(lambda: codec.decode_recovery_closure_binding_record(_wire(record), *wrong), 'invalid_result')


def test_recovery_closure_binding_record_encoding_and_depth():
    class BytesSubclass(bytes):
        pass
    record = _recovery_binding()
    wire = _wire(record)
    args = _recovery_binding_args()
    reverse_payload = json.dumps(dict(reversed(tuple(record['payload'].items()))), separators=(',', ':')).encode('ascii')
    for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                  wire.replace(_wire(record['payload']), reverse_payload), wire + b'\n', b' ' + wire,
                  wire.replace(b':', b': ', 1), wire.replace(b'"s43-physical-receipt-v1"', b'"\\u007343-physical-receipt-v1"'),
                  wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x', b'{"x":"\\q"}',
                  b'x' * 2049, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]', wire.replace(_wire(record['payload']['termination_receipt_ids']), b'[[]]')):
        error = _reject(lambda: codec.decode_recovery_closure_binding_record(frame, *args), 'invalid_encoding')
        assert error.__context__ is None and error.__cause__ is None
    for frame in (b'{"receipt_id":null,' + wire[1:], b'{"receip\\u0074_id":null,' + wire[1:],
                  wire.replace(b'"payload":{', b'"payload":{"activation_id":null,')):
        _reject(lambda: codec.decode_recovery_closure_binding_record(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_recovery_closure_binding_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None, BytesSubclass(wire)):
        _reject(lambda: codec.decode_recovery_closure_binding_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 2049, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]', wire.replace(_wire(record['payload']['termination_receipt_ids']), b'[[]]')):
            _reject(lambda: codec.decode_recovery_closure_binding_record(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_recovery_closure_binding_record(b' ' * 2048, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_recovery_closure_binding_record(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        _recovery_binding_accept(record)
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _recovery_binding_reject(dict(_recovery_binding(), schema_version=text), 'invalid_value')
        oversized = dict(_recovery_binding(), schema_version='x' * 100000)
        _reject(lambda: codec.encode_recovery_closure_binding_record(oversized, *args), 'invalid_value')
        _reject(lambda: codec.decode_recovery_closure_binding_record(_wire(oversized), *args), 'invalid_encoding')
    finally:
        json.loads = original_loads


# Independent lifecycle expectations; no production-table imports.
RL_ENVELOPE_TYPES = (
    ('clock_epoch_id', 'uuid'), ('graph_id', 'uuid'), ('issuer_instance_id', 'uuid'),
    ('issuer_role', 'enum'), ('kind', 'enum'), ('observed_monotonic_ns', 'integer'),
    ('observer_session_id', 'uuid'), ('operation_id', 'uuid?'), ('payload', 'object'),
    ('phase', 'enum'), ('receipt_id', 'uuid'), ('runtime_lock_sha256', 'hash'),
    ('schema_version', 'enum'), ('subject_owner_id', 'uuid'),
)
RL_PAYLOAD_TYPES = (
    ('bootstrap_manifest_sha256', 'hash'), ('fd_layout_sha256', 'hash'),
    ('filter_sha256', 'hash'), ('monitor_session_id', 'uuid'),
    ('observed_monotonic_ns', 'integer'), ('pidfd_reference', 'uuid'),
    ('recovery_instance_id', 'uuid'), ('si_pid', 'integer'), ('si_signo', 'enum'),
    ('si_uid', 'integer'), ('signal', 'enum'), ('state', 'enum'), ('wait_code', 'enum'),
)
RL_KNOWN_ROLES = ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
                  'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe')
RL_PHASES = ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed')
RL_VALID_TUPLES = (('stopped', 'CLD_STOPPED', 'SIGSTOP'),
                   ('precontinue', 'CLD_STOPPED', 'SIGSTOP'), ('continued', 'CLD_CONTINUED', 'SIGCONT'))


def _recovery_lifecycle(operation=SUBJECT):
    return dict(clock_epoch_id=OTHER, graph_id=CUST_GRAPH, issuer_instance_id=SUBJECT,
        issuer_role='supervisor', kind='recovery_lifecycle', observed_monotonic_ns=0,
        observer_session_id=OTHER, operation_id=operation, phase='ready', receipt_id=CUST_RECEIPT,
        runtime_lock_sha256='a' * 64, schema_version='s43-physical-receipt-v1', subject_owner_id=CUST_OWNER,
        payload=dict(bootstrap_manifest_sha256='b' * 64, fd_layout_sha256='c' * 64,
            filter_sha256='d' * 64, monitor_session_id=SUBJECT, observed_monotonic_ns=0,
            pidfd_reference=OTHER, recovery_instance_id=SUBJECT, si_pid=1, si_signo='SIGCHLD',
            si_uid=0, signal='SIGSTOP', state='stopped', wait_code='CLD_STOPPED'))


RL_CANONICAL_BYTES = (
    b'{"clock_epoch_id":"22345678-1234-4234-9234-123456789abc","graph_id":"72345678-1234-4234-9234-123'
    b'456789abc","issuer_instance_id":"12345678-1234-4234-9234-123456789abc","issuer_role":"supervisor'
    b'","kind":"recovery_lifecycle","observed_monotonic_ns":0,"observer_session_id":"22345678-1234-423'
    b'4-9234-123456789abc","operation_id":"12345678-1234-4234-9234-123456789abc","payload":{"bootstrap'
    b'_manifest_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","fd_layout_'
    b'sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","filter_sha256":"dddd'
    b'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","monitor_session_id":"12345678-123'
    b'4-4234-9234-123456789abc","observed_monotonic_ns":0,"pidfd_reference":"22345678-1234-4234-9234-1'
    b'23456789abc","recovery_instance_id":"12345678-1234-4234-9234-123456789abc","si_pid":1,"si_signo"'
    b':"SIGCHLD","si_uid":0,"signal":"SIGSTOP","state":"stopped","wait_code":"CLD_STOPPED"},"phase":"r'
    b'eady","receipt_id":"82345678-1234-4234-9234-123456789abc","runtime_lock_sha256":"aaaaaaaaaaaaaaa'
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":"s43-physical-receipt-v1","s'
    b'ubject_owner_id":"62345678-1234-4234-9234-123456789abc"}'
)


def _recovery_lifecycle_args(operation=SUBJECT):
    return CUST_OWNER, operation, CUST_GRAPH, CUST_RECEIPT


def _recovery_lifecycle_accept(record):
    args = tuple(record[k] for k in ('subject_owner_id', 'operation_id', 'graph_id', 'receipt_id'))
    wire = _wire(record)
    assert codec.encode_recovery_lifecycle_record(record, *args) == wire
    decoded = codec.decode_recovery_lifecycle_record(wire, *args)
    assert decoded == record and decoded is not record
    assert type(decoded) is dict and type(decoded['payload']) is dict
    assert decoded['payload'] is not record['payload']
    return decoded


def _recovery_lifecycle_reject(record, code, operation=SUBJECT, decode_code=None):
    args = _recovery_lifecycle_args(operation)
    _reject(lambda: codec.encode_recovery_lifecycle_record(record, *args), code)
    return _reject(lambda: codec.decode_recovery_lifecycle_record(_wire(record), *args), decode_code or code)


def test_recovery_lifecycle_record_canonical_examples():
    assert len(RL_ENVELOPE_TYPES) == 14 and len(RL_PAYLOAD_TYPES) == 13 and len(RL_KNOWN_ROLES) == 11
    assert codec.encode_recovery_lifecycle_record(_recovery_lifecycle(), *_recovery_lifecycle_args()) == RL_CANONICAL_BYTES
    assert codec.decode_recovery_lifecycle_record(RL_CANONICAL_BYTES, *_recovery_lifecycle_args()) == _recovery_lifecycle()
    for operation in (None, SUBJECT):
        for phase in RL_PHASES:
            for state, wait_code, signal in RL_VALID_TUPLES:
                record = dict(_recovery_lifecycle(operation), phase=phase)
                record['payload'].update(state=state, wait_code=wait_code, signal=signal)
                assert set(record) == {k for k, _ in RL_ENVELOPE_TYPES}
                assert set(record['payload']) == {k for k, _ in RL_PAYLOAD_TYPES}
                first, second = _recovery_lifecycle_accept(record), _recovery_lifecycle_accept(record)
                first['payload'].clear()
                first['receipt_id'] = 'changed'
                assert second == record
                reversed_record = dict(reversed(tuple(record.items())))
                reversed_record['payload'] = dict(reversed(tuple(record['payload'].items())))
                assert codec.encode_recovery_lifecycle_record(reversed_record, *_recovery_lifecycle_args(operation)) == _wire(record)
    for monitor in (SUBJECT, OTHER):
        record = _recovery_lifecycle()
        record['payload']['monitor_session_id'] = monitor
        _recovery_lifecycle_accept(record)
    record = _recovery_lifecycle()
    for nested, fields in ((False, RL_ENVELOPE_TYPES), (True, RL_PAYLOAD_TYPES)):
        for key, typ in fields:
            if typ.startswith('uuid'):
                (record['payload'] if nested else record)[key] = SUBJECT
            elif typ == 'hash':
                (record['payload'] if nested else record)[key] = 'a' * 64
    # Shared/distinct identifiers and digests are claims, not custody/filter proof.
    _recovery_lifecycle_accept(record)


def test_recovery_lifecycle_record_shape_and_type_rejections():
    class DictHook(dict):
        def __len__(self):
            raise AssertionError('hook reached')
    class StringHook(str):
        def __len__(self):
            raise AssertionError('hook reached')
    class IntHook(int):
        def __lt__(self, other):
            raise AssertionError('hook reached')
    class BoolHook:
        def __bool__(self):
            raise AssertionError('hook reached')
    for value in (None, True, 0, 'RAW_SENTINEL', [], [1]):
        _recovery_lifecycle_reject(value, 'invalid_shape')
    _reject(lambda: codec.encode_recovery_lifecycle_record(DictHook(_recovery_lifecycle()), *_recovery_lifecycle_args()), 'invalid_shape')
    for nested, fields in ((False, RL_ENVELOPE_TYPES), (True, RL_PAYLOAD_TYPES)):
        record = _recovery_lifecycle()
        target = record['payload'] if nested else record
        target['RAW_SENTINEL'] = 'extra'
        _recovery_lifecycle_reject(record, 'invalid_shape')
        for key, typ in fields:
            for mutation in ('missing', 'unknown'):
                record = _recovery_lifecycle()
                target = record['payload'] if nested else record
                value = target.pop(key)
                if mutation == 'unknown':
                    target['RAW_SENTINEL'] = value
                _recovery_lifecycle_reject(record, 'invalid_shape')
            bad_values = (None, True, False, 1.0, [], {}, 'RAW_SENTINEL')
            if typ != 'integer':
                bad_values += (0, 1)
            for bad in bad_values:
                if bad is None and typ.endswith('?'):
                    continue
                record = _recovery_lifecycle()
                target = record['payload'] if nested else record
                target[key] = bad
                _recovery_lifecycle_reject(record, 'invalid_shape' if typ == 'object' else 'invalid_value',
                                   decode_code='invalid_value' if typ == 'object' and type(bad) is float else None)
            record = _recovery_lifecycle()
            target = record['payload'] if nested else record
            target[key] = (DictHook() if typ == 'object' else IntHook(1) if typ == 'integer'
                           else StringHook('RAW_SENTINEL'))
            _reject(lambda: codec.encode_recovery_lifecycle_record(record, *_recovery_lifecycle_args()),
                    'invalid_shape' if typ == 'object' else 'invalid_value')
        for bad_key in (StringHook('x'), 'x' * 100000, 1):
            record = _recovery_lifecycle()
            target = record['payload'] if nested else record
            target[bad_key] = target.pop(fields[0][0])
            _reject(lambda: codec.encode_recovery_lifecycle_record(record, *_recovery_lifecycle_args()), 'invalid_shape')


def test_recovery_lifecycle_record_state_and_time_relations():
    for role in RL_KNOWN_ROLES:
        record = dict(_recovery_lifecycle(), issuer_role=role)
        if role == 'supervisor':
            _recovery_lifecycle_accept(record)
        else:
            _recovery_lifecycle_reject(record, 'invalid_result')
    accepted, rejected = [], []
    for state in ('stopped', 'precontinue', 'continued'):
        for wait in ('CLD_STOPPED', 'CLD_CONTINUED'):
            for signal in ('SIGSTOP', 'SIGCONT'):
                record = _recovery_lifecycle()
                record['payload'].update(state=state, wait_code=wait, signal=signal)
                item = (state, wait, signal)
                if item in RL_VALID_TUPLES:
                    _recovery_lifecycle_accept(record)
                    accepted.append(item)
                else:
                    _recovery_lifecycle_reject(record, 'invalid_result')
                    rejected.append(item)
    assert tuple(accepted) == RL_VALID_TUPLES and len(rejected) == 9
    for key, values in {
            'state': ('ready', 'STOPPED', 'RAW_SENTINEL', ''),
            'wait_code': ('CLD_EXITED', 'CLD_TRAPPED', 'cld_stopped', ''),
            'signal': ('SIGCHLD', 'SIGTERM', 'sigstop', '19', 19, ''),
            'si_signo': ('SIGTERM', 'SIGKILL', 'sigchld', '17', 17, 0, '', 'SIGCHLD\n')}.items():
        for bad in values:
            record = _recovery_lifecycle()
            record['payload'][key] = bad
            _recovery_lifecycle_reject(record, 'invalid_value')
    for key, bad in (('issuer_role', 'lifecycle_monitor'), ('phase', 'pre_write'),
                     ('schema_version', 's43-observation-v1')):
        _recovery_lifecycle_reject(dict(_recovery_lifecycle(), **{key: bad}), 'invalid_value')
    for kind in ('process_identity', 'descriptor_identity', 'socket_custody', 'source_custody',
                 'monitor_termination', 'graph_closure', 'recovery_closure_binding', 'RAW_SENTINEL', ''):
        _recovery_lifecycle_reject(dict(_recovery_lifecycle(), kind=kind), 'invalid_value')
    for operation in (None, SUBJECT):
        for observed, payload_time in ((0, 0), (1, 1), (9223372036854775807, 9223372036854775807),
                (0, 1), (1, 0), (0, 9223372036854775807), (9223372036854775807, 0)):
            record = dict(_recovery_lifecycle(operation), observed_monotonic_ns=observed)
            record['payload']['observed_monotonic_ns'] = payload_time
            if observed == payload_time:
                _recovery_lifecycle_accept(record)
            else:
                _recovery_lifecycle_reject(record, 'invalid_result', operation)
    record = dict(_recovery_lifecycle(), issuer_role='broker')
    record['payload'].update(state='continued', signal='unknown')
    _recovery_lifecycle_reject(record, 'invalid_value')


def test_recovery_lifecycle_record_scalar_bounds():
    for value in (0, 9223372036854775807):
        record = dict(_recovery_lifecycle(), observed_monotonic_ns=value)
        record['payload']['observed_monotonic_ns'] = value
        _recovery_lifecycle_accept(record)
    for value in (-1, 9223372036854775808, True, 0.0):
        _recovery_lifecycle_reject(dict(_recovery_lifecycle(), observed_monotonic_ns=value), 'invalid_value')
    for nested, fields in ((False, RL_ENVELOPE_TYPES), (True, RL_PAYLOAD_TYPES)):
        for key, typ in fields:
            if typ not in ('uuid', 'uuid?', 'hash'):
                continue
            valid = 'f' * 64 if typ == 'hash' else SUBJECT
            bad_values = (valid.upper(), valid + '\n', valid + 'x', 'x' + valid, valid[:-1], '')
            if typ != 'hash':
                bad_values += (SUBJECT.replace('-4234-', '-1234-'), SUBJECT.replace('-9234-', '-7234-'))
            for bad in bad_values:
                record = _recovery_lifecycle()
                target = record['payload'] if nested else record
                target[key] = bad
                _recovery_lifecycle_reject(record, 'invalid_value')
    for value in ('0' * 64, 'f' * 64):
        _recovery_lifecycle_accept(dict(_recovery_lifecycle(), runtime_lock_sha256=value))
    for key, minimum, maximum in (
            ('observed_monotonic_ns', 0, 9223372036854775807),
            ('si_pid', 1, 2147483647), ('si_uid', 0, 4294967294)):
        for value in (minimum, 10, 11, maximum):
            record = _recovery_lifecycle()
            record['payload'][key] = value
            if key == 'observed_monotonic_ns':
                record[key] = value
            _recovery_lifecycle_accept(record)
        for value in (minimum - 1, maximum + 1, True, False, 1.0):
            record = _recovery_lifecycle()
            record['payload'][key] = value
            _recovery_lifecycle_reject(record, 'invalid_value')


    for key in ('bootstrap_manifest_sha256', 'fd_layout_sha256', 'filter_sha256'):
        for value in ('0' * 64, 'f' * 64):
            record = _recovery_lifecycle()
            record['payload'][key] = value
            _recovery_lifecycle_accept(record)


def test_recovery_lifecycle_record_expected_subject_binding():
    class StringSubclass(str):
        pass
    for operation in (None, SUBJECT):
        record = _recovery_lifecycle(operation)
        args = _recovery_lifecycle_args(operation)
        for index in range(4):
            changed = list(args)
            changed[index] = OTHER
            _reject(lambda: codec.encode_recovery_lifecycle_record(record, *changed), 'wrong_subject')
            _reject(lambda: codec.decode_recovery_lifecycle_record(_wire(record), *changed), 'wrong_subject')
            for bad in (True, 1, b'uuid', [], {}, '', SUBJECT.upper(), SUBJECT + '\n', StringSubclass(SUBJECT)):
                changed = list(args)
                changed[index] = bad
                code = 'invalid_value' if type(bad) is str else 'invalid_shape'
                _reject(lambda: codec.encode_recovery_lifecycle_record(record, *changed), code)
                _reject(lambda: codec.decode_recovery_lifecycle_record(_wire(record), *changed), code)
                _reject(lambda: codec.encode_recovery_lifecycle_record(None, *changed), code)
                _reject(lambda: codec.decode_recovery_lifecycle_record(b'', *changed), code)
            changed = list(args)
            changed[index] = None
            if index != 1 or operation is not None:
                code = 'wrong_subject' if index == 1 else 'invalid_shape'
                _reject(lambda: codec.encode_recovery_lifecycle_record(record, *changed), code)
                _reject(lambda: codec.decode_recovery_lifecycle_record(_wire(record), *changed), code)
        wrong = (OTHER, operation, CUST_GRAPH, CUST_RECEIPT)
        _reject(lambda: codec.decode_recovery_lifecycle_record(_wire(record) + b'\n', *wrong), 'invalid_encoding')
        record['issuer_role'] = 'broker'
        _reject(lambda: codec.encode_recovery_lifecycle_record(record, *wrong), 'invalid_result')
        _reject(lambda: codec.decode_recovery_lifecycle_record(_wire(record), *wrong), 'invalid_result')


def test_recovery_lifecycle_record_encoding_and_depth():
    class BytesSubclass(bytes):
        pass
    record = _recovery_lifecycle()
    wire = _wire(record)
    args = _recovery_lifecycle_args()
    reverse_payload = json.dumps(dict(reversed(tuple(record['payload'].items()))), separators=(',', ':')).encode('ascii')
    for frame in (json.dumps(dict(reversed(tuple(record.items()))), separators=(',', ':')).encode('ascii'),
                  wire.replace(_wire(record['payload']), reverse_payload), wire + b'\n', b' ' + wire,
                  wire.replace(b':', b': ', 1), wire.replace(b'"s43-physical-receipt-v1"', b'"\\u007343-physical-receipt-v1"'),
                  wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":-0'),
                  b'\xef\xbb\xbf' + wire, wire + b'\xff', b'', b' ', b'{', b'}', b'{}x', b'{"x":"\\q"}',
                  b'x' * 2049, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
        error = _reject(lambda: codec.decode_recovery_lifecycle_record(frame, *args), 'invalid_encoding')
        assert error.__context__ is None and error.__cause__ is None
    for frame in (b'{"receipt_id":null,' + wire[1:], b'{"receip\\u0074_id":null,' + wire[1:],
                  wire.replace(b'"payload":{', b'"payload":{"bootstrap_manifest_sha256":null,')):
        _reject(lambda: codec.decode_recovery_lifecycle_record(frame, *args), 'invalid_shape')
    for scalar in (b'1.0', b'1e0', b'NaN', b'Infinity', b'-Infinity'):
        _reject(lambda: codec.decode_recovery_lifecycle_record(wire.replace(b'"observed_monotonic_ns":0', b'"observed_monotonic_ns":' + scalar), *args), 'invalid_value')
    for frame in (bytearray(wire), memoryview(wire), wire.decode('ascii'), None, BytesSubclass(wire)):
        _reject(lambda: codec.decode_recovery_lifecycle_record(frame, *args), 'invalid_shape')
    calls = []
    original_loads = json.loads
    def observed_loads(*values, **kwargs):
        calls.append(1)
        return original_loads(*values, **kwargs)
    json.loads = observed_loads
    try:
        for frame in (b'x' * 2049, b'{"a":{"b":{"c":{}}}}', b'[[[[]]]]'):
            _reject(lambda: codec.decode_recovery_lifecycle_record(frame, *args), 'invalid_encoding')
            assert not calls
        _reject(lambda: codec.decode_recovery_lifecycle_record(b' ' * 2048, *args), 'invalid_encoding')
        assert len(calls) == 1
        _reject(lambda: codec.decode_recovery_lifecycle_record(b'{"a":{"b":{}}}', *args), 'invalid_shape')
        assert len(calls) == 2
        _recovery_lifecycle_accept(record)
        assert len(calls) == 3
        for text in ('[' * 20, '\\"' + '[' * 20, '\\\\' + ']' * 20):
            _recovery_lifecycle_reject(dict(_recovery_lifecycle(), schema_version=text), 'invalid_value')
        oversized = dict(_recovery_lifecycle(), schema_version='x' * 100000)
        _reject(lambda: codec.encode_recovery_lifecycle_record(oversized, *args), 'invalid_value')
        _reject(lambda: codec.decode_recovery_lifecycle_record(_wire(oversized), *args), 'invalid_encoding')
    finally:
        json.loads = original_loads
