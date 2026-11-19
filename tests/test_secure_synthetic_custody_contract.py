"""Twenty-seven codec unit nodes; these do not satisfy any formal S4.3 acceptance node."""

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
