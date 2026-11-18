"""Twelve codec unit nodes; these do not satisfy any formal S4.3 acceptance node."""

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
