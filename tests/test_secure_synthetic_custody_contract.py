"""Six codec unit nodes; these do not satisfy any formal S4.3 acceptance node."""

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
