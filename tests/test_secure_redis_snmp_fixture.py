"""Portable protocol and owner-state tests for fixed Redis/SNMP metadata."""

import hashlib
import io
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as public
from recon_cockpit.secure_agent import network_tools_redis_snmp_fixture as fixture
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner

OIDS = tuple(bytes.fromhex(value) for value in ('2b06010201010100', '2b06010201010300', '2b06010201010500'))
COMMUNITY = b'recon-fixture-public'


def ber(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x82]) + size.to_bytes(2, 'big')
    return bytes([tag]) + length + value


def query(*, request_id=b'\x12\x34', community=COMMUNITY, version=b'\x01', pdu=0xa0,
          error=b'\0', index=b'\0', oids=OIDS, value=(5, b''), extra=b''):
    bindings = b''.join(ber(0x30, ber(6, oid) + ber(*value)) for oid in oids)
    request = ber(pdu, ber(2, request_id) + ber(2, error) + ber(2, index) + ber(0x30, bindings) + extra)
    return ber(0x30, ber(2, version) + ber(4, community) + request)


class Connection:
    def __init__(self, raw):
        self.source, self.sent, self.timeouts = io.BytesIO(raw), b'', []

    def recv(self, size):
        return self.source.read(min(size, 3))

    def sendall(self, raw):
        self.sent += raw

    def settimeout(self, timeout):
        self.timeouts.append(timeout)


@pytest.mark.parametrize('case', public.REDIS_SNMP_CASES)
def test_case_maps_to_only_its_fixed_metadata_tool_and_finite_public_spec(case):
    expected = 'redis_server_info_v1' if case.startswith('redis-') else 'snmp_system_get_v1'
    assert public.tool_for_case(case) == expected
    spec = contract.spec(case)
    assert spec['tool_id'] == expected and spec['max_connections'] == spec['max_requests'] == 1
    assert spec['topology'][0]['target'] == '127.0.0.1' and spec['topology'][0]['port'] == 8080
    assert spec['external_egress'] is False and spec['resume'] is False
    identity = contract.identity(case, str(uuid4()))
    assert identity['spec_sha256'] == hashlib.sha256(contract._encode(spec)).hexdigest()
    context = {'identity': identity, 'connection_count': 1, 'request_count': 1}
    assert contract.validate_context(context, identity) == context
    for change in ({'connection_count': 2}, {'request_count': 2}, {'connection_count': True}, {'request_count': True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize('case', [value for value in public.REDIS_SNMP_CASES if value.startswith('redis-')])
def test_redis_one_actual_resp2_query_receives_only_its_fixed_response(monkeypatch, case):
    connection, counted, slept = Connection(b'*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n'), [], []
    monkeypatch.setattr(fixture.time, 'sleep', slept.append)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 10, on_request=lambda: counted.append(1))
    assert counted == [1]
    assert connection.sent == (public.redis_response(case) or b'')
    assert bool(slept) is case.endswith('-stalled')
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)
    if case in ('redis-ok', 'redis-empty', 'redis-injected', 'redis-oversized'):
        length, body = connection.sent[1:].split(b'\r\n', 1)
        assert int(length) == len(body) - 2 and body.endswith(b'\r\n')
    if case == 'redis-oversized':
        assert 8192 < len(connection.sent) <= public.REDIS_MAX_RESPONSE_BYTES
    elif case == 'redis-injected':
        assert public.HOSTILE_NOTE.encode('ascii') in connection.sent
    elif case == 'redis-redirect-ip':
        assert connection.sent == b'-MOVED 1 127.0.0.2:8080\r\n'
    elif case == 'redis-redirect-port':
        assert connection.sent == b'-MOVED 1 127.0.0.1:8081\r\n'
    elif case == 'redis-denied':
        assert connection.sent == b'-NOAUTH Authentication required.\r\n'


@pytest.mark.parametrize('raw', [b'PING\r\n', b'*1\r\n$4\r\nINFO\r\n', b'*2\r\n$4\r\nAUTH\r\n$1\r\nx\r\n',
    b'*2\r\n$5\r\nHELLO\r\n$1\r\n2\r\n', b'*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n',
    b'*2\r\n$4\r\nINFO\r\n$3\r\nall\r\n', b'*3\r\n$4\r\nINFO\r\n',
    b'*2\r\n$9999999999999999\r\nINFO\r\n', b'', public.REDIS_INFO_REQUEST[:-1],
    public.REDIS_INFO_REQUEST.replace(b'INFO', b'info'), public.REDIS_INFO_REQUEST.replace(b'\r\n', b'\n')])
def test_redis_unreviewed_command_protocol_or_length_never_counts_or_gets_response(raw):
    connection = Connection(raw)
    with pytest.raises(ValueError):
        fixture.serve(connection, case='redis-ok', deadline=time.monotonic() + 5,
                      on_request=lambda: pytest.fail('unreviewed Redis query counted'))
    assert connection.sent == b''


def test_redis_never_processes_a_pipelined_followup_command():
    followup = b'*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n'
    connection, counted = Connection(public.REDIS_INFO_REQUEST + followup), []
    fixture.serve(connection, case='redis-ok', deadline=time.monotonic() + 5, on_request=lambda: counted.append(1))
    assert counted == [1] and connection.source.read() == followup
    assert connection.sent == public.redis_response('redis-ok')


@pytest.mark.parametrize('request_id', [b'\0', b'\x01', b'\x7f', b'\0\x80', b'\x12\x34', b'\x7f\xff\xff\xff'])
def test_snmp_accepts_only_canonical_bounded_request_ids_and_exact_ordered_null_oids(request_id):
    raw = query(request_id=request_id)
    assert fixture.parse_snmp_request(raw) == request_id
    assert fixture.read_snmp_request(Connection(raw), time.monotonic() + 5) == request_id


@pytest.mark.parametrize('options', [
    {'community': b'public'}, {'community': b'real-secret'}, {'version': b'\0'}, {'version': b'\x03'},
    {'version': b'\0\x01'}, {'pdu': 0xa1}, {'pdu': 0xa2}, {'pdu': 0xa3}, {'pdu': 0xa5},
    {'error': b'\x01'}, {'index': b'\x01'}, {'error': b'\0\0'}, {'index': b''},
    {'request_id': b''}, {'request_id': b'\x80'}, {'request_id': b'\xff'}, {'request_id': b'\0\x01'},
    {'request_id': b'\0\x7f'}, {'request_id': b'\0\x80\0\0\0'},
    {'oids': OIDS[::-1]}, {'oids': OIDS[:2]}, {'oids': OIDS + (OIDS[0],)},
    {'oids': (OIDS[0][:-1] + b'\x01', *OIDS[1:])}, {'value': (4, b'')}, {'value': (5, b'\0')},
    {'extra': b'\x05\0'},
])
def test_snmp_unreviewed_credentials_operations_oids_and_fields_are_rejected_before_counting(options):
    connection = Connection(query(**options))
    with pytest.raises(ValueError):
        fixture.serve(connection, case='snmp-ok', deadline=time.monotonic() + 5,
                      on_request=lambda: pytest.fail('unreviewed SNMP query counted'))
    assert connection.sent == b''


@pytest.mark.parametrize('raw', [b'', b'\x30', b'\x30\x80', b'\x30\x83\x01\0\0', b'\x30\x82\x08\0',
    b'\x30\x81\x01\0', b'\x30\x82\0\x80', b'\x31' + query()[1:], query()[:-1],
    query() + b'\0', b'\x30\x81' + query()[1:], b'\x30\x82\0' + query()[1:]])
def test_snmp_noncanonical_indefinite_truncated_trailing_or_oversized_ber_is_rejected(raw):
    with pytest.raises(ValueError):
        fixture.parse_snmp_request(raw)
    if raw != query() + b'\0':  # Stream framing consumes exactly one PDU then closes.
        with pytest.raises(ValueError):
            fixture.read_snmp_request(Connection(raw), time.monotonic() + 5)


def response_fields(raw):
    outer = fixture.Reader(raw)
    message = fixture.Reader(outer.expect(0x30))
    outer.end()
    assert message.expect(2) == b'\x01' and message.expect(4) == COMMUNITY
    pdu = fixture.Reader(message.expect(0xa2))
    message.end()
    request_id, status, index = pdu.expect(2), pdu.expect(2), pdu.expect(2)
    bindings = fixture.Reader(pdu.expect(0x30))
    pdu.end()
    values = []
    for oid in OIDS:
        binding = fixture.Reader(bindings.expect(0x30))
        assert binding.expect(6) == oid
        values.append(binding.tlv())
        binding.end()
    bindings.end()
    return request_id, status, index, values


@pytest.mark.parametrize('case', [value for value in public.REDIS_SNMP_CASES if value.startswith('snmp-')])
def test_snmp_one_fixed_get_has_typed_success_exception_denial_and_bounded_negative_fixtures(monkeypatch, case):
    connection, counted, slept = Connection(query()), [], []
    monkeypatch.setattr(fixture.time, 'sleep', slept.append)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 10, on_request=lambda: counted.append(1))
    assert counted == [1]
    assert connection.sent == (public.snmp_response(case, b'\x12\x34') or b'')
    assert bool(slept) is case.endswith('-stalled')
    if case == 'snmp-oversized':
        assert 8192 < len(connection.sent) <= public.SNMP_MAX_RESPONSE_BYTES
    elif case not in ('snmp-malformed', 'snmp-stalled'):
        request_id, status, index, values = response_fields(connection.sent)
        assert request_id == b'\x12\x34'
        if case == 'snmp-denied':
            assert (status, index, values) == (b'\x10', b'\x01', [(5, b'')] * 3)
        elif case == 'snmp-no-such-object':
            assert (status, index, values) == (b'\0', b'\0', [(0x80, b'')] * 3)
        else:
            assert (status, index) == (b'\0', b'\0')
            description = public.HOSTILE_NOTE if case == 'snmp-injected' else 'HarborDesk synthetic SNMP fixture'
            assert values == [(4, description.encode('ascii')), (0x43, b'\x30\x39'), (4, b'reconlab')]


@pytest.mark.parametrize('case', ['redis-ok', 'snmp-ok'])
def test_owner_closes_before_processing_a_second_connection(monkeypatch, case):
    seen, closed = [], []
    peers = [SimpleNamespace(settimeout=lambda _: None, close=lambda i=i: closed.append(i)) for i in range(2)]
    iterator = iter(peers)
    service = owner.NetworkToolsService.__new__(owner.NetworkToolsService)
    service.case, service.rpc = case, None
    service.connections = service.requests = 0
    service.failed = False
    service.condition = threading.Condition()
    service.deadline = time.monotonic() + 5
    service.listener = SimpleNamespace(accept=lambda: (next(iterator), None))
    def serve(peer, **kwargs):
        seen.append(peer)
        kwargs['on_request']()
    monkeypatch.setattr(owner.redis_snmp_fixture, 'serve', serve)
    service._serve()
    assert seen == peers[:1] and service.connections == service.requests == 1
    assert service.failed and 1 in closed


@pytest.mark.parametrize('case', ['redis-ok', 'snmp-ok'])
def test_expired_deadline_stops_before_query_is_counted(case):
    raw = public.REDIS_INFO_REQUEST if case.startswith('redis-') else query()
    with pytest.raises(ValueError, match='deadline'):
        fixture.serve(Connection(raw), case=case, deadline=time.monotonic() - 1,
                      on_request=lambda: pytest.fail('expired query counted'))


@pytest.mark.parametrize('case', ['redis-ok', 'snmp-ok'])
def test_unknown_case_never_reads_a_socket(case):
    connection = Connection(b'')
    with pytest.raises(ValueError, match='invalid_redis_snmp_fixture_case'):
        fixture.serve(connection, case=case + '-other', deadline=time.monotonic() + 5,
                      on_request=lambda: pytest.fail('unknown query counted'))
    assert connection.timeouts == []
