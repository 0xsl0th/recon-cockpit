"""Portable XDR and state checks for the finite owner-only RPC fixture."""
import io
import struct
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_rpc_fixture as rpc
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner
from recon_cockpit.secure_agent import worker


def words(*values):
    return struct.pack('!' + 'I' * len(values), *values)


def string(value):
    raw = value.encode('ascii')
    return words(len(raw)) + raw + b'\0' * (-len(raw) % 4)


def call(program=100000, version=2, procedure=4, body=b'', auth=None):
    return (words(41, 0, 2, program, version, procedure) +
            (words(0, 0) if auth is None else words(1, len(auth)) + auth) + words(0, 0) + body)


def discovery(version=2, port=0, *, listing=False):
    program, wanted_version = (100000, 2) if listing else (100005, 1)
    body = words(program, wanted_version, 6, port) if version == 2 else words(program, wanted_version) + string('tcp') + string('127.0.0.1.0.111') + string('libtirpc')
    return call(version=version, procedure=3, body=body)


class Connection:
    def __init__(self, data):
        self.source, self.sent = io.BytesIO(data), b''

    def recv(self, size):
        return self.source.read(min(size, 3))

    def sendall(self, data):
        self.sent += data


@pytest.mark.parametrize('case', ['rpc-ok', 'rpc-empty', 'rpc-injected', 'rpc-malformed'])
def test_rpc_real_xdr_dump_structure_counts_one_metadata_operation(case):
    count = []
    exchange = rpc.Exchange(case, lambda: count.append(1))
    exchange.reply(discovery(version=4, listing=True))
    request = call()
    connection = Connection(words(0x80000000 | len(request)) + request)
    rpc.serve(connection, exchange, time.monotonic() + 1)
    assert count == [1]
    reply = connection.sent[4:]
    assert reply[:24] == words(41, 1, 0, 0, 0, 0)
    if case == 'rpc-empty':
        assert reply[24:] == words(0)
    elif case == 'rpc-malformed':
        assert reply[24:] == words(1)
    else:
        rows = rpc.REGISTRATIONS + ((rpc.INJECTED_REGISTRATION,) if case == 'rpc-injected' else ())
        assert reply[24:] == b''.join(words(1, *row) for row in rows) + words(0)
    with pytest.raises(ValueError):
        exchange.reply(request)


@pytest.mark.parametrize('version', [2, 3, 4])
@pytest.mark.parametrize('case', ['nfs-ok', 'nfs-empty', 'nfs-injected', 'nfs-malformed', 'nfs-redirected'])
def test_mount_discovery_and_export_are_separate_bounded_operations(version, case):
    count = []
    exchange = rpc.Exchange(case, lambda: count.append(1))
    reply = exchange.reply(discovery(version))
    expected = 112 if case == 'nfs-redirected' else 111
    assert reply[24:] == (words(expected) if version == 2 else string('127.0.0.1.0.' + str(expected)))
    assert count == []
    export = call(program=100005, version=1, procedure=5)
    if case == 'nfs-redirected':
        with pytest.raises(ValueError):
            exchange.reply(export)
        assert count == []
        return
    null = call(program=100005, version=1, procedure=0)
    assert exchange.reply(null)[24:] == b''
    result = exchange.reply(export)
    assert count == [1]
    if case == 'nfs-empty':
        assert result[24:] == words(0)
    elif case == 'nfs-malformed':
        assert result[24:] == words(1)
    else:
        assert b'/srv/harbordesk/public' in result and b'/srv/harbordesk/reports' in result
        assert (rpc.HOSTILE_GROUP.encode() in result) is (case == 'nfs-injected')


@pytest.mark.parametrize('raw_request', [call(program=100003), call(procedure=1), call(procedure=2),
    call(procedure=3), call(version=4), call(body=b'extra'), call()[:-1], call() + b'extra',
    call().replace(words(0, 2), words(1, 2), 1), call(auth=words(0) + string('host') + words(0, 0, 0))])
def test_rpc_rejects_non_dump_and_unreviewed_authentication(raw_request):
    exchange = rpc.Exchange('rpc-ok', lambda: pytest.fail('invalid request counted'))
    with pytest.raises(ValueError):
        exchange.reply(raw_request)


@pytest.mark.parametrize('raw_request', [call(program=100005, version=1, procedure=p) for p in (1, 2, 3, 4, 6)])
def test_mount_file_and_unmount_operations_are_never_supported(raw_request):
    exchange = rpc.Exchange('nfs-ok', lambda: pytest.fail('mount operation counted'))
    exchange.reply(discovery())
    with pytest.raises(ValueError):
        exchange.reply(raw_request)


@pytest.mark.parametrize('body', [words(100005, 1, 17, 0), words(100005, 1, 6, 112),
    words(100003, 3, 6, 0), words(100005, 2, 6, 0), words(100005, 1, 6, 0) + words(0)])
def test_discovery_cannot_select_other_program_transport_or_port(body):
    exchange = rpc.Exchange('nfs-ok', lambda: pytest.fail('discovery counted'))
    with pytest.raises(ValueError):
        exchange.reply(call(procedure=3, body=body))


def test_authsys_only_accepts_the_synthetic_namespace_identity():
    auth = words(17) + string('reconlab') + words(0, 0, 1, 0)
    exchange = rpc.Exchange('rpc-ok', lambda: None)
    exchange.reply(discovery(version=4, listing=True))
    assert exchange.reply(call(auth=auth))
    for changed in (auth.replace(b'reconlab', b'host1234'), auth[:-12] + words(1000, 0, 0),
                    words(17) + string('reconlab') + words(0, 0, 2, 0, 0)):
        with pytest.raises(ValueError):
            rpc.Exchange('rpc-ok', lambda: None).reply(call(auth=changed))


@pytest.mark.parametrize('data', [b'', words(0x80000000 | 4097), words(39), words(40),
    words(0x80000028) + call()[:-1]])
def test_tcp_fragments_oversized_and_incomplete_records_are_rejected(data):
    with pytest.raises(ValueError):
        rpc.serve(Connection(data), rpc.Exchange('rpc-ok', lambda: pytest.fail('invalid frame counted')),
                  time.monotonic() + 1)


def test_discovery_and_null_cannot_exceed_finite_wire_budget():
    exchange = rpc.Exchange('nfs-ok', lambda: pytest.fail('discovery counted'))
    for _ in range(3):
        exchange.reply(discovery())
    with pytest.raises(ValueError):
        exchange.reply(discovery())
    for _ in range(rpc.MAX_CALLS - exchange.calls):
        exchange.reply(call(program=100005, version=1, procedure=0))
    with pytest.raises(ValueError):
        exchange.reply(call(program=100005, version=1, procedure=0))


def test_rpc_port_exception_is_fixed_and_legacy_firewall_remains_closed():
    assert rpc.firewall_rules() == worker.firewall_rules('127.0.0.1', 8080).replace('8080', '111')
    with pytest.raises(ValueError):
        worker.firewall_rules('127.0.0.1', 111)
    instance = owner.NetworkToolsOwner()
    for case, port in [('rpc-ok', 111), ('nfs-redirected', 111), ('smb-ok', 8080), ('dig-ok', 8080)]:
        assert instance.service_port({'case': case}) == port
        assert instance.firewall_rules({'case': case}) == (rpc.firewall_rules() if port == 111 else worker.firewall_rules('127.0.0.1', 8080))


@pytest.mark.parametrize('case,cap', [('rpc-ok', 4), ('nfs-ok', 4), ('smb-ok', 1), ('ldap-ok', 1)])
def test_only_rpc_nfs_can_count_bounded_discovery_connections(case, cap):
    identity = contract.identity(case, str(uuid4()))
    value = {'identity': identity, 'connection_count': cap, 'request_count': 1}
    assert contract.validate_context(value, identity) == value
    for changed in ({'connection_count': cap + 1}, {'request_count': 2}, {'connection_count': True}, {'request_count': True}):
        with pytest.raises(ValueError):
            contract.validate_context({**value, **changed}, identity)


@pytest.mark.parametrize('case,cap', [('rpc-ok', 4), ('nfs-ok', 4)])
def test_owner_refuses_connection_budget_before_serving_another_peer(monkeypatch, case, cap):
    import threading
    from types import SimpleNamespace
    serviced, closed = [], []
    peers = [SimpleNamespace(settimeout=lambda _: None,
                            close=lambda index=index: closed.append(index)) for index in range(cap + 1)]
    iterator = iter(peers)
    service = owner.NetworkToolsService.__new__(owner.NetworkToolsService)
    service.case, service.rpc = case, object()
    service.connections = service.requests = 0
    service.failed = False
    service.condition = threading.Condition()
    service.deadline = time.monotonic() + 10
    service.listener = SimpleNamespace(accept=lambda: (next(iterator), None))
    monkeypatch.setattr(owner.rpc_fixture, 'serve', lambda peer, *_: serviced.append(peer))
    service._serve()
    assert serviced == peers[:cap]
    assert service.connections == cap and service.requests == 0 and service.failed
    assert cap in closed


@pytest.mark.parametrize('case,raw', [
    ('rpc-ok', '22398eda0000000000000002000186a0000000040000000300000000000000000000000000000000000186a00000000200000003746370000000000f3132372e302e302e312e302e31313100000000086c69627469727063'),
    ('nfs-ok', '27a235bb0000000000000002000186a0000000040000000300000000000000000000000000000000000186a50000000300000003746370000000000f3132372e302e302e312e302e31313100000000086c69627469727063'),
])
def test_captured_native_discovery_only_returns_the_preapproved_fixed_endpoint(case, raw):
    count = []
    exchange = rpc.Exchange(case, lambda: count.append(1))
    result = exchange.reply(bytes.fromhex(raw))
    assert result[24:] == string('127.0.0.1.0.111')
    assert exchange.discovery == 1 and exchange.calls == 1 and count == []
