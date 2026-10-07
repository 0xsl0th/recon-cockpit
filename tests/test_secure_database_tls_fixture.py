"""Fixed database negotiation, real in-memory TLS and owner counter checks."""

import io
import ssl
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as public
from recon_cockpit.secure_agent import network_tools_database_tls_fixture as fixture
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner


class Connection:
    def __init__(self, raw):
        self.source, self.sent, self.timeouts, self.closed = io.BytesIO(raw), b'', [], False

    def recv(self, count):
        return self.source.read(min(count, 1))

    def sendall(self, raw):
        self.sent += raw

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


def connection_for(case, suffix=b''):
    raw = public.POSTGRESQL_SSL_REQUEST if case.startswith('postgresql-') else public.MYSQL_SSL_REQUEST
    return Connection(raw + suffix)


class MemoryTLS:
    """Socket-free SSLContext wrapper that retains actual TLS verification."""
    def __init__(self, case, *, application=b'', ragged=False):
        self.server_context = owner.tls_context(case)
        self.client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_context.load_verify_locations(cadata=public.CA_PEM.decode('ascii'))
        self.application, self.ragged, self.wraps, self.closed = application, ragged, 0, False

    def transfer(self):
        for outbound, inbound in ((self.client_out, self.server_in), (self.server_out, self.client_in)):
            raw = outbound.read()
            if raw:
                inbound.write(raw)

    def wrap_socket(self, connection, *, server_side, suppress_ragged_eofs):
        assert server_side is True and suppress_ragged_eofs is False
        self.wraps += 1
        self.connection = connection
        # The fixed preface must not consume any pipelined TLS/application bytes.
        assert connection.source.read() == b''
        self.client_in, self.client_out, self.server_in, self.server_out = (ssl.MemoryBIO() for _ in range(4))
        self.client = self.client_context.wrap_bio(self.client_in, self.client_out, server_hostname=public.TLS_NAME)
        self.server = self.server_context.wrap_bio(self.server_in, self.server_out, server_side=True)
        complete = set()
        for _ in range(100):
            for name, peer in (('client', self.client), ('server', self.server)):
                if name not in complete:
                    try:
                        peer.do_handshake()
                        complete.add(name)
                    except ssl.SSLWantReadError:
                        pass
                self.transfer()
            if len(complete) == 2:
                return self
        pytest.fail('bounded in-memory TLS handshake did not complete')

    def version(self):
        return self.server.version()

    def settimeout(self, value):
        self.connection.settimeout(value)

    def unwrap(self):
        if self.ragged:
            self.server_in.write_eof()
            return self.server.unwrap()
        if self.application:
            self.client.write(self.application)
        try:
            self.client.unwrap()
        except ssl.SSLWantReadError:
            pass
        self.transfer()
        self.server.unwrap()  # Rejects application bytes before close_notify.
        self.transfer()
        self.client.unwrap()
        return self.connection

    def close(self):
        self.closed = True


@pytest.mark.parametrize('case', public.DATABASE_TLS_CASES)
def test_specs_pin_fixed_protocol_trust_and_zero_application_capabilities(case):
    spec = contract.spec(case)
    assert spec['topology'][0]['target'] == '127.0.0.1' and spec['topology'][0]['port'] == 8080
    assert spec['max_connections'] == spec['max_requests'] == 1
    assert spec['application_payloads'] == 'none'
    assert spec['request_count_means'] == 'server_completed_tls_handshake_and_clean_close_notify'
    assert all(spec[name] is False for name in ('authentication', 'credentials', 'database_selection', 'sql', 'backend', 'external_egress', 'resume'))
    expected = contract.identity(case, str(uuid4()))
    context = {'identity': expected, 'connection_count': 1, 'request_count': 1}
    assert contract.validate_context(context, expected) == context
    for change in ({'connection_count': 2}, {'request_count': 2}, {'connection_count': 0}, {'request_count': True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, expected)


@pytest.mark.parametrize('case', public.DATABASE_TLS_SUCCESS_CASES)
def test_verified_tls_and_clean_close_count_once_without_application_bytes(case):
    connection, counted = connection_for(case), []
    context = MemoryTLS(case)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5, context=context,
                  on_request=lambda: counted.append(1))
    assert counted == [1] and connection.closed and context.closed
    assert context.wraps == 1 and context.version() == 'TLSv1.3'
    assert connection.sent == public.database_tls_server_preface(case)
    assert all(0 < value <= 2 for value in connection.timeouts)


@pytest.mark.parametrize('case', ['postgresql-tls-untrusted', 'mysql-tls-untrusted'])
def test_untrusted_certificate_never_counts_completed_tls(case):
    context = MemoryTLS(case)
    with pytest.raises(ssl.SSLCertVerificationError):
        fixture.serve(connection_for(case), case=case, deadline=time.monotonic() + 5,
                      context=context, on_request=lambda: pytest.fail('untrusted handshake counted'))


@pytest.mark.parametrize('case', ['postgresql-tls-ok', 'mysql-tls-ok'])
@pytest.mark.parametrize('application', [b'SELECT 1;', b'user\0password\0', b'\0', b'A' * 4096])
def test_application_bytes_after_tls_never_count_success(case, application):
    context = MemoryTLS(case, application=application)
    with pytest.raises(ssl.SSLError):
        fixture.serve(connection_for(case), case=case, deadline=time.monotonic() + 5,
                      context=context, on_request=lambda: pytest.fail('application data counted as TLS-only'))
    assert context.closed


@pytest.mark.parametrize('case', ['postgresql-tls-ok', 'mysql-tls-ok'])
def test_tcp_eof_without_tls_close_notify_never_counts_success(case):
    context = MemoryTLS(case, ragged=True)
    with pytest.raises(ssl.SSLError):
        fixture.serve(connection_for(case), case=case, deadline=time.monotonic() + 5,
                      context=context, on_request=lambda: pytest.fail('ragged EOF counted'))
    assert context.closed


@pytest.mark.parametrize('case', [case for case in public.DATABASE_TLS_CASES if case.endswith(('-refused', '-malformed'))] + ['postgresql-tls-injected'])
def test_invalid_refused_or_hostile_preface_never_wraps_or_counts(case):
    connection = connection_for(case)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                  context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('invalid preface wrapped')),
                  on_request=lambda: pytest.fail('invalid preface counted'))
    assert connection.sent == public.database_tls_server_preface(case)


@pytest.mark.parametrize('case', ['postgresql-tls-stalled', 'mysql-tls-stalled'])
def test_stalled_negotiation_never_counts_before_deadline(monkeypatch, case):
    slept = []
    monkeypatch.setattr(fixture.time, 'sleep', slept.append)
    fixture.serve(connection_for(case), case=case, deadline=time.monotonic() + 5,
                  context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('stalled preface wrapped')),
                  on_request=lambda: pytest.fail('stalled preface counted'))
    assert len(slept) == 1 and 0 < slept[0] <= 5


@pytest.mark.parametrize('case', ['postgresql-tls-ok', 'mysql-tls-ok'])
def test_every_changed_or_truncated_client_negotiation_byte_is_rejected(case):
    expected = public.POSTGRESQL_SSL_REQUEST if case.startswith('postgresql-') else public.MYSQL_SSL_REQUEST
    requests = [expected[:length] for length in range(len(expected))]
    requests += [expected[:index] + bytes([value ^ 1]) + expected[index + 1:] for index, value in enumerate(expected)]
    for raw in requests:
        connection = Connection(raw)
        with pytest.raises(ValueError, match='ssl_request_only'):
            fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                          context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('unreviewed request wrapped')),
                          on_request=lambda: pytest.fail('unreviewed request counted'))
        if case.startswith('postgresql-'):
            assert connection.sent == b''


@pytest.mark.parametrize('version', ['', 'x' * 97, 'x\0y', 'x\ny', 'x\x7fy', 'é', None, b'version'])
def test_mysql_fixture_version_cannot_expand_or_break_preface(version):
    with pytest.raises(ValueError):
        public.mysql_tls_greeting(version=version)


def test_mysql_greeting_has_fixed_lengths_synthetic_nonce_and_tls_capability_only():
    greeting = public.mysql_tls_greeting()
    assert len(greeting) <= public.DATABASE_TLS_MAX_PREFACE_BYTES
    assert int.from_bytes(greeting[:3], 'little') == len(greeting) - 4 and greeting[3] == 0
    assert greeting[4] == 10
    assert greeting[5:greeting.index(b'\0', 5)] == b'8.0.36'
    nonce_offset = greeting.index(b'\0', 5) + 1 + 4
    assert greeting[nonce_offset:nonce_offset + 9] == b'syntheti\0'
    assert greeting.endswith(b'c-salt-12345\0mysql_native_password\0')
    offset = greeting.index(b'\0', 5) + 1 + 4 + 9
    assert int.from_bytes(greeting[offset:offset + 2], 'little') & 0x800
    refused = public.mysql_tls_greeting(tls=False)
    assert not int.from_bytes(refused[offset:offset + 2], 'little') & 0x800
    assert public.HOSTILE_NOTE.encode('ascii') in public.database_tls_server_preface('mysql-tls-injected')


@pytest.mark.parametrize('case', ['postgresql-tls-ok', 'mysql-tls-ok'])
def test_expired_deadline_does_not_negotiate_or_count(case):
    connection = connection_for(case)
    with pytest.raises(ValueError, match='deadline'):
        fixture.serve(connection, case=case, deadline=time.monotonic() - 1, context=None,
                      on_request=lambda: pytest.fail('expired handshake counted'))
    assert connection.sent == b''


@pytest.mark.parametrize('case', ['postgresql-tls-ok', 'mysql-tls-ok'])
def test_owner_closes_second_connection_before_processing_it(monkeypatch, case):
    seen, closed = [], []
    peers = [SimpleNamespace(settimeout=lambda _: None, close=lambda i=i: closed.append(i)) for i in range(2)]
    iterator = iter(peers)
    service = owner.NetworkToolsService.__new__(owner.NetworkToolsService)
    service.case, service.rpc, service.context = case, None, object()
    service.connections = service.requests = 0
    service.failed = False
    service.condition = threading.Condition()
    service.deadline = time.monotonic() + 5
    service.listener = SimpleNamespace(accept=lambda: (next(iterator), None))
    def serve(peer, **kwargs):
        seen.append(peer)
        kwargs['on_request']()
    monkeypatch.setattr(owner.database_tls_fixture, 'serve', serve)
    service._serve()
    assert seen == peers[:1] and service.connections == service.requests == 1
    assert service.failed and 1 in closed


def test_exact_database_negotiations_have_no_authentication_or_database_payload():
    assert public.POSTGRESQL_SSL_REQUEST == bytes.fromhex('0000000804d2162f')
    request = public.MYSQL_SSL_REQUEST
    assert len(request) == 36 and request[:4] == bytes.fromhex('20000001')
    assert request[4:8] == bytes.fromhex('85ae7f00')
    assert request[8:13] == bytes.fromhex('0000000121')
    assert request[13:] == bytes(23)


def test_unknown_case_never_reads_or_sends_any_bytes():
    connection = Connection(b'')
    with pytest.raises(ValueError, match='invalid_database_tls_fixture_case'):
        fixture.serve(connection, case='mysql-tls-unreviewed', deadline=time.monotonic() + 5,
                      context=None, on_request=lambda: pytest.fail('unknown case counted'))
    assert connection.timeouts == [] and connection.sent == b''
