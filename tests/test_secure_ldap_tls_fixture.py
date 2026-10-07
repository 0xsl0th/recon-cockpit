"""Exact LDAP upgrade bytes, real in-memory TLS and case-bound owner witnesses."""

import hashlib
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as public
from recon_cockpit.secure_agent import network_tools_ldap_tls_fixture as fixture
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner
from test_secure_database_tls_fixture import Connection, MemoryTLS


def context_for(case, tmp_path, **kwargs):
    selected = 'postgresql-tls-untrusted' if case == 'ldap-tls-untrusted' else 'postgresql-tls-ok'
    return MemoryTLS(selected, tmp_path, **kwargs)


@pytest.mark.parametrize('case', public.LDAP_TLS_COMPLETE_CASES)
def test_fixed_request_and_verified_tls_count_only_after_clean_close(tmp_path, case):
    connection, counted = Connection(public.LDAP_TLS_REQUEST), []
    context = context_for(case, tmp_path)
    original = context.unwrap
    unwrapped = []
    def unwrap():
        assert counted == []
        closed = original()
        unwrapped.append(True)
        return closed
    context.unwrap = unwrap
    def count():
        assert unwrapped == [True] and connection.source.tell() == 31
        counted.append(1)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        context=context, on_request=count)
    assert counted == [1] and context.wraps == 1 and context.closed and connection.closed
    assert context.version() == 'TLSv1.3'
    assert connection.sent == public.ldap_tls_response(case)
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)


@pytest.mark.parametrize('case', [case for case in public.LDAP_TLS_CASES
    if case not in public.LDAP_TLS_COMPLETE_CASES and case != 'ldap-tls-untrusted'])
def test_negative_cases_count_exact_request_before_any_reply_or_stall(monkeypatch, case):
    connection, counted, waited = Connection(public.LDAP_TLS_REQUEST), [], []
    monkeypatch.setattr(fixture.time, 'sleep', waited.append)
    def count():
        assert connection.source.tell() == 31 and connection.sent == b''
        counted.append(1)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('negative LDAP reply wrapped')),
        on_request=count)
    expected = public.ldap_tls_response(case) or b''
    if case == 'ldap-tls-bad-tls':
        expected += public.TLS_MALFORMED_BYTES
    assert counted == [1] and connection.sent == expected
    assert bool(waited) is (case in ('ldap-tls-stalled', 'ldap-tls-fragmented'))


def test_untrusted_certificate_counts_request_before_ca_verification_failure(tmp_path):
    connection, counted = Connection(public.LDAP_TLS_REQUEST), []
    context = context_for('ldap-tls-untrusted', tmp_path)
    def count():
        assert context.wraps == 0 and connection.source.tell() == 31
        counted.append(1)
    with pytest.raises(ssl.SSLCertVerificationError):
        fixture.serve(connection, case='ldap-tls-untrusted', deadline=time.monotonic() + 5,
            context=context, on_request=count)
    assert counted == [1] and context.wraps == 1


@pytest.mark.parametrize('application', [bytes.fromhex('300c020102600702010304008000'),
    bytes.fromhex('30050201026300'), b'uid=user\0password\0', b'ldap://127.0.0.2:8080/',
    public.LDAP_TLS_REQUEST, b'\0', b'A' * 4096])
def test_bind_search_credentials_and_other_tls_application_bytes_cannot_count(tmp_path, application):
    context = context_for('ldap-tls-ok', tmp_path, application=application)
    with pytest.raises(ssl.SSLError):
        fixture.serve(Connection(public.LDAP_TLS_REQUEST), case='ldap-tls-ok', deadline=time.monotonic() + 5,
            context=context, on_request=lambda: pytest.fail('post-TLS application data counted'))
    assert context.closed


def test_ragged_tcp_eof_does_not_count_tls_completion(tmp_path):
    context = context_for('ldap-tls-ok', tmp_path, ragged=True)
    with pytest.raises(ssl.SSLError):
        fixture.serve(Connection(public.LDAP_TLS_REQUEST), case='ldap-tls-ok', deadline=time.monotonic() + 5,
            context=context, on_request=lambda: pytest.fail('ragged EOF counted'))
    assert context.closed


@pytest.mark.parametrize('case', public.LDAP_TLS_CASES)
@pytest.mark.parametrize('fault', ['mutation', 'truncation'])
def test_each_changed_or_truncated_request_byte_prevents_reply_count_and_tls(case, fault):
    request = public.LDAP_TLS_REQUEST
    candidates = ([request[:index] + bytes([value ^ 1]) + request[index + 1:]
        for index, value in enumerate(request)] if fault == 'mutation'
        else [request[:length] for length in range(len(request))])
    for raw in candidates:
        connection = Connection(raw)
        with pytest.raises(ValueError, match='fixed_request_only'):
            fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('invalid request wrapped')),
                on_request=lambda: pytest.fail('invalid request counted'))
        assert connection.sent == b''


@pytest.mark.parametrize('raw', [bytes.fromhex('300c020101600702010304008000'),
    bytes.fromhex('30050201016300'), b'Bind username password', b'STARTTLS\r\n'])
def test_bind_search_or_text_cannot_replace_starttls_request(raw):
    with pytest.raises(ValueError, match='fixed_request_only'):
        fixture.serve(Connection(raw), case='ldap-tls-refused', deadline=time.monotonic() + 5,
            context=None, on_request=lambda: pytest.fail('unreviewed LDAP operation counted'))


def test_fragmented_reply_starts_with_one_byte_before_separate_remainder(monkeypatch):
    connection, writes, waited, counted = Connection(public.LDAP_TLS_REQUEST), [], [], []
    original = connection.sendall
    connection.sendall = lambda raw: (writes.append(raw), original(raw))
    def wait(value):
        assert writes == [b'\x30'] and counted == [1]
        waited.append(value)
    monkeypatch.setattr(fixture.time, 'sleep', wait)
    fixture.serve(connection, case='ldap-tls-fragmented', deadline=time.monotonic() + 5,
        context=None, on_request=lambda: counted.append(1))
    assert len(writes) == 2 and b''.join(writes) == public.ldap_tls_response('ldap-tls-fragmented')
    assert waited == [0.2]


def test_request_is_one_message_id_one_starttls_extended_operation():
    assert public.LDAP_TLS_REQUEST == bytes.fromhex('301d02010177188016312e332e362e312e342e312e313436362e3230303337')
    assert len(public.LDAP_TLS_REQUEST) == 31
    assert public.LDAP_TLS_REQUEST[9:] == b'1.3.6.1.4.1.1466.20037'


@pytest.mark.parametrize('case', public.LDAP_TLS_CASES)
def test_public_response_shapes_and_maximum_are_fixed(case):
    raw = public.ldap_tls_response(case)
    assert public.tool_for_case(case) == public.LDAP_TLS_TOOL_ID
    assert public.LDAP_TLS_MAX_RESPONSE_BYTES == 1024
    if case == 'ldap-tls-stalled':
        assert raw is None
        return
    assert type(raw) is bytes and 0 < len(raw) <= 1024
    canonical = bytes.fromhex('300c02010178070a010004000400')
    if case in ('ldap-tls-ok', 'ldap-tls-untrusted', 'ldap-tls-fragmented', 'ldap-tls-bad-tls'):
        assert raw == canonical
    elif case == 'ldap-tls-response-name':
        assert raw.endswith(b'\x8a\x16' + b'1.3.6.1.4.1.1466.20037')
    elif case == 'ldap-tls-mismatched-id':
        assert raw == canonical[:4] + b'\x02' + canonical[5:]
    elif case == 'ldap-tls-injected':
        assert public.HOSTILE_NOTE.encode('ascii') in raw
    elif case == 'ldap-tls-refused':
        assert raw[9] == 52
    elif case == 'ldap-tls-referral':
        assert raw[9] == 10 and b'ldap://127.0.0.2:8080/' in raw
    elif case == 'ldap-tls-malformed':
        assert raw[5] == 0x79
    else:
        assert raw == canonical[:7]


@pytest.mark.parametrize('case', public.LDAP_TLS_CASES)
def test_spec_pins_wire_bytes_ca_and_distinguishes_tls_close_from_request_progress(case):
    definition = contract.spec(case)
    complete = case in public.LDAP_TLS_COMPLETE_CASES
    raw = public.ldap_tls_response(case)
    assert definition['request_sha256'] == hashlib.sha256(public.LDAP_TLS_REQUEST).hexdigest()
    assert definition['response_sha256'] == (None if raw is None else hashlib.sha256(raw).hexdigest())
    assert definition['ca_sha256'] == hashlib.sha256(public.CA_PEM).hexdigest()
    assert definition['certificate_sha256'] == (public.UNTRUSTED_SERVER_CERT_SHA256
        if case == 'ldap-tls-untrusted' else public.SERVER_CERT_SHA256)
    assert definition['max_connections'] == definition['max_requests'] == 1
    assert definition['request_bytes'] == 31 and definition['max_fixture_response_bytes'] == 1024
    assert definition['counter_includes_clean_tls_close'] is complete
    assert definition['request_count_means'] == ('validated_starttls_request_then_tls13_and_clean_close_notify'
        if complete else 'validated_starttls_request_before_negative_response')
    assert definition['malformed_tls_sha256'] == (hashlib.sha256(public.TLS_MALFORMED_BYTES).hexdigest()
        if case == 'ldap-tls-bad-tls' else None)
    for name in ('bind', 'search', 'authentication', 'credentials', 'referral_following',
            'tls_application_requests', 'plaintext_session', 'external_egress', 'resume',
            'client_matches_response_message_id', 'client_validates_complete_ldap_response',
            'complete_ldap_response_retained', 'service_identity_claim', 'vulnerability_claim'):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {'identity': identity, 'connection_count': 1, 'request_count': 1}
    assert contract.validate_context(context, identity) == context
    for change in ({'connection_count': 2}, {'request_count': 2}, {'connection_count': 0}, {'request_count': True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize('case', ['ldap-tls-ok', 'ldap-tls-untrusted', 'ldap-tls-referral'])
def test_second_connection_is_closed_before_any_ldap_processing(monkeypatch, case):
    seen, peers = [], [Connection(public.LDAP_TLS_REQUEST), Connection(public.LDAP_TLS_REQUEST)]
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
    monkeypatch.setattr(owner.ldap_tls_fixture, 'serve', serve)
    service._serve()
    assert seen == peers[:1] and service.connections == service.requests == 1
    assert service.failed and peers[1].closed and peers[1].source.tell() == 0 and peers[1].sent == b''


def test_expired_deadline_prevents_request_read_reply_and_count():
    connection = Connection(public.LDAP_TLS_REQUEST)
    with pytest.raises(ValueError, match='deadline'):
        fixture.serve(connection, case='ldap-tls-ok', deadline=time.monotonic() - 1,
            context=None, on_request=lambda: pytest.fail('expired request counted'))
    assert connection.sent == b'' and connection.source.tell() == 0


@pytest.mark.parametrize('case', ['ldap-tls-unknown', '', None, []])
def test_invalid_case_cannot_read_client_or_reply(case):
    connection = Connection(public.LDAP_TLS_REQUEST)
    with pytest.raises(ValueError, match='invalid_ldap_tls_fixture_case'):
        fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
            context=None, on_request=lambda: pytest.fail('invalid case counted'))
    assert connection.sent == b'' and connection.source.tell() == 0


def test_owner_imports_in_isolated_python_without_package(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_ldap_tls_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.LDAP_TLS_CASES) == 12
print('isolated LDAP STARTTLS owner ready')
"""
    result = subprocess.run([sys.executable, '-I', '-S', '-c', script, str(Path(fixture.__file__).resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'isolated LDAP STARTTLS owner ready\n' and result.stderr == ''
