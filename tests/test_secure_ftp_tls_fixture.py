"""Fixed FTP AUTH TLS, actual in-memory TLS and independent owner counters."""

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
from recon_cockpit.secure_agent import network_tools_ftp_tls_fixture as fixture
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner
from test_secure_database_tls_fixture import Connection, MemoryTLS


def context_for(case, tmp_path, **kwargs):
    selected = 'postgresql-tls-untrusted' if case == 'ftp-tls-untrusted' else 'postgresql-tls-ok'
    return MemoryTLS(selected, tmp_path, **kwargs)


@pytest.mark.parametrize('case', public.FTP_TLS_COMPLETE_CASES)
def test_exact_auth_and_verified_tls_count_only_after_clean_close(tmp_path, monkeypatch, case):
    monkeypatch.setattr(fixture.time, 'sleep', lambda _: None)
    connection, counted = Connection(public.FTP_TLS_AUTH), []
    context = context_for(case, tmp_path)
    original, unwrapped = context.unwrap, []
    def unwrap():
        assert counted == []
        closed = original()
        unwrapped.append(True)
        return closed
    context.unwrap = unwrap
    def count():
        assert unwrapped == [True] and connection.source.tell() == 10
        counted.append(1)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        context=context, on_request=count)
    assert counted == [1] and context.wraps == 1 and context.closed and connection.closed
    assert context.version() == 'TLSv1.3'
    assert connection.sent == b''.join(public.ftp_tls_dialogue(case).values())
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)


@pytest.mark.parametrize('case', ['ftp-tls-refused', 'ftp-tls-malformed', 'ftp-tls-stalled'])
def test_negative_cases_count_exact_auth_before_ready_failure_or_stall(monkeypatch, case):
    connection, counted, waited = Connection(public.FTP_TLS_AUTH), [], []
    dialogue = public.ftp_tls_dialogue(case)
    monkeypatch.setattr(fixture.time, 'sleep', waited.append)
    def count():
        assert connection.source.tell() == 10 and connection.sent == dialogue['greeting']
        counted.append(1)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('negative reply wrapped')),
        on_request=count)
    expected = b''.join(raw for raw in dialogue.values() if raw is not None)
    if case == 'ftp-tls-malformed':
        expected += public.TLS_MALFORMED_BYTES
    assert counted == [1] and connection.sent == expected
    assert bool(waited) is (case == 'ftp-tls-stalled')


def test_untrusted_certificate_counts_auth_before_ca_verification_failure(tmp_path):
    connection, counted = Connection(public.FTP_TLS_AUTH), []
    context = context_for('ftp-tls-untrusted', tmp_path)
    def count():
        assert context.wraps == 0 and connection.source.tell() == 10
        counted.append(1)
    with pytest.raises(ssl.SSLCertVerificationError):
        fixture.serve(connection, case='ftp-tls-untrusted', deadline=time.monotonic() + 5,
            context=context, on_request=count)
    assert counted == [1] and context.wraps == 1


@pytest.mark.parametrize('application', [b'USER anonymous\r\n', b'PASS secret\r\n',
    b'PBSZ 0\r\n', b'PROT P\r\n', b'PASV\r\n', b'EPSV\r\n', b'PORT 127,0,0,1,1,1\r\n',
    b'LIST\r\n', b'NLST\r\n', b'RETR file\r\n', b'STOR file\r\n',
    public.FTP_TLS_AUTH, b'\0', b'A' * 4096])
def test_login_data_transfer_and_other_tls_application_bytes_cannot_count(tmp_path, application):
    context = context_for('ftp-tls-ok', tmp_path, application=application)
    with pytest.raises(ssl.SSLError):
        fixture.serve(Connection(public.FTP_TLS_AUTH), case='ftp-tls-ok', deadline=time.monotonic() + 5,
            context=context, on_request=lambda: pytest.fail('post-TLS application data counted'))
    assert context.closed


def test_ragged_tcp_eof_does_not_count_tls_completion(tmp_path):
    context = context_for('ftp-tls-ok', tmp_path, ragged=True)
    with pytest.raises(ssl.SSLError):
        fixture.serve(Connection(public.FTP_TLS_AUTH), case='ftp-tls-ok', deadline=time.monotonic() + 5,
            context=context, on_request=lambda: pytest.fail('ragged EOF counted'))
    assert context.closed


@pytest.mark.parametrize('case', public.FTP_TLS_CASES)
@pytest.mark.parametrize('fault', ['mutation', 'truncation'])
def test_each_changed_or_truncated_command_byte_prevents_ready_count_and_tls(monkeypatch, case, fault):
    monkeypatch.setattr(fixture.time, 'sleep', lambda _: None)
    request = public.FTP_TLS_AUTH
    candidates = ([request[:index] + bytes([value ^ 1]) + request[index + 1:]
        for index, value in enumerate(request)] if fault == 'mutation'
        else [request[:length] for length in range(len(request))])
    for raw in candidates:
        connection = Connection(raw)
        with pytest.raises(ValueError, match='fixed_command_only'):
            fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('invalid AUTH wrapped')),
                on_request=lambda: pytest.fail('invalid AUTH counted'))
        assert connection.sent == public.ftp_tls_dialogue(case)['greeting']


@pytest.mark.parametrize('raw', [b'USER anonymous\r\n', b'PASS secret\r\n', b'AUTH SSL\r\n',
    b'auth tls\r\n', b'AUTH TLS\n', b'PBSZ 0\r\n', b'PROT P\r\n', b'PASV\r\n', b'LIST\r\n'])
def test_login_or_other_ftp_commands_cannot_replace_auth_tls(raw):
    with pytest.raises(ValueError, match='fixed_command_only'):
        fixture.serve(Connection(raw), case='ftp-tls-refused', deadline=time.monotonic() + 5,
            context=None, on_request=lambda: pytest.fail('unreviewed FTP command counted'))


def test_fragmentation_applies_only_to_greeting_and_keeps_ready_one_write(tmp_path, monkeypatch):
    connection, writes, waited = Connection(public.FTP_TLS_AUTH), [], []
    original = connection.sendall
    connection.sendall = lambda raw: (writes.append(raw), original(raw))
    monkeypatch.setattr(fixture.time, 'sleep', waited.append)
    fixture.serve(connection, case='ftp-tls-fragmented', deadline=time.monotonic() + 5,
        context=context_for('ftp-tls-fragmented', tmp_path), on_request=lambda: None)
    dialogue = public.ftp_tls_dialogue('ftp-tls-fragmented')
    assert writes[:-1] == [bytes([value]) for value in dialogue['greeting']]
    assert writes[-1:] == [dialogue['ready']]
    assert waited == [0.002] * len(dialogue['greeting'])


@pytest.mark.parametrize('case', public.FTP_TLS_CASES)
def test_public_dialogue_is_bounded_and_models_native_status_limitations(case):
    dialogue = public.ftp_tls_dialogue(case)
    assert public.tool_for_case(case) == public.FTP_TLS_TOOL_ID
    assert public.FTP_TLS_AUTH == b'AUTH TLS\r\n' and len(public.FTP_TLS_AUTH) == 10
    assert public.FTP_TLS_FINAL_GREETING == b'220 harbordesk.test ready\r\n'
    assert public.FTP_TLS_MAX_RESPONSE_BYTES == 1024
    assert set(dialogue) == {'greeting', 'ready'}
    assert sum(len(raw) for raw in dialogue.values() if raw is not None) <= 1024
    assert (dialogue['ready'] is None) is (case == 'ftp-tls-stalled')
    if case in public.FTP_TLS_SUCCESS_CASES:
        assert dialogue['greeting'].endswith(public.FTP_TLS_FINAL_GREETING)
    if case == 'ftp-tls-injected':
        assert public.HOSTILE_NOTE.encode('ascii') in dialogue['greeting']
        assert public.HOSTILE_NOTE.encode('ascii') not in dialogue['greeting'].splitlines()[-1]
    if case == 'ftp-tls-wrong-status':
        assert dialogue['ready'].startswith(b'454 ')
        assert dialogue == public.ftp_tls_dialogue('ftp-tls-refused')
    if case == 'ftp-tls-bad-banner':
        assert dialogue['greeting'].startswith(b'500 ')
    if case == 'ftp-tls-extra-output':
        assert dialogue['greeting'] == b'220 ' + public.HOSTILE_NOTE.encode('ascii') + b'\r\n'


@pytest.mark.parametrize('case', public.FTP_TLS_CASES)
def test_spec_pins_dialogue_ca_and_distinguishes_tls_close_from_auth_progress(case):
    definition, dialogue = contract.spec(case), public.ftp_tls_dialogue(case)
    complete = case in public.FTP_TLS_COMPLETE_CASES
    assert definition['request_sha256'] == hashlib.sha256(public.FTP_TLS_AUTH).hexdigest()
    assert definition['response_sha256']['greeting'] == hashlib.sha256(dialogue['greeting']).hexdigest()
    assert definition['response_sha256']['ready'] == (None if dialogue['ready'] is None
        else hashlib.sha256(dialogue['ready']).hexdigest())
    assert definition['ca_sha256'] == hashlib.sha256(public.CA_PEM).hexdigest()
    assert definition['certificate_sha256'] == (public.UNTRUSTED_SERVER_CERT_SHA256
        if case == 'ftp-tls-untrusted' else public.SERVER_CERT_SHA256)
    assert definition['max_connections'] == definition['max_requests'] == 1
    assert definition['request_bytes'] == 10 and definition['max_fixture_response_bytes'] == 1024
    assert definition['counter_includes_clean_tls_close'] is complete
    assert definition['request_count_means'] == ('validated_auth_tls_then_tls13_and_clean_close_notify'
        if complete else 'validated_auth_tls_before_negative_response')
    assert definition['malformed_tls_sha256'] == (hashlib.sha256(public.TLS_MALFORMED_BYTES).hexdigest()
        if case == 'ftp-tls-malformed' else None)
    identity = contract.identity(case, str(uuid4()))
    context = {'identity': identity, 'connection_count': 1, 'request_count': 1}
    assert contract.validate_context(context, identity) == context
    for change in ({'connection_count': 2}, {'request_count': 2}, {'connection_count': 0}, {'request_count': True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize('case', ['ftp-tls-ok', 'ftp-tls-untrusted', 'ftp-tls-refused'])
def test_second_connection_is_closed_before_any_ftp_processing(monkeypatch, case):
    seen, peers = [], [Connection(public.FTP_TLS_AUTH), Connection(public.FTP_TLS_AUTH)]
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
    monkeypatch.setattr(owner.ftp_tls_fixture, 'serve', serve)
    service._serve()
    assert seen == peers[:1] and service.connections == service.requests == 1
    assert service.failed and peers[1].closed and peers[1].source.tell() == 0 and peers[1].sent == b''


@pytest.mark.parametrize('case', ['ftp-tls-unknown', '', None, []])
def test_invalid_case_cannot_read_client_or_reply(case):
    connection = Connection(public.FTP_TLS_AUTH)
    with pytest.raises(ValueError, match='invalid_ftp_tls_fixture_case'):
        fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
            context=None, on_request=lambda: pytest.fail('invalid case counted'))
    assert connection.sent == b'' and connection.source.tell() == 0


def test_expired_deadline_prevents_greeting_request_and_count():
    connection = Connection(public.FTP_TLS_AUTH)
    with pytest.raises(ValueError, match='deadline'):
        fixture.serve(connection, case='ftp-tls-ok', deadline=time.monotonic() - 1,
            context=None, on_request=lambda: pytest.fail('expired request counted'))
    assert connection.sent == b'' and connection.source.tell() == 0


def test_owner_imports_in_isolated_python_without_package(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_ftp_tls_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.FTP_TLS_CASES) == 11
print('isolated FTP TLS owner ready')
"""
    result = subprocess.run([sys.executable, '-I', '-S', '-c', script, str(Path(fixture.__file__).resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'isolated FTP TLS owner ready\n' and result.stderr == ''
