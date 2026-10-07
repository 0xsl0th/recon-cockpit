"""Fixed SMTP commands, actual in-memory TLS, and independent owner counters."""

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
from recon_cockpit.secure_agent import network_tools_smtp_tls_fixture as fixture
from recon_cockpit.secure_agent import network_tools_lab_worker as owner
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from test_secure_database_tls_fixture import Connection, MemoryTLS


REQUEST = public.SMTP_TLS_EHLO + public.SMTP_TLS_STARTTLS


def context_for(case, tmp_path, **kwargs):
    # Reuse the socket-free TLS bridge, including actual CA/name verification.
    selected = 'postgresql-tls-untrusted' if case == 'smtp-tls-untrusted' else 'postgresql-tls-ok'
    return MemoryTLS(selected, tmp_path, **kwargs)


@pytest.mark.parametrize('case', public.SMTP_TLS_COMPLETE_CASES)
def test_fixed_prelude_and_clean_verified_tls_count_once_after_close(tmp_path, monkeypatch, case):
    monkeypatch.setattr(fixture.time, 'sleep', lambda _: None)
    connection, counted = Connection(REQUEST), []
    context = context_for(case, tmp_path)
    original_unwrap = context.unwrap
    unwrapped = []
    def unwrap():
        assert counted == []
        closed = original_unwrap()
        unwrapped.append(True)
        return closed
    context.unwrap = unwrap
    def count():
        assert unwrapped == [True]
        assert connection.source.tell() == len(REQUEST)
        counted.append(1)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        context=context, on_request=count)
    assert counted == [1] and context.wraps == 1 and context.closed and connection.closed
    assert context.version() == 'TLSv1.3'
    assert connection.sent == b''.join(public.smtp_tls_dialogue(case).values())
    assert all(0 < timeout <= 2 for timeout in connection.timeouts)


@pytest.mark.parametrize('case', [case for case in public.SMTP_TLS_CASES
    if case not in public.SMTP_TLS_COMPLETE_CASES and case != 'smtp-tls-untrusted'])
def test_negative_preludes_count_both_exact_commands_before_reply_or_stall(monkeypatch, case):
    connection, counted, waited = Connection(REQUEST), [], []
    dialogue = public.smtp_tls_dialogue(case)
    monkeypatch.setattr(fixture.time, 'sleep', waited.append)
    def count():
        assert connection.source.tell() == len(REQUEST)
        assert connection.sent == dialogue['banner'] + dialogue['ehlo']
        counted.append(1)
    fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
        context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('negative prelude wrapped')),
        on_request=count)
    assert counted == [1]
    expected = b''.join(raw for raw in dialogue.values() if raw is not None)
    if case == 'smtp-tls-malformed':
        expected += public.TLS_MALFORMED_BYTES
    assert connection.sent == expected
    assert bool(waited) is (case == 'smtp-tls-stalled')


def test_untrusted_certificate_counts_only_exact_prelude_before_failed_handshake(tmp_path):
    connection, counted = Connection(REQUEST), []
    context = context_for('smtp-tls-untrusted', tmp_path)
    def count():
        assert context.wraps == 0 and connection.source.tell() == len(REQUEST)
        counted.append(1)
    with pytest.raises(ssl.SSLCertVerificationError):
        fixture.serve(connection, case='smtp-tls-untrusted', deadline=time.monotonic() + 5,
            context=context, on_request=count)
    assert counted == [1] and context.wraps == 1


@pytest.mark.parametrize('application', [b'EHLO harbordesk.test\r\n', b'AUTH PLAIN credentials\r\n',
    b'MAIL FROM:<sender@harbordesk.test>\r\n', b'RCPT TO:<recipient@harbordesk.test>\r\n',
    b'DATA\r\nmessage\r\n.\r\n', b'\0', b'A' * 4096])
def test_post_tls_application_bytes_never_count_completed_handshake(tmp_path, application):
    context = context_for('smtp-tls-ok', tmp_path, application=application)
    with pytest.raises(ssl.SSLError):
        fixture.serve(Connection(REQUEST), case='smtp-tls-ok', deadline=time.monotonic() + 5,
            context=context, on_request=lambda: pytest.fail('application data counted as TLS-only'))
    assert context.closed


def test_tcp_eof_without_close_notify_does_not_count_completed_tls(tmp_path):
    context = context_for('smtp-tls-ok', tmp_path, ragged=True)
    with pytest.raises(ssl.SSLError):
        fixture.serve(Connection(REQUEST), case='smtp-tls-ok', deadline=time.monotonic() + 5,
            context=context, on_request=lambda: pytest.fail('ragged EOF counted as clean TLS close'))
    assert context.closed


@pytest.mark.parametrize('case', public.SMTP_TLS_CASES)
@pytest.mark.parametrize('fault', ['mutation', 'truncation'])
def test_every_changed_or_truncated_command_byte_prevents_count_and_tls(monkeypatch, case, fault):
    monkeypatch.setattr(fixture.time, 'sleep', lambda _: None)
    candidates = ([REQUEST[:index] + bytes([value ^ 1]) + REQUEST[index + 1:]
        for index, value in enumerate(REQUEST)] if fault == 'mutation'
        else [REQUEST[:length] for length in range(len(REQUEST))])
    for raw in candidates:
        with pytest.raises(ValueError, match='fixed_command_only'):
            fixture.serve(Connection(raw), case=case, deadline=time.monotonic() + 5,
                context=SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail('invalid command wrapped')),
                on_request=lambda: pytest.fail('invalid command counted'))


@pytest.mark.parametrize('command', [b'AUTH PLAIN credentials\r\n', b'MAIL FROM:<sender>\r\n',
    b'RCPT TO:<recipient>\r\n', b'HELO harbordesk.test\r\n', b'STARTTLS\n',
    b'EHLO external.test\r\n'])
def test_unreviewed_commands_cannot_replace_either_fixed_step(command):
    for raw in (command + public.SMTP_TLS_STARTTLS, public.SMTP_TLS_EHLO + command):
        with pytest.raises(ValueError, match='fixed_command_only'):
            fixture.serve(Connection(raw), case='smtp-tls-refused', deadline=time.monotonic() + 5,
                context=None, on_request=lambda: pytest.fail('unreviewed SMTP command counted'))


def test_fragmented_prelude_keeps_tls_transition_in_one_write(monkeypatch):
    monkeypatch.setattr(fixture.time, 'sleep', lambda _: None)
    connection, writes = Connection(REQUEST), []
    original_send = connection.sendall
    connection.sendall = lambda raw: (writes.append(raw), original_send(raw))
    class StopAtTLS(Exception):
        pass
    def wrap(*args, **kwargs):
        raise StopAtTLS
    with pytest.raises(StopAtTLS):
        fixture.serve(connection, case='smtp-tls-fragmented', deadline=time.monotonic() + 5,
            context=SimpleNamespace(wrap_socket=wrap), on_request=lambda: pytest.fail('TLS not complete'))
    dialogue = public.smtp_tls_dialogue('smtp-tls-fragmented')
    assert writes[-1] == dialogue['ready']
    assert all(len(raw) == 1 for raw in writes[:-1])
    assert len(writes) == len(dialogue['banner']) + len(dialogue['ehlo']) + 1


@pytest.mark.parametrize('case', public.SMTP_TLS_CASES)
def test_public_dialogues_are_bounded_fixed_smtp_with_case_specific_transitions(case):
    dialogue = public.smtp_tls_dialogue(case)
    assert set(dialogue) == {'banner', 'ehlo', 'ready'}
    assert public.tool_for_case(case) == public.SMTP_TLS_TOOL_ID
    assert sum(len(raw) for raw in dialogue.values() if raw is not None) <= public.SMTP_TLS_MAX_PLAINTEXT_BYTES == 1024
    assert public.SMTP_TLS_EHLO == b'EHLO harbordesk.test\r\n'
    assert public.SMTP_TLS_STARTTLS == b'STARTTLS\r\n'
    if case in public.SMTP_TLS_SUCCESS_CASES:
        assert dialogue['ehlo'].splitlines(keepends=True)[-1] == b'250 STARTTLS\r\n'
    if case == 'smtp-tls-injected':
        assert public.HOSTILE_NOTE.encode('ascii') in dialogue['banner']
        assert public.HOSTILE_NOTE.encode('ascii') in dialogue['ehlo']
    if case == 'smtp-tls-extra-output':
        assert b'250-STARTTLS\r\n' in dialogue['ehlo']
        assert dialogue['ehlo'].endswith(public.HOSTILE_NOTE.encode('ascii') + b'\r\n')
    if case == 'smtp-tls-no-advertisement':
        assert b'STARTTLS' not in dialogue['ehlo']


@pytest.mark.parametrize('case', public.SMTP_TLS_CASES)
def test_spec_pins_commands_reply_bytes_trust_and_case_specific_counter_meaning(case):
    definition = contract.spec(case)
    complete = case in public.SMTP_TLS_COMPLETE_CASES
    assert definition['command_sha256'] == [hashlib.sha256(raw).hexdigest()
        for raw in (public.SMTP_TLS_EHLO, public.SMTP_TLS_STARTTLS)]
    assert definition['response_sha256'] == {name: None if raw is None else hashlib.sha256(raw).hexdigest()
        for name, raw in public.smtp_tls_dialogue(case).items()}
    assert definition['ca_sha256'] == hashlib.sha256(public.CA_PEM).hexdigest()
    assert definition['certificate_sha256'] == (public.UNTRUSTED_SERVER_CERT_SHA256
        if case == 'smtp-tls-untrusted' else public.SERVER_CERT_SHA256)
    assert definition['max_commands'] == 2
    assert definition['max_connections'] == definition['max_requests'] == 1
    assert definition['max_fixture_plaintext_bytes'] == 1024
    assert definition['counter_includes_clean_tls_close'] is complete
    assert definition['request_count_means'] == ('validated_ehlo_starttls_then_tls13_and_clean_close_notify'
        if complete else 'validated_ehlo_and_starttls_before_negative_response')
    for name in ('authentication', 'credentials', 'mail', 'recipient_probing',
            'tls_application_requests', 'plaintext_session', 'external_egress', 'resume',
            'client_validates_smtp_reply_codes', 'client_requires_starttls_advertisement',
            'full_smtp_dialogue_retained', 'service_identity_claim', 'vulnerability_claim'):
        assert definition[name] is False
    identity = contract.identity(case, str(uuid4()))
    context = {'identity': identity, 'connection_count': 1, 'request_count': 1}
    assert contract.validate_context(context, identity) == context
    for change in ({'connection_count': 2}, {'request_count': 2}, {'connection_count': 0}, {'request_count': True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **change}, identity)


@pytest.mark.parametrize('case', ['smtp-tls-ok', 'smtp-tls-untrusted', 'smtp-tls-refused'])
def test_second_connection_is_closed_before_any_smtp_processing(monkeypatch, case):
    seen = []
    peers = [Connection(REQUEST), Connection(REQUEST)]
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
    monkeypatch.setattr(owner.smtp_tls_fixture, 'serve', serve)
    service._serve()
    assert seen == peers[:1] and service.connections == service.requests == 1
    assert service.failed and peers[1].closed
    assert peers[1].source.tell() == 0 and peers[1].sent == b''


def test_expired_deadline_prevents_banner_and_execution_count():
    connection = Connection(REQUEST)
    with pytest.raises(ValueError, match='deadline'):
        fixture.serve(connection, case='smtp-tls-ok', deadline=time.monotonic() - 1,
            context=None, on_request=lambda: pytest.fail('expired request counted'))
    assert connection.sent == b'' and connection.source.tell() == 0


@pytest.mark.parametrize('case', ['smtp-tls-unknown', '', None, []])
def test_invalid_fixture_case_never_touches_a_connection(case):
    connection = Connection(REQUEST)
    with pytest.raises(ValueError, match='invalid_smtp_tls_fixture_case'):
        fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
            context=None, on_request=lambda: pytest.fail('invalid case counted'))
    assert connection.sent == b'' and connection.source.tell() == 0


def test_owner_module_imports_without_package_under_isolated_python(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_smtp_tls_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert len(module.fixture.SMTP_TLS_CASES) == 12
print('isolated SMTP STARTTLS owner ready')
"""
    result = subprocess.run([sys.executable, '-I', '-S', '-c', script, str(Path(fixture.__file__).resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'isolated SMTP STARTTLS owner ready\n' and result.stderr == ''
