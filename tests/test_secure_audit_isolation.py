"""Audit protocol and durability tests; doubles do not prove confinement."""

import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import audit_protocol as protocol, audit_worker as worker
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent import cli


def envelope():
    return {'version': '1', 'writer_id': str(uuid4()), 'sequence': 1,
            'event': {'event_type': 'execution_started', 'target': '127.0.0.1'}}


@pytest.mark.parametrize('raw', [b'', b'[]', b'null', b'{"x":1,"x":2}',
                                 b'{"x":{"a":1,"a":2}}', b'{"x":NaN}',
                                 b'{"x":Infinity}', b'\xff', b'{} trailing',
                                 b'x' * (protocol.MAX_PACKET + 1)])
def test_malformed_or_oversized_packet_rejected(raw):
    with pytest.raises((ValueError, UnicodeError)):
        protocol.decode(raw)


@pytest.mark.parametrize('mutation', [{'version': '2'}, {'writer_id': str(uuid4())},
                                    {'sequence': True}, {'sequence': 0}, {'sequence': 2},
                                    {'path': '/tmp/reopen'}, {'operation': 'truncate'},
                                    {'approval_reference': 'forged'}, {'event': []}])
def test_wrong_identity_replay_or_authority_fields_rejected(mutation):
    value = envelope()
    identity = value['writer_id']
    value.update(mutation)
    with pytest.raises(ValueError):
        protocol.request(value, identity, 1)


@pytest.mark.parametrize('event', [None, {}, {'event_type': ''}, {'event_type': True},
                                   {'event_type': 'a' * 81},
                                   {'event_type': 'test', 'raw': 'a' * protocol.MAX_EVENT},
                                   {'event_type': 'test', 'cost': float('nan')},
                                   *({'event_type': 'test', key: 'forged'} for key in protocol.RESERVED)])
def test_producer_cannot_override_envelope_or_exceed_event_bounds(event):
    with pytest.raises(ValueError):
        protocol.event_bytes(event)


def test_receipts_bind_exact_event_sequence_and_writer():
    event = {'event_type': 'policy_decision', 'reasons': ['out_of_scope']}
    raw = protocol.event_bytes(event)
    one = protocol.receipt(str(uuid4()), 1, raw)
    assert one['event_digest'] == __import__('hashlib').sha256(raw).hexdigest()
    assert protocol.receipt(one['writer_id'], 2, raw) != one
    assert protocol.receipt(str(uuid4()), 1, raw) != one
    assert protocol.receipt(one['writer_id'], 1, protocol.event_bytes({**event, 'reasons': []})) != one


@pytest.fixture
def append_file(tmp_path):
    path = tmp_path / 'events.jsonl'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        yield path, fd
    finally:
        os.close(fd)


def test_append_completes_partial_writes_and_fsync_before_return(append_file, monkeypatch):
    path, fd = append_file
    original_write = os.write
    order = []

    def write(descriptor, raw):
        order.append('write')
        return original_write(descriptor, raw[:9])

    def sync(descriptor):
        assert descriptor == fd
        record = json.loads(path.read_text())
        assert record['event_type'] == 'execution_started'
        order.append('fsync')

    monkeypatch.setattr(worker.os, 'write', write)
    monkeypatch.setattr(worker.os, 'fsync', sync)
    worker.append(fd, {'event_type': 'execution_started'})
    assert len(order) > 2 and order[-1] == 'fsync'
    assert set(json.loads(path.read_text())) == protocol.RESERVED | {'event_type'}


@pytest.mark.parametrize('failure', ['fsync', 'zero_write', 'full', 'permissions', 'unlinked'])
def test_durability_failure_never_returns_success(append_file, monkeypatch, failure):
    path, fd = append_file
    if failure == 'fsync':
        monkeypatch.setattr(worker.os, 'fsync', lambda _: (_ for _ in ()).throw(OSError('fixture')))
    elif failure == 'zero_write':
        monkeypatch.setattr(worker.os, 'write', lambda *_: 0)
    elif failure == 'full':
        os.ftruncate(fd, protocol.MAX_FILE_BYTES)
    elif failure == 'permissions':
        path.chmod(0o644)
    else:
        path.unlink()
    with pytest.raises((ValueError, OSError)):
        worker.append(fd, {'event_type': 'execution_started'})


@pytest.mark.parametrize('mode', [os.O_RDONLY, os.O_WRONLY, os.O_RDWR | os.O_APPEND])
def test_worker_requires_write_only_append_descriptor(tmp_path, mode):
    path = tmp_path / 'events.jsonl'
    path.touch(mode=0o600)
    fd = os.open(path, mode)
    try:
        info = os.fstat(fd)
        with pytest.raises(ValueError):
            worker.verify_fd(fd, (info.st_dev, info.st_ino))
    finally:
        os.close(fd)


def test_worker_checks_descriptor_identity_and_private_links(append_file, tmp_path):
    path, fd = append_file
    info = os.fstat(fd)
    worker.verify_fd(fd, (info.st_dev, info.st_ino))
    with pytest.raises(ValueError):
        worker.verify_fd(fd, (info.st_dev, info.st_ino + 1))
    os.link(path, tmp_path / 'alias')
    with pytest.raises(ValueError):
        worker.verify_fd(fd, (info.st_dev, info.st_ino))


@pytest.fixture
def sink_double(tmp_path, monkeypatch):
    calls = []

    def start(self):
        self._supervisor = SimpleNamespace(check=lambda: None)

    monkeypatch.setattr(LinuxAuditSink, '_start', start)
    monkeypatch.setattr(LinuxAuditSink, '_quiet', lambda self: None)
    monkeypatch.setattr(LinuxAuditSink, '_verify_path', lambda self: None)
    monkeypatch.setattr(LinuxAuditSink, '_send', lambda self, raw: calls.append(protocol.decode(raw)))

    def cleanup(self):
        self._closed = True
        calls.append('cleanup')

    monkeypatch.setattr(LinuxAuditSink, '_cleanup', cleanup)
    sink = LinuxAuditSink(tmp_path / 'events.jsonl')

    def reply(self):
        request = calls[-1]
        return protocol.receipt(request['writer_id'], request['sequence'],
                                protocol.event_bytes(request['event']))

    monkeypatch.setattr(LinuxAuditSink, '_reply', reply)
    return sink, calls


def test_host_advances_only_after_matching_durability_receipt(sink_double):
    sink, calls = sink_double
    for sequence in (1, 2):
        sink.emit({'event_type': 'owned_fixture'})
        assert sink._sequence == sequence
        assert calls[-1]['sequence'] == sequence


@pytest.mark.parametrize('mutation', [{'durable': False}, {'durable': 1}, {'sequence': True},
                                    {'sequence': 2}, {'writer_id': str(uuid4())},
                                    {'event_digest': '0' * 64}, {'unexpected': True}])
def test_bad_receipt_permanently_poisoned_without_retry(sink_double, monkeypatch, mutation):
    sink, calls = sink_double
    original = sink._reply

    def reply():
        return {**original(), **mutation}

    monkeypatch.setattr(sink, '_reply', reply)
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'execution_started'})
    assert sink._sequence == 0 and sink._failed and calls[-1] == 'cleanup'
    count = len(calls)
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'execution_started'})
    assert len(calls) == count


@pytest.mark.parametrize('operation', ['_verify_path', '_send', '_reply'])
def test_transport_storage_or_timeout_failure_closes_sink(sink_double, monkeypatch, operation):
    sink, calls = sink_double
    def fail(*args):
        raise TimeoutError('private fixture error')
    monkeypatch.setattr(sink, operation, fail)
    with pytest.raises(AuditUnavailable, match='^audit_unavailable$'):
        sink.emit({'event_type': 'execution_started'})
    assert calls[-1] == 'cleanup' and sink._failed


def test_event_limit_cannot_send_or_restart(sink_double):
    sink, calls = sink_double
    sink._sequence = protocol.MAX_EVENTS
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'execution_started'})
    assert calls == ['cleanup']


@pytest.mark.parametrize('args', [[], ['--mock'], ['--session-mock', 'three_step'],
                                ['--inspect-assessment', '/not-used'],
                                ['--inspect-evaluation', '/not-used'],
                                ['--evaluate-owned-lab', '--evaluation-dir', '/not-used']])
def test_cli_rejects_unsupported_audit_modes_before_opening(args, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([*args, '--isolated-audit'])
    assert exc.value.code == 2
    assert '--isolated-audit requires' in capsys.readouterr().err


def test_cli_missing_isolation_never_falls_back(tmp_path, monkeypatch, capsys):
    def unavailable(self):
        raise RuntimeError('owned fixture isolation unavailable')
    monkeypatch.setattr(LinuxAuditSink, '_start', unavailable)
    monkeypatch.setattr(cli, 'AuditSink', lambda *_: pytest.fail('host fallback'))
    path = tmp_path / 'events.jsonl'
    assert cli.main(['--control-plane-mock', 'three_step', '--isolated-audit',
                     '--audit', str(path)]) == 3
    assert json.loads(capsys.readouterr().out)['execution_status'] == 'audit_error'
    assert not path.exists()
