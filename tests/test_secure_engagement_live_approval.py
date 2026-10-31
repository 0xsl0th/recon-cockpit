"""Portable reviewer mechanics; actual isolated views remain separate native gates."""

import array
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import engagement_live_approval as host
from recon_cockpit.secure_agent import engagement_live_approval_view as view
from recon_cockpit.secure_agent import engagement_live_approval_worker as worker
from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent import engagement_live_protocol as protocol
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from test_secure_engagement_live_contract import opened, prepared, clock, uid, roe, M


def state_fixture(monkeypatch):
    selected = opened()
    now = [0]
    monkeypatch.setattr(c, 'sample_clock', lambda: clock(now[0]))
    monkeypatch.setattr(worker.time, 'monotonic_ns', lambda: M + now[0])
    state = worker.GrantState(binding=selected['binding'], roe=selected['roe'],
                              scope=selected['scope'], policy=selected['policy'])
    state._store._clock = lambda: (M + now[0]) / c.SECOND
    return state, prepared(), now


def issue(state, value):
    """Unit-only view outcome; never used by native tests or a live producer."""
    state.begin_review(value)
    return state.issue_reviewed(value)


def service_fixture(monkeypatch, *, budget=60):
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    from recon_cockpit.secure_agent.engagement_live_broker import RoleSlot

    selected = roe()
    now = datetime.now(timezone.utc)
    selected['window'] = {'start_utc': (now - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                          'end_utc': (now + timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ')}
    selected['limits']['max_engagement_ms'] = 180000
    sample = c.sample_clock()
    session = opened(clock_value=sample, roe_value=selected)
    value = c.derive_prepared(session, 'http_identify', dispatch_id=uid(10), clock=sample)
    slot = RoleSlot(None, 0, 'terminal')
    slot.reviewer_id = session['binding']['reviewer_id']
    monkeypatch.setattr(runtime, 'validate_runtime', lambda value: deepcopy(value))
    monkeypatch.setattr(runtime, 'runtime_digest', lambda value: 'a' * 64)
    control = ExecutionControl(time.monotonic() + budget, threading.Event())
    service = host.EngagementApprovalService(parse_policy(session['policy']), session['binding']['session_id'],
        frontend='terminal', session_binding=session, runtime_manifest={'portable_fixture': True},
        witness_slot=slot, control=control)
    return service, value, control


def test_both_review_texts_bind_complete_engagement_and_exact_action(monkeypatch):
    state, value, _ = state_fixture(monkeypatch)
    action, policy, envelope = parse_action(value['action']), state.policy, value['envelope']
    rendered = view.review_text(action, policy, envelope)
    assert json.loads(rendered.split('Complete engagement envelope:\n')[1]) == envelope
    displayed = json.loads(rendered.split('Exact action (fixed rationale omitted):\n')[1]
                           .split('\n\nComplete engagement envelope:')[0])
    assert displayed == {k: v for k, v in value['action'].items() if k != 'rationale'}
    for field in ('engagement_id', 'ledger_owner_id', 'session_id', 'dispatch_id', 'reviewer_id'):
        assert envelope[field] in rendered
    assert '2026-10-21T00:00:00.000000000Z' in rendered
    assert str(envelope['window_start_utc_ns']) in rendered
    assert action.digest in rendered and policy.digest in rendered
    captured = bytearray()
    import termios
    monkeypatch.setattr(termios, 'tcflush', lambda *a: None)
    monkeypatch.setattr(worker, '_terminal_ready', lambda *a, **k: None)
    monkeypatch.setattr(worker.os, 'write', lambda fd, raw: captured.extend(raw) or len(raw))
    monkeypatch.setattr(worker.os, 'read', lambda *a: b'\n')
    monkeypatch.setattr(worker.select, 'select', lambda *a: ([], [], []))
    assert worker.terminal_review(90, 91, action, policy, envelope) is False
    assert rendered.encode('ascii') in captured and b'Action time remaining:' in captured


def test_fresh_challenge_rejects_stale_input_and_enter_only(monkeypatch):
    state, value, _ = state_fixture(monkeypatch)
    action = parse_action(value['action'])
    challenges = {view.fresh_challenge(action) for _ in range(10)}
    assert len(challenges) == 10
    for answer in (b'\n', (next(iter(challenges)) + '\n').encode('ascii')):
        data = iter(bytes([byte]) for byte in answer)
        flushed = []
        import termios
        monkeypatch.setattr(termios, 'tcflush', lambda *a: flushed.append(a))
        monkeypatch.setattr(worker, '_terminal_ready', lambda *a, **k: None)
        monkeypatch.setattr(worker.os, 'write', lambda fd, raw: len(raw))
        monkeypatch.setattr(worker.os, 'read', lambda *a: next(data))
        monkeypatch.setattr(worker.select, 'select', lambda *a: ([], [], []))
        assert not worker.terminal_review(90, 91, action, state.policy, value['envelope'])
        assert len(flushed) == 1


def test_reference_cannot_move_between_revision_session_or_action(monkeypatch):
    for key, replacement in [('revision', 2), ('session_id', uid(90)), ('ledger_owner_id', uid(91))]:
        state, value, _ = state_fixture(monkeypatch)
        reference = issue(state, value)
        wrong = deepcopy(value)
        wrong['envelope'][key] = replacement
        result, witness = state.consume(reference, wrong)
        assert not result['accepted'] and witness is None
    state, value, _ = state_fixture(monkeypatch)
    reference = issue(state, value)
    assert state.consume(reference, prepared('http_headers'))[0]['accepted'] is False


def test_mismatched_consume_burns_reference_before_refusal(monkeypatch):
    state, value, _ = state_fixture(monkeypatch)
    reference = issue(state, value)
    wrong = deepcopy(value)
    wrong['envelope']['dispatch_id'] = uid(92)
    assert state.consume(reference, wrong)[0]['accepted'] is False
    assert reference not in state._bindings and reference not in state._store._grants
    replay, raw = state.consume(reference, value)
    assert replay == {'accepted': False, 'consume_sequence': 2,
        'reference_sha256': hashlib.sha256(reference.encode('ascii')).hexdigest(), 'witness_sha256': None}
    assert raw is None


def test_expired_and_replayed_grants_emit_no_witness(monkeypatch):
    state, value, now = state_fixture(monkeypatch)
    reference = issue(state, value)
    now[0] = 30 * c.SECOND
    assert state.consume(reference, value)[1] is None
    now[0] = 0  # A subsequent test clock cannot restore a burned capability.
    assert state.consume(reference, value)[1] is None
    state, value, now = state_fixture(monkeypatch)
    reference = issue(state, value)
    assert state.consume(reference, value)[0]['accepted'] is True
    assert state.consume(reference, value)[1] is None


def test_direct_witness_binds_complete_context_and_consume_sequence(monkeypatch):
    state, value, _ = state_fixture(monkeypatch)
    state.deadline_ns = M + 2*c.SECOND
    reference = issue(state, value)
    assert state.consume('f' * 48, value)[1] is None
    result, raw = state.consume(reference, value)
    proof = c.decode(raw, max_bytes=4096)
    assert proof['consume_sequence'] == result['consume_sequence'] == 2
    assert proof['envelope_sha256'] == c.envelope_digest(value['envelope'])
    assert proof['action_sha256'] == parse_action(value['action']).digest
    assert proof['policy_sha256'] == state.policy.digest
    assert proof['reference_sha256'] == result['reference_sha256']
    assert proof['issued_at_ns'] < proof['expires_at_ns'] <= value['envelope']['action_deadline_ns']
    assert proof['expires_at_ns'] <= state.deadline_ns
    assert result['witness_sha256'] == hashlib.sha256(raw).hexdigest()
    assert reference.encode('ascii') not in raw


def test_worker_refuses_forged_out_of_order_or_oversized_packets(monkeypatch):
    sequence = protocol.ChannelSequence(uid(5), 'terminal')
    request = {'schema_version': '1', 'channel_id': uid(5), 'sequence': 1,
               'operation': 'REVIEW', 'body': prepared()}
    assert sequence.accept(request) == request
    for change in ({}, {'sequence': 3}, {'channel_id': uid(99)}, {'operation': 'APPROVE'},
                   {'body': {'approved': True}}):
        with pytest.raises(c.LiveError):
            sequence.accept({**request, **change})
    with pytest.raises(c.LiveError):
        protocol.decode_frame(b' ' * 32769, role='terminal', direction='request')
    assert sequence.received == 1

    # Start a fresh copy of the real worker with a cold protocol cache. The
    # portable seal double denies module-file reads after sealing, matching the
    # actual terminal refusal without installing a process-wide syscall filter.
    import importlib.machinery
    from pathlib import Path
    import sys
    from types import ModuleType
    import recon_cockpit.secure_agent as package
    from recon_cockpit.secure_agent import approval_worker as terminal
    from recon_cockpit.secure_agent import graphical_approval_worker as graphical
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime

    source = Path(worker.__file__).read_text()
    protocol_name = package.__name__ + '.engagement_live_protocol'
    original_protocol = sys.modules[protocol_name]
    original_get_data = importlib.machinery.SourceFileLoader.get_data
    for role in ('terminal', 'graphical'):
        with monkeypatch.context() as patch:
            # This is a declared peer double; portable hosts need not implement
            # Linux SEQPACKET sockets, and no socket is constructed by this path.
            patch.setattr(socket, 'SOCK_SEQPACKET', getattr(socket, 'SOCK_SEQPACKET', 5), raising=False)
            session = opened('terminal' if role == 'terminal' else 'graphical_v1')
            binding = session['binding']
            events, denied, replies, closed, diagnostics = [], [], [], [], []
            sealed = [False]
            def get_data(loader, path):
                if sealed[0]:
                    denied.append(path)
                    raise PermissionError(1, 'module reads denied after seal', path)
                if loader.name == protocol_name:
                    events.append('protocol_load')
                return original_get_data(loader, path)
            patch.setattr(importlib.machinery.SourceFileLoader, 'get_data', get_data)
            patch.delitem(sys.modules, protocol_name)
            patch.delattr(package, 'engagement_live_protocol')
            fresh = ModuleType(package.__name__ + '._portable_reviewer')
            fresh.__package__ = package.__name__
            exec(compile(source, worker.__file__, 'exec'), fresh.__dict__)

            class Peer:
                family, type = socket.AF_UNIX, socket.SOCK_SEQPACKET
                def fileno(self): return 99
                def setblocking(self, value): pass
                def recv(self, *args): return b''
                def close(self): closed.append('peer')
            class Window:
                def __init__(self): self._root = SimpleNamespace(winfo_screen=lambda: ':99.0')
                def warmup(self): pass
                def close(self): closed.append('window')

            payload = {'session_binding': binding, 'roe': session['roe'],
                'scope': session['scope'], 'policy': session['policy'],
                'reviewer_id': binding['reviewer_id'], 'review_mode': binding['review_mode']}
            if role == 'terminal': payload['tty_identity'] = [1, 2, 3]
            else: payload.update(display=':99.0', display_socket=[1, 2],
                                 authority_sha256=hashlib.sha256(b'cookie').hexdigest())
            initial = {'observer': {}, 'payload': payload, 'runtime_sha256': binding['runtime_sha256'],
                       'deadline_ns': binding['session_deadline_ns']}
            rights = {'review_witness': 98, **({'intentional_tty': 97} if role == 'terminal' else {})}
            patch.setattr(fresh, 'socket', SimpleNamespace(AF_UNIX=socket.AF_UNIX,
                SOCK_SEQPACKET=socket.SOCK_SEQPACKET, MSG_DONTWAIT=socket.MSG_DONTWAIT,
                socket=lambda **kwargs: Peer()))
            patch.setattr(fresh, 'sys', SimpleNamespace(argv=['worker', binding['reviewer_id'], 'b'*64]))
            patch.setattr(fresh, 'os', SimpleNamespace(environ={'DISPLAY': ':99.0'},
                close=lambda fd: closed.append(fd),
                write=lambda fd, raw: diagnostics.append(repr(sys.exception())) or len(raw)))
            patch.setattr(fresh, 'time', SimpleNamespace(monotonic_ns=lambda: M, monotonic=lambda: M/c.SECOND))
            patch.setattr(c, 'sample_clock', lambda: clock())
            patch.setattr(runtime, '_read_file', lambda path, limit:
                c.canonical({'role': role}) if path == runtime.MANIFEST_PATH else b'cookie')
            patch.setattr(runtime, '_receive_initial', lambda *a, **kw: (initial, {}, rights, Peer()))
            patch.setattr(runtime, 'check_role_entry', lambda **kw: {})
            patch.setattr(runtime, 'bootstrap_role', lambda **kw: {'boundary_checks': {}})
            patch.setattr(runtime, '_emit_ready', lambda value: events.append('ready'))
            patch.setattr(terminal, 'verify_terminal', lambda *a: None)
            patch.setattr(graphical, 'verify_display', lambda *a: None)
            patch.setattr(view, 'ReviewWindow', Window)

            def seal(*args):
                events.append('seal')
                sealed[0] = True
                loaded = sys.modules.get(protocol_name)
                if loaded is not None:
                    def receive(*args, **kwargs):
                        events.append('receive')
                        kwargs['control'].check()
                        return {'schema_version': '1', 'channel_id': binding['reviewer_id'],
                                'sequence': 1, 'operation': 'CLOSE', 'body': None}
                    patch.setattr(loaded, 'receive_packet', receive)
                    patch.setattr(loaded, 'send_packet', lambda channel, frame, **kw: replies.append(frame))
            patch.setattr(terminal, 'seal', seal)
            patch.setattr(graphical, 'seal', seal)
            assert fresh.main() == 0, (role, events, denied, diagnostics)
            assert not denied
            assert events.index('protocol_load') < events.index('seal') < events.index('ready') < events.index('receive')
            assert len(replies) == 1 and replies[0]['operation'] == 'CLOSE'
            assert replies[0]['body']['data']['role'] == role and closed
        assert sys.modules[protocol_name] is original_protocol
        assert package.engagement_live_protocol is original_protocol


def test_unexpected_ancillary_descriptors_are_closed(monkeypatch):
    read, write = os.pipe()
    class Packet:
        def recvmsg(self, *a):
            return b'{}', [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [read]).tobytes())], 0, None
    monkeypatch.setattr(protocol, '_ready', lambda *a, **k: None)
    try:
        with pytest.raises(c.LiveError):
            protocol.receive_packet(Packet(), role='terminal', control=ExecutionControl(time.monotonic() + 1))
        with pytest.raises(OSError):
            os.fstat(read)
    finally:
        os.close(write)


def test_service_is_inert_and_frontend_is_fixed(monkeypatch):
    service, value, control = service_fixture(monkeypatch)
    assert service._owner is service._channel is service.readiness is None
    assert service._control is control and service._frontend == 'terminal'
    for frontend in ('automatic', 'graphical', True, None):
        with pytest.raises(c.LiveError):
            host.EngagementApprovalService(parse_policy(service._opened['policy']),
                service._binding['session_id'], frontend=frontend,
                session_binding=service._opened, runtime_manifest=service._runtime,
                witness_slot=service._slot, control=control)


def test_changed_reply_closes_service_without_reconnect(monkeypatch):
    service, value, control = service_fixture(monkeypatch)
    service._owner = object()
    monkeypatch.setattr(service, '_quiet', lambda: None)
    sent, closed = [], []
    monkeypatch.setattr(protocol, 'send_packet', lambda channel, packet, **kw: sent.append(packet))
    monkeypatch.setattr(protocol, 'receive_packet', lambda *a, **kw: {
        'schema_version': '1', 'channel_id': uid(99), 'sequence': 1, 'operation': 'REVIEW',
        'body': {'request_sequence': 1, 'status': 'ok', 'code': None, 'data': None}})
    def close():
        closed.append(True)
        service._closed = True
    monkeypatch.setattr(service, 'close', close)
    for _ in range(2):
        with pytest.raises(c.LiveError):
            service.review(parse_action(value['action']), parse_policy(value['policy']),
                           value['envelope'], control=control)
    assert len(sent) == 1 and len(closed) == 2
    assert service._observations[0]['projection']['reply'] is None


def test_original_deadline_bounds_review_consume_and_output(monkeypatch):
    service, value, original = service_fixture(monkeypatch)
    replacement = ExecutionControl(original.deadline, original.cancelled)
    for operation in ('REVIEW', 'CONSUME'):
        with pytest.raises(c.LiveError, match='invalid_input'):
            service._exchange(operation, value, 'a'*48, replacement)
    stop = threading.Event()
    clipped = host._clipped_control(original, int((original.deadline - 5)*c.SECOND), stop)
    assert clipped.original is original and clipped.cancelled is original.cancelled
    assert clipped.deadline < original.deadline
    stop.set()
    with pytest.raises(c.LiveError, match='cancelled'):
        clipped.check()
    stop.clear()
    original.cancelled.set()
    with pytest.raises(Exception, match='session_cancelled'):
        clipped.check()
    # Contention is part of the original deadline, including a first start.
    for operation in ('START', 'REVIEW', 'CONSUME'):
        service, value, original = service_fixture(monkeypatch, budget=0.04)
        sent = []
        monkeypatch.setattr(protocol, 'send_packet', lambda *a, **kw: sent.append(a))
        service._lock.acquire()
        released = threading.Event()
        def release():
            time.sleep(0.12)
            service._lock.release()
            released.set()
        holder = threading.Thread(target=release)
        holder.start()
        began = time.monotonic()
        try:
            with pytest.raises(Exception, match='session_timeout|timeout') as failure:
                if operation == 'START':
                    service.start()
                else:
                    service._exchange(operation, value, 'a'*48, original)
            assert failure.value.cleanup_error.code == 'engagement_live_cleanup_incomplete'
            assert time.monotonic() - began < 0.5
            assert not sent and service._owner is None and not service._observations
            assert service._stop.is_set()
        finally:
            holder.join(timeout=1)
        assert released.is_set()

    # The invocation clock starts before validating Prepared. Advancing that
    # validation cannot give CONSUME a fresh two seconds or reach transport.
    service, value, _ = service_fixture(monkeypatch)
    tick = [time.monotonic()]
    original = ExecutionControl(tick[0]+60, clock=lambda:tick[0])
    service._control = original
    sent, closed = [], []
    service._owner = object()
    with monkeypatch.context() as patch:
        patch.setattr(host.time,'monotonic',lambda:tick[0])
        patch.setattr(host.time,'monotonic_ns',lambda:int(tick[0]*c.SECOND))
        def slow_validation(value):
            tick[0] += 2.1
            return deepcopy(value)
        patch.setattr(c,'validate_prepared',slow_validation)
        patch.setattr(service,'_quiet',lambda:None)
        patch.setattr(service,'close',lambda:closed.append(True))
        patch.setattr(protocol,'send_packet',lambda *a,**kw:sent.append(a))
        with pytest.raises(c.LiveError,match='timeout'):
            service._exchange('CONSUME',value,'a'*48,original)
    assert not sent and closed == [True] and not service._observations

    # Cached readiness still consumes the narrower startup phase through its
    # final detachment; returning an already-started role cannot renew time.
    service, _, _ = service_fixture(monkeypatch)
    tick = [time.monotonic()]
    service._control = ExecutionControl(tick[0]+60, clock=lambda:tick[0])
    service._binding['session_deadline_ns'] = int((tick[0]+.5)*c.SECOND)
    service._owner, service._ready = object(), {'portable_fixture':True}
    closed = []
    with monkeypatch.context() as patch:
        patch.setattr(host.time,'monotonic',lambda:tick[0])
        def late_readiness(value, *args):
            tick[0] += 1
            return deepcopy(value)
        patch.setattr(c,'detached',late_readiness)
        patch.setattr(service,'close',lambda:closed.append(True))
        with pytest.raises(c.LiveError,match='timeout'):
            service.start()
    assert closed == [True]


def test_peer_eof_and_denial_issue_no_grant(monkeypatch):
    state, value, _ = state_fixture(monkeypatch)
    import termios
    monkeypatch.setattr(termios, 'tcflush', lambda *a: None)
    monkeypatch.setattr(worker, '_terminal_ready', lambda *a, **k: None)
    monkeypatch.setattr(worker.os, 'write', lambda fd, raw: len(raw))
    monkeypatch.setattr(worker.os, 'read', lambda *a: b'')
    with pytest.raises(c.LiveError, match='approval_unavailable'):
        worker.terminal_review(90, 91, parse_action(value['action']), state.policy, value['envelope'])
    assert not state._store._grants and not state._bindings
    # A vanished RPC peer also prevents the next terminal operation.
    monkeypatch.undo()
    state, value, _ = state_fixture(monkeypatch)
    monkeypatch.setattr(worker.time, 'monotonic', lambda: M / c.SECOND)
    monkeypatch.setattr(worker.select, 'select', lambda *a: ([91], [], []))
    with pytest.raises(c.LiveError, match='approval_unavailable'):
        worker._terminal_ready(90, 91, value['envelope'])
    assert not state._store._grants


def test_witness_custody_is_single_transfer_and_sealed(tmp_path,monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_broker as broker
    import fcntl
    # Portable custody uses real POSIX descriptors with explicitly modeled
    # allocation. Linux seqpacket/memfd sealing is a separate native gate.
    def pair():
        peers=socket.socketpair()
        for peer in peers:
            peer.setblocking(False);peer.set_inheritable(False)
        return peers
    def export_pair(name):
        path=tmp_path/name
        writer=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
        try:reader=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
        except BaseException:
            os.close(writer)
            raise
        return reader,writer
    monkeypatch.setattr(broker,'_pair',pair)
    def one_way():
        from test_secure_engagement_live_runtime import portable_halfclose
        reader,writer=pair();portable_halfclose(reader,writer);return reader,writer
    monkeypatch.setattr(broker,'_one_way',one_way)
    original_identity=broker._pair_identity
    def identity(peer):
        from test_secure_engagement_live_runtime import portable_socket_identity
        return portable_socket_identity(original_identity(peer),peer.fileno())
    monkeypatch.setattr(broker,'_pair_identity',identity)
    monkeypatch.setattr(broker,'_memfd',export_pair)
    bundle = broker.preallocate_role_bundle('terminal')
    rights = bundle.slots[0].take_reviewer_bootstrap()
    try:
        assert set(rights) == {'host', 'child', 'review_witness'}
        with pytest.raises(c.LiveError):
            bundle.slots[0].take_reviewer_bootstrap()
        assert rights['review_witness'].recv(1) == b''
        for descriptor in bundle.evidence_readers.values():
            assert fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            with pytest.raises(OSError):
                os.write(descriptor, b'forged')
    finally:
        for peer in rights.values():
            peer.close()
        bundle.close()


def test_terminal_or_display_identity_change_refuses_before_review(monkeypatch):
    service, value, control = service_fixture(monkeypatch)
    read, write = os.pipe()
    original_open = host.os.open
    monkeypatch.setattr(host.os, 'open', lambda path, flags, *a, **kw:
                        read if path == '/dev/tty' else original_open(path, flags, *a, **kw))
    try:
        with pytest.raises(c.LiveError, match='approval_unavailable'):
            service._start()
        assert service._owner is None and not service._observations
        with pytest.raises(OSError):
            os.fstat(read)
    finally:
        os.close(write)
    # A changed reviewer identity cannot even take its preallocated channel.
    service._slot.reviewer_id = uid(99)
    with pytest.raises(c.LiveError, match='invalid_role'):
        service._start()


def test_inherited_service_refuses_before_lock_or_channel_use(monkeypatch):
    service, value, control = service_fixture(monkeypatch)
    class ForbiddenLock:
        def __enter__(self):
            pytest.fail('foreign owner reached RPC lock')
        def acquire(self, **kw):
            pytest.fail('foreign owner reached cleanup lock')
    service._lock = ForbiddenLock()
    service._pid += 1
    for call in (service.start, service.close, lambda: service.readiness,
                 lambda: service._exchange('REVIEW', value, None, control)):
        with pytest.raises(c.LiveError, match='foreign_owner'):
            call()


def test_runtime_failure_cannot_fallback_or_leave_live_review(monkeypatch, tmp_path):
    service, value, control = service_fixture(monkeypatch)
    starts, closes = [], []
    def failed_start(*, control):
        assert control.original is service._control
        assert control.deadline <= value['envelope']['action_deadline_ns']/c.SECOND
        starts.append(True)
        raise c.LiveError('engagement_live_unsupported_runtime')
    def close():
        closes.append(True)
        service._closed = True
    monkeypatch.setattr(service, '_start', failed_start)
    monkeypatch.setattr(service, 'close', close)
    with pytest.raises(c.LiveError, match='unsupported_runtime'):
        service.review(parse_action(value['action']), parse_policy(value['policy']),
                       value['envelope'], control=control)
    with pytest.raises(c.LiveError, match='approval_unavailable'):
        service.review(parse_action(value['action']), parse_policy(value['policy']),
                       value['envelope'], control=control)
    assert starts == [True] and len(closes) == 2
    assert not service._observations

    # Both explicit startup and first-review startup carry the session's first
    # stop through the actual phase wrapper. A later failure cannot buy two
    # more seconds, and simply constructing/checking a phase never stops work.
    from recon_cockpit.secure_agent.engagement_live_session import _CleanupEpoch
    for operation in ('START', 'REVIEW'):
        service, value, _ = service_fixture(monkeypatch)
        tick = [time.monotonic()]
        original = ExecutionControl(tick[0]+60, clock=lambda:tick[0])
        service._control = original
        service._cleanup_epoch = epoch = _CleanupEpoch(original)
        seen = []
        with monkeypatch.context() as patch:
            patch.setattr(host.time, 'monotonic', lambda:tick[0])
            patch.setattr(host.time, 'monotonic_ns', lambda:int(tick[0]*c.SECOND))
            def startup_failure(*, control):
                control.check()
                assert epoch.snapshot() is None
                first = epoch.stop()
                tick[0] += 1
                end = control.cleanup_deadline
                assert int(end*c.SECOND) <= first['deadline_ns']
                assert first['deadline_ns']-int(end*c.SECOND) <= 1
                assert epoch.snapshot() == first
                seen.append(end)
                raise c.LiveError('engagement_live_unsupported_runtime')
            patch.setattr(service, '_start_owned', startup_failure)
            patch.setattr(service, 'close', lambda:None)
            with pytest.raises(c.LiveError, match='unsupported_runtime'):
                if operation == 'START': service.start()
                else: service._exchange('REVIEW', value, None, original)
        assert len(seen) == 1 and not service._observations

    # Process reaping still runs after a channel-close failure. A timing-only
    # process failure retains its observed closed descriptors; only a separate
    # resource-close failure makes combined descriptor custody incomplete.
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    for broken_channel, late_process in ((True, False), (False, True), (True, True)):
        service, _, _ = service_fixture(monkeypatch)
        service._cleanup_epoch = _CleanupEpoch(service._control)
        owner = service._owner = SimpleNamespace(process=object(), pin=object(), cleanup=None)
        events = []
        resource_error = OSError('modeled reviewer channel close failure')
        def channel_close():
            events.append('channel_close')
            if broken_channel: raise resource_error
        service._channel = SimpleNamespace(shutdown=lambda how:events.append('interrupt'), close=channel_close)
        now = time.monotonic_ns()
        actual = {'schema_version':'1', 'started_at_ns':now, 'finished_at_ns':now,
                  'deadline_ns':now+c.SECOND, 'status':'failed' if late_process else 'complete',
                  'processes':[{'portable_process_observation':True}], 'descriptors_closed':True}
        process_error = c.LiveError('engagement_live_cleanup_incomplete')
        process_error.cleanup = actual
        def reap(processes, pins, *, deadline):
            assert processes == [owner.process] and pins == [owner.pin]
            assert int(deadline*c.SECOND) <= service._cleanup_epoch.snapshot()['deadline_ns']
            events.append('reap')
            if late_process: raise process_error
            return actual
        with monkeypatch.context() as patch:
            patch.setattr(runtime, 'cleanup_owned', reap)
            with pytest.raises(c.LiveError, match='cleanup_incomplete') as caught:
                service.close()
            assert events == ['interrupt', 'channel_close', 'reap']
            receipt = service._cleanup_receipt
            assert owner.cleanup is receipt and receipt['status'] == 'failed'
            assert receipt['processes'] == actual['processes'] and actual['descriptors_closed'] is True
            if broken_channel:
                assert receipt['descriptors_closed'] is False
                assert caught.value.resource_cleanup_error is resource_error
                assert caught.value.process_cleanup is actual
            else:
                assert receipt is actual and caught.value is process_error
                assert receipt['descriptors_closed'] is True
            assert service.close() is receipt
            assert events.count('reap') == 1
            if broken_channel:
                from engagement_live_native import _save_case_failure
                directory = tmp_path/str(late_process)
                directory.mkdir(mode=0o700)
                _save_case_failure(directory, 'core', 'portable_cleanup_retention', caught.value)
                saved = json.loads((directory/'case-failure.json').read_bytes())
                assert saved['capture_complete'] is True and saved['acceptance'] is False
                observations = {row['attribute']:row['value'] for row in saved['observations']
                                if row['owner'] == 'exception:0'}
                assert observations['cleanup'] == receipt
                assert observations['process_cleanup'] == actual
