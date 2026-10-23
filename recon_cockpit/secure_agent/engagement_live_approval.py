"""Trusted host client for one fixed isolated engagement review surface."""

import hashlib
from contextlib import contextmanager
import math
import os
from pathlib import Path
import select
import socket
import stat
import threading
import time

from . import engagement_live_contract as contract
from . import engagement_live_protocol as protocol
from .execution import ExecutionControl
from .models import parse_policy


class _ControlClip:
    def __init__(self, original, deadline, stop):
        self.original, self.deadline, self._stop = original, deadline, stop
        self.cancelled, self.clock = original.cancelled, original.clock

    def remaining(self):
        if self._stop is not None and self._stop.is_set():
            contract.fail('cancelled')
        self.original.check()
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            contract.fail('timeout')
        return remaining

    def check(self):
        self.remaining()


def _clipped_control(original, deadline_ns, stop=None):
    deadline = min(original.deadline, deadline_ns / contract.SECOND)
    if int(deadline * contract.SECOND) > deadline_ns:
        deadline = math.nextafter(deadline, -math.inf)
    return _ControlClip(original, deadline, stop)


@contextmanager
def _bounded_lock(lock, control):
    acquired = False
    try:
        while not acquired:
            acquired = lock.acquire(timeout=min(0.05, control.remaining()))
        control.check()
        yield
    finally:
        if acquired:
            lock.release()


class EngagementApprovalService:
    """Construction is inert; channel custody transfers once at start.

    A blocked review is interruptible by shutdown before acquiring its RPC lock.
    No reset, reconnect, saved-grant import or affirmative host operation exists.
    """

    def __init__(self, policy, session_id, *, frontend, session_binding,
                 runtime_manifest, witness_slot, control, host_evidence_budget=None,
                 cleanup_epoch=None, failure_sink=None):
        from .engagement_live_session import _HostEvidenceBudget

        if frontend not in {'terminal', 'graphical_v1'} or type(frontend) is not str:
            contract.fail('invalid_input')
        if type(control) is not ExecutionControl or control.clock is not time.monotonic:
            contract.fail('invalid_input')
        self._opened = contract.validate_session_opened(session_binding)
        binding = self._opened['binding']
        self._policy = parse_policy(policy.to_dict())
        if (contract.uuid(session_id) != binding['session_id'] or frontend != binding['review_mode']
                or self._policy.to_dict() != self._opened['policy']):
            contract.fail('invalid_prepared')
        from .engagement_live_runtime import validate_runtime, runtime_digest
        self._runtime = validate_runtime(runtime_manifest)
        if runtime_digest(self._runtime) != binding['runtime_sha256']:
            contract.fail('invalid_runtime')
        self._binding, self._frontend = binding, frontend
        self._role = 'terminal' if frontend == 'terminal' else 'graphical'
        self._slot, self._control = witness_slot, control
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._closed = False
        self._owner = self._channel = self._ready = None
        self._cleanup_receipt = None
        self._startup_observation = None
        self._sequence = protocol.ChannelSequence(binding['reviewer_id'], self._role)
        self._observations = []
        self._host_evidence_budget = (_HostEvidenceBudget() if host_evidence_budget is None
                                      else host_evidence_budget)
        if type(self._host_evidence_budget) is not _HostEvidenceBudget:
            contract.fail('invalid_input')
        self._host_evidence_budget._check()
        self._cleanup_epoch, self._failure_sink = cleanup_epoch, failure_sink

    def _check_owner(self):
        if self._pid != os.getpid():
            contract.fail('foreign_owner')

    def _check(self):
        self._check_owner()
        if self._closed or self._stop.is_set():
            contract.fail('approval_unavailable')
        self._control.check()

    @property
    def readiness(self):
        self._check_owner()
        return None if self._ready is None else contract.detached(self._ready, 16384)

    def _start(self, *, control=None):
        phase = control if control is not None else _clipped_control(self._control,
            min(self._binding['session_deadline_ns'], self._binding['broker_deadline_ns']), self._stop)
        with contract._deadline_context(phase.deadline):
            phase.check()
            result = self._start_owned(control=phase)
            phase.check()
            return result

    def _start_owned(self, *, control):
        from . import engagement_live_runtime as runtime
        from .engagement_live_broker import RoleSlot

        self._check()
        if self._owner is not None:
            return self.readiness
        if (type(self._slot) is not RoleSlot or self._slot.reviewer_id != self._binding['reviewer_id']
                or self._slot.review_mode != self._frontend):
            contract.fail('invalid_role')
        payload = {'session_binding': self._binding, 'roe': self._opened['roe'],
                   'scope': self._opened['scope'], 'policy': self._opened['policy'],
                   'reviewer_id': self._binding['reviewer_id'], 'review_mode': self._frontend}
        phase = control if control is not None else _clipped_control(self._control,
            min(self._binding['session_deadline_ns'], self._binding['broker_deadline_ns']), self._stop)
        phase.check()
        extra_mounts, environment = [], {}
        owned_fds = []
        peers = None
        try:
            if self._role == 'terminal':
                terminal = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
                owned_fds.append(terminal)
                info = os.fstat(terminal)
                if not stat.S_ISCHR(info.st_mode) or not os.isatty(terminal):
                    contract.fail('approval_unavailable')
                payload['tty_identity'] = [info.st_dev, info.st_ino, info.st_rdev]
            else:
                from . import graphical_approval_isolation as graphical
                from .graphical_approval_protocol import canonical_display

                display = canonical_display(os.environ.get('DISPLAY'))
                socket_path = Path('/tmp/.X11-unix/X' + display[1:].split('.')[0])
                info = socket_path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in {0, os.getuid()}:
                    contract.fail('approval_unavailable')
                source = Path(os.environ['XAUTHORITY']) if os.environ.get('XAUTHORITY') else Path.home() / '.Xauthority'
                cookie = graphical.select_authority(graphical._read_authority(source), display,
                                                     socket.gethostname().encode('utf-8'))
                cookie_fd = graphical._sealed_file('engagement-review-display', cookie)
                owned_fds.append(cookie_fd)
                payload.update(display=display, display_socket=[info.st_dev, info.st_ino],
                               authority_sha256=hashlib.sha256(cookie).hexdigest())
                del cookie
                extra_mounts = [(str(socket_path), str(socket_path)), (cookie_fd, graphical.AUTHORITY_PATH)]
                environment = {'DISPLAY': display, 'XAUTHORITY': graphical.AUTHORITY_PATH,
                    'FONTCONFIG_FILE': graphical.FONTCONFIG_PATH,
                    'TCL_LIBRARY': '/usr/share/tcltk/tcl8.6', 'TK_LIBRARY': '/usr/share/tcltk/tk8.6'}
            peers = self._slot.take_reviewer_bootstrap()
            parent, child = peers.pop('host'), peers.pop('child')
            witness = peers.pop('review_witness')
            witness_fd = witness.detach()
            rights = ({'intentional_tty': terminal, 'review_witness': witness_fd}
                      if self._role == 'terminal' else {'review_witness': witness_fd})
            if self._role == 'terminal':
                owned_fds.remove(terminal)
            self._channel = parent
            # The runtime builder receives all rights/stdin ownership, including
            # failure paths. It closes parent copies after the single transfer.
            self._owner = runtime._start_role(runtime=self._runtime, role=self._role,
                payload=payload, rights=rights, control=phase, stdin_pair=(parent, child),
                extra_mounts=tuple(extra_mounts), environment=environment,
                worker_id=self._binding['reviewer_id'])
            self._channel = self._owner.channel
            self._ready = runtime.validate_readiness(self._role, self._owner.ready, self._runtime,
                expected_binding={'worker_id': self._binding['reviewer_id']})
            self._check()
            return self.readiness
        except BaseException as error:
            receipt = getattr(error, 'startup_cleanup', None)
            if receipt is not None:
                self._cleanup_receipt = receipt
            self._startup_observation = getattr(error, 'startup_observation', None)
            raise
        finally:
            if peers is not None:
                for peer in peers.values():
                    peer.close()
            while owned_fds:
                os.close(owned_fds.pop())

    def start(self):
        self._check_owner()
        phase = _clipped_control(self._control, min(self._binding['session_deadline_ns'],
                                                   self._binding['broker_deadline_ns']), self._stop)
        try:
            with contract._deadline_context(phase.deadline), _bounded_lock(self._lock, phase):
                result = self._start(control=phase)
                phase.check()
                return result
        except BaseException as error:
            if self._failure_sink is not None:
                self._failure_sink(error)
            self.close()
            raise

    def _quiet(self):
        self._owner.pin.check_alive()
        for stream in (self._owner.process.stdout, self._owner.process.stderr):
            try:
                raw = os.read(stream.fileno(), 1)
            except BlockingIOError:
                continue
            # EOF is also terminal while this role is meant to remain alive.
            contract.fail('approval_unavailable')

    def _projection(self, request, reply=None):
        operation = request['operation']
        body = request['body']
        if operation == 'CONSUME':
            body = {'prepared': body['prepared'],
                    'reference_sha256': hashlib.sha256(body['reference'].encode('ascii')).hexdigest()}
        elif operation == 'REVIEW':
            body = {'prepared': body}
        projected_request = body
        projected_reply = None
        if reply is not None:
            data = reply['body']['data']
            if operation == 'REVIEW' and reply['body']['status'] == 'ok':
                data = {'reference_sha256': None if data is None else hashlib.sha256(data.encode('ascii')).hexdigest()}
            projected_reply = data if reply['body']['status'] == 'ok' else reply['body']
        raw_request = protocol.encode_frame(request, role=self._role, direction='request')
        return {'role': self._role, 'channel_id': request['channel_id'], 'operation': operation,
            'request_sequence': request['sequence'], 'request': projected_request,
            'reply': projected_reply,
            'request_projection_sha256': contract.digest(contract.canonical(projected_request)),
            'reply_projection_sha256': None if projected_reply is None else contract.digest(contract.canonical(projected_reply)),
            'original_request_sha256': contract.digest(raw_request), 'original_request_bytes': len(raw_request),
            # receive_packet validates the decoded frame but does not expose raw
            # bytes; this client never mislabels a re-encoding as the original.
            'original_reply_sha256': None, 'original_reply_bytes': None}

    def _exchange(self, operation, prepared, reference, control):
        self._check_owner()
        if control is not self._control:
            contract.fail('invalid_input')
        # Establish the phase at invocation, including time spent waiting for
        # another exchange. Mutex contention cannot renew the caller's budget.
        phase = _clipped_control(self._control, min(
            self._binding['session_deadline_ns'], self._binding['broker_deadline_ns'],
            time.monotonic_ns() + (30 if operation == 'REVIEW' else 2) * contract.SECOND), self._stop)
        observation = ticket = None
        request_retained = False
        def observation_row():
            return {'schema_version': '1', 'broker_id': self._binding['broker_id'],
                'session_id': self._binding['session_id'], 'dispatch_id': observation['dispatch_id'],
                'observer_id': self._binding['reviewer_id'], 'row_sequence': 1,
                'observed_at_ns': observation['observed_at_ns'], 'kind': 'capability_projection',
                'data': observation['projection']}
        try:
            with contract._deadline_context(phase.deadline):
                phase.check()
                prepared = contract.validate_prepared(prepared)
                phase = _clipped_control(self._control, min(int(phase.deadline*contract.SECOND),
                    prepared['envelope']['action_deadline_ns']), self._stop)
                phase.check()
            with contract._deadline_context(phase.deadline), _bounded_lock(self._lock, phase):
                self._check()
                if self._owner is None:
                    if operation == 'CONSUME':
                        contract.fail('approval_unknown_or_replayed')
                    self._start(control=phase)
                if operation == 'REVIEW':
                    prepared = contract.validate_prepared_context(prepared, self._opened)
                body = prepared if operation == 'REVIEW' else {'reference': reference, 'prepared': prepared}
                phase.check()
                self._quiet()
                request = self._sequence.make(operation, body)
                if len(self._observations) >= 34:
                    contract.fail('limit_exceeded')
                observation = {'observed_at_ns': time.monotonic_ns(),
                               'dispatch_id': prepared['envelope']['dispatch_id'],
                               'projection': self._projection(request)}
                initial_row = observation_row()
                # Prepared is already exact; the closed reviewer reply can add
                # only its bounded reference/consume/refusal projection.
                ticket = self._host_evidence_budget.reserve(kind='other_host',
                    maximum_bytes=len(contract.canonical(initial_row)) + 2048 + 3,
                    maximum_rows=1, control=phase)
                self._host_evidence_budget.record_request(ticket, initial_row)
                request_retained = True
                self._observations.append(observation)
                protocol.send_packet(self._channel, request, role=self._role, control=phase)
                reply = self._sequence.accept(protocol.receive_packet(self._channel, role=self._role, control=phase))
                protocol.require_reply(reply, request, role=self._role)
                observation['projection'] = self._projection(request, reply)
                self._host_evidence_budget.finalize(ticket, observation_row())
                ticket = None
                self._check()
                phase.check()
                self._quiet()
                if reply['body']['status'] != 'ok':
                    contract.fail('approval_unavailable')
                return reply['body']['data']
        except BaseException as error:
            if self._failure_sink is not None:
                self._failure_sink(error)
            if observation is not None:
                # This is when the incomplete exchange was actually observed,
                # not a claim that its earlier send already witnessed timeout.
                observation['observed_at_ns'] = time.monotonic_ns()
            try:
                if ticket is not None:
                    if request_retained:
                        self._host_evidence_budget.finalize(ticket, observation_row())
                    else:
                        self._host_evidence_budget.release(ticket)
            except BaseException as evidence_error:
                error.evidence_error = evidence_error
            finally:
                try:
                    self.close()
                except BaseException as cleanup_error:
                    error.cleanup_error = cleanup_error
            raise

    def review(self, action, policy, envelope, *, control):
        prepared = {'schema_version': '1', 'action': action.to_dict(),
                    'policy': policy.to_dict(), 'envelope': envelope}
        return self._exchange('REVIEW', prepared, None, control)

    def consume(self, reference, action, policy, envelope, *, control):
        prepared = {'schema_version': '1', 'action': action.to_dict(),
                    'policy': policy.to_dict(), 'envelope': envelope}
        return self._exchange('CONSUME', prepared, reference, control)

    def _interrupt(self):
        self._check_owner()
        self._stop.set()
        channel = self._channel
        if channel is not None:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _close(self, deadline):
        from . import engagement_live_runtime as runtime

        self._check_owner()
        if self._cleanup_epoch is not None:
            deadline = self._cleanup_epoch.stop(
                bound_deadline_ns=int(deadline*contract.SECOND))['deadline_ns']/contract.SECOND
        self._interrupt()
        if self._cleanup_receipt is not None:
            return self._cleanup_receipt
        acquired = self._lock.acquire(timeout=max(0, deadline - time.monotonic()))
        try:
            self._closed = True
            if not acquired:
                contract.fail('cleanup_incomplete')
            if self._cleanup_receipt is not None:
                return self._cleanup_receipt
            owner = self._owner
            if self._channel is not None:
                self._channel.close()
                self._channel = None
            self._cleanup_receipt = runtime.cleanup_owned(
                [] if owner is None else [owner.process], [] if owner is None else [owner.pin], deadline=deadline)
            if owner is not None:
                owner.cleanup = self._cleanup_receipt
            return self._cleanup_receipt
        finally:
            if acquired:
                self._lock.release()

    def close(self):
        return self._close(time.monotonic() + 2)
