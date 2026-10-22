"""Fixed isolated engagement reviewer with volatile, one-use exact-context grants."""

import errno
import os
import stat
import sys


def _entry_only_stdio():
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd <= 2:
            continue
        try:
            os.fstat(fd)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        raise ValueError('engagement_live_inherited_descriptor')
    for fd in (1, 2):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd):
            raise ValueError('engagement_live_invalid_output')
    try:
        fd = os.open('/dev/tty', os.O_RDWR)
    except OSError as error:
        if error.errno not in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
            raise
    else:
        os.close(fd)
        raise ValueError('engagement_live_ambient_terminal')


if __name__ == '__main__':
    try:
        _entry_only_stdio()
    except Exception:
        os.write(2, b'engagement_live_approval_refused\n')
        raise SystemExit(78) from None
    sys.path.insert(0, '/app')
    __package__ = 'recon_cockpit.secure_agent'

import hashlib
import re
import select
import socket
import time

from . import engagement_live_contract as contract
from .approvals import ApprovalStore
from .engagement_live_approval_view import check_review_time, fresh_challenge, review_text
from .models import parse_action, parse_policy


def _reference(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{48}', value) is None:
        contract.fail('invalid_frame')
    return hashlib.sha256(value.encode('ascii')).hexdigest()


class GrantState:
    """Worker-local state. Only actual view acceptance invokes issue_reviewed."""

    def __init__(self, *, binding, roe, scope, policy, deadline_ns=None):
        self.context = contract.validate_role_context(binding=binding, roe=roe,
                                                      scope=scope, policy=policy)
        self.binding = self.context['binding']
        maximum = min(self.binding['session_deadline_ns'], self.binding['broker_deadline_ns'])
        self.deadline_ns = maximum if deadline_ns is None else contract.integer(deadline_ns, 1, maximum)
        self.policy = parse_policy(self.context['policy'])
        self._store = ApprovalStore()
        self._bindings = {}
        self.consume_sequence = 0
        self.reviews = 0

    def validate_context(self, prepared):
        return contract.validate_prepared_role_context(prepared, **self.context)

    def begin_review(self, prepared):
        prepared = self.validate_context(prepared)
        self.reviews += 1
        if self.reviews > 2:
            contract.fail('limit_exceeded')
        check_review_time(prepared['envelope'])
        return prepared

    def issue_reviewed(self, prepared):
        prepared = self.validate_context(prepared)
        stop = check_review_time(prepared['envelope'])
        grant = self._store.issue(parse_action(prepared['action']), self.policy)
        numerator, denominator = grant.expires_at.as_integer_ratio()
        expiry = min(numerator * contract.SECOND // denominator, stop,
                     self.deadline_ns,
                     prepared['envelope']['action_deadline_ns'],
                     self.binding['session_deadline_ns'], self.binding['broker_deadline_ns'])
        if expiry <= time.monotonic_ns():
            self._store.consume(grant.reference, parse_action(prepared['action']), self.policy)
            contract.fail('timeout')
        self._bindings[grant.reference] = (contract.prepared_digest(prepared), expiry)
        return grant.reference

    def consume(self, reference, prepared):
        reference_sha256 = _reference(reference)
        self.consume_sequence += 1
        if self.consume_sequence > 32:
            contract.fail('limit_exceeded')
        # Burn both records before any cross-context or expiry decision. A valid
        # but mismatched Prepared can never leave an old reference reusable.
        binding = self._bindings.pop(reference, None)
        action = parse_action(prepared['action'])
        policy = parse_policy(prepared['policy'])
        failure, grant = self._store.consume_with_grant(reference, action, policy)
        result = {'accepted': False, 'consume_sequence': self.consume_sequence,
                  'reference_sha256': reference_sha256, 'witness_sha256': None}
        if failure is not None or binding is None or grant is None:
            return result, None
        try:
            prepared = self.validate_context(prepared)
            stop = check_review_time(prepared['envelope'])
            if binding[0] != contract.prepared_digest(prepared):
                return result, None
            issued = time.monotonic_ns()
            expires = min(binding[1], stop)
            if issued >= expires:
                return result, None
        except contract.LiveError:
            return result, None
        envelope = prepared['envelope']
        witness = {
            'schema_version': '1', 'reviewer_id': envelope['reviewer_id'],
            'broker_id': envelope['broker_id'], 'ledger_owner_id': envelope['ledger_owner_id'],
            'session_id': envelope['session_id'], 'dispatch_id': envelope['dispatch_id'],
            'consume_sequence': self.consume_sequence, 'reference_sha256': reference_sha256,
            'envelope_sha256': contract.envelope_digest(envelope),
            'action_sha256': action.digest, 'policy_sha256': policy.digest,
            'issued_at_ns': issued, 'expires_at_ns': expires, 'accepted': True,
        }
        raw = contract.canonical(witness, max_bytes=4096)
        result.update(accepted=True, witness_sha256=hashlib.sha256(raw).hexdigest())
        return result, raw


def _terminal_ready(fd, peer_fd, envelope, *, writing=False, deadline_ns=None):
    check_review_time(envelope)
    stop_ns = min(envelope['action_deadline_ns'], envelope['session_deadline_ns'],
                  envelope['broker_deadline_ns'])
    if deadline_ns is not None:
        stop_ns = min(stop_ns, deadline_ns)
    stop = stop_ns / contract.SECOND
    while True:
        remaining = min(.05, stop - time.monotonic())
        if remaining <= 0:
            contract.fail('timeout')
        readable, writable, _ = select.select([peer_fd] if writing else [peer_fd, fd],
                                               [fd] if writing else [], [], remaining)
        if peer_fd in readable:
            contract.fail('approval_unavailable')
        check_review_time(envelope)
        if fd in (writable if writing else readable):
            return


def terminal_review(fd, peer_fd, action, policy, envelope, *, deadline_ns=None):
    """Fresh literal prompt; peer activity, stale input and Enter alone deny."""
    import termios
    check_review_time(envelope)
    termios.tcflush(fd, termios.TCIFLUSH)
    challenge = fresh_challenge(action)
    prompt = (review_text(action, policy, envelope) + '\nAction time remaining: '
              + str(max(0, (envelope['action_deadline_ns'] - time.monotonic_ns()) // contract.SECOND))
              + " seconds\nType '" + challenge + "' to approve once (blank denies): ").encode('ascii')
    if len(prompt) > 16384:
        contract.fail('limit_exceeded')
    offset = 0
    while offset < len(prompt):
        _terminal_ready(fd, peer_fd, envelope, writing=True, deadline_ns=deadline_ns)
        try:
            count = os.write(fd, prompt[offset:])
        except BlockingIOError:
            continue
        if count <= 0:
            contract.fail('approval_unavailable')
        offset += count
    answer = bytearray()
    while len(answer) < 128:
        _terminal_ready(fd, peer_fd, envelope, deadline_ns=deadline_ns)
        try:
            raw = os.read(fd, 1)
        except BlockingIOError:
            continue
        if not raw:
            contract.fail('approval_unavailable')
        if raw == b'\n':
            check_review_time(envelope)
            if select.select([peer_fd], [], [], 0)[0]:
                contract.fail('approval_unavailable')
            return bytes(answer) == challenge.encode('ascii')
        answer.extend(raw)
    return False


class _Deadline:
    """A worker-local clipped clock, with no caller-selected clock or renewal."""

    def __init__(self, deadline_ns, binding):
        self.deadline_ns = deadline_ns
        self.deadline = deadline_ns / contract.SECOND
        self.binding = binding

    def remaining(self):
        contract.check_clock(contract.sample_clock(), anchor=self.binding['clock_anchor'],
            window_start_utc_ns=self.binding['window_start_utc_ns'],
            window_end_utc_ns=self.binding['window_end_utc_ns'], deadline_ns=self.deadline_ns)
        value = self.deadline - time.monotonic()
        if value <= 0:
            contract.fail('timeout')
        return value

    def check(self):
        self.remaining()


def _serve(channel, state, role, witness_fd, *, terminal_fd=None, window=None):
    from . import engagement_live_protocol as protocol

    binding = state.binding
    sequence = protocol.ChannelSequence(binding['reviewer_id'], role)
    session_control = _Deadline(state.deadline_ns, binding)
    while True:
        request = sequence.accept(protocol.receive_packet(channel, role=role, control=session_control))
        protocol.require_request(request, role=role)
        operation = request['operation']
        phase_control = session_control
        if operation == 'CLOSE':
            if window is not None:
                window.close()
            data = {'role': role, 'worker_id': binding['reviewer_id'],
                    'stopped_at_ns': time.monotonic_ns()}
        elif operation == 'REVIEW':
            prepared = state.begin_review(request['body'])
            action, policy = parse_action(prepared['action']), parse_policy(prepared['policy'])
            envelope = prepared['envelope']
            phase_control = _Deadline(min(envelope['action_deadline_ns'],state.deadline_ns), binding)
            accepted = (terminal_review(terminal_fd, channel.fileno(), action, policy, envelope,
                                        deadline_ns=phase_control.deadline_ns)
                        if role == 'terminal'
                        else window.review(action, policy, envelope, channel.fileno(),
                                           deadline_ns=phase_control.deadline_ns))
            phase_control.check()
            data = state.issue_reviewed(prepared) if accepted else None
        elif operation == 'CONSUME':
            prepared = request['body']['prepared']
            phase_control = _Deadline(min(session_control.deadline_ns,
                                          prepared['envelope']['action_deadline_ns'],
                                          time.monotonic_ns() + 2 * contract.SECOND), binding)
            # Even an expired/mismatched consume burns the original reference.
            data, witness = state.consume(request['body']['reference'], prepared)
            if witness is not None:
                phase_control.check()
                if select.select([channel], [], [], 0)[0]:
                    contract.fail('invalid_sequence')
                if os.write(witness_fd, witness) != len(witness):
                    contract.fail('approval_unavailable')
                phase_control.check()
        else:
            contract.fail('invalid_frame')
        reply = sequence.make(operation, {'request_sequence': request['sequence'],
            'status': 'ok', 'code': None, 'data': data})
        protocol.send_packet(channel, reply, role=role, control=phase_control)
        if operation == 'CLOSE':
            return 0


def main():
    from . import engagement_live_runtime as runtime

    rights = {}
    channel = window = witness = None
    try:
        if len(sys.argv) != 3:
            contract.fail('invalid_input')
        worker_id, commitment = contract.uuid(sys.argv[1]), contract.digest_string(sys.argv[2])
        selected = contract.decode(runtime._read_file(runtime.MANIFEST_PATH, 131072), max_bytes=131072)
        role = contract.member(selected.get('role'), {'terminal', 'graphical'})
        # Import the selected accepted seal helper before the one initial FD
        # transfer, so its verified libffi residue cannot hide an injected FD.
        if role == 'terminal':
            from . import approval_worker as accepted
        else:
            from . import graphical_approval_worker as accepted
            from . import graphical_approval_protocol as graphical
            from .engagement_live_approval_view import ReviewWindow
        initial, manifest, rights, channel = runtime._receive_initial(
            role, worker_id, commitment, entry_verified=True)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            contract.fail('invalid_channel')
        entry = runtime.check_role_entry(role=role, bootstrap=initial,
                                        expected_fds=rights, observer=initial['observer'])
        payload = initial['payload']
        contract.obj(payload, runtime.SPEC['closed_objects']['bootstrap_payloads'][role])
        state = GrantState(binding=payload['session_binding'], roe=payload['roe'],
                           scope=payload['scope'], policy=payload['policy'], deadline_ns=initial['deadline_ns'])
        binding = state.binding
        expected_mode = 'terminal' if role == 'terminal' else 'graphical_v1'
        if (payload['reviewer_id'] != worker_id or binding['reviewer_id'] != worker_id
                or payload['review_mode'] != expected_mode or binding['review_mode'] != expected_mode
                or initial['runtime_sha256'] != binding['runtime_sha256']
                or not time.monotonic_ns() < initial['deadline_ns'] <= min(
                    binding['session_deadline_ns'], binding['broker_deadline_ns'])):
            contract.fail('invalid_role')
        witness = socket.socket(fileno=rights['review_witness'])
        if witness.family != socket.AF_UNIX or witness.type != socket.SOCK_SEQPACKET:
            contract.fail('invalid_channel')
        witness.setblocking(False)
        # The sender is half-closed to input at allocation; it cannot receive a
        # substitute grant or later control message from the broker.
        if witness.recv(1, socket.MSG_DONTWAIT) != b'':
            contract.fail('invalid_channel')
        terminal_fd = rights.get('intentional_tty')
        if role == 'terminal':
            identity = payload['tty_identity']
            if type(identity) is not list or len(identity) != 3:
                contract.fail('invalid_role')
            for item in identity:
                contract.integer(item, 0, 2**64 - 1)
            accepted.verify_terminal(terminal_fd, identity)
        else:
            display = graphical.canonical_display(payload['display'])
            if display != payload['display'] or os.environ.get('DISPLAY') != display:
                contract.fail('invalid_role')
            authority = runtime._read_file(graphical.AUTHORITY_PATH, 65536)
            if hashlib.sha256(authority).hexdigest() != payload['authority_sha256']:
                contract.fail('invalid_role')
            del authority
            window = ReviewWindow()
            window.warmup()
            if window._root.winfo_screen() != display:
                contract.fail('invalid_role')
            accepted.verify_display(payload, channel, witness)
        # Warm entropy and canonical model paths before denying filesystem opens.
        fresh_challenge(parse_action(contract.configurable_contract.action(payload['scope'], 1)))
        state.policy.digest
        ready = runtime.bootstrap_role(role=role, entry=entry, runtime_manifest=manifest,
                                       expected_fds=rights, deadline_ns=initial['deadline_ns'])
        if role == 'terminal':
            accepted.seal(terminal_fd)
            ready['boundary_checks'].update(network_creation_blocked=True,
                terminal_bound=True, terminal_input_owned=True)
        else:
            accepted.seal()
            ready['boundary_checks'].update(network_creation_blocked=True, display_bound=True,
                graphical_input_owned=True, remote_interpreter_disabled=True, task_set_sealed=True)
        runtime._emit_ready(ready)
        return _serve(channel, state, role, witness.fileno(), terminal_fd=terminal_fd, window=window)
    except Exception:
        os.write(2, b'engagement_live_approval_refused\n')
        return 78
    finally:
        if window is not None:
            window.close()
        if witness is not None:
            rights.pop('review_witness', None)
            witness.close()
        for fd in rights.values():
            try:
                os.close(fd)
            except OSError:
                pass
        if channel is not None:
            channel.close()


if __name__ == '__main__':
    raise SystemExit(main())
