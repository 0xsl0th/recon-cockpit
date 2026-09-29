"""Trusted, lazy client for fixed Linux terminal review and opaque grants."""

import array
import os
from pathlib import Path
import select
import socket
import threading
import time
from uuid import uuid4

from . import approval_protocol as protocol
from .approvals import ApprovalUnavailable
from .execution import ExecutionControl, ExecutionStopped
from .isolation import _namespaces, _runtime_files, _trusted_program
from .models import parse_policy
from .planner_isolation import LinuxIsolatedMockProvider
from .routed import _Supervisor


def _open_terminal():
    return os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)


class LinuxApprovalService:
    """One immutable session, no issue/reset/reconnect or local fallback.

    Construction is inert. Only the trusted UI's first review opens /dev/tty
    and starts the fixed worker. The worker owns all grant state and input.
    """

    def __init__(self, policy, session_id):
        self._policy = parse_policy(policy.to_dict())
        self._session_id = protocol.identity(session_id)
        self._identity = str(uuid4())
        self._sequence = 0
        self._closed = False
        self._lock = threading.Lock()
        self._control = self._channel = self._supervisor = self._checks = None

    @property
    def boundary_checks(self):
        return None if self._checks is None else dict(self._checks)

    def _command(self, stdlib, files, bootstrap_digest):
        host = _namespaces()
        argv = [_trusted_program('bwrap'), '--unshare-user', '--unshare-net', '--unshare-pid',
                '--unshare-ipc', '--unshare-uts', '--unshare-cgroup', '--uid', '0', '--gid', '0',
                '--cap-drop', 'ALL', '--die-with-parent', '--new-session', '--clearenv',
                '--setenv', 'LC_ALL', 'C', '--chdir', '/', '--proc', '/proc', '--dev', '/dev',
                '--ro-bind', stdlib, stdlib]
        for source, destination in files:
            argv.extend(('--ro-bind', source, destination))
        argv.extend(('--ro-bind', str(Path(__file__).with_name('planner_worker.py').resolve()),
                     '/app/planner_worker.py'))
        for name in ('approval_worker', 'approval_protocol', 'approvals', 'models'):
            argv.extend(('--ro-bind', str(Path(__file__).with_name(name + '.py').resolve()),
                         '/app/approval_runtime/' + name + '.py'))
        argv.extend(('--remount-ro', '/proc', '--remount-ro', '/dev', '--remount-ro', '/',
                     '/usr/bin/python3', '-I', '-S', '/app/approval_runtime/approval_worker.py',
                     bootstrap_digest, *(host[name] for name in ('user', 'net', 'mnt', 'pid'))))
        return argv

    def _start(self, control):
        if type(control) is not ExecutionControl or control.clock is not time.monotonic:
            raise ApprovalUnavailable('invalid_approval_control')
        control.check()
        if control.remaining() > protocol.MAX_LIFETIME:
            raise ApprovalUnavailable('approval_lifetime_limit')
        self._control = control
        LinuxIsolatedMockProvider().check_available()
        stdlib, files = _runtime_files('/usr/bin/python3', None, control=control)
        self._supervisor = _Supervisor(10, 65536, control=control)
        self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._channel.setblocking(False)
        terminal = None
        try:
            terminal = _open_terminal()
            info = os.fstat(terminal)
            initial = {'version': '1', 'broker_id': self._identity, 'session_id': self._session_id,
                       'policy': self._policy.to_dict(), 'deadline': control.deadline,
                       'terminal': [info.st_dev, info.st_ino, info.st_rdev]}
            protocol.initial(initial, time.monotonic())
            bootstrap_digest = protocol.digest(initial)
            self._process = self._supervisor.launch(
                'worker', self._command(stdlib, files, bootstrap_digest), stdin=child)
            child.close()
            for stream in (self._process.stdout, self._process.stderr):
                os.set_blocking(stream.fileno(), False)
            self._send(protocol.encode(initial), fd=terminal)
            os.close(terminal)
            terminal = None
            expected = {'version': '1', 'bootstrap_digest': bootstrap_digest, 'ready': True,
                        'checks': dict.fromkeys(protocol.CHECKS, True)}
            if protocol.encode(self._reply()) != protocol.encode(expected):
                raise ApprovalUnavailable('approval_invalid_ready')
            self._checks = expected['checks']
        finally:
            if terminal is not None:
                os.close(terminal)
            child.close()

    def _send(self, raw, *, fd=None):
        ancillary = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]
        while True:
            self._supervisor.check()
            try:
                if self._channel.sendmsg([raw], ancillary) != len(raw):
                    raise ApprovalUnavailable('approval_short_send')
                return
            except BlockingIOError:
                self._supervisor.wait_for(lambda: bool(select.select([], [self._channel], [], 0)[1]))

    def _quiet(self):
        for stream in (self._process.stdout, self._process.stderr):
            try:
                os.read(stream.fileno(), 1)
            except BlockingIOError:
                continue
            raise ApprovalUnavailable('approval_unexpected_output_or_exit')
        if self._process.poll() is not None:
            raise ApprovalUnavailable('approval_worker_exited')

    def _reply(self):
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b'\n' in supervisor.buffers['worker_out']
                            or bool(supervisor.buffers['worker_err']) or bool(supervisor.eof))
        raw = bytes(supervisor.buffers['worker_out'])
        if (supervisor.buffers['worker_err'] or supervisor.eof or len(raw) > 2048
                or not raw.endswith(b'\n') or raw.count(b'\n') != 1):
            raise ApprovalUnavailable('approval_invalid_reply')
        supervisor.buffers['worker_out'].clear()
        value = protocol.decode(raw[:-1])
        self._quiet()
        return value

    def _exchange(self, operation, action, policy, *, reference=None, control=None):
        with self._lock:
            if self._closed:
                raise ApprovalUnavailable('approval_closed')
            try:
                if self._control is None:
                    if operation == 'consume':
                        return 'approval_missing' if reference is None else 'approval_unknown_or_replayed'
                    self._start(control)
                if control is not None and control is not self._control:
                    raise ApprovalUnavailable('approval_control_changed')
                self._control.check()
                # Reviews may wait for the human, bounded by the original
                # session deadline. Consumption is a short noninteractive RPC.
                self._supervisor.deadline = min(self._control.deadline,
                    time.monotonic() + (protocol.MAX_LIFETIME if operation == 'review' else 5))
                value = {'version': '1', 'broker_id': self._identity, 'session_id': self._session_id,
                         'sequence': self._sequence + 1, 'operation': operation,
                         'action': action.to_dict(), 'policy_digest': policy.digest}
                if operation == 'consume':
                    value['reference'] = reference
                protocol.request(value, self._identity, self._session_id, self._sequence + 1)
                self._quiet()
                self._send(protocol.encode(value))
                reply = self._reply()
                expected = protocol.receipt(value, reply.get('result'))
                if protocol.encode(reply) != protocol.encode(expected):
                    raise ApprovalUnavailable('approval_receipt_mismatch')
                self._control.check()
                self._sequence += 1
                return reply['result']
            except BaseException as exc:
                self._cleanup()
                if isinstance(exc, (ExecutionStopped, KeyboardInterrupt, SystemExit)):
                    raise
                raise ApprovalUnavailable('approval_unavailable') from None

    def review(self, action, policy, *, control):
        return self._exchange('review', action, policy, control=control)

    def consume(self, reference, action, policy):
        return self._exchange('consume', action, policy, reference=reference)

    def _cleanup(self):
        self._closed = True
        self._checks = None
        try:
            if self._channel is not None:
                self._channel.close()
        finally:
            if self._supervisor is not None:
                try:
                    self._supervisor.close()
                except Exception:
                    raise ApprovalUnavailable('approval_cleanup_failed') from None

    def close(self):
        with self._lock:
            if not self._closed:
                self._cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
