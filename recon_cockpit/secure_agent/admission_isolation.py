"""Lazy host client for isolated, fixed-session launch admission."""

from dataclasses import asdict
import os
from pathlib import Path
import select
import socket
import threading
import time
from types import MappingProxyType
from uuid import uuid4

from . import launch_admission as protocol
from .execution import ExecutionControl, ExecutionStopped
from .isolation import IsolationUnavailable, _namespaces, _runtime_files, _trusted_program
from .planner_isolation import LinuxIsolatedMockProvider
from .routed import _Supervisor


class LinuxLaunchAdmission:
    """An opaque permit client, never the owner of execution reservations."""

    def __init__(self, policy, session_id, limits, *, execute=False, profile='fixture', case=None):
        self._config = protocol.configuration({
            'version': '1', 'service_id': str(uuid4()), 'session_id': session_id,
            'policy': policy.to_dict(), 'limits': asdict(limits), 'execute': execute,
            'profile': profile, 'case': case})
        self._sequence = 0
        self._closed = False
        self._lock = threading.Lock()
        self._control = self._channel = self._supervisor = self._checks = None
        self._snapshot = {'executions_reserved': 0, 'output_bytes_reserved': 0}

    @property
    def snapshot(self):
        return MappingProxyType(dict(self._snapshot))

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
        for name in ('admission_worker', 'launch_admission', 'models', 'tool_parameters', 'tool_adapters'):
            argv.extend(('--ro-bind', str(Path(__file__).with_name(name + '.py').resolve()),
                         '/app/admission_runtime/' + name + '.py'))
        argv.extend(('--remount-ro', '/proc', '--remount-ro', '/dev', '--remount-ro', '/',
                     '/usr/bin/python3', '-I', '-S', '/app/admission_runtime/admission_worker.py',
                     bootstrap_digest, *(host[name] for name in ('user', 'net', 'mnt', 'pid'))))
        return argv

    def _runtime(self, control):
        LinuxIsolatedMockProvider().check_available()
        return _runtime_files('/usr/bin/python3', None, control=control)

    def _start(self, control):
        if (not self._config['execute'] or type(control) is not ExecutionControl
                or control.clock is not time.monotonic):
            raise IsolationUnavailable('Invalid launch admission context')
        control.check()
        self._control = control
        initial = {'configuration': self._config, 'deadline': control.deadline}
        protocol.initial(initial, time.monotonic())
        stdlib, files = self._runtime(control)
        self._supervisor = _Supervisor(10, 65536, control=control)
        self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._channel.setblocking(False)
        try:
            commitment = protocol.digest(initial)
            self._process = self._supervisor.launch('worker', self._command(stdlib, files, commitment), stdin=child)
            child.close()
            for stream in (self._process.stdout, self._process.stderr):
                os.set_blocking(stream.fileno(), False)
            self._send(protocol.encode(initial))
            expected = {'version': '1', 'bootstrap_digest': commitment, 'ready': True,
                        'checks': dict.fromkeys(protocol.CHECKS, True)}
            if protocol.encode(self._reply()) != protocol.encode(expected):
                raise IsolationUnavailable('Invalid launch admission bootstrap receipt')
            self._checks = expected['checks']
        finally:
            child.close()

    def _send(self, raw):
        while True:
            self._supervisor.check()
            try:
                if self._channel.send(raw) != len(raw):
                    raise IsolationUnavailable('Short launch admission send')
                return
            except BlockingIOError:
                self._supervisor.wait_for(lambda: bool(select.select([], [self._channel], [], 0)[1]))

    def _quiet(self):
        for stream in (self._process.stdout, self._process.stderr):
            try:
                os.read(stream.fileno(), 1)
            except BlockingIOError:
                continue
            raise IsolationUnavailable('Unexpected launch admission output or exit')
        if self._process.poll() is not None:
            raise IsolationUnavailable('Launch admission worker exited')

    def _reply(self):
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b'\n' in supervisor.buffers['worker_out']
                            or bool(supervisor.buffers['worker_err']) or bool(supervisor.eof))
        raw = bytes(supervisor.buffers['worker_out'])
        if (supervisor.buffers['worker_err'] or supervisor.eof or len(raw) > 2048
                or not raw.endswith(b'\n') or raw.count(b'\n') != 1):
            raise IsolationUnavailable('Invalid launch admission reply')
        supervisor.buffers['worker_out'].clear()
        value = protocol.decode(raw[:-1])
        self._quiet()
        return value

    def _exchange(self, operation, action, policy, *, permit=None, control):
        with self._lock:
            if self._closed:
                raise IsolationUnavailable('Launch admission closed')
            try:
                if self._control is None:
                    if operation != 'admit':
                        raise IsolationUnavailable('Launch admission has not issued a permit')
                    self._start(control)
                if control is not self._control:
                    raise IsolationUnavailable('Launch admission control changed')
                self._control.check()
                self._supervisor.deadline = min(self._control.deadline, time.monotonic() + 5)
                value = {'version': '1', 'service_id': self._config['service_id'],
                    'session_id': self._config['session_id'], 'sequence': self._sequence + 1,
                    'operation': operation, 'action': action.to_dict(), 'policy_digest': policy.digest}
                if operation == 'redeem':
                    value['permit'] = permit
                protocol.request(value, self._config, self._sequence + 1)
                self._quiet()
                self._send(protocol.encode(value))
                reply = self._reply()
                outcome = protocol.result(reply.get('result'), operation, self._config)
                if protocol.encode(reply) != protocol.encode(protocol.receipt(value, outcome)):
                    raise IsolationUnavailable('Launch admission receipt mismatch')
                expected = dict(self._snapshot)
                if operation == 'admit' and outcome['reason'] is None:
                    expected['executions_reserved'] += 1
                    expected['output_bytes_reserved'] += action.parameters.max_output_bytes
                if outcome['snapshot'] != expected:
                    raise IsolationUnavailable('Launch admission counters changed')
                self._control.check()
                self._sequence += 1
                self._snapshot = dict(outcome['snapshot'])
                return outcome
            except BaseException as exc:
                self._cleanup()
                if isinstance(exc, (ExecutionStopped, KeyboardInterrupt, SystemExit)):
                    raise
                raise IsolationUnavailable('Launch admission unavailable; no fallback') from None

    def admit(self, action, policy, *, control):
        return self._exchange('admit', action, policy, control=control)

    def redeem(self, permit, action, policy, *, control):
        return self._exchange('redeem', action, policy, permit=permit, control=control)

    def _cleanup(self):
        self._closed = True
        self._checks = None
        try:
            if self._channel is not None:
                self._channel.close()
        finally:
            if self._supervisor is not None:
                self._supervisor.close()

    def close(self):
        with self._lock:
            if not self._closed:
                self._cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
