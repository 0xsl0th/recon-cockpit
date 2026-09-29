"""Lazy fixture-launcher client; executable construction and permits stay remote."""

from dataclasses import asdict
import os
from pathlib import Path
import re
import select
import socket
import threading
import time
from types import MappingProxyType
from uuid import uuid4

from . import launch_admission as admission, launcher_protocol as protocol
from .authorized_execution import AuthorizedFixtureBackend, AuthorizedDiscoveryFixtureBackend
from .owned_lab import AuthorizedOwnedLabBackend
from .owned_lab_contract import validate_result_context, validate_closure
from .execution import ExecutionControl, ExecutionStopped
from .isolation import (IsolationUnavailable, LinuxFixtureBackend, _namespaces,
                        _runtime_files, _runtime_probe, _trusted_program)
from .planner_isolation import LinuxIsolatedMockProvider
from .routed import _Supervisor

MODULES = ('launcher_worker', 'launcher_protocol', 'execution', 'models', 'worker',
           'executor_worker', 'admission_isolation', 'admission_worker', 'launch_admission',
           'isolation', 'routed', 'planner_isolation', 'planner_worker', 'session_provider')
OWNED_MODULES = ('owned_launcher_runtime', 'owned_lab', 'owned_lab_worker', 'owned_lab_executor',
                 'owned_lab_contract', 'assessment_contract', 'authorized_execution', 'session_limits', '__init__')


class LinuxFixtureLauncher:
    def __init__(self, backend):
        if type(backend) not in {AuthorizedFixtureBackend, AuthorizedDiscoveryFixtureBackend, AuthorizedOwnedLabBackend}:
            raise ValueError('unsupported_launcher_backend')
        self.name = backend.name
        owned = type(backend) is AuthorizedOwnedLabBackend
        self._config = protocol.configuration({'version': '1', 'service_id': str(uuid4()),
            'session_id': backend._session_id, 'policy': backend._policy.to_dict(),
            'limits': asdict(backend._limits), 'execute': backend._execute,
            'profile': 'owned_lab' if owned else backend.launch_mode,
            'case': backend._lab_identity['scenario'] if owned else None,
            **({'owned_lab': backend._lab_identity} if owned else {})})
        self._control = self._channel = self._supervisor = self._checks = None
        self._snapshot = {'executions_reserved': 0, 'output_bytes_reserved': 0}
        self._sequence = 0
        self._closed = False
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._lab_context = self._lab_receipt = None
        self._cleanup_verified = False

    @property
    def identity(self):
        if self._config['profile'] != 'owned_lab':
            raise ValueError('launcher_has_no_persistent_lab')
        return dict(self._config['owned_lab'])

    @property
    def snapshot(self):
        return MappingProxyType(dict(self._snapshot))

    @property
    def boundary_checks(self):
        return None if self._checks is None else dict(self._checks)

    def check_available(self, action=None):
        if self._closed or self._stopped.is_set() or not self._config['execute']:
            raise IsolationUnavailable('Fixture launcher unavailable')
        LinuxIsolatedMockProvider().check_available()
        LinuxFixtureBackend().check_available()  # No runtime probes or child start.
        if action is not None and not admission.profile_allows(action, self._config):
            raise IsolationUnavailable('Fixture launcher profile denied')

    def _runtime(self, control):
        stdlib, files = _runtime_files('/usr/bin/python3', _trusted_program('nft'), control=control)
        programs = [_trusted_program('bwrap')]
        if self._config['profile'] == 'owned_lab':
            programs.append(_trusted_program('nsenter'))
        listing = _runtime_probe([_trusted_program('ldd'), *programs], 5, 65536, control).decode('ascii')
        if 'not found' in listing:
            raise IsolationUnavailable('Missing launcher runtime')
        libraries = set(re.findall(r'(?:=>\s+)?(/[^\s]+)\s+\(', listing))
        if not libraries:
            raise IsolationUnavailable('Invalid launcher runtime')
        files += [(str(Path(p).resolve(strict=True)), p) for p in sorted(libraries)]
        files += [(str(Path(p).resolve(strict=True)), '/usr/bin/'+Path(p).name) for p in programs]
        by_destination = {destination: source for source, destination in files}
        files = [(by_destination[p], p) for p in sorted(by_destination)]
        closure = protocol.runtime({'stdlib': stdlib, 'files': [p for _, p in files]}, owned_lab=self._config['profile'] == 'owned_lab')
        return closure, files

    def _command(self, closure, files, commitment):
        host = _namespaces()
        argv = [_trusted_program('bwrap'), '--unshare-user', '--unshare-net', '--unshare-pid',
            '--unshare-ipc', '--unshare-uts', '--unshare-cgroup', '--uid', str(os.getuid()),
            '--gid', str(os.getgid()), '--cap-drop', 'ALL', '--die-with-parent', '--new-session',
            '--clearenv', '--setenv', 'LC_ALL', 'C', '--chdir', '/', '--proc', '/proc', '--dev', '/dev',
            '--size', '1048576', '--tmpfs', '/tmp', '--ro-bind', closure['stdlib'], closure['stdlib']]
        for source, destination in files:
            argv += ['--ro-bind', source, destination]
        for name in (*MODULES, *(OWNED_MODULES if self._config['profile'] == 'owned_lab' else ())):
            argv += ['--ro-bind', str(Path(__file__).with_name(name+'.py').resolve()),
                     '/app/recon_cockpit/secure_agent/'+name+'.py']
        # Private /proc must permit nested Bubblewrap's UID/GID-map writes.
        # The admission and executor children still mount their own /proc read-only.
        argv += ['--remount-ro', '/dev', '--remount-ro', '/',
            '/usr/bin/python3', '-I', '-S', '/app/recon_cockpit/secure_agent/launcher_worker.py',
            commitment, *(host[name] for name in ('user', 'net', 'mnt', 'pid'))]
        return argv

    def _start(self, control):
        if type(control) is not ExecutionControl or control.clock is not time.monotonic:
            raise IsolationUnavailable('Invalid fixture launcher control')
        self.check_available()
        control.check()
        self._control = control
        closure, files = self._runtime(control)
        initial = {'configuration': self._config, 'deadline': control.deadline, 'runtime': closure}
        protocol.initial(initial, time.monotonic())
        commitment = admission.digest(initial)
        self._supervisor = _Supervisor(10, protocol.MAX_REPLY*16+4096, control=control)
        self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._channel.setblocking(False)
        try:
            self._process = self._supervisor.launch('worker', self._command(closure, files, commitment), stdin=child)
            child.close()
            for stream in (self._process.stdout, self._process.stderr):
                os.set_blocking(stream.fileno(), False)
            self._send(admission.encode(initial))
            expected = {'version': '1', 'ready': True, 'bootstrap_digest': commitment,
                        'checks': dict.fromkeys(protocol.CHECKS, True)}
            if protocol.encode(self._reply()) != protocol.encode(expected):
                raise IsolationUnavailable('Invalid fixture launcher bootstrap')
            self._checks = expected['checks']
        finally:
            child.close()

    def _send(self, raw):
        while True:
            self._supervisor.check()
            if self._stopped.is_set():
                raise IsolationUnavailable('Fixture launcher stopped')
            try:
                if self._channel.send(raw) != len(raw):
                    raise IsolationUnavailable('Short fixture launcher send')
                return
            except BlockingIOError:
                self._supervisor.wait_for(lambda: bool(select.select([], [self._channel], [], 0)[1]))

    def _quiet(self):
        for stream in (self._process.stdout, self._process.stderr):
            try:
                os.read(stream.fileno(), 1)
            except BlockingIOError:
                continue
            raise IsolationUnavailable('Unexpected fixture launcher output')
        if self._process.poll() is not None:
            raise IsolationUnavailable('Fixture launcher exited')

    def _reply(self):
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b'\n' in supervisor.buffers['worker_out']
                            or bool(supervisor.buffers['worker_err']) or bool(supervisor.eof)
                            or self._stopped.is_set())
        raw = bytes(supervisor.buffers['worker_out'])
        if (self._stopped.is_set() or supervisor.buffers['worker_err'] or supervisor.eof
                or len(raw) > protocol.MAX_REPLY+1 or not raw.endswith(b'\n') or raw.count(b'\n') != 1):
            raise IsolationUnavailable('Invalid fixture launcher reply')
        supervisor.buffers['worker_out'].clear()
        value = protocol.decode(raw[:-1])
        self._quiet()
        return value

    def run(self, action, policy, *, control=None):
        if not self._lock.acquire(blocking=False):
            self._stopped.set()
            raise IsolationUnavailable('Fixture launcher already running')
        try:
            self.check_available(action)
            if self._control is None:
                self._start(control)
            if control is not self._control:
                raise IsolationUnavailable('Fixture launcher control changed')
            control.check()
            value = {'version': '1', 'service_id': self._config['service_id'], 'session_id': self._config['session_id'],
                'sequence': self._sequence+1, 'operation': 'execute', 'action': action.to_dict(), 'policy_digest': policy.digest}
            protocol.request(value, self._config, self._sequence+1)
            self._supervisor.deadline = min(control.deadline, time.monotonic()+action.parameters.timeout_seconds+18)
            self._quiet()
            self._send(admission.encode(value))
            reply = self._reply()
            result = protocol.result(reply.get('result'), self._config)
            lab_context = (validate_result_context(result, self.identity, previous=self._lab_context,
                tool_id=action.tool_id, execution_status=result['status']) if self._config['profile'] == 'owned_lab' else None)
            expected = {'executions_reserved': self._snapshot['executions_reserved']+1,
                        'output_bytes_reserved': self._snapshot['output_bytes_reserved']+action.parameters.max_output_bytes}
            if (expected['output_bytes_reserved'] > self._config['limits']['max_output_bytes']
                    or protocol.encode(reply) != protocol.encode(protocol.receipt(value, result, expected))):
                raise IsolationUnavailable('Fixture launcher receipt mismatch')
            control.check()
            self._sequence += 1
            self._snapshot = expected
            self._lab_context = lab_context
            return result
        except BaseException as exc:
            self._cleanup()
            if isinstance(exc, (ExecutionStopped, KeyboardInterrupt, SystemExit)):
                raise
            raise IsolationUnavailable('Fixture launcher unavailable; no fallback') from None
        finally:
            self._lock.release()

    def _cleanup(self):
        self._cleanup_verified = False
        self._closed = True
        self._stopped.set()
        self._checks = None
        try:
            if self._channel is not None:
                self._channel.close()
        finally:
            if self._supervisor is not None:
                self._supervisor.close()
        self._cleanup_verified = True

    def close(self):
        self._stopped.set()
        with self._lock:
            if not self._closed:
                self._cleanup()
            if self._config['profile'] == 'owned_lab':
                if not self._cleanup_verified:
                    raise IsolationUnavailable('Lab cleanup was not verified')
                if self._lab_receipt is None:
                    context = self._lab_context or {'identity': self.identity, 'connection_count': 0, 'request_count': 0}
                    self._lab_receipt = validate_closure({**context, 'status': 'closed'}, self.identity, previous=self._lab_context)
                return {**self._lab_receipt, 'identity': self.identity}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
