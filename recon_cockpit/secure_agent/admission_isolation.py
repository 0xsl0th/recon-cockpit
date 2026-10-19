"""Lazy host client for isolated, fixed-session launch admission."""

from dataclasses import asdict
import fcntl
import os
from pathlib import Path
import select
import socket
import stat
import threading
import time
from types import MappingProxyType
from uuid import uuid4

from . import launch_admission as protocol
from .execution import ExecutionControl, ExecutionStopped
from .isolation import IsolationUnavailable, _namespaces, _runtime_files, _trusted_program
from .planner_isolation import LinuxIsolatedMockProvider
from .routed import _Supervisor


NAME_TLS_SOURCE_MODULES = ('admission_worker', 'launch_admission', 'models', 'tool_parameters',
                         'tool_adapters', 'name_tls_contract', 'name_tls_public', 'session_limits')


def _name_tls_source_copies(control):
    """Seal exact nested source bytes, including parent Bubblewrap data mounts."""
    descriptors = {}
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    paths = {'/app/planner_worker.py': Path(__file__).with_name('planner_worker.py'),
             **{'/app/admission_runtime/' + name + '.py': Path(__file__).with_name(name + '.py')
                for name in NAME_TLS_SOURCE_MODULES}}
    total = 0
    try:
        for destination, path in sorted(paths.items()):
            control.check()
            source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                before = os.fstat(source)
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 131072:
                    raise ValueError('name_tls_admission_source_type')
                raw = bytearray()
                while len(raw) <= 131072:
                    part = os.read(source, min(65536, 131073 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
                after = os.fstat(source)
                stamp = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if stamp(before) != stamp(after) or len(raw) != before.st_size:
                    raise ValueError('name_tls_admission_source_changed')
            finally:
                os.close(source)
            total += len(raw)
            if total > 1048576:
                raise ValueError('name_tls_admission_source_limit')
            descriptor = os.memfd_create('recon-name-tls-admission', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors[destination] = descriptor
            offset = 0
            while offset < len(raw):
                count = os.write(descriptor, raw[offset:])
                if count <= 0:
                    raise ValueError('name_tls_admission_source_short_write')
                offset += count
            os.lseek(descriptor, 0, os.SEEK_SET)
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        control.check()
        return descriptors
    except BaseException:
        for descriptor in descriptors.values():
            os.close(descriptor)
        raise


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

    def _command(self, stdlib, files, bootstrap_digest, source_descriptors=None):
        host = _namespaces()
        argv = [_trusted_program('bwrap'), '--unshare-user', '--unshare-net', '--unshare-pid',
                '--unshare-ipc', '--unshare-uts', '--unshare-cgroup', '--uid', '0', '--gid', '0',
                '--cap-drop', 'ALL', '--die-with-parent', '--new-session', '--clearenv',
                '--setenv', 'LC_ALL', 'C', '--chdir', '/', '--proc', '/proc', '--dev', '/dev',
                '--ro-bind', stdlib, stdlib]
        for source, destination in files:
            argv.extend(('--ro-bind', source, destination))
        if self._config['profile'] == 'owned_name_tls_v1':
            expected = {'/app/planner_worker.py', *('/app/admission_runtime/' + name + '.py' for name in NAME_TLS_SOURCE_MODULES)}
            if (type(source_descriptors) is not dict or set(source_descriptors) != expected
                    or any(type(fd) is not int or fd < 3 for fd in source_descriptors.values())
                    or len(set(source_descriptors.values())) != len(expected)):
                raise ValueError('name_tls_admission_source_inventory')
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            for destination, descriptor in sorted(source_descriptors.items()):
                if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
                    raise ValueError('name_tls_admission_source_unsealed')
                argv.extend(('--perms', '0444', '--ro-bind-data', str(descriptor), destination))
        else:
            if source_descriptors is not None:
                raise ValueError('unexpected_admission_sources')
            argv.extend(('--ro-bind', str(Path(__file__).with_name('planner_worker.py').resolve()),
                         '/app/planner_worker.py'))
        for name in ('admission_worker', 'launch_admission', 'models', 'tool_parameters', 'tool_adapters',
                     *(('name_tls_contract', 'name_tls_public', 'session_limits')
                       if self._config['profile'] == 'owned_name_tls_v1' else ()),
                     *(('configurable_scope', 'configurable_contract')
                       if self._config['profile'] == 'configurable_owned_lab' else ()),
                     *(('stock_http_contract', 'stock_http_spec', 'configurable_scope', 'configurable_contract')
                       if self._config['profile'] in {'stock_nginx_diagnostic_v1', 'stock_http_compatibility_v1'} else ()),
                     *(('stock_http_production_contract', 'stock_apache_spec', 'stock_http_production_nmap_spec')
                       if self._config['profile'] == 'stock_http_compatibility_v1' else ()),
                     *(('stock_ssh_contract', 'stock_ssh_spec', 'stock_ssh_process', 'stock_ssh_nmap_spec',
                        'network_tools_ssh_fixture', 'stock_http_spec', 'configurable_scope', 'configurable_contract')
                       if self._config['profile'] == 'stock_ssh_compatibility_v1' else ()),
                     *(('routing_contract', 'routing_topology_spec', 'stock_http_contract', 'stock_http_production_contract',
                        'stock_http_spec', 'stock_apache_spec', 'stock_http_production_nmap_spec',
                        'stock_ssh_contract', 'stock_ssh_spec', 'stock_ssh_process', 'stock_ssh_nmap_spec',
                        'network_tools_ssh_fixture', 'configurable_scope', 'configurable_contract')
                       if self._config['profile'] == 'disconnected_routing_v1' else ())):
            if source_descriptors is None:
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
        source_descriptors = None
        try:
            commitment = protocol.digest(initial)
            if self._config['profile'] == 'owned_name_tls_v1':
                source_descriptors = _name_tls_source_copies(control)
            argv = (self._command(stdlib, files, commitment) if source_descriptors is None else
                    self._command(stdlib, files, commitment, source_descriptors))
            self._process = self._supervisor.launch('worker', argv, stdin=child,
                pass_fds=tuple((source_descriptors or {}).values()))
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
            for descriptor in (source_descriptors or {}).values():
                os.close(descriptor)
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
                if self._config['profile'] == 'owned_name_tls_v1':
                    detail = (bytes(self._supervisor.buffers.get('worker_err', b''))[:4096]
                              .decode('utf-8', 'replace') if self._supervisor is not None else '')
                    raise IsolationUnavailable('Launch admission unavailable: ' + type(exc).__name__ + ': '
                                               + str(exc)[:256] + ': ' + detail + '; no fallback') from None
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
