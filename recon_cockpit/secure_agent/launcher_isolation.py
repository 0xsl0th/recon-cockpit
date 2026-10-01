"""Lazy fixture-launcher client; executable construction and permits stay remote."""

from dataclasses import asdict
import array
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
from .nmap_backend import AuthorizedNmapOwnedBackend
from .web_backend import AuthorizedWebLabBackend
from .http_headers_backend import AuthorizedHTTPHeadersBackend
from .web_tools_backend import AuthorizedWebToolsBackend
from .network_tools_backend import AuthorizedNetworkToolsBackend
from .owned_lab_contract import validate_result_context, validate_closure
from .execution import ExecutionControl, ExecutionStopped
from .isolation import (IsolationUnavailable, LinuxFixtureBackend, _namespaces,
                        _runtime_files, _runtime_probe, _trusted_program)
from .planner_isolation import LinuxIsolatedMockProvider
from .routed import _Supervisor

MODULES = ('launcher_worker', 'launcher_protocol', 'execution', 'models', 'tool_parameters', 'tool_adapters', 'worker',
           'executor_worker', 'admission_isolation', 'admission_worker', 'launch_admission',
           'isolation', 'routed', 'planner_isolation', 'planner_worker', 'session_provider')
NMAP_MODULES = ('nmap_contract', 'nmap_backend', 'nmap_execution', 'nmap_runtime', 'nmap_worker',
                'nmap_parser', 'nmap_parser_worker')
WEB_MODULES = ('web_backend', 'web_lab', 'web_lab_worker', 'web_fixture', 'web_lab_contract', 'web_assessment_contract')
HTTP_HEADERS_MODULES = ('http_headers_backend', 'http_headers_lab', 'http_headers_lab_worker',
    'http_headers_fixture', 'http_headers_lab_contract', 'http_headers_contract', 'http_headers_operation',
    'http_headers_parser', 'http_headers_parser_runtime', 'http_headers_parser_worker')
WEB_TOOLS_MODULES = ('web_tools_backend', 'web_tools_lab', 'web_tools_lab_worker', 'web_tools_fixture',
    'web_tools_tls_fixture', 'web_tools_lab_contract', 'web_tools_contract', 'web_tools_runtime',
    'web_tools_execution', 'web_tools_worker', 'web_tools_parser', 'web_tools_parser_runtime',
    'web_tools_parser_worker', 'http_headers_parser', 'tool_runtime_common', 'tool_worker_common')
NETWORK_TOOLS_MODULES = ('network_tools_backend', 'network_tools_lab', 'network_tools_lab_worker',
    'network_tools_fixture', 'web_tools_tls_fixture', 'network_tools_lab_contract',
    'network_tools_contract', 'network_tools_runtime', 'network_tools_execution', 'network_tools_worker',
    'network_tools_parser', 'network_tools_parser_runtime', 'network_tools_parser_worker',
    'tool_runtime_common', 'tool_worker_common')
OWNED_MODULES = ('owned_launcher_runtime', 'owned_lab', 'owned_lab_worker', 'owned_lab_executor',
                 'owned_lab_contract', 'assessment_contract', 'authorized_execution', 'session_limits', '__init__')


class LinuxFixtureLauncher:
    def __init__(self, backend, *, audit=None, approvals=None):
        if type(backend) not in {AuthorizedFixtureBackend, AuthorizedDiscoveryFixtureBackend, AuthorizedOwnedLabBackend, AuthorizedNmapOwnedBackend, AuthorizedWebLabBackend, AuthorizedHTTPHeadersBackend, AuthorizedWebToolsBackend, AuthorizedNetworkToolsBackend}:
            raise ValueError('unsupported_launcher_backend')
        self.name = backend.name
        self._nmap_manifest = getattr(backend, "_nmap_manifest", None)
        self._web_tools_manifest = getattr(backend, "_web_tools_manifest", None)
        self._network_tools_manifest = getattr(backend, "_network_tools_manifest", None)
        owned = type(backend) in {AuthorizedOwnedLabBackend, AuthorizedNmapOwnedBackend, AuthorizedWebLabBackend, AuthorizedHTTPHeadersBackend, AuthorizedWebToolsBackend, AuthorizedNetworkToolsBackend}
        self._config = protocol.configuration({'version': '1', 'service_id': str(uuid4()),
            'session_id': backend._session_id, 'policy': backend._policy.to_dict(),
            'limits': asdict(backend._limits), 'execute': backend._execute,
            'profile': 'owned_lab' if type(backend) is AuthorizedOwnedLabBackend else backend.launch_mode,
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
        self._witness_reader = self._witness_source = None
        self._approval_reader = self._approval_source = None
        self._approval_service = approvals
        if approvals is not None:
            from .approval_isolation import LinuxApprovalService
            if (audit is None or type(approvals) is not LinuxApprovalService
                    or approvals._session_id != self._config['session_id']
                    or approvals._policy.to_dict() != self._config['policy']):
                raise ValueError('launcher_requires_bound_isolated_approval')
        if audit is not None:
            from .audit_isolation import LinuxAuditSink
            if type(audit) is not LinuxAuditSink:
                raise ValueError('launcher_requires_isolated_audit')
            self._witness_reader, self._witness_source = audit.take_launch_witness()
        if approvals is not None:
            try:
                self._approval_reader, self._approval_source = approvals.take_launch_witness()
            except BaseException:
                self._witness_reader.close()
                self._witness_reader = None
                raise

    @property
    def identity(self):
        if self._config['profile'] not in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab'}:
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
        if self._config['profile'] in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab'}:
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
        closure = {'stdlib': stdlib, 'files': [p for _, p in files]}
        nmap = self._config['profile'] in {'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab'}
        if nmap:
            from .nmap_runtime import inspect_nmap_runtime, runtime_source_mounts
            closure['nmap_runtime'] = self._nmap_manifest if self._nmap_manifest is not None else inspect_nmap_runtime(control)
            files += runtime_source_mounts(closure['nmap_runtime'])
        web_tools = self._config['profile'] == 'owned_web_tools_lab'
        if web_tools:
            from .web_tools_runtime import inspect_tool_runtime, runtime_source_mounts, validate_manifest
            from .web_tools_contract import action
            selected = action(self._config['case'], 1)['tool_id']
            closure['web_tools_runtime'] = (inspect_tool_runtime(selected, control) if self._web_tools_manifest is None
                else validate_manifest(self._web_tools_manifest, tool_id=selected))
            files += runtime_source_mounts(closure['web_tools_runtime'])
        network_tools = self._config['profile'] == 'owned_network_tools_lab'
        if network_tools:
            from .network_tools_runtime import inspect_tool_runtime, runtime_source_mounts, validate_manifest
            from .network_tools_contract import action
            selected = action(self._config['case'], 1)['tool_id']
            closure['network_tools_runtime'] = (inspect_tool_runtime(selected, control) if self._network_tools_manifest is None
                else validate_manifest(self._network_tools_manifest, tool_id=selected))
            files += runtime_source_mounts(closure['network_tools_runtime'])
        protocol.runtime(closure, owned_lab=self._config['profile'] in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab'}, nmap=nmap, web_tools=web_tools, network_tools=network_tools)
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
        for name in (*MODULES,
                     *(WEB_MODULES if self._config['profile'] == 'owned_web_lab' else ()),
                     *(HTTP_HEADERS_MODULES if self._config['profile'] == 'owned_http_headers_lab' else ()),
                     *(WEB_TOOLS_MODULES if self._config['profile'] == 'owned_web_tools_lab' else ()),
                     *(NETWORK_TOOLS_MODULES if self._config['profile'] == 'owned_network_tools_lab' else ()),
                     *(NMAP_MODULES if self._config['profile'] in {'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab'} else ()), *(OWNED_MODULES if self._config['profile'] in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab'} else ()),
                     *(('audit_witness', 'audit_protocol') if self._witness_source is not None else ()),
                     *(('approval_witness', 'approval_protocol') if self._approval_source is not None else ())):
            argv += ['--ro-bind', str(Path(__file__).with_name(name+'.py').resolve()),
                     '/app/recon_cockpit/secure_agent/'+name+'.py']
        # Private /proc must permit nested Bubblewrap's UID/GID-map writes.
        # The admission and executor children still mount their own /proc read-only.
        argv += ['--remount-ro', '/dev', '--remount-ro', '/',
            '/usr/bin/python3', '-I', '-S', '/app/recon_cockpit/secure_agent/launcher_worker.py',
            commitment, *(host[name] for name in ('user', 'net', 'mnt', 'pid'))]
        if self._approval_source is not None:
            argv.append({'owned_nmap_lab': 'nmap-launch-preconditions',
                         'owned_web_lab': 'web-launch-preconditions',
                         'owned_http_headers_lab': 'http-headers-launch-preconditions',
                         'owned_web_tools_lab': 'web-tools-launch-preconditions',
                         'owned_network_tools_lab': 'network-tools-launch-preconditions'}.get(self._config['profile'], 'launch-preconditions'))
        elif self._witness_source is not None:
            argv.append('launch-witness')
        return argv

    def _start(self, control):
        if type(control) is not ExecutionControl or control.clock is not time.monotonic:
            raise IsolationUnavailable('Invalid fixture launcher control')
        self.check_available()
        control.check()
        if self._approval_source is not None and self._config['policy']['require_approval']:
            self._approval_service.seal_launch_witness()
        self._control = control
        closure, files = self._runtime(control)
        initial = {'configuration': self._config, 'deadline': control.deadline, 'runtime': closure}
        if self._witness_source is not None:
            initial['audit_witness'] = self._witness_source
        if self._approval_source is not None:
            initial['approval_witness'] = self._approval_source
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
            if self._witness_reader is None:
                self._send(admission.encode(initial))
            else:
                try:
                    if self._approval_reader is None:
                        self._send(admission.encode(initial), fd=self._witness_reader.fileno())
                    else:
                        self._send(admission.encode(initial), fd=self._witness_reader.fileno(),
                                   approval_fd=self._approval_reader.fileno())
                finally:
                    self._witness_reader.close()
                    self._witness_reader = None
                    if self._approval_reader is not None:
                        self._approval_reader.close()
                        self._approval_reader = None
            expected = {'version': '1', 'ready': True, 'bootstrap_digest': commitment,
                        'checks': dict.fromkeys(protocol.CHECKS, True)}
            if protocol.encode(self._reply()) != protocol.encode(expected):
                raise IsolationUnavailable('Invalid fixture launcher bootstrap')
            self._checks = expected['checks']
        finally:
            child.close()

    def _send(self, raw, *, fd=None, approval_fd=None):
        while True:
            self._supervisor.check()
            if self._stopped.is_set():
                raise IsolationUnavailable('Fixture launcher stopped')
            try:
                written = (self._channel.send(raw) if fd is None else self._channel.sendmsg(
                    [raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                             array.array('i', [fd] if approval_fd is None else [fd, approval_fd]))]))
                if written != len(raw):
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
            context_validator = validate_result_context
            if self._config['profile'] == 'owned_nmap_lab':
                from .nmap_contract import validate_result_context as context_validator
            elif self._config['profile'] == 'owned_web_lab':
                from .web_assessment_contract import validate_result_context as context_validator
            elif self._config['profile'] == 'owned_http_headers_lab':
                from .http_headers_contract import validate_result_context as context_validator
            elif self._config['profile'] == 'owned_web_tools_lab':
                from .web_tools_contract import validate_result_context as context_validator
            elif self._config['profile'] == 'owned_network_tools_lab':
                from .network_tools_contract import validate_result_context as context_validator
            lab_context = (context_validator(result, self.identity, previous=self._lab_context,
                tool_id=action.tool_id, execution_status=result['status']) if self._config['profile'] in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab'} else None)
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
            if self._witness_reader is not None:
                self._witness_reader.close()
                self._witness_reader = None
            if self._approval_reader is not None:
                self._approval_reader.close()
                self._approval_reader = None
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
            if self._config['profile'] in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab'}:
                if not self._cleanup_verified:
                    raise IsolationUnavailable('Lab cleanup was not verified')
                if self._lab_receipt is None:
                    context = self._lab_context or {'identity': self.identity, 'connection_count': 0, 'request_count': 0}
                    closure_validator = validate_closure
                    if self._config['profile'] == 'owned_web_lab':
                        from .web_lab_contract import validate_closure as closure_validator
                    elif self._config['profile'] == 'owned_http_headers_lab':
                        from .http_headers_lab_contract import validate_closure as closure_validator
                    elif self._config['profile'] == 'owned_web_tools_lab':
                        from .web_tools_lab_contract import validate_closure as closure_validator
                    elif self._config['profile'] == 'owned_network_tools_lab':
                        from .network_tools_lab_contract import validate_closure as closure_validator
                    self._lab_receipt = closure_validator({**context, 'status': 'closed'}, self.identity, previous=self._lab_context)
                return {**self._lab_receipt, 'identity': self.identity}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
