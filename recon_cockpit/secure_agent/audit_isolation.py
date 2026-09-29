"""Trusted host adapter for a fixed append-only Linux audit worker."""

import array
import os
from pathlib import Path
import select
import socket
import stat
import threading
import time
from uuid import uuid4

from . import audit_protocol as protocol
from .audit import AuditSink, AuditUnavailable
from .execution import ExecutionControl
from .isolation import _namespaces, _runtime_files, _trusted_program
from .planner_isolation import LinuxIsolatedMockProvider
from .routed import _Supervisor


class LinuxAuditSink:
    """Bounded synchronous append interface; a fault permanently closes it.

    Host ownership of the path remains trusted. The worker owns the sole
    retained append descriptor, not approval, policy or execution authority.
    """

    def __init__(self, path, *, launch_witness=False):
        if type(launch_witness) is not bool:
            raise ValueError('invalid_launch_witness_mode')
        self._launch_witness = launch_witness
        self._witness_reader = None
        self._path = Path(path)
        self._identity = str(uuid4())
        self._sequence = 0
        self._closed = False
        self._failed = False
        self._lock = threading.Lock()
        self._channel = self._supervisor = None
        self._checks = None
        self._expires = time.monotonic() + protocol.MAX_LIFETIME
        try:
            self._start()
        except BaseException as exc:
            self._failed = True
            self._cleanup()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise AuditUnavailable('audit_unavailable') from None

    @property
    def boundary_checks(self):
        return None if self._checks is None else dict(self._checks)

    def _command(self, stdlib, files):
        host = _namespaces()
        argv = [_trusted_program('bwrap'), '--unshare-user', '--unshare-net', '--unshare-pid',
                '--unshare-ipc', '--unshare-uts', '--unshare-cgroup', '--uid', '0', '--gid', '0',
                '--cap-drop', 'ALL', '--die-with-parent', '--new-session', '--clearenv',
                '--setenv', 'LC_ALL', 'C', '--chdir', '/', '--proc', '/proc', '--dev', '/dev',
                '--ro-bind', stdlib, stdlib]
        for source, destination in files:
            argv.extend(('--ro-bind', source, destination))
        for name in ('planner_worker', 'audit_worker', 'audit_protocol'):
            argv.extend(('--ro-bind', str(Path(__file__).with_name(name + '.py').resolve()),
                         '/app/' + name + '.py'))
        if self._launch_witness:
            argv.extend(('--ro-bind', str(Path(__file__).with_name('audit_witness.py').resolve()), '/app/audit_witness.py'))
        argv.extend(('--remount-ro', '/proc', '--remount-ro', '/dev', '--remount-ro', '/',
                     '/usr/bin/python3', '-I', '-S', '/app/audit_worker.py', self._identity,
                     *(host[name] for name in ('user', 'net', 'mnt', 'pid'))))
        if self._launch_witness:
            argv.append('launch-witness')
        return argv

    def _start(self):
        LinuxIsolatedMockProvider().check_available()
        control = ExecutionControl(time.monotonic() + 10)
        stdlib, files = _runtime_files('/usr/bin/python3', None, control=control)
        self._supervisor = _Supervisor(protocol.EXCHANGE_SECONDS, 1048576)
        self._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._channel.setblocking(False)
        witness_writer = None
        try:
            if self._launch_witness:
                self._witness_reader, witness_writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                self._witness_reader.shutdown(socket.SHUT_WR)
                witness_writer.shutdown(socket.SHUT_RD)
                self._witness_reader.setblocking(False)
                witness_writer.setblocking(False)
            # Reuse the existing private path, O_NOFOLLOW, mode/link validation
            # and directory fsync. Transfer exactly this descriptor, then close
            # our copy before accepting READY or any producer event.
            with AuditSink(self._path) as source:
                info = os.fstat(source._fd)
                self._file_identity = (info.st_dev, info.st_ino)
                if info.st_size > protocol.MAX_FILE_BYTES:
                    raise AuditUnavailable('audit_file_limit')
                self._process = self._supervisor.launch('worker', self._command(stdlib, files), stdin=child)
                child.close()
                for stream in (self._process.stdout, self._process.stderr):
                    os.set_blocking(stream.fileno(), False)
                initial = {'version': '1', 'writer_id': self._identity, 'device': info.st_dev, 'inode': info.st_ino}
                if witness_writer is None:
                    self._send(protocol.encode(initial), fd=source._fd)
                else:
                    witness_info = os.fstat(witness_writer.fileno())
                    initial['witness'] = [witness_info.st_dev, witness_info.st_ino]
                    self._send(protocol.encode(initial), fd=source._fd, witness_fd=witness_writer.fileno())
                    witness_writer.close()
            ready = self._reply()
            expected = {'version': '1', 'writer_id': self._identity, 'ready': True,
                        'checks': dict.fromkeys(protocol.CHECKS, True)}
            if protocol.encode(ready) != protocol.encode(expected):
                raise AuditUnavailable('audit_invalid_ready')
            self._checks = ready['checks']
            self._verify_path()
        finally:
            if witness_writer is not None:
                witness_writer.close()
            child.close()

    def take_launch_witness(self):
        """Transfer the one receiving endpoint once; no source reset or clone."""
        with self._lock:
            if self._closed or self._failed or self._witness_reader is None:
                raise AuditUnavailable('launch_witness_unavailable')
            reader = self._witness_reader
            info = os.fstat(reader.fileno())
            self._witness_reader = None
            return reader, {'version': '1', 'writer_id': self._identity, 'device': info.st_dev, 'inode': info.st_ino}

    def _send(self, raw, *, fd=None, witness_fd=None):
        if len(raw) > protocol.MAX_PACKET:
            raise AuditUnavailable('audit_packet_limit')
        ancillary = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]
        if witness_fd is not None:
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd, witness_fd]))]
        while True:
            self._supervisor.check()
            try:
                if self._channel.sendmsg([raw], ancillary) != len(raw):
                    raise AuditUnavailable('audit_short_send')
                return
            except BlockingIOError:
                self._supervisor.wait_for(lambda: bool(select.select([], [self._channel], [], 0)[1]))

    def _quiet(self):
        # Reject already-available unsolicited output before releasing an event.
        for stream in (self._process.stdout, self._process.stderr):
            try:
                os.read(stream.fileno(), 1)
            except BlockingIOError:
                continue
            raise AuditUnavailable('audit_unexpected_output_or_exit')
        if self._process.poll() is not None:
            raise AuditUnavailable('audit_worker_exited')

    def _reply(self):
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b'\n' in supervisor.buffers['worker_out']
                            or bool(supervisor.buffers['worker_err'])
                            or bool(supervisor.eof))
        raw = bytes(supervisor.buffers['worker_out'])
        if (supervisor.buffers['worker_err'] or supervisor.eof or len(raw) > 2048
                or not raw.endswith(b'\n') or raw.count(b'\n') != 1):
            raise AuditUnavailable('audit_invalid_reply')
        supervisor.buffers['worker_out'].clear()
        value = protocol.decode(raw[:-1])
        self._quiet()
        return value

    def _verify_path(self):
        info = self._path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != self._file_identity):
            raise AuditUnavailable('audit_file_changed')

    def emit(self, event):
        with self._lock:
            if self._failed or self._closed:
                raise AuditUnavailable('audit_closed')
            try:
                raw = protocol.event_bytes(event)
                sequence = self._sequence + 1
                request = {'version': '1', 'writer_id': self._identity,
                           'sequence': sequence, 'event': event}
                protocol.request(request, self._identity, sequence)
                self._supervisor.deadline = min(self._expires, time.monotonic() + protocol.EXCHANGE_SECONDS)
                self._supervisor.check()
                self._verify_path()
                self._quiet()
                self._send(protocol.encode(request))
                reply = self._reply()
                if protocol.encode(reply) != protocol.encode(protocol.receipt(self._identity, sequence, raw)):
                    raise AuditUnavailable('audit_receipt_mismatch')
                self._verify_path()
                self._sequence = sequence
            except BaseException as exc:
                self._failed = True
                self._cleanup()
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise AuditUnavailable('audit_unavailable') from None

    def _cleanup(self):
        self._closed = True
        self._checks = None
        try:
            if self._channel is not None:
                self._channel.close()
        finally:
            try:
                if self._witness_reader is not None:
                    self._witness_reader.close()
                    self._witness_reader = None
            finally:
                try:
                    if self._supervisor is not None:
                        self._supervisor.close()
                except Exception:
                    raise AuditUnavailable('audit_cleanup_failed') from None

    def close(self):
        with self._lock:
            if self._closed:
                return
            try:
                self._channel.close()
                self._supervisor.deadline = time.monotonic() + protocol.EXCHANGE_SECONDS
                self._supervisor.wait_for(lambda: self._process.poll() is not None and
                                          {'worker_out', 'worker_err'} <= self._supervisor.eof,
                                          worker_may_exit=True)
                if (self._process.returncode != 0 or self._supervisor.buffers['worker_out']
                        or self._supervisor.buffers['worker_err']):
                    raise AuditUnavailable('audit_close_failed')
            except Exception:
                self._failed = True
                raise AuditUnavailable('audit_unavailable') from None
            finally:
                self._cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
