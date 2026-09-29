"""Fixed Linux audit writer. Receives one append descriptor, never a path."""

import errno
import os
import stat
import sys


def private_descriptors():
    for name in os.listdir('/proc/self/fd'):
        if int(name) <= 2:
            continue
        try:
            os.fstat(int(name))
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        raise ValueError('inherited_audit_descriptor')
    for fd in (1, 2):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd):
            raise ValueError('invalid_audit_output')
    try:
        fd = os.open('/dev/tty', os.O_RDWR)
    except OSError as exc:
        if exc.errno not in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
            raise
    else:
        os.close(fd)
        raise ValueError('audit_terminal_accessible')


if __name__ == '__main__':
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write('audit_worker_refused\n')
        raise SystemExit(78) from None

import array
from datetime import datetime, timezone
import fcntl
import select
import socket
import time
from uuid import uuid4

if not __package__:
    sys.path.insert(0, '/app')
    import audit_protocol as protocol
    import planner_worker as bootstrap
else:
    from . import audit_protocol as protocol, planner_worker as bootstrap


def packet(channel, *, expect_fd=False):
    raw, ancillary, flags, _ = channel.recvmsg(protocol.MAX_PACKET, socket.CMSG_SPACE(16))
    descriptors = []
    try:
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise ValueError('unexpected_audit_ancillary')
            values = array.array('i')
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
        if flags or len(descriptors) != int(expect_fd):
            raise ValueError('invalid_audit_descriptors')
        if not raw and not expect_fd:
            return None, None
        value = protocol.decode(raw)
        return value, descriptors.pop() if expect_fd else None
    finally:
        for fd in descriptors:
            os.close(fd)


def verify_fd(fd, identity):
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != identity
            or info.st_size > protocol.MAX_FILE_BYTES
            or flags & os.O_ACCMODE != os.O_WRONLY or not flags & os.O_APPEND):
        raise ValueError('invalid_audit_file')


def seal(fd):
    # No pathname lookup or descriptor-mode changes after bootstrap. In
    # particular, /proc/self/fd cannot reopen O_APPEND as a writable random FD.
    libc = bootstrap.ctypes.CDLL(None, use_errno=True)
    bootstrap._install_syscall_filter(extra_denied=(
        'open', 'openat', 'openat2', 'creat', 'truncate', 'ftruncate', 'fcntl', 'ioctl', 'fallocate',
        'chmod', 'fchmod', 'fchmodat', 'fchmodat2', 'chown', 'fchown', 'fchownat', 'lchown',
        'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2',
        'link', 'linkat', 'symlink', 'symlinkat', 'pwrite64', 'pwritev', 'pwritev2',
        'connect', 'bind', 'listen', 'accept', 'accept4', 'sendmsg', 'sendmmsg'))
    for operation in (
        lambda: os.open('/proc/self/fd/' + str(fd), os.O_RDWR),
        lambda: fcntl.fcntl(fd, fcntl.F_SETFL, os.O_APPEND),
        lambda: os.ftruncate(fd, os.fstat(fd).st_size),
        lambda: fcntl.ioctl(fd, 0, 0),
    ):
        try:
            result = operation()
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        else:
            if type(result) is int and result > 2:
                os.close(result)
            raise ValueError('audit_file_operation_allowed')
    bootstrap.ctypes.set_errno(0)
    if libc.fallocate(-1, 0, 0, 0) != -1 or bootstrap.ctypes.get_errno() != errno.EPERM:
        raise ValueError('audit_fallocate_allowed')


def append(fd, event):
    payload = {**event, 'event_schema_version': '1', 'event_id': str(uuid4()),
               'timestamp': datetime.now(timezone.utc).isoformat(),
               'source': 'recon-cockpit.secure-agent'}
    raw = protocol.encode(payload) + b'\n'
    if len(raw) > protocol.MAX_PACKET:
        raise ValueError('audit_record_limit')
    # Nonblocking lock: a hostile/cooperating writer cannot stall this worker.
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        info = os.fstat(fd)
        if (info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_size + len(raw) > protocol.MAX_FILE_BYTES):
            raise ValueError('audit_file_changed_or_full')
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise ValueError('audit_short_write')
            offset += written
        os.fsync(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def main():
    fd = None
    witness_channel = None
    try:
        if len(sys.argv) not in (6, 7) or (len(sys.argv) == 7 and sys.argv[6] != 'launch-witness'):
            raise ValueError('invalid_audit_bootstrap')
        witnessed = len(sys.argv) == 7
        identity = protocol.writer_id(sys.argv[1])
        _, host = bootstrap._arguments(['three_step', *sys.argv[2:6]])
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError('invalid_audit_channel')
        checks = bootstrap._bootstrap(host)
        channel.settimeout(protocol.EXCHANGE_SECONDS)
        if witnessed:
            if __package__:
                from . import audit_witness
            else:
                import audit_witness
            initial, descriptors = audit_witness.receive(channel, 2)
            fd, witness_fd = descriptors
            witness_channel = audit_witness.endpoint(witness_fd, initial.get('witness'), writer=True)
        else:
            initial, fd = packet(channel, expect_fd=True)
        if (set(initial) != {'version', 'writer_id', 'device', 'inode'} | ({'witness'} if witnessed else set())
                or initial['version'] != '1' or initial['writer_id'] != identity
                or type(initial['device']) is not int or type(initial['inode']) is not int):
            raise ValueError('invalid_audit_init')
        verify_fd(fd, (initial['device'], initial['inode']))
        # Set the channel mode before ioctl/fcntl are denied as well. Subsequent
        # waits use select without changing descriptor flags or socket state.
        channel.setblocking(False)
        # Warm lazy datetime formatting before sealing filesystem opens.
        datetime.now(timezone.utc).isoformat()
        seal(fd)
        checks.update(descriptors_private=True, file_operations_blocked=True)
        print(protocol.encode({'version': '1', 'writer_id': identity, 'ready': True,
                               'checks': checks}).decode('ascii'), flush=True)
        deadline = time.monotonic() + protocol.MAX_LIFETIME
        sequence = 1
        witness_sequence = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('audit_lifetime_exceeded')
            if not select.select([channel], [], [], remaining)[0]:
                raise ValueError('audit_lifetime_exceeded')
            value, _ = packet(channel)
            if value is None:
                break
            raw = protocol.request(value, identity, sequence)
            is_intent = witnessed and value['event']['event_type'] == 'execution_started'
            if is_intent:
                # Reject malformed/excess intents before persisting them; issue
                # the timed witness only after the durable append completes.
                proof = audit_witness.witness(value['event'], identity, sequence, witness_sequence+1, time.monotonic())
            append(fd, value['event'])
            if is_intent:
                proof['issued_at'] = time.monotonic()
                encoded = protocol.encode(proof)
                if os.write(witness_channel.fileno(), encoded) != len(encoded):
                    raise ValueError('audit_witness_short_write')
                witness_sequence += 1
            print(protocol.encode(protocol.receipt(identity, sequence, raw)).decode('ascii'), flush=True)
            sequence += 1
        return 0
    except Exception:
        sys.stderr.write('audit_worker_refused\n')
        return 78
    finally:
        if witness_channel is not None:
            witness_channel.close()
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
