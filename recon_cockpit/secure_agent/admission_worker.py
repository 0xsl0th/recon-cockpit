"""Fixed policy/budget admission worker with no launch or consent capability."""

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
        raise ValueError('inherited_admission_descriptor')
    for fd in (1, 2):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd):
            raise ValueError('invalid_admission_output')
    try:
        fd = os.open('/dev/tty', os.O_RDWR)
    except OSError as exc:
        if exc.errno not in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
            raise
    else:
        os.close(fd)
        raise ValueError('admission_terminal_accessible')


if __name__ == '__main__':
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write('launch_admission_refused\n')
        raise SystemExit(78) from None

import array
import fcntl
import secrets
import select
import socket
import time

if not __package__:
    sys.path.insert(0, '/app')
    from admission_runtime import launch_admission as protocol
    import planner_worker as bootstrap
else:
    from . import launch_admission as protocol, planner_worker as bootstrap


def packet(channel):
    raw, ancillary, flags, _ = channel.recvmsg(protocol.MAX_PACKET, socket.CMSG_SPACE(256))
    # No capability transfer exists on either init or operation messages.
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array.array('i')
            descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
            for fd in descriptors:
                os.close(fd)
    if flags or ancillary:
        raise ValueError('unexpected_admission_descriptors')
    return protocol.decode(raw) if raw else None


def seal():
    bootstrap._install_syscall_filter(extra_denied=(
        'open', 'openat', 'openat2', 'creat', 'fcntl', 'ioctl',
        'connect', 'bind', 'listen', 'accept', 'accept4', 'sendmsg', 'sendmmsg'))
    for operation in (
        lambda: os.open('/proc/self/fd/0', os.O_RDONLY),
        lambda: fcntl.fcntl(0, fcntl.F_SETFL, 0),
        lambda: fcntl.ioctl(0, 0, 0),
    ):
        try:
            result = operation()
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        else:
            if type(result) is int and result > 2:
                os.close(result)
            raise ValueError('admission_file_operation_allowed')


def main():
    try:
        if len(sys.argv) != 6:
            raise ValueError('invalid_admission_bootstrap')
        _, host = bootstrap._arguments(['three_step', *sys.argv[2:]])
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError('invalid_admission_channel')
        checks = bootstrap._bootstrap(host)
        channel.settimeout(5)
        initial = packet(channel)
        if protocol.digest(initial) != sys.argv[1]:
            raise ValueError('admission_bootstrap_changed')
        state = protocol.AdmissionState(initial)
        channel.setblocking(False)
        # Warm the fixed digest/entropy paths before denying new opens.
        protocol.digest(initial)
        secrets.token_hex(32)
        seal()
        checks.update(descriptors_private=True, file_operations_blocked=True)
        print(protocol.encode({'version': '1', 'bootstrap_digest': sys.argv[1],
                               'ready': True, 'checks': checks}).decode('ascii'), flush=True)
        while True:
            remaining = initial['deadline'] - time.monotonic()
            if remaining <= 0 or not select.select([channel], [], [], remaining)[0]:
                raise ValueError('admission_session_expired')
            value = packet(channel)
            if value is None:
                break
            outcome = state.handle(value)
            if time.monotonic() >= initial['deadline']:
                raise ValueError('admission_session_expired')
            print(protocol.encode(protocol.receipt(value, outcome)).decode('ascii'), flush=True)
        return 0
    except Exception:
        sys.stderr.write('launch_admission_refused\n')
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
