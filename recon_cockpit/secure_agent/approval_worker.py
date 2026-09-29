"""Fixed terminal reviewer. No launch, network, credential or audit capability."""

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
        raise ValueError('inherited_approval_descriptor')
    for fd in (1, 2):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd):
            raise ValueError('invalid_approval_output')
    try:
        fd = os.open('/dev/tty', os.O_RDWR)
    except OSError as exc:
        if exc.errno not in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
            raise
    else:
        os.close(fd)
        raise ValueError('ambient_approval_terminal')


if __name__ == '__main__':
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write('approval_worker_refused\n')
        raise SystemExit(78) from None

import array
import ctypes
import fcntl
import secrets
import select
import socket
import termios
import time

if not __package__:
    sys.path.insert(0, '/app')
    from approval_runtime import approval_protocol as protocol
    from approval_runtime.approvals import ApprovalStore
    import planner_worker as bootstrap
else:
    from . import approval_protocol as protocol, planner_worker as bootstrap
    from .approvals import ApprovalStore


def packet(channel, *, expect_fd=False):
    raw, ancillary, flags, _ = channel.recvmsg(protocol.MAX_PACKET, socket.CMSG_SPACE(16))
    descriptors = []
    try:
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise ValueError('unexpected_approval_ancillary')
            values = array.array('i')
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
        if flags or len(descriptors) != int(expect_fd):
            raise ValueError('invalid_approval_descriptors')
        if not raw and not expect_fd:
            return None, None
        value = protocol.decode(raw)
        return value, descriptors.pop() if expect_fd else None
    finally:
        for fd in descriptors:
            os.close(fd)


def verify_terminal(fd, identity):
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if (not stat.S_ISCHR(info.st_mode) or not os.isatty(fd)
            or [info.st_dev, info.st_ino, info.st_rdev] != identity
            or flags & os.O_ACCMODE != os.O_RDWR or not flags & os.O_NONBLOCK):
        raise ValueError('invalid_approval_terminal')


def seal(fd):
    # Permit only input flushing on the intentional TTY. In particular no
    # TIOCSTI injection, terminal takeover, mode changes or other FD ioctls.
    class Comparison(ctypes.Structure):
        _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                    ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]

    library = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                              ctypes.c_uint, ctypes.POINTER(Comparison)]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise ValueError('approval_seccomp_failed')
    try:
        number = library.seccomp_syscall_resolve_name(b'ioctl')
        if number == -1:
            raise ValueError('approval_seccomp_failed')
        for argument, allowed in ((0, fd), (1, termios.TCFLSH), (2, termios.TCIFLUSH)):
            comparison = Comparison(argument, 1, allowed, 0)  # SCMP_CMP_NE
            if library.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM,
                                              number, 1, ctypes.byref(comparison)) != 0:
                raise ValueError('approval_seccomp_failed')
        if library.seccomp_load(context) != 0:
            raise ValueError('approval_seccomp_failed')
    finally:
        library.seccomp_release(context)
    bootstrap._install_syscall_filter(extra_denied=(
        'open', 'openat', 'openat2', 'creat', 'fcntl',
        'connect', 'bind', 'listen', 'accept', 'accept4', 'sendmsg', 'sendmmsg'))
    for operation in (
        lambda: os.open('/proc/self/fd/' + str(fd), os.O_RDWR),
        lambda: fcntl.fcntl(fd, fcntl.F_SETFL, 0),
        lambda: fcntl.ioctl(fd, termios.TIOCSTI, b'\0'),
        lambda: fcntl.ioctl(1, termios.TCFLSH, termios.TCIFLUSH),
    ):
        try:
            result = operation()
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        else:
            if type(result) is int and result > 2:
                os.close(result)
            raise ValueError('approval_terminal_operation_allowed')


def ready_fd(fd, deadline, *, writing=False):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not any(select.select([] if writing else [fd],
                                               [fd] if writing else [], [], remaining)[:2]):
        raise ValueError('approval_deadline')


def review(fd, action, policy, session_id, deadline):
    canonical = action.to_dict()
    canonical.pop('rationale')
    challenge = 'approve ' + action.digest[:16] + ' ' + secrets.token_hex(16)
    prompt = protocol.encode({'review_exact_action': canonical, 'action_digest': action.digest,
                              'policy_digest': policy.digest, 'policy_version': policy.policy_version,
                              'session_id': session_id}) + (
        "\nType '" + challenge + "' to approve once (blank denies): ").encode('ascii')
    # Pretyped input cannot approve a newly displayed action; the independent
    # nonce also defeats old answers buffered elsewhere in the terminal stack.
    termios.tcflush(fd, termios.TCIFLUSH)
    offset = 0
    while offset < len(prompt):
        ready_fd(fd, deadline, writing=True)
        try:
            written = os.write(fd, prompt[offset:])
        except BlockingIOError:
            continue
        if written <= 0:
            raise ValueError('approval_terminal_closed')
        offset += written
    answer = bytearray()
    while len(answer) < 128:
        ready_fd(fd, deadline)
        try:
            byte = os.read(fd, 1)
        except BlockingIOError:
            continue
        if not byte:
            raise ValueError('approval_terminal_closed')
        if byte == b'\n':
            if time.monotonic() >= deadline:
                raise ValueError('approval_deadline')
            return bytes(answer) == challenge.encode('ascii')
        answer.extend(byte)
    return False


def main():
    fd = None
    witness_channel = None
    try:
        if len(sys.argv) not in (6, 7) or (len(sys.argv) == 7 and sys.argv[6] != 'launch-witness'):
            raise ValueError('invalid_approval_bootstrap')
        witnessed = len(sys.argv) == 7
        _, host = bootstrap._arguments(['three_step', *sys.argv[2:6]])
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError('invalid_approval_channel')
        checks = bootstrap._bootstrap(host)
        channel.settimeout(5)
        if witnessed:
            if __package__:
                from . import approval_witness
            else:
                from approval_runtime import approval_witness
            initial, descriptors = approval_witness.receive(channel, 2)
            fd, witness_fd = descriptors
            witness_channel = approval_witness.endpoint(witness_fd, initial.get('witness'), writer=True)
        else:
            initial, fd = packet(channel, expect_fd=True)
        if protocol.digest(initial) != sys.argv[1]:
            raise ValueError('approval_bootstrap_changed')
        policy = protocol.initial(initial, time.monotonic())
        if ('witness' in initial) != witnessed:
            raise ValueError('approval_witness_mode_changed')
        verify_terminal(fd, initial['terminal'])
        channel.setblocking(False)
        store = ApprovalStore()
        # Warm digest/entropy paths before denying filesystem opens.
        policy.digest
        secrets.token_hex(16)
        seal(fd)
        checks.update(descriptors_private=True, terminal_operations_restricted=True)
        print(protocol.encode({'version': '1', 'bootstrap_digest': sys.argv[1],
                               'ready': True, 'checks': checks}).decode('ascii'), flush=True)
        sequence, reviews, witness_sequence = 1, 0, 0
        while True:
            ready_fd(channel, initial['deadline'])
            value, _ = packet(channel)
            if value is None:
                break
            action = protocol.request(value, initial['broker_id'], initial['session_id'], sequence)
            if value['operation'] == 'review':
                reviews += 1
                if (reviews > protocol.MAX_REVIEWS or value['policy_digest'] != policy.digest
                        or policy.evaluate(action).decision != 'approval_required'):
                    raise ValueError('approval_review_not_allowed')
                result = None
                if review(fd, action, policy, initial['session_id'], initial['deadline']):
                    result = store.issue(action, policy).reference
            else:
                # Burn first even when the requested policy has changed.
                if witnessed:
                    result, grant = store.consume_with_grant(value['reference'], action, policy)
                else:
                    result = store.consume(value['reference'], action, policy)
                if value['policy_digest'] != policy.digest:
                    result = 'approval_policy_changed'
                if witnessed and result is None:
                    proof = approval_witness.witness(initial, action, grant, witness_sequence+1,
                                                     sequence, time.monotonic())
                    encoded = protocol.encode(proof)
                    if os.write(witness_channel.fileno(), encoded) != len(encoded):
                        raise ValueError('approval_witness_short_write')
                    witness_sequence += 1
            if time.monotonic() >= initial['deadline']:
                raise ValueError('approval_deadline')
            print(protocol.encode(protocol.receipt(value, result)).decode('ascii'), flush=True)
            sequence += 1
        return 0
    except Exception:
        sys.stderr.write('approval_worker_refused\n')
        return 78
    finally:
        if witness_channel is not None:
            witness_channel.close()
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
