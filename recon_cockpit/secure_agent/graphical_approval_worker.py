"""Fixed graphical reviewer: its own window, fresh challenge, grants and witness.

The only host-facing operations remain review and consume. This worker has one
intentional trusted local X11 connection; planners/tools never receive it.
"""

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
        raise ValueError('inherited_graphical_approval_descriptor')
    for fd in (1, 2):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd):
            raise ValueError('invalid_graphical_approval_output')
    try:
        fd = os.open('/dev/tty', os.O_RDWR)
    except OSError as exc:
        if exc.errno not in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
            raise
    else:
        os.close(fd)
        raise ValueError('ambient_graphical_terminal')


if __name__ == '__main__':
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write('graphical_approval_worker_refused\n')
        raise SystemExit(78) from None

import array
import secrets
import select
import socket
import time

if not __package__:
    sys.path.insert(0, '/app')
    from approval_runtime import approval_protocol as protocol
    from approval_runtime import graphical_approval_protocol as graphical
    from approval_runtime.approvals import ApprovalStore
    from approval_runtime.graphical_approval_view import ReviewWindow
    import planner_worker as bootstrap
else:
    from . import approval_protocol as protocol, graphical_approval_protocol as graphical
    from . import planner_worker as bootstrap
    from .approvals import ApprovalStore
    from .graphical_approval_view import ReviewWindow


def packet(channel, count=0):
    raw, ancillary, flags, _ = channel.recvmsg(protocol.MAX_PACKET, socket.CMSG_SPACE(256))
    descriptors = []
    try:
        invalid = False
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                invalid = True
                continue
            values = array.array('i')
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
        if invalid or flags or len(descriptors) != count:
            raise ValueError('invalid_graphical_approval_descriptors')
        if not raw and not ancillary and not count:
            return None, []
        value = protocol.decode(raw)
        result, descriptors = descriptors, []
        return value, result
    finally:
        for fd in descriptors:
            os.close(fd)


def ready(channel, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([channel], [], [], remaining)[0]:
        raise ValueError('graphical_approval_deadline')


def seal():
    # Tk has already opened its sole X11 connection, resources and notifier.
    # No new network endpoints, programs or filesystem opens are possible while
    # processing a review. Existing X11 access remains a trusted desktop capability.
    bootstrap._install_syscall_filter(extra_denied=(
        'open', 'openat', 'openat2', 'creat', 'connect', 'bind', 'listen',
        'accept', 'accept4', 'sendmsg', 'sendmmsg', 'ioctl'))
    for path in ('/proc/self/status', '/run/graphical-approval-seal-witness'):
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        else:
            os.close(fd)
            raise ValueError('graphical_approval_filesystem_open_allowed')


def verify_display(initial, channel, witness_channel):
    path = '/tmp/.X11-unix/X' + initial['display'][1:].split('.')[0]
    info = os.lstat(path)
    if (not stat.S_ISSOCK(info.st_mode) or [info.st_dev, info.st_ino] != initial['display_socket']
            or os.environ.get('XAUTHORITY') != graphical.AUTHORITY_PATH
            or os.environ.get('FONTCONFIG_FILE') != graphical.FONTCONFIG_PATH):
        raise ValueError('graphical_display_mount_changed')
    excluded = {channel.fileno(), *(() if witness_channel is None else (witness_channel.fileno(),))}
    display_sockets = 0
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd <= 2 or fd in excluded:
            continue
        try:
            info = os.fstat(fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        if stat.S_ISSOCK(info.st_mode):
            with socket.socket(fileno=os.dup(fd)) as connection:
                if (connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM
                        or connection.getpeername() != path):
                    raise ValueError('graphical_display_peer_changed')
            display_sockets += 1
    if display_sockets != 1:
        raise ValueError('graphical_display_connection_missing')


def main():
    window = witness_channel = None
    descriptors = []
    try:
        if (len(sys.argv) not in {6, 7}
                or (len(sys.argv) == 7 and sys.argv[6] != 'launch-witness')):
            raise ValueError('invalid_graphical_approval_bootstrap')
        witnessed = len(sys.argv) == 7
        _, host = bootstrap._arguments(['three_step', *sys.argv[2:6]])
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError('invalid_graphical_approval_channel')
        bootstrap._private_namespaces(host)
        bootstrap._zero_capabilities()
        bootstrap._no_new_privileges()
        bootstrap._root_read_only()
        channel.settimeout(5)
        initial, descriptors = packet(channel, int(witnessed))
        if protocol.digest(initial) != sys.argv[1]:
            raise ValueError('graphical_approval_bootstrap_changed')
        policy = graphical.initial(initial, time.monotonic())
        if ('witness' in initial) != witnessed:
            raise ValueError('graphical_approval_witness_mode_changed')
        if witnessed:
            if not __package__:
                from approval_runtime import approval_witness
            else:
                from . import approval_witness
            witness_channel = approval_witness.endpoint(descriptors.pop(), initial['witness'], writer=True)
        if os.environ.get('DISPLAY') != initial['display']:
            raise ValueError('graphical_approval_display_changed')
        window = ReviewWindow()
        window.warmup()
        if window._root.winfo_screen() != initial['display']:
            raise ValueError('graphical_approval_display_changed')
        verify_display(initial, channel, witness_channel)
        channel.setblocking(False)
        store = ApprovalStore()
        policy.digest
        secrets.token_hex(16)
        checks = bootstrap._bootstrap(host)
        seal()
        checks.update(descriptors_private=True, display_bound=True, graphical_input_owned=True)
        if set(checks) != graphical.CHECKS:
            raise ValueError('graphical_approval_checks_changed')
        print(protocol.encode({'version': '1', 'bootstrap_digest': sys.argv[1],
                               'ready': True, 'checks': checks}).decode('ascii'), flush=True)
        sequence, reviews, witness_sequence = 1, 0, 0
        while True:
            ready(channel, initial['deadline'])
            value, _ = packet(channel)
            if value is None:
                break
            action = protocol.request(value, initial['broker_id'], initial['session_id'], sequence)
            if value['operation'] == 'review':
                reviews += 1
                if (reviews > protocol.MAX_REVIEWS or value['policy_digest'] != policy.digest
                        or policy.evaluate(action).decision != 'approval_required'):
                    raise ValueError('graphical_approval_review_not_allowed')
                result = None
                if window.review(action, policy, initial['session_id'], initial['deadline'], channel.fileno()):
                    result = store.issue(action, policy).reference
            else:
                result, grant = store.consume_with_grant(value['reference'], action, policy)
                if value['policy_digest'] != policy.digest:
                    result = 'approval_policy_changed'
                if witnessed and result is None:
                    proof = approval_witness.witness(initial, action, grant, witness_sequence + 1,
                                                     sequence, time.monotonic())
                    encoded = protocol.encode(proof)
                    if os.write(witness_channel.fileno(), encoded) != len(encoded):
                        raise ValueError('graphical_approval_witness_short_write')
                    witness_sequence += 1
            if time.monotonic() >= initial['deadline']:
                raise ValueError('graphical_approval_deadline')
            print(protocol.encode(protocol.receipt(value, result)).decode('ascii'), flush=True)
            sequence += 1
        return 0
    except Exception:
        sys.stderr.write('graphical_approval_worker_refused\n')
        return 78
    finally:
        for fd in descriptors:
            os.close(fd)
        if witness_channel is not None:
            witness_channel.close()
        if window is not None:
            window.close()


if __name__ == '__main__':
    raise SystemExit(main())
