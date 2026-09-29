"""Fixed confined launcher: owns nested admission and fresh fixture executors."""

import os
import sys
import errno
import stat

ENTRY_DESCRIPTORS_VERIFIED = False
if __name__ == '__main__':
    try:
        # Check inherited capabilities before ctypes/libffi loads its own
        # runtime descriptor, as in the admission and approval bootstraps.
        for name in os.listdir('/proc/self/fd'):
            if int(name) <= 2:
                continue
            try:
                os.fstat(int(name))
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            raise ValueError('inherited_launcher_descriptor')
        if any(not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd) for fd in (1, 2)):
            raise ValueError('invalid_launcher_output')
        try:
            terminal = os.open('/dev/tty', os.O_RDWR)
        except OSError as exc:
            if exc.errno not in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
                raise
        else:
            os.close(terminal)
            raise ValueError('launcher_terminal_accessible')
        ENTRY_DESCRIPTORS_VERIFIED = True
    except Exception:
        sys.stderr.write('fixture_launcher_refused\n')
        raise SystemExit(78) from None

if not __package__:
    sys.path.insert(0, '/app')
    from recon_cockpit.secure_agent import launcher_protocol as protocol
    from recon_cockpit.secure_agent import launch_admission as admission, planner_worker as bootstrap
    from recon_cockpit.secure_agent.admission_worker import packet
    from recon_cockpit.secure_agent.admission_isolation import LinuxLaunchAdmission
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.isolation import LinuxFixtureBackend, _capture_bounded, _namespaces
    from recon_cockpit.secure_agent.models import parse_policy
else:
    from . import launcher_protocol as protocol, launch_admission as admission, planner_worker as bootstrap
    from .admission_worker import packet
    from .admission_isolation import LinuxLaunchAdmission
    from .execution import ExecutionControl
    from .isolation import LinuxFixtureBackend, _capture_bounded, _namespaces
    from .models import parse_policy

from dataclasses import dataclass
from pathlib import Path
import hashlib
import resource
import secrets
import select
import socket
import time
from contextlib import nullcontext


@dataclass(frozen=True)
class _Limits:
    max_steps: int
    max_runtime_seconds: int
    max_output_bytes: int


class _NestedAdmission(LinuxLaunchAdmission):
    def __init__(self, config, closure):
        super().__init__(parse_policy(config['policy']), config['session_id'],
                         _Limits(**config['limits']), execute=config['execute'], profile=config['profile'], case=config['case'])
        self._closure = closure

    def _runtime(self, control):
        control.check()
        return self._closure['stdlib'], [(p, p) for p in self._closure['files']
                                        if p not in {'/usr/bin/bwrap', '/usr/sbin/nft', '/usr/bin/nsenter'}]


def boundary(host):
    if (not ENTRY_DESCRIPTORS_VERIFIED or sys.platform != 'linux' or os.getuid() <= 0 or os.getgid() <= 0
            or any(os.readlink('/proc/self/ns/' + name) == identity for name, identity in host.items())):
        raise ValueError('invalid_launcher_namespaces')
    for kind, current in (('uid', os.getuid()), ('gid', os.getgid())):
        rows = [list(map(int, row.split())) for row in Path('/proc/self/' + kind + '_map').read_text().splitlines()]
        if len(rows) != 1 or rows[0][0] != current or rows[0][2] != 1:
            raise ValueError('invalid_launcher_identity')
    if [name for _, name in socket.if_nameindex()] != ['lo']:
        raise ValueError('invalid_launcher_network')
    bootstrap._zero_capabilities()
    bootstrap._no_new_privileges()
    bootstrap._root_read_only()
    for kind, cap in ((resource.RLIMIT_AS, 256*1024*1024), (resource.RLIMIT_CPU, 30),
                      (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_CORE, 0),
                      (resource.RLIMIT_FSIZE, 1048576), (resource.RLIMIT_NPROC, 64)):
        resource.setrlimit(kind, (cap, cap))
    # Unlike the admission worker, this trusted process must create children and
    # nested namespaces. It has no host network or filesystem to delegate.
    return dict.fromkeys(protocol.CHECKS, True)


def execute(action, config, closure, control, snapshot):
    control.check()
    nonce = secrets.token_hex(32)
    policy = parse_policy(config['policy'])
    if policy.evaluate(action).decision == 'deny':
        raise ValueError('launcher_policy_denied')
    envelope = {'schema_version': '1', 'mode': config['profile'], 'execute': True,
        'session_id': config['session_id'], 'nonce': nonce, 'sequence': snapshot['executions_reserved'],
        'action': action.to_dict(), 'action_digest': action.digest, 'policy': policy.to_dict(),
        'policy_digest': policy.digest, 'limits': config['limits'], 'limits_digest': admission.digest(config['limits']),
        'deadline': control.deadline, 'output_reserved_before': snapshot['output_bytes_reserved'] - action.parameters.max_output_bytes,
        'output_reserved_after': snapshot['output_bytes_reserved'], 'host_namespaces': _namespaces()}
    raw = admission.encode(envelope)
    argv = LinuxFixtureBackend(verify_boundary=True)._command(
        closure['stdlib'], [(p, p) for p in closure['files'] if p != '/usr/bin/bwrap'])
    directory = Path(__file__).parent
    mounts = []
    # Reuse the established one-launch verifier, without controller/approval or
    # admission modules in the fresh executor's filesystem.
    for name, destination in (('models', '/app/recon_cockpit/secure_agent/models.py'),
                              ('executor_worker', '/app/executor_worker.py')):
        mounts += ['--ro-bind', str(directory / (name+'.py')), destination]
    index = argv.index('--remount-ro')
    argv[index:index] = mounts
    argv[-4:] = ['/usr/bin/python3', '-I', '-S', '/app/executor_worker.py', nonce, hashlib.sha256(raw).hexdigest()]
    code, stdout, stderr, reason = _capture_bounded(argv, raw, action.parameters.timeout_seconds+8,
        action.parameters.max_output_bytes*6+16384, control=control)
    control.check()
    if reason is not None:
        raise ValueError('launcher_executor_incomplete')
    if code != 0 or stderr:
        raise ValueError('launcher_executor_failed')
    result = protocol.decode(stdout)
    checks = {'forbidden_ip_blocked', 'forbidden_port_blocked', 'namespace_creation_blocked', 'capabilities_dropped'}
    if (type(result.get('boundary_checks')) is not dict or set(result['boundary_checks']) != checks
            or any(value is not True for value in result['boundary_checks'].values())):
        raise ValueError('launcher_executor_boundary_failed')
    result['backend'] = protocol.PROFILES[config['profile']]
    return protocol.result(result, config)


def main():
    try:
        if len(sys.argv) != 6:
            raise ValueError('invalid_launcher_bootstrap')
        _, host = bootstrap._arguments(['three_step', *sys.argv[2:]])
        checks = boundary(host)
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise ValueError('invalid_launcher_channel')
        channel.settimeout(5)
        init = packet(channel)
        if admission.digest(init) != sys.argv[1]:
            raise ValueError('launcher_bootstrap_changed')
        config = protocol.initial(init, time.monotonic())
        if not config['execute']:
            raise ValueError('launcher_dry_run')
        control = ExecutionControl(init['deadline'])
        channel.setblocking(False)
        owned = None
        if config['profile'] == 'owned_lab':
            from recon_cockpit.secure_agent.owned_launcher_runtime import ConfinedOwnedBackend
            owned = ConfinedOwnedBackend(config, init['runtime'])
        with _NestedAdmission(config, init['runtime']) as gate, (owned.lab if owned is not None else nullcontext()):
            print(protocol.encode({'version': '1', 'ready': True, 'bootstrap_digest': sys.argv[1], 'checks': checks}).decode(), flush=True)
            sequence = 1
            while True:
                if not select.select([channel], [], [], control.remaining())[0]:
                    raise ValueError('launcher_session_expired')
                value = packet(channel)
                if value is None:
                    break
                action = protocol.request(value, config, sequence)
                sequence += 1
                policy = parse_policy(config['policy'])
                granted = gate.admit(action, policy, control=control)
                if granted['reason'] is not None or gate.redeem(granted['permit'], action, policy, control=control)['reason'] is not None:
                    raise ValueError('launcher_admission_denied')
                result = (owned.run(action, policy, control=control) if owned is not None else
                          execute(action, config, init['runtime'], control, gate.snapshot))
                if owned is not None and dict(owned.snapshot) != dict(gate.snapshot):
                    raise ValueError('owned_launcher_reservations_changed')
                control.check()
                print(protocol.encode(protocol.receipt(value, result, gate.snapshot)).decode(), flush=True)
        return 0
    except Exception:
        sys.stderr.write('fixture_launcher_refused\n')
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
