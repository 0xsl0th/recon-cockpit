"""Host observations of an actual pinned topology worker, never a ledger RPC."""

from copy import deepcopy
import os
from pathlib import Path
import re
import select
import time


def _read(path, limit=4096):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    assert len(raw) <= limit, 'owned process observation bound'
    return raw


def _descendants(pid):
    pending, seen = [pid], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        assert len(seen) <= 256, 'owned process tree bound'
        try:
            for thread in Path(f'/proc/{current}/task').iterdir():
                try:
                    pending.extend(int(value) for value in _read(thread / 'children').split())
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            continue
    return seen - {pid}


def _worker_identity(pid, script):
    root = Path(f'/proc/{pid}')
    command = _read(root / 'cmdline').split(b'\0')
    assert command[0] == b'/usr/bin/python3'
    assert script in command
    raw = _read(root / 'stat')
    # comm may contain spaces or parentheses; the kernel appends the fixed
    # numeric fields only after its final closing parenthesis.
    suffix = raw[raw.rindex(b')') + 2:].split()
    started = int(suffix[19])
    assert started > 0
    namespaces = {name: os.readlink(root / 'ns' / name) for name in ('user', 'net', 'mnt', 'pid')}
    assert all(re.fullmatch(name + r':\[[1-9][0-9]*\]', value) for name, value in namespaces.items())
    return {'pid': pid, 'start_time_ticks': started, 'namespaces': namespaces}


def _ancestry_row(pid):
    raw = _read(Path(f'/proc/{pid}/stat'))
    suffix = raw[raw.rindex(b')') + 2:].split()
    parent, started = int(suffix[1]), int(suffix[19])
    assert parent > 0 and started > 0
    return {'pid': pid, 'parent_pid': parent, 'start_time_ticks': started}


def _identity(pid):
    return _worker_identity(pid, b'/app/recon_cockpit/secure_agent/name_tls_topology_worker.py')


class OwnerPin:
    def _identity(self, pid):
        return _identity(pid)

    def _matches(self, identity, namespaces):
        return identity['namespaces'] == namespaces

    def __init__(self, launcher_pid, namespaces):
        self.descriptor = None
        candidates = []
        try:
            for pid in sorted(_descendants(launcher_pid)):
                try:
                    identity = self._identity(pid)
                except (FileNotFoundError, ProcessLookupError, AssertionError, ValueError):
                    continue
                if not self._matches(identity, namespaces):
                    continue
                descriptor = os.pidfd_open(pid)
                try:
                    assert self._identity(pid) == identity
                    poller = select.poll()
                    poller.register(descriptor, select.POLLIN)
                    assert not poller.poll(0), 'actual topology owner already exited'
                    candidates.append((descriptor, identity))
                except BaseException:
                    os.close(descriptor)
                    raise
            assert len(candidates) == 1, 'actual topology worker identity is not unique/live'
            self.descriptor, self.identity = candidates.pop()
        finally:
            for descriptor, _ in candidates:
                os.close(descriptor)

    def observe(self, *, alive):
        assert self.descriptor is not None
        poller = select.poll()
        poller.register(self.descriptor, select.POLLIN)
        ready = poller.poll(0)
        assert all(flags & select.POLLIN and not flags & ~(select.POLLIN | select.POLLHUP)
                   for _, flags in ready), 'unexpected owner pidfd state'
        if alive:
            assert not ready, 'actual topology owner exited while launcher survived'
            assert self._identity(self.identity['pid']) == self.identity, 'actual topology owner identity changed'
            assert not poller.poll(0), 'actual topology owner exited during observation'
            return {**deepcopy(self.identity), 'pidfd_readable': False, 'proc_absent': False,
                    'identity_source': 'current_proc'}
        proc = Path(f"/proc/{self.identity['pid']}")
        deadline = time.monotonic() + 3
        while (not ready or proc.exists()) and time.monotonic() < deadline:
            ready = poller.poll(50)
            if ready and proc.exists():
                time.sleep(.01)
        assert ready and all(flags & select.POLLIN and not flags & ~(select.POLLIN | select.POLLHUP)
                             for _, flags in ready) and not proc.exists(), 'actual topology owner was not reaped'
        return {**deepcopy(self.identity), 'pidfd_readable': True, 'proc_absent': True,
                'identity_source': 'retained_pin'}

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


class ApprovalPin(OwnerPin):
    """Pin the actual approval Python payload, separately from its bwrap PID."""

    def _identity(self, pid):
        return _worker_identity(pid, b'/app/approval_runtime/approval_worker.py')

    def _matches(self, identity, namespaces):
        return all(value != os.readlink('/proc/self/ns/' + name)
                   for name, value in identity['namespaces'].items())

    def __init__(self, supervised_pid):
        self.supervised_pid = supervised_pid
        super().__init__(supervised_pid, None)

    def binding(self, initial, control, supervised_start_time_ticks):
        """Retain the observed broker bootstrap and current supervised ancestry."""
        from recon_cockpit.secure_agent import approval_protocol
        control.check()
        before = self.observe(alive=True)
        host = {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'net', 'mnt', 'pid')}
        commitment = approval_protocol.digest(initial)
        expected = ['/usr/bin/python3', '-I', '-S', '/app/approval_runtime/approval_worker.py',
                    commitment, *(host[name] for name in ('user', 'net', 'mnt', 'pid')), 'launch-witness']
        command_path = Path(f"/proc/{before['pid']}/cmdline")
        command = _read(command_path)
        assert command == b'\0'.join(value.encode('ascii') for value in expected) + b'\0', 'approval bootstrap argv changed'
        rows, current = [], before['pid']
        while len(rows) < 16:
            control.check()
            assert current not in {row['pid'] for row in rows}, 'approval ancestry cycle'
            row = _ancestry_row(current)
            rows.append(row)
            if current == self.supervised_pid:
                break
            current = row['parent_pid']
        assert rows[-1]['pid'] == self.supervised_pid and rows[-1]['parent_pid'] == os.getpid(), 'approval supervised ancestry changed'
        assert rows[-1]['start_time_ticks'] == supervised_start_time_ticks, 'approval supervised process changed'
        assert rows[0]['start_time_ticks'] == before['start_time_ticks']
        assert all(parent['start_time_ticks'] <= child['start_time_ticks']
                   for child, parent in zip(rows, rows[1:])), 'approval ancestry start order changed'
        for row in rows:
            control.check()
            assert _ancestry_row(row['pid']) == row, 'approval ancestry changed during observation'
        assert _read(command_path) == command and self.observe(alive=True) == before
        control.check()
        return {'bootstrap_sha256': commitment, 'argv': expected, 'host_namespaces': host,
                'observer_pid': os.getpid(), 'ancestry': rows}


def acknowledged_owner(session, *, alive):
    result = session.outcomes[-1]['untrusted_result']
    namespaces = result['name_tls_topology']['owner_namespaces']
    pin = getattr(session, '_actual_topology_pin', None)
    if pin is None:
        assert alive, 'closed owner lacks an earlier live process pin'
        pin = OwnerPin(session.backend._process.pid, namespaces)
        session._actual_topology_pin = pin
        session.stack.callback(pin.close)
    assert pin.identity['namespaces'] == namespaces
    return pin.observe(alive=alive)
