"""Trusted orchestration of the fixed owned engagement process graph.

The host supplies no approval, durable witness, reservation, or release claim.
Those decisions remain on the inherited channels of their isolated owners.
"""

from copy import deepcopy
import base64
import os
from pathlib import Path
import stat
import threading
import time

from . import engagement_live_contract as c
from .execution import ExecutionControl
from .models import parse_action, parse_policy


class _HostEvidenceBudget:
    """One host allocation across all producers and sequential broker owners."""

    def __init__(self):
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._pending = {}
        self._rows = []
        self._bytes = 0
        self._supervision = 0
        self._session_owners = []

    def _check(self):
        if self._pid != os.getpid():
            c.fail('foreign_owner')

    def _attach_session(self, session):
        self._check()
        with self._lock:
            prior = tuple(self._session_owners)
        if len(prior) >= 2 or any(not owner._verified_reaped() for owner in prior):
            c.fail('cleanup_incomplete')
        with self._lock:
            if tuple(self._session_owners) != prior:
                c.fail('cleanup_incomplete')
            self._session_owners.append(session)

    def reserve(self, *, kind, maximum_bytes, maximum_rows, control):
        from .engagement_live_approval import _bounded_lock

        self._check()
        if kind not in ('supervision_projection', 'other_host'):
            c.fail('invalid_input')
        c.integer(maximum_bytes, 1, 3072 if kind == 'supervision_projection' else 262144)
        # Each ticket describes one actual observation, not an arbitrary batch.
        c.integer(maximum_rows, 1, 1)
        with _bounded_lock(self._lock, control):
            reserved_bytes = sum(row['bytes'] for row in self._pending.values())
            reserved_supervision = sum(row['kind'] == 'supervision_projection'
                                       for row in self._pending.values())
            if (self._bytes + reserved_bytes + maximum_bytes > 262144
                    or len(self._rows) + len(self._pending) + 1 > 128
                    or (kind == 'supervision_projection'
                        and self._supervision + reserved_supervision + 1 > 96)):
                c.fail('limit_exceeded')
            ticket = object()
            self._pending[ticket] = {'kind': kind, 'bytes': maximum_bytes,
                                     'request': None, 'row': None}
            return ticket

    @staticmethod
    def _copy_row(row):
        if type(row) is not dict or type(row.get('kind')) is not str:
            c.fail('evidence_invalid')
        selected = deepcopy(row)
        # Charge the maximum eventual combined host sequence width now.
        selected['row_sequence'] = 128
        raw = c.canonical(selected, max_bytes=262144)
        return c.decode(raw, max_bytes=262144), len(raw) + 1

    @staticmethod
    def _request_identity(row):
        selected = deepcopy(row)
        selected.pop('observed_at_ns', None)
        data = selected.get('data')
        if selected['kind'] == 'supervision_projection' and type(data) is dict:
            data.pop('reply', None)
            data.pop('local_error', None)
        elif selected['kind'] == 'capability_projection' and type(data) is dict:
            for key in ('reply', 'reply_projection_sha256',
                        'original_reply_sha256', 'original_reply_bytes'):
                data.pop(key, None)
        return selected

    def record_request(self, ticket, row):
        self._check()
        selected, size = self._copy_row(row)
        identity = self._request_identity(selected)
        with self._lock:
            pending = self._pending.get(ticket)
            if (pending is None or pending['row'] is not None or size > pending['bytes']
                    or (selected['kind'] == 'supervision_projection')
                       != (pending['kind'] == 'supervision_projection')):
                c.fail('evidence_invalid')
            pending['request'], pending['row'] = identity, selected

    def finalize(self, ticket, row):
        self._check()
        selected, size = self._copy_row(row)
        identity = self._request_identity(selected)
        with self._lock:
            pending = self._pending.get(ticket)
            if (pending is None or size > pending['bytes']
                    or (selected['kind'] == 'supervision_projection')
                       != (pending['kind'] == 'supervision_projection')
                    or (pending['request'] is not None and pending['request'] != identity)
                    or (pending['row'] is not None
                        and selected['observed_at_ns'] < pending['row']['observed_at_ns'])):
                c.fail('evidence_invalid')
            self._rows.append(selected)
            self._bytes += size
            self._supervision += pending['kind'] == 'supervision_projection'
            del self._pending[ticket]

    def release(self, ticket):
        self._check()
        with self._lock:
            pending = self._pending.get(ticket)
            if pending is None or pending['row'] is not None:
                c.fail('evidence_invalid')
            del self._pending[ticket]

    def snapshot(self):
        self._check()
        with self._lock:
            return {'rows': deepcopy(self._rows + [row['row'] for row in self._pending.values()
                                                   if row['row'] is not None]),
                    'unresolved_tickets': len(self._pending),
                    'reserved_bytes': sum(row['bytes'] for row in self._pending.values()),
                    'reserved_rows': len(self._pending)}


class _CleanupEpoch:
    """The first stop fixes cleanup time; no caller can restart the clock."""

    def __init__(self, control, *, stop_event=None, on_stop=None):
        self._pid = os.getpid()
        self._bound_ns = int(control.deadline * c.SECOND)
        self._lock = threading.Lock()
        self._value = None
        self._stop_event = threading.Event() if stop_event is None else stop_event
        self._on_stop = on_stop

    @property
    def stopped(self):
        return self._stop_event.is_set()

    def stop(self, *, bound_deadline_ns=None):
        if self._pid != os.getpid():
            c.fail('foreign_owner')
        now = time.monotonic_ns()
        bound = self._bound_ns
        if bound_deadline_ns is not None:
            bound = min(bound, c.integer(bound_deadline_ns, 1, c.INTEGER_MAX))
        with self._lock:
            first = self._value is None
            if first:
                self._value = {'first_stop_requested_at_ns': now,
                               'deadline_ns': min(bound, now + 2 * c.SECOND)}
                self._stop_event.set()
            else:
                self._value['deadline_ns'] = min(self._value['deadline_ns'], bound)
        # The stop fence is already visible to every work control. Interrupting
        # a peer may clamp this epoch again, so callbacks run outside its lock.
        if first and self._on_stop is not None:
            self._on_stop()
        with self._lock:
            return dict(self._value)

    def snapshot(self):
        if self._pid != os.getpid():
            c.fail('foreign_owner')
        with self._lock:
            return None if self._value is None else dict(self._value)


class EngagementSession:
    @classmethod
    def start(cls, store_directory, audit_path, *, review_mode, control):
        return cls._start_with_host_budget(store_directory, audit_path,
            review_mode=review_mode, control=control, host_evidence_budget=_HostEvidenceBudget())

    @classmethod
    def _start_with_host_budget(cls, store_directory, audit_path, *, review_mode,
                               control, host_evidence_budget):
        from . import engagement_live_runtime as runtime
        from .engagement_live_broker import EngagementBroker, preallocate_role_bundle
        from .engagement_live_audit import EngagementAuditService

        if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                or review_mode not in {'terminal', 'graphical_v1'}):
            c.fail('invalid_input')
        control.check()
        if type(host_evidence_budget) is not _HostEvidenceBudget:
            c.fail('invalid_input')
        host_evidence_budget._check()
        self = cls.__new__(cls)
        self._pid = os.getpid()
        self._control = control
        self._mode = review_mode
        self._store_directory = store_directory
        self._audit_path = audit_path
        self._runtime = None
        self._bundle = self._broker = self._audit = None
        self._monitor_thread = None
        self._stop = threading.Event()
        self._closing = threading.Event()
        self._close_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._slot_locks = (threading.Lock(), threading.Lock())
        self._sessions = {}
        self._used_slots = set()
        self._operations = {}
        self._roles = []
        self._readiness = []
        self._cleanup_receipts = []
        self._startup_observations = []
        self._failure = None
        self._cleanup = None
        self._closed = False
        self._startup_quiesced = False
        self._started_at_ns = time.monotonic_ns()
        self._observer_rows = []
        self._child_slots = []
        self._unstarted_supervisors = []
        self._remaining_channels_closed = False
        self._host_evidence_budget = host_evidence_budget
        self._cleanup_epoch = _CleanupEpoch(control, stop_event=self._stop, on_stop=self._request_stop)
        try:
            self._host_evidence_budget._attach_session(self)
            self._runtime = runtime.inspect_runtime(control)
            self._bundle = preallocate_role_bundle(review_mode)
            self._broker = EngagementBroker(runtime=self._runtime, store_directory=store_directory,
                                             control=control, role_bundle=self._bundle,
                                             cleanup_epoch=self._cleanup_epoch)
            self._roles.append(self._broker)
            self._broker_ready = self._broker.start()
            self._readiness.append(self._broker_ready['readiness'])
            for slot, allocated in zip(self._bundle.slots, self._broker_ready['allocated_slots']):
                for declaration in slot.child_slot_bindings:
                    self._child_slots.append({'schema_version': '1',
                        'broker_id': self._broker_ready['broker_id'],
                        'session_id': allocated['session_id'], 'launcher_id': slot.launcher_id,
                        **declaration, 'prepared_sha256': None, 'bootstrap': None, 'entry_sha256': None})
            self._audit = EngagementAuditService(audit_path, runtime=self._runtime,
                                                 role_bundle=self._bundle, control=control,
                                                 cleanup_epoch=self._cleanup_epoch)
            self._roles.append(self._audit)
            self._audit.start()
            self._broker.observe_audit(self._audit.readiness)
            self._check()
            self._monitor_thread = threading.Thread(target=self._monitor,
                name='engagement-live-lifecycle', daemon=True)
            self._monitor_thread.start()
            return self
        except BaseException as error:
            self._remember_failure(error)
            try:
                self.close()
            except BaseException as cleanup_error:
                error.cleanup_error = cleanup_error
            # An owner is retained for diagnostics even when startup produced
            # only partial observations. It is never represented as READY.
            error.engagement_session = self
            raise

    def _owner_check(self):
        if self._pid != os.getpid():
            c.fail('foreign_owner')

    def _check(self, control=None):
        self._owner_check()
        if control is not None and control is not self._control:
            c.fail('invalid_input')
        if self._closed or self._stop.is_set() or self._closing.is_set():
            c.fail('session_unavailable')
        self._control.check()

    def _remember_failure(self, error):
        if self._failure is None:
            self._failure = error
        receipt = getattr(error, 'startup_cleanup', None)
        if receipt is None:
            receipt = getattr(error, 'cleanup', None)
        if receipt is not None and receipt not in self._cleanup_receipts:
            self._cleanup_receipts.append(receipt)
        observation = getattr(error, 'startup_observation', None)
        if observation is not None:
            self._startup_observations.append(observation)

    def _supervisor_failed(self, error):
        # This fixed notification may run on a supervisor. It must never join
        # that thread or acquire a Session operation/cleanup lock.
        self._cleanup_epoch.stop()
        self._remember_failure(error)
        self._stop.set()

    def _request_stop(self):
        """Publish the stop fence and interrupt peers without waiting for locks."""
        self._owner_check()
        self._stop.set()
        for role in list(self._roles):
            if role is self._broker:
                continue
            interrupt = getattr(role, '_interrupt', None)
            if interrupt is not None:
                try:
                    interrupt()
                except BaseException as error:
                    self._remember_failure(error)

    def _session(self, session_id):
        c.uuid(session_id)
        with self._state_lock:
            row = self._sessions.get(session_id)
        if row is None or row['stopped']:
            c.fail('session_unavailable')
        return row

    def _register(self, row, role, owner, readiness):
        self._roles.append(owner)
        row[role] = owner
        self._readiness.append(readiness)
        self._broker.observe_role(row['ingress'], role, readiness)

    def open_session(self, *, ingress=0):
        self._check()
        try:
            return self._open_session(ingress=ingress)
        except BaseException as error:
            self._remember_failure(error)
            try:
                self.close()
            except BaseException as cleanup_error:
                error.cleanup_error = cleanup_error
            raise

    def _open_session(self, *, ingress=0):
        from .engagement_live_endpoint import prepare_endpoint
        from .engagement_live_launcher import EngagementLauncher
        from .engagement_live_approval import EngagementApprovalService
        from .engagement_live_approval import _clipped_control, _bounded_lock

        self._check()
        c.integer(ingress, 0, 1)
        startup = _clipped_control(self._control, int(self._control.deadline*c.SECOND),
                                   self._stop, self._cleanup_epoch)
        # The same finite setup slot covers persistent namespace/nft builders
        # and later child construction. Two API submitters cannot create a
        # second helper outside the explicit process-graph bound.
        with _bounded_lock(self._slot_locks[ingress], startup), \
                _bounded_lock(self._bundle._child_setup_lock, startup):
            self._check()
            with self._state_lock:
                if ingress in self._used_slots:
                    c.fail('limit_exceeded')
                self._used_slots.add(ingress)
            peers = None
            try:
                opened = c.validate_session_opened(self._broker.open_session(ingress=ingress))
                binding = opened['binding']
                slot = self._bundle.slots[ingress]
                allocated = self._broker_ready['allocated_slots'][ingress]
                if (binding['session_id'] != allocated['session_id']
                        or binding['reviewer_id'] != slot.reviewer_id
                        or binding['broker_id'] != self._broker_ready['broker_id']
                        or binding['ledger_owner_id'] != self._broker_ready['ledger_owner_id']
                        or opened['roe'] != self._broker_ready['roe']
                        or opened['scope'] != self._broker_ready['scope']
                        or opened['policy'] != self._broker_ready['policy']):
                    c.fail('invalid_prepared')
                row = {'opened': opened, 'ingress': ingress, 'stopped': False,
                       'endpoint': None, 'launcher': None, 'reviewer': None}
                with self._state_lock:
                    self._sessions[binding['session_id']] = row
                peers = slot.take_endpoint_bootstrap()
                endpoint_peers = {name: peers.pop(name) for name in ('host', 'child', 'broker_control')}
                endpoint_peers['endpoint_id'] = slot.endpoint_id
                arm = peers.pop('launcher_arm')
                endpoint = prepare_endpoint(runtime=self._runtime, session_binding=opened,
                    broker_peer=endpoint_peers, arm_peer=arm, control=_clipped_control(
                        self._control, binding['session_deadline_ns'], self._stop, self._cleanup_epoch))
                self._register(row, 'endpoint', endpoint, endpoint.ready)
                launcher = EngagementLauncher(self._runtime, endpoint=endpoint, role_slot=slot,
                    host_evidence_budget=self._host_evidence_budget,
                    cleanup_epoch=self._cleanup_epoch, failure_sink=self._supervisor_failed)
                # Register ownership before any launch can partially succeed.
                self._roles.append(launcher)
                row['launcher'] = launcher
                self._check()
                launcher.start(opened, self._bundle, self._control)
                self._readiness.append(launcher.readiness)
                self._broker.observe_role(ingress, 'launcher', launcher.readiness)
                endpoint.close_namespaces()
                reviewer = EngagementApprovalService(parse_policy(opened['policy']), binding['session_id'],
                    frontend=self._mode, session_binding=opened, runtime_manifest=self._runtime,
                    witness_slot=slot, control=self._control,
                    host_evidence_budget=self._host_evidence_budget,
                    cleanup_epoch=self._cleanup_epoch, failure_sink=self._supervisor_failed)
                self._roles.append(reviewer)
                row['reviewer'] = reviewer
                self._check()
                reviewer.start()
                self._readiness.append(reviewer.readiness)
                self._broker.observe_role(ingress,
                    'terminal' if self._mode == 'terminal' else 'graphical', reviewer.readiness)
                self._check()
                return deepcopy(opened)
            except BaseException as error:
                self._remember_failure(error)
                # Do not call close while holding this slot's startup lock.
                # The monitor or the caller's finally block owns total cleanup.
                self._cleanup_epoch.stop()
                self._stop.set()
                self._interrupt_roles(self._roles)
                raise
            finally:
                if peers is not None:
                    for peer in peers.values():
                        peer.close()

    def prepare(self, session_id, slot, *, ingress=0):
        self._check()
        row = self._session(session_id)
        reply = self._broker.prepare(session_id, slot, ingress=ingress)
        value = c.validate_prepared_context(reply['prepared'], row['opened'])
        if value['envelope']['slot'] != slot:
            c.fail('invalid_prepared')
        dispatch_id = value['envelope']['dispatch_id']
        with self._state_lock:
            if dispatch_id in self._operations or len(self._operations) >= 4:
                c.fail('invalid_prepared')
            self._operations[dispatch_id] = {'session': row['opened'], 'prepared': value,
                'result': None, 'client': None, 'meter': None, 'host_capture': None,
                'elapsed_ms': dict.fromkeys(('review', 'admission', 'native', 'parser', 'cleanup', 'action'))}
        row['launcher'].prepare(value, self._control)
        self._check()
        return deepcopy(value)

    def _prepared(self, value):
        value = c.validate_prepared(value)
        row = self._session(value['envelope']['session_id'])
        with self._state_lock:
            operation = self._operations.get(value['envelope']['dispatch_id'])
        if operation is None or operation['prepared'] != value:
            c.fail('invalid_prepared')
        c.validate_prepared_context(value, row['opened'])
        return value, row, operation

    def review(self, prepared, *, control):
        self._check(control)
        prepared, row, operation = self._prepared(prepared)
        began = time.monotonic_ns()
        try:
            return row['reviewer'].review(parse_action(prepared['action']),
                parse_policy(prepared['policy']), prepared['envelope'], control=control)
        finally:
            operation['elapsed_ms']['review'] = (time.monotonic_ns() - began) // 1000000

    def execute(self, prepared, reference, *, ingress=0, control):
        from .engagement_live_witness import started_event

        self._check(control)
        prepared, row, operation = self._prepared(prepared)
        if type(reference) is not str:
            c.fail('approval_unknown_or_replayed')
        consumed = row['reviewer'].consume(reference, parse_action(prepared['action']),
            parse_policy(prepared['policy']), prepared['envelope'], control=control)
        if not consumed['accepted']:
            c.fail('approval_unknown_or_replayed')
        # Original exact started event is fsynced by the isolated audit owner.
        # The broker requires its independent direct witness for this sequence.
        receipt = self._audit.emit(started_event(prepared), control=control)
        self._check(control)
        result = c.validate_live_result(self._broker._dispatch_with_control(c.prepared_digest(prepared),
            consumed['reference_sha256'], consumed['consume_sequence'], receipt['sequence'],
            ingress=ingress, control=control))
        if (result['session_id'] != prepared['envelope']['session_id']
                or result['dispatch_id'] != prepared['envelope']['dispatch_id']):
            c.fail('invalid_frame')
        with self._state_lock:
            # A missing reply stays null. An actual known refusal/uncertainty is
            # retained verbatim, even when the action already consumed quota.
            operation['result'] = result
        self._check(control)
        return deepcopy(result)

    def cancel(self, session_id):
        self._check()
        row = self._session(session_id)
        row['stopped'] = True
        self._cleanup_epoch.stop()
        self._interrupt_roles([row[key] for key in ('reviewer', 'launcher', 'endpoint')])
        try:
            return self._broker.cancel(session_id)
        finally:
            self._stop.set()

    def revoke(self, *, expected_revision, expected_generation, event_id):
        self._check()
        return self._broker.revoke(expected_revision=expected_revision,
                                  expected_generation=expected_generation, event_id=event_id)

    def snapshot(self):
        self._check()
        return self._broker.snapshot()

    def _verified_reaped(self):
        """Packaging can retain a timed-out cleanup only after actual reaping."""
        if not self._closed or self._cleanup is None or not self._startup_quiesced:
            return False
        if self._child_slots and not self._remaining_channels_closed:
            return False
        monitor = self._monitor_thread
        if monitor is not None and monitor is not threading.current_thread() and monitor.is_alive():
            return False
        for session in self._sessions.values():
            launcher = session['launcher']
            if launcher is not None and not launcher.supervisor_resolved:
                return False
        reaped = set()
        for receipt in self._cleanup_receipts:
            if not receipt['descriptors_closed']:
                return False
            for process in receipt['processes']:
                if (not process['exit_observed'] or not process['reaped_observed']
                        or process['wrapper_pid'] is None or process['wrapper_returncode'] is None
                        or process['pid'] is None or process['start_time_ticks'] is None):
                    return False
                reaped.add((process['pid'],process['start_time_ticks']))
        observations = list(self._startup_observations) + [
            row['parent_observation'] for row in self._readiness]
        return all((row['payload']['pid'],row['payload']['start_time_ticks']) in reaped
                   for row in observations)

    def _recover_ledger(self, *, deadline=None):
        """Fresh read-only data custody after all live authority is reaped."""
        from .engagement_dispatch_store import DispatchLedger, DATABASE
        from . import engagement_dispatch_contract as ledger

        self._owner_check()
        if not self._verified_reaped():
            c.fail('cleanup_incomplete')
        began = time.monotonic_ns()
        limit = min(time.monotonic()+2, float('inf') if deadline is None else deadline)
        def identity(info):
            return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
                    'uid': info.st_uid, 'gid': info.st_gid}
        def observe(store):
            store._check_parent()
            store._check_directory()
            store._check_files(read_entry=True)
            return {'parent': identity(os.fstat(store._parent_fd)),
                    'directory': identity(os.fstat(store._directory_fd)),
                    'database': identity(os.stat(DATABASE, dir_fd=store._directory_fd, follow_symlinks=False))}
        with ledger._deadline_context(limit):
            store = DispatchLedger.open(self._store_directory, read_only=True)
            try:
                before = observe(store)
                owner_id = store.owner_reference
                if self._broker is not None and self._broker.readiness is not None:
                    if owner_id == self._broker.readiness['ledger_owner_id']:
                        c.fail('foreign_owner')
                snapshot = store.snapshot()
                raw = ledger.canonical(snapshot)
                if not 0 < len(raw) <= 2097152 or observe(store) != before:
                    c.fail('evidence_invalid')
            finally:
                store.close()
        c._check_deadline(limit)
        finished = time.monotonic_ns()
        return raw, {'schema_version': '1', 'source': 'postcleanup_readonly', 'owner_id': owner_id,
            'started_at_ns': began, 'finished_at_ns': finished, 'read_only': True,
            'store_identity': before, 'bytes': len(raw), 'sha256': c.digest(raw),
            'ledger_state_sha256': snapshot['events'][-1]['receipt']['state_sha256'], 'closed': True}

    def _saved_audit(self, deadline):
        if self._audit is None or self._audit._file_identity is None:
            return b''
        path = Path(self._audit_path).absolute()
        parent = path.parent.resolve(strict=True)
        directory = os.open(parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fd = None
        try:
            parent_info = os.fstat(directory)
            if (parent_info.st_dev,parent_info.st_ino) != self._audit._parent_identity:
                c.fail('evidence_invalid')
            fd = os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid()
                    or (before.st_dev,before.st_ino) != self._audit._file_identity
                    or before.st_size > 1048576):
                c.fail('evidence_invalid')
            raw = bytearray()
            while len(raw) < before.st_size:
                c._check_deadline(deadline)
                part = os.read(fd,min(65536,before.st_size-len(raw)))
                if not part:
                    c.fail('evidence_invalid')
                raw.extend(part)
            after = os.fstat(fd)
            named = os.stat(path.name,dir_fd=directory,follow_symlinks=False)
            key = lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_nlink,item.st_mode)
            if key(before) != key(after) or key(after) != key(named):
                c.fail('evidence_invalid')
            c._check_deadline(deadline)
            return bytes(raw)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)

    def _evidence_payload(self, *, deadline=None, case_id=None, instrumentation=(),
                          boundary_proofs=(), core_proofs=(), boundary_observations=(), recover=False):
        """Copy actual retained observations after cleanup; never fill gaps."""
        from . import engagement_live_runtime as runtime
        from . import engagement_live_evidence as evidence
        from .engagement_live_witness import validate_transcript_row

        self._owner_check()
        if not self._verified_reaped():
            c.fail('cleanup_incomplete')
        if self._runtime is None:
            c.fail('invalid_runtime')
        limit = min(time.monotonic()+15,float('inf') if deadline is None else deadline)
        c._check_deadline(limit)
        members = {}
        readies = deepcopy(self._readiness)
        natives = []
        receipts = deepcopy(self._cleanup_receipts)
        # Keep the actual whole-graph timing result as well as individual role
        # receipts. Readers count distinct PID/start identities, so this cannot
        # inflate process counts or hide a shared-deadline cleanup failure.
        receipts.append(deepcopy(self._cleanup))
        operations = deepcopy(list(self._operations.values()))
        by_dispatch = {row['prepared']['envelope']['dispatch_id']:row for row in operations}
        child_slots = deepcopy(self._child_slots)
        supervisors = deepcopy(self._unstarted_supervisors)
        startups = deepcopy(self._startup_observations)
        exports, instances, segments, raw_segments = [], [], [], []
        captures = set()
        def retain_prepared(actual):
            did = actual['envelope']['dispatch_id']
            if did not in by_dispatch:
                session = self._sessions.get(actual['envelope']['session_id'])
                if session is None or len(operations) >= 4:
                    c.fail('evidence_invalid')
                c.validate_prepared_context(actual, session['opened'])
                pending = {'session': session['opened'], 'prepared': actual, 'result': None,
                    'client': None, 'meter': None, 'host_capture': None,
                    'elapsed_ms': dict.fromkeys(('review','admission','native','parser','cleanup','action'))}
                operations.append(pending)
                by_dispatch[did] = pending
            elif by_dispatch[did]['prepared'] != actual:
                c.fail('evidence_invalid')
            return by_dispatch[did]
        for session in self._sessions.values():
            launcher = session['launcher']
            if launcher is None:
                continue
            actual = launcher.supervision_snapshot()
            startups.extend(actual['startup'])
            readies.extend(actual['readiness'])
            natives.extend(actual['native'])
            receipts.extend(actual['receipts'])
            supervisors.extend(actual['supervisors'])
            for slot in actual['child_slots']:
                matching = [i for i, old in enumerate(child_slots)
                            if (old['broker_id'], old['session_id'], old['child_slot'])
                            == (slot['broker_id'], slot['session_id'], slot['child_slot'])]
                if len(matching) != 1:
                    c.fail('evidence_invalid')
                old = child_slots[matching[0]]
                if any(old[key] != slot[key] for key in
                       ('schema_version','broker_id','session_id','launcher_id','child_slot','role','worker_id','pair')):
                    c.fail('evidence_invalid')
                child_slots[matching[0]] = slot
            for prepared in actual['prepared']:
                retain_prepared(c.validate_prepared(prepared))
            for did, capture in actual['captures'].items():
                operation = by_dispatch.get(did)
                if operation is None or operation['host_capture'] is not None:
                    c.fail('evidence_invalid')
                operation['host_capture'] = deepcopy(capture['host_capture'])
                for stream in ('stdout','stderr'):
                    raw_capture = capture[stream]
                    if (type(raw_capture) is not bytes
                            or len(raw_capture) != capture['host_capture'][stream+'_bytes']
                            or c.digest(raw_capture) != capture['host_capture'][stream+'_sha256']):
                        c.fail('evidence_invalid')
                    members['client-'+did+'.'+stream+'.bin'] = raw_capture
                captures.add(did)
        unavailable = {'status':'unavailable','source':None,'file':None,'reason':'not_started','broker_id':None}
        ledger_exports = {key:dict(unavailable) for key in ('initial','final','recovery')}
        saved = None
        try:
            if (self._broker is not None and self._broker._cleanup is not None
                    and self._broker._owner is not None):
                saved = self._broker.close_evidence(deadline=limit)
            ready = None if self._broker is None else self._broker.readiness
            if ready is not None:
                instances.append({'broker_id':ready['broker_id'],'ledger_owner_id':ready['ledger_owner_id']})
            if saved is not None and saved['broker_id'] is not None:
                for phase in ('initial','final'):
                    row = saved[phase]
                    if row is None:
                        ledger_exports[phase]['reason'] = 'not_acknowledged'
                        continue
                    name = phase+'-ledger.json'
                    members[name] = row['raw']
                    ledger_exports[phase] = {'status':'complete','source':'sealed_broker','file':name,
                                              'reason':None,'broker_id':saved['broker_id']}
                    exports.append({'broker_id':saved['broker_id'], **{key:row[key] for key in
                                   ('reference','host_descriptor','broker_descriptor')}})
                transcript = saved['transcript']
                if transcript is not None:
                    raw = transcript['raw']
                    segments.append({'source':'broker_memfd','broker_id':saved['broker_id'],
                        'offset':0,'bytes':len(raw),'sha256':c.digest(raw),'seals':transcript['seals'],
                        'status':transcript['status']})
                    raw_segments.append(raw)
                    # Only complete individual canonical rows are observations.
                    # A crash tail is retained verbatim in its own segment.
                    for line in raw.split(b'\n')[:-1]:
                        c._check_deadline(limit)
                        row = validate_transcript_row(c.decode(line))
                        if row['kind'] != 'protocol':
                            continue
                        frame = row['data']['frame']
                        if (row['data']['direction'] == 'sent' and frame['operation'] == 'PREPARE'
                                and row['data']['channel_role'] in ('launcher','endpoint')):
                            # Retain actual broker preparation even if the final
                            # host acknowledgment was lost during child setup.
                            actual = c.validate_prepared(frame['body'])
                            retain_prepared(actual)
                        if row['data']['direction'] != 'received':
                            continue
                        operation = by_dispatch.get(row['dispatch_id'])
                        if frame['operation'] == 'METER' and row['data']['channel_role'] == 'endpoint':
                            if operation is not None:
                                operation['meter'] = frame['body']
                        elif frame['operation'] == 'RESULT' and row['data']['channel_role'] == 'launcher':
                            if operation is not None:
                                operation['client'] = frame['body']
                        elif frame['operation'] == 'NATIVE_OBSERVED':
                            # The original relay remains in the transcript;
                            # only independently retained host facts enter the
                            # process arrays. Replay decides missing/conflict.
                            pass
                        elif frame['operation'] == 'OBSERVATION' and row['data']['channel_role'] == 'launcher':
                            observation = frame['body']
                            did = observation['dispatch_id']
                            if operation is None or did != row['dispatch_id']:
                                c.fail('evidence_invalid')
                            data = observation['data']
                            if observation['kind'] == 'capture':
                                for stream in ('stdout','stderr'):
                                    encoded = data[stream+'_base64']
                                    raw_capture = base64.b64decode(encoded,validate=True)
                                    if (base64.b64encode(raw_capture).decode('ascii') != encoded
                                            or len(raw_capture) != data[stream+'_bytes']
                                            or c.digest(raw_capture) != data[stream+'_sha256']):
                                        c.fail('evidence_invalid')
                                    name = 'client-'+did+'.'+stream+'.bin'
                                    if name in members and members[name] != raw_capture:
                                        c.fail('evidence_invalid')
            host = self._host_evidence_budget.snapshot()
            if any(host[key] for key in ('unresolved_tickets','reserved_bytes','reserved_rows')):
                c.fail('evidence_incomplete')
            broker_ids = {row['broker_id'] for row in instances}
            if self._broker is not None:
                broker_ids.add(self._broker._broker_id)
            observer_rows = [row for row in host['rows'] if row['broker_id'] in broker_ids]
            if observer_rows:
                observer_rows.sort(key=lambda row:row['observed_at_ns'])
                for index,row in enumerate(observer_rows,1):
                    row['row_sequence'] = index
                    validate_transcript_row(row)
                raw = b''.join(c.canonical(row)+b'\n' for row in observer_rows)
                segments.append({'source':'role_observer','broker_id':None,'offset':sum(map(len,raw_segments)),
                    'bytes':len(raw),'sha256':c.digest(raw),'seals':None,'status':'observer_complete'})
                raw_segments.append(raw)
            recovery = None
            if recover:
                members['recovery-ledger.json'], recovery = self._recover_ledger(deadline=limit)
                ledger_exports['recovery'] = {'status':'complete','source':'postcleanup_readonly',
                    'file':'recovery-ledger.json','reason':None,'broker_id':None}
            else:
                ledger_exports['recovery']['reason'] = 'not_applicable'
            def unique(values):
                result, hashes = [], set()
                for value in values:
                    digest = c.digest(c.canonical(value))
                    if digest not in hashes:
                        hashes.add(digest)
                        result.append(value)
                return result
            members.update({
                'runtime.json':c.canonical({'schema_version':'1','runtime':self._runtime,
                                            'instrumentation':list(instrumentation)},max_bytes=2097152),
                'processes.json':c.canonical({'schema_version':'1','startup':unique(startups),
                    'readiness':unique(readies),
                    'native':unique(natives),'child_slots':child_slots,
                    'boundary_observations':list(boundary_observations)},max_bytes=1048576),
                'results.json':c.canonical({'schema_version':'1','operations':operations,
                    'boundary_proofs':list(boundary_proofs),'core_proofs':list(core_proofs)},max_bytes=524288),
                'cleanup.json':c.canonical({'schema_version':'1','receipts':unique(receipts),
                    'supervisors':supervisors,'exports':exports,'recovery':recovery},max_bytes=524288),
                'audit.jsonl':self._saved_audit(limit), 'transcript.jsonl':b''.join(raw_segments)})
            case = None if case_id is None else evidence._case(case_id)
            manifest = {'schema_version':'1','contract_sha256':c.CONTRACT_SHA256,
                'gates_sha256':c.INVENTORY_SHA256,'runtime_sha256':runtime.runtime_digest(self._runtime),
                'evidence_class':'production_run' if case is None else 'owned_gate',
                'proof_kind':'role_boundary' if case is not None and case['group']=='native_runtime' else 'live_operation',
                'case_id':case_id,'configuration':None if case is None else case.get('configuration'),
                'review_mode':self._mode,'instrumentation':[{key:item[key] for key in
                    ('kind','source_sha256','configuration_sha256')} for item in instrumentation],
                'broker_instances':instances,'ledger_exports':ledger_exports,
                'transcript':{'status':'unavailable' if not segments else
                    'partial' if any(s['status'].endswith('partial') for s in segments) else 'complete',
                    'segments':segments,'reason':'not_started' if not segments else
                    'broker_lost' if any(s['status'].endswith('partial') for s in segments) else None},
                'dispatches':[{'dispatch_id':op['prepared']['envelope']['dispatch_id'],
                    'session_id':op['prepared']['envelope']['session_id'],'slot':op['prepared']['envelope']['slot'],
                    **{stream+'_file':('client-'+op['prepared']['envelope']['dispatch_id']+'.'+stream+'.bin'
                        if op['prepared']['envelope']['dispatch_id'] in captures else None)
                       for stream in ('stdout','stderr')}} for op in operations],
                'members':[{'name':name,'bytes':len(raw),'sha256':c.digest(raw)} for name,raw in sorted(members.items())]}
            c._check_deadline(limit)
            return manifest,members
        finally:
            if self._bundle is not None:
                self._bundle.close()

    @staticmethod
    def _interrupt_roles(roles):
        for owner in roles:
            interrupt = getattr(owner, '_interrupt', None)
            if interrupt is not None:
                interrupt()

    def _monitor(self):
        try:
            while not self._closing.wait(.05):
                if self._stop.is_set():
                    c.fail('session_unavailable')
                self._control.check()
                if self._broker.pidfd is not None:
                    import select
                    if select.select([self._broker.pidfd], [], [], 0)[0]:
                        c.fail('session_unavailable')
                event = self._broker.poll_lifecycle()
                if event is None:
                    continue
                if event['operation'] == 'BROKER_STOP':
                    self._cleanup_epoch.stop(bound_deadline_ns=event['body']['cleanup_deadline_ns'])
                    c.fail('session_unavailable')
                with self._state_lock:
                    row = self._sessions.get(event['body']['session_id'])
                if row is None:
                    c.fail('invalid_frame')
                if row['stopped']:
                    continue
                row['stopped'] = True
                # The shared stop epoch covers both supervisors. A terminal
                # event cannot leave another owner running beyond that epoch.
                self._cleanup_epoch.stop(bound_deadline_ns=event['body']['cleanup_deadline_ns'])
                c.fail('session_unavailable')
        except BaseException as error:
            self._remember_failure(error)
            try:
                self.close()
            except BaseException as cleanup_error:
                self._remember_failure(cleanup_error)

    def _close_unstarted_supervisors(self, launchers, epoch):
        """Observe terminal custody of allocations whose thread never started."""
        if not self._child_slots:
            return
        from . import engagement_live_runtime as runtime

        began = time.monotonic_ns()
        # Startup is already fenced and every existing supervisor has joined.
        # This closes actual untransferred endpoints while preserving only the
        # integer export readers needed for subsequent evidence packaging.
        self._bundle.close_remaining_channels()
        active = {owner.slot.launcher_id for owner in launchers
                  if owner._supervisor is not None}
        for owner in launchers:
            if owner._supervisor is None and owner._owner is not None:
                if owner._owner.channel.fileno() != -1:
                    c.fail('cleanup_incomplete')
        existing = {(row['broker_id'],row['session_id'],row['launcher_id'])
                    for row in self._unstarted_supervisors}
        missing = sorted({(row['broker_id'],row['session_id'],row['launcher_id'])
                          for row in self._child_slots if row['launcher_id'] not in active} - existing)
        observer = runtime._observer() if missing else None
        finished = time.monotonic_ns()
        epoch = self._cleanup_epoch.snapshot()
        for broker_id,session_id,launcher_id in missing:
            self._unstarted_supervisors.append({'schema_version':'1','broker_id':broker_id,
                'session_id':session_id,'launcher_id':launcher_id,'host_observer':deepcopy(observer),
                'thread_native_id':None,'thread_started_at_ns':None,'state':'not_started',
                'first_stop_requested_at_ns':epoch['first_stop_requested_at_ns'],
                'cleanup_started_at_ns':max(began,epoch['first_stop_requested_at_ns']),
                'cleanup_finished_at_ns':finished,'cleanup_deadline_ns':epoch['deadline_ns'],
                'join_attempted':False,'thread_alive_observed':False,'channel_closed':True,
                'pending_slots':[],'status':'complete' if finished <= epoch['deadline_ns'] else 'failed'})
        self._remaining_channels_closed = True

    def close(self):
        self._owner_check()
        epoch = self._cleanup_epoch.stop()
        deadline = epoch['deadline_ns'] / c.SECOND
        self._closing.set()
        self._stop.set()
        # All blocking view/client channels are interrupted before any lock is
        # acquired. Cleanup shares one budget across the entire live graph.
        self._interrupt_roles([r for r in self._roles if r is not self._broker])
        # Interrupting a live child may narrow the shared epoch to its earlier
        # action deadline. All later roles inherit that same actual bound.
        epoch = self._cleanup_epoch.snapshot()
        deadline = epoch['deadline_ns'] / c.SECOND
        if not self._close_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            c.fail('cleanup_incomplete')
        errors = []
        try:
            already_failed = self._cleanup is not None and self._cleanup['status'] != 'complete'
            if self._closed and self._verified_reaped():
                if already_failed:
                    c.fail('cleanup_incomplete')
                return deepcopy(self._cleanup)
            began = time.monotonic_ns()
            held = []
            try:
                for lock in self._slot_locks:
                    if not lock.acquire(timeout=max(0, deadline-time.monotonic())):
                        c.fail('cleanup_incomplete')
                    held.append(lock)
                self._startup_quiesced = True
            except BaseException as error:
                errors.append(error)
            finally:
                for lock in reversed(held):
                    lock.release()
            launchers = [row['launcher'] for row in self._sessions.values()
                         if row['launcher'] is not None]
            endpoints = [row['endpoint'] for row in self._sessions.values()
                         if row['endpoint'] is not None]
            # Signal all roles above, then join every supervisor before an
            # endpoint pin can be closed/recycled during a namespace lease.
            ordered = launchers + [owner for owner in reversed(self._roles) if owner not in launchers]
            for owner in ordered:
                try:
                    epoch = self._cleanup_epoch.snapshot()
                    deadline = min(deadline, epoch['deadline_ns']/c.SECOND)
                    if owner in endpoints and any(not item.supervisor_resolved for item in launchers):
                        c.fail('cleanup_incomplete')
                    receipt = owner._close(deadline)
                    if receipt is not None and receipt not in self._cleanup_receipts:
                        self._cleanup_receipts.append(receipt)
                except BaseException as error:
                    self._remember_failure(error)
                    errors.append(error)
            supervisors_resolved = all(owner.supervisor_resolved for owner in launchers)
            if self._startup_quiesced and supervisors_resolved:
                try:
                    self._close_unstarted_supervisors(launchers, epoch)
                except BaseException as error:
                    self._remember_failure(error)
                    errors.append(error)
            finished = time.monotonic_ns()
            epoch = self._cleanup_epoch.snapshot()
            deadline = min(deadline, epoch['deadline_ns']/c.SECOND)
            resolved = all(r['status'] == 'complete' and r['descriptors_closed']
                           for r in self._cleanup_receipts)
            channels_closed = not self._child_slots or self._remaining_channels_closed
            resolved = resolved and supervisors_resolved and self._startup_quiesced and channels_closed
            self._cleanup = {'schema_version': '1', 'started_at_ns': began,
                'finished_at_ns': finished, 'deadline_ns': epoch['deadline_ns'],
                'status': 'failed' if already_failed or errors or not resolved or finished > epoch['deadline_ns'] else 'complete',
                'processes': [p for receipt in self._cleanup_receipts for p in receipt['processes']],
                'descriptors_closed': supervisors_resolved and self._startup_quiesced and channels_closed
                    and all(r['descriptors_closed'] for r in self._cleanup_receipts)}
            self._closed = True
        finally:
            self._close_lock.release()
        monitor = self._monitor_thread
        deadline = min(deadline, self._cleanup_epoch.snapshot()['deadline_ns']/c.SECOND)
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=max(0, deadline-time.monotonic()))
            if monitor.is_alive():
                self._cleanup['status'] = 'failed'
                errors.append(c.LiveError('engagement_live_cleanup_incomplete'))
        self._cleanup['deadline_ns'] = min(self._cleanup['deadline_ns'],
            self._cleanup_epoch.snapshot()['deadline_ns'])
        self._cleanup['finished_at_ns'] = time.monotonic_ns()
        if self._cleanup['finished_at_ns'] > self._cleanup['deadline_ns']:
            self._cleanup['status'] = 'failed'
        if errors or self._cleanup['status'] != 'complete':
            error = c.LiveError('engagement_live_cleanup_incomplete')
            error.cleanup = self._cleanup
            raise error
        return deepcopy(self._cleanup)
