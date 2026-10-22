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


class EngagementSession:
    @classmethod
    def start(cls, store_directory, audit_path, *, review_mode, control):
        from . import engagement_live_runtime as runtime
        from .engagement_live_broker import EngagementBroker, preallocate_role_bundle
        from .engagement_live_audit import EngagementAuditService

        if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                or review_mode not in {'terminal', 'graphical_v1'}):
            c.fail('invalid_input')
        control.check()
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
        self._started_at_ns = time.monotonic_ns()
        self._observer_rows = []
        try:
            self._runtime = runtime.inspect_runtime(control)
            self._bundle = preallocate_role_bundle(review_mode)
            self._broker = EngagementBroker(runtime=self._runtime, store_directory=store_directory,
                                             control=control, role_bundle=self._bundle)
            self._roles.append(self._broker)
            self._broker_ready = self._broker.start()
            self._readiness.append(self._broker_ready['readiness'])
            self._audit = EngagementAuditService(audit_path, runtime=self._runtime,
                                                 role_bundle=self._bundle, control=control)
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
        from .engagement_live_approval import _clipped_control

        self._check()
        c.integer(ingress, 0, 1)
        with self._slot_locks[ingress]:
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
                        self._control, binding['session_deadline_ns'], self._stop))
                self._register(row, 'endpoint', endpoint, endpoint.ready)
                launcher = EngagementLauncher(self._runtime, endpoint=endpoint, role_slot=slot)
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
                    witness_slot=slot, control=self._control)
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
                'result': None, 'client': None, 'meter': None,
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
        self._interrupt_roles([row[key] for key in ('reviewer', 'launcher', 'endpoint')])
        return self._broker.cancel(session_id)

    def revoke(self, *, expected_revision, expected_generation, event_id):
        self._check()
        return self._broker.revoke(expected_revision=expected_revision,
                                  expected_generation=expected_generation, event_id=event_id)

    def snapshot(self):
        self._check()
        return self._broker.snapshot()

    def _verified_reaped(self):
        """Packaging can retain a timed-out cleanup only after actual reaping."""
        if not self._closed or self._cleanup is None:
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
        exports, instances, segments, raw_segments = [], [], [], []
        captures = set()
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
                            did = actual['envelope']['dispatch_id']
                            if did not in by_dispatch:
                                session = self._sessions.get(actual['envelope']['session_id'])
                                if session is None or len(operations) >= 4:
                                    c.fail('evidence_invalid')
                                c.validate_prepared_context(actual,session['opened'])
                                pending = {'session':session['opened'],'prepared':actual,'result':None,
                                    'client':None,'meter':None,'elapsed_ms':dict.fromkeys(
                                        ('review','admission','native','parser','cleanup','action'))}
                                operations.append(pending)
                                by_dispatch[did] = pending
                            elif by_dispatch[did]['prepared'] != actual:
                                c.fail('evidence_invalid')
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
                            natives.append(frame['body'])
                        elif frame['operation'] == 'OBSERVATION' and row['data']['channel_role'] == 'launcher':
                            observation = frame['body']
                            did = observation['dispatch_id']
                            if operation is None or did != row['dispatch_id']:
                                c.fail('evidence_invalid')
                            data = observation['data']
                            if observation['kind'] == 'capture':
                                if did in captures:
                                    c.fail('evidence_invalid')
                                captures.add(did)
                                for stream in ('stdout','stderr'):
                                    encoded = data[stream+'_base64']
                                    raw_capture = base64.b64decode(encoded,validate=True)
                                    if (base64.b64encode(raw_capture).decode('ascii') != encoded
                                            or len(raw_capture) != data[stream+'_bytes']
                                            or c.digest(raw_capture) != data[stream+'_sha256']):
                                        c.fail('evidence_invalid')
                                    members['client-'+did+'.'+stream+'.bin'] = raw_capture
                            elif observation['kind'] == 'role_readiness':
                                readies.append(data)
                            elif observation['kind'] == 'cleanup':
                                receipts.append(data)
            observer_rows = deepcopy(self._observer_rows)
            for session in self._sessions.values():
                reviewer = session['reviewer']
                if reviewer is None:
                    continue
                for item in reviewer._observations:
                    observer_rows.append({'schema_version':'1','broker_id':session['opened']['binding']['broker_id'],
                        'session_id':session['opened']['binding']['session_id'],'dispatch_id':item['dispatch_id'],
                        'observer_id':session['opened']['binding']['reviewer_id'],'row_sequence':1,
                        'observed_at_ns':item['observed_at_ns'],'kind':'capability_projection','data':item['projection']})
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
                'processes.json':c.canonical({'schema_version':'1','startup':unique(self._startup_observations),
                    'readiness':unique(readies),
                    'native':unique(natives),'boundary_observations':list(boundary_observations)},max_bytes=1048576),
                'results.json':c.canonical({'schema_version':'1','operations':operations,
                    'boundary_proofs':list(boundary_proofs),'core_proofs':list(core_proofs)},max_bytes=524288),
                'cleanup.json':c.canonical({'schema_version':'1','receipts':unique(receipts),
                    'exports':exports,'recovery':recovery},max_bytes=524288),
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
                self._control.check()
                if self._broker.pidfd is not None:
                    import select
                    if select.select([self._broker.pidfd], [], [], 0)[0]:
                        c.fail('session_unavailable')
                event = self._broker.poll_lifecycle()
                if event is None:
                    continue
                if event['operation'] == 'BROKER_STOP':
                    c.fail('session_unavailable')
                with self._state_lock:
                    row = self._sessions.get(event['body']['session_id'])
                if row is None:
                    c.fail('invalid_frame')
                if row['stopped']:
                    continue
                row['stopped'] = True
                roles = [row[key] for key in ('reviewer', 'launcher', 'endpoint') if row[key] is not None]
                self._interrupt_roles(roles)
                deadline = min(self._control.deadline, time.monotonic() + 2)
                for owner in roles:
                    receipt = owner._close(deadline)
                    if receipt is not None and receipt not in self._cleanup_receipts:
                        self._cleanup_receipts.append(receipt)
        except BaseException as error:
            self._remember_failure(error)
            try:
                self.close()
            except BaseException as cleanup_error:
                self._remember_failure(cleanup_error)

    def close(self):
        self._owner_check()
        self._closing.set()
        self._stop.set()
        # All blocking view/client channels are interrupted before any lock is
        # acquired. Cleanup shares one budget across the entire live graph.
        self._interrupt_roles([r for r in self._roles if r is not self._broker])
        now = time.monotonic()
        deadline = min(self._control.deadline, now + 2) if now < self._control.deadline else now + 2
        if not self._close_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            c.fail('cleanup_incomplete')
        try:
            if self._closed:
                return deepcopy(self._cleanup)
            began = time.monotonic_ns()
            errors = []
            held = []
            try:
                for lock in self._slot_locks:
                    if not lock.acquire(timeout=max(0, deadline-time.monotonic())):
                        c.fail('cleanup_incomplete')
                    held.append(lock)
            except BaseException as error:
                errors.append(error)
            finally:
                for lock in reversed(held):
                    lock.release()
            for owner in reversed(self._roles):
                try:
                    receipt = owner._close(deadline)
                    if receipt is not None and receipt not in self._cleanup_receipts:
                        self._cleanup_receipts.append(receipt)
                except BaseException as error:
                    self._remember_failure(error)
                    errors.append(error)
            finished = time.monotonic_ns()
            resolved = all(r['status'] == 'complete' and r['descriptors_closed']
                           for r in self._cleanup_receipts)
            self._cleanup = {'schema_version': '1', 'started_at_ns': began,
                'finished_at_ns': finished, 'deadline_ns': int(deadline*c.SECOND),
                'status': 'failed' if errors or not resolved or finished > int(deadline*c.SECOND) else 'complete',
                'processes': [p for receipt in self._cleanup_receipts for p in receipt['processes']],
                'descriptors_closed': all(r['descriptors_closed'] for r in self._cleanup_receipts)}
            self._closed = True
            if errors or self._cleanup['status'] != 'complete':
                error = c.LiveError('engagement_live_cleanup_incomplete')
                error.cleanup = self._cleanup
                raise error
            return deepcopy(self._cleanup)
        finally:
            self._close_lock.release()
