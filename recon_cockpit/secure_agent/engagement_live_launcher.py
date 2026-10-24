"""Host custody of one fixed launcher; authority arrives only from the broker."""
import os
import socket
import threading
import time

from . import engagement_live_contract as c


def _actually_reaped(receipt):
    return (type(receipt) is dict and receipt.get('descriptors_closed') is True
            and type(receipt.get('processes')) is list and len(receipt['processes']) == 1
            and all(row.get('pin_verified') is True and row.get('exit_observed') is True
                    and row.get('reaped_observed') is True and row.get('wrapper_returncode') is not None
                    for row in receipt['processes']))


class _SupervisorControl:
    """An original host control clipped to owned work, never a caller renewal."""
    def __init__(self, supervisor, deadline_ns):
        self.supervisor = supervisor
        self.original = supervisor.control
        self.clock = self.original.clock
        self.cancelled = self.original.cancelled
        self.deadline = min(self.original.deadline, deadline_ns / c.SECOND)

    @property
    def cleanup_deadline(self):
        return self.supervisor.epoch.stop(bound_deadline_ns=self.supervisor.cleanup_bound_ns())['deadline_ns'] / c.SECOND

    def check(self):
        from .execution import ExecutionStopped
        try:
            self.original.check()
        except ExecutionStopped as error:
            c.fail('cancelled' if error.reason == 'session_cancelled' else 'timeout')
        if self.supervisor.stop.is_set() or self.supervisor.epoch.stopped:
            c.fail('cancelled')
        if self.clock() >= self.deadline:
            c.fail('timeout')
        self.supervisor.check_pending_deadlines()

    def remaining(self):
        self.check()
        return max(0, self.deadline - self.clock())


class _FixedSupervisor:
    """Single owner of a fixed child's process handles; never its request end."""
    def __init__(self, *, launcher, opened, channel, bindings, endpoints, control,
                 budget, epoch, failure_sink, setup_lock):
        from . import engagement_live_runtime as rt
        from . import engagement_live_protocol as p
        self.launcher = launcher
        self.opened, self.channel, self.control = opened, channel, control
        self.budget, self.epoch, self.failure_sink = budget, epoch, failure_sink
        self.setup_lock = setup_lock
        self.bindings = c.validate_child_slot_bindings(bindings)
        self.observer = rt._observer()
        self.sequence = p.ChannelSequence(launcher.slot.launcher_id, 'launcher_supervision')
        self.stop = threading.Event()
        self.state_lock = threading.Lock()
        self.thread = None
        self._start_in_progress = False
        self.thread_id = self.thread_started_ns = None
        self.join_attempted = False
        self.closure = None
        self.closed = False
        self._channel_close_error = None
        self.failure = None
        self._failure_state = None
        self._terminal_finalized = False
        self._checking = False
        self._request_ticket = None
        self._terminal_tickets = []
        self._sources = {'child_slots': [], 'startup': [], 'readiness': [], 'native': [],
                         'captures': {}, 'receipts': [], 'supervisors': [], 'prepared': []}
        self.children = {}
        binding = opened['binding']
        if set(endpoints) != set(c.CHILD_SLOTS): c.fail('invalid_channel')
        for row in self.bindings:
            name = row['child_slot']
            self.children[name] = {'binding': row, 'endpoint': endpoints[name],
                'owner': None, 'capture': None, 'prepared': None, 'state': 'allocated',
                'startup_deadline_ns': None, 'pending': False, 'start_resolved': False}
            self._sources['child_slots'].append({'schema_version': '1',
                'broker_id': binding['broker_id'], 'session_id': binding['session_id'],
                'launcher_id': launcher.slot.launcher_id, **row,
                'prepared_sha256': None, 'bootstrap': None, 'entry_sha256': None})
        endpoints.clear()  # Ownership moves only after every fixed slot is constructed.
        self._deadline_ns = min(binding['session_deadline_ns'], binding['broker_deadline_ns'],
                                int(control.deadline*c.SECOND))

    def phase(self, deadline_ns=None):
        if deadline_ns is None:
            deadlines = [self._deadline_ns]
            for state in self.children.values():
                if state['state'] in {'allocated', 'reaped'}: continue
                if state['prepared'] is not None:
                    deadlines.append(state['prepared']['envelope']['action_deadline_ns'])
                if (state['state'] in {'starting', 'bootstrap_returned'}
                        or state['binding']['role'] == 'parser') and state['startup_deadline_ns'] is not None:
                    deadlines.append(state['startup_deadline_ns'])
                native = getattr(state['capture'], 'native_deadline_ns', None)
                if native is not None: deadlines.append(native)
            deadline_ns = min(deadlines)
        return _SupervisorControl(self, min(self._deadline_ns, deadline_ns))

    def cleanup_bound_ns(self):
        deadlines = [self._deadline_ns]
        deadlines.extend(row['prepared']['envelope']['action_deadline_ns'] for row in self.children.values()
                         if row['prepared'] is not None and row['state'] not in {'allocated', 'reaped'})
        return min(deadlines)

    def check_pending_deadlines(self):
        if self._checking:
            return
        self._checking = True
        try:
            now = time.monotonic_ns()
            for state in self.children.values():
                if state['state'] in {'allocated', 'reaped'}:
                    continue
                prepared = state['prepared']
                if prepared is not None and now >= prepared['envelope']['action_deadline_ns']:
                    c.fail('timeout')
                startup = state['startup_deadline_ns']
                if (state['state'] in {'starting', 'bootstrap_returned'}
                        or state['binding']['role'] == 'parser') and startup is not None and now >= startup:
                    c.fail('timeout')
                capture = state['capture']
                if capture is not None:
                    native_deadline = getattr(capture, 'native_deadline_ns', None)
                    if native_deadline is not None and now >= native_deadline and state['state'] != 'reaped':
                        c.fail('timeout')
        finally:
            self._checking = False

    def start(self):
        phase = self.phase()
        try:
            for _ in range(2):
                self._terminal_tickets.append(self.budget.reserve(kind='supervision_projection',
                    maximum_bytes=c.SUPERVISION_ROW_BYTES, maximum_rows=1, control=phase))
            # Register the actual owner before Thread.start. A failed start is
            # handled as not_started; it is never relabeled joined.
            self.thread = threading.Thread(target=self._run, name='engagement-child-supervisor', daemon=False)
            with self.state_lock:
                if self.stop.is_set() or self.closed: c.fail('cancelled')
                self._start_in_progress = True
            try:
                self.thread.start()
            finally:
                with self.state_lock: self._start_in_progress = False
        except BaseException:
            self.interrupt()
            raise

    def interrupt(self, bound_deadline_ns=None):
        bound = self.cleanup_bound_ns()
        self.epoch.stop(bound_deadline_ns=bound if bound_deadline_ns is None else min(bound, bound_deadline_ns))
        self.stop.set()
        try:
            self.channel.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _append(self, key, value):
        if value is None:
            return
        value = c.detached(value, 2097152)
        digest = c.digest(c.canonical(value, max_bytes=2097152))
        with self.state_lock:
            if not any(c.digest(c.canonical(row, max_bytes=2097152)) == digest for row in self._sources[key]):
                self._sources[key].append(value)

    def _child_record(self, name):
        return next(row for row in self._sources['child_slots'] if row['child_slot'] == name)

    def _row(self, data, prepared=None):
        binding = self.opened['binding']
        return {'schema_version': '1', 'broker_id': binding['broker_id'],
            'observer_id': self.launcher.slot.launcher_id, 'row_sequence': 1,
            'session_id': binding['session_id'],
            'dispatch_id': None if prepared is None else prepared['envelope']['dispatch_id'],
            'observed_at_ns': time.monotonic_ns(), 'kind': 'supervision_projection', 'data': data}

    def _projection(self, operation, data):
        name = data['child_slot']
        result = {'child_slot': name}
        if operation == 'START': result['prepared_sha256'] = c.prepared_digest(data['prepared'])
        elif operation == 'BOOTSTRAP':
            raw = c.canonical(data['bootstrap']); result.update(bootstrap_sha256=c.digest(raw), bootstrap_bytes=len(raw))
        elif operation == 'OBSERVE_READY': result['bootstrap_sha256'] = data['bootstrap_sha256']
        elif operation == 'READY': result['readiness_sha256'] = c.digest(c.canonical(data['readiness']))
        elif operation == 'NATIVE_BEGIN': result['release_sha256'] = c.digest(c.canonical(data['release']))
        elif operation == 'NATIVE_BUDGET': result.update(started_at_ns=data['started_at_ns'], native_deadline_ns=data['native_deadline_ns'])
        elif operation == 'NATIVE': result['native_readiness_sha256'] = c.digest(c.canonical(data['native_readiness']))
        elif operation == 'CAPTURED':
            record = self._sources['captures'][self.children[name]['prepared']['envelope']['dispatch_id']]['host_capture']
            result.update(capture_sha256=c.digest(c.canonical(data['capture'])),
                host_capture_sha256=c.digest(c.canonical(record)), cleanup_sha256=record['cleanup_sha256'], status=data['status'])
        elif operation == 'REAPED': result['cleanup_sha256'] = c.digest(c.canonical(data['cleanup']))
        return result

    def _record_capture(self, state):
        from . import engagement_live_protocol as p
        capture = state['capture']
        if capture is None:
            return
        value = capture.partial()
        if value is None:
            return
        prepared = state['prepared']; did = prepared['envelope']['dispatch_id']
        metadata = {'schema_version': '1', 'slot': prepared['envelope']['slot'],
            'exit_code': value['exit_code'], 'truncated': value['truncated'], 'status': value['status'],
            'cleanup_sha256': None if value['cleanup'] is None else c.digest(c.canonical(value['cleanup']))}
        for name in ('stdout', 'stderr'):
            raw = value[name]
            if type(raw) is not bytes:
                c.fail('evidence_invalid')
            metadata[name+'_bytes'] = len(raw); metadata[name+'_sha256'] = c.digest(raw)
        if metadata['stdout_bytes'] + metadata['stderr_bytes'] > c.SLOTS[metadata['slot']][4]:
            c.fail('limit_exceeded')
        with self.state_lock:
            self._sources['captures'][did] = {'host_capture': metadata,
                'stdout': value['stdout'], 'stderr': value['stderr']}
        self._append('receipts', value['cleanup'])
        self._append('native', value.get('native_readiness'))

    def _retain_error(self, error, state):
        owner = getattr(error, 'child_owner', None)
        if owner is not None:
            state['owner'] = owner
        self._append('startup', getattr(error, 'startup_observation', None))
        self._append('receipts', getattr(error, 'startup_cleanup', None))
        if state['owner'] is not None:
            self._append('startup', getattr(state['owner'], 'entry', None))
        self._record_capture(state)

    def _normal_cleanup_deadline(self, phase):
        epoch = self.epoch.snapshot()
        return min(phase.deadline, time.monotonic()+2,
                   epoch['deadline_ns']/c.SECOND if epoch else phase.deadline)

    def _start_child(self, name, prepared):
        from . import engagement_live_runtime as rt
        from .engagement_live_broker import _locked
        state = self.children[name]
        if state['state'] != 'allocated':
            c.fail('dispatch_replayed')
        value = c.validate_prepared_context(prepared, self.opened)
        role, action, _ = c.CHILD_SLOTS[name]
        if value['envelope']['slot'] != action:
            c.fail('invalid_prepared')
        # Enforce real finite overlap, including pending/unpublished spawns.
        active = [v for v in self.children.values() if v['state'] not in {'allocated', 'reaped'}]
        if role == 'parser':
            if active: c.fail('invalid_role')
        elif (len(active) >= 2 or any(v['binding']['role'] == 'parser' for v in active)
              or any(v['prepared']['envelope']['dispatch_id'] != value['envelope']['dispatch_id'] for v in active)):
            c.fail('invalid_role')
        deadline = min(value['envelope']['action_deadline_ns'], self._deadline_ns,
                       time.monotonic_ns() + (2 if role == 'parser' else 10)*c.SECOND)
        with self.state_lock:
            state.update(prepared=value, state='starting', pending=True, startup_deadline_ns=deadline)
            record = self._child_record(name); record['prepared_sha256'] = c.prepared_digest(value)
        self._append('prepared', value)
        phase = self.phase(value['envelope']['action_deadline_ns']); lease = None
        try:
            with _locked(self.setup_lock, phase):
                phase.check()
                if role in {'nmap', 'headers'}:
                    lease = self.launcher.endpoint._namespace_lease(phase)
                payload = ({'prepared': value, 'endpoint_identity': self.launcher.endpoint.identity,
                            'scope': self.opened['scope']} if role in {'nmap', 'headers'} else
                    {'prepared': value, 'endpoint_identity': self.launcher.endpoint.identity,
                     'launcher_id': self.launcher.slot.launcher_id} if role == 'admission' else
                    {'slot': action, 'scope': self.opened['scope']})
                from .engagement_live_broker import _pair_identity
                if _pair_identity(state['endpoint']) != state['binding']['pair']['child_endpoint']:
                    c.fail('invalid_channel')
                endpoint, state['endpoint'] = state['endpoint'], None
                owner = rt._spawn_child_owned(runtime=self.launcher.runtime, role=role, payload=payload,
                    child_stdin=endpoint, worker_id=state['binding']['worker_id'], control=phase,
                    namespace_lease=lease, supervision_identity={'launcher_id': self.launcher.slot.launcher_id, 'child_slot': name},
                    startup_deadline=deadline/c.SECOND)
                with self.state_lock:
                    state['owner'] = owner
                phase.check()
                self._append('startup', owner.entry)
                raw = c.canonical(owner.bootstrap)
                with self.state_lock:
                    record['bootstrap'] = {'deadline_ns': owner.bootstrap['deadline_ns'], 'bytes': len(raw), 'sha256': c.digest(raw)}
                    record['entry_sha256'] = c.digest(c.canonical(owner.entry))
                    state['state'] = 'bootstrap_returned'
                return {'child_slot': name, 'bootstrap': owner.bootstrap}
        except BaseException as error:
            self._retain_error(error, state)
            raise
        finally:
            try:
                if lease is not None: lease.close()
            finally:
                with self.state_lock:
                    state['pending'] = False
                    state['start_resolved'] = True

    def _execute(self, operation, data):
        from .engagement_live_client import SupervisedCapture
        name = data['child_slot']; state = self.children[name]
        if operation == 'START':
            return self._start_child(name, data['prepared'])
        if state['owner'] is None or state['prepared'] is None:
            c.fail('invalid_frame')
        phase = self.phase(state['prepared']['envelope']['action_deadline_ns'])
        owner = state['owner']
        if operation == 'OBSERVE_READY':
            record = self._child_record(name)
            if state['state'] != 'bootstrap_returned' or data['bootstrap_sha256'] != record['bootstrap']['sha256']:
                c.fail('invalid_frame')
            ready = owner.observe_ready(self.phase(state['startup_deadline_ns']))
            self._append('readiness', ready); state['state'] = 'ready'
            return {'child_slot': name, 'readiness': ready}
        if operation == 'NATIVE_BEGIN':
            if state['state'] != 'ready' or state['capture'] is not None:
                c.fail('dispatch_replayed')
            # Admission must already be actually reaped, not merely requested.
            admission = name.replace('_client', '_admission')
            admission_state = self.children[admission]
            if (admission_state['state'] != 'reaped' or admission_state['owner'] is None
                    or admission_state['owner'].cleanup is None
                    or admission_state['owner'].cleanup['status'] != 'complete'
                    or not _actually_reaped(admission_state['owner'].cleanup)):
                c.fail('admission_unavailable')
            capture = SupervisedCapture(owner, state['prepared'], self.launcher.runtime)
            state['capture'] = capture
            budget = capture.begin(data['release'], phase)
            state['state'] = 'active_or_rpc'
            return budget
        if operation == 'OBSERVE_NATIVE':
            if state['state'] != 'active_or_rpc' or state['capture'] is None:
                c.fail('invalid_frame')
            if getattr(state['capture'], 'native_ready', None) is not None:
                c.fail('dispatch_replayed')
            observed = state['capture'].observe_native(phase)
            self._append('native', observed)
            return {'child_slot': name, 'native_readiness': observed}
        if operation == 'CAPTURE':
            if state['state'] != 'active_or_rpc' or state['capture'] is None:
                c.fail('invalid_frame')
            result = state['capture'].capture(phase)
            self._record_capture(state)
            state['state'] = 'reaped' if _actually_reaped(result['cleanup']) else 'cleanup_pending'
            return {'child_slot': name, **result}
        if operation == 'REAP':
            if state['state'] == 'reaped': c.fail('dispatch_replayed')
            cleanup = owner.close(deadline=self._normal_cleanup_deadline(phase))
            self._append('receipts', cleanup); self._record_capture(state)
            state['state'] = 'reaped' if _actually_reaped(cleanup) else 'cleanup_pending'
            return {'child_slot': name, 'cleanup': cleanup}
        c.fail('invalid_frame')

    def _terminal(self, error, state=None):
        code = getattr(error, 'code', 'engagement_live_unavailable')
        if code not in c.ERROR_CODES: code = 'engagement_live_unavailable'
        self.interrupt()
        self.failure = error
        self._failure_state = state
        if state is not None: self._retain_error(error, state)
        if self._terminal_tickets:
            ticket = self._terminal_tickets.pop(0)
            prepared = None if state is None else state['prepared']
            data = {'kind': 'local_failure', 'launcher_id': self.launcher.slot.launcher_id,
                'child_slot': None if state is None else state['binding']['child_slot'],
                'child_worker_id': None if state is None else state['binding']['worker_id'],
                'prepared_sha256': None if prepared is None else c.prepared_digest(prepared),
                'code': code, 'observed_at_ns': time.monotonic_ns(), 'capture_sha256': None, 'cleanup_sha256': None}
            # First cause never refers to mutable partial-capture metadata.
            # The post-join terminal record binds final retained facts.
            self.budget.finalize(ticket, self._row(data, prepared))
        self.failure_sink(error)

    def _exchange(self, ticket):
        from . import engagement_live_protocol as p
        phase = self.phase(); raw = None; row = None; state = None
        try:
            # Receive an exact packet once; retain actual wire digest separately
            # from its compact typed projection. No untrusted ancillary survives.
            with c._deadline_context(phase.deadline):
                frame = p.receive_packet(self.channel, role='launcher_supervision', control=phase)
                raw = p.encode_frame(frame, role='launcher_supervision', direction='request')
                frame = self.sequence.accept(frame)
            data = frame['body']; state = self.children[data['child_slot']]
            prepared = data['prepared'] if frame['operation'] == 'START' else state['prepared']
            projection = self._projection(frame['operation'], data)
            observed = time.monotonic_ns()
            item = {'kind': 'rpc', 'launcher_id': self.launcher.slot.launcher_id,
                'child_slot': data['child_slot'], 'child_worker_id': state['binding']['worker_id'],
                'prepared_sha256': None if prepared is None else c.prepared_digest(prepared),
                'request': {'sequence': frame['sequence'], 'operation': frame['operation'],
                    'observed_at_ns': observed, 'bytes': len(raw), 'sha256': c.digest(raw),
                    'projection': projection, 'projection_sha256': c.digest(c.canonical(projection))},
                'reply': None, 'local_error': None}
            row = self._row(item, prepared); self.budget.record_request(ticket, row)
            if prepared is not None:
                phase = self.phase(prepared['envelope']['action_deadline_ns'])
            try:
                phase.check()
                with c._deadline_context(phase.deadline):
                    result = self._execute(frame['operation'], data)
                    phase.check()
                    body = {'request_sequence': frame['sequence'], 'status': 'ok', 'code': None, 'data': result}
            except c.LiveError as error:
                self._retain_error(error, state)
                body = {'request_sequence': frame['sequence'], 'status': 'refused', 'code': error.code, 'data': None}
                # Original expired/cancelled work cannot obtain fresh send time.
                if error.code.endswith(('_timeout', '_cancelled')): raise
            operation = p.SUPERVISION_RESPONSES[frame['operation']]
            with c._deadline_context(phase.deadline):
                reply = self.sequence.make(operation, body)
                encoded = p.encode_frame(reply, role='launcher_supervision', direction='reply')
            p._ready(self.channel, writing=True, control=phase)
            count = p.send_once(self.channel, encoded)
            if count != len(encoded): c.fail('unavailable')
            compact = {**body, 'data': None if body['data'] is None else self._projection(operation, body['data'])}
            row['data']['reply'] = {'sequence': reply['sequence'], 'operation': operation,
                'observed_at_ns': time.monotonic_ns(), 'bytes': len(encoded), 'sha256': c.digest(encoded),
                'projection': compact, 'projection_sha256': c.digest(c.canonical(compact))}
            if body['status'] == 'refused': raise c.LiveError(body['code'])
            phase.check()
        except BaseException as error:
            if row is not None:
                row['data']['local_error'] = getattr(error, 'code', 'engagement_live_unavailable')
                if row['data']['local_error'] not in c.ERROR_CODES: row['data']['local_error'] = 'engagement_live_unavailable'
            self._terminal(error, state)
            raise
        finally:
            if row is not None:
                row['observed_at_ns'] = time.monotonic_ns()
                self.budget.finalize(ticket, row)
            else:
                # A malformed/EOF packet has no invented canonical projection.
                self.budget.release(ticket)
            self._request_ticket = None

    def _drain(self):
        for state in self.children.values():
            if state['state'] == 'active_or_rpc' and state['capture'] is not None:
                state['capture'].drain(self.phase(state['prepared']['envelope']['action_deadline_ns']))

    def _run(self):
        import select
        self.thread_id = threading.get_native_id(); self.thread_started_ns = time.monotonic_ns()
        try:
            while not self.stop.is_set():
                phase = self.phase(); phase.check(); self._drain()
                if self._request_ticket is None:
                    self._request_ticket = self.budget.reserve(kind='supervision_projection',
                        maximum_bytes=c.SUPERVISION_ROW_BYTES, maximum_rows=1, control=phase)
                if not select.select([self.channel], [], [], min(.05, phase.remaining()))[0]:
                    continue
                # Authority phases bind the original context internally. The
                # terminal data-only journal path must still retain a refusal
                # after that context has expired; it performs no transport.
                self._exchange(self._request_ticket)
        except BaseException as error:
            if self.failure is None:
                try: self._terminal(error)
                except BaseException: self.failure = error; self.failure_sink(error)
        finally:
            self._finish_owned()

    def _finish_owned(self):
        epoch = self.epoch.stop()
        deadline = epoch['deadline_ns']/c.SECOND
        for state in self.children.values():
            endpoint, state['endpoint'] = state['endpoint'], None
            if endpoint is not None:
                try: endpoint.close()
                except OSError as error: self._failed_channel_close(error, state)
            owner = state['owner']
            if owner is not None:
                try:
                    receipt = owner.close(deadline=deadline)
                    self._append('receipts', receipt)
                    no_start = (not state['pending'] and state['start_resolved']
                        and getattr(owner, 'process', object()) is None
                        and getattr(owner, 'entry', None) is None
                        and receipt.get('processes') == []
                        and receipt.get('descriptors_closed') is True)
                    state['state'] = 'reaped' if _actually_reaped(receipt) or no_start else 'cleanup_pending'
                except BaseException as error:
                    try: self._retain_error(error, state)
                    except BaseException:
                        if self.failure is None: self.failure = error
                    state['state'] = 'cleanup_pending'
            elif not state['pending'] and state['start_resolved']:
                # The fixed start call has resolved without publishing an
                # owner; no process was created. Closure is not a fake reap.
                state['state'] = 'reaped'
            try: self._record_capture(state)
            except c.LiveError: pass
        try: self.channel.close()
        except OSError as error: self._failed_channel_close(error)
        self.closed = self._channel_close_error is None
        if self.closed and self._request_ticket is not None:
            try: self.budget.release(self._request_ticket)
            except c.LiveError: pass
            self._request_ticket = None

    def _failed_channel_close(self, error, state=None):
        if self._channel_close_error is None: self._channel_close_error = error
        if self.failure is None:
            self.failure = c.LiveError('engagement_live_cleanup_incomplete')
            self.failure.close_error = error
            self._failure_state = state
            self.failure_sink(self.failure)

    def _finalize_terminal_tickets(self):
        if self._terminal_finalized: return
        if self.failure is not None and self._terminal_tickets:
            state = self._failure_state
            prepared = None if state is None else state['prepared']
            code = getattr(self.failure, 'code', 'engagement_live_unavailable')
            if code not in c.ERROR_CODES: code = 'engagement_live_unavailable'
            data = {'kind': 'local_failure', 'launcher_id': self.launcher.slot.launcher_id,
                'child_slot': None if state is None else state['binding']['child_slot'],
                'child_worker_id': None if state is None else state['binding']['worker_id'],
                'prepared_sha256': None if prepared is None else c.prepared_digest(prepared),
                'code': code, 'observed_at_ns': time.monotonic_ns(), 'capture_sha256': None, 'cleanup_sha256': None}
            if prepared is not None:
                captured = self._sources['captures'].get(prepared['envelope']['dispatch_id'])
                if captured is not None:
                    data['capture_sha256'] = c.digest(c.canonical(captured['host_capture']))
                if state['owner'] is not None and getattr(state['owner'], 'cleanup', None) is not None:
                    data['cleanup_sha256'] = c.digest(c.canonical(state['owner'].cleanup))
            self.budget.finalize(self._terminal_tickets.pop(0), self._row(data, prepared))
        for ticket in self._terminal_tickets: self.budget.release(ticket)
        self._terminal_tickets.clear()
        self._terminal_finalized = True

    def close(self, deadline):
        started = time.monotonic_ns()
        self.interrupt(bound_deadline_ns=int(deadline*c.SECOND))
        epoch = self.epoch.snapshot()
        if self.thread is not None and self.thread.ident is not None:
            self.join_attempted = True
            self.thread.join(max(0, epoch['deadline_ns']/c.SECOND-time.monotonic()))
        elif not self._start_in_progress:
            self._finish_owned()
        alive = None if self.thread is None else self.thread.is_alive()
        if self.thread is None: alive = False
        pending = [name for name, row in self.children.items()
                   if row['pending'] or row['state'] not in {'allocated', 'reaped'}]
        state = 'unknown' if self._start_in_progress else 'alive' if alive else 'joined' if self.thread_id is not None and self.join_attempted else 'not_started'
        if state == 'unknown': alive = None
        finished = time.monotonic_ns()
        self.closure = {'schema_version': '1', 'broker_id': self.opened['binding']['broker_id'],
            'session_id': self.opened['binding']['session_id'], 'launcher_id': self.launcher.slot.launcher_id,
            'host_observer': self.observer, 'thread_native_id': self.thread_id,
            'thread_started_at_ns': self.thread_started_ns,
            'first_stop_requested_at_ns': epoch['first_stop_requested_at_ns'],
            'cleanup_started_at_ns': max(started, epoch['first_stop_requested_at_ns']),
            'cleanup_deadline_ns': epoch['deadline_ns'], 'cleanup_finished_at_ns': finished,
            'join_attempted': self.join_attempted, 'thread_alive_observed': alive,
            'pending_slots': pending, 'channel_closed': self.closed, 'state': state,
            'status': 'complete' if state in {'joined', 'not_started'} and not alive and not pending and self.closed and finished <= epoch['deadline_ns'] else 'failed'}
        if state in {'joined', 'not_started'} and not alive and self.closed:
            self._finalize_terminal_tickets()
        return self.closure

    @property
    def resolved(self):
        return (self.closure is not None and self.closure['state'] in {'joined', 'not_started'}
                and not self.closure['pending_slots'] and self.closure['channel_closed'])

    def snapshot(self):
        from copy import deepcopy
        with self.state_lock:
            result = deepcopy(self._sources)
        result['supervisors'] = [] if self.closure is None else [c.detached(self.closure)]
        return result


class EngagementLauncher:
    def __init__(self,runtime,*,endpoint,role_slot,host_evidence_budget,cleanup_epoch,failure_sink):
        from .engagement_live_runtime import validate_runtime
        self.runtime=validate_runtime(runtime);self.endpoint=endpoint;self.slot=role_slot
        self._pid=os.getpid();self._owner=None;self._opened=None;self._closed=False;self._cleanup=None
        self._prepared={}
        self._stop=threading.Event()
        self._budget=host_evidence_budget;self._epoch=cleanup_epoch;self._failure_sink=failure_sink
        self._supervisor=None;self._cleanup_error=None

    @property
    def readiness(self):return None if self._owner is None else c.detached(self._owner.ready)

    def _check(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if self._closed or self._stop.is_set():c.fail('session_unavailable')

    def start(self,session_binding,role_bundle,control):
        control.check()
        with c._deadline_context(control.deadline):
            return self._start(session_binding,role_bundle,control)

    def _start(self,session_binding,role_bundle,control):
        from . import engagement_live_runtime as rt
        from .engagement_live_broker import _ClippedControl
        self._check()
        if self._owner is not None:c.fail('session_unavailable')
        opened=c.validate_session_opened(session_binding);binding=opened['binding']
        if self.slot not in role_bundle.slots or binding['reviewer_id']!=self.slot.reviewer_id:c.fail('invalid_role')
        rt.validate_readiness('endpoint',self.endpoint.ready,self.runtime)
        bindings=self.slot.child_slot_bindings
        peers=self.slot.take_launcher_bootstrap();rights={};endpoints={}
        try:
            endpoints=self.slot.take_child_endpoints()
            for key in ('broker_control','endpoint_arm',*(name+'_request' for name in c.CHILD_SLOTS)):
                rights[key]=peers.pop(key).detach()
            transferred,rights=rights,{}
            self._owner=rt._start_role(runtime=self.runtime,role='launcher',payload={
                'session_binding':binding,'roe':opened['roe'],'scope':opened['scope'],'policy':opened['policy'],
                'endpoint_identity':self.endpoint.identity,'child_slots':bindings},rights=transferred,
                control=_ClippedControl(control,opened['binding']['session_deadline_ns'],self._stop,self._epoch),
                stdin_pair=(peers.pop('host'),peers.pop('child')),
                namespace_fds=self.endpoint.namespace_fds,
                expected_net=self.endpoint.identity['parent_observation']['namespaces']['net'],
                worker_id=self.slot.launcher_id)
            self._opened=opened
            self._supervisor=_FixedSupervisor(launcher=self,opened=opened,channel=self._owner.channel,
                bindings=bindings,endpoints=endpoints,control=control,budget=self._budget,
                epoch=self._epoch,failure_sink=self._failure_sink,setup_lock=role_bundle._child_setup_lock)
            self._supervisor.start()
            self._check();control.check()
            return self.readiness
        finally:
            for peer in peers.values():peer.close()
            for fd in rights.values():os.close(fd)
            for peer in endpoints.values():peer.close()

    def prepare(self,prepared,control):
        """Check the host's already acknowledged preparation, with no new RPC."""
        self._check();control.check()
        if self._owner is None:c.fail('session_unavailable')
        self._owner.pin.check_alive()
        value=c.validate_prepared_context(prepared,self._opened)
        did=value['envelope']['dispatch_id']
        if did in self._prepared or len(self._prepared)>=2:c.fail('dispatch_replayed')
        self._prepared[did]=value
        control.check()
        return value

    def _interrupt(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        self._stop.set()
        if self._supervisor is not None:self._supervisor.interrupt()
        if self._owner is not None:
            try:self._owner.channel.shutdown(socket.SHUT_RDWR)
            except OSError:pass

    def _close(self,deadline):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        self._interrupt();self._closed=True
        epoch=self._epoch.stop(bound_deadline_ns=int(deadline*c.SECOND))
        deadline=min(deadline,epoch['deadline_ns']/c.SECOND)
        error=None
        try:
            if self._supervisor is not None:
                closure=self._supervisor.close(deadline)
                if closure['status']!='complete':
                    error=c.LiveError('engagement_live_cleanup_incomplete')
                    error.supervisor_cleanup=closure
        except BaseException as caught:
            error=caught
        finally:
            # Journal/observer failures never strand the actual persistent
            # launcher. Repeat closure may finish custody, not renew time.
            if self._owner is not None:
                try:self._cleanup=self._owner.close(deadline=deadline)
                except BaseException as caught:
                    actual=getattr(caught,'cleanup',None)
                    if actual is not None:self._cleanup=actual
                    if error is None:error=caught
                    else:error.owner_cleanup_error=caught
        if error is not None and self._cleanup_error is None:self._cleanup_error=error
        if self._cleanup_error is not None:
            if self._cleanup is not None:self._cleanup_error.cleanup=self._cleanup
            raise self._cleanup_error
        return self._cleanup

    def close(self):return self._close(time.monotonic()+2)

    @property
    def supervisor_cleanup(self):
        return None if self._supervisor is None else self._supervisor.closure

    @property
    def supervisor_resolved(self):
        return self._supervisor is None or self._supervisor.resolved

    def supervision_snapshot(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if self._supervisor is None:
            return {'child_slots':[],'startup':[],'readiness':[],'native':[],
                    'captures':{},'receipts':[],'supervisors':[],'prepared':[]}
        return self._supervisor.snapshot()

    def evidence(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if not self._closed:c.fail('cleanup_incomplete')
        # Child facts are actual host readbacks; launcher relays remain separate.
        return {'readiness':self.readiness,'cleanup':self._cleanup}
