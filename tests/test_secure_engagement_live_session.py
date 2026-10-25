"""Portable host orchestration checks; no fixture grants native authority."""

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import engagement_live_session as module
from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent.engagement_live_approval import _clipped_control
from recon_cockpit.secure_agent.execution import ExecutionControl
from test_secure_engagement_live_contract import opened, prepared, clock, uid, M

ROOT = Path(__file__).resolve().parents[1]


def cli():
    spec = importlib.util.spec_from_file_location('engagement_live_cli_test', ROOT/'scripts/engagement_live.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def service():
    obj = module.EngagementSession.__new__(module.EngagementSession)
    obj._pid = os.getpid()
    obj._control = ExecutionControl(time.monotonic()+60, threading.Event())
    obj._stop, obj._closing = threading.Event(), threading.Event()
    obj._close_lock, obj._state_lock = threading.Lock(), threading.Lock()
    obj._slot_locks = (threading.Lock(), threading.Lock())
    obj._closed = False
    obj._startup_quiesced = False
    obj._cleanup = obj._failure = obj._broker = obj._audit = obj._bundle = None
    obj._sessions = {}
    obj._operations = {}
    obj._roles = []
    obj._readiness = []
    obj._cleanup_receipts = []
    obj._startup_observations = []
    obj._recovery_helpers = []
    obj._used_slots = set()
    obj._monitor_thread = None
    obj._observer_rows = []
    obj._child_slots = []
    obj._unstarted_supervisors = []
    obj._remaining_channels_closed = False
    obj._host_evidence_budget = module._HostEvidenceBudget()
    obj._cleanup_epoch = module._CleanupEpoch(obj._control)
    selected, value = opened(), prepared()
    row = {'opened': selected, 'ingress': 0, 'stopped': False,
           'reviewer': None, 'endpoint': None, 'launcher': None}
    obj._sessions[selected['binding']['session_id']] = row
    obj._operations[value['envelope']['dispatch_id']] = {'session': selected, 'prepared': value,
        'result': None, 'client': None, 'meter': None, 'host_capture': None,
        'elapsed_ms': dict.fromkeys(('review','admission','native','parser','cleanup','action'))}
    return obj, row, value


def host_row(index=1):
    return {'schema_version':'1','broker_id':uid(1),'observer_id':uid(1),
        'session_id':None,'dispatch_id':None,'row_sequence':1,
        'observed_at_ns':index,'kind':'phase','data':{'clock':None,
        'original_deadline_ns':M,'phase':'prepare','reason':None,
        'related_sha256':None,'stage':'started'}}


def test_default_cli_is_inert_without_execute(tmp_path):
    store, audit, output = (tmp_path/name for name in ('store','audit','evidence'))
    result = subprocess.run([sys.executable, str(ROOT/'scripts/engagement_live.py'),
        '--store-directory', str(store), '--audit-path', str(audit), '--output-directory', str(output)],
        capture_output=True, timeout=3)
    assert result.returncode == 0 and result.stderr == b''
    assert json.loads(result.stdout) == {'schema_version':'1', 'profile':cli().PROFILE,
                                         'execute':False, 'description':cli().DESCRIPTION}
    assert not any(path.exists() for path in (store,audit,output))


def test_rejects_unknown_duplicated_or_expanded_options():
    value = cli()
    for args in (['--execute','--execute'], ['--review-mode=terminal'], ['--unknown'],
                 ['--review-mode','automatic'], ['--store-directory','a\n'], ['--execute'],
                 ['--output-directory'], ['--help','--help']):
        with pytest.raises(ValueError, match='invalid_input'):
            value.parse_options(args)


def test_owned_scope_and_runtime_are_broker_bound():
    obj, row, value = service()
    assert obj._prepared(value)[0] == value
    for field, change in (('scope_sha256','e'*64), ('runtime_sha256','f'*64),
                          ('broker_id',uid(90)), ('ledger_owner_id',uid(91))):
        modified = deepcopy(value)
        modified['envelope'][field] = change
        with pytest.raises(c.LiveError):
            obj._prepared(modified)


def test_session_original_control_cannot_be_replaced():
    obj, row, value = service()
    replacement = ExecutionControl(obj._control.deadline+60, obj._control.cancelled)
    for method in (lambda:obj.review(value,control=replacement),
                   lambda:obj.execute(value,'a'*48,control=replacement)):
        with pytest.raises(c.LiveError, match='invalid_input'):
            method()
    obj._control.cancelled.set()
    with pytest.raises(Exception, match='session_cancelled'):
        obj._check(obj._control)
    budget = module._HostEvidenceBudget()
    control = ExecutionControl(time.monotonic()+10)
    ticket = budget.reserve(kind='other_host', maximum_bytes=4096, maximum_rows=1, control=control)
    row = host_row()
    budget.record_request(ticket,row)
    with pytest.raises(c.LiveError, match='evidence_invalid'):
        budget.release(ticket)
    changed = deepcopy(row)
    changed['data']['phase'] = 'cleanup'
    with pytest.raises(c.LiveError, match='evidence_invalid'):
        budget.finalize(ticket,changed)
    assert budget.snapshot()['unresolved_tickets'] == 1
    budget.finalize(ticket,row)
    row['data']['phase'] = 'cleanup'
    assert budget.snapshot()['rows'][0]['data']['phase'] == 'prepare'
    with pytest.raises(c.LiveError, match='evidence_invalid'):
        budget.finalize(ticket,host_row())
    budget._pid += 1
    with pytest.raises(c.LiveError, match='foreign_owner'):
        budget.snapshot()


def test_prepare_echo_cannot_change_revision_or_scope():
    obj, row, value = service()
    obj._operations.clear()
    reached = []
    row['launcher'] = SimpleNamespace(prepare=lambda *a:reached.append(True))
    for field, change in (('revision',2),('scope_sha256','f'*64)):
        modified = deepcopy(value)
        modified['envelope'][field] = change
        obj._broker = SimpleNamespace(prepare=lambda *a, **kw:{'prepared':modified,'preparation':None})
        with pytest.raises(c.LiveError):
            obj.prepare(value['envelope']['session_id'],'http_identify')
    assert not reached and not obj._operations
    obj._broker = SimpleNamespace(prepare=lambda *a,**kw:{'prepared':value,'preparation':None})
    def partial_setup(*a):
        raise c.LiveError('engagement_live_unavailable')
    row['launcher'].prepare = partial_setup
    with pytest.raises(c.LiveError,match='unavailable'):
        obj.prepare(value['envelope']['session_id'],'http_identify')
    assert obj._operations[value['envelope']['dispatch_id']]['result'] is None


def test_execute_requires_actual_review_reference():
    obj, row, value = service()
    attempted = []
    row['reviewer'] = SimpleNamespace(consume=lambda *a, **kw: attempted.append(a) or {'accepted':False})
    for reference in (True, None, {'approved':True}):
        with pytest.raises(c.LiveError, match='approval_unknown_or_replayed'):
            obj.execute(value,reference,control=obj._control)
    assert not attempted
    with pytest.raises(c.LiveError, match='approval_unknown_or_replayed'):
        obj.execute(value,'a'*48,control=obj._control)
    assert len(attempted) == 1


def test_startup_failure_closes_every_created_role(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    from recon_cockpit.secure_agent import engagement_live_broker as broker
    from recon_cockpit.secure_agent import engagement_live_audit as audit
    calls, startup_epochs = [], []
    now = time.monotonic_ns()
    receipt = {'schema_version':'1','started_at_ns':now,'finished_at_ns':now,
               'deadline_ns':now+2000000000,'status':'complete','processes':[], 'descriptors_closed':True}
    class Broker:
        def __init__(self, **kw):startup_epochs.append(kw['cleanup_epoch'])
        def start(self):return {'readiness':{'portable_observation':True},'allocated_slots':[]}
        def _interrupt(self):calls.append('broker_interrupt')
        def _close(self, deadline):calls.append(('broker_close',deadline));return receipt
    class Audit:
        def __init__(self, *a, **kw):startup_epochs.append(kw['cleanup_epoch'])
        def start(self):raise c.LiveError('engagement_live_audit_unavailable')
        def _interrupt(self):calls.append('audit_interrupt')
        def _close(self, deadline):calls.append(('audit_close',deadline));return receipt
    monkeypatch.setattr(runtime,'inspect_runtime',lambda control:{'pure_fixture':True})
    monkeypatch.setattr(broker,'preallocate_role_bundle',lambda mode:SimpleNamespace(slots=[],close=lambda:calls.append('bundle_close')))
    monkeypatch.setattr(broker,'EngagementBroker',Broker)
    monkeypatch.setattr(audit,'EngagementAuditService',Audit)
    with pytest.raises(c.LiveError, match='audit_unavailable') as caught:
        module.EngagementSession.start('unused','unused',review_mode='terminal',
                                      control=ExecutionControl(time.monotonic()+60))
    deadlines = [v[1] for v in calls if type(v)is tuple]
    assert len(deadlines)==2 and len(set(deadlines))==1
    assert calls.index('audit_interrupt') < next(i for i,v in enumerate(calls) if type(v)is tuple)
    assert caught.value.engagement_session._closed
    assert len(startup_epochs) == 2
    assert all(epoch is caught.value.engagement_session._cleanup_epoch for epoch in startup_epochs)

    # A second startup's local cleanup must stop an already-running peer before
    # it spends its reap budget. Notifications can recursively tighten the
    # epoch, and one failed interrupt cannot prevent the remaining peers.
    stopping, _, _ = service()
    stopping._cleanup_epoch = module._CleanupEpoch(stopping._control,
        stop_event=stopping._stop, on_stop=stopping._request_stop)
    events = []
    bound = time.monotonic_ns()+c.SECOND
    def broken_interrupt():
        events.append('first_peer')
        raise OSError('modeled shutdown failure')
    def peer_interrupt():
        assert stopping._stop.is_set()
        stopping._cleanup_epoch.stop(bound_deadline_ns=bound)
        events.append('second_peer')
    stopping._roles = [SimpleNamespace(_interrupt=broken_interrupt),
                       SimpleNamespace(_interrupt=peer_interrupt)]
    startup = _clipped_control(stopping._control, int(stopping._control.deadline*c.SECOND),
                               stopping._stop, stopping._cleanup_epoch)
    startup.check()
    assert not events and stopping._cleanup_epoch.snapshot() is None
    deadline = startup.cleanup_deadline
    assert events == ['first_peer', 'second_peer'] and isinstance(stopping._failure, OSError)
    assert int(deadline*c.SECOND) <= bound
    before = stopping._cleanup_epoch.snapshot()
    assert startup.cleanup_deadline == deadline
    assert stopping._cleanup_epoch.snapshot() == before and len(events) == 2
    with pytest.raises(c.LiveError, match='cancelled'): startup.check()

    # Publication must fence concurrent work even if the notifying thread is
    # paused before interrupting peers. The second caller must not await it.
    entered, release, stopped = threading.Event(), threading.Event(), threading.Event()
    def delayed_notice():
        entered.set()
        release.wait(1)
    epoch = module._CleanupEpoch(stopping._control, stop_event=stopped, on_stop=delayed_notice)
    work = _clipped_control(stopping._control, int(stopping._control.deadline*c.SECOND),
                            cleanup_epoch=epoch)
    notifier = threading.Thread(target=epoch.stop)
    notifier.start()
    try:
        assert entered.wait(.5) and stopped.is_set() and epoch.stopped
        first = epoch.snapshot()
        assert epoch.stop() == first
        with pytest.raises(c.LiveError, match='cancelled'): work.check()
    finally:
        release.set()
        notifier.join(timeout=1)
    assert not notifier.is_alive()

    # Session must signal both real host threads before joining either, and
    # preserve endpoint descriptor custody until both have actually exited.
    obj, row, _ = service()
    events, launchers = [], []
    class Launcher:
        def __init__(self, name):
            self.name, self.joined = name, False
            self.stop = threading.Event()
            self.thread = threading.Thread(target=lambda:self.stop.wait(2))
            self.thread.start()
        def _interrupt(self):
            events.append(('stop', self.name))
            self.stop.set()
        @property
        def supervisor_resolved(self):
            return self.joined and not self.thread.is_alive()
        def _close(self, deadline):
            assert all(item.stop.is_set() for item in launchers)
            self.thread.join(timeout=max(0, deadline-time.monotonic()))
            self.joined = True
            events.append(('join', self.name))
            return receipt
    class Endpoint:
        def _interrupt(self):pass
        def _close(self, deadline):
            assert all(item.supervisor_resolved for item in launchers)
            events.append(('endpoint', deadline))
            return receipt
    launchers.extend((Launcher('one'), Launcher('two')))
    row['launcher'], row['endpoint'] = launchers[0], Endpoint()
    obj._sessions[uid(98)] = {**row, 'launcher':launchers[1], 'endpoint':Endpoint()}
    obj._roles = [row['endpoint'], launchers[0], obj._sessions[uid(98)]['endpoint'], launchers[1]]
    assert obj.close()['status'] == 'complete'
    assert [event[0] for event in events[:2]] == ['stop','stop']
    assert [event[0] for event in events[2:4]] == ['join','join']
    assert obj._verified_reaped()
    assert obj._cleanup['deadline_ns'] == obj._cleanup_epoch.snapshot()['deadline_ns']

    tightened, _, _ = service()
    bound = time.monotonic_ns()+c.SECOND
    observed_deadlines, joined_at = [], []
    role = SimpleNamespace(
        _interrupt=lambda:tightened._cleanup_epoch.stop(bound_deadline_ns=bound),
        _close=lambda deadline:observed_deadlines.append(deadline) or receipt)
    tightened._roles = [role]
    tightened._monitor_thread = SimpleNamespace(
        join=lambda **kw:joined_at.append(time.monotonic_ns()),is_alive=lambda:False)
    actual = tightened.close()
    assert observed_deadlines == [bound/c.SECOND]
    assert actual['deadline_ns'] == bound
    assert actual['finished_at_ns'] >= joined_at[0]

    # Preallocation is retained even when no launcher was opened. Only actual
    # socket closure behind the terminal startup fence justifies not_started.
    unused, _, _ = service()
    unused._child_slots = [{'broker_id':uid(1),'session_id':uid(90),
                           'launcher_id':uid(91),'child_slot':name} for name in c.CHILD_SLOTS]
    observer = {'portable_actual_observer':True}
    monkeypatch.setattr(runtime,'_observer',lambda:observer)
    fenced = []
    def close_unused():
        assert unused._startup_quiesced and unused._stop.is_set()
        fenced.append(True)
    unused._bundle = SimpleNamespace(close_remaining_channels=close_unused)
    assert unused.close()['status'] == 'complete'
    assert fenced == [True] and unused._verified_reaped()
    closure, = unused._unstarted_supervisors
    assert closure['state'] == 'not_started' and closure['channel_closed']
    assert closure['thread_native_id'] is closure['thread_started_at_ns'] is None
    assert not closure['join_attempted'] and closure['thread_alive_observed'] is False
    assert closure['host_observer'] == observer and not closure['pending_slots']
    failed_unused, _, _ = service()
    failed_unused._child_slots = deepcopy(unused._child_slots)
    def cannot_close():
        raise OSError('owned endpoint close failed')
    failed_unused._bundle = SimpleNamespace(close_remaining_channels=cannot_close)
    with pytest.raises(c.LiveError,match='cleanup_incomplete'):
        failed_unused.close()
    assert not failed_unused._verified_reaped() and not failed_unused._unstarted_supervisors

    unresolved, pending, _ = service()
    touched = []
    pending['launcher'] = SimpleNamespace(supervisor_resolved=False,
        _interrupt=lambda:None,_close=lambda deadline:receipt)
    pending['endpoint'] = SimpleNamespace(_interrupt=lambda:None,
        _close=lambda deadline:touched.append(True) or receipt)
    unresolved._roles = [pending['endpoint'], pending['launcher']]
    with pytest.raises(c.LiveError, match='cleanup_incomplete'):
        unresolved.close()
    assert not touched and not unresolved._verified_reaped()
    assert not unresolved._cleanup['descriptors_closed']

    # Persistent role startup and child setup share the same single helper
    # slot. A queued API caller must stop without starting another builder.
    queued, _, _ = service()
    entered, release = threading.Event(), threading.Event()
    startup_calls, startup_errors = [], []
    queued._bundle = SimpleNamespace(_child_setup_lock=threading.Lock())
    def opening(*, ingress):
        startup_calls.append(ingress)
        entered.set()
        assert release.wait(2)
        raise c.LiveError('engagement_live_invalid_prepared')
    queued._broker = SimpleNamespace(open_session=opening)
    def open_slot(index):
        try:queued._open_session(ingress=index)
        except c.LiveError as error:startup_errors.append(error.code)
    one = threading.Thread(target=open_slot,args=(0,))
    two = threading.Thread(target=open_slot,args=(1,))
    one.start()
    assert entered.wait(2)
    two.start()
    time.sleep(.02)
    assert startup_calls == [0]
    release.set()
    one.join(2);two.join(2)
    assert not one.is_alive() and not two.is_alive()
    assert startup_calls == [0] and len(startup_errors) == 2


def test_cancel_and_eof_do_not_start_followup():
    obj, row, value = service()
    events = []
    row['reviewer'] = SimpleNamespace(_interrupt=lambda:events.append('review_interrupted'))
    obj._broker = SimpleNamespace(cancel=lambda sid:events.append('broker_cancel'))
    obj.cancel(value['envelope']['session_id'])
    assert events == ['review_interrupted','broker_cancel']
    with pytest.raises(c.LiveError, match='session_unavailable'):
        obj.review(value,control=obj._control)
    obj._stop.set()
    with pytest.raises(c.LiveError, match='session_unavailable'):
        obj.prepare(value['envelope']['session_id'],'http_headers')


def test_lease_narrowing_never_renews_original_deadline(monkeypatch):
    _idle_session_cleanup_reserve()
    _terminal_cleanup_budget_paths(monkeypatch)
    obj, row, value = service()
    original = obj._control
    tighter = _clipped_control(original,int((original.deadline-3)*c.SECOND),obj._stop)
    assert tighter.original is original and tighter.deadline <= original.deadline-3
    assert tighter.cancelled is original.cancelled and tighter.clock is original.clock
    attempted_renewal = _clipped_control(original,int((original.deadline+100)*c.SECOND),obj._stop)
    assert attempted_renewal.deadline == original.deadline
    obj._stop.set()
    with pytest.raises(c.LiveError, match='cancelled'):
        tighter.check()
    ticks = [10*c.SECOND]
    monkeypatch.setattr(module.time, 'monotonic_ns', lambda:ticks[0])
    epoch = module._CleanupEpoch(SimpleNamespace(deadline=20))
    first = epoch.stop()
    assert first == {'first_stop_requested_at_ns':10*c.SECOND,'deadline_ns':11_900_000_000}
    ticks[0] += 9*c.SECOND
    assert epoch.stop() == first
    assert epoch.stop(bound_deadline_ns=11*c.SECOND)['deadline_ns'] == 11*c.SECOND
    assert epoch.stop()['deadline_ns'] == 11*c.SECOND
    assert epoch.stop(bound_deadline_ns=30*c.SECOND)['deadline_ns'] == 11*c.SECOND
    assert epoch.snapshot()['first_stop_requested_at_ns'] == first['first_stop_requested_at_ns']
    ticks[0] = 10*c.SECOND
    original = module._CleanupEpoch(SimpleNamespace(deadline=11))
    assert original.stop(bound_deadline_ns=12*c.SECOND)['deadline_ns'] == 11*c.SECOND
    received = module._CleanupEpoch(SimpleNamespace(deadline=20))
    assert received.stop(bound_deadline_ns=10_500_000_000)['deadline_ns'] == 10_500_000_000
    expired = module._CleanupEpoch(SimpleNamespace(deadline=1))
    assert expired.stop()['deadline_ns'] == c.SECOND


def _terminal_cleanup_budget_paths(monkeypatch):
    # Exercise the monitor/close graph with declared role cleanup. The pidfd
    # readiness is a stub; the EOF is a real local socket EOF, never a native
    # worker or kernel-containment claim.
    import select
    import socket
    from recon_cockpit.secure_agent.engagement_live_broker import EngagementBroker

    for trigger in ('broker_death','lifecycle_eof','received_stop','direct_close'):
        obj,_,_=service();obj._sessions.clear();obj._operations.clear()
        obj._cleanup_epoch=module._CleanupEpoch(obj._control,stop_event=obj._stop,on_stop=obj._request_stop)
        observed=[];polled=[];host,peer=socket.socketpair()
        wire_deadline=time.monotonic_ns()+500_000_000
        event={'operation':'BROKER_STOP','body':{'cleanup_deadline_ns':wire_deadline}}
        handle=SimpleNamespace(_owner=object(),bundle=SimpleNamespace(host_lifecycle=host),
            _deadline_ns=int(obj._control.deadline*c.SECOND),_cleanup_epoch=obj._cleanup_epoch,
            control=obj._control,_lifecycle=SimpleNamespace(accept=lambda frame:frame))
        def poll():
            polled.append(trigger)
            return EngagementBroker.poll_lifecycle(handle) if trigger=='lifecycle_eof' else event
        def close_role(deadline):
            now=time.monotonic_ns();observed.append(deadline)
            return {'schema_version':'1','started_at_ns':now,'finished_at_ns':now,
                'deadline_ns':int(deadline*c.SECOND),'status':'complete','processes':[],
                'descriptors_closed':True}
        ready_pin=object()
        role=SimpleNamespace(pidfd=ready_pin if trigger=='broker_death' else None,
            poll_lifecycle=poll,_interrupt=lambda:None,_close=close_role)
        obj._broker=role;obj._roles=[role]
        try:
            peer.close()
            with monkeypatch.context() as patch:
                if trigger=='broker_death':
                    def ready(reads,writes,errors,timeout):
                        assert reads==[ready_pin] and not writes and not errors and timeout==0
                        return reads,[],[]
                    patch.setattr(select,'select',ready)
                if trigger=='direct_close':obj.close()
                else:obj._monitor()
            epoch=obj._cleanup_epoch.snapshot()
            expected=min(int(obj._control.deadline*c.SECOND),epoch['first_stop_requested_at_ns']+1_900_000_000)
            if trigger=='received_stop':expected=min(expected,wire_deadline)
            assert epoch['deadline_ns']==expected and observed==[expected/c.SECOND]
            assert obj._cleanup['status']=='complete' and obj._verified_reaped()
            assert obj._cleanup['finished_at_ns']<=epoch['deadline_ns']
            assert obj.close()==obj._cleanup and obj._cleanup_epoch.snapshot()==epoch
            if trigger in ('broker_death','direct_close'):
                assert not polled
                assert wire_deadline<epoch['deadline_ns']
            else:assert polled==[trigger]
            if trigger=='direct_close':assert obj._failure is None
            else:
                expected_error='engagement_live_invalid_frame' if trigger=='lifecycle_eof' else 'engagement_live_session_unavailable'
                assert obj._failure.code==expected_error
        finally:
            host.close();peer.close()


def _idle_session_cleanup_reserve():
    # Real monitor thread, with declared role cleanup; no native process claim.
    obj,_,_=service();obj._sessions.clear();obj._operations.clear()
    obj._control=ExecutionControl(time.monotonic()+2.25)
    obj._cleanup_epoch=module._CleanupEpoch(obj._control,stop_event=obj._stop,on_stop=obj._request_stop)
    observed=[]
    def close_role(deadline):
        now=time.monotonic_ns();observed.append((now,deadline))
        return {'schema_version':'1','started_at_ns':now,'finished_at_ns':now,
            'deadline_ns':int(deadline*c.SECOND),'status':'complete','processes':[], 'descriptors_closed':True}
    role=SimpleNamespace(pidfd=None,poll_lifecycle=lambda:None,_interrupt=lambda:None,_close=close_role)
    obj._broker=role;obj._roles=[role]
    thread=threading.Thread(target=obj._monitor);obj._monitor_thread=thread
    original=int(obj._control.deadline*c.SECOND)
    try:
        thread.start();thread.join(.7)
        assert not thread.is_alive()
        assert obj._failure.code=='engagement_live_timeout'
        assert obj._cleanup['status']=='complete' and obj._verified_reaped()
        epoch=obj._cleanup_epoch.snapshot()
        assert original-c.CLEANUP_NS<=epoch['first_stop_requested_at_ns']<original-c.SECOND
        assert epoch['deadline_ns']<=min(original,epoch['first_stop_requested_at_ns']+1_900_000_000) and observed
        assert all(at<epoch['deadline_ns'] and bound<=original/c.SECOND for at,bound in observed)
    finally:
        obj._closing.set();obj._stop.set();thread.join(.5)
        if not obj._closed:obj.close()


def test_uncertain_dispatch_is_never_retried(monkeypatch, tmp_path):
    obj, row, value = service()
    events = []
    row['reviewer'] = SimpleNamespace(consume=lambda *a, **kw:
        {'accepted':True,'reference_sha256':'a'*64,'consume_sequence':1,'witness_sha256':'b'*64})
    obj._audit = SimpleNamespace(emit=lambda *a, **kw:events.append('audit') or {'sequence':1})
    def dispatch(*a, **kw):
        events.append('dispatch')
        raise c.LiveError('engagement_live_unavailable')
    obj._broker = SimpleNamespace(_dispatch_with_control=dispatch)
    with pytest.raises(c.LiveError, match='unavailable') as caught:
        obj.execute(value,'a'*48,control=obj._control)
    assert events == ['audit','dispatch']
    assert obj._operations[value['envelope']['dispatch_id']]['result'] is None

    # An outer dispatch failure must retain the supervisor's distinct first
    # error and actual cleanup facts without calling live owner methods.
    from engagement_live_native import _save_case_failure
    def first_supervisor_failure():
        private_local = 'not-for-failure-artifacts'
        raise c.LiveError('engagement_live_invalid_runtime')
    try:
        first_supervisor_failure()
    except c.LiveError as error:
        first = error
    closure = {'state':'joined','status':'failed','pending_slots':[], 'channel_closed':False}
    def forbidden_snapshot():
        raise AssertionError('failure capture must only read retained state')
    supervisor = SimpleNamespace(failure=first, closure=closure, snapshot=forbidden_snapshot)
    row['launcher'] = SimpleNamespace(_supervisor=supervisor)
    obj._failure = first
    obj._cleanup = {'status':'failed', 'descriptors_closed':False, 'processes':[]}
    retained_row = {'kind':'supervision_projection',
        'session_id':value['envelope']['session_id'], 'data':{'kind':'local_failure'}}
    obj._host_evidence_budget._rows.append(retained_row)
    obj._host_evidence_budget.snapshot = forbidden_snapshot
    caught.value.engagement_session = obj
    _save_case_failure(tmp_path, 'core', 'portable_first_failure_retention', caught.value)
    raw = (tmp_path/'case-failure.json').read_bytes()
    saved = json.loads(raw)
    assert saved['acceptance'] is False
    assert b'not-for-failure-artifacts' not in raw
    session_record = saved['sessions'][0]
    first_index = session_record['first_failure_index']
    assert first_index == session_record['supervisors'][0]['failure_index']
    assert first_index != 0
    assert saved['exception_chain'][first_index]['code'] == 'engagement_live_invalid_runtime'
    observations = {(item['owner'], item['attribute']):item['value'] for item in saved['observations']}
    assert observations[('session:0', '_cleanup')] == obj._cleanup
    assert observations[('session:0:supervisor:0', 'closure')] == closure
    assert observations[('session:0', 'finalized_supervision_rows')]['rows'] == [retained_row]
    trace = observations[('exception:'+str(first_index), 'traceback')]
    assert trace['frames'][-1]['function'] == 'first_supervisor_failure'
    assert trace['traversal_truncated'] is False
    assert supervisor.failure is first and obj._failure is first
    assert events == ['audit','dispatch']

    # Sealing runs after the native context has already closed. Its failure
    # must keep that existing owner's facts without running owner methods.
    from engagement_live_native import _retain_payload_failure, _seal_case_payload, _write_case_payload
    from recon_cockpit.secure_agent import engagement_live_evidence as saved_evidence
    obj._closed = obj._startup_quiesced = True
    cleanup = {'schema_version':'1','started_at_ns':100,'finished_at_ns':120,'deadline_ns':150,
        'status':'complete','descriptors_closed':True,'processes':[{'role':'broker','pid':123,
            'start_time_ticks':456,'wrapper_pid':122,'wrapper_returncode':-9,'pin_verified':True,
            'signal_attempted':True,'exit_observed':True,'reaped_observed':True}]}
    obj._cleanup = cleanup
    obj._cleanup_receipts = [deepcopy(cleanup)]
    obj._recovery_helpers = [{'schema_version':'1','helper_id':uid(970),'broker_id':uid(971),
        'generation':0,'status':'failed','process':{'pid':124,'reaped_observed':True},
        'cleanup':{'status':'complete','scratch_disposition':'removed'},
        'error':{'phase':'rw_validation','code':'engagement_live_unavailable'}}]
    supervisor.closure = {'state':'joined','status':'complete','pending_slots':[], 'channel_closed':True}
    phases=[]
    for index in range(10):
        phase=host_row(index+1)
        phase.update(broker_id=value['envelope']['broker_id'],observer_id=value['envelope']['broker_id'],
            session_id=value['envelope']['session_id'],dispatch_id=value['envelope']['dispatch_id'])
        phase['data'].update(phase='reserve' if index>=8 else 'prepare',
            stage='begin' if index%2==0 else 'end',related_sha256=c.prepared_digest(value))
        phases.append(phase)
    foreign=deepcopy(phases[0]);foreign['session_id']=uid(99)
    obj._host_evidence_budget._rows.extend([*phases,foreign])
    associated=SimpleNamespace(_cleanup={'status':'failed','processes':[]},
        _cleanup_receipts=[],_startup_observations=[],_sessions={})
    for boundary in ('single_seal','multi_payload','writer_refusal'):
        for association in ('absent','none','existing'):
            payload_calls=[];writer_calls=[]
            original=c.LiveError('engagement_live_output_exists' if boundary=='writer_refusal' else 'engagement_live_unavailable')
            if association!='absent':original.engagement_session=associated if association=='existing' else None
            def payload_attempt(**kwargs):
                payload_calls.append(kwargs)
                assert obj._closed is True
                if boundary=='writer_refusal':return {},{}
                raise original
            def refusing_writer(destination,**kwargs):
                writer_calls.append((destination,kwargs))
                raise original
            with monkeypatch.context() as patch:
                patch.setattr(obj,'_evidence_payload',payload_attempt)
                patch.setattr(saved_evidence,'write_live_bundle',refusing_writer)
                for name in ('snapshot','_recover_ledger','close'):
                    patch.setattr(obj,name,forbidden_snapshot)
                with pytest.raises(c.LiveError) as sealed:
                    if boundary=='single_seal':
                        _seal_case_payload(obj,{'id':'S42C-N42'},before=None,recover=True)
                    elif boundary=='multi_payload':
                        with _retain_payload_failure(obj):
                            obj._evidence_payload(case_id='S42C-N43',recover=True)
                    else:
                        with _retain_payload_failure(obj):
                            manifest,members=obj._evidence_payload(case_id='S42C-N32',recover=True)
                            _write_case_payload(tmp_path/'unwritten',(manifest,members,time.monotonic()+15))
                assert sealed.value is original
                expected=associated if association=='existing' else obj
                assert original.engagement_session is expected
                directory=tmp_path/('payload-failure-'+boundary+'-'+association)
                directory.mkdir(mode=0o700)
                _save_case_failure(directory,'core','portable_postcontext_payload_failure',original)
            assert len(payload_calls)==1 and payload_calls[0]['recover'] is True
            assert len(writer_calls)==(1 if boundary=='writer_refusal' else 0)
            assert not (tmp_path/'unwritten').exists()
            retained=(directory/'case-failure.json').read_bytes()
            assert len(retained)<=262144
            failure=json.loads(retained)
            assert failure['acceptance'] is False and failure['exception_chain'][0]['session_index']==0
            facts={(item['owner'],item['attribute']):item['value'] for item in failure['observations']}
            assert facts[('session:0','_cleanup')]==expected._cleanup
            assert facts[('session:0','_cleanup_receipts')]==expected._cleanup_receipts
            if association=='existing':
                assert failure['sessions'][0]['supervisors']==[]
                assert ('session:0','finalized_phase_rows') not in facts
            else:
                assert facts[('session:0','_recovery_helpers')]==obj._recovery_helpers
                projected=facts[('session:0','recovery_helper_closure_rows')]
                assert projected['rows']==obj._recovery_helpers
                assert projected['observed_helper_rows']==projected['retained_helper_rows']==1
                assert projected['omitted_helper_rows']==0 and projected['work_included'] is False
                assert facts[('session:0:supervisor:0','closure')]==supervisor.closure
                assert facts[('session:0','finalized_supervision_rows')]['rows']==[retained_row]
                tail=facts[('session:0','finalized_phase_rows')]
                assert tail=={'rows':phases[-8:],'observed_matching_rows':10,'earlier_rows_omitted':2,
                    'scope':'finalized_rows_only_nonatomic_diagnostic_tail'}
                assert {'owner':'session:0','attribute':'finalized_phase_rows','reason':'row_tail_limit'} in failure['omitted']
                assert failure['capture_complete'] is False
    # A permitted long journal record list may exceed the diagnostic capsule's
    # independent list cap. Its actual process/cleanup facts still survive.
    helper=deepcopy(obj._recovery_helpers[0]);helper['work']={'records':[{'index':i} for i in range(95)]}
    obj._recovery_helpers=[helper]
    original=c.LiveError('engagement_live_unavailable');original.engagement_session=obj
    directory=tmp_path/'large-recovery-failure';directory.mkdir(mode=0o700)
    with monkeypatch.context() as patch:
        for name in ('snapshot','_recover_ledger','close'):patch.setattr(obj,name,forbidden_snapshot)
        _save_case_failure(directory,'core','portable_large_recovery_failure',original)
    encoded=(directory/'case-failure.json').read_bytes();assert len(encoded)<=262144
    failure=json.loads(encoded)
    facts={(item['owner'],item['attribute']):item['value'] for item in failure['observations']}
    assert ('session:0','_recovery_helpers') not in facts
    projection=facts[('session:0','recovery_helper_closure_rows')]
    assert projection['rows']==[{key:value for key,value in helper.items() if key!='work'}]
    assert projection['observed_helper_rows']==projection['retained_helper_rows']==1
    assert projection['omitted_helper_rows']==0 and projection['work_included'] is False
    assert {'owner':'session:0','attribute':'_recovery_helpers','reason':'unretained_value'} in failure['omitted']
    assert failure['capture_complete'] is False and failure['acceptance'] is False
    assert original.engagement_session is obj and obj._recovery_helpers==[helper]
    assert events == ['audit','dispatch']

    # Observe the actual full send / decoded reply before protocol postchecks.
    # A late postcheck must not erase a real effect or cause a dispatch retry.
    import socket
    from engagement_live_native import _observe_ingress
    from recon_cockpit.secure_agent import engagement_live_protocol as protocol
    request = {'schema_version':'1','operation':'DISPATCH','channel_id':uid(91),'sequence':1,
        'body':{'prepared_sha256':c.prepared_digest(value),'reference_sha256':'a'*64,
                'consume_sequence':1,'audit_sequence':1}}
    e=value['envelope']
    result={'schema_version':'1','broker_id':e['broker_id'],'session_id':e['session_id'],
        'dispatch_id':e['dispatch_id'],'envelope_sha256':c.envelope_digest(e),'slot':e['slot'],
        'outcome':'unresolved','reason':'engagement_live_unavailable','admission':None,
        'release':None,'completion':None,'observation':None,'client_result_sha256':None,'cleanup_sha256':None}
    original_send,original_decode=protocol.send_once,protocol.decode_frame
    for mode,statuses in (('normal',('pending','ok')),('normal',('refused',)),
                          ('send_expired',()),('receive_expired',('pending',)),('short_send',())):
        observed, _, _ = service();now=[10.];calls=[]
        def remaining():
            if now[0]>=11.:raise c.LiveError('engagement_live_timeout')
            return 11.-now[0]
        control=SimpleNamespace(deadline=11.,remaining=remaining,check=lambda:remaining())
        replies=[]
        for index,status in enumerate(statuses):
            body={'request_sequence':1,'status':status,'code':None,'data':result}
            if status=='pending':body['data']={'dispatch_id':e['dispatch_id']}
            if status=='refused':body.update(code='engagement_live_unavailable',data=None)
            replies.append({'schema_version':'1','operation':'DISPATCH','channel_id':uid(91),
                            'sequence':index+1,'body':body})
        reply_raw=[c.canonical(frame) for frame in replies]
        from test_secure_engagement_live_runtime import PortablePacket
        parent,peer=socket.socketpair();parent=PortablePacket(parent)
        def actual_send(channel,raw):
            calls.append('send')
            assert observed._host_evidence_budget.snapshot()['reserved_rows']==3
            count=original_send(channel,raw[:-1] if mode=='short_send' else raw)
            if mode=='send_expired':now[0]=11.01
            return count
        def actual_decode(*args,**kwargs):
            frame=original_decode(*args,**kwargs);calls.append('decoded')
            if mode=='receive_expired':now[0]=11.01
            return frame
        try:
            with monkeypatch.context() as patch:
                patch.setattr(module.time,'monotonic',lambda:now[0])
                patch.setattr(protocol,'send_once',actual_send);patch.setattr(protocol,'decode_frame',actual_decode)
                with _observe_ingress(observed):
                    def exchange():
                        with c._deadline_context(control.deadline):
                            protocol.send_packet(parent,request,role='ingress',control=control)
                            assert peer.recv(32768)==c.canonical(request)
                            for encoded in reply_raw:
                                peer.sendall(encoded)
                                protocol.receive_packet(parent,role='ingress',control=control)
                    if mode=='normal':exchange()
                    else:
                        with pytest.raises(c.LiveError,match='timeout' if mode.endswith('expired') else 'unavailable'):exchange()
                retained=observed._host_evidence_budget.snapshot()
            assert retained['unresolved_tickets']==0 and calls.count('send')==1
            expected=0 if mode=='short_send' else 1+len(statuses)
            assert len(retained['rows'])==expected
            assert [item['data']['frame']['body']['status'] for item in retained['rows'][1:]]==list(statuses)
            if mode=='send_expired':assert peer.recv(32768)==c.canonical(request)
        finally:parent.close();peer.close()


def test_recovery_opens_fresh_owner_without_replenishing(tmp_path,monkeypatch):
    _recovery_payload_merge_cases()
    _recovery_frame_cases()
    _recovery_owner_coordination_cases(tmp_path,monkeypatch)
    _recovery_packaging_snapshot_cases(monkeypatch)
    _copied_recovery_primitive_cases(tmp_path,monkeypatch)
    from test_secure_engagement_dispatch_store import new_store
    obj, row, value = service()
    created = new_store(tmp_path)
    before = created.snapshot()
    old_owner = created.owner_reference
    obj._store_directory = created.directory
    created.close()
    with pytest.raises(c.LiveError, match='cleanup_incomplete'):
        obj._recover_ledger()
    obj._closed = True
    obj._startup_quiesced = True
    obj._cleanup = {'status':'failed'}
    receipt={'status':'failed','descriptors_closed':True,'processes':[{
        'pid':123,'start_time_ticks':456,'wrapper_pid':122,'wrapper_returncode':0,
        'exit_observed':True,'reaped_observed':False}]}
    obj._cleanup_receipts=[receipt]
    obj._host_evidence_budget._session_owners.append(obj)
    with pytest.raises(c.LiveError,match='cleanup_incomplete'):
        obj._recover_ledger()
    receipt['processes'][0]['reaped_observed']=True
    raw, proof = obj._recover_ledger()
    assert json.loads(raw) == before and proof['owner_id'] != old_owner
    assert proof['read_only'] and proof['closed']
    assert proof['ledger_state_sha256'] == before['events'][-1]['receipt']['state_sha256']
    assert proof['finished_at_ns']-proof['started_at_ns'] <= 2000000000
    row['launcher'] = SimpleNamespace(supervisor_resolved=False)
    with pytest.raises(c.LiveError, match='cleanup_incomplete'):
        obj._recover_ledger()
    row['launcher'].supervisor_resolved = True
    obj._startup_quiesced = False
    with pytest.raises(c.LiveError, match='cleanup_incomplete'):
        obj._recover_ledger()


def _recovery_payload_merge_cases():
    """Merger-only declared payloads: no runtime or helper proof is asserted."""
    from engagement_live_native import _merge_core_payloads
    def payload(generation, *, helper=True, complete=True, direct=False):
        observer={'helper_id':uid(970+generation),'broker_id':uid(980+generation),
            'generation':generation,'status':'complete' if complete else 'failed'}
        recovery={'owner_id':uid(990+generation),'source':'postcleanup_readonly' if direct else 'postcleanup_copied_recovery'} if complete else None
        unavailable={'status':'unavailable','source':None,'file':None,'reason':'not_started','broker_id':None}
        export={'status':'complete','source':recovery['source'],'file':'recovery-ledger.json',
            'reason':None,'broker_id':None} if complete else deepcopy(unavailable)
        manifest={'runtime_sha256':'a'*64,'broker_instances':[{'broker_id':observer['broker_id']}],
            'dispatches':[],'transcript':{'segments':[]},
            'ledger_exports':{'initial':deepcopy(unavailable),'final':deepcopy(unavailable),'recovery':export}}
        cleanup={'schema_version':'2' if helper else '1','receipts':[],'exports':[],
            'supervisors':[],'recovery':recovery}
        if helper:cleanup['recovery_helpers']=[observer]
        members={'runtime.json':b'{}','processes.json':c.canonical({'schema_version':'1',
            **{key:[] for key in ('startup','readiness','native','child_slots','boundary_observations')}}),
            'results.json':c.canonical({'schema_version':'1','operations':[],'boundary_proofs':[],'core_proofs':[]}),
            'cleanup.json':c.canonical(cleanup),'audit.jsonl':b'','transcript.jsonl':b''}
        if complete:members['recovery-ledger.json']=c.canonical({'declared_generation':generation})
        return manifest,members
    earlier,later=payload(0),payload(1)
    before=deepcopy([earlier,later])
    manifest,members=_merge_core_payloads([earlier,later])
    merged=json.loads(members['cleanup.json'])
    assert merged['schema_version']=='2'
    assert merged['recovery_helpers']==[json.loads(item[1]['cleanup.json'])['recovery_helpers'][0]
        for item in (earlier,later)]
    assert merged['recovery']==json.loads(later[1]['cleanup.json'])['recovery']
    assert members['recovery-ledger.json']==later[1]['recovery-ledger.json']
    assert [earlier,later]==before
    failed=payload(1,complete=False)
    manifest,members=_merge_core_payloads([earlier,failed])
    merged=json.loads(members['cleanup.json'])
    assert [item['status'] for item in merged['recovery_helpers']]==['complete','failed']
    assert merged['recovery'] is None and 'recovery-ledger.json' not in members
    assert manifest['ledger_exports']['recovery']==failed[0]['ledger_exports']['recovery']
    direct=payload(1,helper=False,direct=True)
    manifest,members=_merge_core_payloads([earlier,direct])
    merged=json.loads(members['cleanup.json'])
    assert len(merged['recovery_helpers'])==1 and merged['recovery']['source']=='postcleanup_readonly'
    assert members['recovery-ledger.json']==direct[1]['recovery-ledger.json']
    _,members=_merge_core_payloads([payload(0,helper=False,direct=True),direct])
    assert json.loads(members['cleanup.json'])['schema_version']=='1'
    assert 'recovery_helpers' not in json.loads(members['cleanup.json'])
    for field in ('helper_id','broker_id'):
        duplicate=deepcopy(later);cleanup=json.loads(duplicate[1]['cleanup.json'])
        cleanup['recovery_helpers'][0][field]=json.loads(earlier[1]['cleanup.json'])['recovery_helpers'][0][field]
        duplicate[1]['cleanup.json']=c.canonical(cleanup)
        with pytest.raises(AssertionError,match='one retained recovery helper'):
            _merge_core_payloads([earlier,duplicate])


def _recovery_frame_cases():
    import hashlib
    digest=lambda data:hashlib.sha256(data).hexdigest()
    body=b'{"value":1}';header=len(body).to_bytes(8,'big');complete=header+body
    empty,value,used=module._recovery_frame(b'',4096,1)
    assert empty['payload_sha256'] is empty['frame_sha256'] is None and value is None and used==0
    for prefix in (header[:1],header[:7],header,complete[:-1]):
        row,value,used=module._recovery_frame(prefix,4096,1)
        assert value is None and used==0 and row['complete'] is False
        assert row['received_bytes']==len(prefix) and row['frame_sha256']==digest(prefix)
        assert row['payload_sha256']==digest(prefix[8:])
    row,value,used=module._recovery_frame(complete+b'trailing',4096,1)
    assert value=={'value':1} and used==len(complete)
    assert row['received_bytes']==len(complete) and row['frame_sha256']==digest(complete)
    for body in (b'{"value": 1}',b'{"value":1,"value":2}',b'\xff',b'{'):
        packet=len(body).to_bytes(8,'big')+body
        with pytest.raises(module._RecoveryError,match='framing') as caught:
            module._recovery_frame(packet,4096,1)
        row=caught.value.frame
        assert row['complete'] is False and row['frame_sha256']==digest(packet)
        assert row['payload_sha256']==digest(body) and row['received_bytes']==len(packet)
    with pytest.raises(module._RecoveryError,match='framing') as caught:
        module._recovery_frame((4097).to_bytes(8,'big'),4096,1)
    assert caught.value.frame['frame_sha256']==digest((4097).to_bytes(8,'big'))
    assert caught.value.frame['declared_bytes'] is None


def _recovery_owner_coordination_cases(tmp_path,monkeypatch):
    # Concurrent close cannot mutate descriptors while the lifecycle owner is
    # running, and contention consumes only the original deadline remainder.
    now=time.monotonic_ns();owner=module._RecoveryOwner(None,-1,-2,now,now+50000000)
    entered=threading.Event();release=threading.Event();calls=[];errors=[]
    def running():
        entered.set();assert release.wait(1);return 'retained'
    def cleanup():calls.append('cleanup');owner.resolved=True
    with monkeypatch.context() as patch:
        patch.setattr(owner,'_run_locked',running);patch.setattr(owner,'_cleanup_locked',cleanup)
        def invoke():
            try:assert owner.run()=='retained'
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=invoke);worker.start()
        try:
            assert entered.wait(.5) and owner.active
            before=dict(owner.fds);began=time.monotonic()
            with pytest.raises(module._RecoveryError,match='helper_reap'):owner._cleanup()
            assert time.monotonic()-began<.5 and not calls and owner.fds==before and owner.active
        finally:release.set();worker.join(1)
        assert not worker.is_alive() and not errors and not owner.active
        owner._cleanup();owner._cleanup()
        assert calls==['cleanup'] and owner.resolved
    # Recovery registers before its I/O seam. A second recovery or successor
    # attachment cannot pass the actual shared session ownership fence.
    obj,_,_=service();obj._closed=obj._startup_quiesced=True;obj._cleanup={'status':'complete'}
    budget=obj._host_evidence_budget;budget._session_owners.append(obj)
    entered=threading.Event();release=threading.Event();calls=[];errors=[]
    def recovering(**kwargs):
        calls.append(kwargs);entered.set();assert release.wait(1);return b'{}',{}
    with monkeypatch.context() as patch:
        patch.setattr(obj,'_recover_ledger_registered',recovering)
        def invoke_recovery():
            try:assert obj._recover_ledger()==(b'{}',{})
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=invoke_recovery);worker.start()
        try:
            assert entered.wait(.5) and not obj._verified_reaped()
            with pytest.raises(c.LiveError,match='cleanup_incomplete'):obj._recover_ledger()
            successor,_,_=service()
            with pytest.raises(c.LiveError,match='cleanup_incomplete'):budget._attach_session(successor)
            assert len(calls)==1 and budget._session_owners==[obj]
        finally:release.set();worker.join(1)
        assert not worker.is_alive() and not errors and obj._verified_reaped()
        budget._attach_session(successor)
        with pytest.raises(c.LiveError,match='cleanup_incomplete'):obj._recover_ledger()
        assert len(calls)==1 and budget._session_owners==[obj,successor]
    # Exclusive creation failure confers no ownership; a successful mkdir
    # followed by failed open leaves unresolved custody, never name-only rmdir.
    for variant in ('collision','open_failure'):
        parent=tmp_path/('scratch-'+variant);parent.mkdir(mode=0o700)
        store=parent/'store';store.mkdir(mode=0o700)
        parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);store_fd=os.open(store,os.O_RDONLY|os.O_DIRECTORY)
        now=time.monotonic_ns();owner=module._RecoveryOwner(None,parent_fd,store_fd,now,now+2*c.SECOND)
        proposed='recovery_'+owner.helper_id.replace('-','');existing=parent/proposed
        if variant=='collision':existing.mkdir(mode=0o700)
        removed=[];real_open=os.open
        def fail_open(path,flags,*args,**kwargs):
            if path==proposed:raise PermissionError('declared post-mkdir refusal')
            return real_open(path,flags,*args,**kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(module.os,'rmdir',lambda *args,**kwargs:removed.append((args,kwargs)))
            if variant=='open_failure':patch.setattr(module.os,'open',fail_open)
            with pytest.raises(FileExistsError if variant=='collision' else PermissionError):owner._allocate_scratch()
            if variant=='collision':
                assert owner.scratch_parent_name is None and owner._scratch_parent_created is False
                owner._remove_scratch(None)
            else:
                assert owner._scratch_parent_created and owner._scratch_parent_identity is None
                with pytest.raises(module._RecoveryError,match='scratch_cleanup'):owner._remove_scratch(None)
            assert not removed and not owner.resolved and existing.is_dir()
        for fd in set(owner.fds.values()):os.close(fd)


def _recovery_packaging_snapshot_cases(monkeypatch):
    """Guard unit/caller checks; declared rows are not acceptance evidence."""
    from test_secure_engagement_live_evidence import runtime as declared_runtime
    obj,_,_=service();obj._closed=obj._startup_quiesced=True
    obj._cleanup={'schema_version':'1','started_at_ns':1,'finished_at_ns':2,'deadline_ns':3,
        'status':'complete','processes':[],'descriptors_closed':True}
    obj._operations.clear();obj._sessions.clear();obj._runtime=declared_runtime();obj._mode='terminal'
    records=[{'helper_id':uid(979),'status':'complete','retained':{'closed':True}}]
    def forbidden(*args,**kwargs):raise AssertionError('snapshot must not drive cleanup or recovery')
    class UntouchedLock:
        def acquire(self,*args,**kwargs):forbidden()
        def release(self):forbidden()
    owner=SimpleNamespace(quiescent=True,_lifecycle_lock=UntouchedLock(),run=forbidden,_cleanup=forbidden)
    obj._recovery_owner=owner;obj._recovery_helpers=deepcopy(records)
    budget=obj._host_evidence_budget
    def unlocked():
        assert budget._lock.acquire(blocking=False)
        budget._lock.release()
    captured=obj._recovery_packaging_snapshot(deadline=time.monotonic()+1)
    assert captured==(owner,c.canonical(records,max_bytes=524288))
    assert obj._recovery_packaging_snapshot(deadline=time.monotonic()+1,expected=captured)==captured
    # Canonical ordering is stable, while bool/int distinctions must survive.
    obj._recovery_helpers=[dict(reversed(list(records[0].items())))]
    assert obj._recovery_packaging_snapshot(deadline=time.monotonic()+1,expected=captured)==captured
    unlocked()
    for variant in ('owner','nested','bool_int','pending','active'):
        obj._recovery_owner=owner;owner.quiescent=True;obj._recovery_in_progress=False
        obj._recovery_helpers=deepcopy(records)
        if variant=='owner':obj._recovery_owner=SimpleNamespace(quiescent=True)
        elif variant=='nested':obj._recovery_helpers[0]['status']='failed'
        elif variant=='bool_int':
            obj._recovery_helpers[0]['retained']['closed']=1
            assert obj._recovery_helpers==records  # Python equality is insufficient.
        elif variant=='pending':obj._recovery_in_progress=True
        else:owner.quiescent=False
        code='cleanup_incomplete' if variant in ('pending','active') else 'evidence_incomplete'
        with pytest.raises(c.LiveError,match=code):
            obj._recovery_packaging_snapshot(deadline=time.monotonic()+1,expected=captured)
        unlocked()
        assert captured[1]==c.canonical(records,max_bytes=524288)
    obj._recovery_owner=owner;owner.quiescent=True;obj._recovery_in_progress=False
    obj._recovery_helpers=deepcopy(records)
    budget._lock.acquire();began=time.monotonic()
    try:
        with pytest.raises(c.LiveError,match='cleanup_incomplete'):
            obj._recovery_packaging_snapshot(deadline=began+.02)
        assert time.monotonic()-began<.5 and obj._recovery_helpers==records
    finally:budget._lock.release()
    unlocked()
    # The actual caller captures helpers before reading saved audit bytes and
    # checks them again immediately before returning the assembled payload.
    with monkeypatch.context() as patch:
        patch.setattr(obj,'_saved_audit',lambda deadline:b'')
        patch.setattr(obj,'_recover_ledger',forbidden)
        _,members=obj._evidence_payload(recover=False)
        assert json.loads(members['cleanup.json'])['recovery_helpers']==records
        for variant in ('owner','nested','bool_int','pending'):
            obj._recovery_owner=owner;obj._recovery_in_progress=False;obj._recovery_helpers=deepcopy(records)
            calls=[]
            def mutate_after_capture(deadline):
                calls.append('saved_audit')
                if variant=='owner':obj._recovery_owner=SimpleNamespace(quiescent=True)
                elif variant=='nested':obj._recovery_helpers[0]['status']='failed'
                elif variant=='bool_int':obj._recovery_helpers[0]['retained']['closed']=1
                else:obj._recovery_in_progress=True
                return b''
            patch.setattr(obj,'_saved_audit',mutate_after_capture)
            with pytest.raises(c.LiveError,match='cleanup_incomplete' if variant=='pending' else 'evidence_incomplete'):
                obj._evidence_payload(recover=False)
            assert calls==['saved_audit'];unlocked()


def _copied_recovery_primitive_cases(tmp_path,monkeypatch):
    """Real local SQLite/lock checks; no isolated-runtime acceptance witness."""
    import hashlib
    from test_secure_engagement_dispatch_store import new_store
    from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger,DispatchLedgerError
    with new_store(tmp_path,'copied-recovery-source') as source:
        expected=source.snapshot();source_owner=source.owner_reference;source_path=source.directory
    main=(source_path/'records.sqlite3').read_bytes()
    module._recovery_main_header(main)
    pages=len(main)//4096;nonce=0xffffffff
    selected=[1,pages] if pages>1 else [1]
    def journal(numbers=selected,sector=512):
        header=bytes(12)+b''.join(value.to_bytes(4,'big') for value in (nonce,pages,sector,4096))
        result=bytearray(header+bytes(sector-len(header)))
        for number in numbers:
            page=main[(number-1)*4096:number*4096]
            checksum=nonce;offset=len(page)-200
            while offset>0:
                checksum=(checksum+page[offset])&0xffffffff;offset-=200
            result.extend(number.to_bytes(4,'big')+page+checksum.to_bytes(4,'big'))
        return bytes(result)
    retained=journal();original={'main':main,'journal':retained}
    (source_path/'records.sqlite3-journal').write_bytes(retained)
    (source_path/'records.sqlite3-journal').chmod(0o600)
    classified=module._recovery_inactive_journal(main,retained)
    assert classified['record_count']==len(selected)
    assert [row['page_number'] for row in classified['records']]==selected
    assert [row['index'] for row in classified['records']]==list(range(len(selected)))
    assert all(row['checksum']==row['computed_checksum'] and row['before_image_sha256']==row['main_page_sha256']
        for row in classified['records'])
    assert classified['records'][0]['before_image_sha256']==hashlib.sha256(main[:4096]).hexdigest()
    for sector in (512,65536):
        assert module._recovery_inactive_journal(main,journal([],sector))['record_count']==0
    def replace(raw,start,data):return raw[:start]+data+raw[start+len(data):]
    broken=[retained+b'\x00',retained[:-1],retained+b'\x00'*4104,
        replace(retained,0,b'\xd9'),replace(retained,8,b'\x01'),replace(retained,28,b'\x01'),
        replace(retained,16,(pages+1).to_bytes(4,'big')),replace(retained,20,(513).to_bytes(4,'big')),
        replace(retained,24,(1024).to_bytes(4,'big')),replace(retained,512,(0).to_bytes(4,'big')),
        replace(retained,512,(pages+1).to_bytes(4,'big')),replace(retained,512+4100,b'\x00'*4),
        replace(retained,512+4+1,bytes([retained[512+5]^1])),
        retained+bytes.fromhex('d9d505f920a163d7'),journal([1,1])]
    for bad in broken:
        with pytest.raises(module._RecoveryError):module._recovery_inactive_journal(main,bad)
    for bad in (b'',main[:-1],replace(main,0,b'X'),replace(main,16,b'\x08\x00'),
            replace(main,18,b'\x02'),replace(main,19,b'\x02')):
        with pytest.raises(module._RecoveryError,match='main_header'):
            module._recovery_main_header(bad)
    # The accepted read-only constructor continues to refuse the original
    # retained journal. Only the distinct private copy is validated writable.
    with pytest.raises(DispatchLedgerError):DispatchLedger.open(source_path,read_only=True)
    scratch_parent=tmp_path/'copied-recovery-scratch';scratch_parent.mkdir(mode=0o700)
    scratch=scratch_parent/'store';scratch.mkdir(mode=0o700)
    for name,data in (('records.sqlite3',main),('records.sqlite3-journal',retained)):
        target=scratch/name;target.write_bytes(data);target.chmod(0o600)
    budget=module._RecoveryProgress(time.monotonic_ns()+2*c.SECOND)
    query='WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n'
    seen=[]
    class CopiedLedger(DispatchLedger):
        def _progress(self):
            if not seen or seen[-1] is not self:seen.append(self)
            return budget.step(self)
    with CopiedLedger._open(scratch,read_only=False,initial=None,deadline=budget.deadline_ns/c.SECOND) as writable:
        rw_owner=writable.owner_reference
        constructor_count=budget.callbacks
        assert writable.snapshot()==expected
        # A tiny valid store can execute fewer than1000 SQLite VM instructions
        # and legitimately report zero callbacks. This fixed read-only test
        # load exercises the registered callback without altering the ledger.
        with writable._transaction():assert writable._execute(query).fetchone()[0]==50005000
        rw_count=budget.callbacks
    assert 0<=constructor_count<rw_count<4000
    assert (scratch/'records.sqlite3').read_bytes()==main
    assert (scratch/'records.sqlite3-journal').read_bytes()==retained
    module._recovery_inactive_journal((scratch/'records.sqlite3').read_bytes(),(scratch/'records.sqlite3-journal').read_bytes())
    (scratch/'records.sqlite3-journal').unlink()
    with CopiedLedger._open(scratch,read_only=True,initial=None,deadline=budget.deadline_ns/c.SECOND) as readonly:
        assert readonly.snapshot()==expected
        assert readonly._db.execute('PRAGMA query_only').fetchone()[0]==1
        assert len({source_owner,rw_owner,readonly.owner_reference})==3
        with readonly._transaction():assert readonly._execute(query).fetchone()[0]==50005000
    assert rw_count<budget.callbacks<4000 and len(seen)==2
    assert (source_path/'records.sqlite3').read_bytes()==original['main']
    assert (source_path/'records.sqlite3-journal').read_bytes()==original['journal']
    # Exhaustion crosses constructor boundaries even though the accepted
    # per-operation callback counter is reset by the next transaction.
    seen.clear();budget=module._RecoveryProgress(time.monotonic_ns()+2*c.SECOND);budget.callbacks=3999
    class LoadedConstructor(CopiedLedger):
        # Test-only read load after the real constructor installs its handler;
        # no accepted method is patched and the production subclass is intact.
        def _configure(self,*,initial):
            super()._configure(initial=initial)
            self._db.execute(query).fetchone()
    with pytest.raises(DispatchLedgerError,match='timeout'):
        LoadedConstructor._open(scratch,read_only=True,initial=None,deadline=budget.deadline_ns/c.SECOND)
    assert budget.callbacks==4000 and len(seen)==1 and seen[0]._interrupted is True
    assert seen[0]._db is seen[0]._parent_fd is seen[0]._directory_fd is None
    local=SimpleNamespace(_callbacks=0,_interrupted=False,_deadline=time.monotonic()+2)
    assert budget.step(local)==1 and budget.callbacks==4000
    local._callbacks=0;local._interrupted=False
    assert budget.step(local)==1 and local._interrupted is True
    with monkeypatch.context() as patch:
        patch.setattr(module.time,'monotonic_ns',lambda:100)
        timed=module._RecoveryProgress(100)
        assert timed.step(local)==1 and timed.callbacks==1
    _copied_recovery_lock_preservation(tmp_path)


def _copied_recovery_lock_preservation(tmp_path):
    """Closing source FDs in another process preserves an active SQLite lock."""
    import fcntl
    from test_secure_engagement_dispatch_store import new_store
    program='''import json,os,sys
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent.engagement_live_session import _recovery_lock
fd=os.open(sys.argv[2],os.O_RDONLY|os.O_CLOEXEC)
try:
 rows=[_recovery_lock(fd,offset=1073741824,length=1),
       _recovery_lock(fd,offset=1073741826,length=510),
       _recovery_lock(fd,offset=1073741825,length=1,query=True)]
finally:os.close(fd)
print(json.dumps(rows,separators=(',',':'),sort_keys=True))
'''
    with new_store(tmp_path,'recovery-lock-source') as source:
        path=source.directory/'records.sqlite3'
        def observe():
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',program,str(ROOT),str(path)],
                capture_output=True,timeout=3)
            assert result.returncode==0 and not result.stderr
            return json.loads(result.stdout)
        source._db.execute('BEGIN IMMEDIATE')
        try:
            first=observe()
            if not hasattr(fcntl,'F_OFD_GETLK') or not hasattr(fcntl,'F_OFD_SETLK'):
                assert all(row.get('status','unsupported')=='unsupported' for row in first)
                return
            for rows in (first,observe()):
                assert all(row['status']=='acquired' and row['errno'] is None for row in rows[:2])
                assert rows[2]['result_type']=='F_WRLCK' and rows[2]['owner_pid']==os.getpid()
                assert rows[2]['input_owner_pid']==0 and rows[2]['errno'] is None
        finally:source._db.execute('ROLLBACK')
        after=observe()
        assert after[2]['result_type']=='F_UNLCK' and after[2]['owner_pid']==0


def copied_recovery_work_fixture(tmp_path):
    """Actual stage facts from a portable child, with declared outer bindings.

    This is deliberately not a complete runtime/process observation and must
    never be used as a native helper or case acceptance witness.
    """
    from test_secure_engagement_dispatch_store import new_store
    with new_store(tmp_path,'recovery-work-source') as source:
        expected=source.snapshot();old_owner=source.owner_reference;source_path=source.directory
    main=(source_path/'records.sqlite3').read_bytes();pages=len(main)//4096;nonce=123
    header=bytes(12)+b''.join(value.to_bytes(4,'big') for value in (nonce,pages,512,4096))
    page=main[:4096];checksum=nonce
    for offset in range(3896,0,-200):checksum=(checksum+page[offset])&0xffffffff
    journal=header+bytes(512-28)+(1).to_bytes(4,'big')+page+checksum.to_bytes(4,'big')
    source_journal=source_path/'records.sqlite3-journal';source_journal.write_bytes(journal);source_journal.chmod(0o600)
    scratch_parent=tmp_path/'recovery-work-scratch';scratch_parent.mkdir(mode=0o700)
    scratch=scratch_parent/'store';scratch.mkdir(mode=0o700)
    # Exercise the declared fallback's joins on Linux as well, so its data
    # model cannot silently drift until another platform runs this same case.
    from recon_cockpit.secure_agent import engagement_live_context as context
    declared=_declared_recovery_work_fixture(expected,main,journal,old_owner)
    assert context._recovery_work(declared[0],declared[1],set(declared[2]),{})==expected
    import fcntl
    if (not sys.platform.startswith('linux') or not all(hasattr(fcntl,name)
            for name in ('F_OFD_SETLK','F_OFD_GETLK'))):
        # The Linux helper is unsupported here. Pure replay still receives a
        # declared complete data fixture, with no /proc access or child launch.
        if not hasattr(fcntl,'F_OFD_SETLK'):
            assert module._recovery_lock(-1,offset=1073741824,length=1)['status']=='unsupported'
        if not hasattr(fcntl,'F_OFD_GETLK'):
            assert module._recovery_lock(-1,offset=1073741825,length=1,query=True)['result_type'] is None
        return declared
    program='''import fcntl,json,os,resource,sys,time
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent import engagement_live_session as m
paths=sys.argv[2:6]
original=[os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC) for path in paths]
copies=[fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,8) for fd in original]
for target,fd in zip(range(4,8),copies):os.dup2(fd,target)
for fd in set(original+copies)-set(range(4,8)):os.close(fd)
started=time.monotonic_ns();deadline=started+2000000000
work={'schema_version':'1','helper_id':sys.argv[6],'broker_id':sys.argv[7],
 'runtime_sha256':'a'*64,'source_package_sha256':'b'*64,'started_at_ns':started,
 'work_deadline_ns':deadline,'deadline_ns':deadline+500000000,'finished_at_ns':None,
 'copy':None,'rw':None,'ro':None,'post_rw_copy':None,'post_ro_copy':None,
 'journal_disposition':None,'progress_callbacks':0,'source_descriptors_closed':False,
 'copy_descriptors_closed':False,'source_package_closed_at_ns':time.monotonic_ns(),
 'sqlite_file_size_limit':None}
contents=m._recovery_copy_files(work,deadline)
resource.setrlimit(resource.RLIMIT_FSIZE,(8388608,8388608))
soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
work['sqlite_file_size_limit']={'observed_at_ns':time.monotonic_ns(),'soft':soft,'hard':hard}
progress=m._RecoveryProgress(deadline)
rw=m._recovery_sqlite_stage(work,'rw',progress)
m._recovery_dispose_journal(work,contents,deadline)
ro=m._recovery_sqlite_stage(work,'ro',progress)
assert rw==ro
work['post_ro_copy'],unused=m._recovery_observe_store(6,7,deadline)
work['finished_at_ns']=time.monotonic_ns()
for fd in range(4,8):os.close(fd)
print(json.dumps({'work':work,'export':ro},separators=(',',':'),sort_keys=True))
'''
    result=subprocess.run([sys.executable,'-I','-S','-B','-c',program,str(ROOT),
        str(source_path.parent),str(source_path),str(scratch_parent),str(scratch),uid(970),uid(971)],
        capture_output=True,timeout=4)
    assert result.returncode==0 and not result.stderr,result.stderr.decode('utf-8',errors='replace')
    retained=json.loads(result.stdout);work=retained['work']
    assert retained['export']==expected
    assert (source_path/'records.sqlite3').read_bytes()==main and source_journal.read_bytes()==journal
    assert (scratch/'records.sqlite3').read_bytes()==main and not (scratch/'records.sqlite3-journal').exists()
    helper={field:work[field] for field in ('helper_id','broker_id','deadline_ns','work_deadline_ns')}
    helper.update(work=work,parent_observer={'uid':os.getuid(),'gid':os.getgid()},
        config={field:work[field] for field in ('runtime_sha256','source_package_sha256')},
        process={'release_sent_at_ns':work['started_at_ns']},
        scratch={field:work['copy']['copied'][field] for field in ('parent','directory')})
    return helper,{'recovery-ledger.json':retained['export']},{old_owner}


def _declared_recovery_work_fixture(export,main,journal,old_owner):
    """Portable replay declarations, explicitly not an executed helper receipt."""
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    identity=lambda inode:{'device':1,'inode':inode,'mode':0o40700,'uid':os.getuid(),'gid':os.getgid()}
    def file(name,data,inode):
        stamp={**identity(inode),'mode':0o100600,'nlink':1,'size':len(data),'mtime_ns':10,'ctime_ns':10}
        return {'name':name,'held':stamp,'named':deepcopy(stamp),'fd_flags':os.O_RDONLY,
            'sha256':c.digest(data),'header_hex':data[:28].hex(),'trailer_hex':data[-16:].hex()}
    source={'parent':identity(10),'directory':identity(11),'observed_at_ns':110,
        'files':[file('records.sqlite3',main,12),file('records.sqlite3-journal',journal,13)]}
    copied={'parent':identity(20),'directory':identity(21),'observed_at_ns':111,
        'files':[file('records.sqlite3',main,22),file('records.sqlite3-journal',journal,23)]}
    after=deepcopy(source);after['observed_at_ns']=113
    def lock(offset,length,start):return {'command':'F_OFD_SETLK','lock_type':'F_RDLCK',
        'offset':offset,'length':length,'started_at_ns':start,'finished_at_ns':start+1,'status':'acquired','errno':None}
    def query(start):return {'command':'F_OFD_GETLK','query_type':'F_WRLCK','input_owner_pid':0,
        'offset':1073741825,'length':1,'started_at_ns':start,'finished_at_ns':start+1,
        'result_type':'F_UNLCK','owner_pid':0,'errno':None}
    encoded=ledger.canonical(export)
    def stage(mode,owner,start,before,count):return {'mode':mode,'owner_id':uid(owner),
        'opened_at_ns':start,'snapshot_at_ns':start+1,'closed_at_ns':start+2,'closed':True,
        'snapshot_bytes':len(encoded),'snapshot_sha256':c.digest(encoded),'snapshot_event_sequence':len(export['events']),
        'ledger_state_sha256':export['events'][-1]['receipt']['state_sha256'],
        'progress_callbacks_before':before,'progress_callbacks_after':count}
    post_rw=deepcopy(copied);post_rw['observed_at_ns']=123
    post_ro=deepcopy(copied);post_ro.update(observed_at_ns=131,files=[deepcopy(copied['files'][0])])
    work={'schema_version':'1','helper_id':uid(970),'broker_id':uid(971),'runtime_sha256':'a'*64,
        'source_package_sha256':'b'*64,'started_at_ns':101,'work_deadline_ns':1500000000,
        'deadline_ns':2000000000,'finished_at_ns':132,'source_package_closed_at_ns':102,
        'source_descriptors_closed':True,'copy_descriptors_closed':True,'progress_callbacks':5,
        'copy':{'started_at_ns':103,'finished_at_ns':118,'source_before':source,'source_after':after,'copied':copied,
            'raw_copy_fds_closed_at_ns':112,'raw_source_fds_closed_at_ns':117,
            'locks':{'main_device':1,'main_inode':12,'pending':lock(1073741824,1,104),
                'shared':lock(1073741826,510,106),'reserved_before':query(108),'reserved_after':query(114),'released_at_ns':116}},
        'sqlite_file_size_limit':{'soft':8388608,'hard':8388608,'observed_at_ns':119},
        'rw':stage('read_write',974,120,0,3),'ro':stage('read_only',975,128,3,5),
        'post_rw_copy':post_rw,'post_ro_copy':post_ro,
        'journal_disposition':{'status':'removed_inactive_copy','observed_at_ns':124,
            'journal':deepcopy(copied['files'][1]),'main_before':deepcopy(copied['files'][0]),
            'main_after':deepcopy(copied['files'][0]),'header':module._recovery_inactive_journal(main,journal),
            'unlink_started_at_ns':125,'unlink_finished_at_ns':126,'absence_observed_at_ns':127}}
    helper={key:work[key] for key in ('helper_id','broker_id','deadline_ns','work_deadline_ns')}
    helper.update(work=work,parent_observer={'uid':os.getuid(),'gid':os.getgid()},
        config={key:work[key] for key in ('runtime_sha256','source_package_sha256')},
        process={'release_sent_at_ns':100},scratch={key:copied[key] for key in ('parent','directory')})
    return helper,{'recovery-ledger.json':export},{old_owner}


def test_cli_output_is_bounded_and_never_reports_late_success(monkeypatch):
    value = cli()
    with pytest.raises(ValueError, match='limit_exceeded'):
        value._output(b'x'*8193,time.monotonic()+1)
    monkeypatch.setattr(value,'parse_options',lambda args:{'help':False,'execute':True})
    monkeypatch.setattr(value,'_run',lambda options, deadline:{'status':'complete'})
    written = []
    def expired_output(raw,deadline):
        written.append(raw)
        raise ValueError('engagement_live_timeout')
    monkeypatch.setattr(value,'_output',expired_output)
    assert value.main([]) == 2
    assert json.loads(written[-1])['error'] == 'engagement_live_timeout'
    written.clear()
    def partial_output(raw,deadline):
        written.append(raw[:5])
        error = ValueError('engagement_live_timeout')
        error.output_started = True
        raise error
    monkeypatch.setattr(value,'_output',partial_output)
    assert value.main([]) == 2 and len(written) == 1

    # A single allocator survives sequential owners; two concurrent producers
    # cannot both consume its last row. Reservations count before transport.
    budget = module._HostEvidenceBudget()
    control = ExecutionControl(time.monotonic()+10)
    for index in range(127):
        ticket = budget.reserve(kind='other_host', maximum_bytes=1024, maximum_rows=1, control=control)
        budget.finalize(ticket,host_row(index+1))
    barrier = threading.Barrier(2)
    accepted, refused = [], []
    def compete():
        barrier.wait(timeout=2)
        try:
            ticket = budget.reserve(kind='other_host', maximum_bytes=1024, maximum_rows=1, control=control)
            budget.finalize(ticket,host_row(128))
            accepted.append(True)
        except c.LiveError as error:
            refused.append(error.code)
    workers = [threading.Thread(target=compete) for _ in range(2)]
    for item in workers:item.start()
    for item in workers:item.join(timeout=2)
    assert all(not item.is_alive() for item in workers)
    assert accepted == [True] and refused == ['engagement_live_limit_exceeded']
    assert len(budget.snapshot()['rows']) == 128
    reserved = module._HostEvidenceBudget()
    ticket = reserved.reserve(kind='other_host', maximum_bytes=262144, maximum_rows=1, control=control)
    with pytest.raises(c.LiveError, match='limit_exceeded'):
        reserved.reserve(kind='other_host', maximum_bytes=1, maximum_rows=1, control=control)
    assert reserved.snapshot()['rows'] == []
    reserved.release(ticket)
    assert reserved.snapshot()['reserved_bytes'] == 0
