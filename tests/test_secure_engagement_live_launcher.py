"""S42C-L01..L16: fixed ordering and bounded local doubles, no native proof."""
from copy import deepcopy
from contextlib import contextmanager
import threading
import os
import socket
import time
from types import SimpleNamespace

import pytest
from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent import engagement_live_protocol as p
from recon_cockpit.secure_agent import engagement_live_runtime as rt
from recon_cockpit.secure_agent import engagement_live_launcher_worker as worker
from recon_cockpit.secure_agent import engagement_live_admission_worker as admission
from recon_cockpit.secure_agent import engagement_live_client as client
from recon_cockpit.secure_agent import engagement_live_endpoint as endpoint
from recon_cockpit.secure_agent import engagement_live_parser as parser
from recon_cockpit.secure_agent import engagement_live_context as context
from test_secure_engagement_live_contract import opened,prepared,release,clock,uid,M
from test_secure_engagement_live_runtime import declared_runtime,declared_readiness,declared_cleanup,PortablePacket


def refused(function,*args,**kwargs):
    with pytest.raises(c.LiveError):function(*args,**kwargs)


def data(slot='http_identify'):
    bundle=declared_runtime();session=opened();session['binding']['runtime_sha256']=rt.runtime_digest(bundle)
    value=prepared(slot,opened_value=session);ready=declared_readiness(bundle,'endpoint')
    return bundle,session,value,ready


def permit_state():
    bundle,session,value,ready=data()
    state=admission.AdmissionState(value,admission_id=uid(50),launcher_id=uid(51),endpoint_identity=ready,runtime_sha256=rt.runtime_digest(bundle))
    return state,value


def execution_model(monkeypatch,slot='http_identify',*,fail_native=False,fail_arm=False):
    bundle,session,value,ready=data(slot);events=[];clean=declared_cleanup(declared_readiness(bundle,'admission'))
    state=worker.LauncherState.__new__(worker.LauncherState)
    state.pending=value;state.release=None;state.payload={'scope':session['scope'],'endpoint_identity':ready};state.runtime=bundle
    state.permit={'reference':'a'*64};state.cleanups=[];state.readies=[];state.capture=None;state.meter=None
    state._control=lambda deadline:SimpleNamespace(deadline=time.monotonic()+1,check=lambda:None,remaining=lambda:.1)
    state.admission_rpc=lambda *args:(events.append('redeem') or None)
    state.observe=lambda *args:events.append('cleanup_record')
    state.send=lambda operation,body:events.append(operation)
    state.admission=SimpleNamespace(close=lambda **kw:(events.append('admission_reaped') or clean))
    def native(control):
        events.append('native_image')
        if fail_native:c.fail('invalid_runtime')
        return {'actual':'modeled only'}
    state.client=SimpleNamespace(release=lambda *args:events.append('client_release'),observe_native=native,
        collect=lambda control:c.fail('unavailable'),close=lambda:(events.append('client_reaped') or clean))
    state.arm=object()
    def arm(*args,**kwargs):
        events.append('arm')
        if fail_arm:c.fail('invalid_frame')
    monkeypatch.setattr(endpoint,'arm_endpoint',arm);monkeypatch.setattr(c,'sample_clock',clock)
    return state,release(value),events


def test_sealed_runtime_and_action_are_independently_checked():
    bundle,session,value,ready=data()
    assert c.validate_prepared_role_context(value,binding=session['binding'],roe=session['roe'],scope=session['scope'],policy=session['policy'])==value
    for field in ('runtime_sha256','action_sha256','policy_sha256'):
        bad=deepcopy(value);bad['envelope'][field]='f'*64
        refused(c.validate_prepared_role_context,bad,binding=session['binding'],roe=session['roe'],scope=session['scope'],policy=session['policy'])
    bad=deepcopy(bundle);bad['roles'][0]['sources'][0]['sha256']='0'*64;refused(rt.validate_runtime,bad)
    bad=deepcopy(bundle);bad['roles'][0]['native_files'][0]['sha256']='0'*64
    changed=rt.runtime_digest(rt.validate_runtime(bad))
    assert changed!=value['envelope']['runtime_sha256']
    refused(admission.AdmissionState,value,admission_id=uid(50),launcher_id=uid(51),endpoint_identity=ready,runtime_sha256=changed)
    bad=deepcopy(value);bad['action']['parameters']['extra']='x';refused(c.validate_prepared,bad)


def test_nested_admission_has_full_engagement_binding():
    state,value=permit_state();permit=state.issue(value,clock=clock())
    assert permit['prepared_sha256']==c.prepared_digest(value) and permit['envelope_sha256']==c.envelope_digest(value['envelope'])
    for key in ('broker_id','session_id','ledger_owner_id','dispatch_id'):
        forged=release(value);forged[key]=uid(999)
        fresh,_=permit_state();ticket=fresh.issue(value,clock=clock())
        refused(fresh.redeem,{'prepared_sha256':ticket['prepared_sha256'],'reference':ticket['reference'],'release':forged},clock=clock())


def test_nested_permit_is_single_use_and_prepared_before_consume(monkeypatch):
    state,value=permit_state();ticket=state.issue(value,clock=clock());refused(state.issue,value,clock=clock())
    request={'prepared_sha256':ticket['prepared_sha256'],'reference':ticket['reference'],'release':release(value)}
    assert state.redeem(request,clock=clock())['status']=='redeemed';refused(state.redeem,request,clock=clock())
    model,go,events=execution_model(monkeypatch);refused(model.run,go)
    assert events.index('redeem')<events.index('admission_reaped')<events.index('client_release')


def test_go_requires_inherited_broker_peer(monkeypatch):
    value=release(data()[2]);frame={'schema_version':'1','channel_id':uid(1),'sequence':1,'operation':'GO','body':value}
    refused(p.validate_frame,frame,role='terminal');refused(p.ChannelSequence(uid(2),'launcher').accept,frame)
    seq=p.ChannelSequence(uid(1),'launcher');assert seq.accept(frame)==frame;refused(seq.accept,frame)
    model,go,events=execution_model(monkeypatch);model.pending=None;refused(model.run,go);assert not events


def test_nmap_order_observes_native_before_endpoint_arm(monkeypatch):
    _supervisor_refusal_cause_cases(monkeypatch)
    state,go,events=execution_model(monkeypatch);refused(state.run,go)
    assert events.index('client_release')<events.index('native_image')<events.index('NATIVE_OBSERVED')<events.index('arm')
    state,go,events=execution_model(monkeypatch,fail_native=True);refused(state.run,go)
    assert 'native_image'in events and 'arm'not in events


def test_get_order_arms_before_fixed_worker_release(monkeypatch):
    state,go,events=execution_model(monkeypatch,'http_headers');refused(state.run,go)
    assert events.index('arm')<events.index('client_release') and 'native_image'not in events
    state,go,events=execution_model(monkeypatch,'http_headers',fail_arm=True);refused(state.run,go)
    assert 'client_release'not in events


def test_preparation_overlap_is_finitely_bounded(monkeypatch):
    _supervisor_overlap_cases(monkeypatch)
    bundle,session,value,ready=data();calls=[]
    state=worker.LauncherState.__new__(worker.LauncherState)
    state.payload={'session_binding':session['binding'],'roe':session['roe'],'scope':session['scope'],'policy':session['policy'],'endpoint_identity':ready}
    state.pending=value;state.prepared_ids=set();state.runtime=bundle
    monkeypatch.setattr(client,'prepare_client',lambda **kw:calls.append(kw))
    refused(state.prepare,value);assert not calls
    state.pending=None;state.prepared_ids={uid(80),uid(81)};refused(state.prepare,value);assert not calls


def test_current_clock_and_lease_checked_before_arm():
    state,value=permit_state();ticket=state.issue(value,clock=clock())
    for sample in (clock(10*c.SECOND),{**clock(1),'utc_ns':clock()['utc_ns']-c.SECOND},{**clock(1),'utc_ns':clock()['utc_ns']+60*c.SECOND}):
        refused(c.validate_release_binding,release(value),value,clock=sample)
    assert ticket['expires_at_ns']==value['envelope']['action_deadline_ns']


def test_stale_audit_and_approval_stop_delayed_release():
    bundle,session,value,ready=data();reservation={'deadline_ns':M+30*c.SECOND}
    for approval_ns,audit_ns in ((M,M+2*c.SECOND),(M+2*c.SECOND,M)):
        a={'issued_at_ns':approval_ns,'expires_at_ns':M+30*c.SECOND}
        lease=c.derive_effective_lease(value,reservation,a,{'issued_at_ns':audit_ns},clock=clock(2*c.SECOND))
        assert lease==M+10*c.SECOND
        refused(c.validate_release_binding,release(value,lease=lease),value,clock=clock(10*c.SECOND))


def test_cancel_before_arm_has_terminal_priority(monkeypatch):
    state=worker.LauncherState.__new__(worker.LauncherState);state.stopped=False;state._polling=False
    state.host=object();state.broker=object();state.pending=None;state.deadline_ns=time.monotonic_ns()+c.SECOND
    state.sequence=p.ChannelSequence(uid(777),'launcher')
    monkeypatch.setattr(p,'receive_packet',lambda *args,**kwargs:{'schema_version':'1','channel_id':uid(777),'sequence':1,'operation':'CANCEL','body':{'reason':'engagement_live_cancelled'}})
    monkeypatch.setattr(worker.select,'select',lambda *args:([state.broker],[],[]))
    refused(state.poll_stop);assert state.stopped
    monkeypatch.setattr(worker.select,'select',lambda *args:([],[],[]));refused(state.poll_stop)


def test_all_client_control_authority_fds_are_closed(monkeypatch):
    _supervisor_channel_close_failure_cases(monkeypatch)
    assert rt.RIGHTS['nmap']==rt.RIGHTS['headers']==rt.RIGHTS['parser']==rt.RIGHTS['admission']==()
    monkeypatch.setattr(admission.os,'listdir',lambda path:['0','1','2','99'])
    monkeypatch.setattr(admission.os,'fstat',lambda fd:SimpleNamespace(st_mode=0))
    with pytest.raises(ValueError):admission._entry_only_stdio()


def test_native_timeouts_and_output_caps_remain_exact(monkeypatch):
    for slot,cap,native in [('http_identify',8192,5),('http_headers',2048,1)]:
        bundle,session,value,ready=data(slot);events=[]
        owner=SimpleNamespace(ready=declared_readiness(bundle,'nmap' if native==5 else 'headers'),pin=SimpleNamespace(check_alive=lambda:None),channel=object())
        waiting=client.WaitingClient(owner,value,bundle);monkeypatch.setattr(c,'sample_clock',clock)
        monkeypatch.setattr(rt,'_send_bytes',lambda *args:events.append(args))
        bounded=SimpleNamespace(deadline=time.monotonic()+10,check=lambda:None)
        waiting.release(release(value),bounded)
        assert waiting.native_deadline<=bounded.deadline and value['envelope']['output_limit']==cap and value['envelope']['native_timeout_ns']==native*c.SECOND
        import base64
        capture={'schema_version':'1','slot':slot,'exit_code':0,'truncated':False}
        for stream,raw in [('stdout',b'x'*cap),('stderr',b'y')]:capture.update({stream+'_base64':base64.b64encode(raw).decode(),stream+'_sha256':c.digest(raw),stream+'_bytes':len(raw)})
        refused(p.validate_launcher_observation,{'dispatch_id':uid(10),'kind':'capture','data':capture})


def test_parser_isolated_replay_has_no_live_capability(monkeypatch):
    _parser_autonomous_deadline_case(monkeypatch)
    bundle,session,value,ready=data();requests=[]
    def start(**kw):requests.append(kw);c.fail('unavailable')
    monkeypatch.setattr(rt,'_start_role',start)
    control=SimpleNamespace(deadline=time.monotonic()+2,check=lambda:None)
    refused(parser.parse,tool_id=value['action']['tool_id'],raw=b'x',stderr=b'',scope=session['scope'],truncated=False,control=control,runtime=bundle)
    assert len(requests)==1 and requests[0]['role']=='parser' and requests[0]['rights']=={} and set(requests[0]['payload'])=={'slot','scope'}


def test_partial_meter_result_never_becomes_success(monkeypatch):
    _terminal_capture_cases(monkeypatch)
    fields=rt.SPEC['output_and_evidence']['result_exact_fields'];value=dict.fromkeys(fields)
    value.update(schema_version='1',dispatch_id=uid(10),slot='http_identify',status='succeeded',exit_code=0,truncated=False,
        envelope_sha256='a'*64,runtime_sha256='b'*64,stdout_sha256='c'*64,stderr_sha256='d'*64,stdout_bytes=1,stderr_bytes=0)
    refused(context.validate_client_result,value)
    value['status']='unresolved';value['stop_reason']='unresolved';assert context.validate_client_result(value)==value
    value['stdout_bytes']=8193;refused(context.validate_client_result,value)


def test_payload_identity_and_cleanup_are_not_boolean_claims(monkeypatch):
    _supervisor_thread_cases(monkeypatch)
    _persistent_launcher_cleanup_case(monkeypatch)
    bundle=declared_runtime();ready=declared_readiness(bundle,'headers');cleanup=declared_cleanup(ready)
    assert rt.validate_readiness('headers',ready,bundle)==ready and rt.validate_cleanup(cleanup)==cleanup
    for field,bad in [('start_time_ticks',True),('pid',0)]:
        changed=deepcopy(ready);changed['parent_observation']['payload'][field]=bad;refused(rt.validate_readiness,'headers',changed,bundle)
    bad=deepcopy(cleanup);bad['processes'][0]['reaped_observed']=False;refused(rt.validate_cleanup,bad)


def test_all_phases_share_original_deadline_and_cleanup(monkeypatch):
    _fixed_deadline_marker_path_cases(monkeypatch)
    _retained_prepared_bound_cases(monkeypatch)
    _normal_cleanup_before_stop_cases(monkeypatch)
    _idle_supervisor_cleanup_reserve(monkeypatch)
    _supervisor_thread_deadline_cases(monkeypatch)
    state=SimpleNamespace(pending=prepared(),poll_stop=lambda:None)
    control=worker.LauncherControl(state,M+3*c.SECOND)
    monkeypatch.setattr(c,'sample_clock',lambda:clock(3*c.SECOND));monkeypatch.setattr(worker.time,'monotonic',lambda:(M+3*c.SECOND)/c.SECOND)
    refused(control.check)
    value=prepared();go=release(value,lease=M+4*c.SECOND)
    assert go['effect_stop_ns']==M+4*c.SECOND and go['effect_stop_ns']<=value['envelope']['action_deadline_ns']-2*c.SECOND
    refused(c.validate_release_binding,go,value,clock=clock(4*c.SECOND))
    worker_state=worker.LauncherState.__new__(worker.LauncherState)
    sent=[];worker_state.client=None;worker_state.pending=None
    worker_state.send=lambda *args,**kwargs:sent.append(args)
    worker_state.deadline_ns=time.monotonic_ns()+c.SECOND
    worker_state.supervisor=SimpleNamespace(close=lambda:c.fail('cleanup_incomplete'))
    refused(worker_state.close);assert worker_state.stopped and sent==[]
    worker_state.supervisor=SimpleNamespace(close=lambda:None);worker_state.worker_id=uid(88)
    worker_state.close();assert sent[0][0]=='CLOSED'


def _normal_cleanup_before_stop_cases(monkeypatch):
    from recon_cockpit.secure_agent.engagement_live_launcher import _FixedSupervisor, _SupervisorControl
    from recon_cockpit.secure_agent.engagement_live_session import _CleanupEpoch
    from recon_cockpit.secure_agent.execution import ExecutionControl

    # Allocate the normal REAP allowance first, then publish a stop while that
    # cleanup is in flight. These are deadline inputs, not process observations.
    now = [100*c.SECOND]
    with monkeypatch.context() as patch:
        patch.setattr(time, 'monotonic', lambda: now[0]/c.SECOND)
        patch.setattr(time, 'monotonic_ns', lambda: now[0])
        for original in (105., 100.75):
            now[0] = 100*c.SECOND
            owner = _FixedSupervisor.__new__(_FixedSupervisor)
            owner.control = ExecutionControl(original, clock=time.monotonic)
            owner._deadline_ns = int(original*c.SECOND); owner.children = {}
            epoch = owner.epoch = _CleanupEpoch(owner.control)
            phase = _SupervisorControl(owner, int(original*c.SECOND))
            deadline = phase.normal_cleanup_deadline
            assert deadline == min(original, 101.9)
            assert epoch.snapshot() is None
            now[0] += 10_000_000
            stopped = epoch.stop()
            assert int(deadline*c.SECOND) <= stopped['deadline_ns']
            assert stopped['deadline_ns'] <= stopped['first_stop_requested_at_ns']+1_900_000_000
            now[0] = 100_500_000_000
            assert phase.normal_cleanup_deadline == stopped['deadline_ns']/c.SECOND
            # A received earlier bound narrows later cleanup; repeated calls
            # cannot restore either the normal allowance or the original one.
            tightened = epoch.stop(bound_deadline_ns=100_600_000_000)
            assert phase.normal_cleanup_deadline == 100.6
            assert epoch.stop(bound_deadline_ns=int(original*c.SECOND)) == tightened
            assert phase.normal_cleanup_deadline == 100.6

        now[0] = 100*c.SECOND
        owner = _FixedSupervisor.__new__(_FixedSupervisor)
        owner.control = ExecutionControl(105., clock=time.monotonic)
        owner._deadline_ns = 105*c.SECOND; owner.children = {}
        epoch = owner.epoch = _CleanupEpoch(owner.control)
        phase = _SupervisorControl(owner, 105*c.SECOND)
        assert phase.normal_cleanup_deadline == 101.9 and epoch.snapshot() is None
        sampled = []
        def stop_after_time_sample():
            sampled.append(now[0])
            now[0] += 10_000_000
            epoch.stop(bound_deadline_ns=100_600_000_000)
            return sampled[-1]/c.SECOND
        # A stop between the local clock sample and the epoch read must be
        # visible. Reading the epoch first would retain the stale 101.9 bound.
        with patch.context() as race:
            race.setattr(time, 'monotonic', stop_after_time_sample)
            assert phase.normal_cleanup_deadline == 100.6
        assert sampled == [100*c.SECOND]
        stopped = epoch.snapshot()
        assert stopped['first_stop_requested_at_ns'] == 100_010_000_000
        assert stopped['deadline_ns'] == 100_600_000_000
        assert phase.normal_cleanup_deadline == 100.6
        assert epoch.stop(bound_deadline_ns=105*c.SECOND) == stopped


def _retained_prepared_bound_cases(monkeypatch):
    """Real supervisor transitions, declared owners/clock; no native proof."""
    import base64
    from recon_cockpit.secure_agent import engagement_live_launcher as host
    from recon_cockpit.secure_agent import engagement_live_broker as broker
    from recon_cockpit.secure_agent.engagement_live_session import _CleanupEpoch
    from recon_cockpit.secure_agent.execution import ExecutionControl
    bundle, session, value, endpoint_ready = data()
    hard = value['envelope']['action_deadline_ns']; did = value['envelope']['dispatch_id']
    now = [M+c.SECOND]
    with monkeypatch.context() as patch:
        patch.setattr(time, 'monotonic_ns', lambda: now[0])
        patch.setattr(time, 'monotonic', lambda: now[0]/c.SECOND)
        def owner():
            sup = host._FixedSupervisor.__new__(host._FixedSupervisor)
            sup.control = ExecutionControl(session['binding']['broker_deadline_ns']/c.SECOND, clock=time.monotonic)
            sup._deadline_ns = session['binding']['session_deadline_ns']
            sup.epoch = _CleanupEpoch(sup.control); sup.stop = threading.Event()
            sup.state_lock = threading.Lock(); sup.setup_lock = threading.Lock()
            sup._checking = False; sup._request_ticket = None; sup._terminal_tickets = []
            sup.failure = None; sup._failure_state = None; sup.opened = session
            sup.channel = SimpleNamespace(shutdown=lambda how: None)
            sup.launcher = SimpleNamespace(runtime=bundle, slot=SimpleNamespace(launcher_id=uid(700)),
                endpoint=SimpleNamespace(identity=endpoint_ready,
                    _namespace_lease=lambda control: SimpleNamespace(close=lambda: None)))
            sup._sources = {'captures':{}, 'receipts':[], 'native':[], 'startup':[], 'prepared':[], 'child_slots':[]}
            sup.children = {}
            for index, (name, (role, _, _)) in enumerate(c.CHILD_SLOTS.items()):
                sup.children[name] = {'binding':{'child_slot':name, 'role':role, 'worker_id':uid(800+index),
                    'pair':{'child_endpoint':'declared endpoint'}}, 'endpoint':object(), 'owner':None,
                    'capture':None, 'prepared':None, 'state':'allocated', 'startup_deadline_ns':None,
                    'pending':False, 'start_resolved':False}
                sup._sources['child_slots'].append({'child_slot':name, 'prepared_sha256':None,
                    'bootstrap':None, 'entry_sha256':None})
            return sup

        sup = owner(); sup.epoch.register_action(did, hard)
        ready = declared_readiness(bundle, 'nmap', pid=808)
        receipt = declared_cleanup(ready, started=now[0]-100, finished=now[0])
        capture = {'stdout':b'declared portable capture', 'stderr':b'', 'exit_code':0,
            'truncated':False, 'status':'succeeded', 'cleanup':receipt, 'native_readiness':None}
        state = sup.children['identify_client']
        wire = {key:capture[key] for key in ('exit_code', 'truncated')}
        wire.update(schema_version='1', slot=value['envelope']['slot'])
        for stream in ('stdout', 'stderr'):
            raw = capture[stream]
            wire.update({stream+'_base64':base64.b64encode(raw).decode('ascii'),
                stream+'_bytes':len(raw), stream+'_sha256':c.digest(raw)})
        def captured(control):
            control.check()
            return {'capture':wire, 'cleanup':receipt, 'status':'succeeded'}
        state.update(prepared=value, state='active_or_rpc', start_resolved=True,
            owner=SimpleNamespace(cleanup=receipt), capture=SimpleNamespace(capture=captured,
                partial=lambda: capture, native_deadline_ns=hard-c.CLEANUP_NS))
        result = sup._execute('CAPTURE', {'child_slot':'identify_client'})
        assert result['cleanup'] is receipt and state['state'] == 'reaped'
        saved = sup._sources['captures'][did]
        assert saved['stdout'] == capture['stdout'] and saved['host_capture']['cleanup_sha256'] == c.digest(c.canonical(receipt))
        assert sup.cleanup_bound_ns() == hard and sup.epoch.snapshot() is None
        # A reaped CAPTURE still waits for meter/parser/result. No new hard or
        # work allowance is created merely because all owned clients exited.
        now[0] = hard-c.CLEANUP_NS-1; sup.phase().check()
        now[0] += 1
        with pytest.raises(c.LiveError, match='timeout'): sup.phase().check()
        sup.check_pending_deadlines()  # Hard bound is distinct from work cutoff.
        now[0] = hard+1
        with pytest.raises(c.LiveError, match='timeout'): sup.check_pending_deadlines()
        with pytest.raises(c.LiveError, match='timeout'): sup.phase().check()
        assert sup.cleanup_bound_ns() == hard
        assert sup.epoch.stop()['deadline_ns'] == hard

        # Normal cleanup uses the shared original minimum even when another
        # explicit phase has a later own-action hard bound.
        now[0] = M+c.SECOND; sup = owner()
        earlier = now[0]+500_000_000
        sup.epoch.register_action(uid(901), earlier)
        phase = sup.phase(hard)
        assert phase.normal_cleanup_deadline == earlier/c.SECOND
        assert sup.epoch.snapshot() is None

        # REAP must use the parser's actual retained short deadline, but client
        # cleanup must retain its reserve after native work has already expired.
        for name in ('identify_parser', 'identify_client'):
            sup = owner(); sup.epoch.register_action(did, hard); deadlines = []
            state = sup.children[name]; parser_end = now[0]+250_000_000
            role = state['binding']['role']
            actual_shape = declared_readiness(bundle, role, pid=820 if role == 'parser' else 821)
            def closed(*, deadline):
                deadlines.append(deadline)
                cleanup = declared_cleanup(actual_shape, started=now[0], finished=now[0]+1)
                cleanup['deadline_ns'] = int(deadline*c.SECOND)
                return rt.validate_cleanup(cleanup)
            state.update(prepared=value, state='ready', owner=SimpleNamespace(close=closed),
                startup_deadline_ns=parser_end, start_resolved=True)
            if name.endswith('_client'):
                state['capture'] = SimpleNamespace(native_deadline_ns=now[0]-1, partial=lambda: None)
            sup._execute('REAP', {'child_slot':name})
            expected = parser_end/c.SECOND if name.endswith('_parser') else now[0]/c.SECOND+1.9
            assert deadlines == [expected] and state['state'] == 'reaped'
            refused(sup._execute, 'REAP', {'child_slot':name})
            assert deadlines == [expected]

        # First valid START records the original before spawning or receiving
        # a host PREPARED reply. The real exchange refuses and stops after an
        # owned spawn seam fails; no child/process is actually constructed.
        sup = owner(); failures = []; callbacks = []; sent = []; rows = []
        def notice():
            assert sup.epoch._lock.acquire(blocking=False)
            sup.epoch._lock.release()
            callbacks.append(sup.epoch.snapshot())
            assert callbacks[-1]['deadline_ns'] <= hard
            sup.interrupt(bound_deadline_ns=hard+c.SECOND)
        sup.epoch = _CleanupEpoch(sup.control, on_stop=notice)
        sup.failure_sink = failures.append
        sup.sequence = p.ChannelSequence(uid(700), 'launcher_supervision')
        sup.budget = SimpleNamespace(record_request=lambda ticket, row: rows.append(deepcopy(row)),
            finalize=lambda ticket, row: rows.append(deepcopy(row)), release=lambda ticket: None)
        def failed_spawn(**kwargs):
            assert sup.epoch.action_bound_ns() == hard
            assert sup.children['identify_client']['pending']
            c.fail('unavailable')
        request = p.ChannelSequence(uid(700), 'launcher_supervision').make('START',
            {'child_slot':'identify_client', 'prepared':value})
        with patch.context() as startup:
            startup.setattr(rt, '_spawn_child_owned', failed_spawn)
            startup.setattr(broker, '_pair_identity', lambda peer: 'declared endpoint')
            startup.setattr(p, 'receive_packet', lambda channel, **kw: kw['control'].check() or request)
            startup.setattr(p, '_ready', lambda channel, **kw: kw['control'].check())
            startup.setattr(p, 'send_once', lambda channel, raw: sent.append(raw) or len(raw))
            with pytest.raises(c.LiveError, match='unavailable') as caught: sup._exchange(object())
        state = sup.children['identify_client']
        assert state['owner'] is None and state['start_resolved'] and not state['pending']
        assert failures == [caught.value] and len(callbacks) == 1 and len(sent) == 1
        assert rows[-1]['data']['reply']['projection']['status'] == 'refused'
        assert sup._request_ticket is None and sup.cleanup_bound_ns() == hard
        assert sup.epoch.stop(bound_deadline_ns=hard+c.SECOND) == callbacks[0]


def _supervisor_expected_bound_ns(model):
    # Derive the original bound from the contract inputs, before the supervisor's
    # integer-nanosecond representation and its conversion back to seconds.
    binding=model.session['binding']
    return min(int(model.control.deadline*c.SECOND),binding['session_deadline_ns'],
               binding['broker_deadline_ns'],model.prepared['envelope']['action_deadline_ns'])


# These tests use real host threads and POSIX pairs with declared child process
# observations. They do not claim Linux isolation or native process execution.
@contextmanager
def supervisor_lab(monkeypatch, *, seconds=3):
    from recon_cockpit.secure_agent import engagement_live_launcher as host_launcher
    from recon_cockpit.secure_agent import engagement_live_broker as host_broker
    from recon_cockpit.secure_agent.engagement_live_session import _HostEvidenceBudget, _CleanupEpoch
    from recon_cockpit.secure_agent.execution import ExecutionControl
    bundle=declared_runtime(); origin=time.monotonic_ns()
    sample=lambda:{'utc_ns':1792540800000000000+time.monotonic_ns()-origin,
                   'mono_before_ns':time.monotonic_ns(),'mono_after_ns':time.monotonic_ns()}
    session=opened(clock_value=sample());session['binding']['runtime_sha256']=rt.runtime_digest(bundle)
    value=c.derive_prepared(session,'http_identify',dispatch_id=uid(10),clock=sample())
    endpoint_ready=declared_readiness(bundle,'endpoint',pid=700)
    observer=endpoint_ready['parent_observation']['observer']
    monkeypatch.setattr(rt,'_observer',lambda:deepcopy(observer))
    original_identity=host_broker._pair_identity
    def identity(peer):
        from test_secure_engagement_live_runtime import portable_socket_identity
        return portable_socket_identity(original_identity(peer),peer.fileno())
    monkeypatch.setattr(host_broker,'_pair_identity',identity)
    peers=[];bindings=[];ends={}
    for index,(name,(role,_,fd)) in enumerate(c.CHILD_SLOTS.items()):
        left,right=socket.socketpair();left.setblocking(False);right.setblocking(False)
        peers.extend((left,right));ends[name]=right
        bindings.append({'child_slot':name,'role':role,'worker_id':uid(800+index),
            'pair':{'launcher_fd':fd,'request_endpoint':identity(left),'child_endpoint':identity(right)}})
    from test_secure_engagement_live_runtime import PortablePacket
    host,remote=(PortablePacket(peer) for peer in socket.socketpair())
    host.setblocking(False);remote.setblocking(False);peers.extend((host,remote))
    control=ExecutionControl(time.monotonic()+seconds);budget=_HostEvidenceBudget();epoch=_CleanupEpoch(control);errors=[]
    lease=SimpleNamespace(close=lambda:None)
    endpoint_owner=SimpleNamespace(identity=endpoint_ready,_namespace_lease=lambda phase:lease)
    launcher=SimpleNamespace(runtime=bundle,slot=SimpleNamespace(launcher_id=uid(700)),endpoint=endpoint_owner)
    supervisor=host_launcher._FixedSupervisor(launcher=launcher,opened=session,channel=host,
        bindings=bindings,endpoints=ends,control=control,budget=budget,epoch=epoch,
        failure_sink=errors.append,setup_lock=threading.Lock())
    model=SimpleNamespace(supervisor=supervisor,peer=remote,bindings=bindings,prepared=value,
        session=session,runtime=bundle,control=control,budget=budget,epoch=epoch,errors=errors,clock=sample,owners=[],calls=[])
    def spawn(**kwargs):
        name=kwargs['supervision_identity']['child_slot'];binding=next(x for x in bindings if x['child_slot']==name)
        assert identity(kwargs['child_stdin'])==binding['pair']['child_endpoint']
        bound_ns=_supervisor_expected_bound_ns(model)
        assert kwargs['control'].deadline==min(control.deadline,bound_ns/c.SECOND)
        assert kwargs['control'].deadline<=min(control.deadline,value['envelope']['action_deadline_ns']/c.SECOND)
        assert kwargs['startup_deadline']<=kwargs['control'].deadline
        assert kwargs['startup_deadline']<=time.monotonic()+(2 if kwargs['role']=='parser' else 10)
        model.calls.append(kwargs);kwargs['child_stdin'].close()
        bootstrap=rt.reconstruct_child_bootstrap(runtime=bundle,child_slot=binding,prepared=value,
            session=session,endpoint_identity=endpoint_ready,observer=observer,
            deadline_ns=int(kwargs['control'].deadline*c.SECOND),launcher_id=uid(700))
        ready=declared_readiness(bundle,kwargs['role'],pid=800+len(model.owners),worker_id=binding['worker_id'])
        ready['worker_ready']['bootstrap_sha256']=rt._hash(bootstrap)
        entry=deepcopy(ready['parent_observation']);entry['stage']='entry';entry['descriptors']=entry['descriptors'][:3]
        owner=SimpleNamespace(bootstrap=bootstrap,entry=entry,ready=ready,cleanup=None)
        def close(*,deadline=None):
            if owner.cleanup is None:
                now=time.monotonic_ns();owner.cleanup=declared_cleanup(ready,started=now,finished=now+1)
            return owner.cleanup
        owner.close=close;owner.observe_ready=lambda control:(control.check() or ready)
        model.owners.append(owner);return owner
    monkeypatch.setattr(rt,'_spawn_child_owned',spawn)
    try:yield model
    finally:
        supervisor.close(min(control.deadline,time.monotonic()+.5))
        if supervisor.thread is not None and supervisor.thread.is_alive():supervisor.thread.join(.5)
        for peer in peers:peer.close()


def _supervisor_refusal_cause_cases(monkeypatch):
    # Exercise the real exchange and terminal path with finite transport doubles.
    # A sent refusal keeps its first cause; failed sends keep their own failure.
    for reason, delivery in (('invalid_runtime', 'sent'), ('timeout', 'not_sent'),
                             ('cancelled', 'not_sent'), ('invalid_runtime', 'send_error'),
                             ('invalid_runtime', 'short_send')):
        with supervisor_lab(monkeypatch) as model:
            sup = model.supervisor
            original = c.LiveError('engagement_live_' + reason)
            send_error = OSError('declared refusal send failure')
            events, sent = [], []
            request = p.ChannelSequence(uid(700), 'launcher_supervision').make(
                'START', {'child_slot':'identify_client', 'prepared':model.prepared})
            def receive(channel, *, role, control):
                assert channel is sup.channel and role == 'launcher_supervision'
                control.check(); events.append('receive')
                return request
            def first_child_failure(operation, data, *, request_observed_ns=None):
                assert operation == 'START' and data == request['body']
                events.append('execute')
                raise original
            def ready(channel, *, writing, control):
                assert channel is sup.channel and writing is True
                control.check(); events.append('ready')
            def send(channel, raw):
                assert channel is sup.channel
                events.append('send'); sent.append(raw)
                if delivery == 'send_error': raise send_error
                return len(raw) - (delivery == 'short_send')
            for _ in range(2):
                sup._terminal_tickets.append(model.budget.reserve(kind='supervision_projection',
                    maximum_bytes=c.SUPERVISION_ROW_BYTES, maximum_rows=1, control=model.control))
            ticket = model.budget.reserve(kind='supervision_projection',
                maximum_bytes=c.SUPERVISION_ROW_BYTES, maximum_rows=1, control=model.control)
            sup._request_ticket = ticket
            with monkeypatch.context() as patch:
                patch.setattr(sup, '_execute', first_child_failure)
                patch.setattr(p, 'receive_packet', receive)
                patch.setattr(p, '_ready', ready)
                patch.setattr(p, 'send_once', send)
                with pytest.raises((c.LiveError, OSError)) as caught:
                    sup._exchange(ticket)
            failure = caught.value
            assert sup.failure is failure and model.errors == [failure]
            assert sup._failure_state is sup.children['identify_client']
            assert sup._request_ticket is None and model.calls == []
            if delivery in {'sent', 'not_sent'}:
                assert failure is original and failure.code == 'engagement_live_' + reason
                names = []
                trace = failure.__traceback__
                while trace is not None:
                    names.append(trace.tb_frame.f_code.co_name); trace = trace.tb_next
                assert 'first_child_failure' in names
            elif delivery == 'send_error':
                assert failure is send_error and failure is not original
            else:
                assert failure is not original and failure.code == 'engagement_live_unavailable'
            row = next(row['data'] for row in model.budget.snapshot()['rows']
                       if row['data']['kind'] == 'rpc')
            if delivery == 'not_sent':
                assert events == ['receive', 'execute'] and sent == [] and row['reply'] is None
                assert sup.sequence.sent == 0
            else:
                assert events == ['receive', 'execute', 'ready', 'send']
                expected = {'schema_version':'1', 'channel_id':uid(700), 'sequence':1,
                    'operation':'BOOTSTRAP', 'body':{'request_sequence':1, 'status':'refused',
                        'code':original.code, 'data':None}}
                assert sent == [p.encode_frame(expected, role='launcher_supervision', direction='reply')]
                assert sup.sequence.sent == 1
                assert (row['reply'] is not None) == (delivery == 'sent')
            assert row['local_error'] == getattr(failure, 'code', 'engagement_live_unavailable')
            sup.close(time.monotonic() + .5)
            assert model.budget.snapshot()['unresolved_tickets'] == 0
            assert sup.failure is failure and model.errors == [failure] and model.calls == []


def _supervisor_overlap_cases(monkeypatch):
    with supervisor_lab(monkeypatch,seconds=20) as model:
        sup=model.supervisor;value=model.prepared
        boot=sup._execute('START',{'child_slot':'identify_client','prepared':value})
        bound_ns=_supervisor_expected_bound_ns(model)
        expected_phase=min(model.control.deadline,bound_ns/c.SECOND)
        assert boot['bootstrap']['deadline_ns']==int(expected_phase*c.SECOND)
        assert boot['bootstrap']['deadline_ns']<=bound_ns
        assert boot['bootstrap']['deadline_ns']>int(model.calls[0]['startup_deadline']*c.SECOND)
        refused(sup._execute,'START',{'child_slot':'identify_client','prepared':value})
        sup._execute('START',{'child_slot':'identify_admission','prepared':value})
        refused(sup._execute,'START',{'child_slot':'identify_parser','prepared':value})
        assert len(model.calls)==2
        for name in ('identify_client','identify_admission'):sup._execute('REAP',{'child_slot':name})
        sup._execute('START',{'child_slot':'identify_parser','prepared':value})
        assert len(model.calls)==3 and all(row['descriptors']==[] for row in [owner.bootstrap for owner in model.owners])
    with supervisor_lab(monkeypatch) as model:
        one=model.supervisor.children['identify_client'];other=model.supervisor.children['headers_client']
        one['endpoint'],other['endpoint']=other['endpoint'],one['endpoint']
        refused(model.supervisor._execute,'START',{'child_slot':'identify_client','prepared':model.prepared})
        assert model.calls==[]
        receipt=model.supervisor.close(time.monotonic()+.5)
        assert receipt['pending_slots']==[] and model.supervisor.resolved
        assert model.supervisor.snapshot()['receipts']==[]


def _supervisor_thread_cases(monkeypatch):
    with supervisor_lab(monkeypatch) as model:
        sup=model.supervisor;original_thread=threading.Thread
        entered=threading.Event();resume=threading.Event();failures=[]
        def child_thread(*args,**kwargs):
            child=original_thread(*args,**kwargs)
            def held_start():
                entered.set();assert resume.wait(.5)
                # Model a Thread.start call that resolves without starting
                # after its caller requested stop, never a fabricated join.
                assert sup.stop.is_set();c.fail('cancelled')
            child.start=held_start
            return child
        def start_call():
            try:sup.start()
            except c.LiveError as error:failures.append(error)
        caller=original_thread(target=start_call)
        with monkeypatch.context() as patch:
            patch.setattr(threading,'Thread',child_thread)
            caller.start();assert entered.wait(.5)
            try:
                first=sup.close(time.monotonic()+.02)
                assert first['state']=='unknown' and first['thread_alive_observed'] is None
                assert first['status']=='failed' and not sup.resolved
            finally:resume.set();caller.join(.5)
        assert not caller.is_alive() and failures
        second=sup.close(time.monotonic()+.5)
        assert second['state']=='not_started' and second['thread_native_id'] is None
        assert second['cleanup_deadline_ns']==first['cleanup_deadline_ns']
        assert sup.resolved and model.budget.snapshot()['unresolved_tickets']==0
    with supervisor_lab(monkeypatch) as model:
        sup=model.supervisor;sup.start();sequence=p.ChannelSequence(uid(700),'launcher_supervision')
        request=sequence.make('START',{'child_slot':'identify_client','prepared':model.prepared})
        p.send_packet(model.peer,request,role='launcher_supervision',control=model.control)
        reply=sequence.accept(p.receive_packet(model.peer,role='launcher_supervision',control=model.control))
        p.require_reply(reply,request,role='launcher_supervision');assert reply['body']['status']=='ok'
        # Two terminal tickets remain reserved until the actual thread joins.
        assert model.budget.snapshot()['unresolved_tickets']>=2
        sup.close(time.monotonic()+.5)
        assert sup.closure['state']=='joined' and sup.resolved and sup.closed
        assert not sup.thread.is_alive() and model.budget.snapshot()['unresolved_tickets']==0
        rows=model.budget.snapshot()['rows'];assert any(row['data']['kind']=='rpc' for row in rows)
        assert len(model.calls)==1
    with supervisor_lab(monkeypatch) as model:
        sup=model.supervisor;original=rt._spawn_child_owned;entered=threading.Event();resume=threading.Event()
        def held(**kwargs):
            entered.set();assert resume.wait(.5)
            kwargs['control'].check()
            return original(**kwargs)
        monkeypatch.setattr(rt,'_spawn_child_owned',held)
        sup.start();request=p.ChannelSequence(uid(700),'launcher_supervision').make('START',{'child_slot':'identify_client','prepared':model.prepared})
        p.send_packet(model.peer,request,role='launcher_supervision',control=model.control);assert entered.wait(.5)
        try:
            receipt=sup.close(time.monotonic()+.02)
            assert receipt['status']=='failed' and receipt['state']=='alive' and 'identify_client' in receipt['pending_slots']
            assert not sup.resolved and model.budget.snapshot()['unresolved_tickets']>=2
        finally:resume.set()
        sup.thread.join(.5);assert not sup.thread.is_alive()
        final=sup.close(time.monotonic()+1)
        assert final['cleanup_deadline_ns']==receipt['cleanup_deadline_ns']
        assert model.calls==[] and model.budget.snapshot()['unresolved_tickets']==0


def _idle_supervisor_cleanup_reserve(monkeypatch):
    # Real idle owner thread: stop while the original cleanup allowance remains.
    with supervisor_lab(monkeypatch,seconds=2.25) as model:
        sup=model.supervisor;original=sup.cleanup_bound_ns()
        sup.start();sup.thread.join(.65)
        assert not sup.thread.is_alive()
        epoch=model.epoch.snapshot()
        assert sup.failure.code=='engagement_live_timeout'
        assert original-c.CLEANUP_NS<=epoch['first_stop_requested_at_ns']<original-c.SECOND
        assert epoch['deadline_ns']<=original and epoch['deadline_ns']>time.monotonic_ns()+c.SECOND
        sup.close(time.monotonic()+.5)
        assert sup.closure['status']=='complete' and sup.closure['channel_closed']
        assert model.calls==[] and model.budget.snapshot()['unresolved_tickets']==0
    with supervisor_lab(monkeypatch,seconds=50) as model:
        sup=model.supervisor;state=sup.children['identify_client']
        state.update(state='ready',prepared=model.prepared)
        try:
            original=model.prepared['envelope']['action_deadline_ns']
            phase=sup.phase()
            assert sup.cleanup_bound_ns()==original
            assert phase.deadline==original/c.SECOND
            assert phase.work_deadline==(original-c.CLEANUP_NS)/c.SECOND
            # A shorter native/startup phase keeps its full existing allowance.
            short=time.monotonic_ns()+100_000_000
            assert sup.phase(short).work_deadline==short/c.SECOND
        finally:state.update(state='allocated',prepared=None)


def _supervisor_thread_deadline_cases(monkeypatch):
    with supervisor_lab(monkeypatch) as model:
        phase=model.supervisor.phase();phase.check()
        assert not model.supervisor.stop.is_set()
        model.epoch.stop()
        with pytest.raises(c.LiveError,match='cancelled'):phase.check()
        assert not model.supervisor.stop.is_set()
    with supervisor_lab(monkeypatch) as model:
        sup=model.supervisor;state=sup.children['identify_admission']
        state.update(state='bootstrap_returned',prepared=model.prepared,
                     startup_deadline_ns=time.monotonic_ns()+500_000_000,start_resolved=True)
        seen=[];received=threading.Event()
        def receive(*args,**kwargs):
            seen.append((threading.get_ident(),c._operation_deadline()))
            received.set();c.fail('invalid_frame')
        with monkeypatch.context() as patch:
            patch.setattr(p,'receive_packet',receive)
            sup.start();model.peer.send(b'x');assert received.wait(.5);sup.thread.join(.5)
        assert seen==[(sup.thread.ident,state['startup_deadline_ns']/c.SECOND)]
        assert seen[0][0]!=threading.get_ident() and model.calls==[]
        sup.close(time.monotonic()+.5)

    with supervisor_lab(monkeypatch, seconds=2.8) as model:
        sup=model.supervisor;seen=[];executed=threading.Event()
        bound=model.prepared['envelope']['action_deadline_ns']/c.SECOND
        def execute(operation,data,*,request_observed_ns=None):
            seen.append((threading.get_ident(),c._operation_deadline(),time.monotonic()))
            executed.set();c.fail('invalid_role')
        monkeypatch.setattr(sup,'_execute',execute);sup.start()
        request=p.ChannelSequence(uid(700),'launcher_supervision').make('START',{'child_slot':'identify_client','prepared':model.prepared})
        p.send_packet(model.peer,request,role='launcher_supervision',control=model.control)
        assert executed.wait(.5);sup.thread.join(.5)
        sup.close(time.monotonic()+.5)
        assert seen and seen[0][0]!=threading.get_ident()
        bound_ns=_supervisor_expected_bound_ns(model)
        assert seen[0][1]==(bound_ns-c.CLEANUP_NS)/c.SECOND
        assert seen[0][1]<=min(bound,model.control.deadline)
        assert seen[0][1]<seen[0][2]+2
        rows=model.budget.snapshot()['rows']
        terminal=[row for row in rows if row['data']['kind']=='local_failure']
        assert len(terminal)==2 and all(row['data']['capture_sha256'] is None for row in terminal)
        assert model.budget.snapshot()['unresolved_tickets']==0


    with supervisor_lab(monkeypatch, seconds=2.25) as model:
        sup=model.supervisor;entered=threading.Event()
        work_deadline=(sup.cleanup_bound_ns()-c.CLEANUP_NS)/c.SECOND
        def expired(operation,data,*,request_observed_ns=None):
            entered.set()
            while time.monotonic()<work_deadline+.005:time.sleep(.002)
            c._check_deadline(work_deadline)
        monkeypatch.setattr(sup,'_execute',expired);sup.start()
        request=p.ChannelSequence(uid(700),'launcher_supervision').make('START',{'child_slot':'identify_client','prepared':model.prepared})
        p.send_packet(model.peer,request,role='launcher_supervision',control=model.control)
        assert entered.wait(.2);sup.thread.join(.5);assert not sup.thread.is_alive()
        sup.close(time.monotonic()+.5)
        rows=model.budget.snapshot()['rows'];rpc=next(row['data'] for row in rows if row['data']['kind']=='rpc')
        assert rpc['reply'] is None and rpc['local_error']=='engagement_live_timeout'
        assert len([row for row in rows if row['data']['kind']=='local_failure'])==2
        assert model.budget.snapshot()['unresolved_tickets']==0 and model.calls==[]


def _terminal_capture_cases(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_launcher as launcher
    with supervisor_lab(monkeypatch) as model:
        sup=model.supervisor
        sup._execute('START',{'child_slot':'identify_client','prepared':model.prepared})
        state=sup.children['identify_client'];owner=state['owner']
        state['capture']=SimpleNamespace(partial=lambda:{'stdout':b'partial','stderr':b'',
            'exit_code':None,'truncated':False,'status':'unresolved','cleanup':owner.cleanup,'native_readiness':None})
        for _ in range(2):sup._terminal_tickets.append(model.budget.reserve(kind='supervision_projection',maximum_bytes=3072,maximum_rows=1,control=model.control))
        sup._terminal(c.LiveError('engagement_live_unavailable'),state)
        first=model.budget.snapshot()['rows'][0]['data']
        assert first['capture_sha256'] is None and first['cleanup_sha256'] is None
        assert model.budget.snapshot()['unresolved_tickets']==1
        sup.close(time.monotonic()+.5)
        final=model.budget.snapshot()['rows'][-1]['data']
        retained=sup.snapshot()['captures'][model.prepared['envelope']['dispatch_id']]['host_capture']
        assert final['capture_sha256']==c.digest(c.canonical(retained))
        assert final['cleanup_sha256']==c.digest(c.canonical(owner.cleanup))
        assert model.budget.snapshot()['unresolved_tickets']==0 and sup.resolved
        assert not launcher._actually_reaped({'descriptors_closed':True,'processes':[]})
        for key in ('pin_verified','exit_observed','reaped_observed'):
            bad=deepcopy(owner.cleanup);bad['processes'][0][key]=False
            assert not launcher._actually_reaped(bad)


def _supervisor_channel_close_failure_cases(monkeypatch):
    class BrokenClose:
        def __init__(self, peer): self.peer=peer
        def shutdown(self, how): return self.peer.shutdown(how)
        def close(self):
            self.peer.close()
            raise OSError('declared close failure after actual descriptor release')
    for target in ('endpoint','channel'):
        with supervisor_lab(monkeypatch) as model:
            sup=model.supervisor
            if target=='channel': sup.channel=BrokenClose(sup.channel)
            else:
                state=sup.children['identify_client'];state['endpoint']=BrokenClose(state['endpoint'])
            first=sup.close(time.monotonic()+.5)
            assert first['channel_closed'] is False and first['status']=='failed' and not sup.resolved
            error=sup._channel_close_error
            second=sup.close(time.monotonic()+1)
            assert second['cleanup_deadline_ns']==first['cleanup_deadline_ns']
            assert second['channel_closed'] is False and not sup.resolved and sup._channel_close_error is error
            assert sup.failure.code=='engagement_live_cleanup_incomplete'


def _persistent_launcher_cleanup_case(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_launcher as launcher
    with supervisor_lab(monkeypatch) as model:
        service=launcher.EngagementLauncher.__new__(launcher.EngagementLauncher)
        service._pid=os.getpid();service._stop=threading.Event();service._closed=False
        service._epoch=model.epoch;service._cleanup_error=None;service._cleanup=None
        deadlines=[];ready=declared_readiness(model.runtime,'launcher',pid=950)
        receipt=declared_cleanup(ready)
        def owned_close(*,deadline):deadlines.append(deadline);return receipt
        service._owner=SimpleNamespace(channel=model.peer,close=owned_close)
        service._supervisor=SimpleNamespace(interrupt=lambda:None,
            close=lambda deadline:c.fail('evidence_invalid'),resolved=False)
        refused(service._close,time.monotonic()+.5)
        assert service._cleanup==receipt and len(deadlines)==1
        refused(service._close,time.monotonic()+2)
        assert len(deadlines)==2 and deadlines[1]<=deadlines[0]
        assert service._cleanup_error.cleanup==receipt
        # Actual joining/reaping after the original epoch remains useful
        # custody evidence, but cannot promote the live cleanup to success.
        late={'status':'failed','state':'joined'}
        service._cleanup_error=None
        service._supervisor=SimpleNamespace(interrupt=lambda:None,
            close=lambda deadline:late,resolved=True)
        with pytest.raises(c.LiveError) as caught:service._close(time.monotonic()+2)
        assert caught.value.supervisor_cleanup is late and caught.value.cleanup==receipt
        assert len(deadlines)==3 and deadlines[2]<=deadlines[0]


def _parser_autonomous_deadline_case(monkeypatch):
    with supervisor_lab(monkeypatch) as model:
        sup=model.supervisor;name='identify_parser'
        received=time.monotonic_ns()-500_000_000
        sup._execute('START',{'child_slot':name,'prepared':model.prepared},request_observed_ns=received)
        assert sup.children[name]['startup_deadline_ns'] <= received+2*c.SECOND
        assert int(model.calls[0]['startup_deadline']*c.SECOND) <= received+2*c.SECOND
        state=sup.children[name];sup._execute('OBSERVE_READY',{'child_slot':name,'bootstrap_sha256':c.digest(c.canonical(state['owner'].bootstrap))})
        # Fixed clock-bound fixture: a ready parser retains its original phase
        # deadline even if no further REAP or parser reply RPC ever arrives.
        state['startup_deadline_ns']=time.monotonic_ns()+80_000_000
        sup.start();sup.thread.join(.5)
        assert not sup.thread.is_alive() and model.errors
        assert getattr(model.errors[0],'code',None)=='engagement_live_timeout'
        sup.close(time.monotonic()+.5)
        assert state['owner'].cleanup is not None and sup.resolved


def _fixed_deadline_marker_path_cases(monkeypatch):
    """Actual transformed run/close and journal ACK, with declared native boundary.

    Real local sockets and files exercise delivery, normal METER/CANCEL/STOP,
    capture return, teardown and append ordering. Linux also retains its physical
    SEQPACKET/memfd path; every platform exercises a framed stream/tempfile path.
    The portable file declares only the unavailable seal precondition; actual
    Transcript construction, reserve and append remain in use. Admission/native creation and
    CAPTURE RPC are declared here; native cases and saved inspection remain
    separate gates. No private proposal or historical baseline is imported.
    """
    import ast
    import json
    from pathlib import Path
    import select
    import sys
    import tempfile
    from types import ModuleType, MethodType
    from recon_cockpit.secure_agent import engagement_live_endpoint_worker as endpoint_worker
    from test_secure_engagement_live_contract import U
    from test_secure_engagement_live_meter import Stream
    ROOT = Path(__file__).resolve().parents[1]
    PROPOSAL = Path(__file__).with_name('engagement_live_native.py')

    def transformed(case_id):
        # Compile only the literal fixed fixture definitions; importing the native
        # harness is unnecessary. Compile whole transformed workers without main.
        names = {'DEADLINE_FAULT_CASES', '_deadline_once', '_LAUNCHER_HELPERS',
                 '_BROKER', 'deadline_fault_transforms'}
        tree = ast.parse(PROPOSAL.read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names
                 or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets)]
        definitions = {}; exec(compile(ast.Module(body=nodes, type_ignores=[]), str(PROPOSAL), 'exec'), definitions)
        transforms = definitions['deadline_fault_transforms'](case_id); result = []
        for suffix in ('launcher', 'broker'):
            name = 'engagement_live_'+suffix+'_worker'
            source = transforms[name]((ROOT/'recon_cockpit/secure_agent'/f'{name}.py').read_text())
            module = ModuleType('recon_cockpit.secure_agent._owned_'+suffix+'_model')
            module.__package__ = 'recon_cockpit.secure_agent'; module.__file__ = str(PROPOSAL)
            exec(compile(source, str(PROPOSAL)+':'+suffix, 'exec'), module.__dict__)
            result.append(module)
        return result

    class StreamRecords:
        """Bounded fixture framing over real bytes, retaining peek and EOF.

        Canonical JSON contains no literal newline. One nonblocking send writes
        one complete record; no retries or additional deadline allowances are
        introduced. A pair-local lock prevents a reader from racing a send still
        in progress; it is held only across bounded nonblocking socket calls.
        """
        def __init__(self, peer, gate): self.peer=PortablePacket(peer); self.gate=gate
        def __getattr__(self, name): return getattr(self.peer, name)
        def send(self, raw, flags=0): return self.sendmsg([raw], [], flags)
        def sendmsg(self, buffers, ancillary=(), flags=0):
            raw=b''.join(buffers)
            assert not ancillary and 0<len(raw)<=c.MAX_PACKET and b'\n' not in raw
            wire=raw+b'\n'
            with self.gate:
                assert self.peer.sendmsg([wire], [], flags)==len(wire), 'short fixture record send'
            return len(raw)
        def recv(self, size, flags=0): return self.recvmsg(size, 0, flags)[0]
        def recvmsg(self, size, ancillary_size=0, flags=0):
            assert 0<size<=c.MAX_PACKET+1
            with self.gate:
                queued=self.peer.recvmsg(c.MAX_PACKET+1, 0, flags | socket.MSG_PEEK)[0]
                if not queued:
                    return self.peer.recvmsg(size, ancillary_size, flags)
                boundary=queued.find(b'\n')
                assert 0<boundary<=c.MAX_PACKET, 'incomplete or oversized fixture record'
                wire, ancillary, received_flags, address=self.peer.recvmsg(boundary+1, ancillary_size, flags)
                assert wire==queued[:boundary+1], 'fixture record changed after peek'
            if boundary>size: received_flags |= socket.MSG_TRUNC
            return wire[:-1][:size], ancillary, received_flags, address

    class DarwinFlagEcho:
        """Simulate only returned flags; bytes, ancillary data and EOF stay real."""
        def __init__(self, peer): self.peer=peer; self.extra_flags=0; self.ancillary=()
        def __getattr__(self, name): return getattr(self.peer, name)
        def recvmsg(self, size, ancillary_size=0, flags=0):
            raw, ancillary, received, address=self.peer.recvmsg(size, ancillary_size, flags)
            self.ancillary=ancillary
            return raw, ancillary, received | (flags & socket.MSG_DONTWAIT) | self.extra_flags, address

    def channel_pair(backend):
        if backend=='seqpacket': return socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        peers=socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM); gate=threading.Lock()
        # Force Darwin's requested flag echo in every existing stream schedule.
        return tuple(StreamRecords(DarwinFlagEcho(peer), gate) for peer in peers)

    def check_stream_flag_normalization():
        import array
        import errno
        from recon_cockpit.secure_agent.execution import ExecutionControl
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        with left,right,tempfile.TemporaryFile() as descriptor:
            left.setblocking(False);right.setblocking(False)
            echoed=DarwinFlagEcho(left);gate=threading.Lock()
            reader=StreamRecords(echoed,gate);writer=StreamRecords(right,gate)
            frame=p.ChannelSequence(uid(980),'launcher').make('STOP',None);raw=c.canonical(frame)
            def receive_frame():
                return p.receive_packet(reader,role='launcher',control=ExecutionControl(time.monotonic()+.1))
            writer.send(raw)
            assert reader.recv(c.MAX_PACKET,socket.MSG_DONTWAIT|socket.MSG_PEEK)==raw
            assert receive_frame()==frame
            # Only requested DONTWAIT is normalized; unexpected output still refuses.
            for extra in (socket.MSG_TRUNC,socket.MSG_CTRUNC,1<<29):
                echoed.extra_flags=extra;writer.send(raw)
                with pytest.raises(c.LiveError) as caught:receive_frame()
                assert caught.value.code=='engagement_live_invalid_frame'
            echoed.extra_flags=socket.MSG_DONTWAIT;writer.send(raw)
            assert reader.recvmsg(c.MAX_PACKET)[2] & socket.MSG_DONTWAIT
            echoed.extra_flags=0;writer.send(raw)
            value,ancillary,flags,_=reader.recvmsg(1,0,socket.MSG_DONTWAIT)
            assert value==raw[:1] and not ancillary and flags & socket.MSG_TRUNC
            assert not flags & socket.MSG_DONTWAIT
            # Actual received rights remain visible to the production refusal/close path.
            rights=array.array('i',[descriptor.fileno()]);wire=raw+b'\n'
            assert right.sendmsg([wire],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,rights)])==len(wire)
            with pytest.raises(c.LiveError) as caught:receive_frame()
            assert caught.value.code=='engagement_live_invalid_channel'
            received=array.array('i')
            assert len(echoed.ancillary)==1
            level,kind,data=echoed.ancillary[0];assert (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS)
            received.frombytes(data);assert len(received)==1
            for fd in received:
                with pytest.raises(OSError) as closed:os.fstat(fd)
                assert closed.value.errno==errno.EBADF
            right.shutdown(socket.SHUT_WR)
            value,ancillary,flags,_=reader.recvmsg(c.MAX_PACKET,0,socket.MSG_DONTWAIT)
            assert value==b'' and not ancillary and flags==0
            echoed.extra_flags=socket.MSG_DONTWAIT|socket.MSG_TRUNC|socket.MSG_CTRUNC|(1<<29)
            assert reader.recvmsg(c.MAX_PACKET)[2] & echoed.extra_flags==echoed.extra_flags

    @contextmanager
    def path_model(monkeypatch, case_id='S42C-N35'):
        launcher, broker = transformed(case_id)
        if backend=='stream':
            # Only this transformed module sees the portable flag value. Shared
            # socket APIs and the physical Linux backend remain unchanged.
            launcher.socket=SimpleNamespace(**vars(socket)); launcher.socket.MSG_CMSG_CLOEXEC=0
        anchor = time.monotonic_ns()
        def sample():
            now = time.monotonic_ns()
            return {'mono_before_ns':now, 'mono_after_ns':now, 'utc_ns':U+now-anchor}
        monkeypatch.setattr(c, 'sample_clock', sample)
        bundle = declared_runtime(); session = opened(clock_value=sample())
        session['binding']['runtime_sha256'] = rt.runtime_digest(bundle)
        value = c.derive_prepared(session, 'http_identify', dispatch_id=uid(10), clock=sample())
        go = release(value, lease=sample()['mono_after_ns']+5*c.SECOND); go['guard_clock'] = sample()
        left, right = channel_pair(backend)
        host, supervisor_host = channel_pair(backend)
        for peer in (left,right,host,supervisor_host): peer.setblocking(False)
        journal_file=None
        if backend=='seqpacket':
            fd=os.memfd_create('declared-marker-model', os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        else:
            journal_file=tempfile.TemporaryFile(); fd=journal_file.fileno()
            # This schedule tests actual append/ACK ordering, not Linux sealing.
            # Declare only the seal query; keep real fstat, access flags and writes.
            file_control=broker.fcntl; seal_query=object()
            def declared_unsealed(descriptor, operation):
                if descriptor==fd and operation is seal_query: return 0
                return file_control.fcntl(descriptor, operation)
            broker.fcntl=SimpleNamespace(**vars(file_control))
            broker.fcntl.F_GET_SEALS=seal_query; broker.fcntl.fcntl=declared_unsealed
        journal = broker.Transcript(fd, broker_id=value['envelope']['broker_id'])
        events=[]; errors=[]; threads=[]
        ready = declared_readiness(bundle,'nmap'); cleanup = declared_cleanup(ready)
        native = {'schema_version':'1','role':'nmap','waiting_image':deepcopy(ready['parent_observation']['executable']),
                  'parent_observation':deepcopy(ready['parent_observation']), 'observed_at_ns':time.monotonic_ns()}
        native['parent_observation']['stage']='native'; native['parent_observation']['executable'].update(destination='/tool/nmap',sha256='f'*64)
        capture={'stdout':b'actual model bytes','stderr':b'','exit_code':0,'truncated':False,
                 'status':'succeeded','cleanup':cleanup,'readiness':ready,'native_readiness':native}
        state=launcher.LauncherState.__new__(launcher.LauncherState)
        state.pending=value; state.release=None; state.worker_id=uid(51); state.deadline_ns=value['envelope']['session_deadline_ns']
        state.stopped=False; state._polling=False; state.host=host; state.broker=left; state.sequence=p.ChannelSequence(state.worker_id,'launcher')
        state.runtime=bundle; state.payload={'scope':session['scope'],'endpoint_identity':declared_readiness(bundle,'endpoint')}
        state.permit={'reference':'a'*64}; state.cleanups=[]; state.readies=[]; state.capture=None; state.meter=None; state.arm=object()
        # Actual SupervisorChannel.close exercises the shutdown which triggered the
        # old race. Client/admission/native boundaries remain explicitly declared.
        supervisor=rt.SupervisorChannel.__new__(rt.SupervisorChannel)
        supervisor.channel=host; supervisor.channels={}; supervisor.pending=False; supervisor.failed=False
        state.supervisor=supervisor
        state.admission_rpc=lambda *args:(events.append('redeem') or None)
        state.admission=SimpleNamespace(close=lambda **kwargs:(events.append('admission_cleanup') or cleanup))
        def collect(control):
            control.check(); events.append('capture_delivered'); return capture
        state.client=SimpleNamespace(native_ready=native,native_deadline=time.monotonic()+5,
            release=lambda *args:events.append('release'),observe_native=lambda *args:native,
            collect=collect,close=lambda:(events.append('native_cleanup') or cleanup))
        row={'prepared':value,'release':go,'state':'running','observations':[]}
        def send(operation,body,**kwargs):
            events.append(operation)
            if operation=='NATIVE_OBSERVED':row['native']=body
        state.send=send
        state.observe=lambda kind,data:events.append('relay_'+kind)
        monkeypatch.setattr(endpoint,'arm_endpoint',lambda *args,**kwargs:events.append('arm'))
        core=SimpleNamespace(slots=[{'dispatch_id':value['envelope']['dispatch_id']}],dispatches={value['envelope']['dispatch_id']:row},
            transcript=journal,deadline_ns=value['envelope']['broker_deadline_ns'],check=lambda:c.check_clock(sample(),anchor=value['envelope']['clock_anchor'],
            window_start_utc_ns=value['envelope']['window_start_utc_ns'],window_end_utc_ns=value['envelope']['window_end_utc_ns'],deadline_ns=value['envelope']['action_deadline_ns']))
        core.phase=MethodType(broker.BrokerCore.phase,core)
        loop=broker.BrokerLoop.__new__(broker.BrokerLoop)
        loop.core=core;loop.launchers=[right];loop.endpoints=[];loop.sequences={('launcher',0):p.ChannelSequence(state.worker_id,'launcher')}
        loop.stopping=False
        def launch():
            try:state.run(go)
            except BaseException as error:errors.append(error)
            finally:
                events.append('launcher_close');state.close()
        def start(*,expect_marker=True):
            thread=threading.Thread(target=launch);threads.append(thread);thread.start()
            if expect_marker:assert select.select([right],[],[],.5)[0], 'launcher never sent marker'
            return thread
        def ordinary(operation,body):
            frame=loop.sequences[('launcher',0)].make(operation,body)
            p.send_packet(right,frame,role='launcher',control=rt._WorkerControl(time.monotonic_ns()+c.SECOND))
        model=SimpleNamespace(launcher=launcher,state=state,row=row,loop=loop,journal=journal,fd=fd,events=events,errors=errors,
            left=left,right=right,host=host,supervisor_host=supervisor_host,start=start,threads=threads,ordinary=ordinary,
            prepared=value,go=go,scope=session['scope'])
        try:yield model
        finally:
            for peer in (left,right,host,supervisor_host):
                try:peer.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            for thread in threads:thread.join(1);assert not thread.is_alive()
            for peer in (left,right,host,supervisor_host):peer.close()
            if journal_file is None: os.close(fd)
            else: journal_file.close()

    def rows(model):
        return [json.loads(line) for line in os.pread(model.fd,1048576,0).splitlines()]

    def test_real_append_precedes_launcher_host_shutdown(monkeypatch,case_id,with_meter):
        with path_model(monkeypatch,case_id) as model:
            meter_value=None
            if with_meter:
                meter=endpoint_worker.Meter(model.prepared,uid(60),model.scope);meter.arm(model.go)
                # Accepted identify grammar first observes the real empty probe.
                meter.admit();assert meter.receive(Stream([b'']))==b''
                meter.admit();stream=Stream([meter.expected]);assert meter.receive(stream)==meter.reply;assert meter.send(stream)
                assert meter.connections==2 and meter.reason=='complete'
                meter_value=meter.snapshot()
            launcher_thread=model.start();entered=threading.Event();allow=threading.Event();broker_errors=[]
            original=model.journal.record
            def held(*args,**kwargs):
                entered.set()
                assert allow.wait(.05), 'test scheduling exceeded fixed barrier budget'
                result=original(*args,**kwargs);model.events.append('broker_appended');return result
            model.journal.record=held
            if with_meter:model.ordinary('METER',meter_value)
            def receive():
                try:model.loop.role_message('launcher',0)
                except BaseException as error:broker_errors.append(error)
            receiver=threading.Thread(target=receive);model.threads.append(receiver);receiver.start()
            try:
                assert entered.wait(.05)
                # The old fixture closes the supervision peer before this append.
                assert 'launcher_close' not in model.events
                assert not select.select([model.supervisor_host],[],[],0)[0]
                assert not rows(model)
            finally:allow.set()
            launcher_thread.join(.5);receiver.join(.5)
            assert not launcher_thread.is_alive() and not receiver.is_alive() and not broker_errors
            assert len(model.errors)==1 and model.errors[0].code=='engagement_live_timeout'
            assert model.events.index('broker_appended')<model.events.index('launcher_close')
            if case_id=='S42C-N35':
                assert model.events.index('capture_delivered')<model.events.index('broker_appended')
                assert model.state.capture['stdout_bytes']==len(b'actual model bytes')
            else:assert 'capture_delivered' not in model.events and 'native_cleanup' in model.events
            assert select.select([model.supervisor_host],[],[],0)[0]
            assert model.supervisor_host.recv(1)==b''
            retained=rows(model);assert len(retained)==1
            assert retained[0]['kind']=='phase' and retained[0]['data']['reason']=='engagement_live_timeout'
            assert retained[0]['data']['original_deadline_ns']==model.prepared['envelope']['action_deadline_ns']
            assert model.state._owned_deadline_seen is True
            assert model.state.poll_stop.__func__.__name__=='poll_stop'
            if with_meter:assert model.state.meter is not None
            # The private ACK never increments ordinary incoming role sequence.
            assert model.state.sequence.received==(1 if with_meter else 0)

    def test_failure_never_substitutes_for_journal_ack(monkeypatch,failure):
        with path_model(monkeypatch) as model:
            thread=model.start()
            if failure in ('CANCEL','STOP'):model.ordinary(failure,None if failure=='STOP' else {'reason':'engagement_live_cancelled'})
            elif failure=='broker_eof':model.right.shutdown(socket.SHUT_RDWR)
            elif failure=='host_eof':model.supervisor_host.shutdown(socket.SHUT_RDWR)
            elif failure=='wrong_ack':
                model.right.send(c.canonical({'schema_version':'1','channel_id':model.state.worker_id,'sequence':1,
                    'operation':'OWNED_DEADLINE_ACK','body':{'marker_sha256':'f'*64}}))
            elif failure=='journal_failure':
                def failed(*args,**kwargs):raise OSError('declared append failure')
                model.journal.record=failed
                with pytest.raises(OSError):model.loop.role_message('launcher',0)
                assert not select.select([model.left],[],[],0)[0], 'ACK sent despite failed journal append'
                model.right.shutdown(socket.SHUT_RDWR)
            thread.join(.5);assert not thread.is_alive()
            assert len(model.errors)==1 and not getattr(model.state,'_owned_deadline_seen',False)
            assert not rows(model) and model.state.poll_stop.__func__.__name__=='poll_stop'
            assert model.state.supervisor.failed and 'launcher_close' in model.events
            if failure in ('CANCEL','STOP','host_eof'):assert model.errors[0].code=='engagement_live_cancelled'
            if failure=='missing_ack':assert model.errors[0].code=='engagement_live_timeout'

    def test_terminal_or_duplicate_packet_immediately_after_ack(monkeypatch,following):
        with path_model(monkeypatch) as model:
            queued=[]
            class QueuedFollowing:
                # Complete the actual append/ACK/following writes before the
                # marker send returns; the original 100 ms phase includes them.
                def __getattr__(self,name):return getattr(model.left,name)
                def send(self,raw,flags=0):
                    count=model.left.send(raw,flags)
                    assert count==len(raw) and not queued
                    assert json.loads(raw).get('operation')=='OWNED_DEADLINE'
                    assert model.right.recv(4097,socket.MSG_PEEK)==raw
                    model.loop.role_message('launcher',0)
                    assert len(rows(model))==1 and 'launcher_close' not in model.events
                    if following=='CANCEL':model.ordinary('CANCEL',{'reason':'engagement_live_cancelled'})
                    else:
                        duplicate=c.canonical({'schema_version':'1','channel_id':model.state.worker_id,'sequence':1,
                            'operation':'OWNED_DEADLINE_ACK','body':{'marker_sha256':c.digest(raw)}})
                        assert model.right.send(duplicate)==len(duplicate)
                        if following=='duplicate_ack_host_eof':model.supervisor_host.shutdown(socket.SHUT_RDWR)
                    queued.append(following)
                    return count
            model.state.broker=QueuedFollowing()
            thread=model.start(expect_marker=False)
            thread.join(.5);assert not thread.is_alive(),(backend,following,model.errors)
            assert queued==[following],(backend,following,model.errors)
            assert len(model.errors)==1 and getattr(model.errors[0],'code',None)==('engagement_live_cancelled' if following=='CANCEL' else 'engagement_live_invalid_frame'),(backend,following,model.errors)
            assert not getattr(model.state,'_owned_deadline_seen',False)
            assert model.state.supervisor.failed and model.state.poll_stop.__func__.__name__=='poll_stop'
            assert len(rows(model))==1 and 'RESULT' not in model.events

    def test_ack_arriving_after_empty_broker_check(monkeypatch):
        # Return an actual empty readiness observation, then deliver the actual
        # journal ACK before the caller resumes. The old second broker check
        # consumes it through the ordinary protocol and rejects the private ACK.
        with path_model(monkeypatch) as model:
            real_select=model.launcher.select.select;injected=[]
            def inject_after_empty(readers,writers,errors,timeout=None):
                selected=real_select(readers,writers,errors,timeout)
                if (readers==[model.state.broker] and not writers and not errors and timeout==0
                        and not selected[0] and not injected
                        and real_select([model.right],[],[],0)[0]):
                    raw=model.right.recv(4097,socket.MSG_PEEK)
                    assert json.loads(raw)['operation']=='OWNED_DEADLINE'
                    model.loop.role_message('launcher',0)
                    assert len(rows(model))==1 and 'launcher_close' not in model.events
                    assert real_select([model.left],[],[],0)[0]
                    injected.append(raw)
                return selected
            # This transformed module alone sees the scheduling seam; physical
            # readiness, packet data, append and every control clock remain real.
            monkeypatch.setattr(model.launcher,'select',SimpleNamespace(select=inject_after_empty))
            thread=model.start(expect_marker=False);thread.join(.5)
            assert not thread.is_alive(),(backend,model.errors)
            assert len(injected)==1,(backend,model.errors)
            assert len(model.errors)==1 and getattr(model.errors[0],'code',None)=='engagement_live_timeout',(backend,model.errors)
            assert model.state._owned_deadline_seen is True
            assert len(rows(model))==1 and 'RESULT' not in model.events
            assert model.state.supervisor.failed and 'launcher_close' in model.events
            assert model.state.poll_stop.__func__.__name__=='poll_stop'
            assert not hasattr(model.state,'_owned_ack')

    def test_original_deadline_can_expire_before_or_after_marker_send(monkeypatch,expiry):
        # Only time is declared here. Real socket send/absence, actual transformed
        # control and teardown remain exercised; no scheduler-dependent15ms race.
        with path_model(monkeypatch) as model:
            original_marker=model.launcher._owned_deadline_marker;clock=[];originals=[];sent=[]
            def at_marker(state,phase):
                entered=time.monotonic_ns();original=entered+15_000_000
                originals.append(original);state.deadline_ns=original
                clock.append(original+1 if expiry=='before_send' else entered)
                fixed=SimpleNamespace(monotonic=lambda:clock[0]/c.SECOND,monotonic_ns=lambda:clock[0])
                monkeypatch.setattr(model.launcher,'time',fixed)
                monkeypatch.setattr(c.records,'time',fixed)
                if expiry=='ack_wait':
                    class SendThenExpire:
                        def __getattr__(self,name):return getattr(model.left,name)
                        def send(self,raw,flags=0):
                            count=model.left.send(raw,flags)
                            if json.loads(raw).get('operation')=='OWNED_DEADLINE':
                                assert count==len(raw);sent.append(bytes(raw));clock[0]=original+1
                            return count
                    state.broker=SendThenExpire()
                return original_marker(state,phase)
            monkeypatch.setattr(model.launcher,'_owned_deadline_marker',at_marker)
            thread=model.start(expect_marker=False);thread.join(.5)
            assert not thread.is_alive() and len(originals)==1
            assert len(model.errors)==1 and model.errors[0].code=='engagement_live_timeout'
            assert model.state.deadline_ns==originals[0] and not getattr(model.state,'_owned_deadline_seen',False)
            assert not rows(model) and model.state.supervisor.failed and 'launcher_close' in model.events
            assert model.state.poll_stop.__func__.__name__=='poll_stop'
            if expiry=='before_send':
                assert not sent and not select.select([model.right],[],[],0)[0]
            else:
                assert len(sent)==1 and model.right.recv(4097)==sent[0]
                assert json.loads(sent[0])['operation']=='OWNED_DEADLINE'

    check_stream_flag_normalization()
    backends=('seqpacket','stream') if sys.platform=='linux' else ('stream',)
    for backend in backends:
        checked = 0
        for case_id in ('S42C-N34', 'S42C-N35'):
            for with_meter in (False, True):
                with monkeypatch.context() as local:
                    test_real_append_precedes_launcher_host_shutdown(local, case_id, with_meter)
                checked += 1
        for failure in ('CANCEL', 'STOP', 'broker_eof', 'host_eof', 'wrong_ack', 'missing_ack', 'journal_failure'):
            with monkeypatch.context() as local:
                test_failure_never_substitutes_for_journal_ack(local, failure)
            checked += 1
        for following in ('CANCEL', 'duplicate_ack', 'duplicate_ack_host_eof'):
            with monkeypatch.context() as local:
                test_terminal_or_duplicate_packet_immediately_after_ack(local, following)
            checked += 1
        for expiry in ('before_send', 'ack_wait'):
            with monkeypatch.context() as local:
                test_original_deadline_can_expire_before_or_after_marker_send(local, expiry)
            checked += 1
        assert checked == 16  # Original15 plus duplicate-ACK/host-EOF precedence.
        with monkeypatch.context() as local:
            test_ack_arriving_after_empty_broker_check(local)
