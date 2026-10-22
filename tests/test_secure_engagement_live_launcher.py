"""S42C-L01..L16: fixed ordering and bounded local doubles, no native proof."""
from copy import deepcopy
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
from test_secure_engagement_live_runtime import declared_runtime,declared_readiness,declared_cleanup


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
    state.host=object();state.broker=object();state.pending=None
    monkeypatch.setattr(worker.select,'select',lambda *args:([state.host,state.broker],[],[]))
    refused(state.poll_stop);assert state.stopped
    monkeypatch.setattr(worker.select,'select',lambda *args:([],[],[]));refused(state.poll_stop)


def test_all_client_control_authority_fds_are_closed(monkeypatch):
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
    bundle,session,value,ready=data();requests=[]
    def start(**kw):requests.append(kw);c.fail('unavailable')
    monkeypatch.setattr(rt,'_start_role',start)
    control=SimpleNamespace(deadline=time.monotonic()+2,check=lambda:None)
    refused(parser.parse,tool_id=value['action']['tool_id'],raw=b'x',stderr=b'',scope=session['scope'],truncated=False,control=control,runtime=bundle)
    assert len(requests)==1 and requests[0]['role']=='parser' and requests[0]['rights']=={} and set(requests[0]['payload'])=={'slot','scope'}


def test_partial_meter_result_never_becomes_success():
    fields=rt.SPEC['output_and_evidence']['result_exact_fields'];value=dict.fromkeys(fields)
    value.update(schema_version='1',dispatch_id=uid(10),slot='http_identify',status='succeeded',exit_code=0,truncated=False,
        envelope_sha256='a'*64,runtime_sha256='b'*64,stdout_sha256='c'*64,stderr_sha256='d'*64,stdout_bytes=1,stderr_bytes=0)
    refused(context.validate_client_result,value)
    value['status']='unresolved';value['stop_reason']='unresolved';assert context.validate_client_result(value)==value
    value['stdout_bytes']=8193;refused(context.validate_client_result,value)


def test_payload_identity_and_cleanup_are_not_boolean_claims():
    bundle=declared_runtime();ready=declared_readiness(bundle,'headers');cleanup=declared_cleanup(ready)
    assert rt.validate_readiness('headers',ready,bundle)==ready and rt.validate_cleanup(cleanup)==cleanup
    for field,bad in [('start_time_ticks',True),('pid',0)]:
        changed=deepcopy(ready);changed['parent_observation']['payload'][field]=bad;refused(rt.validate_readiness,'headers',changed,bundle)
    bad=deepcopy(cleanup);bad['processes'][0]['reaped_observed']=False;refused(rt.validate_cleanup,bad)


def test_all_phases_share_original_deadline_and_cleanup(monkeypatch):
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
    worker_state.admission=SimpleNamespace(close=lambda **kwargs:c.fail('cleanup_incomplete'))
    worker_state.close();assert worker_state.stopped and sent==[]
    worker_state.admission=None;worker_state.worker_id=uid(88)
    worker_state.close();assert sent[0][0]=='CLOSED'
