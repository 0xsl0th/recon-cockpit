"""S42C-W01..W12: real local channels and declared replay, never native proof."""
import array
import base64
from contextlib import contextmanager
from copy import deepcopy
import errno
import hashlib
import os
import socket
import stat
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import audit_protocol as legacy
from recon_cockpit.secure_agent import audit_witness as old_witness
from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent import engagement_live_witness as w
from recon_cockpit.secure_agent import engagement_live_audit as adapter
from recon_cockpit.secure_agent.execution import ExecutionControl
from test_secure_engagement_live_contract import opened, prepared, clock, uid, M


def sha(raw):return hashlib.sha256(raw).hexdigest()


def refused(function,*args,code=None,**kwargs):
    with pytest.raises(c.LiveError) as caught:function(*args,**kwargs)
    assert caught.value.code in c.ERROR_CODES
    if code:assert caught.value.code=='engagement_live_'+code
    return caught.value


def approval(p=None,*,sequence=1,issued=None,expires=None):
    p=prepared() if p is None else p;e=p['envelope']
    return {'schema_version':'1',**{k:e[k] for k in ('reviewer_id','broker_id','ledger_owner_id','session_id','dispatch_id',
        'action_sha256','policy_sha256')},'consume_sequence':sequence,'reference_sha256':'f'*64,
        'envelope_sha256':c.envelope_digest(e),'issued_at_ns':M if issued is None else issued,
        'expires_at_ns':M+30*c.SECOND if expires is None else expires,'accepted':True}


def audit(p=None,*,sequence=1,audit_sequence=1,issued=1000.0):
    p=prepared() if p is None else p;event=w.started_event(p)
    value=old_witness.witness(event,uid(90),audit_sequence,sequence,issued)
    raw=legacy.encode(value)
    return raw,{'version':'1','writer_id':uid(90),'device':10,'inode':11}


@contextmanager
def direct(monkeypatch,*,kind='approval',halfclosed=True):
    """Use a real pair. On macOS only its unavailable packet-type tag is modeled.

    Portable tests prove real direction, identity and ancillary behavior. They
    do not label the stream fallback as a Linux seqpacket/confinement witness.
    """
    packet_type=getattr(socket,'SOCK_SEQPACKET',5)
    try:left,right=socket.socketpair(socket.AF_UNIX,packet_type);modeled=False
    except OSError:left,right=socket.socketpair();modeled=True
    left.setblocking(False);right.setblocking(False)
    if halfclosed:left.shutdown(socket.SHUT_WR);right.shutdown(socket.SHUT_RD)
    identity=[os.fstat(left.fileno()).st_dev,os.fstat(left.fileno()).st_ino]
    reader=None
    try:
        with monkeypatch.context() as local:
            local.setattr(socket,'MSG_CMSG_CLOEXEC',getattr(socket,'MSG_CMSG_CLOEXEC',0),raising=False)
            if modeled:
                original=socket.socket
                class PacketTag:
                    family=socket.AF_UNIX;type=packet_type
                    def __init__(self,*,fileno):self.inner=original(fileno=fileno)
                    def __getattr__(self,key):return getattr(self.inner,key)
                local.setattr(socket,'SOCK_SEQPACKET',packet_type,raising=False)
                local.setattr(socket,'socket',PacketTag)
            reader=w.DirectReader(left.detach(),identity,kind=kind)
            yield reader,right,identity
    finally:
        if reader is not None:reader.close()
        left.close();right.close()


def audit_ready():
    """Closed declared readiness, not a process/kernel observation."""
    from test_secure_engagement_live_runtime import declared_runtime,declared_readiness
    parent=declared_readiness(declared_runtime(),'headers')['parent_observation']
    parent['role']='audit';parent['uid_map'][0][0]=parent['gid_map'][0][0]=0
    result={'schema_version':'1','writer_id':uid(90),
        'initial':{'version':'1','writer_id':uid(90),'device':20,'inode':21,'witness':[10,12]},
        'ready':{'version':'1','writer_id':uid(90),'ready':True,'checks':dict.fromkeys(legacy.CHECKS,True)},
        'source_manifest':{'version':'1','writer_id':uid(90),'device':10,'inode':11},
        'append_identity':{'device':20,'inode':21,'mode':stat.S_IFREG|0o600,'uid':1000,'gid':1000,'links':1,'size':0},
        'parent_observation':parent}
    return w.validate_audit_readiness(result)


def resequence(rows):
    """Keep the segment framing valid while testing deeper proof omissions."""
    rows=deepcopy(rows);sequences={}
    for wrapped in rows:
        segment=wrapped['segment'];sequences[segment]=sequences.get(segment,0)+1
        wrapped['row']['row_sequence']=sequences[segment]
    return rows


def complete_authority_fixture(*,runtime_sha256='a'*64):
    """Real pure v2 history and declared protocol data; no native authority.

    The independently encoded producer/witness/projections all bind the same
    exact Prepared. Callers must add actual-shaped client/runtime/cleanup data
    before asking the full bundle context to validate a useful result.
    """
    session=opened();session['binding']['runtime_sha256']=runtime_sha256
    session=c.validate_session_opened(session);p=prepared(opened_value=session);env=p['envelope']
    state,create=ledger._apply(None,{'schema_version':'2','engagement_id':uid(1),'event_id':uid(100),
        'operation':'create','expected_revision':None,'expected_generation':None,'body':session['roe']})
    initial=deepcopy(state)
    state,session_receipt=ledger._apply(state,{'schema_version':'2','engagement_id':uid(1),'event_id':uid(101),
        'operation':'session','expected_revision':1,'expected_generation':0,'body':{'owner_id':uid(3),
        'session_id':uid(4),'clock':clock(),'original_deadline_ns':M+60*c.SECOND}})
    assert session_receipt==session['session_receipt']['receipt']
    a=approval(p);araw=c.canonical(a);event=w.started_event(p);draw,source=audit(p)
    approval_observation={'raw_base64':base64.b64encode(araw).decode(),'raw_sha256':sha(araw),'witness':a,'received_at_ns':M+1}
    audit_observation={'producer_event':event,'producer_sha256':sha(legacy.event_bytes(event)),
        'raw_base64':base64.b64encode(draw).decode(),'raw_sha256':sha(draw),'received_at_ns':M+2}
    state,reservation=ledger._apply(state,{'schema_version':'2','engagement_id':uid(1),'event_id':uid(102),
        'operation':'reserve','expected_revision':1,'expected_generation':0,'body':{'owner_id':uid(3),
        'session_id':uid(4),'dispatch_id':uid(10),'slot':'http_identify','clock':clock(3),
        'approval':{'broker_id':uid(5),'consume_sequence':1,'witness_sha256':sha(araw)},
        'audit':{'writer_id':uid(90),'audit_sequence':1,'event_sha256':sha(legacy.event_bytes(event))}}})
    lease=c.derive_effective_lease(p,state['reservations'][0],a,{'issued_at_ns':M},clock=clock(4))
    release={'schema_version':'1',**{k:env[k] for k in ('broker_id','ledger_owner_id','session_id','dispatch_id')},
        'envelope_sha256':c.envelope_digest(env),'prepared_sha256':c.prepared_digest(p),
        'reservation_event_id':reservation['event_id'],'reservation_sequence':reservation['sequence'],
        'reservation_state_sha256':reservation['state_sha256'],'approval_witness_sha256':sha(araw),
        'audit_witness_sha256':sha(draw),'guard_clock':clock(4),'effective_lease_deadline_ns':lease,
        'effect_stop_ns':c.effect_stop(p,lease),'release_sequence':1}
    from unittest.mock import patch
    from test_secure_engagement_live_meter import Stream
    from recon_cockpit.secure_agent import engagement_live_endpoint_worker as endpoint
    from recon_cockpit.secure_agent import engagement_live_protocol as protocol_codec
    with patch.object(c,'sample_clock',lambda:clock(100)),patch.object(endpoint.time,'monotonic_ns',lambda:M+100):
        meter=endpoint.Meter(p,uid(60),session['scope']);meter.arm(release)
        meter.admit();assert meter.receive(Stream([b'']))==b''
        meter.admit();stream=Stream([endpoint.IDENTIFY_REQUEST]);assert meter.receive(stream)==endpoint.IDENTIFY_RESPONSE
        assert meter.send(stream);meter=meter.snapshot()
    observation={'connections':meter['accepted_connections'],'request_bytes':meter['received_request_bytes'],
        'response_bytes':meter['sent_response_bytes'],'client_output_bytes':1,
        'parsed_sha256':'a'*64,'meter_sha256':sha(c.canonical(meter))}
    state,completion=ledger._apply(state,{'schema_version':'2','engagement_id':uid(1),'event_id':uid(103),
        'operation':'complete','expected_revision':None,'expected_generation':None,'body':{'owner_id':uid(3),
        'session_id':uid(4),'dispatch_id':uid(10),'clock':clock(200),'outcome':'reported_success',
        'observation':{**{k:observation[k] for k in ('connections','request_bytes','response_bytes')},
                       'evidence_sha256':sha(c.canonical(observation))}}})
    wrap=lambda receipt:{'schema_version':'2','kind':'data_only','disposition':'recorded','receipt':receipt}
    result={'schema_version':'1',**{k:env[k] for k in ('broker_id','session_id','dispatch_id','slot')},
        'envelope_sha256':c.envelope_digest(env),'outcome':'useful','reason':None,'admission':wrap(reservation),
        'release':{'release_sha256':sha(c.canonical(release)),'attempted_at_ns':M+4,'send_status':'sent',
                   'effective_lease_deadline_ns':lease,'effect_stop_ns':release['effect_stop_ns']},
        'completion':wrap(completion),'observation':observation,'client_result_sha256':'c'*64,'cleanup_sha256':'d'*64}
    c.validate_live_result(result)
    rows=[]
    def row(kind,data,at,*,source='broker_memfd',observer=uid(2),dispatch=uid(10)):
        segment=0 if source=='broker_memfd' else 1
        sequence=sum(r['segment']==segment for r in rows)+1
        value={'schema_version':'1','broker_id':uid(2),'session_id':uid(4) if dispatch else None,
            'dispatch_id':dispatch,'observer_id':observer,'row_sequence':sequence,'observed_at_ns':at,'kind':kind,'data':deepcopy(data)}
        w.validate_transcript_row(value);rows.append({'segment':segment,'source':source,'row':value})
    def protocol(operation,body,channel,role,at,*,dispatch=uid(10),direction=None):
        direction=direction or ('received' if role=='lifecycle' else 'sent')
        sequence=1+sum(r['row']['kind']=='protocol' and r['row']['data']['frame']['channel_id']==channel and
                       r['row']['data']['direction']==direction for r in rows)
        row('protocol',{'channel_role':role,'direction':direction,
            'frame':{'schema_version':'1','channel_id':channel,'sequence':sequence,'operation':operation,'body':body}},at,dispatch=dispatch)
    permit=protocol_codec.permit_projection({'schema_version':'1','admission_id':uid(61),
        'session_id':uid(4),'dispatch_id':uid(10),'reference':'1'*64,'prepared_sha256':c.prepared_digest(p),
        'envelope_sha256':c.envelope_digest(env),'action_sha256':env['action_sha256'],
        'policy_sha256':env['policy_sha256'],'runtime_sha256':env['runtime_sha256'],
        'issued_at_ns':M,'expires_at_ns':env['action_deadline_ns']})
    def admission(operation,request,reply,sequence,at):
        projection={'role':'admission','channel_id':uid(61),'operation':operation,'request_sequence':sequence,
            'request':request,'reply':reply,'request_projection_sha256':sha(c.canonical(request)),
            'reply_projection_sha256':sha(c.canonical(reply)),'original_request_bytes':None,
            'original_request_sha256':None,'original_reply_bytes':None,'original_reply_sha256':None}
        protocol('OBSERVATION',{'dispatch_id':uid(10),'kind':'capability_projection','data':projection},
                 uid(92),'launcher',at,direction='received')
    protocol('AUDIT_OBSERVED',audit_ready(),uid(91),'lifecycle',M,dispatch=None)
    admission('ISSUE',p,permit,1,M)
    row('approval_witness',approval_observation,M+1);row('audit_witness',audit_observation,M+2)
    protocol('DISPATCH',{'prepared_sha256':c.prepared_digest(p),'reference_sha256':a['reference_sha256'],
        'consume_sequence':a['consume_sequence'],'audit_sequence':1},uid(96),'ingress',M+3,
        dispatch=None,direction='received')
    protocol('DISPATCH',{'request_sequence':1,'status':'pending','code':None,
        'data':{'dispatch_id':uid(10)}},uid(96),'ingress',M+3)
    protocol('GO',release,uid(92),'launcher',M+4)
    admission('REDEEM',{'prepared_sha256':c.prepared_digest(p),'reference_sha256':permit['reference_sha256'],'release':release},
        {'schema_version':'1','admission_id':uid(61),'session_id':uid(4),'dispatch_id':uid(10),
         'permit_sha256':sha(c.canonical(permit)),'release_sha256':sha(c.canonical(release)),
         'prepared_sha256':c.prepared_digest(p),'redeemed_at_ns':M+5,'status':'redeemed'},2,M+5)
    protocol('METER',meter,uid(60),'endpoint',M+101,direction='received')
    protocol('METER',meter,uid(92),'launcher',M+102)
    protocol('DISPATCH',{'request_sequence':1,'status':'ok','code':None,'data':result},uid(96),'ingress',M+201)
    for sequence,operation,request,reply,at in [
        (1,'REVIEW',{'prepared':p},{'reference_sha256':a['reference_sha256']},M),
        (2,'CONSUME',{'prepared':p,'reference_sha256':a['reference_sha256']},
          {'accepted':True,'consume_sequence':1,'reference_sha256':a['reference_sha256'],'witness_sha256':sha(araw)},M+1)]:
        row('capability_projection',{'role':'terminal','channel_id':uid(5),'operation':operation,
            'request_sequence':sequence,'request':request,'reply':reply,
            'request_projection_sha256':sha(c.canonical(request)),'reply_projection_sha256':sha(c.canonical(reply)),
            'original_request_bytes':None,'original_request_sha256':None,'original_reply_bytes':None,'original_reply_sha256':None},
            at,source='role_observer',observer=uid(5))
    audit_wrapper={**event,'event_schema_version':'1','event_id':uid(93),'timestamp':'2026-10-21T00:00:00Z','source':'recon-cockpit.secure-agent'}
    loaded={'initial-ledger.json':initial,'final-ledger.json':state,
        'audit.jsonl':legacy.encode(audit_wrapper)+b'\n','results.json':{'operations':[{
            'session':session,'prepared':p,'result':result,'client':None,'meter':meter,
            'elapsed_ms':dict.fromkeys(('review','admission','native','parser','cleanup','action'))}]}}
    return loaded,rows


def test_approval_witness_binds_complete_current_envelope(monkeypatch):
    p=prepared();value=approval(p)
    with direct(monkeypatch) as (reader,writer,_):
        writer.send(c.canonical(value));raw,received=reader.poll()
        assert reader.approval(raw,p,received_at_ns=M+1)==value
        assert reader.sequence==1
        refused(reader.approval,raw,p,received_at_ns=M+2)
    for field in ('reviewer_id','broker_id','ledger_owner_id','session_id','dispatch_id'):
        bad=deepcopy(value);bad[field]=uid(99);refused(w.validate_approval_witness,bad,p)
    for field in ('envelope_sha256','action_sha256','policy_sha256'):
        bad=deepcopy(value);bad[field]='e'*64;refused(w.validate_approval_witness,bad,p)
    for field,change in [('schema_version','2'),('accepted',False),('consume_sequence',True),
                         ('reference_sha256','bad'),('issued_at_ns',M-1),('expires_at_ns',M+31*c.SECOND)]:
        bad=deepcopy(value);bad[field]=change;refused(w.validate_approval_witness,bad,p)
    loaded,rows=complete_authority_fixture()
    assert not w.validate_evidence_transcript(loaded,rows,deadline=time.monotonic()+15)['missing_evidence']
    # A syntactically valid replacement reference still cannot match the actual
    # REVIEW/CONSUME and direct witness commitments retained for this dispatch.
    bad=deepcopy(rows);entry=next(r for r in bad if r['row']['kind']=='approval_witness')['row']['data']
    entry['witness']['reference_sha256']='e'*64;raw=c.canonical(entry['witness'])
    entry['raw_base64']=base64.b64encode(raw).decode();entry['raw_sha256']=sha(raw)
    refused(w.validate_evidence_transcript,loaded,bad,deadline=time.monotonic()+15)


def test_copied_or_wrong_endpoint_witness_refuses(monkeypatch):
    with direct(monkeypatch) as (reader,writer,identity):
        alien,peer=socket.socketpair();alien.setblocking(False);peer.setblocking(False)
        alien.shutdown(socket.SHUT_WR);peer.shutdown(socket.SHUT_RD)
        try:
            with pytest.raises(ValueError):w.DirectReader(alien.detach(),identity,kind='approval')
            writer.send(c.canonical(approval()));raw,_=reader.poll()
            assert reader.approval(raw,prepared(),received_at_ns=M+1)['accepted'] is True
        finally:alien.close();peer.close()
    with pytest.raises(ValueError):
        with direct(monkeypatch,halfclosed=False):pass


def test_approval_witness_age_and_original_expiry():
    p=prepared();value=approval(p)
    assert w.validate_approval_witness(value,p,now_ns=M+10*c.SECOND)==value
    for when in (M-1,M+10*c.SECOND+1,M+30*c.SECOND):
        refused(w.validate_approval_witness,value,p,now_ns=when,code='stale_witness')
    value['expires_at_ns']=M+2*c.SECOND
    assert w.validate_approval_witness(value,p,now_ns=M+2*c.SECOND-1)==value
    refused(w.validate_approval_witness,value,p,now_ns=M+2*c.SECOND,code='stale_witness')
    assert value['expires_at_ns']==M+2*c.SECOND


def test_audit_full_producer_event_digest_is_required():
    p=prepared();raw,source=audit(p)
    assert w.validate_audit_witness(raw,p,source=source,sequence=1,now_ns=M+1)['event_sha256']==sha(legacy.event_bytes(w.started_event(p)))
    value=legacy.decode(raw);event=w.started_event(p);event['engagement_live']['generation']+=1
    assert old_witness.claims(event)==value['intent']
    value['event_digest']=sha(legacy.event_bytes(event))
    refused(w.validate_audit_witness,legacy.encode(value),p,source=source,sequence=1,now_ns=M+1)
    loaded,rows=complete_authority_fixture()
    assert not w.validate_evidence_transcript(loaded,rows,deadline=time.monotonic()+15)['missing_evidence']
    # Useful results need both actual admission exchanges and the exact direct
    # final meter followed by its launcher copy; a hash alone is insufficient.
    for omitted in ('OBSERVATION','METER'):
        changed=resequence([r for r in rows if not (r['row']['kind']=='protocol' and
            r['row']['data']['frame']['operation']==omitted)])
        result=w.validate_evidence_transcript(loaded,changed,deadline=time.monotonic()+15)
        assert result['missing_evidence']==['transcript']
    changed=deepcopy(rows)
    forward=next(r for r in changed if r['row']['kind']=='protocol' and r['row']['data']['channel_role']=='launcher' and
                 r['row']['data']['frame']['operation']=='METER')
    forward['row']['data']['frame']['body']['endpoint_id']=uid(999)
    refused(w.validate_evidence_transcript,loaded,changed,deadline=time.monotonic()+15)
    def terminal(r):
        return (r['row']['kind']=='protocol' and r['row']['data']['channel_role']=='ingress' and
            r['row']['data']['frame']['operation']=='DISPATCH' and r['row']['data']['frame']['body'].get('status')=='ok')
    missing=resequence([r for r in rows if not terminal(r)])
    assert w.validate_evidence_transcript(loaded,missing,deadline=time.monotonic()+15)['missing_evidence']==['transcript']
    changed=deepcopy(rows);ack=next(r for r in changed if terminal(r))
    ack['row']['data']['frame']['body']['data']['observation']['request_bytes']+=1
    refused(w.validate_evidence_transcript,loaded,changed,deadline=time.monotonic()+15)
    lost=deepcopy(loaded);lost['results.json']['operations'][0]['result']=None
    result=w.validate_evidence_transcript(lost,rows,deadline=time.monotonic()+15)
    assert result['linkage']['dispatches'][uid(10)]['result'] is None and 'unsettled_dispatch' in result['missing_evidence']


def test_audit_wrapper_and_producer_are_distinct():
    p=prepared();event=w.started_event(p)
    wrapper={**event,'event_schema_version':'1','event_id':uid(92),'timestamp':'2026-10-21T00:00:00Z','source':'recon-cockpit.secure-agent'}
    assert w._audit_events(legacy.encode(wrapper)+b'\n')=={sha(legacy.event_bytes(event)):event}
    for field in legacy.RESERVED:
        bad=dict(wrapper);del bad[field];refused(w._audit_events,legacy.encode(bad)+b'\n')
    raw,source=audit(p);value=legacy.decode(raw);value['event_digest']=sha(legacy.encode(wrapper))
    refused(w.validate_audit_witness,legacy.encode(value),p,source=source,sequence=1,now_ns=M+1)


def test_audit_raw_float_witness_is_not_normalized():
    p=prepared();raw,source=audit(p,issued=1000.125)
    result=w.validate_audit_witness(raw,p,source=source,sequence=1,now_ns=M+125000000)
    assert result['issued_at_ns']==M+125000000 and result['raw_sha256']==sha(raw)
    alternate=raw.replace(b'1000.125',b'1000.1250')
    assert legacy.decode(alternate)==legacy.decode(raw) and sha(alternate)!=sha(raw)
    refused(w.validate_audit_witness,alternate,p,source=source,sequence=1,now_ns=M+125000000)
    for value in (float('nan'),float('inf'),True):
        packet=legacy.decode(raw);packet['issued_at']=value
        with pytest.raises((ValueError,c.LiveError)):
            w._audit_decode(legacy.encode(packet))


def test_audit_writer_sequence_and_durability_are_bound(monkeypatch):
    p=prepared();raw,source=audit(p)
    with direct(monkeypatch,kind='audit') as (reader,writer,_):
        writer.send(raw);packet,_=reader.poll()
        assert reader.audit(packet,p,source=source,received_at_ns=M+1)['sequence']==1
        for candidate in (raw,audit(p,sequence=3,audit_sequence=3)[0],audit(p,sequence=2,audit_sequence=1)[0]):
            refused(reader.audit,candidate,p,source=source,received_at_ns=M+2)
        assert reader.sequence==reader.audit_sequence==1
    bad=dict(source);bad['writer_id']=uid(99)
    refused(w.validate_audit_witness,raw,p,source=bad,sequence=1,now_ns=M+1)
    ready=audit_ready();ready['ready']['checks']['file_operations_blocked']=False
    refused(w.validate_audit_readiness,ready)


@contextmanager
def audit_service(monkeypatch,deadline=None):
    """Real nonblocking pipes/channel, inert process double; no worker launch."""
    service=adapter.EngagementAuditService.__new__(adapter.EngagementAuditService)
    service._pid=os.getpid();service.control=ExecutionControl(time.monotonic()+1 if deadline is None else deadline)
    service._lock=threading.Lock();service._stop=threading.Event();service._closed=False
    service.writer_id=uid(90);service._sequence=0;service._buffer=bytearray();service._observations=[]
    service._channel,peer=socket.socketpair();service._channel.setblocking(False);peer.setblocking(False)
    pipes=[];writers=[]
    for _ in range(2):
        read,write=os.pipe();os.set_blocking(read,False);pipes.append(os.fdopen(read,'rb',buffering=0));writers.append(write)
    service._process=SimpleNamespace(stdout=pipes[0],stderr=pipes[1],poll=lambda:None)
    monkeypatch.setattr(service,'_verify_path',lambda:None)
    try:yield service,peer,writers
    finally:
        service._channel.close();peer.close()
        for pipe in pipes:pipe.close()
        for fd in writers:
            try:os.close(fd)
            except OSError:pass


def test_audit_adapter_clips_original_exchange_deadline(monkeypatch):
    event=w.started_event(prepared())
    deadline=time.monotonic()+.06
    with audit_service(monkeypatch,deadline) as (service,peer,writers):
        began=time.monotonic()
        with pytest.raises(Exception):service.emit(event,control=service.control)
        elapsed=time.monotonic()-began
        assert .04<=elapsed<.5 and service._sequence==0 and service._stop.is_set()
        assert service._phase(service.control).deadline<=deadline
        assert peer.recv(32768)
    # Waiting for another caller is part of this same original exchange bound.
    # The holder has a finite release even against the old unbounded-lock code.
    with audit_service(monkeypatch) as (service,peer,writers):
        held=threading.Event();release=threading.Event()
        def hold():
            with service._lock:held.set();release.wait(.65)
        worker=threading.Thread(target=hold);worker.start();assert held.wait(1)
        service.control=ExecutionControl(time.monotonic()+.06)
        began=time.monotonic()
        try:
            with pytest.raises(Exception):service.emit(event,control=service.control)
            elapsed=time.monotonic()-began
            assert .04<=elapsed<.5 and service._sequence==0
            with pytest.raises(BlockingIOError):peer.recv(32768)
        finally:release.set();worker.join(1)
        assert not worker.is_alive()


def test_audit_output_or_witness_failure_is_terminal(monkeypatch):
    p=prepared();event=w.started_event(p)
    for mutation in ('not_durable','missing_durable','wrong_digest','wrong_sequence','partial','closed'):
        with audit_service(monkeypatch) as (service,peer,writers):
            if mutation=='closed':peer.close()
            else:
                reply=legacy.receipt(uid(90),1,legacy.event_bytes(event))
                if mutation=='not_durable':reply['durable']=False
                if mutation=='missing_durable':del reply['durable']
                if mutation=='wrong_digest':reply['event_digest']='e'*64
                if mutation=='wrong_sequence':reply['sequence']=2
                encoded=legacy.encode(reply)+b'\n'
                def respond(control,*,info_fd=None,encoded=encoded):
                    os.write(writers[0],encoded[:-1] if mutation=='partial' else encoded)
                    if mutation=='partial':os.close(writers[0])
                    return adapter.EngagementAuditService._reply(service,control,info_fd=info_fd)
                monkeypatch.setattr(service,'_reply',respond)
            refused(service.emit,event,control=service.control)
            assert service._sequence==0 and not service._observations and service._stop.is_set()
            refused(service.emit,event,control=service.control,code='audit_unavailable')


def test_halfclosed_channels_reject_write_and_rights(monkeypatch):
    with direct(monkeypatch) as (reader,writer,_):
        with pytest.raises(OSError) as caught:reader.channel.send(b'not permitted')
        assert caught.value.errno==errno.EPIPE
        assert writer.recv(1)==b''
        fd=os.open(os.devnull,os.O_RDONLY)
        try:writer.sendmsg([b'x'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        finally:os.close(fd)
        refused(reader.poll,code='invalid_witness');assert reader.closed
    with direct(monkeypatch) as (reader,writer,_):
        writer.send(b'x'*4097);refused(reader.poll,code='invalid_witness');assert reader.closed


def test_proof_consumption_is_unique_across_ingresses(tmp_path,monkeypatch):
    # The broker's single event loop receives two callers; the same direct
    # reader sequence cannot produce two accepted copies of their shared proof.
    p=prepared();value=approval(p);encoded=c.canonical(value);accepted=[]
    with direct(monkeypatch) as (reader,writer,_):
        for ingress in (uid(81),uid(82)):
            writer.send(encoded);packet,_=reader.poll()
            try:accepted.append((ingress,reader.approval(packet,p,received_at_ns=M+1)))
            except c.LiveError:pass
        assert [row[0] for row in accepted]==[uid(81)] and reader.sequence==1
    # Two actual caller channels submit the same proof concurrently. The real
    # broker core serializes their durable reservations; this is a portable
    # transaction/channel check, not an isolated native broker witness.
    from test_secure_engagement_live_broker import lab,ready,proofs
    from recon_cockpit.secure_agent import engagement_live_protocol as protocol
    with lab(tmp_path,monkeypatch) as (core,store,_,launcher,channels):
        dispatch=ready(core);pointers=proofs(core,dispatch,channels)
        pairs=[socket.socketpair() for _ in range(2)]
        barrier=threading.Barrier(3);errors=[];answers=[]
        def submit(index):
            try:
                frame={'schema_version':'1','channel_id':uid(81+index),'sequence':1,
                       'operation':'DISPATCH','body':pointers}
                barrier.wait(timeout=2);pairs[index][1].sendall(c.canonical(frame))
            except Exception as error:errors.append(error)
        workers=[threading.Thread(target=submit,args=(i,)) for i in range(2)]
        try:
            for worker in workers:worker.start()
            barrier.wait(timeout=2)
            for index,pair in enumerate(pairs):
                pair[0].settimeout(2)
                frame=protocol.decode_frame(pair[0].recv(32768),role='ingress',direction='request')
                assert frame['channel_id']==uid(81+index)
                try:core.reserve(frame['body']);core.guarded_go(dispatch)
                except c.LiveError:answers.append(False)
                else:answers.append(True)
            for worker in workers:worker.join(2);assert not worker.is_alive()
            assert not errors and answers==[True,False]
            state=store.snapshot()
            assert len(state['reservations'])==1 and state['state']['usage']==dispatch['prepared']['envelope']['cost']
            assert protocol.decode_frame(launcher[1].recv(32768),role='launcher',direction='request')['operation']=='GO'
            with pytest.raises(BlockingIOError):launcher[1].recv(32768)
        finally:
            for pair in pairs:
                for endpoint in pair:endpoint.close()
            for worker in workers:worker.join(2)
    loaded,rows=complete_authority_fixture()
    replay=w.validate_evidence_transcript(loaded,rows,deadline=time.monotonic()+15)
    assert not replay['missing_evidence'] and replay['linkage']['dispatches'][uid(10)]['reservation_observed'] is True
    duplicate=deepcopy(next(row for row in rows if row['row']['kind']=='approval_witness'))
    refused(w.validate_evidence_transcript,loaded,resequence([*rows[:4],duplicate,*rows[4:]]),deadline=time.monotonic()+15)
    incomplete=deepcopy(rows);projection=next(row for row in incomplete if row['row']['kind']=='capability_projection')
    projection['row']['data']['reply']=None;projection['row']['data']['reply_projection_sha256']=None
    refused(w.validate_evidence_transcript,loaded,incomplete,deadline=time.monotonic()+15)


def test_closed_witness_diagnostics_remain_bounded(monkeypatch):
    with direct(monkeypatch) as (reader,writer,_):
        writer.close();refused(reader.poll,code='invalid_witness');assert reader.closed
        refused(reader.poll,code='invalid_channel')
    for content,stream in ((b'private unexpected diagnostic',1),(b'x'*2049,0),(b'{}\n{}\n',0)):
        with audit_service(monkeypatch) as (service,peer,writers):
            os.write(writers[stream],content)
            refused(service._reply,service._phase(service.control))
            assert len(service._buffer)<=4096 and service._sequence==0
    # A reply left over from an earlier phase is rejected before another event
    # can be sent; it cannot satisfy a later request just because bytes match.
    with audit_service(monkeypatch) as (service,peer,writers):
        os.write(writers[0],legacy.encode(legacy.receipt(uid(90),1,b'old'))+b'\n')
        refused(service.emit,w.started_event(prepared()),control=service.control)
        with pytest.raises(BlockingIOError):peer.recv(1)
    loaded,rows=complete_authority_fixture();meter=loaded['results.json']['operations'][0]['meter']
    position=next(i for i,r in enumerate(rows) if r['row']['kind']=='protocol' and r['row']['data']['frame']['operation']=='METER')
    prefix=[{'segment':0,'source':'broker_memfd','row':{'schema_version':'1','broker_id':uid(2),
        'session_id':uid(4),'dispatch_id':uid(10),'observer_id':uid(2),'row_sequence':1,
        'observed_at_ns':M+100,'kind':'meter','data':deepcopy(event)}} for event in meter['events'][:-1]]
    combined=resequence([*rows[:position],*prefix,*rows[position:]])
    replay=w.validate_evidence_transcript(loaded,combined,deadline=time.monotonic()+15)
    assert replay['linkage']['dispatches'][uid(10)]['meter_prefix']==meter['events'][:-1]
    assert not replay['missing_evidence']
    # Valid row framing cannot hide a deleted event or a contradictory final
    # byte count. A prefix never substitutes for the unique final meter.
    bad=resequence([*rows[:position],*prefix[:2],*prefix[3:],*rows[position:]])
    refused(w.validate_evidence_transcript,loaded,bad,deadline=time.monotonic()+15)
    bad=deepcopy(combined)
    event=next(r['row']['data'] for r in bad if r['row']['kind']=='meter' and r['row']['data']['kind']=='send')
    event['actual_bytes']-=1;event['remaining_after']+=1
    refused(w.validate_evidence_transcript,loaded,bad,deadline=time.monotonic()+15)
