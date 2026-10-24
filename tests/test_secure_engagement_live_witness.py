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


def audit_ready(runtime_bundle=None):
    """Closed declared readiness, not a process/kernel observation."""
    from test_secure_engagement_live_runtime import declared_runtime,declared_readiness
    bundle=declared_runtime() if runtime_bundle is None else runtime_bundle
    parent=declared_readiness(bundle,'parser',pid=901)['parent_observation']
    parent['role']='audit';parent['uid_map'][0][0]=parent['gid_map'][0][0]=0
    parent['sampled_at_ns']=M-1
    library=next(row for row in next(role for role in bundle['roles'] if role['role']=='parser')['native_files']
                 if '/libffi.so.' in row['destination'])
    mapped=next(row for row in parent['mapped_images'] if row['destination']==library['destination'])
    image={**{key:library[key] for key in ('destination','size','sha256')},
           **{key:mapped[key] for key in ('device','inode')},'mode':stat.S_IFREG|0o444,'read_only_mount':True}
    parent['descriptors']=[
        {'fd':0,'purpose':'stdin','kind':'seqpacket','device':10,'inode':40,'mode':stat.S_IFSOCK|0o777,'flags':2050},
        {'fd':1,'purpose':'stdout','kind':'pipe','device':10,'inode':41,'mode':stat.S_IFIFO|0o600,'flags':1},
        {'fd':2,'purpose':'stderr','kind':'pipe','device':10,'inode':42,'mode':stat.S_IFIFO|0o600,'flags':1},
        {'fd':3,'purpose':'audit_import_libffi','kind':'regular','device':image['device'],'inode':image['inode'],'mode':image['mode'],'flags':32768},
        {'fd':4,'purpose':'audit_append','kind':'regular','device':20,'inode':21,'mode':stat.S_IFREG|0o600,'flags':166913},
        {'fd':5,'purpose':'audit_witness','kind':'seqpacket','device':10,'inode':12,'mode':stat.S_IFSOCK|0o777,'flags':2050}]
    result={'schema_version':'1','writer_id':uid(90),
        'initial':{'version':'1','writer_id':uid(90),'device':20,'inode':21,'witness':[10,12]},
        'ready':{'version':'1','writer_id':uid(90),'ready':True,'checks':dict.fromkeys(legacy.CHECKS,True)},
        'source_manifest':{'version':'1','writer_id':uid(90),'device':10,'inode':11},
        'append_identity':{'device':20,'inode':21,'mode':stat.S_IFREG|0o600,'uid':1000,'gid':1000,'links':1,'size':0},
        'parent_observation':parent,'import_image':image}
    return w.validate_audit_runtime_binding(result,bundle)


def resequence(rows):
    """Keep the segment framing valid while testing deeper proof omissions."""
    rows=deepcopy(rows);sequences={}
    for wrapped in rows:
        segment=wrapped['segment'];sequences[segment]=sequences.get(segment,0)+1
        wrapped['row']['row_sequence']=sequences[segment]
    return rows


def complete_authority_fixture(*,runtime_sha256=None,runtime_bundle=None):
    """Real pure v2 history and declared protocol data; no native authority.

    The independently encoded producer/witness/projections all bind the same
    exact Prepared. Callers must add actual-shaped client/runtime/cleanup data
    before asking the full bundle context to validate a useful result.
    """
    from test_secure_engagement_live_runtime import declared_runtime,declared_readiness
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    bundle=declared_runtime() if runtime_bundle is None else runtime_bundle
    digest=runtime.runtime_digest(bundle)
    if runtime_sha256 is not None:assert runtime_sha256==digest
    session=opened();session['binding']['runtime_sha256']=digest
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
    audit_readiness=audit_ready(bundle)
    protocol('AUDIT_OBSERVED',audit_readiness,uid(2),'lifecycle',M,dispatch=None)
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
    broker=declared_readiness(bundle,'broker',pid=200,worker_id=uid(2))
    reader=next(row for row in broker['parent_observation']['descriptors'] if row['purpose']=='audit_witness')
    reader.update(device=10,inode=11,mode=stat.S_IFSOCK|0o777,flags=2050)
    broker['worker_ready']['descriptor_sha256']=sha(c.canonical(broker['parent_observation']['descriptors']))
    loaded={'initial-ledger.json':initial,'final-ledger.json':state,
        'manifest.json':{'broker_instances':[{'broker_id':uid(2)}]},
        'runtime.json':{'schema_version':'1','runtime':bundle,'instrumentation':[]},
        'processes.json':{'schema_version':'1','startup':[],'readiness':[broker],'native':[],'boundary_observations':[]},
        'audit.jsonl':legacy.encode(audit_wrapper)+b'\n','results.json':{'operations':[{
            'session':session,'prepared':p,'result':result,'client':None,'meter':meter,
            'elapsed_ms':dict.fromkeys(('review','admission','native','parser','cleanup','action'))}]}}
    from test_secure_engagement_live_evidence import attach_supervision_fixture
    loaded, rows = attach_supervision_fixture(loaded, rows)
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
    # A07: an audit self-report is useful only through its actual broker reader
    # custody, runtime image and received lifecycle observation.
    def audit_row(items):
        return next(item for item in items if item['row']['kind']=='protocol' and
                    item['row']['data']['frame']['operation']=='AUDIT_OBSERVED')
    for change in ('host_projection','sent','observer','channel','session','duplicate','reader'):
        bad=deepcopy(rows);entry=audit_row(bad)
        if change=='host_projection':entry['source']='role_observer'
        elif change=='sent':entry['row']['data']['direction']='sent'
        elif change=='observer':entry['row']['observer_id']=uid(999)
        elif change=='channel':entry['row']['data']['frame']['channel_id']=uid(999)
        elif change=='session':entry['row']['session_id']=uid(4)
        elif change=='duplicate':bad.insert(1,deepcopy(entry))
        else:entry['row']['data']['frame']['body']['source_manifest']['inode']+=1
        refused(w.validate_evidence_transcript,loaded,resequence(bad),deadline=time.monotonic()+15)
    absent=deepcopy(loaded);absent['processes.json']['readiness']=[row for row in absent['processes.json']['readiness'] if row['role']!='broker']
    assert w.validate_evidence_transcript(absent,rows,deadline=time.monotonic()+15)['missing_evidence']==['process_identity']
    bad=deepcopy(rows);audit_row(bad)['row']['data']['frame']['body']['import_image']['sha256']='f'*64
    refused(w.validate_evidence_transcript,loaded,bad,deadline=time.monotonic()+15)
    # Context callers parse the same exact segment bytes, never concatenating
    # an unfinished broker row with the following observer segment.
    encoded=deepcopy(loaded);segments=[];parts=[]
    for index,source in enumerate(('broker_memfd','role_observer')):
        part=b''.join(c.canonical(item['row'])+b'\n' for item in rows if item['segment']==index)
        if index==0:part+=b'{"unfinished":'
        segments.append({'source':source,'broker_id':uid(2) if index==0 else None,
            'offset':sum(map(len,parts)),'bytes':len(part),'sha256':sha(part),'seals':0 if index==0 else None,
            'status':'reaped_partial' if index==0 else 'observer_complete'})
        parts.append(part)
    encoded['manifest.json']['transcript']={'segments':segments}
    encoded['transcript.jsonl']=b''.join(parts)
    extracted=w._retained_audit_readiness(encoded)
    assert not extracted['missing_evidence'] and len(extracted['observations'])==1
    encoded['manifest.json']['transcript']['segments'][0]['sha256']='f'*64
    refused(w._retained_audit_readiness,encoded)


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
    from test_secure_engagement_live_runtime import declared_runtime
    bundle=declared_runtime();valid=audit_ready(bundle)
    for change in ('missing','extra','duplicate','purpose','append_identity','append_mode','append_access',
                   'append_flag','witness_identity','witness_type','witness_blocking','writer_as_reader',
                   'import_mode','import_access','import_path_access','import_mount','import_map','import_size','import_hash'):
        bad=deepcopy(valid);descriptors=bad['parent_observation']['descriptors']
        named={row['purpose']:row for row in descriptors}
        if change=='missing':descriptors.pop()
        elif change=='extra':descriptors.append({**descriptors[-1],'fd':6,'purpose':'unknown'})
        elif change=='duplicate':descriptors[-1]['fd']=4
        elif change=='purpose':named['audit_append']['purpose']='unknown'
        elif change=='append_identity':bad['initial']['inode']+=1
        elif change=='append_mode':named['audit_append']['mode']=stat.S_IFREG|0o644
        elif change=='append_access':named['audit_append']['flags']|=2
        elif change=='append_flag':named['audit_append']['flags']&=~0x400
        elif change=='witness_identity':bad['initial']['witness'][1]+=1
        elif change=='witness_type':named['audit_witness']['kind']='stream_socket'
        elif change=='witness_blocking':named['audit_witness']['flags']&=~0x800
        elif change=='writer_as_reader':bad['source_manifest'].update(device=10,inode=12)
        elif change=='import_mode':bad['import_image']['mode']=named['audit_import_libffi']['mode']=stat.S_IFREG|0o644
        elif change=='import_access':named['audit_import_libffi']['flags']|=2
        elif change=='import_path_access':named['audit_import_libffi']['flags']|=0x200000
        elif change=='import_mount':bad['import_image']['read_only_mount']=False
        elif change=='import_map':next(row for row in bad['parent_observation']['mapped_images'] if '/libffi.so.' in row['destination'])['inode']+=1
        elif change=='import_size':bad['import_image']['size']+=1
        else:bad['import_image']['sha256']='e'*64
        refused(w.validate_audit_runtime_binding,bad,bundle)
    coherent=deepcopy(valid);coherent['import_image']['sha256']='e'*64
    assert w.validate_audit_readiness(coherent)==coherent
    refused(w.validate_audit_runtime_binding,coherent,bundle)
    # Exercise the actual broker handler's mandatory context check with a real
    # held reader identity and a modeled transport, without a worker/native run.
    from recon_cockpit.secure_agent import engagement_live_broker_worker as worker
    from recon_cockpit.secure_agent import engagement_live_protocol as protocol
    left,right=socket.socketpair()
    try:
        held=os.fstat(left.fileno())
        def handle(value):
            loop=worker.BrokerLoop.__new__(worker.BrokerLoop)
            loop.core=SimpleNamespace(broker_id=uid(2),runtime=bundle,audit_ready=None,
                                      deadline_ns=time.monotonic_ns()+2*c.SECOND)
            loop.lifecycle=object();loop.lifecycle_sequence=protocol.ChannelSequence(uid(2),'lifecycle')
            loop.audit_reader=SimpleNamespace(channel=left);loop.transcript=lambda *args:None
            frame={'schema_version':'1','channel_id':uid(2),'sequence':1,'operation':'AUDIT_OBSERVED','body':value}
            with monkeypatch.context() as patch:
                patch.setattr(protocol,'receive_packet',lambda *args,**kwargs:deepcopy(frame))
                loop.lifecycle_request()
            return loop.core
        valid['source_manifest'].update(device=held.st_dev,inode=held.st_ino)
        assert handle(valid).audit_ready==valid
        coherent=deepcopy(valid);coherent['import_image']['sha256']='e'*64
        refused(handle,coherent)
        # One actual handler phase covers the received frame and nested codec.
        # Expiry during validation must precede any stored audit authority.
        now=[100.0];seen=[]
        loop=worker.BrokerLoop.__new__(worker.BrokerLoop)
        loop.core=SimpleNamespace(broker_id=uid(2),runtime=bundle,audit_ready=None,
                                  deadline_ns=101*c.SECOND)
        loop.lifecycle=object();loop.lifecycle_sequence=protocol.ChannelSequence(uid(2),'lifecycle')
        loop.audit_reader=SimpleNamespace(channel=left)
        loop.transcript=lambda *args:seen.append(('transcript',c._operation_deadline()))
        frame={'schema_version':'1','channel_id':uid(2),'sequence':1,'operation':'AUDIT_OBSERVED','body':valid}
        def receive(*args,control,**kwargs):
            seen.append(('receive',control.deadline,c._operation_deadline()))
            now[0]=100.5
            return deepcopy(frame)
        def expired_binding(value,runtime_bundle):
            seen.append(('validation',c._operation_deadline()))
            now[0]=101.01
            return value
        with monkeypatch.context() as patch:
            patch.setattr(time,'monotonic',lambda:now[0])
            patch.setattr(time,'monotonic_ns',lambda:int(now[0]*c.SECOND))
            patch.setattr(protocol,'receive_packet',receive)
            patch.setattr(w,'validate_audit_runtime_binding',expired_binding)
            refused(loop.lifecycle_request,code='timeout')
            assert c._operation_deadline()==now[0]+2
        assert loop.core.audit_ready is None and not hasattr(loop.core,'audit_source')
        assert seen==[('receive',101.0,101.0),('transcript',101.0),('validation',101.0)]

    finally:left.close();right.close()


@contextmanager
def audit_service(monkeypatch,deadline=None):
    """Real nonblocking pipes/channel, inert process double; no worker launch."""
    service=adapter.EngagementAuditService.__new__(adapter.EngagementAuditService)
    service._pid=os.getpid();service.control=ExecutionControl(time.monotonic()+1 if deadline is None else deadline)
    service._cleanup_epoch=None
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


def test_audit_adapter_clips_original_exchange_deadline(monkeypatch,tmp_path):
    from recon_cockpit.secure_agent.engagement_live_session import _CleanupEpoch
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    now=[100.0]
    with monkeypatch.context() as patch:
        patch.setattr(time,'monotonic',lambda:now[0])
        patch.setattr(time,'monotonic_ns',lambda:int(now[0]*c.SECOND))
        with audit_service(patch) as (service,peer,writers):
            service.control=ExecutionControl(200.0,clock=time.monotonic)
            service._cleanup_epoch=_CleanupEpoch(service.control)
            service._pin=service._parent=service._cleanup=None
            phase=service._phase(service.control);phase.check()
            assert service._cleanup_epoch.snapshot() is None
            service._cleanup_epoch.stop();now[0]=100.5
            deadlines=[];receipt={'status':'complete'}
            def cleanup(processes,pins,*,deadline):deadlines.append(deadline);return receipt
            patch.setattr(runtime,'cleanup_owned',cleanup)
            assert service._close(150.0) is receipt and deadlines==[102.0]
            now[0]=101.0
            assert service.close() is receipt and deadlines==[102.0]
        # A temporary close failure after successful startup fixes the epoch at
        # that failure, still closes later resources, and reaps the real owner.
        with audit_service(patch) as (service,peer,writers):
            service.control=ExecutionControl(200.0,clock=time.monotonic)
            service._cleanup_epoch=_CleanupEpoch(service.control)
            service._pin=service._parent=service._cleanup=None
            calls=[];deadlines.clear()
            first=OSError('temporary close failed')
            def broken():calls.append('first');raise first
            def later():
                assert service._cleanup_epoch.stopped
                calls.append('later');now[0]+=.5
            with pytest.raises(c.LiveError) as caught:
                service._release_startup_resources((SimpleNamespace(close=broken),SimpleNamespace(close=later)),(),None)
            assert calls==['first','later'] and deadlines==[103.0]
            assert caught.value.resource_cleanup_error is first and caught.value.process_cleanup is receipt
            assert caught.value.startup_cleanup['status']=='failed' and not caught.value.startup_cleanup['descriptors_closed']
        # A channel close error cannot skip process reap or become cached success.
        with audit_service(patch) as (service,peer,writers):
            service.control=ExecutionControl(200.0,clock=time.monotonic)
            service._cleanup_epoch=_CleanupEpoch(service.control)
            service._pin=service._parent=service._cleanup=None
            channel=service._channel;deadlines.clear();first=OSError('channel close failed')
            def broken_channel():raise first
            service._channel=SimpleNamespace(shutdown=lambda how:None,close=broken_channel)
            try:
                with pytest.raises(c.LiveError) as caught:service._close(150.0)
                assert deadlines==[103.5] and caught.value.process_cleanup is receipt
                assert caught.value.cleanup['status']=='failed' and not caught.value.cleanup['descriptors_closed']
                assert caught.value.resource_cleanup_error is first
                with pytest.raises(c.LiveError) as again:service._close(170.0)
                assert again.value is caught.value and deadlines==[103.5]
            finally:service._channel=channel
        # A late-only reap failure retains its real closed-descriptor fact;
        # it must not be rewritten as a channel or parent-close failure.
        with audit_service(patch) as (service,peer,writers):
            service.control=ExecutionControl(200.0,clock=time.monotonic)
            service._cleanup_epoch=_CleanupEpoch(service.control)
            service._pin=service._parent=service._cleanup=None
            late={'status':'failed','descriptors_closed':True}
            original=c.LiveError('engagement_live_cleanup_incomplete');original.cleanup=late
            def late_reap(processes,pins,*,deadline):raise original
            patch.setattr(runtime,'cleanup_owned',late_reap)
            with pytest.raises(c.LiveError) as caught:service._close(150.0)
            assert caught.value.cleanup is late and service._cleanup is late
            assert caught.value.cleanup_error is original and not hasattr(caught.value,'resource_cleanup_error')
            with pytest.raises(c.LiveError) as again:service._close(170.0)
            assert again.value is caught.value and again.value.cleanup['descriptors_closed']
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

    # Model only process/bootstrap transport; real private file custody remains.
    # Each late phase sees the same startup deadline, including the final copy.
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    from recon_cockpit.secure_agent import engagement_live_protocol as protocol
    from recon_cockpit.secure_agent import audit as audit_module
    from test_secure_engagement_live_runtime import declared_runtime
    real_sink=audit_module.AuditSink
    bundle=declared_runtime()
    for expires_at in ('observer','binding','copy'):
        now=[100.0];seen=[];cleanup=[]
        with monkeypatch.context() as patch:
            patch.setattr(time,'monotonic',lambda:now[0])
            patch.setattr(time,'monotonic_ns',lambda:int(now[0]*c.SECOND))
            channel=SimpleNamespace(setblocking=lambda value:None,close=lambda:None,
                                    sendmsg=lambda buffers,*args:len(buffers[0]))
            writer_fd=os.open(os.devnull,os.O_RDONLY)
            stdout=open(os.devnull,'rb');stderr=open(os.devnull,'rb');service=None
            try:
                writer=SimpleNamespace(fileno=lambda:writer_fd,close=lambda:None)
                role_bundle=SimpleNamespace(take_audit_writer=lambda:writer,audit_source_identity=(10,11))
                service=adapter.EngagementAuditService(tmp_path/expires_at/'audit.jsonl',runtime=bundle,
                    role_bundle=role_bundle,control=ExecutionControl(101.0,clock=time.monotonic))
                snapshot=SimpleNamespace(stdlib='/unused',pass_fds=(),mounts=lambda argv:None,close=lambda:None)
                patch.setattr(runtime,'_snapshot_audit',lambda *args:snapshot)
                patch.setattr(runtime,'_observer',lambda:{'namespaces':dict.fromkeys(('user','net','mnt','pid'),'declared')})
                patch.setattr(socket,'SOCK_SEQPACKET',getattr(socket,'SOCK_SEQPACKET',5),raising=False)
                patch.setattr(socket,'socketpair',lambda *args:(channel,channel))
                def held_sink(path):
                    # Translate only Linux procfs spelling in this modeled
                    # startup; retain the actual held private-parent identity.
                    assert str(path)==f'/proc/self/fd/{service._parent}/audit.jsonl'
                    held=os.fstat(service._parent);actual=service.path.parent.stat()
                    assert (held.st_dev,held.st_ino)==(actual.st_dev,actual.st_ino)
                    return real_sink(service.path)
                patch.setattr(audit_module,'AuditSink',held_sink)
                patch.setattr(os,'pipe2',lambda flags:os.pipe(),raising=False)
                patch.setattr(adapter.subprocess,'Popen',lambda *args,**kwargs:SimpleNamespace(stdout=stdout,stderr=stderr))
                patch.setattr(protocol,'_ready',lambda *args,**kwargs:None)
                def reply(*args,**kwargs):
                    now[0]=100.5
                    return {'version':'1','writer_id':service.writer_id,'ready':True,
                            'checks':dict.fromkeys(legacy.CHECKS,True)},b'{}'
                patch.setattr(service,'_reply',reply)
                patch.setattr(service,'_close',lambda deadline:cleanup.append(deadline))
                def check_phase(name):
                    seen.append((name,c._operation_deadline()))
                    if name==expires_at:now[0]=101.01
                    c._check_deadline(c._operation_deadline())
                def observe(**kwargs):
                    assert kwargs['control'].deadline==101.0
                    check_phase('observer')
                    return SimpleNamespace(receipt={},import_image={})
                def binding(*args):check_phase('binding')
                def copy(value):check_phase('copy');return value
                patch.setattr(runtime,'_observe_legacy_audit',observe)
                patch.setattr(w,'validate_audit_runtime_binding',binding)
                patch.setattr(c,'detached',copy)
                refused(service.start,code='timeout')
                assert cleanup==[101.0] and c._operation_deadline()==now[0]+2
                assert seen==[(name,101.0) for name in ('observer','binding','copy')[:('observer','binding','copy').index(expires_at)+1]]
            finally:
                stdout.close();stderr.close();os.close(writer_fd)
                if service is not None and service._parent is not None:os.close(service._parent)


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


def _host_ingress_replay_cases():
    """A partial host observation is a mirror, not a second broker sequence."""
    loaded,rows=complete_authority_fixture()
    host=[]
    for wrapped in rows:
        row=wrapped['row']
        if wrapped['source']!='broker_memfd' or row['kind']!='protocol':continue
        data=row['data'];frame=data['frame']
        if data['channel_role']!='ingress' or frame['operation']!='DISPATCH':continue
        if data['direction']=='sent' and frame['body']['status']=='pending':continue
        copied=deepcopy(wrapped);copied.update(segment=1,source='role_observer')
        copied['row'].update(dispatch_id=uid(10),session_id=uid(4))
        copied['row']['data']['direction']='sent' if data['direction']=='received' else 'received'
        host.append(copied)
    assert len(host)==2 and host[1]['row']['data']['frame']['sequence']==2
    combined=resequence([*rows,*host])
    assert not w.validate_evidence_transcript(loaded,combined,deadline=time.monotonic()+15)['missing_evidence']
    for variant in ('duplicate','changed_request','changed_reply','unknown_channel','wrong_observer',
                    'wrong_direction','missing_request','reply_before_request','broker_duplicate','broker_gap'):
        altered=deepcopy(combined)
        mirror=[x for x in altered if x['source']=='role_observer' and x['row']['kind']=='protocol']
        request,reply=mirror
        if variant=='duplicate':altered.append(deepcopy(request))
        elif variant=='changed_request':request['row']['data']['frame']['body']['reference_sha256']='e'*64
        elif variant=='changed_reply':reply['row']['data']['frame']['body']['data']['reason']='engagement_live_revoked'
        elif variant=='unknown_channel':
            for item in mirror:item['row']['data']['frame']['channel_id']=uid(1985)
        elif variant=='wrong_observer':request['row']['observer_id']=uid(1985)
        elif variant=='wrong_direction':request['row']['data']['direction']='received'
        elif variant=='missing_request':altered.remove(request)
        elif variant=='reply_before_request':reply['row']['observed_at_ns']=request['row']['observed_at_ns']-1
        else:
            actual=next(x for x in altered if x['source']=='broker_memfd' and x['row']['kind']=='protocol' and
                x['row']['data']['channel_role']=='ingress' and x['row']['data']['direction']=='received')
            if variant=='broker_duplicate':altered.append(deepcopy(actual))
            else:actual['row']['data']['frame']['sequence']+=1
        altered=resequence(altered)
        if variant in ('unknown_channel','missing_request'):
            assert 'transcript' in w.validate_evidence_transcript(loaded,altered,deadline=time.monotonic()+15)['missing_evidence']
        else:refused(w.validate_evidence_transcript,loaded,altered,deadline=time.monotonic()+15)


def test_proof_consumption_is_unique_across_ingresses(tmp_path,monkeypatch):
    _host_ingress_replay_cases()
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
