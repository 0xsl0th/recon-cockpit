"""Single isolated durable owner and role-bound dispatch coordinator."""
import errno
import os
import stat
import sys


def _entry_only_stdio():
    for name in os.listdir('/proc/self/fd'):
        fd=int(name)
        if fd<=2:continue
        try:os.fstat(fd)
        except OSError as error:
            if error.errno==errno.EBADF:continue
            raise
        raise ValueError('engagement_live_inherited_descriptor')
    if any(not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd) for fd in (1,2)):
        raise ValueError('engagement_live_invalid_output')


if __name__=='__main__':
    try:_entry_only_stdio()
    except Exception:
        os.write(2,b'engagement_live_broker_refused\n');raise SystemExit(78) from None
    sys.path.insert(0,'/app');__package__='recon_cockpit.secure_agent'

import base64
import fcntl
import socket
import time
from contextlib import contextmanager
from uuid import uuid4

from . import engagement_live_contract as c
from . import engagement_live_protocol as p
from . import engagement_live_witness as w
from . import engagement_dispatch_contract as ledger
from .engagement_dispatch_store import DispatchLedger


def _mapped(error):
    if isinstance(error,c.LiveError):return error.code
    if isinstance(error,ledger.DispatchLedgerError):
        code=error.code.removeprefix('engagement_dispatch_')
        return 'engagement_live_'+{'revoked':'revoked','conflict':'revision_changed',
            'window_not_open':'window_not_open','window_closed':'window_closed','clock_changed':'clock_changed',
            'allowance_exhausted':'allowance_exhausted','prerequisite_missing':'prerequisite_missing',
            'timeout':'timeout','limit_exceeded':'limit_exceeded','foreign_owner':'foreign_owner'}.get(code,'unavailable')
    return 'engagement_live_unavailable'


class Transcript:
    def __init__(self,fd,*,broker_id):
        self.fd=fd;self.broker_id=c.uuid(broker_id);self.sequence=0;self.bytes=0;self.sealed=False
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size or fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDWR or fcntl.fcntl(fd,fcntl.F_GET_SEALS):c.fail('invalid_channel')
    def reserve(self,amount=32768,*,terminal=False):
        cap=2097152 if terminal else 2097152-8192
        rows=4096 if terminal else 4096-8
        if self.sealed or self.sequence>=rows or self.bytes+amount>cap:c.fail('limit_exceeded')
    def record(self,kind,data,*,session_id=None,dispatch_id=None,terminal=False,at=None):
        row={'schema_version':'1','broker_id':self.broker_id,'observer_id':self.broker_id,
            'row_sequence':self.sequence+1,'observed_at_ns':time.monotonic_ns() if at is None else at,
            'session_id':session_id,'dispatch_id':dispatch_id,'kind':kind,'data':data}
        w.validate_transcript_row(row);raw=c.canonical(row)+b'\n';self.reserve(len(raw),terminal=terminal)
        # Evidence capacity is checked before the caller can perform an effect.
        offset=0
        while offset<len(raw):
            count=os.write(self.fd,raw[offset:])
            if count<=0:c.fail('unavailable')
            offset+=count
        self.bytes+=len(raw);self.sequence+=1
        return row
    def seal(self):
        if not self.sealed:
            fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,15);self.sealed=True
        if fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)!=15:c.fail('evidence_invalid')


def seal_export(fd,snapshot,phase,*,deadline):
    c.member(phase,('initial','final'))
    with c._deadline_context(min(deadline,c._operation_deadline())):
        value=ledger.validate_export(snapshot);raw=ledger.canonical(value)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size or fcntl.fcntl(fd,fcntl.F_GET_SEALS) or fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDWR:c.fail('invalid_channel')
        offset=0
        while offset<len(raw):
            c._check_deadline(deadline);count=os.write(fd,raw[offset:])
            if count<=0:c.fail('unavailable')
            offset+=count
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
        after=os.fstat(fd)
        if after.st_size!=len(raw) or (info.st_dev,info.st_ino)!=(after.st_dev,after.st_ino) or fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=15:c.fail('evidence_invalid')
        return p.validate_export_reference({'bytes':len(raw),'device':info.st_dev,'inode':info.st_ino,
            'phase':phase,'seals':15,'sha256':c.digest(raw)})


class BrokerCore:
    """Durable transitions and original deadlines; no public execution callback.

    Live proof entries are populated only by methods that decode direct inherited
    witness packets. Portable tests use actual socketpairs and actual v2 stores.
    """
    def __init__(self,store,*,broker_id,runtime,slot_specs,deadline_ns,transcript,launcher_channels):
        from .engagement_live_runtime import validate_runtime,runtime_digest
        if type(store)is not DispatchLedger:c.fail('invalid_input')
        self.store=store;self.broker_id=c.uuid(broker_id);self.runtime=validate_runtime(runtime)
        self.runtime_sha256=runtime_digest(self.runtime);self.deadline_ns=c.integer(deadline_ns,1)
        self.transcript=transcript;self.launcher_channels=launcher_channels
        self.snapshot_value=store.snapshot();self.anchor=c.sample_clock();self.initial_state=dict(self.snapshot_value['state'])
        self.owner_id=store.owner_reference;self.engagement_id=self.snapshot_value['engagement_id']
        self.roe=c.validate_live_roe(self.snapshot_value['revisions'][-1]['roe']);self.policy=ledger.policy_for_roe(self.roe)
        self.terminal_reason=None;self.dispatches={};self.prepared_index={};self.approvals={};self.audits={}
        self.consumed_proofs=set();self.audit_source=None;self.audit_ready=None
        self.approval_sequence={};self.audit_sequence=(0,0);self.role_observations={}
        self.slots=[]
        if type(slot_specs)is not list or len(slot_specs)!=2:c.fail('invalid_input')
        for i,spec in enumerate(slot_specs):
            # The initial bootstrap fixes both channel identity and reviewer.
            c.obj(spec,('slot_index','reviewer_id','review_mode','ingress_channel_id'))
            if type(spec['slot_index'])is not int or spec['slot_index']!=i:c.fail('invalid_input')
            c.uuid(spec['reviewer_id']);c.uuid(spec['ingress_channel_id']);c.member(spec['review_mode'],('terminal','graphical_v1'))
            self.slots.append({**spec,'session_id':str(uuid4()),'opened':None,'state':'allocated','dispatch_id':None})
        self.next_watch_ns=self.anchor['mono_after_ns']+100000000
        self._check_current(self.snapshot_value)

    @contextmanager
    def phase(self,deadline_ns=None):
        limit=min(self.deadline_ns,deadline_ns if deadline_ns is not None else self.deadline_ns)/c.SECOND
        with c._deadline_context(min(limit,c._operation_deadline())):
            self.check();yield;self.check()

    def check(self):
        if self.terminal_reason is not None:raise c.LiveError(self.terminal_reason)
        clock=c.sample_clock();start,end=ledger._window(self.roe)
        c.check_clock(clock,anchor=self.anchor,window_start_utc_ns=start,window_end_utc_ns=end,deadline_ns=self.deadline_ns)
        return clock

    def _check_current(self,snapshot,prepared=None):
        state=snapshot['state']
        if snapshot['engagement_id']!=self.engagement_id:c.fail('foreign_owner')
        if state['status']=='revoked':c.fail('revoked')
        if (state['revision'],state['generation'],state['roe_sha256'])!=(self.initial_state['revision'],self.initial_state['generation'],self.initial_state['roe_sha256']):c.fail('revision_changed')
        if self.store.owner_reference!=self.owner_id:c.fail('foreign_owner')
        clock=self.check()
        if prepared is not None:
            e=prepared['envelope']
            c.check_clock(clock,anchor=e['clock_anchor'],window_start_utc_ns=e['window_start_utc_ns'],window_end_utc_ns=e['window_end_utc_ns'],deadline_ns=e['action_deadline_ns'])
            session=next((s for s in snapshot['sessions'] if s['session_id']==e['session_id']),None)
            if session is None or session['owner_id']!=self.owner_id or session['revision']!=e['revision'] or session['generation']!=e['generation']:c.fail('foreign_owner')
        return clock

    def watch(self,*,force=False):
        if self.terminal_reason is not None:raise c.LiveError(self.terminal_reason)
        now=time.monotonic_ns()
        if not force and now<self.next_watch_ns:return
        scheduled=min(self.next_watch_ns,now) if force else self.next_watch_ns
        started=now;reason=None;status='unchanged';snapshot=None;clock=None
        try:
            with self.phase():snapshot=self.store.snapshot();clock=self._check_current(snapshot)
            self.snapshot_value=snapshot
        except BaseException as error:
            reason=_mapped(error);status='changed' if reason in {'engagement_live_revoked','engagement_live_revision_changed'} else 'refused'
            self.stop(reason)
        finally:
            finished=time.monotonic_ns();self.next_watch_ns=finished+100000000
            receipt=snapshot['events'][-1]['receipt'] if snapshot is not None else None
            self.transcript.record('watch',{'clock':clock,'scheduled_at_ns':scheduled,'started_at_ns':started,
                'finished_at_ns':finished,'status':status,'reason':reason,
                'ledger_sequence':None if receipt is None else receipt['sequence'],
                'ledger_state_sha256':None if receipt is None else receipt['state_sha256']},terminal=reason is not None)
        if reason is not None:raise c.LiveError(reason)

    def open_session(self,index):
        c.integer(index,0,1);self.watch();slot=self.slots[index]
        if slot['state']!='allocated':c.fail('session_unavailable')
        with self.phase():
            snapshot=self.store.snapshot();clock=self._check_current(snapshot)
        self.watch()
        with self.phase():
            result=self.store.record_session(session_id=slot['session_id'],clock=clock,
                original_deadline_ns=min(self.deadline_ns,clock['mono_after_ns']+60*c.SECOND),event_id=str(uuid4()),
                expected_revision=self.initial_state['revision'],expected_generation=self.initial_state['generation'])
        if result['disposition']!='recorded':c.fail('session_unavailable')
        self.watch()
        with self.phase():self.snapshot_value=self.store.snapshot()
        row=next(x for x in self.snapshot_value['sessions'] if x['session_id']==slot['session_id'])
        binding=c.derive_session_binding(self.roe,engagement_id=self.engagement_id,
            revision=self.initial_state['revision'],generation=self.initial_state['generation'],broker_id=self.broker_id,
            ledger_owner_id=self.owner_id,session_id=slot['session_id'],reviewer_id=slot['reviewer_id'],
            review_mode=slot['review_mode'],runtime_sha256=self.runtime_sha256,clock=clock,
            session_deadline_ns=row['session_deadline_ns'],broker_deadline_ns=self.deadline_ns)
        slot['opened']=c.validate_session_opened({'schema_version':'1','binding':binding,'session_receipt':result,
            'roe':self.roe,'scope':self.roe['scope'],'policy':self.policy});slot['state']='active'
        return slot['opened']

    def slot_for(self,session_id):
        for slot in self.slots:
            if slot['session_id']==session_id:return slot
        c.fail('session_unavailable')

    def prepare(self,session_id,slot_name):
        self.watch();slot=self.slot_for(session_id)
        if slot['state']!='active':c.fail('session_unavailable')
        old=self.dispatches.get(slot['dispatch_id'])
        if old is not None and old['state']!='settled':c.fail('session_unavailable')
        with self.phase():
            snapshot=self.store.snapshot();clock=self._check_current(snapshot)
            # The accepted ledger separately enforces the actual prerequisite at
            # reservation. Here only an already settled useful prefix is offered.
            if slot_name=='http_headers' and (old is None or old['prepared']['envelope']['slot']!='http_identify' or old.get('result',{}).get('outcome')!='useful'):c.fail('prerequisite_missing')
            if slot_name=='http_identify' and old is not None:c.fail('dispatch_replayed')
            prepared=c.derive_prepared(slot['opened'],slot_name,dispatch_id=str(uuid4()),clock=clock)
        did=prepared['envelope']['dispatch_id'];slot['dispatch_id']=did
        row={'prepared':prepared,'slot_index':slot['slot_index'],'state':None,'admission':None,'release':None,
            'release_summary':None,'completion':None,'result':None,'client':None,'meter':None,'observations':[]}
        self.dispatches[did]=row;self.prepared_index[c.prepared_digest(prepared)]=did
        self.transition(row,'prepared');return prepared

    def transition(self,row,state,reason=None):
        prior=row['state']
        if prior in {'settled','terminal_unresolved'}:c.fail('dispatch_replayed')
        if prior is not None and w.STATES.index(prior)>=w.STATES.index('release_attempted') and state in w.STATES[:5]:c.fail('dispatch_replayed')
        self.transcript.record('state',{'from_state':prior,'to_state':state,'reason':reason},
            session_id=row['prepared']['envelope']['session_id'],dispatch_id=row['prepared']['envelope']['dispatch_id'],
            terminal=state=='terminal_unresolved')
        row['state']=state

    def mark(self,row,phase,stage,*,related=None,reason=None):
        """Retain the actual bounded phase boundary, with no callable hook."""
        e=row['prepared']['envelope']
        self.transcript.record('phase',{'clock':c.sample_clock(),'original_deadline_ns':e['action_deadline_ns'],
            'phase':phase,'stage':stage,'related_sha256':None if related is None else c.digest(c.canonical(related)),
            'reason':reason},session_id=e['session_id'],dispatch_id=e['dispatch_id'],terminal=stage=='refused')

    def approval_packet(self,raw,received_at_ns,reader):
        value=c.decode(raw,max_bytes=4096);did=value.get('dispatch_id');row=self.dispatches.get(did)
        if row is None:c.fail('invalid_witness')
        proof=reader.approval(raw,row['prepared'],received_at_ns=received_at_ns)
        if did in self.approvals:c.fail('invalid_witness')
        observed={'raw_base64':base64.b64encode(raw).decode('ascii'),'raw_sha256':c.digest(raw),
            'witness':proof,'received_at_ns':received_at_ns}
        self.transcript.record('approval_witness',observed,session_id=proof['session_id'],dispatch_id=did)
        self.approvals[did]=observed

    def audit_packet(self,raw,received_at_ns,reader):
        value,_=w._audit_decode(raw);intent=value['intent']
        candidates=[r for r in self.dispatches.values() if r['prepared']['envelope']['session_id']==intent['session_id'] and r['prepared']['envelope']['action_sha256']==intent['action_digest']]
        if len(candidates)!=1 or self.audit_source is None:c.fail('invalid_witness')
        row=candidates[0];did=row['prepared']['envelope']['dispatch_id']
        reader.audit(raw,row['prepared'],source=self.audit_source,received_at_ns=received_at_ns)
        if did in self.audits:c.fail('invalid_witness')
        event=w.started_event(row['prepared'])
        observed={'producer_event':event,'producer_sha256':c.digest(w.audit_protocol.event_bytes(event)),
            'raw_base64':base64.b64encode(raw).decode('ascii'),'raw_sha256':c.digest(raw),'received_at_ns':received_at_ns}
        self.transcript.record('audit_witness',observed,session_id=intent['session_id'],dispatch_id=did)
        self.audits[did]=observed

    def _proofs(self,row,pointers,clock):
        did=row['prepared']['envelope']['dispatch_id'];approval=self.approvals.get(did);audit=self.audits.get(did)
        if approval is None or audit is None:c.fail('invalid_witness')
        witness=w.validate_approval_witness(approval['witness'],row['prepared'],now_ns=clock['mono_after_ns'])
        legacy,issued=w._audit_decode(w._base64(audit['raw_base64'],2048))
        w.validate_audit_witness(w._base64(audit['raw_base64'],2048),row['prepared'],source=self.audit_source,
            sequence=legacy['sequence'],previous_audit=legacy['audit_sequence']-1,now_ns=clock['mono_after_ns'])
        if (pointers['reference_sha256']!=witness['reference_sha256'] or pointers['consume_sequence']!=witness['consume_sequence'] or pointers['audit_sequence']!=legacy['audit_sequence']):c.fail('invalid_witness')
        return approval,audit,witness,legacy,issued

    def reserve(self,pointers):
        self.watch();did=self.prepared_index.get(pointers['prepared_sha256']);row=self.dispatches.get(did)
        if row is None or row['state']!='ready_for_review':c.fail('dispatch_replayed')
        self.transition(row,'awaiting_witnesses');self.mark(row,'reserve','begin')
        clock=self.check();approval,audit,witness,legacy,_=self._proofs(row,pointers,clock)
        identity=(witness['reviewer_id'],witness['consume_sequence'],witness['reference_sha256'])
        if identity in self.consumed_proofs:c.fail('dispatch_replayed')
        self.consumed_proofs.add(identity);e=row['prepared']['envelope']
        self.transcript.reserve(32768)
        with self.phase(e['action_deadline_ns']):
            self._check_current(self.store.snapshot(),row['prepared'])
        self.watch()
        with self.phase(e['action_deadline_ns']):
            result=self.store.reserve(dispatch_id=did,session_id=e['session_id'],slot=e['slot'],
                approval={'broker_id':witness['reviewer_id'],'consume_sequence':witness['consume_sequence'],'witness_sha256':approval['raw_sha256']},
                audit={'writer_id':legacy['writer_id'],'audit_sequence':legacy['audit_sequence'],'event_sha256':audit['producer_sha256']},
                clock=c.sample_clock(),event_id=str(uuid4()),expected_revision=e['revision'],expected_generation=e['generation'])
            row['admission']=result
        if result['disposition']!='recorded':c.fail('dispatch_replayed')
        row['admission']=result;row['pointers']=dict(pointers);self.transition(row,'admitted');self.mark(row,'reserve','end',related=result)
        return row

    def guarded_go(self,row):
        self.watch();e=row['prepared']['envelope']
        if row['state']!='admitted':c.fail('dispatch_replayed')
        self.transcript.reserve(32768);self.mark(row,'guard','begin')
        attempted=False
        try:
            with self.phase(e['action_deadline_ns']):
                deadline=min(c._operation_deadline(),e['action_deadline_ns']/c.SECOND)
                with self.store._transaction(write=True,deadline=deadline) as snapshot:
                    clock=self._check_current(snapshot,row['prepared'])
                    approval,audit,witness,legacy,audit_issued=self._proofs(row,row['pointers'],clock)
                    reservation=next((r for r in snapshot['reservations'] if r['dispatch_id']==e['dispatch_id']),None)
                    if reservation is None or reservation['owner_id']!=self.owner_id:c.fail('foreign_owner')
                    lease=c.derive_effective_lease(row['prepared'],reservation,witness,{'issued_at_ns':audit_issued},clock=clock)
                    receipt=row['admission']['receipt']
                    release=c.validate_release({'schema_version':'1','broker_id':self.broker_id,'ledger_owner_id':self.owner_id,
                        'session_id':e['session_id'],'dispatch_id':e['dispatch_id'],'envelope_sha256':c.envelope_digest(e),
                        'prepared_sha256':c.prepared_digest(row['prepared']),'reservation_event_id':receipt['event_id'],
                        'reservation_sequence':receipt['sequence'],'reservation_state_sha256':receipt['state_sha256'],
                        'approval_witness_sha256':approval['raw_sha256'],'audit_witness_sha256':audit['raw_sha256'],
                        'guard_clock':clock,'effective_lease_deadline_ns':lease,'effect_stop_ns':c.effect_stop(row['prepared'],lease),'release_sequence':1})
                    c.validate_release_binding(release,row['prepared'],clock=clock)
                    channel,sequence=self.launcher_channels[row['slot_index']]
                    frame=sequence.make('GO',release);raw=p.encode_frame(frame,role='launcher',direction='request')
                    self.transcript.reserve(len(raw)+4096)
                    self.transition(row,'release_attempted');attempted=True
                    row['release']=release;row['release_summary']={'release_sha256':c.digest(c.canonical(release)),
                        'attempted_at_ns':time.monotonic_ns(),'send_status':'unknown',
                        'effective_lease_deadline_ns':lease,'effect_stop_ns':release['effect_stop_ns']}
                    self.mark(row,'go','begin',related=release)
                    try:count=p.send_once(channel,raw)
                    except BlockingIOError:
                        row['release_summary']['send_status']='not_sent';raise
                    if count!=len(raw):c.fail('release_unavailable')
                    row['release_summary']['send_status']='sent'
                    self.transcript.record('protocol',{'channel_role':'launcher','direction':'sent','frame':frame},
                        session_id=e['session_id'],dispatch_id=e['dispatch_id'])
                    self.mark(row,'go','end',related=release)
                    # No blocking acknowledgment/native work occurs under this
                    # writer lock. The transaction's own final checks follow.
            self.mark(row,'guard','end',related=release);self.transition(row,'running');return release
        except BaseException as error:
            reason=_mapped(error)
            self.mark(row,'guard','refused',reason=reason)
            if attempted and row['state']!='terminal_unresolved':self.transition(row,'terminal_unresolved',reason)
            row['result']=self.result(row,'unresolved' if row['admission'] is not None else 'denied',reason)
            raise

    def result(self,row,outcome,reason,*,observation=None,client_result_sha256=None,cleanup_sha256=None):
        e=row['prepared']['envelope']
        return c.validate_live_result({'schema_version':'1','broker_id':self.broker_id,'session_id':e['session_id'],
            'dispatch_id':e['dispatch_id'],'envelope_sha256':c.envelope_digest(e),'slot':e['slot'],'outcome':outcome,'reason':reason,
            'admission':row['admission'],'release':row['release_summary'],'completion':row['completion'],'observation':observation,
            'client_result_sha256':client_result_sha256,'cleanup_sha256':cleanup_sha256})

    def stop(self,reason):
        c.member(reason,c.ERROR_CODES)
        if self.terminal_reason is None:self.terminal_reason=reason
        for slot in self.slots:
            if slot['state']=='active':slot['state']='stopping'

    def status(self):
        snapshot=self.store.snapshot();self.snapshot_value=snapshot
        receipt=snapshot['events'][-1]['receipt'];state=snapshot['state']
        return p.validate_status({'schema_version':'1','broker_id':self.broker_id,'ledger_owner_id':self.owner_id,
            'engagement_id':self.engagement_id,'revision':state['revision'],'generation':state['generation'],
            'status':state['status'],'ledger_sequence':receipt['sequence'],'ledger_state_sha256':receipt['state_sha256'],
            'usage':state['usage'],'last_validated_clock':c.sample_clock(),'terminal_reason':self.terminal_reason,
            'sessions':[{'session_id':s['session_id'],'slot_index':s['slot_index'],'state':s['state'],
                'binding_sha256':None if s['opened']is None else c.digest(c.canonical(s['opened']['binding'])),
                'current_dispatch_id':s['dispatch_id'],'current_dispatch_state':None if s['dispatch_id']is None else self.dispatches[s['dispatch_id']]['state']} for s in self.slots]})

    def complete(self,row):
        from .engagement_live_context import validate_dispatch_observations
        if row['state']!='running' or row['client']is None or row['meter']is None:c.fail('invalid_frame')
        observations=row['observations'];captures=[x['data'] for x in observations if x['kind']=='capture']
        if len(captures)!=1:c.fail('invalid_frame')
        client=validate_dispatch_observations(prepared=row['prepared'],release=row['release'],scope=self.roe['scope'],
            capture=captures[0],client_result=row['client'],meter=row['meter'],
            child_readiness=[x['data'] for x in observations if x['kind']=='role_readiness'],
            child_cleanup=[x['data'] for x in observations if x['kind']=='cleanup'],
            native_readiness=[] if 'native' not in row else [row['native']],runtime_bundle=self.runtime)
        self.transition(row,'settling');self.watch();self.mark(row,'complete','begin');e=row['prepared']['envelope'];meter=row['meter']
        observation={'connections':meter['accepted_connections'],'request_bytes':meter['received_request_bytes'],
            'response_bytes':meter['sent_response_bytes'],'client_output_bytes':client['stdout_bytes']+client['stderr_bytes'],
            'parsed_sha256':None if client['parsed']is None else c.digest(c.canonical(client['parsed'])),
            'meter_sha256':c.digest(c.canonical(meter))}
        if not meter['delivery_known'] or any(observation[key]is None for key in ('connections','request_bytes','response_bytes')):c.fail('meter_refused')
        useful=client['status']=='succeeded';clock=c.sample_clock()
        if useful:c.validate_release_binding(row['release'],row['prepared'],clock=clock)
        with self.phase(e['action_deadline_ns']):
            row['completion']=self.store.complete(dispatch_id=e['dispatch_id'],session_id=e['session_id'],
                outcome='reported_success' if useful else 'reported_failure',
                observation={'evidence_sha256':c.digest(c.canonical(observation)),**{key:observation[key] for key in ('connections','request_bytes','response_bytes')}},
                clock=clock,event_id=str(uuid4()))
        self.mark(row,'complete','end',related=row['completion']);self.transition(row,'settled')
        row['result']=self.result(row,'useful' if useful else 'failed',None if useful else 'engagement_live_release_unavailable',
            observation=observation,client_result_sha256=c.digest(c.canonical(client)),
            cleanup_sha256=c.digest(c.canonical(client['cleanup'])) if client['cleanup']is not None else None)
        return row['result']


class BrokerLoop:
    """Finite inherited channels; no reconnection, host callback or new peer."""
    def __init__(self,core,*,host,lifecycle,ingress,launchers,endpoints,approval_readers,audit_reader):
        self.core=core;self.host=host;self.lifecycle=lifecycle;self.ingress=ingress
        self.launchers=launchers;self.endpoints=endpoints;self.approval_readers=approval_readers;self.audit_reader=audit_reader
        self.lifecycle_sequence=p.ChannelSequence(core.broker_id,'lifecycle')
        self.ingress_sequence=[p.ChannelSequence(s['ingress_channel_id'],'ingress') for s in core.slots]
        self.sequences={};self.worker_ready={};self.pending={};self.closed_roles=set();self.stopping=False

    def control(self):
        from .engagement_live_runtime import _WorkerControl
        return _WorkerControl(min(self.core.deadline_ns,time.monotonic_ns()+2*c.SECOND))

    def transcript(self,role,direction,frame,*,row=None):
        e={} if row is None else row['prepared']['envelope']
        self.core.transcript.record('protocol',{'channel_role':role,'direction':direction,'frame':frame},
            session_id=e.get('session_id'),dispatch_id=e.get('dispatch_id'),terminal=self.stopping)

    def reply(self,index,request,*,data=None,code=None,pending=False,row=None):
        frame=self.ingress_sequence[index].make(request['operation'],{'request_sequence':request['sequence'],
            'status':'refused' if code is not None else 'pending' if pending else 'ok','code':code,'data':data})
        raw=p.encode_frame(frame,role='ingress',direction='reply');self.core.transcript.reserve(len(raw)+4096,terminal=self.stopping)
        p.send_packet(self.ingress[index],frame,role='ingress',control=self.control());self.transcript('ingress','sent',frame,row=row)

    def send_role(self,role,index,operation,body,*,row=None):
        sequence=self.sequences.get((role,index))
        if sequence is None:c.fail('invalid_role')
        frame=sequence.make(operation,body);raw=p.encode_frame(frame,role=role,direction='request')
        self.core.transcript.reserve(len(raw)+4096,terminal=self.stopping)
        peer=(self.launchers if role=='launcher' else self.endpoints)[index]
        p.send_packet(peer,frame,role=role,control=self.control());self.transcript(role,'sent',frame,row=row)

    def lifecycle_request(self):
        phase=self.control()
        with c._deadline_context(phase.deadline):
            self._lifecycle_request(phase)

    def _lifecycle_request(self,phase):
        frame=self.lifecycle_sequence.accept(p.receive_packet(self.lifecycle,role='lifecycle',control=phase))
        p.require_request(frame,role='lifecycle');self.transcript('lifecycle','received',frame)
        op,body=frame['operation'],frame['body']
        if op=='STOP':self.stop(body['reason']);return
        if op=='AUDIT_OBSERVED':
            if self.core.audit_ready is not None:c.fail('invalid_role')
            value=w.validate_audit_runtime_binding(body,self.core.runtime)
            actual=os.fstat(self.audit_reader.channel.fileno())
            if (value['source_manifest']['device'],value['source_manifest']['inode'])!=(actual.st_dev,actual.st_ino):c.fail('invalid_witness')
            phase.check()
            self.core.audit_ready=value;self.core.audit_source=value['source_manifest'];return
        if op!='ROLE_OBSERVED':c.fail('invalid_role')
        from .engagement_live_runtime import validate_readiness
        index=body['slot_index'];role=body['role'];slot=self.core.slots[index]
        if slot['opened']is None:c.fail('invalid_role')
        ready=validate_readiness(role,body['readiness'],self.core.runtime)
        if ready['worker_ready']['runtime_sha256']!=self.core.runtime_sha256:c.fail('invalid_role')
        key=(role,index)
        if key in self.core.role_observations:c.fail('invalid_role')
        if role in {'terminal','graphical'}:
            if ready['worker_ready']['worker_id']!=slot['reviewer_id'] or role!=('terminal' if slot['review_mode']=='terminal' else 'graphical'):c.fail('invalid_role')
        elif key in self.worker_ready and ready['worker_ready']!=self.worker_ready[key]:c.fail('invalid_role')
        phase.check()
        self.core.role_observations[key]=ready

    def ingress_request(self,index):
        request=self.ingress_sequence[index].accept(p.receive_packet(self.ingress[index],role='ingress',control=self.control()))
        p.require_request(request,role='ingress');self.transcript('ingress','received',request)
        if index in self.pending:c.fail('invalid_sequence')
        op,body=request['operation'],request['body'];row=None
        try:
            self.core.watch()
            if op=='OPEN_SESSION':
                if body['slot_index']!=index:c.fail('invalid_role')
                data=self.core.open_session(index)
            elif op=='PREPARE':
                if self.core.slots[index]['session_id']!=body['session_id']:c.fail('foreign_owner')
                review='terminal' if self.core.slots[index]['review_mode']=='terminal' else 'graphical'
                if self.core.audit_ready is None or any((role,index)not in self.core.role_observations for role in ('launcher','endpoint',review)) or any((role,index)not in self.worker_ready for role in ('launcher','endpoint')):c.fail('invalid_role')
                prepared=self.core.prepare(body['session_id'],body['slot']);row=self.core.dispatches[prepared['envelope']['dispatch_id']]
                self.core.transition(row,'preparing');self.core.mark(row,'prepare','begin');self.pending[index]=(request,row)
                self.reply(index,request,pending=True,data={'session_id':body['session_id'],'dispatch_id':prepared['envelope']['dispatch_id']},row=row)
                self.send_role('endpoint',index,'PREPARE',prepared,row=row);self.core.watch()
                self.send_role('launcher',index,'PREPARE',prepared,row=row);return
            elif op=='DISPATCH':
                did=self.core.prepared_index.get(body['prepared_sha256']);row=self.core.dispatches.get(did)
                if row is None or row['state']!='ready_for_review' or any(other is row for _,other in self.pending.values()):c.fail('dispatch_replayed')
                self.pending[index]=(request,row)
                self.reply(index,request,pending=True,data={'dispatch_id':did},row=row)
                # Actual direct witnesses may still be queued independently of
                # the host receipt; a pending pointer never substitutes for them.
                row['pending_pointers']=body;return
            elif op=='CANCEL':
                slot=self.core.slot_for(body['session_id']);self.cancel_slot(slot,'engagement_live_cancelled')
                data={'session_id':slot['session_id'],'state':slot['state']}
            elif op=='REVOKE':
                with self.core.phase():data=self.core.store.revoke(**body)
                self.reply(index,request,data=data);self.stop('engagement_live_revoked');return
            elif op=='SNAPSHOT':
                with self.core.phase():data=self.core.status()
            elif op=='CLOSE':self.stop('engagement_live_cancelled');return
            else:c.fail('invalid_frame')
            self.reply(index,request,data=data,row=row)
        except (c.LiveError,ledger.DispatchLedgerError,OSError) as error:
            if index in self.pending:self.pending.pop(index)
            self.reply(index,request,code=_mapped(error),row=row)

    def role_message(self,role,index):
        peer=(self.launchers if role=='launcher' else self.endpoints)[index]
        frame=p.receive_packet(peer,role=role,control=self.control());key=(role,index)
        if key not in self.sequences:
            if frame['operation']!='READY' or frame['sequence']!=1:c.fail('invalid_role')
            self.sequences[key]=p.ChannelSequence(frame['channel_id'],role)
        frame=self.sequences[key].accept(frame);p.require_request(frame,role=role)
        slot=self.core.slots[index];row=self.core.dispatches.get(slot['dispatch_id'])
        self.transcript(role,'received',frame,row=row);op,body=frame['operation'],frame['body']
        if op=='READY':
            if key in self.worker_ready or body['worker_id']!=frame['channel_id'] or body['role']!=role or body['runtime_sha256']!=self.core.runtime_sha256:c.fail('invalid_role')
            if key in self.core.role_observations and body!=self.core.role_observations[key]['worker_ready']:c.fail('invalid_role')
            self.worker_ready[key]=body
            if role=='launcher':self.core.launcher_channels[index]=(peer,self.sequences[key])
            return
        if op=='CLOSED':self.closed_roles.add(key);return
        if row is None:c.fail('invalid_frame')
        prepared=row['prepared'];e=prepared['envelope']
        if op=='PREPARED':
            if row['state']!='preparing' or body['prepared_sha256']!=c.prepared_digest(prepared) or body['envelope_sha256']!=c.envelope_digest(e) or role+'_prepared' in row:c.fail('invalid_prepared')
            if role=='launcher':
                if body['launcher_ready_sha256']!=c.digest(c.canonical(self.worker_ready[key])) or body['endpoint_ready_sha256']!=c.digest(c.canonical(self.core.role_observations[('endpoint',index)])):c.fail('invalid_prepared')
                known={c.digest(c.canonical(x['data'])):x['data'] for x in row['observations'] if x['kind']=='role_readiness'}
                if body['client_ready_sha256'] not in known or body['admission_ready_sha256'] not in known:c.fail('invalid_prepared')
                projections=[x['data'] for x in row['observations'] if x['kind']=='capability_projection' and x['data']['operation']=='ISSUE']
                if len(projections)!=1 or projections[0]['reply']is None or c.digest(c.canonical(projections[0]['reply']))!=body['admission_permit_sha256'] or body['admission_result_sha256']!=body['admission_permit_sha256']:c.fail('invalid_prepared')
            row[role+'_prepared']=body
            if 'launcher_prepared'in row and 'endpoint_prepared'in row:
                self.core.mark(row,'prepare','end',related=row['launcher_prepared']);self.core.transition(row,'ready_for_review')
                for ingress,(request,current) in list(self.pending.items()):
                    if current is row and request['operation']=='PREPARE':
                        self.reply(ingress,request,data={'schema_version':'1','prepared':prepared,'preparation':row['launcher_prepared']},row=row);self.pending.pop(ingress)
        elif op=='OBSERVATION' and role=='launcher':
            observed=p.validate_launcher_observation(body)
            if observed['dispatch_id']!=e['dispatch_id'] or len(row['observations'])>=12:c.fail('invalid_frame')
            if observed['kind']=='capture' and any(x['kind']=='capture' for x in row['observations']):c.fail('invalid_frame')
            if observed['kind']=='role_readiness':
                from .engagement_live_runtime import validate_readiness
                validate_readiness(observed['data']['role'],observed['data'],self.core.runtime)
            row['observations'].append(observed)
        elif op=='NATIVE_OBSERVED' and role=='launcher':
            if row['state']!='running' or 'native'in row:c.fail('invalid_frame')
            row['native']=body
        elif op=='METER' and role=='endpoint':
            from .engagement_live_runtime import validate_meter
            meter=validate_meter(body)
            if row['release']is None or row['meter']is not None or meter['dispatch_id']!=e['dispatch_id'] or meter['session_id']!=e['session_id'] or meter['go_sha256']!=c.digest(c.canonical(row['release'])) or meter['endpoint_id']!=frame['channel_id']:c.fail('meter_refused')
            row['meter']=meter;self.send_role('launcher',index,'METER',meter,row=row)
        elif op=='RESULT' and role=='launcher':
            if row['client']is not None or body['dispatch_id']!=e['dispatch_id']:c.fail('invalid_frame')
            row['client']=body
            if e['slot']=='http_identify' and body['status']=='succeeded' and ('native'not in row or body['readiness']['native_sha256']!=c.digest(c.canonical(row['native']))):c.fail('invalid_runtime')
            result=self.core.complete(row)
            for ingress,(request,current) in list(self.pending.items()):
                if current is row:
                    self.reply(ingress,request,data=result,row=row);self.pending.pop(ingress)
        else:c.fail('invalid_frame')

    def advance(self):
        for index,(request,row) in list(self.pending.items()):
            self.core.watch()
            if request['operation']!='DISPATCH' or row['state']!='ready_for_review':continue
            did=row['prepared']['envelope']['dispatch_id']
            if did not in self.core.approvals or did not in self.core.audits:continue
            try:
                self.core.reserve(row['pending_pointers']);self.core.watch();self.core.guarded_go(row)
            except (c.LiveError,ledger.DispatchLedgerError,OSError) as error:
                result=row.get('result')
                if result is None:
                    outcome='unresolved' if row['admission']is not None else 'denied'
                    if row['state']!='terminal_unresolved':self.core.transition(row,'terminal_unresolved',_mapped(error))
                    result=self.core.result(row,outcome,_mapped(error));row['result']=result
                self.reply(index,request,data=result,row=row);self.pending.pop(index)
                self.cancel_slot(self.core.slots[row['slot_index']],_mapped(error))

    def cancel_slot(self,slot,reason):
        if slot['state']=='closed':return
        slot['state']='stopping';index=slot['slot_index']
        for role in ('launcher','endpoint'):
            if (role,index)in self.sequences:
                try:self.send_role(role,index,'CANCEL',{'reason':reason})
                except (c.LiveError,OSError):pass
        now=time.monotonic_ns();frame=self.lifecycle_sequence.make('SESSION_STOP',{'session_id':slot['session_id'],'reason':reason,'observed_at_ns':now,'cleanup_deadline_ns':now+2*c.SECOND})
        try:p.send_packet(self.lifecycle,frame,role='lifecycle',control=self.control());self.transcript('lifecycle','sent',frame)
        except (c.LiveError,OSError):pass

    def stop(self,reason):
        if self.stopping:return
        self.stopping=True;self.core.stop(reason)
        for slot in self.core.slots:
            if slot['opened']is not None:self.cancel_slot(slot,reason)
        now=time.monotonic_ns();frame=self.lifecycle_sequence.make('BROKER_STOP',{'reason':reason,'observed_at_ns':now,'cleanup_deadline_ns':now+2*c.SECOND})
        try:p.send_packet(self.lifecycle,frame,role='lifecycle',control=self.control());self.transcript('lifecycle','sent',frame)
        except (c.LiveError,OSError):pass

    def run(self):
        import select
        peers=[self.host,self.lifecycle,*self.ingress,*self.launchers,*self.endpoints,
            *(r.channel for r in self.approval_readers),self.audit_reader.channel]
        while not self.stopping:
            try:
                self.core.watch();self.advance()
                for row in self.core.dispatches.values():
                    if row['state']not in {'settled','terminal_unresolved'}:
                        e=row['prepared']['envelope'];c.check_clock(c.sample_clock(),anchor=e['clock_anchor'],window_start_utc_ns=e['window_start_utc_ns'],window_end_utc_ns=e['window_end_utc_ns'],deadline_ns=e['action_deadline_ns'])
                ready=select.select(peers,[],[],min(.02,max(0,(self.core.next_watch_ns-time.monotonic_ns())/c.SECOND)))[0]
                # Lifecycle EOF/cancel wins over simultaneous authority and data.
                if self.host in ready:self.stop('engagement_live_cancelled');break
                if self.lifecycle in ready:self.lifecycle_request()
                if self.stopping:break
                for index,reader in enumerate(self.approval_readers):
                    if reader.channel in ready:
                        packet=reader.poll()
                        if packet:self.core.approval_packet(*packet,reader)
                if self.audit_reader.channel in ready:
                    packet=self.audit_reader.poll()
                    if packet:self.core.audit_packet(*packet,self.audit_reader)
                for role,channels in (('endpoint',self.endpoints),('launcher',self.launchers)):
                    for index,peer in enumerate(channels):
                        if peer in ready:self.core.watch();self.role_message(role,index)
                for index,peer in enumerate(self.ingress):
                    if peer in ready:self.core.watch();self.ingress_request(index)
            except (c.LiveError,ledger.DispatchLedgerError,OSError) as error:self.stop(_mapped(error))


def main():
    from . import engagement_live_runtime as rt
    store=None;host=None;channels=[];readers=[];transcript=None;core=None;rights={}
    try:
        if len(sys.argv)!=3:c.fail('invalid_input')
        wid=c.uuid(sys.argv[1]);commit=c.digest_string(sys.argv[2])
        initial,manifest,rights,host=rt._receive_initial('broker',wid,commit,entry_verified=True)
        entry=rt.check_role_entry(role='broker',bootstrap=initial,expected_fds=rights,observer=initial['observer'])
        payload=initial['payload'];c.obj(payload,('contract_sha256','gates_sha256','live_started_at_ns','original_broker_deadline_ns','slot_specs','store_directory'))
        if payload['contract_sha256']!=c.CONTRACT_SHA256 or payload['gates_sha256']!=c.INVENTORY_SHA256 or payload['store_directory']!='/store/engagement':c.fail('invalid_runtime')
        deadline=c.integer(payload['original_broker_deadline_ns'],payload['live_started_at_ns']+1,payload['live_started_at_ns']+120*c.SECOND)
        if initial['deadline_ns']!=deadline:c.fail('invalid_role')
        fd=rights.pop('runtime_input')
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=2097152 or fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=15:c.fail('invalid_runtime')
            raw=os.pread(fd,info.st_size+1,0);bundle=rt.validate_runtime(c.decode(raw,max_bytes=2097152))
            if len(raw)!=info.st_size or c.canonical(bundle,max_bytes=2097152)!=raw or rt.runtime_digest(bundle)!=initial['runtime_sha256']:c.fail('invalid_runtime')
        finally:os.close(fd)
        def peer(name):
            channel=socket.socket(fileno=rights[name]);channel.setblocking(False);channels.append(channel);return channel
        lifecycle=peer('host_lifecycle');ingress=[peer('ingress'+str(i)) for i in range(2)]
        launchers=[peer('launcher'+str(i)) for i in range(2)];endpoints=[peer('endpoint'+str(i)) for i in range(2)]
        for i in range(2):
            fd=rights['review_witness'+str(i)];info=os.fstat(fd);readers.append(w.DirectReader(fd,[info.st_dev,info.st_ino],kind='approval'))
        fd=rights['audit_witness'];info=os.fstat(fd);audit_reader=w.DirectReader(fd,[info.st_dev,info.st_ino],kind='audit');readers.append(audit_reader)
        transcript=Transcript(rights['transcript_memfd'],broker_id=wid)
        store=DispatchLedger.open('/store/engagement')
        core=BrokerCore(store,broker_id=wid,runtime=bundle,slot_specs=payload['slot_specs'],deadline_ns=deadline,
            transcript=transcript,launcher_channels=[None,None])
        initial_reference=seal_export(rights['initial_export_memfd'],core.snapshot_value,'initial',deadline=min(deadline/c.SECOND,time.monotonic()+2))
        initial_receipt=core.snapshot_value['events'][-1]['receipt']
        transcript.record('export',{'phase':'initial','reference':initial_reference,'ledger_sequence':initial_receipt['sequence'],'ledger_state_sha256':initial_receipt['state_sha256']})
        ready=rt.bootstrap_role(role='broker',entry=entry,runtime_manifest=manifest,expected_fds=rights,deadline_ns=deadline)
        ready['boundary_checks'].update(dict.fromkeys(rt.SPEC['closed_objects']['boundary_checks']['role_specific']['broker'],True))
        rt._emit_ready(ready)
        from .configurable_scope import scope_digest
        from .models import parse_policy
        business={'schema_version':'1','broker_id':wid,'ledger_owner_id':core.owner_id,'engagement_id':core.engagement_id,
            'revision':core.initial_state['revision'],'generation':core.initial_state['generation'],'roe_sha256':core.initial_state['roe_sha256'],
            'roe':core.roe,'scope':core.roe['scope'],'scope_sha256':scope_digest(core.roe['scope']),
            'policy':core.policy,'policy_sha256':parse_policy(core.policy).digest,'runtime_sha256':core.runtime_sha256,
            'clock_anchor':core.anchor,'broker_deadline_ns':deadline,'initial_export':initial_reference,
            'allocated_slots':[{k:s[k] for k in ('slot_index','session_id','reviewer_id','review_mode')} for s in core.slots]}
        rt._send_bytes(host,c.canonical(business),rt._WorkerControl(min(deadline,time.monotonic_ns()+2*c.SECOND)))
        loop=BrokerLoop(core,host=host,lifecycle=lifecycle,ingress=ingress,launchers=launchers,endpoints=endpoints,
            approval_readers=readers[:2],audit_reader=audit_reader)
        loop.run();return 0
    except (ValueError,OSError,RuntimeError):
        os.write(2,b'engagement_live_broker_refused\n');return 78
    finally:
        if store is not None:
            try:
                limit=time.monotonic()+2
                with c._deadline_context(limit):
                    snapshot=store.snapshot()
                    reference=seal_export(rights['final_export_memfd'],snapshot,'final',deadline=limit)
                    receipt=snapshot['events'][-1]['receipt']
                    transcript.record('export',{'phase':'final','reference':reference,'ledger_sequence':receipt['sequence'],'ledger_state_sha256':receipt['state_sha256']},terminal=True)
            except (ValueError,OSError,RuntimeError):pass
            finally:store.close()
        if transcript is not None:
            try:transcript.seal()
            except OSError:pass
        for channel in channels:channel.close()
        for reader in readers:reader.close()
        for key in ('initial_export_memfd','final_export_memfd','transcript_memfd'):
            if key in rights:os.close(rights[key])
        if host is not None:host.close()


if __name__=='__main__':raise SystemExit(main())
