"""Fixed isolated launcher: broker GO, one-use admission, then bounded clients."""
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
    if any(not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd) for fd in (1,2)):raise ValueError('engagement_live_invalid_output')


if __name__=='__main__':
    try:_entry_only_stdio()
    except Exception:
        os.write(2,b'engagement_live_launcher_refused\n');raise SystemExit(78) from None
    sys.path.insert(0,'/app');__package__='recon_cockpit.secure_agent'

import base64
import select
import socket
import time
from . import engagement_live_contract as c
from . import engagement_live_protocol as p
from . import engagement_live_runtime as rt
from . import engagement_live_witness as witness


class LauncherControl:
    clock=staticmethod(time.monotonic)
    def __init__(self,owner,deadline_ns):self.owner=owner;self.deadline=deadline_ns/c.SECOND
    def check(self):
        if time.monotonic()>=self.deadline:c.fail('timeout')
        self.owner.poll_stop()
        if self.owner.pending is not None:
            e=self.owner.pending['envelope']
            c.check_clock(c.sample_clock(),anchor=e['clock_anchor'],window_start_utc_ns=e['window_start_utc_ns'],window_end_utc_ns=e['window_end_utc_ns'],deadline_ns=min(int(self.deadline*c.SECOND),e['action_deadline_ns']))
    def remaining(self):self.check();return max(0,self.deadline-time.monotonic())


class LauncherState:
    def __init__(self,*,payload,runtime,worker_id,host,broker,arm,ready,deadline_ns,request_channels):
        from .engagement_live_endpoint import ArmChannel
        c.obj(payload,('session_binding','roe','scope','policy','endpoint_identity','child_slots'))
        c.validate_role_context(binding=payload['session_binding'],roe=payload['roe'],scope=payload['scope'],policy=payload['policy'])
        rt.validate_readiness('endpoint',payload['endpoint_identity'],runtime)
        self.payload=payload;self.runtime=runtime;self.worker_id=worker_id;self.host=host;self.broker=broker
        self.arm=ArmChannel(arm);self.ready=ready;self.deadline_ns=deadline_ns
        self.sequence=p.ChannelSequence(worker_id,'launcher');self.pending=None;self.client=None;self.admission=None
        self.permit=None;self.admission_sequence=None;self.release=None;self.meter=None;self.stopped=False
        self.readies=[];self.cleanups=[];self.capture=None;self.prepared_ids=set();self._polling=False
        self.supervisor=rt.SupervisorChannel(host,launcher_id=worker_id,
            slot_bindings=payload['child_slots'],request_channels=request_channels,runtime=runtime,
            endpoint_identity=payload['endpoint_identity'],role_context={key:payload[key]
                for key in ('session_binding','roe','scope','policy')},control=self._control())

    def _control(self,deadline=None):return LauncherControl(self,min(self.deadline_ns,deadline if deadline is not None else self.deadline_ns))
    def poll_stop(self):
        if self.stopped:c.fail('cancelled')
        if self._polling:return
        self._polling=True
        try:
            if select.select([self.broker],[],[],0)[0]:
                frame=self.sequence.accept(p.receive_packet(self.broker,role='launcher',control=rt._WorkerControl(self.deadline_ns)))
                if frame['operation'] in {'STOP','CANCEL'}:self.stopped=True;c.fail('cancelled')
                if frame['operation']!='METER' or self.release is None or self.meter is not None:c.fail('invalid_frame')
                meter=rt.validate_meter(frame['body'])
                if meter['dispatch_id']!=self.release['dispatch_id'] or meter['go_sha256']!=rt._hash(self.release):c.fail('invalid_frame')
                self.meter=meter
            if select.select([self.host],[],[],0)[0]:
                # Exactly one fixed supervision waiter may consume its reply;
                # broker cancellation above always has priority.
                supervisor=getattr(self,'supervisor',None)
                if supervisor is None or not supervisor.pending:
                    self.stopped=True;c.fail('cancelled')
        finally:self._polling=False

    def send(self,op,body,*,control=None):
        # Sending evidence never accepts another effect-bearing command.
        frame=self.sequence.make(op,body)
        p.send_packet(self.broker,frame,role='launcher',control=control or rt._WorkerControl(min(self.deadline_ns,time.monotonic_ns()+2*c.SECOND)))
    def observe(self,kind,data):
        if kind=='cleanup':
            known=getattr(self,'_observed_cleanups',set());digest=rt._hash(data)
            if digest in known:return
            known.add(digest);self._observed_cleanups=known
        self.send('OBSERVATION',{'dispatch_id':self.pending['envelope']['dispatch_id'],'kind':kind,'data':data})

    def record_capture(self,capture):
        self.capture={'schema_version':'1','slot':self.pending['envelope']['slot'],'exit_code':capture['exit_code'],'truncated':capture['truncated']}
        for name in ('stdout','stderr'):
            self.capture.update({name+'_base64':base64.b64encode(capture[name]).decode('ascii'),name+'_bytes':len(capture[name]),name+'_sha256':c.digest(capture[name])})
        self.observe('capture',self.capture)

    def admission_rpc(self,operation,body):
        phase=self._control(min(self.pending['envelope']['action_deadline_ns'],time.monotonic_ns()+2*c.SECOND))
        frame=self.admission_sequence.make(operation,body);raw=p.encode_frame(frame,role='admission',direction='request')
        request=body if operation=='ISSUE' else {'prepared_sha256':body['prepared_sha256'],'reference_sha256':c.digest(body['reference'].encode('ascii')),'release':body['release']}
        projection={'channel_id':frame['channel_id'],'role':'admission','operation':operation,'request_sequence':frame['sequence'],
            'request':request,'reply':None,'request_projection_sha256':c.digest(c.canonical(request)),
            'reply_projection_sha256':None,'original_request_bytes':len(raw),'original_request_sha256':c.digest(raw),
            'original_reply_bytes':None,'original_reply_sha256':None}
        try:
            p.send_packet(self.admission.channel,frame,role='admission',control=phase)
            reply=self.admission_sequence.accept(p.receive_packet(self.admission.channel,role='admission',control=phase))
            p.require_reply(reply,frame,role='admission')
            data=reply['body']
            if data['status']=='refused':projection['reply']=data
            elif data['status']=='ok':projection['reply']=p.permit_projection(data['data']) if operation=='ISSUE' else data['data']
            else:c.fail('invalid_frame')
            projection['reply_projection_sha256']=c.digest(c.canonical(projection['reply']))
            if data['status']=='refused':raise c.LiveError(data['code'])
            phase.check();return data['data'],projection
        finally:
            witness.validate_capability_projection(projection);self.observe('capability_projection',projection)

    def prepare(self,prepared):
        from .engagement_live_client import _prepare_supervised_client
        value=c.validate_prepared_role_context(prepared,binding=self.payload['session_binding'],roe=self.payload['roe'],scope=self.payload['scope'],policy=self.payload['policy'])
        did=value['envelope']['dispatch_id']
        if self.pending is not None or did in self.prepared_ids or len(self.prepared_ids)>=2:c.fail('dispatch_replayed')
        self.prepared_ids.add(did);self.pending=value;self.readies=[];self.cleanups=[];self.meter=None;self.capture=None;self.release=None
        phase=self._control(value['envelope']['action_deadline_ns']);self.arm.prepare(value)
        self.client=_prepare_supervised_client(runtime=self.runtime,prepared=value,endpoint_identity=self.payload['endpoint_identity'],scope=self.payload['scope'],control=phase,supervisor=self.supervisor)
        self.readies.append(self.client.ready);self.observe('role_readiness',self.client.ready)
        admission_slot='identify_admission' if value['envelope']['slot']=='http_identify' else 'headers_admission'
        self.admission=self.supervisor.start_child(child_slot=admission_slot,prepared=value,control=phase)
        self.readies.append(self.admission.ready);self.observe('role_readiness',self.admission.ready)
        self.admission_sequence=p.ChannelSequence(self.admission.ready['worker_ready']['worker_id'],'admission')
        self.permit,projection=self.admission_rpc('ISSUE',value)
        receipt=p.validate_prepare_receipt({'schema_version':'1','prepared_sha256':c.prepared_digest(value),'envelope_sha256':c.envelope_digest(value['envelope']),
            'launcher_ready_sha256':rt._hash(self.ready),'endpoint_ready_sha256':rt._hash(self.payload['endpoint_identity']),
            'client_ready_sha256':rt._hash(self.client.ready),'admission_ready_sha256':rt._hash(self.admission.ready),
            'admission_result_sha256':rt._hash(projection['reply']),'admission_permit_sha256':rt._hash(p.permit_projection(self.permit)),
            'ready_at_ns':time.monotonic_ns(),'preparation_deadline_ns':value['envelope']['action_deadline_ns']})
        phase.check();self.send('PREPARED',receipt)

    def run(self,release):
        from .engagement_live_endpoint import arm_endpoint
        from .engagement_live_parser import _parse_supervised_observed
        from .engagement_live_context import meter_summary,validate_client_result,validate_dispatch_observations
        if self.pending is None or self.release is not None:c.fail('release_unavailable')
        release=c.validate_release_binding(release,self.pending,clock=c.sample_clock());self.release=release
        effect=self._control(release['effect_stop_ns']);whole=self._control(self.pending['envelope']['action_deadline_ns'])
        parsed=parser_receipt=None;failure=None;capture=None
        try:
            self.admission_rpc('REDEEM',{'prepared_sha256':c.prepared_digest(self.pending),'reference':self.permit['reference'],'release':release})
            self.permit=None
            cleanup=self.admission.close(deadline=min(whole.deadline,time.monotonic()+2));self.cleanups.append(cleanup);self.observe('cleanup',cleanup)
            self.admission=None
            if self.pending['envelope']['slot']=='http_identify':
                self.client.release(release,effect);native=self.client.observe_native(effect);self.send('NATIVE_OBSERVED',native)
                arm_endpoint(self.arm,release=release,endpoint_identity=self.payload['endpoint_identity'],control=effect)
            else:
                arm_endpoint(self.arm,release=release,endpoint_identity=self.payload['endpoint_identity'],control=effect)
                self.client.release(release,effect)
            capture=self.client.collect(effect);self.cleanups.append(capture['cleanup']);self.observe('cleanup',capture['cleanup'])
            self.record_capture(capture)
            while self.meter is None:effect.check();select.select([self.broker,self.host],[],[],min(.01,effect.remaining()))
            if capture['status']=='succeeded':
                parsed,parser_receipt,parser_ready=_parse_supervised_observed(tool_id=self.pending['action']['tool_id'],raw=capture['stdout'],stderr=capture['stderr'],scope=self.payload['scope'],truncated=capture['truncated'],control=whole,runtime=self.runtime,prepared=self.pending,supervisor=self.supervisor)
                self.readies.append(parser_ready);self.cleanups.append(parser_receipt['cleanup'])
                self.observe('role_readiness',parser_ready);self.observe('cleanup',parser_receipt['cleanup'])
            else:failure=capture['status']
            whole.check()
        except c.LiveError as error:
            failure='cancelled' if error.code=='engagement_live_cancelled' else 'timeout' if error.code=='engagement_live_timeout' else 'unresolved'
            partial=getattr(error,'client_capture',None)
            if capture is None and partial is not None:
                capture=partial
                try:
                    self.record_capture(capture)
                    if capture['cleanup']is not None:self.cleanups.append(capture['cleanup']);self.observe('cleanup',capture['cleanup'])
                except (c.LiveError,OSError):pass
            raise
        finally:
            if self.admission is not None:
                cleanup=self.admission.close(deadline=min(whole.deadline,time.monotonic()+2));self.cleanups.append(cleanup)
                self.observe('cleanup',cleanup);self.admission=None
            if self.client is not None and capture is None:
                cleanup=self.client.close();self.cleanups.append(cleanup);self.observe('cleanup',cleanup)
        if capture is None:c.fail('release_unavailable')
        e=self.pending['envelope'];status=failure or 'succeeded'
        result={'schema_version':'1','dispatch_id':e['dispatch_id'],'envelope_sha256':c.envelope_digest(e),'runtime_sha256':e['runtime_sha256'],
            'slot':e['slot'],'status':status,'exit_code':capture['exit_code'],'stop_reason':None if status=='succeeded' else ('native_failed' if status=='failed' else status),
            'stdout_sha256':self.capture['stdout_sha256'],'stderr_sha256':self.capture['stderr_sha256'],'stdout_bytes':len(capture['stdout']),
            'stderr_bytes':len(capture['stderr']),'truncated':capture['truncated'],
            'readiness':{'client_sha256':rt._hash(capture['readiness']),'native_sha256':None if capture['native_readiness']is None else rt._hash(capture['native_readiness'])},
            'meter':meter_summary(self.meter),'parsed':parsed,'parser_receipt':parser_receipt,'cleanup':capture['cleanup']}
        validate_client_result(result)
        validate_dispatch_observations(prepared=self.pending,release=release,scope=self.payload['scope'],capture=self.capture,client_result=result,meter=self.meter,child_readiness=self.readies,child_cleanup=self.cleanups,
            native_readiness=[] if capture['native_readiness']is None else [capture['native_readiness']],runtime_bundle=self.runtime)
        whole.check();self.send('RESULT',result);self.pending=None;self.client=None;self.release=None

    def close(self):
        self.stopped=True;deadline=min(self.deadline_ns/c.SECOND,time.monotonic()+2)
        self.supervisor.close()
        # CLOSED reports worker stopping only. Actual child and host-thread
        # cleanup are observed and retained independently by their real owner.
        try:self.send('CLOSED',{'role':'launcher','worker_id':self.worker_id,'stopped_at_ns':time.monotonic_ns()},control=rt._WorkerControl(int(deadline*c.SECOND)))
        except (c.LiveError,OSError):pass


def main():
    host=broker=arm=None;state=None;request_channels={}
    try:
        if len(sys.argv)!=3:c.fail('invalid_input')
        wid=c.uuid(sys.argv[1]);commit=c.digest_string(sys.argv[2])
        initial,manifest,rights,host=rt._receive_initial('launcher',wid,commit,entry_verified=True)
        entry=rt.check_role_entry(role='launcher',bootstrap=initial,expected_fds=rights,observer=initial['observer'])
        raw=rt._read_file('/run/engagement-runtime-bundle.json',2097152)
        bundle=rt.validate_runtime(c.decode(raw,max_bytes=2097152))
        if c.canonical(bundle,max_bytes=2097152)!=raw or rt.runtime_digest(bundle)!=initial['runtime_sha256'] or next(x for x in bundle['roles'] if x['role']=='launcher')!=manifest:c.fail('invalid_runtime')
        broker=socket.socket(fileno=rights['broker_control']);arm=socket.socket(fileno=rights['endpoint_arm'])
        broker.setblocking(False);arm.setblocking(False)
        for name in c.CHILD_SLOTS:
            channel=socket.socket(fileno=rights[name+'_request']);channel.setblocking(False)
            request_channels[name]=channel
        ready=rt.bootstrap_role(role='launcher',entry=entry,runtime_manifest=manifest,expected_fds=rights,deadline_ns=initial['deadline_ns'])
        ready['boundary_checks'].update(dict.fromkeys(rt.SPEC['closed_objects']['boundary_checks']['role_specific']['launcher'],True))
        rt._emit_ready(ready)
        state=LauncherState(payload=initial['payload'],runtime=bundle,worker_id=wid,host=host,broker=broker,arm=arm,ready=ready,deadline_ns=initial['deadline_ns'],request_channels=request_channels)
        state.send('READY',ready)
        while True:
            control=rt._WorkerControl(initial['deadline_ns'])
            readable=select.select([host,broker],[],[],min(.05,control.remaining()))[0]
            if host in readable:break
            if broker not in readable:continue
            frame=state.sequence.accept(p.receive_packet(broker,role='launcher',control=control))
            op=frame['operation']
            if op in {'CANCEL','STOP'}:break
            if op=='PREPARE':state.prepare(frame['body'])
            elif op=='GO':state.run(frame['body'])
            else:c.fail('invalid_frame')
        return 0
    except (ValueError,OSError,RuntimeError):
        os.write(2,b'engagement_live_launcher_refused\n');return 78
    finally:
        if state is not None:state.close()
        for channel in (host,broker,arm):
            if channel is not None:channel.close()
        for channel in request_channels.values():channel.close()


if __name__=='__main__':raise SystemExit(main())
