"""Fixed isolated one-use nested admission; no approval or durable authority."""
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
    for fd in (1,2):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd):raise ValueError('engagement_live_invalid_output')


if __name__=='__main__':
    try:_entry_only_stdio()
    except Exception:
        os.write(2,b'engagement_live_admission_refused\n');raise SystemExit(78) from None
    sys.path.insert(0,'/app');__package__='recon_cockpit.secure_agent'

import hmac
import time
from . import engagement_live_contract as c
from . import engagement_live_protocol as p


class AdmissionState:
    def __init__(self,prepared,*,admission_id,launcher_id,endpoint_identity,runtime_sha256):
        from . import engagement_live_runtime as runtime
        self.prepared=c.validate_prepared(prepared);e=self.prepared['envelope']
        self.admission_id=c.uuid(admission_id);self.launcher_id=c.uuid(launcher_id)
        runtime.validate_protocol_value('role_readiness',endpoint_identity)
        if endpoint_identity['role']!='endpoint' or endpoint_identity['worker_ready']['runtime_sha256']!=runtime_sha256 or e['runtime_sha256']!=runtime_sha256:c.fail('invalid_role')
        self.endpoint_identity=endpoint_identity;self._permit=None;self._issued=False;self._terminal=False

    def issue(self,prepared,*,clock):
        if self._terminal or self._issued:c.fail('admission_unavailable')
        self._issued=True
        value=c.validate_prepared(prepared)
        if value!=self.prepared:c.fail('invalid_prepared')
        e=value['envelope'];now=clock['mono_after_ns']
        expiry=c.check_clock(clock,anchor=e['clock_anchor'],window_start_utc_ns=e['window_start_utc_ns'],
            window_end_utc_ns=e['window_end_utc_ns'],deadline_ns=e['action_deadline_ns'])
        expiry=min(expiry,e['action_deadline_ns'],e['session_deadline_ns'],e['broker_deadline_ns'])
        self._permit=p.validate_permit({'schema_version':'1','admission_id':self.admission_id,
            'session_id':e['session_id'],'dispatch_id':e['dispatch_id'],'prepared_sha256':c.prepared_digest(value),
            'envelope_sha256':c.envelope_digest(e),'action_sha256':e['action_sha256'],
            'policy_sha256':e['policy_sha256'],'runtime_sha256':e['runtime_sha256'],
            'reference':os.urandom(32).hex(),'issued_at_ns':now,'expires_at_ns':expiry})
        return c.detached(self._permit)

    def redeem(self,request,*,clock):
        permit,self._permit=self._permit,None
        self._terminal=True
        c.obj(request,('prepared_sha256','reference','release'))
        if permit is None or request['prepared_sha256']!=permit['prepared_sha256'] or type(request['reference'])is not str or not hmac.compare_digest(request['reference'],permit['reference']):c.fail('admission_unavailable')
        release=c.validate_release_binding(request['release'],self.prepared,clock=clock)
        now=clock['mono_after_ns']
        if not permit['issued_at_ns']<=now<min(permit['expires_at_ns'],release['effect_stop_ns']):c.fail('timeout')
        return p.validate_redeemed({'schema_version':'1','admission_id':self.admission_id,
            'session_id':permit['session_id'],'dispatch_id':permit['dispatch_id'],
            'permit_sha256':c.digest(c.canonical(p.permit_projection(permit))),
            'release_sha256':c.digest(c.canonical(release)),'prepared_sha256':permit['prepared_sha256'],
            'redeemed_at_ns':now,'status':'redeemed'})

    def cancel(self):self._permit=None;self._terminal=True


class _Control:
    def __init__(self,prepared,deadline_ns):
        self.prepared=prepared;self.deadline_ns=deadline_ns;self.deadline=deadline_ns/c.SECOND
    def remaining(self):
        e=self.prepared['envelope']
        c.check_clock(c.sample_clock(),anchor=e['clock_anchor'],window_start_utc_ns=e['window_start_utc_ns'],window_end_utc_ns=e['window_end_utc_ns'],deadline_ns=self.deadline_ns)
        remaining=self.deadline-time.monotonic()
        if remaining<=0:c.fail('timeout')
        return remaining
    def check(self):self.remaining()


def main():
    from . import engagement_live_runtime as runtime
    channel=None
    try:
        if len(sys.argv)!=3:c.fail('invalid_input')
        worker_id=c.uuid(sys.argv[1]);commitment=c.digest_string(sys.argv[2])
        initial,manifest,rights,channel=runtime._receive_initial('admission',worker_id,commitment,entry_verified=True)
        entry=runtime.check_role_entry(role='admission',bootstrap=initial,expected_fds=rights,observer=initial['observer'])
        payload=initial['payload'];c.obj(payload,('prepared','endpoint_identity','launcher_id'))
        state=AdmissionState(payload['prepared'],admission_id=worker_id,launcher_id=payload['launcher_id'],endpoint_identity=payload['endpoint_identity'],runtime_sha256=initial['runtime_sha256'])
        if rights or initial['deadline_ns']>state.prepared['envelope']['action_deadline_ns']:c.fail('invalid_role')
        ready=runtime.bootstrap_role(role='admission',entry=entry,runtime_manifest=manifest,expected_fds=rights,deadline_ns=initial['deadline_ns'])
        ready['boundary_checks'].update(network_creation_blocked=True,authority_absent=True)
        runtime._emit_ready(ready)
        sequence=p.ChannelSequence(worker_id,'admission');life=_Control(state.prepared,initial['deadline_ns'])
        while True:
            request=sequence.accept(p.receive_packet(channel,role='admission',control=life));p.require_request(request,role='admission')
            operation=request['operation'];now=time.monotonic_ns()
            phase=_Control(state.prepared,min(initial['deadline_ns'],now+2*c.SECOND))
            status,code='ok',None
            try:
                if operation=='ISSUE':data=state.issue(request['body'],clock=c.sample_clock())
                elif operation=='REDEEM':data=state.redeem(request['body'],clock=c.sample_clock())
                else:
                    state.cancel();data={'role':'admission','worker_id':worker_id,'stopped_at_ns':time.monotonic_ns()}
            except c.LiveError as error:
                state.cancel();status,code,data='refused',error.code,None
            reply=sequence.make(operation,{'request_sequence':request['sequence'],'status':status,'code':code,'data':data})
            p.send_packet(channel,reply,role='admission',control=phase)
            if operation in {'REDEEM','CANCEL','CLOSE'} or status=='refused':return 0
    except BaseException:
        os.write(2,b'engagement_live_admission_refused\n');return 78
    finally:
        if channel is not None:channel.close()


if __name__=='__main__':raise SystemExit(main())
