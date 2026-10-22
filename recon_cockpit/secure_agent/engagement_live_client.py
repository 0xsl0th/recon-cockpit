"""One actual prepared client, released only by the isolated launcher."""
import os
import selectors
import time

from . import engagement_live_contract as contract
from . import engagement_live_runtime as rt


class WaitingClient:
    def __init__(self,owner,prepared,runtime):
        self.owner=owner;self.prepared=prepared;self.runtime=runtime;self.ready=owner.ready
        self.released=False;self.native_ready=None;self.capture=None
        self.native_deadline=None
    def release(self,release,control):
        if self.released:rt._fail('dispatch_replayed')
        release=contract.validate_release_binding(release,self.prepared,clock=contract.sample_clock())
        self.owner.pin.check_alive();control.check();self.released=True
        self.native_deadline=min(control.deadline,release['effect_stop_ns']/1e9,time.monotonic()+(5 if self.prepared['envelope']['slot']=='http_identify' else 1))
        rt._send_bytes(self.owner.channel,rt._json(release),rt._ClippedControl(control,self.native_deadline))
    def observe_native(self,control):
        if not self.released:rt._fail('release_unavailable')
        if self.prepared['envelope']['slot']!='http_identify':return None
        manifest=next(x for x in self.runtime['roles'] if x['role']=='nmap')
        self.native_ready=rt.observe_native(self.owner.pin,manifest,waiting_image=self.ready['parent_observation']['executable'],control=rt._ClippedControl(control,self.native_deadline))
        return self.native_ready
    def collect(self,control):
        if not self.released or self.capture is not None:rt._fail('release_unavailable')
        bounded=rt._ClippedControl(control,self.native_deadline)
        maximum=8192 if self.prepared['envelope']['slot']=='http_identify' else 2048
        selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};truncated=False;reason=None;failure=None;cleanup=None
        try:
            for name in buffers:
                pipe=getattr(self.owner.process,name);os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,name)
            while selector.get_map() or self.owner.process.poll() is None:
                bounded.check()
                for key,_ in selector.select(min(.01,bounded.remaining())):
                    remaining=maximum-sum(map(len,buffers.values()))
                    # A bounded one-byte capture probe detects pipe overflow; this
                    # is output accounting, never endpoint network-byte admission.
                    raw=os.read(key.fileobj.fileno(),remaining+1)
                    if not raw:selector.unregister(key.fileobj);continue
                    buffers[key.data].extend(raw[:remaining])
                    if len(raw)>remaining:truncated=True;reason='output_limit';break
                if truncated:break
        except contract.LiveError as error:
            if error.code=='engagement_live_timeout':reason='timeout'
            else:failure=error;reason='cancelled' if error.code=='engagement_live_cancelled' else 'unresolved'
        except BaseException as error:
            failure=error;reason='unresolved'
        finally:
            selector.close()
            try:cleanup=self.owner.close()
            except BaseException as error:
                if failure is None:failure=error
                else:failure.cleanup_error=error
                cleanup=getattr(error,'cleanup',None);reason='unresolved'
        if reason is None:
            try:bounded.check();control.check()
            except BaseException as error:failure=error;reason='unresolved'
        code=self.owner.process.returncode
        status=reason or ('succeeded' if code==0 else 'failed')
        self.capture={'stdout':bytes(buffers['stdout']),'stderr':bytes(buffers['stderr']),'exit_code':code,
            'truncated':truncated,'status':status,'readiness':self.ready,'native_readiness':self.native_ready,'cleanup':cleanup}
        if failure is not None:
            failure.client_capture=self.capture
            raise failure
        return self.capture
    def close(self):return self.owner.close()


def prepare_client(*,runtime,prepared,endpoint_identity,scope,control):
    from .configurable_scope import validate_scope, scope_digest
    from .configurable_contract import action
    prepared=contract.validate_prepared(prepared)
    scope=validate_scope(scope)
    if scope_digest(scope)!=prepared['envelope']['scope_sha256'] or action(scope,1 if prepared['envelope']['slot']=='http_identify' else 2)!=prepared['action']:rt._fail('invalid_prepared')
    rt.validate_protocol_value('role_readiness',endpoint_identity)
    if endpoint_identity['role']!='endpoint' or endpoint_identity['worker_ready']['runtime_sha256']!=prepared['envelope']['runtime_sha256']:rt._fail('invalid_role')
    role='nmap' if prepared['envelope']['slot']=='http_identify' else 'headers'
    owner=rt._start_role(runtime=runtime,role=role,payload={'prepared':prepared,'endpoint_identity':endpoint_identity,'scope':scope},rights={},
        control=rt._ClippedControl(control,prepared['envelope']['action_deadline_ns']/1e9),expected_net=endpoint_identity['parent_observation']['namespaces']['net'])
    return WaitingClient(owner,prepared,runtime)
