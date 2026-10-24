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


class SupervisedCapture:
    """Host-owned bounded raw capture; no child request/release endpoint."""
    def __init__(self,owner,prepared,runtime):
        self.owner=owner;self.prepared=contract.validate_prepared(prepared);self.runtime=runtime
        self.slot='identify_client' if prepared['envelope']['slot']=='http_identify' else 'headers_client'
        self.maximum=prepared['envelope']['output_limit'];self.buffers={'stdout':bytearray(),'stderr':bytearray()}
        self.eof=set();self.native_deadline_ns=None;self.started_at_ns=None;self.native_ready=None
        self.status=None;self.truncated=False;self.cleanup=None;self.finished=False;self._draining=False
        if owner.ready is None or owner.cleanup is not None:rt._fail('invalid_role')
        for name in self.buffers:os.set_blocking(getattr(owner.process,name).fileno(),False)
    def begin(self,release,control):
        if self.native_deadline_ns is not None:rt._fail('dispatch_replayed')
        with contract._deadline_context(control.deadline):
            control.check();release=contract.validate_release_binding(release,self.prepared,clock=contract.sample_clock())
        control.check();self.owner.pin.check_alive()
        self.started_at_ns=time.monotonic_ns()
        self.native_deadline_ns=min(release['effect_stop_ns'],int(control.deadline*1e9),self.started_at_ns+self.prepared['envelope']['native_timeout_ns'])
        if self.native_deadline_ns<=self.started_at_ns:rt._fail('timeout')
        return {'child_slot':self.slot,'started_at_ns':self.started_at_ns,'native_deadline_ns':self.native_deadline_ns}
    def _check(self,control):
        control.check()
        if self.native_deadline_ns is None:rt._fail('release_unavailable')
        if time.monotonic_ns()>=self.native_deadline_ns:
            self.status='timeout';rt._fail('timeout')
    def drain(self,control):
        if self.finished:return
        self._check(control)
        if self._draining:return
        self._draining=True
        try:
            # One bounded read per pipe per work check; no draining-to-EAGAIN spin.
            for name,buffer in self.buffers.items():
                if name in self.eof:continue
                self._check(control)
                remaining=self.maximum-sum(map(len,self.buffers.values()))
                try:raw=os.read(getattr(self.owner.process,name).fileno(),remaining+1)
                except BlockingIOError:continue
                if not raw:self.eof.add(name);continue
                buffer.extend(raw[:remaining])
                if len(raw)>remaining:
                    self.truncated=True;self.status='output_limit';rt._fail('limit_exceeded')
            self._check(control)
        finally:self._draining=False
    def observe_native(self,control):
        if self.slot!='identify_client' or self.native_ready is not None:rt._fail('invalid_role')
        outer=self
        class DrainingControl:
            clock=control.clock
            cancelled=getattr(control,'cancelled',None)
            deadline=min(control.deadline,outer.native_deadline_ns/1e9)
            def check(self):outer.drain(control)
            def remaining(self):self.check();return max(0,min(control.remaining(),self.deadline-time.monotonic()))
        self.drain(control)
        manifest=next(row for row in self.runtime['roles'] if row['role']=='nmap')
        self.native_ready=rt.observe_native(self.owner.pin,manifest,waiting_image=self.owner.ready['parent_observation']['executable'],control=DrainingControl())
        self.drain(control);return self.native_ready
    def partial(self):
        code=None if self.owner.process is None else self.owner.process.returncode
        return {'stdout':bytes(self.buffers['stdout']),'stderr':bytes(self.buffers['stderr']),
                'exit_code':code,'truncated':self.truncated,'status':self.status or 'unresolved',
                'readiness':self.owner.ready,'native_readiness':self.native_ready,'cleanup':self.cleanup or self.owner.cleanup}
    def _wire(self):
        import base64
        value={'schema_version':'1','slot':self.prepared['envelope']['slot'],'exit_code':self.owner.process.returncode,'truncated':self.truncated}
        for name,buffer in self.buffers.items():
            raw=bytes(buffer);value.update({name+'_base64':base64.b64encode(raw).decode('ascii'),name+'_bytes':len(raw),name+'_sha256':contract.digest(raw)})
        return value
    def capture(self,control):
        if self.finished:rt._fail('dispatch_replayed')
        failure=None
        try:
            while self.eof!=set(self.buffers) or self.owner.process.poll() is None:
                self.drain(control)
                time.sleep(min(.005,max(0,min(control.deadline,self.native_deadline_ns/1e9)-time.monotonic())))
            self._check(control)
            self.status='succeeded' if self.owner.process.returncode==0 else 'failed'
        except BaseException as error:
            failure=error
            if self.status is None:self.status='cancelled' if getattr(error,'code',None)=='engagement_live_cancelled' else 'timeout' if getattr(error,'code',None)=='engagement_live_timeout' else 'unresolved'
        try:
            deadline=rt._failure_deadline(control) if failure is not None else min(control.deadline,time.monotonic()+2)
            self.cleanup=self.owner.close(deadline=deadline)
        except BaseException as error:
            if failure is not None:error.capture_failure=failure
            failure=error;self.cleanup=getattr(error,'cleanup',None);self.status='unresolved'
        self.finished=True
        if failure is None:
            try:self._check(control)
            except BaseException as error:failure=error;self.status='unresolved'
        if failure is not None:
            failure.client_capture=self.partial();raise failure
        return {'capture':self._wire(),'status':self.status,'cleanup':self.cleanup}


class SupervisedWaitingClient:
    """Launcher proxy; only its real inherited channel can release the client."""
    def __init__(self,owner,prepared,runtime,supervisor):
        self.owner=owner;self.prepared=prepared;self.runtime=runtime;self.supervisor=supervisor
        self.ready=owner.ready;self.released=False;self.native_ready=None;self.capture=None;self.native_deadline=None
    def release(self,release,control):
        with contract._deadline_context(control.deadline):
            control.check()
            if self.released:rt._fail('dispatch_replayed')
            release=contract.validate_release_binding(release,self.prepared,clock=contract.sample_clock())
            budget=self.supervisor.native_begin(child_slot=self.owner.slot,release=release,control=control)
            self.native_deadline=budget['native_deadline_ns']/1e9
            bounded=rt._ClippedControl(control,self.native_deadline);bounded.check();self.released=True
            rt._send_bytes(self.owner.channel,rt._json(release),bounded)
            control.check()
    def observe_native(self,control):
        with contract._deadline_context(control.deadline):
            control.check()
            if not self.released or self.prepared['envelope']['slot']!='http_identify':rt._fail('release_unavailable')
            self.native_ready=self.supervisor.observe_native(child_slot=self.owner.slot,control=rt._ClippedControl(control,self.native_deadline))
            control.check()
            return self.native_ready
    def collect(self,control):
        with contract._deadline_context(control.deadline):
            control.check()
            if not self.released or self.capture is not None:rt._fail('release_unavailable')
            value=self.supervisor.capture(child_slot=self.owner.slot,control=rt._ClippedControl(control,self.native_deadline))
            raw=value['capture'];maximum=self.prepared['envelope']['output_limit']
            self.capture={'stdout':rt._meter_bytes(raw['stdout_base64'],maximum),'stderr':rt._meter_bytes(raw['stderr_base64'],maximum),
                'exit_code':raw['exit_code'],'truncated':raw['truncated'],'status':value['status'],
                'readiness':self.ready,'native_readiness':self.native_ready,'cleanup':value['cleanup']}
            control.check()
            return self.capture
    def close(self):return self.owner.close()


def _prepare_supervised_client(*,runtime,prepared,endpoint_identity,scope,control,supervisor):
    from .configurable_scope import validate_scope,scope_digest
    with contract._deadline_context(control.deadline):
        control.check();prepared=contract.validate_prepared(prepared);scope=validate_scope(scope)
        if scope_digest(scope)!=prepared['envelope']['scope_sha256']:rt._fail('invalid_prepared')
        rt.validate_readiness('endpoint',endpoint_identity,runtime)
        control.check()
    slot='identify_client' if prepared['envelope']['slot']=='http_identify' else 'headers_client'
    owner=supervisor.start_child(child_slot=slot,prepared=prepared,control=control)
    return SupervisedWaitingClient(owner,prepared,runtime,supervisor)
