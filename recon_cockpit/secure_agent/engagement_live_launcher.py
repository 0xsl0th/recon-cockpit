"""Host custody of one fixed launcher; authority arrives only from the broker."""
import os
import socket
import threading
import time

from . import engagement_live_contract as c


class EngagementLauncher:
    def __init__(self,runtime,*,endpoint,role_slot):
        from .engagement_live_runtime import validate_runtime
        self.runtime=validate_runtime(runtime);self.endpoint=endpoint;self.slot=role_slot
        self._pid=os.getpid();self._owner=None;self._opened=None;self._closed=False;self._cleanup=None
        self._prepared={}
        self._stop=threading.Event()

    @property
    def readiness(self):return None if self._owner is None else c.detached(self._owner.ready)

    def _check(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if self._closed or self._stop.is_set():c.fail('session_unavailable')

    def start(self,session_binding,role_bundle,control):
        from . import engagement_live_runtime as rt
        from .engagement_live_broker import _ClippedControl
        self._check()
        if self._owner is not None:c.fail('session_unavailable')
        opened=c.validate_session_opened(session_binding);binding=opened['binding']
        if self.slot not in role_bundle.slots or binding['reviewer_id']!=self.slot.reviewer_id:c.fail('invalid_role')
        rt.validate_readiness('endpoint',self.endpoint.ready,self.runtime)
        peers=self.slot.take_launcher_bootstrap();rights={}
        try:
            for key in ('broker_control','endpoint_arm'):rights[key]=peers.pop(key).detach()
            transferred,rights=rights,{}
            self._owner=rt._start_role(runtime=self.runtime,role='launcher',payload={
                'session_binding':binding,'roe':opened['roe'],'scope':opened['scope'],'policy':opened['policy'],
                'endpoint_identity':self.endpoint.identity},rights=transferred,
                control=_ClippedControl(control,opened['binding']['session_deadline_ns'],self._stop),
                stdin_pair=(peers.pop('host'),peers.pop('child')),
                namespace_fds=self.endpoint.namespace_fds,
                expected_net=self.endpoint.identity['parent_observation']['namespaces']['net'],
                worker_id=self.slot.launcher_id)
            self._opened=opened
            return self.readiness
        finally:
            for peer in peers.values():peer.close()
            for fd in rights.values():os.close(fd)

    def prepare(self,prepared,control):
        """Check the host's already acknowledged preparation, with no new RPC."""
        self._check();control.check()
        if self._owner is None:c.fail('session_unavailable')
        self._owner.pin.check_alive()
        value=c.validate_prepared_context(prepared,self._opened)
        did=value['envelope']['dispatch_id']
        if did in self._prepared or len(self._prepared)>=2:c.fail('dispatch_replayed')
        self._prepared[did]=value
        control.check()
        return value

    def _interrupt(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        self._stop.set()
        if self._owner is not None:
            try:self._owner.channel.shutdown(socket.SHUT_RDWR)
            except OSError:pass

    def _close(self,deadline):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if self._closed:return self._cleanup
        self._interrupt();self._closed=True
        if self._owner is not None:self._cleanup=self._owner.close(deadline=deadline)
        return self._cleanup

    def close(self):return self._close(time.monotonic()+2)

    def evidence(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if not self._closed:c.fail('cleanup_incomplete')
        # Children and captures are observed by this isolated launcher and sent
        # through its broker channel. The host never invents their observations.
        return {'readiness':self.readiness,'cleanup':self._cleanup}
