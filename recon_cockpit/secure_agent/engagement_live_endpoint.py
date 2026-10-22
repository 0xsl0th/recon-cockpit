"""Trusted startup and launcher-only ARM for the fixed owned endpoint."""
import os
import socket

from . import engagement_live_contract as contract
from . import engagement_live_runtime as runtime
from . import engagement_live_protocol as protocol


class EndpointOwner:
    def __init__(self,owner,session_opened):
        self.owner=owner;self.ready=owner.ready;self.identity=self.ready
        self.session_opened=session_opened;self.namespace_fds=[]
        try:
            for name in ('user','net'):
                self.namespace_fds.append(os.open('ns/'+name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=owner.pin.directory))
        except BaseException:
            self.close();raise
        self.namespace_fds=tuple(self.namespace_fds)
    def progress(self,control):
        control.check();self.owner.pin.check_alive();return self.ready
    def _interrupt(self):
        try:self.owner.channel.shutdown(socket.SHUT_RDWR)
        except OSError:pass
    def close_namespaces(self):
        descriptors=self.namespace_fds;self.namespace_fds=()
        for fd in descriptors:os.close(fd)
    def _close(self,deadline=None):
        try:self.close_namespaces()
        finally:receipt=self.owner.close(deadline=deadline)
        return receipt
    def close(self):return self._close()


def prepare_endpoint(*,runtime,session_binding,broker_peer,arm_peer,control):
    from . import engagement_live_runtime as rt
    # Public host builder receives the actual full acknowledgment, not a digest.
    transferred=False;rights={}
    peers=[]
    if type(broker_peer)is dict:peers=[broker_peer.get(k) for k in ('host','child','broker_control')]
    peers.append(arm_peer)
    try:
        opened=contract.validate_session_opened(session_binding)
        rt._fields(broker_peer,('host','child','broker_control','endpoint_id'))
        endpoint_id=broker_peer['endpoint_id']
        if type(endpoint_id)is not str or rt._UUID.fullmatch(endpoint_id)is None:rt._fail('invalid_role')
        payload={'session_binding':opened['binding'],'roe':opened['roe'],'scope':opened['scope'],
                 'policy':opened['policy'],'endpoint_id':endpoint_id}
        for purpose,peer in (('broker_control',broker_peer['broker_control']),('launcher_arm',arm_peer)):
            rights[purpose]=peer.detach() if hasattr(peer,'detach') else peer
        transferred=True
        owner=rt._start_role(runtime=runtime,role='endpoint',payload=payload,rights=rights,control=control,
                             stdin_pair=(broker_peer['host'],broker_peer['child']),worker_id=endpoint_id)
    finally:
        if not transferred:
            for fd in rights.values():
                try:os.close(fd)
                except OSError:pass
            for peer in peers:
                if peer is not None:
                    try:
                        if hasattr(peer,'close'):peer.close()
                        elif peer not in rights.values():os.close(peer)
                    except OSError:pass
    return EndpointOwner(owner,opened)


class ArmChannel:
    """Launcher-owned ARM transport; one pending Prepared, monotonic channels."""
    def __init__(self,channel):
        self.socket=channel;self.prepared=None;self.sent=0;self.received=0
    def prepare(self,prepared):
        if self.prepared is not None:runtime._fail('invalid_prepared')
        self.prepared=contract.validate_prepared(prepared)
    def close(self):self.socket.close()


def arm_endpoint(channel,*,release,endpoint_identity,control):
    runtime.validate_protocol_value('role_readiness',endpoint_identity)
    if endpoint_identity['role']!='endpoint':runtime._fail('invalid_role')
    release=contract.validate_release(release)
    if not isinstance(channel,ArmChannel):runtime._fail('invalid_role')
    frame={'schema_version':'1','channel_id':endpoint_identity['worker_ready']['worker_id'],
           'sequence':channel.sent+1,'operation':'ARM','body':{'release':release,'slot':None}}
    # A wrapped launcher channel pins its prepared slot and sequence; bare sockets
    # cannot select arbitrary action metadata from a release digest.
    prepared=getattr(channel,'prepared',None)
    if prepared is None:runtime._fail('invalid_prepared')
    contract.validate_release_binding(release,prepared,clock=contract.sample_clock())
    frame['body']['slot']=prepared['envelope']['slot']
    sock=channel.socket
    protocol.send_packet(sock,frame,role='arm',control=control)
    channel.sent+=1
    ack=protocol.receive_packet(sock,role='arm',control=control)
    if ack['operation']!='ACK' or ack['sequence']!=channel.received+1 or ack['channel_id']!=frame['channel_id']:runtime._fail('invalid_frame')
    channel.received+=1;channel.prepared=None
    value=ack['body']
    if any(value[k]!=release[k] for k in ('session_id','dispatch_id','envelope_sha256','effective_lease_deadline_ns')) or value['endpoint_id']!=frame['channel_id'] or value['go_sha256']!=runtime._hash(release) or value['slot']!=frame['body']['slot']:runtime._fail('invalid_frame')
    return value
