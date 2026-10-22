"""Trusted host custody and bounded RPC for one isolated engagement broker."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
import socket
import math
import select
import stat
import threading
import time
from pathlib import Path
from uuid import uuid4

from . import engagement_live_contract as c


def _pair():
    pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    for channel in pair:
        channel.setblocking(False)
        channel.set_inheritable(False)
    return pair


def _one_way():
    reader, writer = _pair()
    try:
        reader.shutdown(socket.SHUT_WR)
        writer.shutdown(socket.SHUT_RD)
        return reader, writer
    except BaseException:
        reader.close();writer.close();raise


def _memfd(name):
    writer = reader = None
    try:
        writer = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        reader = os.open('/proc/self/fd/' + str(writer), os.O_RDONLY | os.O_CLOEXEC)
        a, b = os.fstat(writer), os.fstat(reader)
        if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
            c.fail('invalid_channel')
        if fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            c.fail('invalid_channel')
        return reader, writer
    except BaseException:
        for fd in (reader, writer):
            if fd is not None:
                os.close(fd)
        raise


def _close(value):
    if type(value) is int:
        os.close(value)
    else:
        value.close()


@contextmanager
def _locked(lock,control):
    """Serialize one channel without waiting beyond its original control."""
    acquired=False
    try:
        while not acquired:
            control.check()
            acquired=lock.acquire(timeout=min(.02,control.remaining()))
        control.check()
        yield
    finally:
        if acquired:lock.release()


class RoleSlot:
    """Private, once-only descriptor custody; never serialized or reconstructed."""
    def __init__(self, owner, index, review_mode):
        self._owner = owner
        self.slot_index = index
        self.reviewer_id = str(uuid4())
        self.review_mode = review_mode
        self.ingress_channel_id = str(uuid4())
        self.launcher_id = str(uuid4())
        self.endpoint_id = str(uuid4())

    @property
    def ingress_host(self):
        return self._owner._peek(f'ingress_host_{self.slot_index}')

    def take_reviewer_bootstrap(self):
        i = self.slot_index
        return self._owner._take_many({'host': f'reviewer_host_{i}', 'child': f'reviewer_child_{i}',
                                      'review_witness': f'approval_writer_{i}'})

    def take_endpoint_bootstrap(self):
        i = self.slot_index
        return self._owner._take_many({'host': f'endpoint_host_{i}', 'child': f'endpoint_child_{i}',
            'broker_control': f'endpoint_peer_{i}', 'launcher_arm': f'arm_endpoint_{i}'})

    def take_launcher_bootstrap(self):
        i = self.slot_index
        return self._owner._take_many({'host': f'launcher_host_{i}', 'child': f'launcher_child_{i}',
            'broker_control': f'launcher_peer_{i}', 'endpoint_arm': f'arm_launcher_{i}'})


class PreallocatedRoleBundle:
    def __init__(self, review_mode):
        c.member(review_mode, {'terminal', 'graphical_v1'})
        self._pid = os.getpid()
        self._owned = {}
        self._closed = False
        self._broker_taken = False
        self.slots = tuple(RoleSlot(self, index, review_mode) for index in range(2))
        self.lifecycle_id = str(uuid4())
        try:
            self._put_pair('host_lifecycle', 'broker_lifecycle')
            self._put_pair('broker_host', 'broker_child')
            self._put_pair('audit_reader', 'audit_writer', one_way=True)
            info=os.fstat(self._owned['audit_reader'].fileno())
            self.audit_source_identity=(info.st_dev,info.st_ino)
            for slot in self.slots:
                i = slot.slot_index
                self._put_pair(f'ingress_host_{i}', f'ingress_broker_{i}')
                self._put_pair(f'launcher_broker_{i}', f'launcher_peer_{i}')
                self._put_pair(f'endpoint_broker_{i}', f'endpoint_peer_{i}')
                self._put_pair(f'approval_reader_{i}', f'approval_writer_{i}', one_way=True)
                self._put_pair(f'arm_launcher_{i}', f'arm_endpoint_{i}')
                for role in ('reviewer', 'endpoint', 'launcher'):
                    self._put_pair(f'{role}_host_{i}', f'{role}_child_{i}')
            for name in ('initial', 'final', 'transcript'):
                reader, writer = _memfd('engagement-live-' + name)
                self._owned[name + '_reader'] = reader
                self._owned[name + '_writer'] = writer
        except BaseException as exc:
            self.close()
            if isinstance(exc, c.LiveError):
                raise
            if isinstance(exc, (OSError, AttributeError)):
                c.fail('unsupported_runtime')
            raise

    def _put_pair(self, left, right, *, one_way=False):
        a, b = _one_way() if one_way else _pair()
        self._owned[left], self._owned[right] = a, b

    def _check(self):
        if os.getpid() != self._pid or self._closed:
            c.fail('invalid_channel')

    def _peek(self, name):
        self._check()
        if name not in self._owned:
            c.fail('invalid_channel')
        return self._owned[name]

    def _take_many(self, mapping):
        self._check()
        if any(name not in self._owned for name in mapping.values()):
            c.fail('invalid_channel')
        return {key: self._owned.pop(name) for key, name in mapping.items()}

    @property
    def host_lifecycle(self):
        return self._peek('host_lifecycle')

    @property
    def evidence_readers(self):
        return {name: self._peek(name + '_reader') for name in ('initial', 'final', 'transcript')}

    def take_evidence_readers(self):
        return self._take_many({name:name+'_reader' for name in ('initial','final','transcript')})

    def take_audit_writer(self):
        return self._take_many({'audit_witness': 'audit_writer'})['audit_witness']

    def take_broker_bootstrap(self, runtime_input):
        self._check()
        if self._broker_taken:
            c.fail('invalid_channel')
        c.integer(runtime_input)
        mapping = {'host': 'broker_host', 'child': 'broker_child', 'host_lifecycle': 'broker_lifecycle',
            'audit_witness': 'audit_reader', 'initial_export_memfd': 'initial_writer',
            'final_export_memfd': 'final_writer', 'transcript_memfd': 'transcript_writer'}
        for i in range(2):
            mapping.update({f'ingress{i}': f'ingress_broker_{i}', f'launcher{i}': f'launcher_broker_{i}',
                f'endpoint{i}': f'endpoint_broker_{i}', f'review_witness{i}': f'approval_reader_{i}'})
        result = self._take_many(mapping)
        self._broker_taken = True
        result['runtime_input'] = runtime_input
        return result

    def take_worker_rights(self, role, *, slot_index=None, runtime_input=None):
        if role == 'broker':
            return self.take_broker_bootstrap(runtime_input)
        c.integer(slot_index, 0, 1)
        slot = self.slots[slot_index]
        if role in {'terminal', 'graphical'}:
            expected = 'terminal' if slot.review_mode == 'terminal' else 'graphical'
            if role != expected:
                c.fail('invalid_role')
            # Intentional TTY is opened/validated by the terminal host builder.
            return slot.take_reviewer_bootstrap()
        if role == 'endpoint':
            return slot.take_endpoint_bootstrap()
        if role == 'launcher':
            return slot.take_launcher_bootstrap()
        c.fail('invalid_role')

    def close(self):
        if os.getpid() != self._pid:
            c.fail('invalid_channel')
        if self._closed:
            return
        self._closed = True
        values, self._owned = self._owned, {}
        error = None
        for value in values.values():
            try:
                _close(value)
            except OSError as exc:
                error = exc
        if error is not None:
            c.fail('cleanup_incomplete')


def preallocate_role_bundle(review_mode):
    return PreallocatedRoleBundle(review_mode)


class _ClippedControl:
    def __init__(self, original, deadline_ns, stop=None):
        self.original, self.stop = original, stop
        self.deadline = min(original.deadline, deadline_ns / c.SECOND)
        if int(self.deadline*c.SECOND)>deadline_ns:
            self.deadline=math.nextafter(self.deadline,-math.inf)
        self.cancelled,self.clock=original.cancelled,original.clock
    def remaining(self):
        if self.stop is not None and self.stop.is_set():c.fail('cancelled')
        self.original.check()
        value=self.deadline-self.clock()
        if value<=0:c.fail('timeout')
        return value
    def check(self):self.remaining()


def _receive_business(channel,control):
    from . import engagement_live_protocol as p
    p._ready(channel,writing=False,control=control)
    raw,ancillary,flags,_=channel.recvmsg(32769,socket.CMSG_SPACE(256),socket.MSG_CMSG_CLOEXEC)
    if ancillary:
        import array
        for level,kind,data in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                fds=array.array('i');fds.frombytes(data[:len(data)-len(data)%fds.itemsize])
                for fd in fds:os.close(fd)
    if ancillary or flags & ~socket.MSG_CMSG_CLOEXEC or not raw or len(raw)>32768:c.fail('invalid_frame')
    value=c.decode(raw)
    if c.canonical(value)!=raw:c.fail('invalid_frame')
    control.check()
    return value


def _validate_business(value,runtime_sha256,broker_id,slots):
    from . import engagement_live_protocol as p
    from .models import parse_policy
    from .configurable_scope import scope_digest
    c.obj(value,('schema_version','allocated_slots','broker_deadline_ns','broker_id','clock_anchor',
        'engagement_id','generation','initial_export','ledger_owner_id','policy','policy_sha256',
        'revision','roe','roe_sha256','runtime_sha256','scope','scope_sha256'))
    if value['schema_version']!='1' or value['broker_id']!=broker_id or value['runtime_sha256']!=runtime_sha256:c.fail('invalid_frame')
    c.uuid(value['ledger_owner_id']);c.uuid(value['engagement_id'])
    c.integer(value['revision'],1,64);c.integer(value['generation'],0,64)
    roe=c.validate_live_roe(value['roe']);policy=c.ledger.policy_for_roe(roe)
    if (value['scope']!=roe['scope'] or value['roe_sha256']!=c.records.roe_digest(roe)
            or value['scope_sha256']!=scope_digest(roe['scope']) or value['policy']!=policy
            or value['policy_sha256']!=parse_policy(policy).digest):c.fail('invalid_prepared')
    anchor=c.ledger.validate_clock(value['clock_anchor'])
    c.integer(value['broker_deadline_ns'],anchor['mono_after_ns']+1,anchor['mono_after_ns']+120*c.SECOND)
    if type(value['allocated_slots'])is not list or len(value['allocated_slots'])!=2:c.fail('invalid_frame')
    seen=set()
    for index,row in enumerate(value['allocated_slots']):
        c.obj(row,('slot_index','session_id','reviewer_id','review_mode'));c.uuid(row['session_id'])
        if (type(row['slot_index'])is not int or row['slot_index']!=index or row['session_id'] in seen
                or row['reviewer_id']!=slots[index].reviewer_id or row['review_mode']!=slots[index].review_mode):c.fail('invalid_frame')
        seen.add(row['session_id'])
    p.validate_export_reference(value['initial_export'])
    if value['initial_export']['phase']!='initial':c.fail('invalid_frame')
    return c.detached(value)


class EngagementBroker:
    """One host-owned process and two independent, serialized ingress channels."""
    def __init__(self,*,runtime,store_directory,control,role_bundle):
        from .execution import ExecutionControl
        from .engagement_live_runtime import validate_runtime
        if type(control)is not ExecutionControl or control.clock is not time.monotonic:c.fail('invalid_input')
        if type(role_bundle)is not PreallocatedRoleBundle:c.fail('invalid_channel')
        self.runtime=validate_runtime(runtime);self.store_directory=Path(store_directory)
        self.control=control;self.bundle=role_bundle;self._pid=os.getpid();self._owner=None
        self._ready=None;self._closed=False;self._stop=threading.Event();self._locks=[threading.Lock(),threading.Lock()]
        self._lifecycle_lock=threading.Lock();self._sequence=[];self._lifecycle=None;self._cleanup=None
        self._parent_fd=self._directory_fd=None;self._observations=[]
        self._sessions={};self._prepared={}
        self._started_ns=time.monotonic_ns();self._deadline_ns=min(int(control.deadline*c.SECOND),self._started_ns+120*c.SECOND)

    def _check(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if self._closed or self._stop.is_set():c.fail('session_unavailable')
        self.control.check()

    @property
    def readiness(self):return None if self._ready is None else c.detached(self._ready)
    @property
    def evidence_readers(self):return self.bundle.evidence_readers
    @property
    def pidfd(self):return None if self._owner is None else self._owner.pin.fd

    def start(self):
        from . import engagement_live_runtime as runtime
        from . import engagement_live_protocol as p
        self._check()
        if self._owner is not None:return self.readiness
        peers=None;input_fd=None
        try:
            requested=self.store_directory.absolute();parent=requested.parent.resolve(strict=True)
            self._parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self._directory_fd=os.open(requested.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self._parent_fd)
            for fd in (self._parent_fd,self._directory_fd):
                info=os.fstat(fd)
                if info.st_uid!=os.getuid() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700:c.fail('invalid_input')
            before=os.fstat(self._directory_fd)
            child_control=_ClippedControl(self.control,self._deadline_ns,self._stop)
            input_fd=runtime._sealed(c.canonical(self.runtime,max_bytes=c.MAX_CANONICAL),name='engagement-live-runtime',control=child_control)
            peers=self.bundle.take_broker_bootstrap(input_fd);input_fd=None
            host,child=peers.pop('host'),peers.pop('child')
            rights={name:peers[name].detach() if isinstance(peers[name],socket.socket) else peers[name] for name in runtime.RIGHTS['broker']}
            peers={}
            payload={'contract_sha256':c.CONTRACT_SHA256,'gates_sha256':c.INVENTORY_SHA256,
                'live_started_at_ns':self._started_ns,'original_broker_deadline_ns':self._deadline_ns,
                'slot_specs':[{'slot_index':s.slot_index,'reviewer_id':s.reviewer_id,'review_mode':s.review_mode,
                    'ingress_channel_id':s.ingress_channel_id} for s in self.bundle.slots],
                'store_directory':'/store/engagement'}
            broker_id=str(uuid4());self._broker_id=broker_id
            self._owner=runtime._start_role(runtime=self.runtime,role='broker',payload=payload,rights=rights,
                control=child_control,stdin_pair=(host,child),worker_id=broker_id,
                extra_mounts=[(self._directory_fd,'/store/engagement')])
            wire=_validate_business(_receive_business(self._owner.channel,child_control),runtime.runtime_digest(self.runtime),broker_id,self.bundle.slots)
            after=os.stat(requested.name,dir_fd=self._parent_fd,follow_symlinks=False)
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):c.fail('invalid_input')
            self._ready={**wire,'readiness':self._owner.ready}
            self._sequence=[p.ChannelSequence(slot.ingress_channel_id,'ingress') for slot in self.bundle.slots]
            self._lifecycle=p.ChannelSequence(broker_id,'lifecycle')
            self.read_export('initial',wire['initial_export'])
            return self.readiness
        except BaseException as error:
            if peers:
                for item in peers.values():
                    try:_close(item)
                    except OSError:pass
            if input_fd is not None:os.close(input_fd)
            try:self.close()
            except BaseException as cleanup_error:
                error.cleanup_error=cleanup_error
                if getattr(cleanup_error,'cleanup',None)is not None:error.startup_cleanup=cleanup_error.cleanup
            else:
                if self._cleanup is not None:error.startup_cleanup=self._cleanup
            if self._owner is not None:error.startup_observation=self._owner.ready['parent_observation']
            raise
        finally:
            for name in ('_directory_fd','_parent_fd'):
                fd=getattr(self,name)
                if fd is not None:setattr(self,name,None);os.close(fd)

    def read_export(self,phase,reference):
        from . import engagement_live_protocol as p
        p.validate_export_reference(reference)
        if reference['phase']!=phase:c.fail('evidence_invalid')
        fd=self.evidence_readers[phase];info=os.fstat(fd)
        if ((info.st_dev,info.st_ino)!=(reference['device'],reference['inode'])
                or info.st_size!=reference['bytes'] or fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=15
                or fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY):c.fail('evidence_invalid')
        raw=os.pread(fd,reference['bytes']+1,0)
        if len(raw)!=reference['bytes'] or c.digest(raw)!=reference['sha256']:c.fail('evidence_invalid')
        value=c.ledger.decode_export(raw)
        if c.ledger.canonical(value)!=raw:c.fail('evidence_invalid')
        return value

    def _rpc(self,operation,body,ingress=0,*,control=None,deadline_ns=None):
        from . import engagement_live_protocol as p
        self._check();c.integer(ingress,0,1)
        if self._owner is None:c.fail('session_unavailable')
        phase=_ClippedControl(self.control if control is None else control,
            min(self._deadline_ns,self._deadline_ns if deadline_ns is None else deadline_ns),self._stop)
        with _locked(self._locks[ingress],phase):
            self._check();sequence=self._sequence[ingress];channel=self.bundle.slots[ingress].ingress_host
            request=sequence.make(operation,body)
            p.send_packet(channel,request,role='ingress',control=phase)
            self._observations.append(('sent',request))
            pending=False
            while True:
                reply=sequence.accept(p.receive_packet(channel,role='ingress',control=phase))
                p.require_reply(reply,request,role='ingress');self._observations.append(('received',reply))
                data=reply['body']
                if data['status']=='pending':
                    if pending:c.fail('invalid_frame')
                    pending=True;continue
                if data['status']=='refused':raise c.LiveError(data['code'])
                return data['data']

    def open_session(self,*,ingress=0):
        value=c.validate_session_opened(self._rpc('OPEN_SESSION',{'slot_index':ingress},ingress))
        identity=value['binding']['session_id']
        if identity in self._sessions or len(self._sessions)>=2:c.fail('session_unavailable')
        self._sessions[identity]=value
        return value
    def prepare(self,session_id,slot,*,ingress=0):
        opened=self._sessions.get(session_id)
        if opened is None:c.fail('session_unavailable')
        deadline=min(opened['binding']['session_deadline_ns'],time.monotonic_ns()+30*c.SECOND)
        reply=self._rpc('PREPARE',{'session_id':session_id,'slot':slot},ingress,deadline_ns=deadline)
        prepared=c.validate_prepared_context(reply['prepared'],opened)
        if prepared['envelope']['slot']!=slot:c.fail('invalid_prepared')
        digest=c.prepared_digest(prepared)
        if digest in self._prepared or len(self._prepared)>=4:c.fail('dispatch_replayed')
        self._prepared[digest]=prepared
        return reply
    def dispatch(self,prepared_sha256,reference_sha256,consume_sequence,audit_sequence,*,ingress=0):
        return self._dispatch_with_control(prepared_sha256,reference_sha256,consume_sequence,audit_sequence,ingress=ingress,control=self.control)
    def _dispatch_with_control(self,prepared_sha256,reference_sha256,consume_sequence,audit_sequence,*,ingress=0,control):
        prepared=self._prepared.get(prepared_sha256)
        # An unknown digest still reaches the isolated broker's closed refusal
        # boundary, but receives only a bounded exchange, never a new action.
        deadline=time.monotonic_ns()+2*c.SECOND if prepared is None else prepared['envelope']['action_deadline_ns']
        return self._rpc('DISPATCH',dict(prepared_sha256=prepared_sha256,reference_sha256=reference_sha256,consume_sequence=consume_sequence,audit_sequence=audit_sequence),ingress,
            control=control,deadline_ns=deadline)
    def cancel(self,session_id):
        return self._rpc('CANCEL',{'session_id':session_id},self._idle_ingress())
    def _idle_ingress(self):
        for index,lock in enumerate(self._locks):
            if not lock.locked():return index
        # Cancellation must not wait behind a blocked dispatch. The fixed
        # lifecycle STOP has no renewable/affirmative behavior.
        self._lifecycle_send('STOP',{'reason':'engagement_live_cancelled'})
        c.fail('cancelled')
    def revoke(self,*,expected_revision,expected_generation,event_id):
        return self._rpc('REVOKE',dict(expected_revision=expected_revision,expected_generation=expected_generation,event_id=event_id),self._idle_ingress())
    def snapshot(self):return self._rpc('SNAPSHOT',None,self._idle_ingress())

    def _lifecycle_send(self,operation,body):
        from . import engagement_live_protocol as p
        self._check()
        if self._lifecycle is None:c.fail('session_unavailable')
        phase=_ClippedControl(self.control,min(self._deadline_ns,time.monotonic_ns()+2*c.SECOND),self._stop)
        with _locked(self._lifecycle_lock,phase):
            frame=self._lifecycle.make(operation,body)
            p.send_packet(self.bundle.host_lifecycle,frame,role='lifecycle',control=phase)
    def observe_role(self,slot_index,role,readiness):
        return self._lifecycle_send('ROLE_OBSERVED',dict(slot_index=slot_index,role=role,readiness=readiness))
    def observe_audit(self,readiness):return self._lifecycle_send('AUDIT_OBSERVED',readiness)
    def poll_lifecycle(self):
        from . import engagement_live_protocol as p
        if self._owner is None:return None
        if not select.select([self.bundle.host_lifecycle],[],[],0)[0]:return None
        phase=_ClippedControl(self.control,min(self._deadline_ns,time.monotonic_ns()+2*c.SECOND))
        frame=self._lifecycle.accept(p.receive_packet(self.bundle.host_lifecycle,role='lifecycle',control=phase))
        if frame['operation'] not in {'SESSION_STOP','BROKER_STOP'}:c.fail('invalid_frame')
        return frame

    def _interrupt(self):
        if os.getpid()!=self._pid:c.fail('foreign_owner')
        self._stop.set()
        if self._owner is not None:
            # EOF is terminal and requests the worker's bounded final snapshot.
            try:self._owner.channel.shutdown(socket.SHUT_WR)
            except OSError:pass

    def _close(self,deadline):
        from .engagement_live_runtime import cleanup_owned
        if os.getpid()!=self._pid:c.fail('foreign_owner')
        if self._closed:return self._cleanup
        self._interrupt();self._closed=True
        if self._owner is None:
            self.bundle.close()
            return None
        try:
            while self._owner.process.poll() is None and time.monotonic()<deadline-.05:
                time.sleep(min(.005,max(0,deadline-.05-time.monotonic())))
            self._cleanup=cleanup_owned([self._owner.process],[self._owner.pin],deadline=deadline)
            self._owner.cleanup=self._cleanup
            self._retained_evidence_readers=self.bundle.take_evidence_readers()
            self.bundle.close()
            return self._cleanup
        finally:
            self._owner.channel.close()
            if not hasattr(self,'_retained_evidence_readers'):
                self.bundle.close()

    def close(self):return self._close(time.monotonic()+2)

    def close_evidence(self,*,deadline=None):
        """Transfer, copy and close the RO memfds only after observed reaping.

        A missing final seal remains partial evidence. It is never substituted
        by reopening SQLite or by promoting the last acknowledged snapshot.
        """
        from .engagement_live_runtime import _descriptor
        if os.getpid()!=self._pid:c.fail('foreign_owner')
        if not self._closed or self._cleanup is None or self._cleanup['status']!='complete':c.fail('cleanup_incomplete')
        if hasattr(self,'_saved_evidence'):return self._saved_evidence
        limit=min(time.monotonic()+2,deadline if deadline is not None else float('inf'))
        readers=getattr(self,'_retained_evidence_readers',None)
        if readers is None:c.fail('evidence_invalid')
        self._retained_evidence_readers=None
        result={'broker_id':self._ready['broker_id'] if self._ready else None,
            'initial':None,'final':None,'transcript':None}
        descriptors={row['purpose']:row for row in self._owner.bootstrap['descriptors']}
        try:
            for phase,fd in readers.items():
                c._check_deadline(limit);before=os.fstat(fd);seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS)
                if not stat.S_ISREG(before.st_mode) or not 0<=before.st_size<=c.MAX_CANONICAL:c.fail('evidence_invalid')
                raw=os.pread(fd,before.st_size+1,0);after=os.fstat(fd)
                if len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):c.fail('evidence_invalid')
                purpose='transcript_memfd' if phase=='transcript' else phase+'_export_memfd'
                host=_descriptor(fd,purpose);host['kind']='regular'
                broker={**descriptors[purpose],'kind':'regular'}
                if (host['device'],host['inode'])!=(broker['device'],broker['inode']) or host['flags']&os.O_ACCMODE!=os.O_RDONLY or broker['flags']&os.O_ACCMODE!=os.O_RDWR:c.fail('evidence_invalid')
                if phase=='transcript':
                    result[phase]={'raw':raw,'bytes':len(raw),'sha256':c.digest(raw),'seals':seals,
                        'status':'sealed_complete' if seals==15 else 'reaped_partial',
                        'host_descriptor':host,'broker_descriptor':broker}
                elif raw and seals==15:
                    value=c.ledger.decode_export(raw)
                    if c.ledger.canonical(value)!=raw:c.fail('evidence_invalid')
                    reference={'bytes':len(raw),'device':before.st_dev,'inode':before.st_ino,'phase':phase,'seals':15,'sha256':c.digest(raw)}
                    if phase=='initial' and self._ready is not None and reference!=self._ready['initial_export']:c.fail('evidence_invalid')
                    result[phase]={'raw':raw,'reference':reference,'host_descriptor':host,'broker_descriptor':broker}
            c._check_deadline(limit)
        finally:
            close_error=None
            for fd in readers.values():
                try:os.close(fd)
                except OSError as error:close_error=error
            if close_error is not None:raise close_error
        c._check_deadline(limit)
        self._saved_evidence=result
        return result
