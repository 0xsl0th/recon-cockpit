"""Original-deadline adapter for the unchanged isolated append-only writer."""
from __future__ import annotations

import array
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import threading
import time
from uuid import uuid4

from . import audit_protocol as legacy
from . import engagement_live_contract as c
from .engagement_live_broker import _ClippedControl,_locked
from .engagement_live_witness import validate_started_event


class EngagementAuditService:
    def __init__(self,audit_path,*,runtime,role_bundle,control):
        from .execution import ExecutionControl
        from .engagement_live_runtime import validate_runtime
        if type(control)is not ExecutionControl or control.clock is not time.monotonic:c.fail('invalid_input')
        self.runtime=validate_runtime(runtime);self.path=Path(audit_path)
        self.bundle=role_bundle;self.control=control;self._pid=os.getpid();self.writer_id=str(uuid4())
        self._lock=threading.Lock();self._stop=threading.Event();self._closed=False
        self._process=self._channel=self._pin=None;self._ready=None;self._cleanup=None
        self._sequence=0;self._file_identity=None;self._parent=None;self._parent_identity=None
        self._buffer=bytearray();self._observations=[]

    @property
    def readiness(self):return None if self._ready is None else c.detached(self._ready)
    def _check(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if self._closed or self._stop.is_set():c.fail('audit_unavailable')
        self.control.check()
    def _phase(self,control):
        return _ClippedControl(control,min(int(self.control.deadline*c.SECOND),time.monotonic_ns()+2*c.SECOND),self._stop)

    def _reply(self,control,*,info_fd=None):
        info=bytearray()
        while True:
            control.check()
            if self._process.poll() is not None:c.fail('audit_unavailable')
            if b'\n' in self._buffer and (info_fd is None or info):
                if self._buffer.count(b'\n')!=1 or not self._buffer.endswith(b'\n'):c.fail('audit_unavailable')
                if info_fd is not None:
                    try:c.decode(bytes(info),max_bytes=4096)
                    except c.LiveError:pass
                    else:break
                else:break
            fds=[self._process.stdout,self._process.stderr]
            if info_fd is not None:fds.append(info_fd)
            ready=select.select(fds,[],[],min(.02,control.remaining()))[0]
            for item in ready:
                fd=item if type(item)is int else item.fileno()
                try:raw=os.read(fd,4096)
                except BlockingIOError:continue
                if item==self._process.stderr:
                    if raw:c.fail('audit_unavailable')
                elif item==self._process.stdout:
                    if not raw:c.fail('audit_unavailable')
                    self._buffer.extend(raw)
                    if len(self._buffer)>2048:c.fail('limit_exceeded')
                else:
                    info.extend(raw)
                    if len(info)>4096:c.fail('limit_exceeded')
        raw=bytes(self._buffer[:-1]);self._buffer.clear()
        value=legacy.decode(raw)
        if legacy.encode(value)!=raw:c.fail('audit_unavailable')
        control.check()
        return value,bytes(info)

    def _verify_path(self):
        if self._parent is None:c.fail('audit_unavailable')
        current=os.fstat(self._parent)
        if (current.st_dev,current.st_ino)!=self._parent_identity:c.fail('audit_unavailable')
        info=os.stat(self.path.name,dir_fd=self._parent,follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or info.st_size>legacy.MAX_FILE_BYTES
                or (info.st_dev,info.st_ino)!=self._file_identity):c.fail('audit_unavailable')
        return info

    def start(self):
        from . import engagement_live_runtime as runtime
        from .audit import AuditSink
        self._check()
        if self._process is not None:return self.readiness
        snapshot=source=child=writer=None;info_read=info_write=None
        try:
            phase=_ClippedControl(self.control,min(int(self.control.deadline*c.SECOND),time.monotonic_ns()+10*c.SECOND),self._stop)
            snapshot=runtime._snapshot_audit(self.runtime,phase)
            self._channel,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self._channel.setblocking(False);child.setblocking(False)
            writer=self.bundle.take_audit_writer()
            self.path=self.path.absolute()
            if self.path.name=='records.sqlite3':c.fail('invalid_input')
            self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            parent=self.path.parent.resolve(strict=True)
            self._parent=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            parent_info=os.fstat(self._parent);self._parent_identity=(parent_info.st_dev,parent_info.st_ino)
            if parent_info.st_uid!=os.getuid() or stat.S_IMODE(parent_info.st_mode)!=0o700:c.fail('audit_unavailable')
            try:os.stat('records.sqlite3',dir_fd=self._parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:c.fail('invalid_input')
            # The unchanged sink opens through the held parent, so its append
            # descriptor cannot switch to a substituted pathname parent.
            source=AuditSink(Path('/proc/self/fd')/str(self._parent)/self.path.name)
            info=os.fstat(source._fd);self._file_identity=(info.st_dev,info.st_ino)
            self._verify_path()
            identity=os.fstat(writer.fileno())
            initial={'version':'1','writer_id':self.writer_id,'device':info.st_dev,'inode':info.st_ino,
                     'witness':[identity.st_dev,identity.st_ino]}
            observer=runtime._observer();info_read,info_write=os.pipe2(os.O_CLOEXEC)
            argv=['/usr/bin/bwrap','--unshare-user','--unshare-net','--unshare-pid','--unshare-ipc','--unshare-uts','--unshare-cgroup',
                '--uid','0','--gid','0','--cap-drop','ALL','--die-with-parent','--new-session','--as-pid-1','--info-fd',str(info_write),
                '--clearenv','--setenv','LC_ALL','C','--chdir','/','--proc','/proc','--dev','/dev',
                '--ro-bind',snapshot.stdlib,snapshot.stdlib,'--tmpfs',snapshot.stdlib+'/lib-dynload']
            snapshot.mounts(argv)
            argv+=['--remount-ro','/proc','--remount-ro','/dev','--remount-ro','/','/usr/bin/python3','-I','-S','/app/audit_worker.py',
                self.writer_id,*(observer['namespaces'][name] for name in ('user','net','mnt','pid')),'launch-witness']
            phase.check()
            self._process=subprocess.Popen(argv,stdin=child,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                pass_fds=(*snapshot.pass_fds,info_write),close_fds=True,start_new_session=True)
            self._process._engagement_role='audit';child.close();child=None
            os.close(info_write);info_write=None;snapshot.close();snapshot=None
            for stream in (self._process.stdout,self._process.stderr):os.set_blocking(stream.fileno(),False)
            os.set_blocking(info_read,False)
            from .engagement_live_protocol import _ready
            _ready(self._channel,writing=True,control=phase)
            raw=legacy.encode(initial)
            if self._channel.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[source._fd,writer.fileno()]))],socket.MSG_DONTWAIT)!=len(raw):c.fail('audit_unavailable')
            source.close();source=None;writer.close();writer=None
            ready,info_raw=self._reply(phase,info_fd=info_read)
            expected={'version':'1','writer_id':self.writer_id,'ready':True,'checks':dict.fromkeys(legacy.CHECKS,True)}
            if ready!=expected:c.fail('audit_unavailable')
            phase.check()
            with c._deadline_context(phase.deadline):
                self._pin=runtime._observe_legacy_audit(info_raw=info_raw,process=self._process,bundle=self.runtime,observer=observer,control=phase,initial=initial)
                current=self._verify_path()
                reader_dev,reader_ino=self.bundle.audit_source_identity
                self._ready={'schema_version':'1','writer_id':self.writer_id,'initial':initial,'ready':ready,
                    'source_manifest':{'version':'1','writer_id':self.writer_id,'device':reader_dev,'inode':reader_ino},
                    'append_identity':{'device':current.st_dev,'inode':current.st_ino,'mode':current.st_mode,
                        'uid':current.st_uid,'gid':current.st_gid,'links':current.st_nlink,'size':current.st_size},
                    'parent_observation':self._pin.receipt,'import_image':self._pin.import_image}
                from .engagement_live_witness import validate_audit_runtime_binding
                validate_audit_runtime_binding(self._ready,self.runtime)
                phase.check();return self.readiness
        except BaseException as error:
            try:self.close()
            except c.LiveError as cleanup_error:
                error.startup_cleanup=getattr(cleanup_error,'cleanup',None)
            else:error.startup_cleanup=self._cleanup
            if self._pin is not None:error.startup_observation=self._pin.receipt
            raise
        finally:
            for item in (snapshot,source,child,writer):
                if item is not None:item.close()
            for fd in (info_read,info_write):
                if fd is not None:os.close(fd)

    def emit(self,event,*,control):
        from .engagement_live_protocol import _ready,send_once
        self._check();event=validate_started_event(event)
        phase=self._phase(control)
        with _locked(self._lock,phase):
            self._check();phase.check();self._verify_path()
            if self._process is None:c.fail('audit_unavailable')
            for pipe in (self._process.stdout,self._process.stderr):
                if select.select([pipe],[],[],0)[0]:c.fail('audit_unavailable')
            sequence=self._sequence+1
            if sequence>legacy.MAX_EVENTS:c.fail('limit_exceeded')
            request={'version':'1','writer_id':self.writer_id,'sequence':sequence,'event':event}
            event_raw=legacy.request(request,self.writer_id,sequence);raw=legacy.encode(request)
            _ready(self._channel,writing=True,control=phase)
            try:
                if send_once(self._channel,raw)!=len(raw):c.fail('audit_unavailable')
                reply,_=self._reply(phase)
                if reply!=legacy.receipt(self.writer_id,sequence,event_raw):c.fail('audit_not_durable')
                self._verify_path();phase.check();self._sequence=sequence
                self._observations.append({'request':request,'reply':reply})
                return c.detached(reply)
            except OSError as error:
                self._interrupt()
                raise c.LiveError('engagement_live_audit_unavailable') from error
            except BaseException:
                self._interrupt();raise

    def _interrupt(self):
        if self._pid!=os.getpid():c.fail('foreign_owner')
        self._stop.set()
        if self._channel is not None:
            try:self._channel.shutdown(socket.SHUT_RDWR)
            except OSError:pass

    def _close(self,deadline):
        from .engagement_live_runtime import cleanup_owned
        self._interrupt()
        if self._closed:return self._cleanup
        self._closed=True
        try:
            if self._channel is not None:self._channel.close()
            if self._process is not None:
                self._cleanup=cleanup_owned([self._process],[] if self._pin is None else [self._pin],deadline=deadline)
            return self._cleanup
        finally:
            if self._parent is not None:os.close(self._parent);self._parent=None
    def close(self):return self._close(time.monotonic()+2)

    def saved_log(self, *, deadline):
        """Copy the actual closed writer's file; never repair or reopen a writer."""
        if self._pid!=os.getpid():c.fail('foreign_owner')
        if not self._closed or self._cleanup is None or self._cleanup['status']!='complete':c.fail('cleanup_incomplete')
        if self._file_identity is None or self._parent_identity is None:c.fail('audit_unavailable')
        parent=fd=None
        try:
            c._check_deadline(deadline)
            parent=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            info=os.fstat(parent)
            if ((info.st_dev,info.st_ino)!=self._parent_identity or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)!=0o700):c.fail('audit_unavailable')
            before=os.stat(self.path.name,dir_fd=parent,follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600
                    or before.st_nlink!=1 or before.st_size>legacy.MAX_FILE_BYTES
                    or (before.st_dev,before.st_ino)!=self._file_identity):c.fail('audit_unavailable')
            fd=os.open(self.path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            stamp=lambda i:(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
            if stamp(os.fstat(fd))!=stamp(before):c.fail('audit_unavailable')
            copies=[]
            for _ in range(2):
                offset=0;parts=[]
                while offset<=legacy.MAX_FILE_BYTES:
                    c._check_deadline(deadline)
                    raw=os.pread(fd,min(65536,legacy.MAX_FILE_BYTES+1-offset),offset)
                    if not raw:break
                    parts.append(raw);offset+=len(raw)
                if offset>legacy.MAX_FILE_BYTES:c.fail('limit_exceeded')
                copies.append(b''.join(parts))
            if copies[0]!=copies[1] or len(copies[0])!=before.st_size or stamp(os.fstat(fd))!=stamp(before) or stamp(os.stat(self.path.name,dir_fd=parent,follow_symlinks=False))!=stamp(before):c.fail('audit_unavailable')
            result=copies[0]
        except OSError as error:
            raise c.LiveError('engagement_live_audit_unavailable') from error
        finally:
            if fd is not None:os.close(fd)
            if parent is not None:os.close(parent)
        c._check_deadline(deadline)
        return result
