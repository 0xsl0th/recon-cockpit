"""Owned endpoint: one finite HTTP effect and actual application-byte meter."""
import os
import sys

ENTRY_VERIFIED=False
if __name__=='__main__':
    for _name in os.listdir('/proc/self/fd'):
        if int(_name)<=2:continue
        try:os.fstat(int(_name))
        except OSError:continue
        raise SystemExit(78)
    ENTRY_VERIFIED=True
    sys.path.insert(0,'/app')

import base64
import errno
import hashlib
import json
import select
import socket
import time

from recon_cockpit.secure_agent import engagement_live_runtime as runtime
from recon_cockpit.secure_agent import engagement_live_contract as contract
from recon_cockpit.secure_agent import engagement_live_protocol as protocol

IDENTIFY_REQUEST=b'GET / HTTP/1.0\r\n\r\n'
IDENTIFY_RESPONSE=b'HTTP/1.0 200 OK\r\nServer: nginx/1.26.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'


def headers_request(scope):
    selected=scope['http']
    return ('GET / HTTP/1.1\r\nHost: '+selected['target']+':'+str(selected['port'])+'\r\nConnection: close\r\n\r\n').encode('ascii')


# Exact accepted configurable_lab_worker.header_response bytes are copied below;
# endpoint leaves do not import fixture servers or keys.
HEADER_RESPONSE = b'HTTP/1.1 200 Owned\r\nContent-Length: 205\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<!doctype html><html lang="en"><meta charset="utf-8"><title>HarborDesk training portal</title><h1>HarborDesk</h1><p>Owned synthetic HTTP headers fixture.</p><!-- recon-harbordesk-http-headers-v1 --></html>'


class Meter:
    def __init__(self,prepared,endpoint_id,scope):
        self.prepared=contract.validate_prepared(prepared);self.envelope=self.prepared['envelope']
        self.endpoint_id=endpoint_id;self.scope=scope;self.slot=self.envelope['slot']
        self.max_connections=3 if self.slot=='http_identify' else 1
        self.request_limit=4096 if self.slot=='http_identify' else 256
        self.response_limit=4096 if self.slot=='http_identify' else 2048
        self.expected=IDENTIFY_REQUEST if self.slot=='http_identify' else headers_request(scope)
        self.reply=IDENTIFY_RESPONSE if self.slot=='http_identify' else HEADER_RESPONSE
        self.requests=bytearray();self.responses=bytearray();self.events=[];self.connections=0
        self.release=None;self.armed_at=None;self.finished_at=None;self.reason=None;self.cancelled=False
        self.current=bytearray();self.reply_offset=0;self.responded=False
    def check(self):
        if self.cancelled or self.reason is not None:runtime._fail('cancelled')
        if self.release is None:runtime._fail('release_unavailable')
        contract.validate_release_binding(self.release,self.prepared,clock=contract.sample_clock())
    def _event(self,kind,*,requested=0,actual=0,before=0,reason=None,at=None):
        row={'sequence':len(self.events)+1,'connection':self.connections,'kind':kind,'monotonic_ns':time.monotonic_ns() if at is None else at,
             'requested_bytes':requested,'actual_bytes':actual,'remaining_before':before,'remaining_after':before-actual,'reason':reason}
        if len(self.events)>=64:runtime._fail('limit_exceeded')
        self.events.append(row)
    def _capacity(self,maximum_payload=0):
        if len(self.events)>=60: self.stop('transcript_limit');runtime._fail('limit_exceeded')
        projected=len(runtime._json(self._snapshot(known=False)))+((maximum_payload+2)//3)*4+512+2048
        if projected>32768:self.stop('transcript_limit');runtime._fail('limit_exceeded')
    def arm(self,release):
        if self.cancelled or self.release is not None or self.reason is not None:runtime._fail('release_unavailable')
        self.release=contract.validate_release_binding(release,self.prepared,clock=contract.sample_clock())
        self.armed_at=time.monotonic_ns();self._event('arm',at=self.armed_at)
    def admit(self):
        self.check();self._capacity()
        if self.connections>=self.max_connections:self.stop('connection_limit');runtime._fail('meter_refused')
        self.connections+=1;self.current.clear();self.reply_offset=0;self._event('accept')
        return self.connections
    def _stream_terminated(self,kind):
        self._event(kind)
        # b'' is only the Meter-to-run_loop close signal, not a fabricated recv
        # result. The retained event distinguishes an actual EOF from a reset.
        if not self.current and self.slot=='http_identify' and self.connections in (1,2):return b''
        self.stop('peer_eof');runtime._fail('meter_refused')
    def receive(self,stream):
        self.check()
        left=self.request_limit-len(self.requests)
        if left<=0:self.stop('request_limit');runtime._fail('meter_refused')
        self._capacity(left)
        try:raw=stream.recv(left)
        except BlockingIOError:return None
        except ConnectionResetError as error:
            if error.errno!=errno.ECONNRESET:raise
            return self._stream_terminated('reset')
        if not raw:return self._stream_terminated('eof')
        self.requests.extend(raw);self.current.extend(raw)
        self._event('recv',requested=left,actual=len(raw),before=left)
        if not self.expected.startswith(self.current):self.stop('malformed_request');runtime._fail('meter_refused')
        if self.current==self.expected:
            if self.slot=='http_identify' and self.connections not in (2,3):self.stop('malformed_request');runtime._fail('meter_refused')
            return self.reply
        return None
    def send(self,stream):
        self.check()
        left=self.response_limit-len(self.responses)
        if left<=0:self.stop('response_limit');runtime._fail('meter_refused')
        payload=self.reply[self.reply_offset:self.reply_offset+left]
        if not payload:runtime._fail('meter_refused')
        self._capacity(len(payload))
        try:count=stream.send(payload)
        except BlockingIOError:return False
        if count<=0:self.stop('peer_eof');runtime._fail('meter_refused')
        self.responses.extend(payload[:count]);self.reply_offset+=count
        self._event('send',requested=len(payload),actual=count,before=left)
        if self.reply_offset==len(self.reply):
            self.responded=True;self.stop('complete');return True
        return False
    def stop(self,reason):
        if self.reason is None:
            if reason not in runtime.SPEC['output_and_evidence']['reason_enum']:runtime._fail('invalid_input')
            self.reason=reason;self.finished_at=time.monotonic_ns()
            self._event('close',reason=reason,at=self.finished_at)
    def cancel(self,reason='cancelled'):
        self.cancelled=True
        if self.reason is None and self.release is not None:
            self._event('cancel',reason=reason);self.stop(reason)
    def _snapshot(self,known):
        return {'schema_version':'1','endpoint_id':self.endpoint_id,'session_id':self.envelope['session_id'],
            'dispatch_id':self.envelope['dispatch_id'],'envelope_sha256':contract.envelope_digest(self.envelope),
            'go_sha256':runtime._hash(self.release) if self.release else '0'*64,'arm_sequence':1,'slot':self.slot,
            'accepted_connections':self.connections if known else None,'received_request_bytes':len(self.requests) if known else None,
            'sent_response_bytes':len(self.responses) if known else None,'request_sha256':hashlib.sha256(self.requests).hexdigest(),
            'response_sha256':hashlib.sha256(self.responses).hexdigest(),'request_base64':base64.b64encode(self.requests).decode('ascii'),
            'response_base64':base64.b64encode(self.responses).decode('ascii'),'reason':self.reason or 'unresolved','delivery_known':known,
            'armed_at_ns':self.armed_at,'finished_at_ns':self.finished_at if known else None,'events':list(self.events)}
    def snapshot(self):
        if self.release is None:return None
        return self._snapshot(self.reason is not None)


def _nft_child_limits():
    import resource
    bounds=runtime.SPEC['resources']['setup_helper']
    for kind,value in ((resource.RLIMIT_AS,bounds['as_mib']*1048576),
                       (resource.RLIMIT_CPU,bounds['cpu_seconds']),
                       (resource.RLIMIT_NOFILE,bounds['nofile']),
                       (resource.RLIMIT_NPROC,bounds['nproc']),
                       (resource.RLIMIT_FSIZE,bounds['fsize_bytes']),
                       (resource.RLIMIT_CORE,0)):
        hard=resource.getrlimit(kind)[1]
        limit=value if hard==resource.RLIM_INFINITY else min(value,hard)
        resource.setrlimit(kind,(limit,limit))


def _run_nft(rules,check,deadline_ns):
    """Fixed helper, bounded pipes and one original setup phase deadline."""
    import subprocess
    if type(rules)is not bytes or not 1<=len(rules)<=4096 or type(check)is not bool:runtime._fail('invalid_input')
    end=min(deadline_ns,time.monotonic_ns()+2000000000)
    runtime._check(deadline_ns=end)
    process=subprocess.Popen(['/usr/sbin/nft',*(['-c'] if check else []),'-f','-'],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,
        start_new_session=True,preexec_fn=_nft_child_limits)
    offset=0;inputs=process.stdin;reads=[process.stdout,process.stderr]
    try:
        for pipe in (process.stdin,process.stdout,process.stderr):os.set_blocking(pipe.fileno(),False)
        while inputs is not None or reads or process.poll()is None:
            runtime._check(deadline_ns=end)
            readable,writable,_=select.select(reads,[inputs] if inputs is not None else [],[],min(.01,max(0,(end-time.monotonic_ns())/1e9)))
            if writable:
                count=os.write(inputs.fileno(),rules[offset:])
                if count<=0:runtime._fail('unavailable')
                offset+=count
                if offset==len(rules):inputs.close();inputs=None
            for pipe in readable:
                # Any output is a fixed helper refusal; never collect unbounded
                # stderr before noticing its size or the original phase deadline.
                raw=os.read(pipe.fileno(),1)
                if raw:runtime._fail('unavailable')
                reads.remove(pipe)
        if process.returncode!=0:runtime._fail('unavailable')
    finally:
        cleanup_error=None
        cleanup_end=time.monotonic()+2
        try:
            if process.poll()is None:
                try:process.kill()
                except ProcessLookupError:pass
                process.wait(timeout=max(0,cleanup_end-time.monotonic()))
        except (OSError,subprocess.TimeoutExpired) as error:cleanup_error=error
        finally:
            for pipe in (process.stdin,process.stdout,process.stderr):
                try:pipe.close()
                except OSError as error:
                    if cleanup_error is None:cleanup_error=error
        if cleanup_error is not None:runtime._fail('cleanup_incomplete')
    runtime._check(deadline_ns=end)


def prepare_network(scope,deadline_ns):
    import ctypes
    import struct
    import subprocess
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.unshare(0x40000000):runtime._fail('unavailable')
    for name in ('all','default'):
        with open('/proc/sys/net/ipv6/conf/'+name+'/disable_ipv6','w',encoding='ascii') as f:f.write('1\n')
    net=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE);net.settimeout(1);net.bind((0,0))
    def attribute(kind,raw):
        value=struct.pack('=HH',len(raw)+4,kind)+raw
        return value+bytes((-len(value))%4)
    def send(kind,body,sequence,create=False):
        header=struct.pack('=IHHII',16+len(body),kind,1|4|(0x600 if create else 0),sequence,0)
        if net.sendto(header+body,(0,0))!=len(header+body):runtime._fail('unavailable')
        raw,sender=net.recvfrom(4097)
        if sender!=(0,0) or not 36<=len(raw)<=4096 or struct.unpack_from('=IHHI',raw)[:2]!=(len(raw),2) or struct.unpack_from('=I',raw,8)[0]!=sequence or struct.unpack_from('=i',raw,16)[0]:runtime._fail('unavailable')
    try:
        index=socket.if_nametoindex('lo')
        send(16,struct.pack('=BBHiII',socket.AF_UNSPEC,0,0,index,1,1),1)
        packed=socket.inet_aton(scope['http']['target'])
        send(20,struct.pack('=BBBBI',socket.AF_INET,32,0,0,index)+attribute(1,packed)+attribute(2,packed),2,True)
    finally:net.close()
    target=scope['http']['target'];port=scope['http']['port']
    original=f'ip daddr {target} tcp dport {port} ct direction original'
    reply=f'ip saddr {target} tcp sport {port} ct direction reply ct state established'
    rules=('table inet recon_engagement_live {\n'+''.join(' chain '+name+' { type filter hook '+name+' priority 0; policy drop;\n  '+direction+' "lo" '+original+' accept\n  '+direction+' "lo" '+reply+' accept\n }\n' for name,direction in (('input','iifname'),('output','oifname')))+' chain forward { type filter hook forward priority 0; policy drop; }\n}\n').encode('ascii')
    for check in (True,False):
        runtime._check(deadline_ns=deadline_ns)
        _run_nft(rules,check,deadline_ns)
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.bind((target,port));listener.listen(1);listener.setblocking(False)
    return listener


def _sendmmsg_fastopen(stream,endpoint):
    """Actual fixed Linux syscall witness, before effect readiness."""
    import ctypes
    class Iovec(ctypes.Structure):
        _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
    class Message(ctypes.Structure):
        _fields_=[('name',ctypes.c_void_p),('name_length',ctypes.c_uint),('iov',ctypes.POINTER(Iovec)),
                 ('iov_length',ctypes.c_size_t),('control',ctypes.c_void_p),('control_length',ctypes.c_size_t),('flags',ctypes.c_int)]
    class MultiMessage(ctypes.Structure):
        _fields_=[('message',Message),('length',ctypes.c_uint)]
    address=ctypes.create_string_buffer(int(socket.AF_INET).to_bytes(2,sys.byteorder)+endpoint[1].to_bytes(2,'big')+socket.inet_aton(endpoint[0])+bytes(8))
    payload=ctypes.create_string_buffer(b'x');vector=Iovec(ctypes.cast(payload,ctypes.c_void_p),1)
    message=MultiMessage(Message(ctypes.cast(address,ctypes.c_void_p),16,ctypes.pointer(vector),1,None,0,0),0)
    library=ctypes.CDLL(None,use_errno=True)
    library.sendmmsg.argtypes=[ctypes.c_int,ctypes.POINTER(MultiMessage),ctypes.c_uint,ctypes.c_int]
    library.sendmmsg.restype=ctypes.c_int;ctypes.set_errno(0)
    result=library.sendmmsg(stream.fileno(),ctypes.byref(message),1,0x20000000)
    if result==-1:raise OSError(ctypes.get_errno(),'fixed syscall refused')
    return result


def main():
    if len(sys.argv)!=3 or not ENTRY_VERIFIED:return 78
    bootstrap,manifest,rights,stdin=runtime._receive_initial('endpoint',sys.argv[1],sys.argv[2],entry_verified=True)
    payload=bootstrap['payload']
    entry=runtime.check_role_entry(role='endpoint',bootstrap=bootstrap,expected_fds=rights,observer=bootstrap['observer'])
    listener=prepare_network(payload['scope'],bootstrap['deadline_ns'])
    # Network preparation intentionally changes the endpoint net before READY.
    entry['namespaces']['net']=os.readlink('/proc/self/ns/net')
    ready=runtime.bootstrap_role(role='endpoint',entry=entry,runtime_manifest=manifest,expected_fds=rights,deadline_ns=bootstrap['deadline_ns'])
    # Actual endpoint socket/creation denial witnesses precede readiness.
    for family in (socket.AF_INET6,socket.AF_UNIX,socket.AF_PACKET):
        try:s=socket.socket(family,socket.SOCK_STREAM)
        except OSError as error:
            if error.errno!=errno.EPERM:raise
        else:s.close();runtime._fail('invalid_role')
    witness=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        for op in (lambda:witness.connect((payload['scope']['http']['target'],payload['scope']['http']['port'])),
                   lambda:witness.sendto(b'x',0x20000000,(payload['scope']['http']['target'],payload['scope']['http']['port'])),
                   lambda:witness.sendmsg([b'x'],[],0x20000000,(payload['scope']['http']['target'],payload['scope']['http']['port'])),
                   lambda:_sendmmsg_fastopen(witness,(payload['scope']['http']['target'],payload['scope']['http']['port']))):
            try:op()
            except OSError as error:
                if error.errno!=errno.EPERM:raise
            else:runtime._fail('invalid_role')
    finally:witness.close()
    ready['boundary_checks'].update(dict.fromkeys(runtime.SPEC['closed_objects']['boundary_checks']['role_specific']['endpoint'],True))
    runtime._emit_ready(ready)
    return run_loop(payload,rights,listener,bootstrap['deadline_ns'],ready=ready)


def run_loop(payload,rights,listener,deadline_ns,*,ready):
    # Ordinary channel identity and sequence derive solely from inherited peers.
    broker=socket.socket(fileno=rights['broker_control']);arm=socket.socket(fileno=rights['launcher_arm'])
    broker.setblocking(False);arm.setblocking(False)
    control=runtime._WorkerControl(deadline_ns);pending=None;meter=None;stream=None;response=False
    # Protocol transport sequence state belongs to the fixed endpoint only.
    outgoing={'broker':0,'arm':0};incoming={'broker':0,'arm':0}
    def send(channel,which,operation,body):
        outgoing[which]+=1
        frame={'schema_version':'1','channel_id':payload['endpoint_id'],'sequence':outgoing[which],'operation':operation,'body':body}
        protocol.send_packet(channel,frame,role='endpoint' if which=='broker' else 'arm',control=control)
    def receive(channel,which):
        frame=protocol.receive_packet(channel,role='endpoint' if which=='broker' else 'arm',control=control)
        if frame['sequence']!=incoming[which]+1 or frame['channel_id']!=payload['endpoint_id']:runtime._fail('invalid_sequence')
        incoming[which]+=1;return frame
    try:
        send(broker,'broker','READY',ready)
        while True:
            runtime._check(control)
            reads=[broker,arm]
            if meter is not None and meter.release is not None and meter.reason is None:
                reads.append(stream if stream is not None and not response else listener if stream is None else broker)
            readable,writable,_=select.select(reads,[stream] if stream is not None and response else [],[],min(.05,control.remaining()))
            # Broker cancellation always wins over any simultaneously ready ARM/I/O.
            if broker in readable:
                frame=receive(broker,'broker');op=frame['operation']
                if op in ('CANCEL','STOP'):
                    if meter:meter.cancel()
                    break
                if op!='PREPARE' or meter is not None and meter.reason is None:runtime._fail('invalid_prepared')
                pending=contract.validate_prepared_role_context(frame['body'],binding=payload['session_binding'],roe=payload['roe'],scope=payload['scope'],policy=payload['policy'])
                meter=Meter(pending,payload['endpoint_id'],payload['scope'])
                send(broker,'broker','PREPARED',{'prepared_sha256':contract.prepared_digest(pending),'envelope_sha256':contract.envelope_digest(pending['envelope']),'ready_at_ns':time.monotonic_ns()})
            if arm in readable:
                frame=receive(arm,'arm')
                if frame['operation']!='ARM' or meter is None or frame['body']['slot']!=meter.slot:runtime._fail('release_unavailable')
                meter.arm(frame['body']['release']);release=meter.release
                send(arm,'arm','ACK',{'schema_version':'1','endpoint_id':payload['endpoint_id'],'session_id':release['session_id'],
                    'dispatch_id':release['dispatch_id'],'envelope_sha256':release['envelope_sha256'],'go_sha256':runtime._hash(release),
                    'slot':meter.slot,'arm_sequence':1,'effective_lease_deadline_ns':release['effective_lease_deadline_ns'],'armed_at_ns':meter.armed_at})
            if listener in readable and meter is not None:
                meter.check()
                if meter.connections>=meter.max_connections:meter.stop('connection_limit');break
                stream,_=listener.accept();stream.setblocking(False);meter.admit();response=False
            if stream is not None and stream in readable:
                result=meter.receive(stream)
                if result==b'':stream.close();stream=None
                elif result is not None:response=True
            if stream is not None and stream in writable:
                if meter.send(stream):
                    stream.close();stream=None;response=False
                    send(broker,'broker','METER',meter.snapshot())
    except contract.LiveError as error:
        if meter is not None and meter.release is not None and meter.reason is None:
            reason={'engagement_live_timeout':'timeout','engagement_live_window_closed':'window_closed',
                    'engagement_live_clock_changed':'clock_invalid','engagement_live_cancelled':'cancelled'}.get(error.code,'channel_eof' if error.code=='engagement_live_invalid_frame' else 'unresolved')
            meter.cancel(reason)
        raise
    finally:
        if stream is not None:stream.close()
        listener.close()
        if meter is not None and meter.release is not None and meter.reason is None:meter.cancel('channel_eof')
        if meter is not None and meter.release is not None and meter.reason!='complete':
            try:send(broker,'broker','METER',meter.snapshot())
            except Exception:pass
        try:send(broker,'broker','CLOSED',{'role':'endpoint','worker_id':payload['endpoint_id'],'stopped_at_ns':time.monotonic_ns()})
        except Exception:pass
        broker.close();arm.close()
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,RuntimeError):raise SystemExit(78)
