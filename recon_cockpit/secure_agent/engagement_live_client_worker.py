"""Confined waiting image for one fixed Nmap invocation or HTTP GET."""
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

import errno
import select
import socket
import time
from recon_cockpit.secure_agent import engagement_live_runtime as runtime
from recon_cockpit.secure_agent import engagement_live_contract as contract
from recon_cockpit.secure_agent.configurable_scope import validate_scope


def fixed_argv(scope):
    selected=validate_scope(scope)['http']
    return [value.replace('{validated_port}',str(selected['port'])).replace('{validated_ipv4}',selected['target'])
            for value in runtime.SPEC['http_grammar']['nmap_argv']]


def _blocked(target,port):
    channel=socket.socket(socket.AF_INET,socket.SOCK_STREAM);channel.setblocking(False)
    try:
        error=channel.connect_ex((target,port))
        if error in (errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH):return
        if error not in (errno.EINPROGRESS,errno.EWOULDBLOCK):runtime._fail('invalid_role')
        if select.select([],[channel],[],.02)[1]:
            if channel.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0:runtime._fail('invalid_role')
    finally:channel.close()


def _network_witnesses(scope):
    selected=scope['http'];_blocked(selected['target'],selected['port']+1)
    _blocked('10.255.255.254' if selected['target']!='10.255.255.254' else '172.31.255.254',selected['port'])
    _blocked(scope['ssh']['target'],scope['ssh']['port'])
    for family,kind in ((socket.AF_INET,socket.SOCK_RAW),(socket.AF_INET6,socket.SOCK_STREAM),(socket.AF_PACKET,socket.SOCK_RAW)):
        try:s=socket.socket(family,kind)
        except OSError as error:
            if error.errno!=errno.EPERM:raise
        else:s.close();runtime._fail('invalid_role')


def _close_bootstrap(channel):
    channel.close()
    fd=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
    if fd!=0:os.dup2(fd,0);os.close(fd)
    os.set_inheritable(0,True)


def _headers(scope,prepared,release,deadline_ns):
    selected=scope['http'];channel=socket.socket(socket.AF_INET,socket.SOCK_STREAM);channel.setblocking(False)
    request=('GET / HTTP/1.1\r\nHost: '+selected['target']+':'+str(selected['port'])+'\r\nConnection: close\r\n\r\n').encode('ascii')
    end=min(deadline_ns,time.monotonic_ns()+1000000000);control=runtime._WorkerControl(end)
    def check():
        control.check();contract.validate_release_binding(release,prepared,clock=contract.sample_clock())
    try:
        check();code=channel.connect_ex((selected['target'],selected['port']))
        if code not in (0,errno.EINPROGRESS,errno.EWOULDBLOCK):runtime._fail('unavailable')
        while not select.select([],[channel],[],min(.01,control.remaining()))[1]:check()
        if channel.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR):runtime._fail('unavailable')
        offset=0
        while offset<len(request):
            check()
            if not select.select([],[channel],[],min(.01,control.remaining()))[1]:continue
            try:count=channel.send(request[offset:])
            except BlockingIOError:continue
            if count<=0:runtime._fail('unavailable')
            offset+=count
        raw=bytearray()
        while True:
            check()
            if len(raw)>=2048:runtime._fail('limit_exceeded')
            if not select.select([channel],[],[],min(.01,control.remaining()))[0]:continue
            try:part=channel.recv(2048-len(raw))
            except BlockingIOError:continue
            if not part:break
            raw.extend(part)
            written=0
            while written<len(part):
                check();count=os.write(1,part[written:])
                if count<=0:runtime._fail('unavailable')
                written+=count
        check();return 0
    finally:channel.close()


def main():
    if len(sys.argv)!=3 or not ENTRY_VERIFIED:return 78
    selected=runtime._decode(runtime._read_file(runtime.MANIFEST_PATH,131072),131072)
    role=selected['role']
    if role not in ('nmap','headers'):runtime._fail('invalid_role')
    initial,manifest,rights,channel=runtime._receive_initial(role,sys.argv[1],sys.argv[2],entry_verified=True)
    prepared=contract.validate_prepared(initial['payload']['prepared'])
    expected_role='nmap' if prepared['envelope']['slot']=='http_identify' else 'headers'
    if role!=expected_role or initial['runtime_sha256']!=prepared['envelope']['runtime_sha256']:runtime._fail('invalid_role')
    endpoint=initial['payload']['endpoint_identity'];runtime.validate_protocol_value('role_readiness',endpoint)
    if endpoint['role']!='endpoint' or endpoint['worker_ready']['runtime_sha256']!=initial['runtime_sha256']:runtime._fail('invalid_role')
    from recon_cockpit.secure_agent import configurable_contract
    from recon_cockpit.secure_agent.configurable_scope import scope_digest
    scope=validate_scope(initial['payload']['scope'])
    if scope_digest(scope)!=prepared['envelope']['scope_sha256'] or configurable_contract.action(scope,1 if role=='nmap' else 2)!=prepared['action']:runtime._fail('invalid_prepared')
    entry=runtime.check_role_entry(role=role,bootstrap=initial,expected_fds=rights,observer=initial['observer'])
    ready=runtime.bootstrap_role(role=role,entry=entry,runtime_manifest=manifest,expected_fds=rights,deadline_ns=initial['deadline_ns'])
    _network_witnesses(scope)
    ready['boundary_checks'].update(forbidden_target_blocked=True,forbidden_port_blocked=True,ssh_endpoint_blocked=True,raw_sockets_blocked=True,landlock_applied=True)
    runtime._emit_ready(ready)
    raw=runtime._receive_bytes(channel,4096,runtime._WorkerControl(initial['deadline_ns']))
    release=contract.validate_release_binding(runtime._decode(raw,4096),prepared,clock=contract.sample_clock())
    _close_bootstrap(channel)
    if role=='nmap':
        import signal
        timeout=min(5,(release['effect_stop_ns']-time.monotonic_ns())/1e9)
        if timeout<=0:runtime._fail('timeout')
        signal.setitimer(signal.ITIMER_REAL,timeout)
        os.execv('/tool/nmap',fixed_argv(scope))
    return _headers(scope,prepared,release,release['effect_stop_ns'])


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,RuntimeError):raise SystemExit(78)
