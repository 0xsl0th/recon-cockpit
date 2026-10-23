"""S42C-T01..T16: portable models and OS-call doubles, no native proofs."""
from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import stat
from types import SimpleNamespace
from uuid import UUID

import pytest
from recon_cockpit.secure_agent import engagement_live_runtime as r
from recon_cockpit.secure_agent import engagement_live_contract as c

ROOT=Path(__file__).resolve().parents[1]
def uid(n):return str(UUID(int=n,version=4))
def raw(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def sha(v):return hashlib.sha256(v).hexdigest()

def declared_runtime():
    """Declared fixture rows only. No native image/process/kernel claim is made."""
    def file(destination):
        return {'source':'/usr/bin/python3' if destination.startswith('/tool/') else destination,
                'destination':destination,'size':1,'sha256':'a'*64}
    sources=[{'module':m,'destination':r._destination(m),'size':1,'sha256':'b'*64} for m in r.source_modules()]
    roles=[]
    for role in r.ROLES:
        destinations={'/usr/bin/python3','/lib64/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/libffi.so.8'}
        if role=='nmap':destinations.add('/tool/nmap')
        if role=='endpoint':destinations.add('/usr/sbin/nft')
        native=[]
        for destination in sorted(destinations):
            item=file(destination)
            if destination.startswith('/lib64/'):item['source']='/usr/lib/ld-linux-x86-64.so.2'
            native.append(item)
        extensions=set(r.EXTENSIONS)|({'_sqlite3'} if role=='broker' else {'_tkinter'} if role=='graphical' else {'termios'} if role=='terminal' else set())
        resources=[{'source':p,'destination':p,'kind':'directory','device':1,'inode':2,'mode':0o40755,'files_sha256':'c'*64}
            for p in ('/usr/share/tcltk/tcl8.6','/usr/share/tcltk/tk8.6','/usr/share/fonts/truetype/dejavu','/var/cache/fontconfig')] if role=='graphical' else []
        roles.append({'role':role,'entrypoint':r.ENTRYPOINTS[role],
            'sources':[row for row in sources if row['module'] in r.role_modules(role)],
            'executable':'/tool/nmap' if role=='nmap' else '/usr/bin/python3',
            'interpreter':'/lib64/ld-linux-x86-64.so.2','native_files':native,
            'extension_files':[file('/usr/lib/python3.14/lib-dynload/'+x+'.so') for x in sorted(extensions)],
            'readonly_resources':resources,'required_mapped_images':sorted(destinations)})
    helpers=[]
    for name in ('bwrap','nft','nsenter','readelf'):
        executable=file(r.SPEC['runtime_manifest_schema']['helpers_schema']['destinations'][name])
        helpers.append({'name':name,'executable':executable,'interpreter':'/lib64/ld-linux-x86-64.so.2','files':[executable]})
    compiled=[{'name':name,'destination':dest,'size':len(content),'sha256':sha(content)}
              for name,(dest,content) in sorted(r._compiled().items())]
    result={'schema_version':'1','profile':r.PROFILE,'platform':'linux-x86_64',
        'python':{**file('/usr/bin/python3'),'version':'3.14.0','builtin_modules':['sys']},
        'stdlib':{'path':'/usr/lib/python3.14','device':1,'inode':2,'mode':0o40755},
        'sources':sources,'roles':roles,'helpers':helpers,'compiled':compiled}
    return r.validate_runtime(result)


def declared_readiness(bundle,role='headers',*,pid=101,worker_id=None):
    """Finite declared receipt for pure validation tests; never a kernel claim."""
    manifest=next(x for x in bundle['roles'] if x['role']==role)
    namespaces={k:k+':['+str(200+i)+']' for i,k in enumerate(('user','net','mnt','pid'))}
    observer={'pid':90,'uid':1000,'gid':1000,'namespaces':{k:k+':['+str(100+i)+']' for i,k in enumerate(namespaces)}}
    descriptors=[{'fd':i,'purpose':purpose,'kind':'seqpacket' if i==0 else 'pipe','device':1,'inode':10+i,'mode':stat.S_IFSOCK if i==0 else stat.S_IFIFO,'flags':os.O_RDWR if i==0 else os.O_WRONLY} for i,purpose in enumerate(('stdin','stdout','stderr'))]
    for purpose in r.RIGHTS[role]:
        i=len(descriptors);descriptors.append({'fd':i,'purpose':purpose,'kind':'seqpacket','device':1,'inode':10+i,'mode':stat.S_IFSOCK,'flags':os.O_RDWR})
    payload={'pid':pid,'parent_pid':pid+1,'start_time_ticks':1000}
    wrapper={'pid':pid+1,'parent_pid':90,'start_time_ticks':900}
    executable=next(x for x in manifest['native_files'] if x['destination']=='/usr/bin/python3')
    parent={'schema_version':'1','role':role,'observer':observer,'wrapper':wrapper,'payload':payload,'ancestry':[payload,wrapper],
        'namespaces':namespaces,'uid_map':[[65534,1000,1]],'gid_map':[[65534,1000,1]],'uids':[1000]*4,'gids':[1000]*4,'groups':[1000],
        'task_ids':[pid],'descriptors':descriptors,'executable':{'destination':'/usr/bin/python3','device':1,'inode':99,'mode':stat.S_IFREG|0o555,'size':executable['size'],'sha256':executable['sha256']},
        'mapped_images':[{'destination':x['destination'],'device':1,'inode':300+i} for i,x in enumerate(manifest['native_files'])],
        'status':{'cap_inheritable':0,'cap_permitted':0,'cap_effective':0,'cap_bounding':0,'cap_ambient':0,'no_new_privs':1,'seccomp_mode':2},'sampled_at_ns':1000000000,'stage':'sealed'}
    checks=set(r.SPEC['closed_objects']['boundary_checks']['common'])|set(r.SPEC['closed_objects']['boundary_checks']['role_specific'][role])
    ready={'schema_version':'1','role':role,'worker_id':worker_id or uid(pid),'bootstrap_sha256':'e'*64,'runtime_sha256':r.runtime_digest(bundle),
        'source_sha256':r._hash(manifest['sources']),'stage':'sealed_reviewer' if role in ('terminal','graphical') else 'sealed_waiting' if role in ('nmap','headers') else 'sealed_'+role,
        'namespaces':namespaces,'uid':65534,'gid':65534,'groups':[65534],'task_ids':[1],'descriptor_sha256':r._hash(descriptors),'boundary_checks':dict.fromkeys(checks,True)}
    return r.validate_readiness(role,{'schema_version':'1','role':role,'worker_ready':ready,'parent_observation':parent},bundle)


def declared_cleanup(ready,*,started=2000000000,finished=2100000000):
    p=ready['parent_observation']
    return r.validate_cleanup({'schema_version':'1','started_at_ns':started,'finished_at_ns':finished,'deadline_ns':started+2000000000,
        'status':'complete','descriptors_closed':True,'processes':[{'role':ready['role'],'pid':p['payload']['pid'],'start_time_ticks':p['payload']['start_time_ticks'],
        'pin_verified':True,'signal_attempted':True,'exit_observed':True,'reaped_observed':True,'wrapper_pid':p['wrapper']['pid'],'wrapper_returncode':-9}]})


def refused(function,*args,**kwargs):
    with pytest.raises(c.LiveError) as caught:function(*args,**kwargs)
    assert caught.value.code in c.ERROR_CODES
    return caught.value


def test_exact_source_inventory():
    bundle=declared_runtime()
    assert set(r.source_modules())=={x['module'] for x in bundle['sources']}
    assert set(r.SPEC['source_partitions']['audit_exact'])<=set(r.source_modules())
    for change in ('missing','extra','duplicate'):
        bad=deepcopy(bundle)
        if change=='missing':bad['sources'].pop()
        elif change=='extra':bad['sources'].append({'module':'arbitrary','destination':'/app/arbitrary.py','size':1,'sha256':'f'*64})
        else:bad['sources'].append(bad['sources'][0])
        refused(r.validate_runtime,bad)


def test_fixed_native_elf_and_data_inventory():
    bundle=declared_runtime();role=next(x for x in bundle['roles'] if x['role']=='nmap')
    for key,value in (('executable','/bin/sh'),('interpreter','/lib/unknown.so')):
        bad=deepcopy(role);bad[key]=value;refused(r.validate_role_manifest,bad)
    bad=deepcopy(role);bad['native_files'].append({'source':'/bin/sh','destination':'/bin/sh','size':1,'sha256':'f'*64});refused(r.validate_role_manifest,bad)
    bad=deepcopy(bundle);bad['compiled'][0]['sha256']='0'*64;refused(r.validate_runtime,bad)
    refused(r._elf,b'not an ELF')
    assert r.SPEC['http_grammar']['nmap_argv'][0]=='/tool/nmap'
    launcher=next(x for x in bundle['roles'] if x['role']=='launcher')
    assert not {'/tool/nmap','/usr/bin/bwrap'} & {x['destination'] for x in launcher['native_files']}


def test_role_partition_authority_absent():
    for role in ('parser','endpoint','nmap','headers'):
        modules=r.role_modules(role)
        assert 'engagement_dispatch_store' not in modules and 'engagement_live_broker' not in modules
        assert 'engagement_live_approval_worker' not in modules
    assert 'engagement_dispatch_store' in r.role_modules('broker')
    bundle=declared_runtime();p=deepcopy(next(x for x in bundle['roles'] if x['role']=='parser'))
    p['sources'].append(next(x for x in bundle['sources'] if x['module']=='engagement_dispatch_store'))
    refused(r.validate_role_manifest,p)


def test_sealed_source_descriptor_custody(tmp_path,monkeypatch):
    import fcntl
    path=tmp_path/'memfd-model';fds=[];seals={};closed=[]
    def create(*a):
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_TRUNC,0o600);fds.append(fd);seals[fd]=0;return fd
    real=fcntl.fcntl
    def command(fd,operation,value=None):
        if operation==getattr(fcntl,'F_ADD_SEALS',1033):seals[fd]|=value;return 0
        if operation==getattr(fcntl,'F_GET_SEALS',1034):return seals[fd]
        return real(fd,operation) if value is None else real(fd,operation,value)
    monkeypatch.setattr(os,'memfd_create',create,raising=False)
    monkeypatch.setattr(os,'MFD_CLOEXEC',1,raising=False);monkeypatch.setattr(os,'MFD_ALLOW_SEALING',2,raising=False)
    for name,value in (('F_ADD_SEALS',1033),('F_GET_SEALS',1034),('F_SEAL_SEAL',1),('F_SEAL_SHRINK',2),('F_SEAL_GROW',4),('F_SEAL_WRITE',8)):monkeypatch.setattr(fcntl,name,value,raising=False)
    monkeypatch.setattr(fcntl,'fcntl',command)
    fd=r._sealed(b'reviewed bytes');assert seals[fd]==15;os.lseek(fd,0,0);assert os.read(fd,100)==b'reviewed bytes';os.close(fd)
    monkeypatch.setattr(fcntl,'fcntl',lambda *a:(_ for _ in ()).throw(OSError('seal failure')))
    with pytest.raises(OSError):r._sealed(b'x')
    with pytest.raises(OSError):os.fstat(fds[-1])


def test_native_snapshot_mutation_refused(tmp_path,monkeypatch):
    source=tmp_path/'source';source.write_bytes(b'right')
    row={'source':str(source),'destination':'/tool/nmap','size':5,'sha256':sha(b'right')}
    source.write_bytes(b'wrong')
    snapshot=object.__new__(r.RoleSnapshot);snapshot._fds=[]
    refused(snapshot._stage,row,source.read_bytes(),{},None)
    assert snapshot._fds==[]
    for role in ('endpoint','nmap','parser'):
        value=declared_runtime();selected=next(x for x in value['roles'] if x['role']==role)
        selected['native_files'][0]['sha256']='bad';refused(r.validate_runtime,value)


def test_fixed_argv_and_initial_fd_closure(tmp_path,monkeypatch):
    _supervised_spawn_cases(monkeypatch)
    _supervised_proxy_cases(monkeypatch)
    _supervised_bootstrap_cases(monkeypatch)
    import socket
    from recon_cockpit.secure_agent import engagement_live_client_worker as worker
    from test_secure_engagement_live_contract import opened
    scope=opened()['scope'];argv=worker.fixed_argv(scope)
    assert argv[0]=='/tool/nmap' and argv[-1]==scope['http']['target']
    assert '--script' not in argv and '-p' in argv
    pair=socket.socketpair();fd=os.open(tmp_path/'right',os.O_CREAT|os.O_RDWR,0o600)
    with pytest.raises(c.LiveError):r._start_role(runtime={},role='terminal',payload={},rights={'intentional_tty':fd},control=SimpleNamespace(),stdin_pair=pair)
    assert all(x.fileno()==-1 for x in pair)
    with pytest.raises(OSError):os.fstat(fd)
    assert r.RIGHTS['terminal']==('intentional_tty','review_witness')
    assert r.RIGHTS['broker'][0]=='host_lifecycle'
    # A directory passed through /proc/self/fd with ordinary --bind survives
    # into the worker. The explicit fd-consuming operation must mount this
    # same held object while the parent retains its independent custody.
    import subprocess
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent import engagement_live_broker_worker as broker_worker
    store=tmp_path/'store';store.mkdir(mode=0o700)
    store_fd=os.open(store,os.O_RDONLY|os.O_DIRECTORY)
    identity=os.fstat(store_fd);calls=[];setup_fds=[]
    manifest=next(row for row in declared_runtime()['roles'] if row['role']=='broker')
    snapshot=SimpleNamespace(role='broker',stdlib='/usr/lib/python3.14',manifest=manifest,
        pass_fds=(),mounts=lambda argv:argv,close=lambda:calls.append('snapshot_closed'))
    def launch(argv,**options):
        calls.append('launch')
        setup_fds.extend(options['pass_fds'])
        assert argv[argv.index('--bind-fd')+1:argv.index('--bind-fd')+3]==[str(store_fd),'/store/engagement']
        assert '--bind' not in argv and '/proc/self/fd/'+str(store_fd) not in argv
        assert store_fd in options['pass_fds']
        assert os.fstat(store_fd)==identity
        assert argv[-3]==r.ENTRYPOINTS['broker']
        raise OSError(errno.EIO,'injected pre-launch failure')
    try:
        with monkeypatch.context() as patch:
            channel_pair=socket.socketpair()
            patch.setattr(r,'snapshot_role',lambda *args:snapshot)
            patch.setattr(r,'_make_bootstrap',lambda **kwargs:{})
            patch.setattr(r.os,'pipe2',lambda flags:os.pipe(),raising=False)
            patch.setattr(subprocess,'Popen',launch)
            with pytest.raises(OSError,match='injected pre-launch failure'):
                r._start_role(runtime=declared_runtime(),role='broker',payload={},rights={},
                    control=ExecutionControl(r.time.monotonic()+10),stdin_pair=channel_pair,
                    extra_mounts=[(store_fd,'/store/engagement')])
        assert calls==['launch','snapshot_closed'] and os.fstat(store_fd)==identity
        assert all(channel.fileno()==-1 for channel in channel_pair)
        for fd in setup_fds:
            if fd!=store_fd:
                with pytest.raises(OSError):os.fstat(fd)
        # Do not repair the launch by weakening the worker's stdio-only check.
        with monkeypatch.context() as patch:
            patch.setattr(broker_worker.os,'listdir',lambda path:['0','1','2',str(store_fd)])
            with pytest.raises(ValueError,match='engagement_live_inherited_descriptor'):
                broker_worker._entry_only_stdio()
    finally:os.close(store_fd)
    # The closed bootstrap FD is reused by SQLite custody. Both worker and
    # parent must identify its current object, not its obsolete initial purpose.
    targets={16:'/store',17:'/store/engagement',18:'/store/engagement/records.sqlite3',
             19:'anon_inode:[eventpoll]'}
    with monkeypatch.context() as patch:
        patch.setattr(r.os,'listdir',lambda path:[str(fd) for fd in targets])
        patch.setattr(r.os,'readlink',lambda path:targets[int(str(path).rsplit('/',1)[1])])
        patch.setattr(r.os,'stat',lambda path:SimpleNamespace(st_mode=stat.S_IFDIR|0o700 if int(str(path).rsplit('/',1)[1]) in (16,17) else stat.S_IFREG|0o600,st_dev=1,st_ino=int(str(path).rsplit('/',1)[1])))
        patch.setattr(Path,'read_text',lambda *args,**kwargs:'flags:\t02000002\n')
        rows=r._fd_inventory('/declared',purposes={16:'runtime_input'},role='broker',steady=True)
        assert [row['purpose'] for row in rows]==['held_parent_directory','held_store_directory','sqlite_main','selector']
        assert rows[-1]['kind']=='eventpoll'
    _import_descriptor_custody_cases(tmp_path,monkeypatch)
    _audit_readback_cases(tmp_path,monkeypatch,('exact','shifted','unknown_extra','missing',
        'append_identity','witness_identity','append_not_append','append_rdwr','witness_blocking',
        'library_writable','library_path','library_hash','library_size','mount_identity',
        'mount_writable','mapping_identity','mapping_path','changed_inventory'))


def _import_descriptor_custody_cases(tmp_path,monkeypatch):
    # Actual ordinary file descriptors/bytes; only the isolated /proc and
    # read-only mount observations are modeled. No memfd/Linux API is required.
    import fcntl
    destination='/lib/x86_64-linux-gnu/libffi.so.8';content=b'pinned libffi image'
    cases=('plain','deleted','unverified','truthy_entry','multiple','missing_pin','ambiguous_pin',
        'wrong_target','duplicate_suffix','writable_fd','wrong_mode','wrong_size','wrong_hash',
        'wrong_mount_inode','writable_mount','wrong_map_path','wrong_map_inode','wrong_map_device',
        'nonexecutable_map','mapping_overflow','changed_held_identity','deadline')
    for case in cases:
        directory=tmp_path/('import-'+case);directory.mkdir()
        image=directory/'image';image.write_bytes(content)
        fd=os.open(image,os.O_RDWR if case=='writable_fd' else os.O_RDONLY)
        image.chmod(0o600 if case=='wrong_mode' else 0o444)
        before=os.fstat(fd);extra=[];opened=[];closed=[];held_reads=0
        manifest=deepcopy(next(x for x in declared_runtime()['roles'] if x['role']=='broker'))
        manifest['native_files']=[row for row in manifest['native_files'] if row['destination']!=destination]
        row={'source':destination,'destination':destination,'size':len(content),'sha256':sha(content)}
        if case=='wrong_size':row['size']+=1
        if case=='wrong_hash':row['sha256']='0'*64
        if case!='missing_pin':manifest['native_files'].append(row)
        if case=='ambiguous_pin':manifest['native_files'].append({**row,'destination':destination+'.1'})
        manifest['native_files'].sort(key=lambda x:x['destination'])
        target=destination+(' (deleted)' if case!='plain' else '')
        if case=='wrong_target':target='/unreviewed/libffi.so.8 (deleted)'
        if case=='duplicate_suffix':target+=' (deleted)'
        path=destination+' (deleted)' if case=='wrong_map_path' else target
        inode=before.st_ino+(case=='wrong_map_inode')
        device=(os.major(before.st_dev),os.minor(before.st_dev)+(case=='wrong_map_device'))
        perms='r--p' if case=='nonexecutable_map' else 'r-xp'
        mapping=f'1000-2000 {perms} 00000000 {device[0]:x}:{device[1]:x} {inode} {path}\n'
        if case=='wrong_map_path':mapping=mapping.replace(' (deleted)','')
        if case=='mapping_overflow':mapping='x'*262145
        maps=directory/'maps';maps.write_text(mapping)
        other=directory/'other';other.write_bytes(content);other.chmod(0o444)
        if case=='multiple':extra.append(os.open(other,os.O_RDONLY))
        real_open=os.open;real_close=os.close;real_fstat=os.fstat
        def open_observed(path,flags,*args,**kwargs):
            if path==destination:
                assert flags & os.O_NOFOLLOW and flags & os.O_ACCMODE==os.O_RDONLY
                path=other if case=='wrong_mount_inode' else image
            else:assert path=='/proc/self/maps';path=maps
            result=real_open(path,flags,*args,**kwargs);opened.append(result);return result
        def close_observed(number):closed.append(number);real_close(number)
        def fstat_observed(number):
            nonlocal held_reads
            value=real_fstat(number)
            if number==fd:
                held_reads+=1
                if case=='changed_held_identity' and held_reads>1:
                    return SimpleNamespace(**{key:getattr(value,key) for key in ('st_dev','st_mode','st_size','st_mtime_ns','st_ctime_ns')},st_ino=value.st_ino+1)
            return value
        class Control:
            checks=0
            def check(self):
                self.checks+=1
                if case=='deadline' and self.checks==4:raise c.LiveError('engagement_live_timeout')
        try:
            with monkeypatch.context() as patch:
                patch.setattr(r.os,'listdir',lambda path:['0','1','2',str(fd),*(str(x) for x in extra)])
                patch.setattr(r.os,'readlink',lambda path:target)
                patch.setattr(r.os,'open',open_observed)
                patch.setattr(r.os,'close',close_observed)
                patch.setattr(r.os,'fstat',fstat_observed)
                patch.setattr(r.os,'fstatvfs',lambda number:SimpleNamespace(f_flag=0 if case=='writable_mount' else os.ST_RDONLY))
                control=Control()
                if case in ('plain','deleted'):
                    r._close_import_descriptor(entry_verified=True,runtime_manifest=manifest,control=control)
                    assert closed[-1]==fd
                else:
                    refused(r._close_import_descriptor,entry_verified=1 if case=='truthy_entry' else case!='unverified',runtime_manifest=manifest,control=control)
                    assert fd not in closed and real_fstat(fd).st_ino==before.st_ino
                assert set(opened)<=set(closed)
            for number in opened:
                with pytest.raises(OSError):real_fstat(number)
            if case in ('plain','deleted'):
                with pytest.raises(OSError):real_fstat(fd)
        finally:
            for number in [fd,*extra]:
                try:real_close(number)
                except OSError:pass
    # An implementation with no retained import descriptor needs no special close.
    with monkeypatch.context() as patch:
        patch.setattr(r.os,'listdir',lambda path:['0','1','2'])
        r._close_import_descriptor(entry_verified=True,runtime_manifest=manifest,control=None)


def _audit_readback_cases(tmp_path,monkeypatch,cases):
    """Real image reads/FD closes; declared Linux process inventory/map model."""
    destination='/lib/x86_64-linux-gnu/libffi.so.8';content=b'actual pinned audit dependency'
    for case in cases:
        directory=tmp_path/('audit-'+case);directory.mkdir()
        image=directory/'image';image.write_bytes(content);image.chmod(0o444);info=image.stat()
        other=directory/'other';other.write_bytes(content);other.chmod(0o444)
        row={'source':destination,'destination':destination,'size':len(content),'sha256':sha(content)}
        manifest=deepcopy(next(item for item in declared_runtime()['roles'] if item['role']=='parser'))
        manifest['native_files']=[row if item['destination']==destination else item for item in manifest['native_files']]
        initial={'version':'1','writer_id':uid(80),'device':12,'inode':103,'witness':[9,105]}
        descriptors=[{'fd':i,'purpose':name,'kind':'seqpacket' if i==0 else 'pipe',
            'device':9 if i==0 else 15,'inode':200+i,'mode':stat.S_IFSOCK if i==0 else stat.S_IFIFO,
            'flags':0x802 if i==0 else 1} for i,name in enumerate(('stdin','stdout','stderr'))]
        library={'fd':3,'purpose':'observed','kind':'regular','device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'flags':0}
        append={'fd':4,'purpose':'observed','kind':'regular','device':12,'inode':103,'mode':stat.S_IFREG|0o600,'flags':0x401}
        witness={'fd':5,'purpose':'observed','kind':'stream_socket','device':9,'inode':105,'mode':stat.S_IFSOCK,'flags':0x802}
        if case=='shifted':library['fd'],append['fd'],witness['fd']=5,3,4
        descriptors.extend(sorted([library,append,witness],key=lambda x:x['fd']))
        if case=='unknown_extra':descriptors.append({**library,'fd':6,'inode':info.st_ino+1})
        if case=='missing':descriptors.pop()
        if case=='append_identity':initial['inode']+=1
        if case=='witness_identity':initial['witness'][1]+=1
        if case=='append_not_append':append['flags']=1
        if case=='append_rdwr':append['flags']=0x402
        if case=='witness_blocking':witness['flags']=2
        if case=='library_writable':library['flags']=2
        if case=='library_hash':row['sha256']='0'*64
        if case=='library_size':row['size']+=1
        target=destination+' (deleted)'
        if case=='library_path':target='/arbitrary/libffi.so.8 (deleted)'
        mapped_target=destination if case=='mapping_path' else target
        maps=directory/'maps';maps.write_text(f'1000-2000 r-xp 00000000 {os.major(info.st_dev):x}:{os.minor(info.st_dev):x} {info.st_ino+(case=="mapping_identity")} {mapped_target}\n')
        opened=[];closed=[];now=[10.];checks=[];readlinks=[];inventories=[]
        real_open=os.open;real_close=os.close
        def open_observed(path,flags,*,dir_fd):
            assert dir_fd==999
            if path=='fd/'+str(library['fd']):actual=image
            elif path=='root'+destination:
                assert flags&os.O_NOFOLLOW
                actual=other if case=='mount_identity' else image
            else:assert path=='maps';actual=maps
            number=real_open(actual,flags);opened.append(number);return number
        def close_observed(number):
            real_close(number);closed.append(number)
            if case=='deadline_after_close' or (case=='deadline_maps_close' and len(closed)==3):now[0]=12.01
        def readlink(*args,**kwargs):
            readlinks.append(args);return target
        def inventory(*args,**kwargs):
            inventories.append(args)
            current=deepcopy(descriptors)
            if case=='changed_inventory':current[-1]['inode']+=1
            return current
        pin=SimpleNamespace(directory=999,pid=777,check_alive=lambda:checks.append('alive'))
        with monkeypatch.context() as patch:
            patch.setattr(r.os,'open',open_observed);patch.setattr(r.os,'close',close_observed)
            patch.setattr(r.os,'readlink',readlink)
            patch.setattr(r.os,'fstatvfs',lambda number:SimpleNamespace(f_flag=0 if case=='mount_writable' else os.ST_RDONLY))
            patch.setattr(r,'_fd_inventory',inventory)
            patch.setattr(r.time,'monotonic',lambda:now[0])
            control=r._WorkerControl(12000000000)
            if case=='deadline_before':now[0]=12.01
            if case in ('exact','shifted'):
                actual,observed=r._observe_audit_inventory(pin,manifest,descriptors,initial,control)
                assert observed=={'destination':destination,'device':info.st_dev,'inode':info.st_ino,
                    'mode':info.st_mode,'size':len(content),'sha256':sha(content),'read_only_mount':True}
                roles={item['purpose']:item['fd'] for item in actual}
                assert roles['audit_append']==append['fd'] and roles['audit_witness']==witness['fd'] and roles['audit_import_libffi']==library['fd']
                r._validate_audit_inventory(actual,[{key:observed[key] for key in ('destination','device','inode')}])
            else:
                error=refused(r._observe_audit_inventory,pin,manifest,descriptors,initial,control)
                if case.startswith('deadline'):assert error.code=='engagement_live_timeout'
            assert len(opened)==len(closed) and set(opened)==set(closed)
        for number in set(opened):
            with pytest.raises(OSError):os.fstat(number)
        if case=='deadline_before':assert opened==[]
        if case=='deadline_after_close':assert len(opened)==1
        if case=='deadline_maps_close':
            assert len(opened)==3 and len(readlinks)==1 and inventories==[]


def test_readiness_namespace_mapping_and_groups(monkeypatch):
    bundle=declared_runtime();ready=declared_readiness(bundle)
    for mutate in ('namespace','mapping','groups','bool','descriptors'):
        bad=deepcopy(ready)
        if mutate=='namespace':bad['parent_observation']['namespaces']['user']=bad['parent_observation']['observer']['namespaces']['user']
        elif mutate=='mapping':bad['parent_observation']['uid_map'][0][1]=0
        elif mutate=='groups':bad['worker_ready']['groups']=[0]
        elif mutate=='bool':bad['worker_ready']['uid']=True
        else:bad['parent_observation']['descriptors'][0]['inode']+=1
        refused(r.validate_readiness,'headers',bad,bundle)

    ready=declared_readiness(declared_runtime(),'parser')
    extra={**ready['parent_observation']['descriptors'][-1],'fd':3,'purpose':'unexpected'}
    ready['parent_observation']['descriptors'].append(extra)
    ready['worker_ready']['descriptor_sha256']=r._hash(ready['parent_observation']['descriptors'])
    refused(r.validate_readiness,'parser',ready,declared_runtime())
    for role,cap in (('endpoint',7),('broker',21),('terminal',5),('graphical',7),('headers',3),('admission',3)):
        assert r._steady_fd_max(role)==cap
    assert r._steady_fd_max('nmap','native')==16

    # Exercise the actual bootstrap branch with modeled OS boundaries. The
    # launcher and reviewer both select full process, namespace and socketpair
    # denial witnesses. No resource/filter is installed.
    import resource
    from recon_cockpit.secure_agent import planner_worker,worker,name_tls_worker_common
    routed=[]
    with monkeypatch.context() as patch:
        patch.setattr(resource,'getrlimit',lambda kind:(resource.RLIM_INFINITY,resource.RLIM_INFINITY))
        patch.setattr(resource,'setrlimit',lambda *args:None)
        patch.setattr(os,'listdir',lambda path:['1'])
        patch.setattr(os,'statvfs',lambda path:SimpleNamespace(f_flag=os.ST_RDONLY))
        patch.setattr(os,'getuid',lambda:65534);patch.setattr(os,'getgid',lambda:65534)
        patch.setattr(os,'getgroups',lambda:[65534])
        patch.setattr(worker,'drop_privileges',lambda:None)
        patch.setattr(name_tls_worker_common,'seal_group_identity',lambda identity:None)
        patch.setattr(r,'_install_filter',lambda role:routed.append(('filter',role)))
        patch.setattr(planner_worker,'_sockets_blocked',lambda:routed.append(('witness','legacy_full')))
        for name in ('_zero_capabilities','_no_new_privileges'):
            patch.setattr(planner_worker,name,lambda:None)
        for name in ('_process_creation_blocked','_namespace_creation_blocked'):
            patch.setattr(planner_worker,name,lambda name=name:routed.append(('witness',name)))
        for role in ('launcher','terminal'):
            selected=next(row for row in bundle['roles'] if row['role']==role)
            declared=declared_readiness(bundle,role)
            descriptors=declared['parent_observation']['descriptors']
            patch.setattr(r,'_fd_inventory',lambda **kwargs:deepcopy(descriptors))
            deadline=r.time.monotonic_ns()+1000000000
            bootstrap={**declared['worker_ready'],'deadline_ns':deadline}
            entry={'role':role,'bootstrap':bootstrap,'identity':{},'namespaces':declared['worker_ready']['namespaces'],
                'purposes':{row['fd']:row['purpose'] for row in descriptors},'descriptors':descriptors}
            ready=r.bootstrap_role(role=role,entry=entry,runtime_manifest=selected,
                expected_fds={row['purpose']:row['fd'] for row in descriptors if row['fd']>2},deadline_ns=deadline)
            assert ready['role']==role
    assert routed==[item for role in ('launcher','terminal') for item in [('filter',role),('witness','_process_creation_blocked'),('witness','_namespace_creation_blocked'),('witness','legacy_full')]]

    from recon_cockpit.secure_agent import engagement_live_context as context
    for case_id in ('S42C-X45','S42C-X46'):
        bundle=declared_runtime();case=r.SPEC['owned_meter_connection_fixture']['cases'][case_id]
        config={'case_id':case_id,'variant':case['variant'],'role':'endpoint'}
        names=('engagement_live_endpoint_worker','engagement_live_runtime')
        for index,name in enumerate(names,1):
            for row in bundle['sources']+[row for role in bundle['roles'] for row in role['sources']]:
                if row['module']==name:row['sha256']=str(index)*64
        ready=declared_readiness(bundle,'endpoint')
        purposes=[r.SPEC['owned_meter_connection_fixture']['steady_descriptor_purposes'][str(fd)] for fd in range(5,case['steady_descriptors'])]
        descriptors=ready['parent_observation']['descriptors']
        for fd,purpose in enumerate(purposes,5):
            descriptors.append({'fd':fd,'purpose':purpose,'kind':'stream_socket','device':1,
                'inode':900+fd,'mode':stat.S_IFSOCK|0o777,'flags':os.O_RDWR|os.O_NONBLOCK})
        ready['worker_ready']['descriptor_sha256']=r._hash(descriptors)
        loaded={'manifest.json':{'case_id':case_id,'evidence_class':'owned_gate','runtime_sha256':r.runtime_digest(bundle)},
            'runtime.json':{'schema_version':'1','runtime':bundle,'instrumentation':[
                {'kind':'sealed_fault','configuration':config,'configuration_sha256':r._hash(config),'source_sha256':str(i)*64} for i in (1,2)]},
            'processes.json':{'readiness':[ready]},'results.json':{'boundary_proofs':[{
                'case_id':case_id,'role':'endpoint','kind':'meter_boundary','runtime_sha256':r.runtime_digest(bundle),
                'source_sha256':'1'*64,'control_observation_sha256':r._hash(ready)}]}}
        refused(r.validate_readiness,'endpoint',ready,bundle)
        with context._retained_fixture_validation(loaded,deadline=r.time.monotonic()+1):
            assert r._steady_fd_max('endpoint')==7
            assert r.validate_readiness('endpoint',ready,bundle)==ready
            assert r.validate_protocol_value('role_readiness',ready)==ready
            with context._retained_fixture_validation({'manifest.json':{'case_id':None}}):
                refused(r.validate_readiness,'endpoint',ready,bundle)
            assert r.validate_readiness('endpoint',ready,bundle)==ready
        refused(r.validate_readiness,'endpoint',ready,bundle)
        for field in ('class','config','source','purpose','count','proof'):
            bad=deepcopy(loaded)
            if field=='class':bad['manifest.json']['evidence_class']='production_run'
            elif field=='config':bad['runtime.json']['instrumentation'][0]['configuration']['role']='launcher'
            elif field=='source':bad['runtime.json']['instrumentation'][0]['source_sha256']='f'*64
            elif field=='purpose':bad['processes.json']['readiness'][0]['parent_observation']['descriptors'][6]['purpose']='observed'
            elif field=='count':bad['processes.json']['readiness'][0]['parent_observation']['descriptors'].pop()
            else:bad['results.json']['boundary_proofs'][0]['control_observation_sha256']='f'*64
            with pytest.raises(c.LiveError):
                with context._retained_fixture_validation(bad):raise AssertionError('invalid fixture selected')
            assert r._RETAINED_FIXTURE_DESCRIPTORS.get()is None
        with pytest.raises(RuntimeError):
            with context._retained_fixture_validation(loaded):raise RuntimeError('bounded callback failure')
        assert r._RETAINED_FIXTURE_DESCRIPTORS.get()is None


def test_actual_native_elf_required_before_arm(monkeypatch):
    _supervised_native_receipt_cases(monkeypatch)
    bundle=declared_runtime();waiting=declared_readiness(bundle,'nmap')
    image=waiting['parent_observation']['executable']
    bad={'schema_version':'1','role':'nmap','waiting_image':image,'parent_observation':deepcopy(waiting['parent_observation']),'observed_at_ns':2000000000}
    refused(r.validate_protocol_value,'native_readiness',bad)
    bad['parent_observation']['stage']='native';bad['parent_observation']['executable']['destination']='/tool/nmap'
    refused(r.validate_protocol_value,'native_readiness',bad)
    bad['parent_observation']['executable']['sha256']='f'*64
    assert r.validate_protocol_value('native_readiness',bad)==bad


def _client_result():
    from recon_cockpit.secure_agent import engagement_live_context as context
    return {'schema_version':'1','dispatch_id':uid(10),'envelope_sha256':'a'*64,'runtime_sha256':'b'*64,'slot':'http_headers',
        'status':'failed','exit_code':1,'stop_reason':'native_failed','stdout_sha256':sha(b''),'stderr_sha256':sha(b''),
        'stdout_bytes':0,'stderr_bytes':0,'truncated':False,'readiness':None,'meter':None,'parsed':None,'parser_receipt':None,'cleanup':None}


def test_aggregate_raw_capture_budget(monkeypatch):
    _supervised_capture_cases(monkeypatch)
    from recon_cockpit.secure_agent import engagement_live_context as context
    result=_client_result();result.update(stdout_bytes=2047,stderr_bytes=1)
    assert context.validate_client_result(result)==result
    result['stderr_bytes']=2;refused(context.validate_client_result,result)
    result=_client_result();result['stdout_bytes']=True;refused(context.validate_client_result,result)


def test_original_startup_deadline(monkeypatch,tmp_path):
    _supervised_phase_deadline_cases(monkeypatch)
    _pending_close_deadline_case(monkeypatch)
    calls=[]
    parent=SimpleNamespace(deadline=12.,clock=r.time.monotonic,cancelled=object(),check=lambda:calls.append('check'),remaining=lambda:1.25)
    clipped=r._ClippedControl(parent,11.)
    assert clipped.cancelled is parent.cancelled and clipped.clock is parent.clock and clipped.deadline==11.
    parent.check=lambda:(_ for _ in ()).throw(c.LiveError('engagement_live_cancelled'))
    refused(clipped.check);refused(clipped.remaining)

    # Verification cleanup cannot hand an expired original allowance to recv,
    # even when a bootstrap packet would already be readable.
    import socket
    manifest=next(x for x in declared_runtime()['roles'] if x['role']=='parser')
    now=[10.];received=[]
    decoded=[];real_decode=r._decode
    def decode_at_original_deadline(*args):
        assert c._operation_deadline()==12.
        decoded.append('manifest')
        now[0]=10.25
        assert c._operation_deadline()==12.
        return real_decode(*args)
    def late_cleanup(**kwargs):
        assert kwargs['control'].deadline==12.
        now[0]=12.01
    with monkeypatch.context() as patch:
        patch.setattr(r.time,'monotonic',lambda:now[0])
        patch.setattr(r,'_read_file',lambda *args:raw(manifest))
        patch.setattr(r,'_decode',decode_at_original_deadline)
        patch.setattr(r,'_close_import_descriptor',late_cleanup)
        patch.setattr(socket,'socket',lambda **kwargs:received.append('channel'))
        assert refused(r._receive_initial,'parser',uid(1),'a'*64,entry_verified=True).code=='engagement_live_timeout'
        assert decoded==['manifest'] and received==[]
    _audit_readback_cases(tmp_path,monkeypatch,('deadline_before','deadline_after_close','deadline_maps_close'))

    import resource
    from recon_cockpit.secure_agent.engagement_live_endpoint_worker import _nft_child_limits
    applied={}
    monkeypatch.setattr(resource,'getrlimit',lambda kind:(resource.RLIM_INFINITY,32 if kind==resource.RLIMIT_NOFILE else resource.RLIM_INFINITY))
    monkeypatch.setattr(resource,'setrlimit',lambda kind,pair:applied.__setitem__(kind,pair))
    _nft_child_limits()
    assert applied[resource.RLIMIT_AS]==(256*1048576,)*2
    assert applied[resource.RLIMIT_CPU]==(2,2) and applied[resource.RLIMIT_NPROC]==(1,1)
    assert applied[resource.RLIMIT_NOFILE]==(32,32) and applied[resource.RLIMIT_FSIZE]==(0,0)
    assert applied[resource.RLIMIT_CORE]==(0,0)

    # Emergency helper cleanup still closes every pipe if reaping or an earlier
    # close fails; the original work deadline never becomes another setup budget.
    import subprocess
    from recon_cockpit.secure_agent import engagement_live_endpoint_worker as endpoint
    events=[]
    class Pipe:
        def __init__(self,name,fd):self.name,self.fd=name,fd
        def fileno(self):return self.fd
        def close(self):
            events.append(self.name)
            if self.name=='stdin':raise OSError(errno.EIO,'injected close failure')
    def wait(*,timeout):
        events.append(('wait',timeout))
        raise subprocess.TimeoutExpired('fixed nft',timeout)
    process=SimpleNamespace(stdin=Pipe('stdin',100),stdout=Pipe('stdout',101),stderr=Pipe('stderr',102),
        poll=lambda:None,kill=lambda:events.append('kill'),wait=wait)
    monkeypatch.setattr(subprocess,'Popen',lambda *a,**k:process)
    monkeypatch.setattr(endpoint.os,'set_blocking',lambda *a:None)
    monkeypatch.setattr(endpoint.select,'select',lambda *a:(_ for _ in ()).throw(c.LiveError('engagement_live_timeout')))
    with pytest.raises(c.LiveError,match='engagement_live_cleanup_incomplete'):
        endpoint._run_nft(b'table inet x {}',True,r.time.monotonic_ns()+1000000000)
    assert events[0]=='kill' and events[1][0]=='wait' and 0<events[1][1]<=2
    assert events[2:]==['stdin','stdout','stderr']


def test_native_action_session_deadline_minimum(monkeypatch):
    _supervised_native_clock_case(monkeypatch)
    from recon_cockpit.secure_agent.engagement_live_client import WaitingClient
    from test_secure_engagement_live_contract import prepared,release,clock,M
    value=prepared();calls=[]
    owner=SimpleNamespace(ready={},pin=SimpleNamespace(check_alive=lambda:calls.append('pin')),channel=object())
    client=WaitingClient(owner,value,{})
    monkeypatch.setattr(c,'sample_clock',lambda:clock());monkeypatch.setattr(r.time,'monotonic',lambda:M/1e9)
    monkeypatch.setattr(r,'_send_bytes',lambda channel,data,control:calls.append(control.deadline))
    control=SimpleNamespace(deadline=M/1e9+3,clock=r.time.monotonic,cancelled=object(),check=lambda:None,remaining=lambda:3)
    client.release(release(value),control)
    assert calls==['pin',M/1e9+3]
    refused(client.release,release(value),control)


def test_parser_closed_input_and_reply(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_parser as parser
    from test_secure_engagement_live_contract import opened
    control=SimpleNamespace(deadline=r.time.monotonic()+2,clock=r.time.monotonic,cancelled=object(),check=lambda:None,remaining=lambda:2)
    common=dict(raw=b'',stderr=b'',scope=opened()['scope'],truncated=False,control=control,runtime={})
    refused(parser.parse,tool_id='configurable_ssh_host_keys_v1',**common)
    common['raw']=b'x'*8192;common['stderr']=b'x';refused(parser.parse,tool_id=parser.parser.NMAP,**common)
    refused(r._decode,b'{"x":1,"x":2}')
    refused(r._decode,b'{"x":true}garbage')


def _parser_model(monkeypatch,late=False):
    from recon_cockpit.secure_agent import engagement_live_parser as parser
    from test_secure_engagement_live_contract import opened
    calls=[];bundle=declared_runtime();ready=declared_readiness(bundle,'parser');cleanup=declared_cleanup(ready)
    state={'late':False}
    def check():
        if state['late']:raise c.LiveError('engagement_live_timeout')
    control=SimpleNamespace(deadline=r.time.monotonic()+2,clock=r.time.monotonic,cancelled=object(),check=check,remaining=lambda:2)
    def close():calls.append('cleanup');state['late']=late;return cleanup
    owner=SimpleNamespace(ready=ready,pin=SimpleNamespace(check_alive=lambda:calls.append('pin')),channel=object(),close=close)
    monkeypatch.setattr(r,'_start_role',lambda **kw:owner)
    monkeypatch.setattr(r,'_send_bytes',lambda *a:calls.append('input'))
    monkeypatch.setattr(r,'_receive_bytes',lambda *a:r._json({'schema_version':'1','slot':'http_headers','parsed':{'declared':True}}))
    monkeypatch.setattr(parser.parser,'validate_result',lambda *a:{'declared':True})
    kwargs=dict(tool_id=parser.parser.HEADERS,raw=b'captured',stderr=b'',scope=opened()['scope'],truncated=False,control=control,runtime=bundle)
    return parser,kwargs,calls


def test_parser_pin_before_input_release(monkeypatch):
    _supervised_parser_case(monkeypatch)
    parser,kwargs,calls=_parser_model(monkeypatch)
    result,receipt=parser.parse(**kwargs)
    assert calls==['pin','input','cleanup'] and result=={'declared':True}
    assert receipt['cleanup']['status']=='complete'


def test_payload_hup_and_shared_cleanup_deadline(monkeypatch):
    import signal
    class Poll:
        flags=select.POLLIN
        def register(self,*a):pass
        def poll(self,*a):return [(9,self.flags)]
    monkeypatch.setattr(select,'poll',Poll)
    assert r._payload_state(9)=='exited';Poll.flags=select.POLLHUP;assert r._payload_state(9)=='reaped'
    for flags in (0,select.POLLNVAL,select.POLLERR):Poll.flags=flags;refused(r._payload_state,9)
    calls=[];now=[0]
    monkeypatch.setattr(r.time,'monotonic_ns',lambda:now[0]+1000000000)
    monkeypatch.setattr(r.time,'sleep',lambda amount:now.__setitem__(0,now[0]+int(amount*1e9)))
    class Process:
        pid=100;returncode=None;stdin=stdout=stderr=None
        def poll(self):return self.returncode
        def wait(self,timeout):calls.append(('wait',timeout));self.returncode=-9
    process=Process()
    pin=SimpleNamespace(role='parser',pid=101,identity={'start_time_ticks':1},verified=True,process=process,fd=9,close=lambda:calls.append('close'))
    states=iter(['alive','reaped'])
    monkeypatch.setattr(r,'_payload_state',lambda fd:next(states))
    monkeypatch.setattr(signal,'pidfd_send_signal',lambda *a:calls.append('signal'),raising=False)
    monkeypatch.setattr(os,'killpg',lambda *a:calls.append('wrapper'))
    result=r.cleanup_owned([process],[pin],deadline=2.)
    assert result['deadline_ns']==2000000000 and result['status']=='complete'
    assert calls[0]=='signal' and calls[-1]=='close' and 0<calls[-2][1]<=.9
    calls.clear()
    owner=r.PendingChild(runtime={},role='parser',bootstrap={},control=SimpleNamespace(deadline=2.,cleanup_deadline=1.5))
    monkeypatch.setattr(r,'cleanup_owned',lambda processes,pins,deadline:(calls.append(deadline) or result))
    assert owner.close() is result and owner.close(deadline=9.) is result and calls==[1.5]


def test_cleanup_failure_refuses_useful_result(monkeypatch):
    _supervised_parser_case(monkeypatch,late=True)
    actual=declared_cleanup(declared_readiness(declared_runtime(),'admission'))
    actual['status']='failed'
    peer=SimpleNamespace(close=lambda:None)
    child=r.LauncherChild(SimpleNamespace(), 'identify_admission',peer,{}, {}, {})
    child.cleanup=actual
    for _ in range(2):
        error=refused(child.close)
        assert error.code=='engagement_live_cleanup_incomplete' and error.cleanup is actual

    parser,kwargs,calls=_parser_model(monkeypatch,late=True)
    refused(parser.parse,**kwargs)
    assert calls==['pin','input','cleanup']
    from recon_cockpit.secure_agent import engagement_live_context as context
    result=_client_result();result.update(status='succeeded',exit_code=0,stop_reason=None,parsed={'declared':True})
    refused(context.validate_client_result,result)
    calls=[]
    def broken_close():calls.append('snapshot');raise OSError('close failure')
    process=SimpleNamespace(_engagement_unverified_pin=SimpleNamespace(entry_receipt={'actual':'entry'}))
    actual={'status':'complete'}
    monkeypatch.setattr(r,'cleanup_owned',lambda processes,pins:(calls.append('reap') or actual))
    monkeypatch.setattr(os,'close',lambda fd:calls.append(('fd',fd)))
    peer=lambda name:SimpleNamespace(close=lambda:calls.append(name))
    original=c.LiveError('engagement_live_invalid_role');rights={'owned':17}
    r._release_startup_resources(snapshot=SimpleNamespace(close=broken_close),info_read=18,info_write=19,
        child=peer('child'),rights=rights,parent=peer('parent'),process=process,owner=None,
        successful=False,failure=original)
    assert calls==['snapshot',('fd',19),('fd',18),'child',('fd',17),'parent','reap']
    assert rights=={} and original.startup_cleanup is actual and original.startup_observation=={'actual':'entry'}
    calls.clear()
    error=refused(r._release_startup_resources,snapshot=SimpleNamespace(close=broken_close),info_read=None,
        info_write=None,child=peer('child'),rights={},parent=peer('parent'),process=process,
        owner=None,successful=True,failure=None)
    assert calls==['snapshot','child','parent','reap'] and error.startup_cleanup is actual


def test_context_runtime_meter_parser_crosslinks():
    from recon_cockpit.secure_agent import engagement_live_context as context
    bundle=declared_runtime();loaded={'runtime.json':{'schema_version':'1','runtime':bundle,'instrumentation':[]},
        'manifest.json':{'runtime_sha256':r.runtime_digest(bundle),'broker_instances':[],'transcript':{'segments':[]}},
        'transcript.jsonl':b'',
        'processes.json':{'schema_version':'1','startup':[],'readiness':[],'native':[],'child_slots':[],'boundary_observations':[]},
        'results.json':{'schema_version':'1','operations':[],'boundary_proofs':[],'core_proofs':[]},
        'cleanup.json':{'schema_version':'1','receipts':[],'supervisors':[],'exports':[],'recovery':None}}
    assert context.validate_live_context(loaded)==loaded['results.json']
    bad=deepcopy(loaded);bad['manifest.json']['runtime_sha256']='0'*64;refused(context.validate_live_context,bad)
    bad=deepcopy(loaded);bad['cleanup.json']['recovery']={};refused(context.validate_live_context,bad)
    bad=deepcopy(loaded);bad['processes.json']['native']=[{'role':'nmap'}];refused(context.validate_live_context,bad)
    ready=declared_readiness(bundle);entry=deepcopy(ready['parent_observation']);entry['stage']='entry'
    bad=deepcopy(loaded);bad['processes.json']['startup']=[entry]
    refused(context.validate_live_context,bad) # Observed startup cannot disappear without actual cleanup.
    bad['cleanup.json']['receipts']=[declared_cleanup(ready)]
    assert context.validate_live_context(bad)==bad['results.json']
    bad['processes.json']['startup'][0]['stage']='sealed';refused(context.validate_live_context,bad)
    bad=deepcopy(loaded);config={'case_id':'S42C-X01','variant':'sealed_nmap_executable_changed','role':'nmap'}
    fault={'kind':'sealed_fault','configuration':config,'configuration_sha256':r._hash(config),'source_sha256':'f'*64}
    bad['runtime.json']['instrumentation']=[fault]
    refused(context.validate_live_context,bad)
    fault['source_sha256']=bundle['sources'][0]['sha256']
    assert context.validate_live_context(bad)==bad['results.json']
    fault['kind']='scripted_review';fault['source_sha256']='f'*64
    # A declared host-driver commitment is not mislabeled a sealed worker hash.
    assert context.validate_live_context(bad)==bad['results.json']



def _supervised_data(slot='http_identify'):
    from test_secure_engagement_live_contract import opened,prepared,M
    bundle=declared_runtime();session=opened();session['binding']['runtime_sha256']=r.runtime_digest(bundle)
    value=prepared(slot,opened_value=session);endpoint=declared_readiness(bundle,'endpoint')
    bindings=[]
    for index,(name,(role,action,fd)) in enumerate(c.CHILD_SLOTS.items()):
        bindings.append({'child_slot':name,'role':role,'worker_id':uid(400+index),'pair':{
            'launcher_fd':fd,'request_endpoint':{'device':1,'inode':500+index*2,'mode':stat.S_IFSOCK,'flags':2|0x800},
            'child_endpoint':{'device':1,'inode':501+index*2,'mode':stat.S_IFSOCK,'flags':2|0x800}}})
    return bundle,session,value,endpoint,bindings


def _supervised_bootstrap_cases(monkeypatch):
    bundle,session,value,endpoint,bindings=_supervised_data()
    observer=endpoint['parent_observation']['observer'];deadline=value['envelope']['action_deadline_ns']
    from test_secure_engagement_live_contract import prepared
    # This is pure reconstruction: any accidental filesystem/clock call fails.
    with monkeypatch.context() as patch:
        patch.setattr(r,'_observer',lambda:(_ for _ in ()).throw(AssertionError('pure replay read host')))
        for binding in bindings:
            item=prepared(c.CHILD_SLOTS[binding['child_slot']][1],opened_value=session)
            boot=r.reconstruct_child_bootstrap(runtime=bundle,child_slot=binding,prepared=item,session=session,
                endpoint_identity=endpoint,observer=observer,deadline_ns=deadline,launcher_id=uid(300))
            assert boot['descriptors']==[] and boot['worker_id']==binding['worker_id']
            assert boot['deadline_ns']==deadline
            assert boot['expected_namespaces']['net']==(endpoint['parent_observation']['namespaces']['net'] if binding['role'] in ('nmap','headers') else observer['namespaces']['net'])
            assert r.validate_protocol_value('initial_bootstrap',boot)==boot
            for mutate in ('rights','observer','deadline','role'):
                bad=deepcopy(boot)
                if mutate=='rights':bad['descriptors']=[{'fd':3}]
                elif mutate=='observer':bad['observer']['uid']=True
                elif mutate=='deadline':bad['deadline_ns']=True
                else:bad['role']='launcher'
                refused(r.validate_initial_bootstrap,bad)
    bad=deepcopy(bindings[0]);bad['pair']['child_endpoint']=deepcopy(bad['pair']['request_endpoint'])
    refused(r.validate_child_slot,bad)


def _supervised_spawn_cases(monkeypatch):
    import socket,subprocess
    from recon_cockpit.secure_agent.execution import ExecutionControl
    bundle,session,value,endpoint,bindings=_supervised_data()
    binding=next(x for x in bindings if x['role']=='parser')
    manifest=next(x for x in bundle['roles'] if x['role']=='parser')
    for oversize in (False,True):
        parent,child=socket.socketpair();calls=[];fds=[]
        snapshot=SimpleNamespace(role='parser',runtime_sha256=r.runtime_digest(bundle),manifest=manifest,
            pass_fds=(),close=lambda:calls.append('snapshot_closed'))
        control=ExecutionControl(r.time.monotonic()+30)
        payload={'slot':'http_identify','scope':session['scope']}
        def launch(argv,**kwargs):
            calls.append('popen');fds.extend(kwargs['pass_fds'])
            assert kwargs['stdin'] is child and kwargs['close_fds'] and kwargs['start_new_session']
            assert kwargs['stdin'] is not parent
            raise OSError(errno.EIO,'fixed pre-spawn refusal')
        with monkeypatch.context() as patch:
            patch.setattr(r,'snapshot_role',lambda *a:snapshot)
            patch.setattr(r,'_observer',lambda:endpoint['parent_observation']['observer'])
            patch.setattr(r,'_base_command',lambda *a,**kw:['fixed'])
            patch.setattr(r,'_finish_command',lambda *a,**kw:None)
            patch.setattr(r.os,'pipe2',lambda flags:os.pipe(),raising=False)
            patch.setattr(subprocess,'Popen',launch)
            original_json=r._json
            if oversize:patch.setattr(r,'_json',lambda obj:b'x'*32769 if type(obj)is dict and obj.get('operation')=='BOOTSTRAP' else original_json(obj))
            try:
                if oversize:
                    assert refused(r._spawn_child_owned,runtime=bundle,role='parser',payload=payload,
                        child_stdin=child,worker_id=binding['worker_id'],control=control,
                        supervision_identity={'launcher_id':uid(300),'child_slot':binding['child_slot']}).code=='engagement_live_limit_exceeded'
                else:
                    with pytest.raises(OSError,match='fixed pre-spawn refusal'):
                        r._spawn_child_owned(runtime=bundle,role='parser',payload=payload,child_stdin=child,
                            worker_id=binding['worker_id'],control=control,
                            supervision_identity={'launcher_id':uid(300),'child_slot':binding['child_slot']})
            finally:parent.close()
        assert child.fileno()==-1 and calls==(['snapshot_closed'] if oversize else ['popen','snapshot_closed'])
        for fd in fds:
            with pytest.raises(OSError):os.fstat(fd)
    # Namespace helper image changes reuse the same wrapper; no hidden fork.
    argv,passed=r._namespace_command(['fixed-bwrap'],(10,11),(12,13))
    assert argv[:2]==['/usr/bin/nsenter','--no-fork'] and 'os.execv' in argv[-3]
    assert passed==(10,11,12,13)


def _pending_close_deadline_case(monkeypatch):
    bundle=declared_runtime();ready=declared_readiness(bundle,'parser');now=[10.];calls=[]
    control=SimpleNamespace(deadline=12.,clock=lambda:now[0],cancelled=object(),cleanup_deadline=13.,
        check=lambda:None,remaining=lambda:12.-now[0])
    owner=r.PendingChild(runtime=bundle,role='parser',bootstrap={'expected_namespaces':{}},control=control)
    owner.process=object();owner.pin=object();owner.entry={'retained':'entry'};owner.info_read=81
    def close(fd):calls.append(('close',fd));now[0]=12.1
    cleanup=declared_cleanup(ready)
    with monkeypatch.context() as patch:
        patch.setattr(r.time,'monotonic',lambda:now[0])
        patch.setattr(r,'_finish_observation',lambda **kw:(owner.pin,ready))
        patch.setattr(r.os,'close',close)
        patch.setattr(r,'cleanup_owned',lambda processes,pins,deadline:(calls.append(('cleanup',deadline)) or cleanup))
        error=refused(owner.observe_ready,control)
    assert error.code=='engagement_live_timeout' and error.startup_cleanup==cleanup
    assert owner.info_read is None and calls==[('close',81),('cleanup',13.)]


def _capture_fixture(monkeypatch,*,stdout=b'',stderr=b'',slot='http_headers'):
    from recon_cockpit.secure_agent.engagement_live_client import SupervisedCapture
    from test_secure_engagement_live_contract import prepared
    bundle=declared_runtime();ready=declared_readiness(bundle,'headers' if slot=='http_headers' else 'nmap')
    pipes=[]
    for content in (stdout,stderr):
        rd,wr=os.pipe();os.write(wr,content);os.close(wr);pipes.append(os.fdopen(rd,'rb',buffering=0))
    calls=[];cleanup=declared_cleanup(ready)
    process=SimpleNamespace(stdout=pipes[0],stderr=pipes[1],returncode=0,poll=lambda:0)
    owner=SimpleNamespace(ready=ready,cleanup=None,process=process,pin=SimpleNamespace(check_alive=lambda:calls.append('alive')))
    def close(*,deadline):calls.append(('close',deadline));owner.cleanup=cleanup;return cleanup
    owner.close=close
    engine=SupervisedCapture(owner,prepared(slot),bundle)
    control=SimpleNamespace(deadline=r.time.monotonic()+5,clock=r.time.monotonic,cancelled=object(),
        check=lambda:None,remaining=lambda:5,cleanup_deadline=r.time.monotonic()+2)
    engine.started_at_ns=r.time.monotonic_ns();engine.native_deadline_ns=int(control.deadline*1e9)
    return engine,control,calls,pipes


def _supervised_capture_cases(monkeypatch):
    for stdout,stderr,overflow in ((b'a'*2047,b'b',False),(b'a'*2048,b'b',True)):
        engine,control,calls,pipes=_capture_fixture(monkeypatch,stdout=stdout,stderr=stderr)
        try:
            if overflow:
                error=refused(engine.capture,control)
                assert error.code=='engagement_live_limit_exceeded'
                assert error.client_capture['truncated'] and error.client_capture['status']=='output_limit'
                assert len(error.client_capture['stdout'])+len(error.client_capture['stderr'])==2048
            else:
                value=engine.capture(control)
                assert value['status']=='succeeded' and value['capture']['stdout_bytes']==2047 and value['capture']['stderr_bytes']==1
                assert value['cleanup']['status']=='complete'
            assert len(calls)==1 and calls[0][0]=='close'
            refused(engine.capture,control)
        finally:
            for pipe in pipes:pipe.close()
    # Native image observation actively drains; it does not wait for CAPTURE.
    engine,control,calls,pipes=_capture_fixture(monkeypatch,stdout=b'actual pipe bytes',slot='http_identify')
    try:
        with monkeypatch.context() as patch:
            def observe(*args,control,**kwargs):control.check();return {'declared_native':True}
            patch.setattr(r,'observe_native',observe)
            assert engine.observe_native(control)=={'declared_native':True}
        assert engine.partial()['stdout']==b'actual pipe bytes'
        refused(engine.observe_native,control)
    finally:
        for pipe in pipes:pipe.close()


def _supervised_native_clock_case(monkeypatch):
    from recon_cockpit.secure_agent.engagement_live_client import SupervisedCapture,SupervisedWaitingClient
    from test_secure_engagement_live_contract import prepared,release,clock,M
    engine,control,calls,pipes=_capture_fixture(monkeypatch)
    try:
        value=prepared('http_headers');engine.prepared=value;engine.native_deadline_ns=None
        with monkeypatch.context() as patch:
            patch.setattr(c,'sample_clock',lambda:clock())
            patch.setattr(r.time,'monotonic',lambda:M/1e9)
            patch.setattr(r.time,'monotonic_ns',lambda:M)
            control.deadline=M/1e9+3;control.clock=lambda:r.time.monotonic()
            result=engine.begin(release(value),control)
            assert result['native_deadline_ns']==M+c.SECOND
            refused(engine.begin,release(value),control)
            patch.setattr(r.time,'monotonic_ns',lambda:M+c.SECOND)
            assert refused(engine.drain,control).code=='engagement_live_timeout'
            assert engine.partial()['status']=='timeout' # idle driver can retain this before cleanup
        # Release cannot reach the direct child endpoint before one actual budget.
        order=[];owner=SimpleNamespace(slot='headers_client',channel=object(),ready={})
        supervisor=SimpleNamespace(native_begin=lambda **kw:(order.append('native_begin') or {'native_deadline_ns':M+c.SECOND}))
        client=SupervisedWaitingClient(owner,value,{},supervisor)
        with monkeypatch.context() as patch:
            patch.setattr(c,'sample_clock',lambda:clock());patch.setattr(r.time,'monotonic',lambda:M/1e9)
            patch.setattr(r,'_send_bytes',lambda *a:order.append('direct_go'))
            client.release(release(value),control);refused(client.release,release(value),control)
        assert order==['native_begin','direct_go']
    finally:
        for pipe in pipes:pipe.close()


def _supervised_parser_case(monkeypatch,late=False):
    from recon_cockpit.secure_agent import engagement_live_parser as parser
    from test_secure_engagement_live_contract import opened,prepared
    bundle=declared_runtime();ready=declared_readiness(bundle,'parser');cleanup=declared_cleanup(ready)
    calls=[];state={'expired':False}
    def check():
        if state['expired']:raise c.LiveError('engagement_live_timeout')
    control=SimpleNamespace(deadline=r.time.monotonic()+2,clock=r.time.monotonic,cancelled=object(),check=check,remaining=lambda:2)
    def close(*,deadline):calls.append('actual_reap');assert deadline<=control.deadline;state['expired']=late;return cleanup
    owner=SimpleNamespace(ready=ready,channel=object(),close=close)
    def start(**kwargs):calls.append('host_ready');assert kwargs['child_slot']=='headers_parser';return owner
    supervisor=SimpleNamespace(start_child=start)
    with monkeypatch.context() as patch:
        patch.setattr(r,'_send_bytes',lambda *a:calls.append('direct_input'))
        patch.setattr(r,'_receive_bytes',lambda *a:r._json({'schema_version':'1','slot':'http_headers','parsed':{'declared':True}}))
        patch.setattr(parser.parser,'validate_result',lambda *a:{'declared':True})
        kwargs=dict(tool_id=parser.parser.HEADERS,raw=b'captured',stderr=b'',scope=opened()['scope'],truncated=False,
                    control=control,runtime=bundle,prepared=prepared('http_headers'),supervisor=supervisor)
        if late:refused(parser._parse_supervised_observed,**kwargs)
        else:
            parsed,receipt,observed=parser._parse_supervised_observed(**kwargs)
            assert parsed=={'declared':True} and observed==ready and receipt['cleanup']==cleanup
    assert calls==['host_ready','direct_input','actual_reap']

def _supervised_proxy_cases(monkeypatch):
    import socket
    from recon_cockpit.secure_agent import engagement_live_protocol as protocol
    from test_secure_engagement_live_contract import M
    # Actual ordinary stream pairs retain distinct opposite-end identities.
    # Only received fd numbering/Linux flag spelling is modeled for portability.
    for mutation in (None,'swap','bootstrap','worker','stdin','observer','runtime'):
        bundle,session,prepared,endpoint,bindings=_supervised_data()
        sockets=[];channels={};children={};observed={}
        for binding in bindings:
            parent,child=socket.socketpair();parent.setblocking(False);child.setblocking(False)
            sockets.extend((parent,child));name=binding['child_slot'];channels[name]=parent;children[name]=child
            for key,peer in (('request_endpoint',parent),('child_endpoint',child)):
                actual=r._descriptor(peer.fileno(),key)
                binding['pair'][key]={k:actual[k] for k in ('device','inode','mode','flags')}
                binding['pair'][key]['flags']=2|0x800
                assert os.get_blocking(peer.fileno())is False
            observed[parent.fileno()]={**r._descriptor(parent.fileno(),name+'_request'),
                'fd':binding['pair']['launcher_fd'],'flags':2|0x800}
        host,peer=socket.socketpair();sockets.extend((host,peer));calls=[]
        control=SimpleNamespace(deadline=M/1e9+30,clock=lambda:M/1e9,cancelled=object(),check=lambda:None,remaining=lambda:30)
        context={key:session['binding'] if key=='session_binding' else session[key] for key in ('session_binding','roe','scope','policy')}
        try:
            with monkeypatch.context() as patch:
                original_descriptor=r._descriptor
                patch.setattr(r,'_descriptor',lambda fd,purpose:{**observed[fd],'purpose':purpose} if fd in observed else original_descriptor(fd,purpose))
                selected=dict(channels)
                if mutation=='swap':selected['identify_client'],selected['headers_client']=selected['headers_client'],selected['identify_client']
                if mutation=='swap':
                    refused(r.SupervisorChannel,host,launcher_id=uid(300),slot_bindings=bindings,request_channels=selected,
                        runtime=bundle,endpoint_identity=endpoint,role_context=context,control=control)
                    continue
                proxy=r.SupervisorChannel(host,launcher_id=uid(300),slot_bindings=bindings,request_channels=selected,
                    runtime=bundle,endpoint_identity=endpoint,role_context=context,control=control)
                binding=bindings[0]
                bootstrap=r.reconstruct_child_bootstrap(runtime=bundle,child_slot=binding,prepared=prepared,session=session,
                    endpoint_identity=endpoint,observer=endpoint['parent_observation']['observer'],deadline_ns=M+30*c.SECOND,launcher_id=uid(300))
                ready=declared_readiness(bundle,'nmap',worker_id=binding['worker_id'])
                ready['worker_ready']['bootstrap_sha256']=r._hash(bootstrap)
                stdin=ready['parent_observation']['descriptors'][0]
                stdin.update(binding['pair']['child_endpoint']);ready['worker_ready']['descriptor_sha256']=r._hash(ready['parent_observation']['descriptors'])
                if mutation=='bootstrap':bootstrap['payload']['scope']['http']['port']+=1
                if mutation=='worker':ready['worker_ready']['worker_id']=uid(999)
                if mutation=='stdin':stdin['inode']+=1;ready['worker_ready']['descriptor_sha256']=r._hash(ready['parent_observation']['descriptors'])
                if mutation=='observer':ready['parent_observation']['observer']['pid']+=1
                if mutation=='runtime':ready['worker_ready']['runtime_sha256']='f'*64
                def rpc(op,body,phase):
                    calls.append(op)
                    if op=='START':return {'child_slot':'identify_client','bootstrap':bootstrap}
                    if op=='OBSERVE_READY':return {'child_slot':'identify_client','readiness':ready}
                    raise AssertionError('unexpected modeled host request')
                proxy._rpc=rpc
                patch.setattr(protocol,'send_initial',lambda channel,value,rights,control:(calls.append('INITIAL'),assert_no_rights(rights)))
                patch.setattr(r.time,'monotonic',lambda:M/1e9)
                if mutation is not None:
                    refused(proxy.start_child,child_slot='identify_client',prepared=prepared,control=control)
                    assert channels['identify_client'].fileno()==-1
                else:
                    owner=proxy.start_child(child_slot='identify_client',prepared=prepared,control=control)
                    assert owner.ready==ready and not hasattr(owner,'process') and not hasattr(owner,'pin')
                    assert calls==['START','INITIAL','OBSERVE_READY']
                    refused(proxy.start_child,child_slot='identify_client',prepared=prepared,control=control)
                    assert calls==['START','INITIAL','OBSERVE_READY']
        finally:
            for item in sockets:item.close()


def assert_no_rights(rights):
    assert rights==()


def _supervised_native_receipt_cases(monkeypatch):
    bundle,session,prepared,endpoint,bindings=_supervised_data()
    # Nmap and Python are distinct real image commitments in this fixture.
    for row in bundle['roles']:
        for image in row['native_files']:
            if image['destination']=='/tool/nmap':image['sha256']='c'*64
    bundle=r.validate_runtime(bundle)
    waiting=declared_readiness(bundle,'nmap');parent=deepcopy(waiting['parent_observation'])
    image=next(x for x in bundle['roles'] if x['role']=='nmap')['native_files']
    image=next(x for x in image if x['destination']=='/tool/nmap')
    parent.update(stage='native',sampled_at_ns=2000000000)
    parent['executable']={**parent['executable'],'destination':'/tool/nmap','sha256':image['sha256'],'size':image['size']}
    good={'schema_version':'1','role':'nmap','waiting_image':deepcopy(waiting['parent_observation']['executable']),
          'parent_observation':parent,'observed_at_ns':2000000000}
    for mutation in (None,'pid','start','hash','size','map','waiting','observer','stage'):
        value=deepcopy(good)
        if mutation=='pid':value['parent_observation']['payload']['pid']+=1
        elif mutation=='start':value['parent_observation']['payload']['start_time_ticks']+=1
        elif mutation=='hash':value['parent_observation']['executable']['sha256']='f'*64
        elif mutation=='size':value['parent_observation']['executable']['size']+=1
        elif mutation=='map':value['parent_observation']['mapped_images'].append({'destination':'/bad.so','device':1,'inode':999})
        elif mutation=='waiting':value['waiting_image']['inode']+=1
        elif mutation=='observer':value['parent_observation']['observer']['pid']+=1
        elif mutation=='stage':value['parent_observation']['stage']='sealed'
        proxy=r.SupervisorChannel.__new__(r.SupervisorChannel)
        proxy.runtime=bundle;proxy.states={'identify_client':'active'};proxy.native={}
        control=SimpleNamespace(deadline=r.time.monotonic()+2,check=lambda:None);proxy.control=control
        proxy.children={'identify_client':SimpleNamespace(ready=waiting)}
        proxy._rpc=lambda *args:{'child_slot':'identify_client','native_readiness':value}
        if mutation is None:assert proxy.observe_native(child_slot='identify_client',control=control)==good
        else:refused(proxy.observe_native,child_slot='identify_client',control=control)


def _supervised_phase_deadline_cases(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_parser as parser
    from recon_cockpit.secure_agent.engagement_live_client import SupervisedWaitingClient
    from test_secure_engagement_live_contract import opened,prepared
    # A host reply does not reset the original caller's remaining validation
    # allowance. Expiry closes the sole proxy channel before another release.
    now=[10.];calls=[]
    control=SimpleNamespace(deadline=11.,clock=lambda:now[0],cancelled=object(),
                            check=lambda:None,remaining=lambda:11.-now[0])
    proxy=r.SupervisorChannel.__new__(r.SupervisorChannel)
    proxy.control=control;proxy.states={'identify_client':'active'};proxy.native={}
    def rpc(*args):now[0]=10.75;calls.append('host_reply');return {'native_readiness':{}}
    def validate(*args):
        assert c._operation_deadline()==11.
        calls.append('original_validation');now[0]=11.01
        c.canonical({})
        raise AssertionError('expired validation returned')
    proxy._rpc=rpc;proxy.close=lambda:calls.append('closed')
    with monkeypatch.context() as patch:
        patch.setattr(r.time,'monotonic',lambda:now[0])
        patch.setattr(r,'validate_protocol_value',validate)
        assert refused(proxy.observe_native,child_slot='identify_client',control=control).code=='engagement_live_timeout'
    assert calls==['host_reply','original_validation','closed'] and proxy.native=={}

    # REAP's post-reply validator and real request-channel closure share the
    # same original bound; cached receipts are data, not another host exchange.
    now[0]=10.;calls=[]
    supervisor=SimpleNamespace(control=control,controls={'identify_parser':control},states={},
        _rpc=lambda *args:(calls.append('reap_reply') or {'cleanup':{}}))
    def cleanup_validation(*args):
        assert c._operation_deadline()==11.
        calls.append('cleanup_validation');now[0]=11.01;c.canonical({})
        raise AssertionError('expired cleanup validator returned')
    supervisor._check_cleanup=cleanup_validation
    child=r.LauncherChild(supervisor,'identify_parser',SimpleNamespace(close=lambda:calls.append('request_closed')),{}, {}, {})
    with monkeypatch.context() as patch:
        patch.setattr(r.time,'monotonic',lambda:now[0])
        assert refused(child.close).code=='engagement_live_timeout'
    assert calls==['reap_reply','cleanup_validation','request_closed'] and child.cleanup is None
    now[0]=10.;calls=[]
    actual=declared_cleanup(declared_readiness(declared_runtime(),'parser'))
    supervisor._check_cleanup=lambda *args:actual
    def late_channel_close():calls.append('request_closed');now[0]=11.01
    child=r.LauncherChild(supervisor,'identify_parser',SimpleNamespace(close=late_channel_close),{}, {}, {})
    with monkeypatch.context() as patch:
        patch.setattr(r.time,'monotonic',lambda:now[0])
        assert refused(child.close).code=='engagement_live_timeout'
    assert calls==['reap_reply','request_closed'] and child.cleanup is actual
    assert child.close() is actual and calls==['reap_reply','request_closed']

    # The public waiting-client proxy also binds release validation before its
    # NATIVE_BEGIN RPC; it cannot begin work after that validation uses the lease.
    value=prepared('http_headers');calls=[];now[0]=10.
    client=SupervisedWaitingClient(SimpleNamespace(ready={}),value,{},
        SimpleNamespace(native_begin=lambda **kwargs:calls.append('native_begin')))
    def release_validation(*args,**kwargs):
        assert c._operation_deadline()==11.
        now[0]=11.01;c.canonical({})
        raise AssertionError('expired validation returned')
    with monkeypatch.context() as patch:
        patch.setattr(r.time,'monotonic',lambda:now[0])
        patch.setattr(c,'validate_release_binding',release_validation)
        assert refused(client.release,{},control).code=='engagement_live_timeout'
    assert calls==[] and client.released is False

    # Parser input validation and encoding consume the same two-second phase
    # that later owns startup/input/reaping; an expired prelude starts no child.
    scope=opened()['scope'];calls=[];now[0]=10.;control.deadline=20.
    def scope_validation(value):
        assert c._operation_deadline()==12.
        now[0]=12.01;return value
    with monkeypatch.context() as patch:
        patch.setattr(r.time,'monotonic',lambda:now[0])
        patch.setattr(parser,'validate_scope',scope_validation)
        assert refused(parser._parse_supervised_observed,tool_id=parser.parser.HEADERS,
            raw=b'',stderr=b'',scope=scope,truncated=False,control=control,runtime={},
            prepared=value,supervisor=SimpleNamespace(start_child=lambda **kwargs:calls.append('start'))).code=='engagement_live_timeout'
    assert calls==[]
