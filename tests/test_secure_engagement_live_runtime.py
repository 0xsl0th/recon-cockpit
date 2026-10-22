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
        destinations={'/usr/bin/python3','/lib64/ld-linux-x86-64.so.2'}
        if role in ('nmap','launcher'):destinations.add('/tool/nmap')
        if role=='launcher':destinations.add('/usr/bin/bwrap')
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
    if role=='launcher':checks-={'process_creation_blocked','namespace_creation_blocked'};checks|={'bounded_child_creation','fixed_namespace_builder'}
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


def test_readiness_namespace_mapping_and_groups():
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


def test_actual_native_elf_required_before_arm():
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


def test_aggregate_raw_capture_budget():
    from recon_cockpit.secure_agent import engagement_live_context as context
    result=_client_result();result.update(stdout_bytes=2047,stderr_bytes=1)
    assert context.validate_client_result(result)==result
    result['stderr_bytes']=2;refused(context.validate_client_result,result)
    result=_client_result();result['stdout_bytes']=True;refused(context.validate_client_result,result)


def test_original_startup_deadline(monkeypatch):
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


def test_cleanup_failure_refuses_useful_result(monkeypatch):
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
        'manifest.json':{'runtime_sha256':r.runtime_digest(bundle),'broker_instances':[]},
        'processes.json':{'schema_version':'1','startup':[],'readiness':[],'native':[],'boundary_observations':[]},
        'results.json':{'schema_version':'1','operations':[],'boundary_proofs':[],'core_proofs':[]},
        'cleanup.json':{'schema_version':'1','receipts':[],'exports':[],'recovery':None}}
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


