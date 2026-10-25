"""Trusted orchestration of the fixed owned engagement process graph.

The host supplies no approval, durable witness, reservation, or release claim.
Those decisions remain on the inherited channels of their isolated owners.
"""

from copy import deepcopy
import base64
import os
from pathlib import Path
import stat
import threading
import time

from . import engagement_live_contract as c
from .models import parse_action, parse_policy


_RECOVERY_MAIN = 'records.sqlite3'
_RECOVERY_JOURNAL = _RECOVERY_MAIN + '-journal'
_RECOVERY_NAMES = (_RECOVERY_MAIN, _RECOVERY_JOURNAL)
_RECOVERY_PURPOSES = ('source_package', 'source_parent', 'source_store',
                      'scratch_parent', 'scratch_store')
_RECOVERY_FD_PURPOSES = (
    'bounded config then release input pipe', 'READY/result framed stdout pipe',
    'bounded diagnostic stderr pipe', 'sealed O_RDONLY source package',
    'held source parent directory', 'held source store directory',
    'registered scratch parent directory', 'registered scratch store directory')


class _RecoveryError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _recovery_json(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _recovery_check(deadline_ns):
    if time.monotonic_ns() >= deadline_ns:
        raise _RecoveryError('work_deadline')


def _recovery_identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'uid': info.st_uid, 'gid': info.st_gid}


def _recovery_stamp(info):
    return {**_recovery_identity(info), 'size': info.st_size, 'nlink': info.st_nlink,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def _recovery_read(fd, maximum, deadline_ns):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
        raise _RecoveryError('copy_limit')
    data = bytearray()
    while len(data) < before.st_size:
        _recovery_check(deadline_ns)
        part = os.pread(fd, min(65536, before.st_size - len(data)), len(data))
        if not part:
            raise _RecoveryError('source_changed')
        data.extend(part)
    if _recovery_stamp(before) != _recovery_stamp(os.fstat(fd)):
        raise _RecoveryError('source_changed')
    _recovery_check(deadline_ns)
    return bytes(data)


def _recovery_private_directory(fd):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid() or info.st_gid != os.getgid()):
        raise _RecoveryError('source_custody')
    return _recovery_identity(info)


def _recovery_directory_pair(parent, directory):
    parent_id = _recovery_private_directory(parent)
    directory_id = _recovery_private_directory(directory)
    parent_path = Path(os.readlink('/proc/self/fd/'+str(parent)))
    directory_path = Path(os.readlink('/proc/self/fd/'+str(directory)))
    if (directory_path.parent != parent_path
            or _recovery_identity(os.stat(parent_path, follow_symlinks=False)) != parent_id
            or _recovery_identity(os.stat(directory_path.name, dir_fd=parent,
                                           follow_symlinks=False)) != directory_id):
        raise _RecoveryError('source_custody')
    return parent_id, directory_id


def _recovery_file(fd, directory, name, deadline_ns):
    import fcntl
    before = os.fstat(fd)
    maximum = 8388608 if name == _RECOVERY_MAIN else 16777216
    if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid() or before.st_gid != os.getgid() or before.st_nlink != 1
            or not (1 if name == _RECOVERY_MAIN else 0) <= before.st_size <= maximum):
        raise _RecoveryError('source_custody')
    raw = _recovery_read(fd, maximum, deadline_ns)
    held = _recovery_stamp(os.fstat(fd))
    named = _recovery_stamp(os.stat(name, dir_fd=directory, follow_symlinks=False))
    if held != named or held != _recovery_stamp(before):
        raise _RecoveryError('source_changed')
    return {'name': name, 'held': held, 'named': named,
            'fd_flags': fcntl.fcntl(fd, fcntl.F_GETFL), 'sha256': c.digest(raw),
            'header_hex': raw[:28].hex(), 'trailer_hex': raw[-16:].hex()}, raw


def _recovery_observe_store(parent, directory, deadline_ns, *, held=None):
    """Raw access is confined to the fresh helper; never called by its parent."""
    _recovery_check(deadline_ns)
    parent_id, directory_id = _recovery_directory_pair(parent, directory)
    names = sorted(os.listdir(directory))
    if names not in ([_RECOVERY_MAIN], sorted(_RECOVERY_NAMES)):
        raise _RecoveryError('source_custody')
    rows, contents = [], {}
    for name in names:
        _recovery_check(deadline_ns)
        fd = None if held is None else held.get(name)
        owned = fd is None
        if owned:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
        try:
            row, raw = _recovery_file(fd, directory, name, deadline_ns)
            rows.append(row)
            contents[name] = raw
        finally:
            if owned:
                os.close(fd)
    if sorted(os.listdir(directory)) != names or _recovery_directory_pair(parent, directory) != (parent_id, directory_id):
        raise _RecoveryError('source_changed')
    return {'parent': parent_id, 'directory': directory_id, 'files': rows,
            'observed_at_ns': time.monotonic_ns()}, contents


def _recovery_main_header(raw):
    if (not 0 < len(raw) <= 8388608 or len(raw) % 4096
            or raw[:16] != b'SQLite format 3\0' or raw[16:20] != b'\x10\x00\x01\x01'):
        raise _RecoveryError('main_header')


def _recovery_inactive_journal(main_raw, journal_raw):
    """Classify only the strict unchanged-copy survivor; this is not recovery."""
    _recovery_main_header(main_raw)
    if journal_raw[-8:] == bytes.fromhex('d9d505f920a163d7'):
        raise _RecoveryError('journal_trailer')
    if len(journal_raw) < 28 or journal_raw[:12] != bytes(12):
        raise _RecoveryError('journal_disposition')
    nonce, pages, sector, page_size = (int.from_bytes(journal_raw[i:i+4], 'big')
                                     for i in (12, 16, 20, 24))
    if (page_size != 4096 or not 512 <= sector <= 65536 or sector & (sector-1)
            or pages != len(main_raw)//4096 or not 1 <= pages <= 2048
            or len(journal_raw) < sector or any(journal_raw[28:sector])
            or (len(journal_raw)-sector) % 4104):
        raise _RecoveryError('journal_disposition')
    count = (len(journal_raw)-sector)//4104
    if count > 2048:
        raise _RecoveryError('journal_disposition')
    seen, records = set(), []
    for index in range(count):
        start = sector + index*4104
        number = int.from_bytes(journal_raw[start:start+4], 'big')
        page = journal_raw[start+4:start+4100]
        checksum = int.from_bytes(journal_raw[start+4100:start+4104], 'big')
        computed = (nonce + sum(page[i] for i in range(3896, 0, -200))) & 0xffffffff
        if number in seen or not 1 <= number <= pages or checksum != computed:
            raise _RecoveryError('journal_disposition')
        before_hash = c.digest(page)
        main_hash = c.digest(main_raw[(number-1)*4096:number*4096])
        if before_hash != main_hash:
            raise _RecoveryError('journal_disposition')
        seen.add(number)
        records.append({'index': index, 'page_number': number, 'before_image_sha256': before_hash,
                        'main_page_sha256': main_hash, 'checksum': checksum, 'computed_checksum': computed})
    return {'header_hex': journal_raw[:28].hex(), 'nonce': nonce, 'original_pages': pages,
            'page_bytes': page_size, 'sector_bytes': sector, 'padding_bytes': sector-28,
            'padding_sha256': c.digest(journal_raw[28:sector]), 'record_count': count, 'records': records}


class _RecoveryProgress:
    """A callback allowance shared by both accepted constructors and snapshots."""
    def __init__(self, deadline_ns):
        self.deadline_ns = deadline_ns
        self.callbacks = 0

    def step(self, store):
        self.callbacks = min(4000, self.callbacks + 1)
        store._callbacks += 1
        if (self.callbacks >= 4000 or store._callbacks >= 4000
                or time.monotonic_ns() >= self.deadline_ns or time.monotonic() >= store._deadline):
            store._interrupted = True
            return 1
        return 0


def _recovery_lock(fd, *, offset, length, query=False):
    import ctypes
    import fcntl
    class Flock(ctypes.Structure):
        _fields_ = [('type', ctypes.c_short), ('whence', ctypes.c_short),
                    ('start', ctypes.c_longlong), ('length', ctypes.c_longlong), ('pid', ctypes.c_int)]
    began = time.monotonic_ns()
    if query:
        row = {'command': 'F_OFD_GETLK', 'query_type': 'F_WRLCK', 'input_owner_pid': 0,
               'offset': offset, 'length': length, 'started_at_ns': began,
               'finished_at_ns': began, 'result_type': None, 'owner_pid': None, 'errno': None}
    else:
        row = {'command': 'F_OFD_SETLK', 'lock_type': 'F_RDLCK', 'offset': offset, 'length': length,
               'started_at_ns': began, 'finished_at_ns': began, 'status': 'unsupported', 'errno': None}
    command = getattr(fcntl, row['command'], None)
    if command is None:
        return row
    lock = Flock(fcntl.F_WRLCK if query else fcntl.F_RDLCK, os.SEEK_SET, offset, length, 0)
    try:
        returned = fcntl.fcntl(fd, command, bytes(lock))
        if query:
            result = Flock.from_buffer_copy(returned)
            row['result_type'] = {fcntl.F_UNLCK:'F_UNLCK', fcntl.F_RDLCK:'F_RDLCK',
                                  fcntl.F_WRLCK:'F_WRLCK'}.get(result.type)
            row['owner_pid'] = result.pid
        else:
            row['status'] = 'acquired'
    except OSError as error:
        row['errno'] = error.errno
        if not query:
            row['status'] = 'refused'
    row['finished_at_ns'] = time.monotonic_ns()
    return row


def _recovery_package(runtime_bundle, control):
    from . import engagement_live_runtime as runtime
    runtime.validate_runtime(runtime_bundle)
    sources = []
    for expected in runtime_bundle['sources']:
        raw = runtime._read_file(runtime._source_path(expected['module']), 262144, control)
        if len(raw) != expected['size'] or c.digest(raw) != expected['sha256']:
            raise _RecoveryError('source_package')
        sources.append({**expected, 'source_base64': base64.b64encode(raw).decode('ascii')})
    package = {'schema_version': '1', 'runtime': runtime_bundle,
               'runtime_sha256': runtime.runtime_digest(runtime_bundle),
               'source_manifest_sha256': c.digest(_recovery_json(runtime_bundle['sources'])), 'sources': sources}
    raw = _recovery_json(package)
    if len(sources) != 52 or len(raw) > 2097152:
        raise _RecoveryError('source_package')
    return raw


# This literal executes before any project module is imported. It accepts data
# and inherited descriptors only; its module map is sealed and contains no disk
# fallback for the application namespace.
_RECOVERY_BOOTSTRAP = r'''
import os, sys, json, hashlib, base64, fcntl, resource, time, importlib.util
def canonical(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def read_exact(n):
    b=bytearray()
    while len(b)<n:
        p=os.read(0,n-len(b))
        if not p: raise ValueError('config')
        b.extend(p)
    return bytes(b)
n=int.from_bytes(read_exact(8),'big')
if not 0<n<=4096: raise ValueError('config')
raw=read_exact(n); config=json.loads(raw)
if canonical(config)!=raw or set(config)!={'schema_version','helper_id','broker_id','runtime_sha256','source_manifest_sha256','source_package_bytes','source_package_sha256','started_at_ns','work_deadline_ns','deadline_ns','inherited_fds'}: raise ValueError('config')
if config['schema_version']!='1' or not config['started_at_ns']<=time.monotonic_ns()<config['work_deadline_ns']<config['deadline_ns']: raise ValueError('deadline')
if config['deadline_ns']>config['started_at_ns']+2000000000 or config['work_deadline_ns']>min(config['started_at_ns']+1500000000,config['deadline_ns']-500000000): raise ValueError('deadline')
names=('source_package','source_parent','source_store','scratch_parent','scratch_store')
fds=config['inherited_fds']
if set(fds)!=set(names)|{'stdin','stdout','stderr'} or [fds[k] for k in ('stdin','stdout','stderr')]!=[0,1,2]: raise ValueError('fds')
inputs=[fds[k] for k in names]
if len(set(inputs))!=5 or any(type(x)is not int or not 3<=x<=255 for x in inputs): raise ValueError('fds')
copies=[fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,8) for fd in inputs]
for dst,src in enumerate(copies,3): os.dup2(src,dst,inheritable=False)
for fd in set(inputs+copies)-set(range(8)): os.close(fd)
for name in os.listdir('/proc/self/fd'):
    fd=int(name)
    if fd>=8:
        try: os.close(fd)
        except OSError: pass
for which,limit in ((resource.RLIMIT_NOFILE,32),(resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,2),(resource.RLIMIT_FSIZE,16777216)):
    resource.setrlimit(which,(limit,limit))
flags=fcntl.fcntl(3,fcntl.F_GETFL)
if flags&os.O_ACCMODE!=os.O_RDONLY or flags&getattr(os,'O_PATH',0) or fcntl.fcntl(3,fcntl.F_GET_SEALS)!=15: raise ValueError('package')
size=os.fstat(3).st_size
if type(config['source_package_bytes'])is not int or size!=config['source_package_bytes'] or not 0<size<=2097152: raise ValueError('package')
raw=os.pread(3,size+1,0)
if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=config['source_package_sha256']: raise ValueError('package')
package=json.loads(raw)
if canonical(package)!=raw or set(package)!={'schema_version','runtime','runtime_sha256','source_manifest_sha256','sources'} or package['schema_version']!='1': raise ValueError('package')
bundle=package['runtime']
if hashlib.sha256(canonical(bundle)).hexdigest()!=config['runtime_sha256'] or package['runtime_sha256']!=config['runtime_sha256'] or package['source_manifest_sha256']!=config['source_manifest_sha256'] or hashlib.sha256(canonical(bundle['sources'])).hexdigest()!=config['source_manifest_sha256']: raise ValueError('manifest')
rows=package['sources']; expected=bundle['sources']
if len(rows)!=52 or len(expected)!=52: raise ValueError('sources')
modules={}
for row,want in zip(rows,expected):
    if set(row)!={'module','destination','size','sha256','source_base64'} or {k:row[k] for k in want}!=want or set(want)!={'module','destination','size','sha256'}: raise ValueError('source')
    source=base64.b64decode(row['source_base64'],validate=True)
    if base64.b64encode(source).decode()!=row['source_base64'] or len(source)!=row['size'] or hashlib.sha256(source).hexdigest()!=row['sha256']: raise ValueError('source')
    name=row['module']
    if name in ('recon_cockpit.__init__','recon_cockpit.secure_agent.__init__'):
        fullname=name[:-9]; ispackage=True
    else:
        if not name.isidentifier(): raise ValueError('module')
        fullname='recon_cockpit.secure_agent.'+name; ispackage=False
    if fullname in modules: raise ValueError('module')
    destination='/app/'+fullname.replace('.','/')+('/__init__.py' if ispackage else '.py')
    if row['destination']!=destination: raise ValueError('destination')
    modules[fullname]=(source,destination,ispackage)
stdlib=bundle['stdlib']; st=os.stat(stdlib['path'],follow_symlinks=False)
if (st.st_dev,st.st_ino,st.st_mode)!=(stdlib['device'],stdlib['inode'],stdlib['mode']): raise ValueError('stdlib')
sys.path[:]=[stdlib['path'],stdlib['path']+'/lib-dynload']
class Loader:
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='recon_cockpit' or fullname.startswith('recon_cockpit.'):
            if fullname not in modules: raise ImportError('closed source map')
            return importlib.util.spec_from_loader(fullname,self,is_package=modules[fullname][2])
    def create_module(self,spec): return None
    def exec_module(self,module):
        source,destination,ispackage=modules[module.__name__]
        module.__file__=destination
        if ispackage: module.__path__=[]
        exec(compile(source,destination,'exec'),module.__dict__)
sys.meta_path.insert(0,Loader())
from recon_cockpit.secure_agent.engagement_live_session import _recovery_copy_main
_recovery_copy_main(config,package)
'''


def _recovery_image(path, destination, deadline_ns):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        raw = _recovery_read(fd, 16777216, deadline_ns)
        return {'destination': destination, 'device': info.st_dev, 'inode': info.st_ino,
                'mode': info.st_mode, 'size': len(raw), 'sha256': c.digest(raw)}
    finally:
        os.close(fd)


def _recovery_default_vfs(bundle, deadline_ns):
    import ctypes
    import _sqlite3
    import re
    broker = next(row for row in bundle['roles'] if row['role'] == 'broker')
    libraries = [row for row in broker['native_files'] if re.fullmatch(
        r'/(?:usr/)?lib(?:64)?/(?:[A-Za-z0-9_-]+/)?libsqlite3\.so\.\d+(?:\.\d+)*', row['destination'])]
    if len(libraries) != 1:
        raise _RecoveryError('unsupported_vfs')
    selected = libraries[0]
    observed = _recovery_image(selected['source'], selected['destination'], deadline_ns)
    if any(observed[key] != selected[key] for key in ('size', 'sha256')):
        raise _RecoveryError('unsupported_runtime')
    library = ctypes.CDLL(selected['source'], mode=os.RTLD_NOLOAD | os.RTLD_NOW | os.RTLD_LOCAL)
    library.sqlite3_vfs_find.argtypes = [ctypes.c_char_p]
    library.sqlite3_vfs_find.restype = ctypes.c_void_p
    library.sqlite3_libversion_number.argtypes = []
    library.sqlite3_libversion_number.restype = ctypes.c_int
    class Vfs(ctypes.Structure):
        _fields_ = [('iVersion', ctypes.c_int), ('szOsFile', ctypes.c_int),
                    ('mxPathname', ctypes.c_int), ('pNext', ctypes.c_void_p), ('zName', ctypes.c_void_p)]
    pointer = library.sqlite3_vfs_find(None)
    if not pointer:
        raise _RecoveryError('unsupported_vfs')
    vfs = Vfs.from_address(pointer)
    if not 1 <= vfs.iVersion <= 3 or not vfs.zName or ctypes.string_at(vfs.zName, 5) != b'unix\0':
        raise _RecoveryError('unsupported_vfs')
    version = _sqlite3.sqlite_version
    if type(version) is not str or re.fullmatch(r'(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){2}', version) is None:
        raise _RecoveryError('unsupported_vfs')
    parts = list(map(int, version.split('.')))
    numeric = library.sqlite3_libversion_number()
    if numeric != parts[0]*1000000 + parts[1]*1000 + parts[2]:
        raise _RecoveryError('unsupported_vfs')
    _recovery_check(deadline_ns)
    return {'library': observed, 'library_source': selected['source'], 'library_version': numeric,
            'sqlite_module_version': parts, 'vfs_struct_version': vfs.iVersion, 'vfs_name': 'unix',
            'vfs_name_hex': '756e697800', 'observed_at_ns': time.monotonic_ns()}


def _recovery_write(fd, raw, deadline_ns):
    import select
    os.set_blocking(fd, False)
    offset = 0
    while offset < len(raw):
        _recovery_check(deadline_ns)
        if not select.select([], [fd], [], min(.01, max(0, (deadline_ns-time.monotonic_ns())/1e9)))[1]:
            continue
        try:
            count = os.write(fd, raw[offset:offset+65536])
        except BlockingIOError:
            continue
        if count <= 0:
            raise _RecoveryError('framing')
        offset += count


def _recovery_child_frame(value, maximum, deadline_ns):
    raw = _recovery_json(value)
    if not 0 < len(raw) <= maximum:
        raise _RecoveryError('output_limit')
    _recovery_write(1, len(raw).to_bytes(8, 'big') + raw, deadline_ns)


def _recovery_copy_files(work, deadline_ns):
    _recovery_check(deadline_ns)
    source_fds = {}
    stage = {'started_at_ns': time.monotonic_ns(), 'finished_at_ns': None,
             'source_before': None, 'source_after': None, 'copied': None, 'locks': None,
             'raw_source_fds_closed_at_ns': None, 'raw_copy_fds_closed_at_ns': None}
    # A lock record needs the actually opened main identity. Until then copy is
    # unobserved rather than a fictitious zero-inode stage.
    main = os.open(_RECOVERY_MAIN, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=5)
    source_fds[_RECOVERY_MAIN] = main
    info = os.fstat(main)
    locks = {'main_device': info.st_dev, 'main_inode': info.st_ino, 'pending': None,
             'shared': None, 'reserved_before': None, 'reserved_after': None, 'released_at_ns': None}
    stage['locks'] = locks
    work['copy'] = stage
    try:
        for key, offset, length in (('pending', 1073741824, 1), ('shared', 1073741826, 510)):
            _recovery_check(deadline_ns)
            locks[key] = _recovery_lock(main, offset=offset, length=length)
            if locks[key]['status'] != 'acquired':
                raise _RecoveryError('unsupported_ofd')
        locks['reserved_before'] = _recovery_lock(main, offset=1073741825, length=1, query=True)
        if (locks['reserved_before']['result_type'], locks['reserved_before']['owner_pid'],
                locks['reserved_before']['errno']) != ('F_UNLCK', 0, None):
            raise _RecoveryError('reserved_writer')
        _recovery_check(deadline_ns)
        source_fds[_RECOVERY_JOURNAL] = os.open(_RECOVERY_JOURNAL,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=5)
        stage['source_before'], contents = _recovery_observe_store(4, 5, deadline_ns, held=source_fds)
        _recovery_main_header(contents[_RECOVERY_MAIN])
        if contents[_RECOVERY_JOURNAL][-8:] == bytes.fromhex('d9d505f920a163d7'):
            raise _RecoveryError('journal_trailer')
        if os.listdir(7):
            raise _RecoveryError('copy_custody')
        for name in _RECOVERY_NAMES:
            _recovery_check(deadline_ns)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=7)
            try:
                if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) in {
                        (os.fstat(other).st_dev, os.fstat(other).st_ino) for other in source_fds.values()}:
                    raise _RecoveryError('copy_custody')
                raw, offset = contents[name], 0
                while offset < len(raw):
                    _recovery_check(deadline_ns)
                    count = os.write(fd, raw[offset:offset+65536])
                    if count <= 0:
                        raise _RecoveryError('copy_custody')
                    offset += count
            finally:
                os.close(fd)
        stage['copied'], copied = _recovery_observe_store(6, 7, deadline_ns)
        stage['raw_copy_fds_closed_at_ns'] = time.monotonic_ns()
        work['copy_descriptors_closed'] = True
        if copied != contents:
            raise _RecoveryError('copy_custody')
        _recovery_main_header(copied[_RECOVERY_MAIN])
        stage['source_after'], after = _recovery_observe_store(4, 5, deadline_ns, held=source_fds)
        for key in ('parent', 'directory', 'files'):
            if stage['source_before'][key] != stage['source_after'][key]:
                raise _RecoveryError('source_changed')
        if after != contents:
            raise _RecoveryError('source_changed')
        locks['reserved_after'] = _recovery_lock(main, offset=1073741825, length=1, query=True)
        if (locks['reserved_after']['result_type'], locks['reserved_after']['owner_pid'],
                locks['reserved_after']['errno']) != ('F_UNLCK', 0, None):
            raise _RecoveryError('reserved_writer')
        return copied
    finally:
        for fd in source_fds.values():
            os.close(fd)
        locks['released_at_ns'] = time.monotonic_ns()
        stage['raw_source_fds_closed_at_ns'] = time.monotonic_ns()
        work['source_descriptors_closed'] = True
        stage['finished_at_ns'] = time.monotonic_ns()


def _recovery_sqlite_stage(work, key, progress):
    from .engagement_dispatch_store import DispatchLedger
    from . import engagement_dispatch_contract as ledger
    class RecoveryLedger(DispatchLedger):
        def _progress(self):
            return progress.step(self)
    stage = {'mode': 'read_only' if key == 'ro' else 'read_write', 'owner_id': None,
             'opened_at_ns': None, 'snapshot_at_ns': None, 'closed_at_ns': None, 'closed': False,
             'snapshot_bytes': None, 'snapshot_sha256': None, 'snapshot_event_sequence': None,
             'ledger_state_sha256': None, 'progress_callbacks_before': progress.callbacks,
             'progress_callbacks_after': progress.callbacks}
    work[key] = stage
    store = None
    try:
        with ledger._deadline_context(progress.deadline_ns/1e9):
            # This fixed path resolves the registered scratch parent capability.
            store = RecoveryLedger.open('/proc/self/fd/6/store', read_only=key == 'ro')
            stage['opened_at_ns'] = time.monotonic_ns()
            stage['owner_id'] = store.owner_reference
            snapshot = store.snapshot()
            raw = ledger.canonical(snapshot)
            if not 0 < len(raw) <= 2097152:
                raise _RecoveryError('output_limit')
            stage.update(snapshot_at_ns=time.monotonic_ns(), snapshot_bytes=len(raw),
                         snapshot_sha256=c.digest(raw), snapshot_event_sequence=len(snapshot['events']),
                         ledger_state_sha256=snapshot['events'][-1]['receipt']['state_sha256'])
            return snapshot
    finally:
        try:
            if store is not None:
                with ledger._deadline_context(progress.deadline_ns/1e9):
                    store.close()
                stage['closed'] = True
                stage['closed_at_ns'] = time.monotonic_ns()
        finally:
            stage['progress_callbacks_after'] = progress.callbacks
            work['progress_callbacks'] = progress.callbacks


def _recovery_dispose_journal(work, contents, deadline_ns):
    post, after = _recovery_observe_store(6, 7, deadline_ns)
    work['post_rw_copy'] = post
    main = next(row for row in post['files'] if row['name'] == _RECOVERY_MAIN)
    journal = next((row for row in post['files'] if row['name'] == _RECOVERY_JOURNAL), None)
    row = {'status': 'refused', 'observed_at_ns': time.monotonic_ns(), 'journal': journal,
           'header': None, 'main_before': main, 'main_after': None,
           'unlink_started_at_ns': None, 'unlink_finished_at_ns': None, 'absence_observed_at_ns': None}
    work['journal_disposition'] = row
    if journal is None:
        row.update(status='absent_after_rw', main_after=main, absence_observed_at_ns=time.monotonic_ns())
        return
    initial = next(item for item in work['copy']['copied']['files'] if item['name'] == _RECOVERY_JOURNAL)
    if journal != initial or after[_RECOVERY_MAIN] != contents[_RECOVERY_MAIN]:
        raise _RecoveryError('journal_disposition')
    if after[_RECOVERY_JOURNAL]:
        row['header'] = _recovery_inactive_journal(after[_RECOVERY_MAIN], after[_RECOVERY_JOURNAL])
        disposition = 'removed_inactive_copy'
    else:
        disposition = 'removed_empty_copy'
    _recovery_check(deadline_ns)
    # Classification read descriptors are closed before this point. Rebind the
    # fixed names to those exact observations immediately before copy-only
    # deletion; an observed replacement after classification refuses.
    if (_recovery_directory_pair(6, 7) != (post['parent'], post['directory'])
            or _recovery_stamp(os.stat(_RECOVERY_MAIN, dir_fd=7, follow_symlinks=False)) != main['held']
            or _recovery_stamp(os.stat(_RECOVERY_JOURNAL, dir_fd=7, follow_symlinks=False)) != journal['held']):
        raise _RecoveryError('journal_disposition')
    _recovery_check(deadline_ns)
    row['unlink_started_at_ns'] = time.monotonic_ns()
    os.unlink(_RECOVERY_JOURNAL, dir_fd=7)
    row['unlink_finished_at_ns'] = time.monotonic_ns()
    final, final_bytes = _recovery_observe_store(6, 7, deadline_ns)
    row['main_after'] = final['files'][0]
    if len(final['files']) != 1 or final_bytes[_RECOVERY_MAIN] != after[_RECOVERY_MAIN] or row['main_after'] != main:
        raise _RecoveryError('journal_disposition')
    row.update(status=disposition, absence_observed_at_ns=time.monotonic_ns())


def _recovery_copy_main(config, package):
    """Fixed fresh-exec entry: validated data export, never live authority."""
    import select
    import resource
    from . import engagement_live_runtime as runtime
    from .engagement_live_context import _recovery_shape
    from .engagement_dispatch_store import DispatchLedger  # Imports SQLite before READY.
    _recovery_shape(config, 'config')
    _recovery_shape(package, 'source_package')
    runtime.validate_runtime(package['runtime'])
    deadline_ns = config['work_deadline_ns']
    _recovery_check(deadline_ns)
    vfs = _recovery_default_vfs(package['runtime'], deadline_ns)
    ready = {'schema_version': '1', 'kind': 'copied_ledger_recovery_ready',
             'helper_id': config['helper_id'], 'broker_id': config['broker_id'], 'pid': os.getpid(),
             'runtime_sha256': config['runtime_sha256'], 'source_manifest_sha256': config['source_manifest_sha256'],
             'source_package_sha256': config['source_package_sha256'], 'default_vfs': vfs,
             'observed_at_ns': time.monotonic_ns()}
    _recovery_shape(ready, 'ready')
    _recovery_child_frame(ready, 4096, deadline_ns)
    os.set_blocking(0, False)
    release = bytearray()
    while True:
        _recovery_check(deadline_ns)
        if not select.select([0], [], [], min(.01, max(0, (deadline_ns-time.monotonic_ns())/1e9)))[0]:
            continue
        part = os.read(0, 2)
        if not part:
            break
        release.extend(part)
        if release != b'\x01':
            raise _RecoveryError('release')
    if release != b'\x01':
        raise _RecoveryError('release')
    work = {'schema_version': '1', **{key: config[key] for key in ('helper_id', 'broker_id', 'runtime_sha256',
            'source_package_sha256', 'work_deadline_ns', 'deadline_ns')}, 'started_at_ns': time.monotonic_ns(),
            'finished_at_ns': None, 'copy': None, 'rw': None, 'ro': None, 'post_rw_copy': None,
            'post_ro_copy': None, 'journal_disposition': None, 'sqlite_file_size_limit': None,
            'progress_callbacks': 0, 'source_descriptors_closed': False, 'copy_descriptors_closed': False,
            'source_package_closed_at_ns': None}
    result = {'schema_version': '1', 'status': 'failed', 'error': None, 'export': None, 'provenance': work}
    stage = 'source_custody'
    progress = _RecoveryProgress(deadline_ns)
    try:
        os.close(3)
        work['source_package_closed_at_ns'] = time.monotonic_ns()
        copied = _recovery_copy_files(work, deadline_ns)
        resource.setrlimit(resource.RLIMIT_FSIZE, (8388608, 8388608))
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        if (soft, hard) != (8388608, 8388608):
            raise _RecoveryError('copy_limit')
        work['sqlite_file_size_limit'] = {'soft': soft, 'hard': hard, 'observed_at_ns': time.monotonic_ns()}
        stage = 'sqlite_rw'
        rw = _recovery_sqlite_stage(work, 'rw', progress)
        stage = 'journal_disposition'
        _recovery_dispose_journal(work, copied, deadline_ns)
        stage = 'sqlite_ro'
        ro = _recovery_sqlite_stage(work, 'ro', progress)
        if rw != ro or work['rw']['owner_id'] == work['ro']['owner_id']:
            raise _RecoveryError('snapshot_mismatch')
        work['post_ro_copy'], after = _recovery_observe_store(6, 7, deadline_ns)
        if (len(after) != 1 or work['post_ro_copy']['files'][0]
                != work['journal_disposition']['main_after']):
            raise _RecoveryError('source_changed')
        _recovery_check(deadline_ns)
        result.update(status='complete', export=ro)
    except Exception as error:
        result['error'] = (error.code if isinstance(error, _RecoveryError) else
                           'progress_limit' if progress.callbacks >= 4000 else
                           'work_deadline' if time.monotonic_ns() >= deadline_ns else stage)
    finally:
        work['finished_at_ns'] = time.monotonic_ns()
        work['progress_callbacks'] = progress.callbacks
    _recovery_shape(result, 'result')
    if len(_recovery_json({**result, 'export': None})) > 32768:
        raise _RecoveryError('output_limit')
    _recovery_child_frame(result, 2129920, deadline_ns)
    if result['status'] != 'complete':
        raise SystemExit(1)


class _RecoveryControl:
    def __init__(self, deadline_ns):
        self.deadline_ns = deadline_ns
        self.deadline = deadline_ns / 1e9

    def check(self):
        _recovery_check(self.deadline_ns)


def _recovery_descriptor(fd, purpose, *, number=None):
    import fcntl
    info = os.fstat(fd)
    kind = ('pipe' if stat.S_ISFIFO(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode)
            else 'regular' if stat.S_ISREG(info.st_mode) else None)
    if kind is None:
        raise _RecoveryError('ready')
    return {'fd': fd if number is None else number, 'purpose': purpose, 'kind': kind,
            'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'flags': fcntl.fcntl(fd, fcntl.F_GETFL)}


def _recovery_empty_frame():
    return {'started_at_ns': None, 'finished_at_ns': None, 'header_hex': '', 'declared_bytes': None,
            'received_bytes': 0, 'payload_bytes': 0, 'payload_sha256': None,
            'frame_sha256': None, 'complete': False}


def _recovery_frame(raw, maximum, started_at_ns):
    import json
    row = _recovery_empty_frame()
    if raw:
        row['started_at_ns'] = started_at_ns
    row['header_hex'] = raw[:8].hex()
    if raw:
        row.update(received_bytes=min(8, len(raw)), payload_sha256=c.digest(b''),
                   frame_sha256=c.digest(raw[:8]))
    if len(raw) < 8:
        return row, None, 0
    declared = int.from_bytes(raw[:8], 'big')
    if not 0 < declared <= maximum:
        # The raw header remains evidence even when its number cannot inhabit
        # the bounded decoded field. Remaining bytes stay in owner.stdout;
        # this malformed record cannot be packaged as a valid frame.
        error = _RecoveryError('framing')
        error.frame = row
        raise error
    body = raw[8:8+declared]
    row.update(declared_bytes=declared, received_bytes=8+len(body), payload_bytes=len(body),
               payload_sha256=c.digest(body), frame_sha256=c.digest(raw[:8+len(body)]))
    if len(body) != declared:
        return row, None, 0
    try:
        value = json.loads(body)
        if _recovery_json(value) != body:
            raise ValueError('canonical')
    except (ValueError, TypeError, RecursionError, UnicodeError):
        row['finished_at_ns'] = time.monotonic_ns()
        error = _RecoveryError('framing')
        error.frame = row
        raise error from None
    row.update(complete=True, finished_at_ns=time.monotonic_ns())
    return row, value, 8+declared


class _RecoveryOwner:
    """Parent-owned publication, data pipes, observations and scratch closure."""
    def __init__(self, session, source_parent, source_store, started_at_ns, deadline_ns):
        from uuid import uuid4
        self.session = session
        self.pid = os.getpid()
        self._lifecycle_lock = threading.Lock()
        self.active = False
        self.quiescent = False
        self.helper_id = str(uuid4())
        self.started_at_ns = started_at_ns
        self.deadline_ns = deadline_ns
        self.work_deadline_ns = min(started_at_ns+1500000000, deadline_ns-500000000)
        self.control = _RecoveryControl(self.work_deadline_ns)
        self.fds = {'source_parent': source_parent, 'source_store': source_store}
        self.transport_fds = {}
        self.process = None
        self.pidfd = None
        self.proc_directory = None
        self.publication = threading.Event()
        self.publication_thread = None
        self.publication_error = None
        self.scratch_parent_name = None
        self._source_parent_identity = None
        self._scratch_parent_created = False
        self._scratch_parent_identity = None
        self._scratch_parent_removed = False
        self._scratch_store_created = False
        self._scratch_store_identity = None
        self._scratch_store_removed = False
        self.record = None
        self.resolved = False
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.stdout_eof = self.stderr_eof = False
        self.frame_started = None
        self.result_started = None
        self.ready_size = None
        self.result = None
        self.expected_source = None
        self.cleanup_started_at_ns = None

    def _source_metadata(self):
        parent, directory = self.fds['source_parent'], self.fds['source_store']
        _recovery_directory_pair(parent, directory)
        names = sorted(os.listdir(directory))
        if names != sorted(_RECOVERY_NAMES):
            raise _RecoveryError('source_custody')
        for name in names:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            maximum = 8388608 if name == _RECOVERY_MAIN else 16777216
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_gid != os.getgid() or info.st_nlink != 1
                    or not (1 if name == _RECOVERY_MAIN else 0) <= info.st_size <= maximum):
                raise _RecoveryError('source_custody')
        broker = self.session._broker
        ready = None if broker is None else broker.readiness
        if ready is None:
            raise _RecoveryError('source_custody')
        # Locate the actual broker READY parent descriptor observation, never a
        # namespace path claim or a prior snapshot's database identity.
        observations = [ready['readiness']]
        descriptors = []
        for row in observations:
            worker = row.get('worker_ready', {})
            parent_row = row.get('parent_observation', {})
            if worker.get('role') == 'broker' and worker.get('worker_id') == broker._broker_id:
                descriptors.extend(parent_row.get('descriptors', ()))
        matches = {}
        for purpose in ('held_store_directory', 'sqlite_main'):
            values = {(row['device'], row['inode']) for row in descriptors if row.get('purpose') == purpose}
            if len(values) != 1:
                raise _RecoveryError('source_custody')
            matches[purpose] = values.pop()
        main = os.stat(_RECOVERY_MAIN, dir_fd=directory, follow_symlinks=False)
        current = os.fstat(directory)
        if matches != {'held_store_directory': (current.st_dev, current.st_ino),
                       'sqlite_main': (main.st_dev, main.st_ino)}:
            raise _RecoveryError('source_custody')
        self.expected_source = matches

    def _allocate_scratch(self):
        self.control.check()
        self._source_parent_identity = _recovery_private_directory(self.fds['source_parent'])
        proposed = 'recovery_'+self.helper_id.replace('-', '')
        os.mkdir(proposed, 0o700, dir_fd=self.fds['source_parent'])
        # A proposed name is not ownership. If the exclusive mkdir fails, no
        # cleanup path may remove the pre-existing object at that name.
        self._scratch_parent_created = True
        self.scratch_parent_name = proposed
        self.fds['scratch_parent'] = os.open(self.scratch_parent_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fds['source_parent'])
        parent_identity = _recovery_private_directory(self.fds['scratch_parent'])
        if _recovery_identity(os.stat(proposed, dir_fd=self.fds['source_parent'],
                                      follow_symlinks=False)) != parent_identity:
            raise _RecoveryError('copy_custody')
        self._scratch_parent_identity = parent_identity
        os.mkdir('store', 0o700, dir_fd=self.fds['scratch_parent'])
        self._scratch_store_created = True
        self.fds['scratch_store'] = os.open('store', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=self.fds['scratch_parent'])
        pair = _recovery_directory_pair(self.fds['scratch_parent'], self.fds['scratch_store'])
        if pair[0] != parent_identity:
            raise _RecoveryError('copy_custody')
        self._scratch_store_identity = pair[1]
        return {'name': 'store', 'parent': parent_identity, 'directory': pair[1],
                'registered_at_ns': time.monotonic_ns()}

    def _setup(self):
        import fcntl
        from . import engagement_live_runtime as runtime
        from .engagement_live_context import _recovery_shape
        self.control.check()
        self._source_metadata()
        package = _recovery_package(self.session._runtime, self.control)
        writable = runtime._sealed(package, name='engagement-recovery-sources', control=self.control)
        try:
            self.fds['source_package'] = os.open('/proc/self/fd/'+str(writable), os.O_RDONLY | os.O_CLOEXEC)
        finally:
            os.close(writable)
        if fcntl.fcntl(self.fds['source_package'], fcntl.F_GET_SEALS) != 15:
            raise _RecoveryError('source_package')
        scratch = self._allocate_scratch()
        transports = {}
        for index, name in enumerate(('stdin', 'stdout', 'stderr')):
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            parent, child = (write_fd, read_fd) if index == 0 else (read_fd, write_fd)
            self.transport_fds[name+'_parent'] = parent
            self.transport_fds[name+'_child'] = child
            transports[name] = {'created_at_ns': time.monotonic_ns(),
                'parent': _recovery_descriptor(parent, name+'_parent'),
                'child': _recovery_descriptor(child, _RECOVERY_FD_PURPOSES[index])}
        if any(not 3 <= self.fds[name] <= 255 for name in _RECOVERY_PURPOSES):
            raise _RecoveryError('publication')
        inherited = {'stdin': 0, 'stdout': 1, 'stderr': 2,
                     **{name: self.fds[name] for name in _RECOVERY_PURPOSES}}
        config = {'schema_version': '1', 'helper_id': self.helper_id, 'broker_id': self.session._broker._broker_id,
            'runtime_sha256': runtime.runtime_digest(self.session._runtime),
            'source_manifest_sha256': c.digest(_recovery_json(self.session._runtime['sources'])),
            'source_package_bytes': len(package), 'source_package_sha256': c.digest(package),
            'started_at_ns': self.started_at_ns, 'work_deadline_ns': self.work_deadline_ns,
            'deadline_ns': self.deadline_ns, 'inherited_fds': inherited}
        _recovery_shape(config, 'config')
        raw = _recovery_json(config)
        if len(raw) > 4096:
            raise _RecoveryError('source_package')
        process = {'publication_registered_at_ns': time.monotonic_ns(), 'publication_state': 'pending',
            'publication_resolved_at_ns': None, 'pid': None, 'parent_pid': None, 'start_time_ticks': None,
            'observed_at_ns': None, 'pidfd': None, 'task_ids': [], 'release_sent_at_ns': None,
            'signal_sent_at_ns': None, 'exit_observed_at_ns': None, 'reaped_at_ns': None, 'returncode': None}
        cleanup = {'started_at_ns': self.started_at_ns, 'finished_at_ns': None, 'deadline_ns': self.deadline_ns,
            'status': 'unknown', 'scratch_disposition': 'unknown', 'removed_names': [],
            **{key: False for key in ('descriptors_closed', 'stdio_closed', 'pidfd_closed',
                'source_package_closed', 'parent_closed', 'directory_closed', 'directory_removed')}}
        self.record = {'schema_version': '1', 'helper_id': self.helper_id, 'broker_id': config['broker_id'],
            'generation': self.session._host_evidence_budget._session_owners.index(self.session),
            'started_at_ns': self.started_at_ns, 'work_deadline_ns': self.work_deadline_ns,
            'deadline_ns': self.deadline_ns, 'finished_at_ns': None, 'status': 'unknown',
            'parent_observer': runtime._observer(), 'config': config, 'config_bytes': len(raw),
            'config_sha256': c.digest(raw), 'process': process, 'transports': transports,
            'scratch': scratch, 'runtime': None, 'ready': None, 'work': None, 'error': None,
            'cleanup': cleanup, 'transfer': {'ready': _recovery_empty_frame(), 'result': _recovery_empty_frame(),
                'export_bytes': None, 'export_sha256': None, 'provenance_bytes': None, 'provenance_sha256': None,
                'result_status': None, 'result_error': None, 'stdout_bytes': 0, 'stdout_eof': False,
                'stderr_bytes': 0, 'stderr_hex': '', 'stderr_sha256': c.digest(b''), 'stderr_eof': False}}
        self.session._recovery_helpers.append(self.record)
        self.config_raw = raw
        self.control.check()

    def _publish(self):
        import subprocess
        try:
            self.process = subprocess.Popen(
                [self.session._runtime['python']['source'], '-I', '-S', '-B', '-c', _RECOVERY_BOOTSTRAP],
                stdin=self.transport_fds['stdin_child'], stdout=self.transport_fds['stdout_child'],
                stderr=self.transport_fds['stderr_child'], close_fds=True,
                pass_fds=tuple(self.fds[name] for name in _RECOVERY_PURPOSES),
                env={'LANG': 'C', 'LC_ALL': 'C'}, cwd='/')
            self.record['process'].update(publication_state='published', pid=self.process.pid,
                                          publication_resolved_at_ns=time.monotonic_ns())
        except BaseException as error:
            self.publication_error = error
            self.record['process'].update(publication_state='not_started',
                                          publication_resolved_at_ns=time.monotonic_ns())
        finally:
            self.publication.set()

    def _pin(self):
        import fcntl
        from . import engagement_live_runtime as runtime
        self.pidfd = os.pidfd_open(self.process.pid, 0)
        self.proc_directory = os.open('/proc/'+str(self.process.pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        identity = runtime._process_identity(self.process.pid)
        if identity['parent_pid'] != self.pid or runtime._payload_state(self.pidfd) != 'alive':
            raise _RecoveryError('publication')
        info = os.fstat(self.pidfd)
        self.record['process'].update(**identity, observed_at_ns=time.monotonic_ns(),
            pidfd={'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
                   'flags': fcntl.fcntl(self.pidfd, fcntl.F_GETFL)})
        tasks = sorted(int(value) for value in os.listdir('/proc/'+str(self.process.pid)+'/task'))
        if tasks != [self.process.pid]:
            raise _RecoveryError('unsupported_runtime')
        self.record['process']['task_ids'] = tasks

    def _check_pin(self):
        from . import engagement_live_runtime as runtime
        row = self.record['process']
        if (self.pidfd is None or runtime._payload_state(self.pidfd) != 'alive'
                or runtime._process_identity(row['pid']) != {key: row[key] for key in ('pid', 'parent_pid', 'start_time_ticks')}):
            raise _RecoveryError('helper_exit')

    def _drain(self, timeout=0):
        import select
        fds = {self.transport_fds[name+'_parent']: name for name in ('stdout', 'stderr')
               if name+'_parent' in self.transport_fds and not getattr(self, name+'_eof')}
        if not fds:
            return
        ready = select.select(list(fds), [], [], timeout)[0]
        for fd in ready:
            name = fds[fd]
            maximum = 2134032 if name == 'stdout' else 4096
            target = getattr(self, name)
            if len(target) > maximum:
                raise _RecoveryError('output_limit')
            part = os.read(fd, min(65536, maximum+1-len(target)))
            if not part:
                setattr(self, name+'_eof', True)
            else:
                if name == 'stdout' and self.frame_started is None:
                    self.frame_started = time.monotonic_ns()
                if (name == 'stdout' and self.ready_size is not None and self.result_started is None
                        and len(target)+len(part) > self.ready_size):
                    self.result_started = time.monotonic_ns()
                target.extend(part)
                if len(target) > maximum:
                    raise _RecoveryError('output_limit')
        transfer = self.record['transfer']
        transfer.update(stdout_bytes=len(self.stdout), stdout_eof=self.stdout_eof,
            stderr_bytes=len(self.stderr), stderr_hex=bytes(self.stderr).hex(),
            stderr_sha256=c.digest(bytes(self.stderr)), stderr_eof=self.stderr_eof)

    def _observe_runtime(self, ready):
        import fcntl
        import resource
        from . import engagement_live_runtime as runtime
        from .engagement_live_context import _recovery_shape
        _recovery_shape(ready, 'ready')
        self._check_pin()
        config = self.record['config']
        if (ready['pid'] != self.process.pid or any(ready[key] != config[key] for key in (
                'helper_id', 'broker_id', 'runtime_sha256', 'source_manifest_sha256', 'source_package_sha256'))):
            raise _RecoveryError('ready')
        directory = '/proc/'+str(self.process.pid)
        descriptors = runtime._fd_inventory(directory, purposes=dict(enumerate(_RECOVERY_FD_PURPOSES)))
        if [row['fd'] for row in descriptors] != list(range(8)):
            raise _RecoveryError('ready')
        expected = [{**self.record['transports'][name]['child'], 'fd': index}
                    for index, name in enumerate(('stdin', 'stdout', 'stderr'))]
        expected += [_recovery_descriptor(self.fds[name], _RECOVERY_FD_PURPOSES[index], number=index)
                     for index, name in enumerate(_RECOVERY_PURPOSES, 3)]
        # Nonblocking pipe mode can legitimately have been set by the fixed
        # child's READY write; access rights and identities remain exact.
        for actual, want in zip(descriptors, expected):
            if any(actual[key] != want[key] for key in ('fd', 'purpose', 'kind', 'device', 'inode', 'mode')):
                raise _RecoveryError('ready')
            if actual['flags'] & ~os.O_NONBLOCK != want['flags'] & ~os.O_NONBLOCK:
                raise _RecoveryError('ready')
        package_fd = self.fds['source_package']
        if (fcntl.fcntl(package_fd, fcntl.F_GET_SEALS) != 15
                or descriptors[3]['flags'] & os.O_ACCMODE != os.O_RDONLY
                or descriptors[3]['flags'] & getattr(os, 'O_PATH', 0)):
            raise _RecoveryError('source_package')
        bundle = self.session._runtime
        allowed = {}
        for role in (row for row in bundle['roles'] if row['role'] == 'broker'):
            for row in role['native_files']+role['extension_files']:
                previous = allowed.setdefault(row['source'], row)
                if any(previous[key] != row[key] for key in ('size', 'sha256')):
                    raise _RecoveryError('unsupported_runtime')
        images = {}
        inode_images = {}
        for source, row in allowed.items():
            self.control.check()
            image = _recovery_image(source, row['destination'], self.work_deadline_ns)
            if any(image[key] != row[key] for key in ('size', 'sha256')):
                raise _RecoveryError('unsupported_runtime')
            images[source] = image
            inode_images.setdefault((image['device'], image['inode']), []).append(image)
        maps = runtime._proc_read(self.proc_directory, 'maps', 262144).decode('utf-8')
        mapped = {}
        for line in maps.splitlines():
            bits = line.split(maxsplit=5)
            if len(bits) < 2 or 'x' not in bits[1]:
                continue
            if len(bits) == 6 and bits[5] in ('[vdso]', '[vsyscall]'):
                continue
            if len(bits) != 6:
                raise _RecoveryError('unsupported_runtime')
            device = os.makedev(*(int(x, 16) for x in bits[3].split(':')))
            candidates = inode_images.get((device, int(bits[4])))
            if not candidates:
                raise _RecoveryError('unsupported_runtime')
            for image in candidates:
                mapped[image['destination']] = image
        interpreter = _recovery_image(os.readlink(directory+'/exe'), bundle['python']['destination'], self.work_deadline_ns)
        if any(interpreter[key] != bundle['python'][key] for key in ('size', 'sha256')):
            raise _RecoveryError('unsupported_runtime')
        sqlite_rows = [row for role in bundle['roles'] if role['role'] == 'broker'
                       for row in role['extension_files'] if Path(row['source']).name.startswith('_sqlite3.')]
        if len(sqlite_rows) != 1:
            raise _RecoveryError('unsupported_runtime')
        sqlite = images[sqlite_rows[0]['source']]
        vfs = ready['default_vfs']
        if (sqlite['destination'] not in mapped or mapped[sqlite['destination']] != sqlite
                or vfs['library'] != images.get(vfs['library_source'])
                or mapped.get(vfs['library']['destination']) != vfs['library']
                or interpreter['destination'] not in mapped
                or vfs['library_version'] != sum(n*m for n,m in zip(vfs['sqlite_module_version'], (1000000,1000,1)))):
            raise _RecoveryError('unsupported_runtime')
        tasks = sorted(int(value) for value in os.listdir(directory+'/task'))
        if tasks != [self.process.pid]:
            raise _RecoveryError('unsupported_runtime')
        self.record['process']['task_ids'] = tasks
        limits = {'observed_at_ns': time.monotonic_ns()}
        for key, which, target in (('address_space', resource.RLIMIT_AS, 268435456),
                ('cpu', resource.RLIMIT_CPU, 2), ('nofile', resource.RLIMIT_NOFILE, 32),
                ('file_size', resource.RLIMIT_FSIZE, 16777216)):
            soft, hard = resource.prlimit(self.process.pid, which)
            if (soft, hard) != (target, target):
                raise _RecoveryError('unsupported_runtime')
            limits[key] = {'soft': soft, 'hard': hard}
        stdlib = os.stat(bundle['stdlib']['path'], follow_symlinks=False)
        if stdlib.st_mode != bundle['stdlib']['mode']:
            raise _RecoveryError('unsupported_runtime')
        if (stdlib.st_dev, stdlib.st_ino) != (bundle['stdlib']['device'], bundle['stdlib']['inode']):
            raise _RecoveryError('unsupported_runtime')
        self.record['runtime'] = {'observed_at_ns': time.monotonic_ns(),
            'runtime_sha256': config['runtime_sha256'], 'source_manifest_sha256': config['source_manifest_sha256'],
            'default_vfs_sha256': c.digest(_recovery_json(vfs)), 'descriptors': descriptors,
            'interpreter': interpreter, 'mapped_images': sorted(mapped.values(), key=lambda row: row['destination']),
            'sqlite_extension': sqlite, 'stdlib': _recovery_identity(stdlib), 'resource_limits': limits,
            'source_package': {'bytes': config['source_package_bytes'], 'sha256': config['source_package_sha256'],
                'source_manifest_sha256': config['source_manifest_sha256'], 'seals': 15, 'descriptor': descriptors[3]},
            'vfs': 'unix', 'locking': 'posix_rollback'}
        _recovery_shape(self.record['runtime'], 'helper_runtime')
        self._source_metadata()
        self._check_pin()
        self.control.check()

    def _retain_partial_frames(self):
        """Retain final drained prefixes without promoting failed input."""
        frames = [('ready', bytes(self.stdout), 4096, self.frame_started)]
        if self.ready_size is not None:
            frames.append(('result', bytes(self.stdout[self.ready_size:]), 2129920, self.result_started))
        for name, raw, maximum, began in frames:
            if self.record['transfer'][name]['complete']:
                continue
            try:
                row, _value, _consumed = _recovery_frame(raw, maximum, began)
                # Bytes drained during refusal/closure have not passed the
                # corresponding READY/result acceptance path.
                row['complete'] = False
            except _RecoveryError as error:
                row = getattr(error, 'frame', None)
            if row is not None:
                self.record['transfer'][name] = row

    def _receive(self):
        from .engagement_live_context import _recovery_shape
        while self.result is None:
            self.control.check()
            self._drain(min(.01, max(0, (self.work_deadline_ns-time.monotonic_ns())/1e9)))
            if self.ready_size is None:
                try:
                    framed, value, consumed = _recovery_frame(bytes(self.stdout), 4096, self.frame_started)
                except _RecoveryError as error:
                    if hasattr(error, 'frame'):
                        self.record['transfer']['ready'] = error.frame
                    raise
                self.record['transfer']['ready'] = framed
                if value is not None:
                    self.record['ready'] = value
                    self._observe_runtime(value)
                    self.ready_size = consumed
                    _recovery_write(self.transport_fds['stdin_parent'], b'\x01', self.work_deadline_ns)
                    self.record['process']['release_sent_at_ns'] = time.monotonic_ns()
                    os.close(self.transport_fds.pop('stdin_parent'))
            if self.ready_size is not None:
                try:
                    framed, value, consumed = _recovery_frame(bytes(self.stdout[self.ready_size:]), 2129920, self.result_started)
                except _RecoveryError as error:
                    if hasattr(error, 'frame'):
                        self.record['transfer']['result'] = error.frame
                    raise
                self.record['transfer']['result'] = framed
                if value is not None:
                    if len(self.stdout) != self.ready_size+consumed:
                        raise _RecoveryError('framing')
                    _recovery_shape(value, 'result')
                    work = value['provenance']
                    config = self.record['config']
                    if any(work[key] != config[key] for key in ('helper_id', 'broker_id', 'runtime_sha256',
                            'source_package_sha256', 'work_deadline_ns', 'deadline_ns')):
                        raise _RecoveryError('framing')
                    metadata_bytes = len(_recovery_json({**value, 'export': None}))
                    if metadata_bytes > 32768:
                        raise _RecoveryError('output_limit')
                    self.result = value
                    self.record['work'] = work
                    transfer = self.record['transfer']
                    transfer.update(result_status=value['status'], result_error=value['error'],
                        provenance_bytes=len(_recovery_json(work)), provenance_sha256=c.digest(_recovery_json(work)))
                    if value['export'] is not None:
                        raw = _recovery_json(value['export'])
                        if not 0 < len(raw) <= 2097152:
                            raise _RecoveryError('output_limit')
                        transfer.update(export_bytes=len(raw), export_sha256=c.digest(raw))
                    if value['status'] != 'complete':
                        raise _RecoveryError(value['error'] or 'sqlite_ro')
            if self.stdout_eof and self.result is None:
                raise _RecoveryError('framing')
        self.control.check()

    def _validate_work(self):
        from . import engagement_dispatch_contract as ledger
        # Accepted export validation is data-only; no original or copy DB opens.
        value = self.result['export']
        with ledger._deadline_context(self.work_deadline_ns/1e9):
            ledger.validate_export(value)
        work = self.record['work']
        if (work['finished_at_ns'] is None or work['finished_at_ns'] > self.work_deadline_ns
                or not work['source_descriptors_closed'] or not work['copy_descriptors_closed']
                or work['source_package_closed_at_ns'] is None or work['progress_callbacks'] >= 4000):
            raise _RecoveryError('framing')
        source = work['copy']['source_before']
        main = next(row for row in source['files'] if row['name'] == _RECOVERY_MAIN)
        if ((source['directory']['device'], source['directory']['inode']) != self.expected_source['held_store_directory']
                or (main['held']['device'], main['held']['inode']) != self.expected_source['sqlite_main']):
            raise _RecoveryError('source_custody')
        raw = ledger.canonical(value)
        broker_owner = self.session._broker.readiness['ledger_owner_id']
        for name in ('rw', 'ro'):
            stage = work[name]
            if (not stage['closed'] or stage['owner_id'] == broker_owner
                    or stage['snapshot_bytes'] != len(raw) or stage['snapshot_sha256'] != c.digest(raw)
                    or stage['ledger_state_sha256'] != value['events'][-1]['receipt']['state_sha256']):
                raise _RecoveryError('snapshot_mismatch')
        if work['rw']['owner_id'] == work['ro']['owner_id']:
            raise _RecoveryError('snapshot_mismatch')
        self.control.check()

    def _remove_scratch(self, cleanup_row):
        if not self._scratch_parent_created or self._scratch_parent_removed:
            return
        # A successful mkdir followed by a failed open does not provide a held
        # identity. Retain that unresolved ownership; never delete by name.
        if (self._scratch_parent_identity is None or 'scratch_parent' not in self.fds
                or self._source_parent_identity is None
                or _recovery_private_directory(self.fds['source_parent']) != self._source_parent_identity
                or _recovery_private_directory(self.fds['scratch_parent']) != self._scratch_parent_identity
                or _recovery_identity(os.stat(self.scratch_parent_name, dir_fd=self.fds['source_parent'],
                                               follow_symlinks=False)) != self._scratch_parent_identity):
            raise _RecoveryError('scratch_cleanup')
        parent = self.fds['scratch_parent']
        if self._scratch_store_created and not self._scratch_store_removed:
            if self._scratch_store_identity is None or 'scratch_store' not in self.fds:
                raise _RecoveryError('scratch_cleanup')
            directory = self.fds['scratch_store']
            pair = _recovery_directory_pair(parent, directory)
            if pair != (self._scratch_parent_identity, self._scratch_store_identity):
                raise _RecoveryError('scratch_cleanup')
            if self.record is not None and pair != (self.record['scratch']['parent'], self.record['scratch']['directory']):
                raise _RecoveryError('scratch_cleanup')
            names = sorted(os.listdir(directory))
            if not set(names) <= set(_RECOVERY_NAMES):
                raise _RecoveryError('scratch_cleanup')
            infos = {name: os.stat(name, dir_fd=directory, follow_symlinks=False) for name in names}
            if self.result is not None and self.result['status'] == 'complete':
                final = self.result['provenance']['post_ro_copy']
                if (final is None or (final['parent'], final['directory']) != pair
                        or sorted(item['name'] for item in final['files']) != names):
                    raise _RecoveryError('scratch_cleanup')
                final_files = {item['name']: item for item in final['files']}
                if (len(final_files) != len(final['files'])
                        or any(_recovery_stamp(infos[name]) != final_files[name]['held'] for name in names)):
                    raise _RecoveryError('scratch_cleanup')
            for name in names:
                info = infos[name]
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != os.getuid() or info.st_nlink != 1):
                    raise _RecoveryError('scratch_cleanup')
                if self.record is not None and self.record['work'] is not None:
                    work = self.record['work']
                    observed = (work['post_ro_copy'] or work['post_rw_copy']
                                or (None if work['copy'] is None else work['copy']['copied']))
                    known = [] if observed is None else [x for x in observed['files'] if x['name'] == name]
                    if known and (info.st_dev, info.st_ino) != (known[0]['held']['device'], known[0]['held']['inode']):
                        raise _RecoveryError('scratch_cleanup')
                if _recovery_stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _recovery_stamp(info):
                    raise _RecoveryError('scratch_cleanup')
                os.unlink(name, dir_fd=directory)
                if cleanup_row is not None:
                    cleanup_row['removed_names'].append(name)
            if (os.listdir(directory) or _recovery_directory_pair(parent, directory)
                    != (self._scratch_parent_identity, self._scratch_store_identity)):
                raise _RecoveryError('scratch_cleanup')
            os.rmdir('store', dir_fd=parent)
            self._scratch_store_removed = True
        # This also handles failure before store mkdir: only a genuinely empty
        # held parent can be removed, never an unexpected child entry.
        if (os.listdir(parent) or _recovery_private_directory(parent) != self._scratch_parent_identity
                or _recovery_identity(os.stat(self.scratch_parent_name, dir_fd=self.fds['source_parent'],
                                               follow_symlinks=False)) != self._scratch_parent_identity):
            raise _RecoveryError('scratch_cleanup')
        os.rmdir(self.scratch_parent_name, dir_fd=self.fds['source_parent'])
        self._scratch_parent_removed = True

    def _cleanup(self):
        if os.getpid() != self.pid:
            raise _RecoveryError('publication')
        if not self._lifecycle_lock.acquire(timeout=max(0, (self.deadline_ns-time.monotonic_ns())/1e9)):
            raise _RecoveryError('helper_reap')
        try:
            if self.resolved:
                return
            self.active = True
            self.quiescent = False
            self._cleanup_locked()
            if self.record is not None:
                self.record['status'] = 'failed' if self.resolved else 'unknown'
                self.record['error'] = self.record['error'] or 'helper_reap'
                self.record['finished_at_ns'] = time.monotonic_ns()
        finally:
            self.active = False
            self.quiescent = self.resolved and self.record is not None
            self._lifecycle_lock.release()

    def _cleanup_locked(self):
        import signal
        from . import engagement_live_runtime as runtime
        row = None if self.record is None else self.record['cleanup']
        if self.resolved:
            return
        if self.cleanup_started_at_ns is None:
            self.cleanup_started_at_ns = time.monotonic_ns()
        if row is not None:
            row['started_at_ns'] = self.cleanup_started_at_ns
        if self.publication_thread is not None and not self.publication.is_set():
            return
        for name in ('stdin_child', 'stdout_child', 'stderr_child'):
            if name in self.transport_fds:
                os.close(self.transport_fds.pop(name))
        process = self.process
        if process is not None:
            if self.pidfd is None:
                try:
                    self._pin()
                except Exception:
                    return
            while process.poll() is None and time.monotonic_ns() < self.deadline_ns:
                if self.result is None or self.result['status'] != 'complete' or self.record['error'] is not None:
                    if self.record['process']['signal_sent_at_ns'] is None:
                        try:
                            signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                            self.record['process']['signal_sent_at_ns'] = time.monotonic_ns()
                        except ProcessLookupError:
                            pass
                try:
                    self._drain(min(.005, max(0, (self.deadline_ns-time.monotonic_ns())/1e9)))
                except Exception:
                    if self.record['error'] is None:
                        self.record['error'] = 'output_limit'
            if process.poll() is None:
                # Signal only the retained pidfd even when the original closure
                # deadline has expired; no new wait interval is allocated.
                try:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                    self.record['process']['signal_sent_at_ns'] = time.monotonic_ns()
                except ProcessLookupError:
                    pass
                return
            self.record['process'].update(returncode=process.returncode,
                exit_observed_at_ns=time.monotonic_ns(), reaped_at_ns=time.monotonic_ns())
            try:
                while not (self.stdout_eof and self.stderr_eof) and time.monotonic_ns() < self.deadline_ns:
                    self._drain(0)
                if not (self.stdout_eof and self.stderr_eof):
                    raise _RecoveryError('framing')
            except Exception:
                if self.record['error'] is None:
                    self.record['error'] = 'framing'
        elif self.record is not None:
            # A resolved failed Popen owns no child endpoints. Read the actual
            # empty pipe EOFs rather than inventing transfer completion.
            try:
                self._drain(0)
            except Exception:
                self.record['error'] = self.record['error'] or 'framing'
        if self.record is not None:
            self._retain_partial_frames()
        # Every launch endpoint closes only after publication resolves.
        failures = []
        for name, fd in list(self.transport_fds.items()):
            try:
                os.close(fd)
                del self.transport_fds[name]
            except OSError:
                failures.append(name)
        for name in ('proc_directory', 'pidfd'):
            fd = getattr(self, name)
            if fd is not None:
                try:
                    os.close(fd)
                    setattr(self, name, None)
                except OSError:
                    failures.append(name)
        if row is not None:
            row.update(stdio_closed=not self.transport_fds, pidfd_closed=self.pidfd is None)
        try:
            self._remove_scratch(row)
        except Exception:
            if self.record is not None:
                self.record['error'] = 'scratch_cleanup'
                row.update(scratch_disposition='retained', status='failed', finished_at_ns=time.monotonic_ns())
            return
        for name, fd in list(self.fds.items()):
            try:
                os.close(fd)
                del self.fds[name]
            except OSError:
                failures.append(name)
        self.resolved = not failures and not self.fds and not self.transport_fds and self.pidfd is None
        if row is not None:
            now = time.monotonic_ns()
            row.update(finished_at_ns=now, status='complete' if self.resolved and now <= self.deadline_ns else 'failed',
                scratch_disposition='removed', removed_names=sorted(set(row['removed_names'])),
                descriptors_closed=self.resolved, stdio_closed=not self.transport_fds, pidfd_closed=self.pidfd is None,
                source_package_closed='source_package' not in self.fds,
                parent_closed=not any(key in self.fds for key in ('source_parent', 'scratch_parent')),
                directory_closed=not any(key in self.fds for key in ('source_store', 'scratch_store')),
                directory_removed=True)

    def run(self):
        if os.getpid() != self.pid:
            raise _RecoveryError('publication')
        if not self._lifecycle_lock.acquire(timeout=max(0, (self.deadline_ns-time.monotonic_ns())/1e9)):
            raise _RecoveryError('helper_reap')
        try:
            if self.resolved:
                raise _RecoveryError('publication')
            self.active = True
            self.quiescent = False
            return self._run_locked()
        finally:
            self.active = False
            self.quiescent = self.resolved and self.record is not None
            self._lifecycle_lock.release()

    def _run_locked(self):
        try:
            with c._deadline_context(self.work_deadline_ns/1e9):
                self._setup()
                self.publication_thread = threading.Thread(target=self._publish, daemon=True)
                self.publication_thread.start()
                while not self.publication.wait(min(.005, max(0, (self.work_deadline_ns-time.monotonic_ns())/1e9))):
                    self.control.check()
                if self.publication_error is not None:
                    raise _RecoveryError('publication')
                for name in ('stdin_child', 'stdout_child', 'stderr_child'):
                    os.close(self.transport_fds.pop(name))
                self._pin()
                for name in ('stdout_parent', 'stderr_parent'):
                    os.set_blocking(self.transport_fds[name], False)
                _recovery_write(self.transport_fds['stdin_parent'], len(self.config_raw).to_bytes(8, 'big')+self.config_raw,
                                self.work_deadline_ns)
                self._receive()
                self._validate_work()
        except BaseException as error:
            if self.record is not None:
                self.record['error'] = (error.code if isinstance(error, _RecoveryError) else
                    'work_deadline' if time.monotonic_ns() >= self.work_deadline_ns
                        or getattr(error, 'code', '').endswith('_timeout') else 'publication')
                if self.publication_thread is None:
                    self.record['process'].update(publication_state='not_started',
                        publication_resolved_at_ns=time.monotonic_ns())
        finally:
            self._cleanup_locked()
        if self.record is None:
            raise _RecoveryError('publication')
        record = self.record
        record['finished_at_ns'] = time.monotonic_ns()
        if not self.resolved:
            record['status'] = 'unknown'
            raise _RecoveryError(record['error'] or 'helper_reap')
        complete = (record['error'] is None and self.result is not None and self.result['status'] == 'complete'
            and record['process']['returncode'] == 0 and record['process']['signal_sent_at_ns'] is None
            and record['cleanup']['status'] == 'complete' and self.stdout_eof and self.stderr_eof
            and record['finished_at_ns'] <= self.deadline_ns
            and len(self.stdout) == self.ready_size+record['transfer']['result']['received_bytes'])
        record['status'] = 'complete' if complete else 'failed'
        if not complete:
            record['error'] = record['error'] or ('work_deadline' if time.monotonic_ns() >= self.deadline_ns else 'helper_exit')
            raise _RecoveryError(record['error'])
        from .engagement_live_context import _recovery_shape
        try:
            # Validation decorators inherit this original hard deadline. They
            # must not allocate their normal default interval after closure.
            with c._deadline_context(self.deadline_ns/1e9):
                _recovery_check(self.deadline_ns)
                raw = _recovery_json(self.result['export'])
                export_sha256 = c.digest(raw)
                _recovery_check(self.deadline_ns)
                _recovery_shape(record, 'helper_observation')
                _recovery_check(self.deadline_ns)
                stage = record['work']['ro']
                store = record['work']['post_ro_copy']
                main = store['files'][0]['held']
                # Sample after validation/export serialization and immediately
                # before the final immutable record hash. Check the remaining
                # hash/receipt tail against the same deadline before return.
                record['finished_at_ns'] = time.monotonic_ns()
                _recovery_check(self.deadline_ns)
                helper_sha256 = c.digest(_recovery_json(record))
                _recovery_check(self.deadline_ns)
                receipt = {'schema_version': '2', 'source': 'postcleanup_copied_recovery',
                    'owner_id': stage['owner_id'], 'started_at_ns': stage['opened_at_ns'],
                    'finished_at_ns': stage['closed_at_ns'], 'read_only': True,
                    'store_identity': {'parent': store['parent'], 'directory': store['directory'],
                        'database': {key: main[key] for key in ('device', 'inode', 'mode', 'uid', 'gid')}},
                    'bytes': len(raw), 'sha256': export_sha256, 'ledger_state_sha256': stage['ledger_state_sha256'],
                    'closed': True, 'helper_id': self.helper_id, 'helper_sha256': helper_sha256}
                _recovery_shape(receipt, 'copied_receipt')
                _recovery_json(receipt)
                _recovery_check(self.deadline_ns)
            _recovery_check(self.deadline_ns)
            return raw, receipt
        except BaseException as error:
            record['status'] = 'failed'
            record['finished_at_ns'] = time.monotonic_ns()
            record['error'] = (error.code if isinstance(error, _RecoveryError) else
                'work_deadline' if record['finished_at_ns'] >= self.deadline_ns
                    or getattr(error, 'code', '').endswith('_timeout') else 'framing')
            raise _RecoveryError(record['error']) from error


class _HostEvidenceBudget:
    """One host allocation across all producers and sequential broker owners."""

    def __init__(self):
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._pending = {}
        self._rows = []
        self._bytes = 0
        self._supervision = 0
        self._session_owners = []

    def _check(self):
        if self._pid != os.getpid():
            c.fail('foreign_owner')

    def _attach_session(self, session):
        from .engagement_live_approval import _bounded_lock

        self._check()
        with _bounded_lock(self._lock, session._control):
            prior = tuple(self._session_owners)
        if len(prior) >= 2 or any(not owner._verified_reaped() for owner in prior):
            c.fail('cleanup_incomplete')
        with _bounded_lock(self._lock, session._control):
            if (tuple(self._session_owners) != prior
                    or any(not owner._verified_reaped() for owner in prior)):
                c.fail('cleanup_incomplete')
            self._session_owners.append(session)

    def reserve(self, *, kind, maximum_bytes, maximum_rows, control):
        from .engagement_live_approval import _bounded_lock

        self._check()
        if kind not in ('supervision_projection', 'other_host'):
            c.fail('invalid_input')
        c.integer(maximum_bytes, 1, 3072 if kind == 'supervision_projection' else 262144)
        # Each ticket describes one actual observation, not an arbitrary batch.
        c.integer(maximum_rows, 1, 1)
        with _bounded_lock(self._lock, control):
            reserved_bytes = sum(row['bytes'] for row in self._pending.values())
            reserved_supervision = sum(row['kind'] == 'supervision_projection'
                                       for row in self._pending.values())
            if (self._bytes + reserved_bytes + maximum_bytes > 262144
                    or len(self._rows) + len(self._pending) + 1 > 128
                    or (kind == 'supervision_projection'
                        and self._supervision + reserved_supervision + 1 > 96)):
                c.fail('limit_exceeded')
            ticket = object()
            self._pending[ticket] = {'kind': kind, 'bytes': maximum_bytes,
                                     'request': None, 'row': None}
            return ticket

    @staticmethod
    def _copy_row(row):
        if type(row) is not dict or type(row.get('kind')) is not str:
            c.fail('evidence_invalid')
        selected = deepcopy(row)
        # Charge the maximum eventual combined host sequence width now.
        selected['row_sequence'] = 128
        raw = c.canonical(selected, max_bytes=262144)
        return c.decode(raw, max_bytes=262144), len(raw) + 1

    @staticmethod
    def _request_identity(row):
        selected = deepcopy(row)
        selected.pop('observed_at_ns', None)
        data = selected.get('data')
        if selected['kind'] == 'supervision_projection' and type(data) is dict:
            data.pop('reply', None)
            data.pop('local_error', None)
        elif selected['kind'] == 'capability_projection' and type(data) is dict:
            for key in ('reply', 'reply_projection_sha256',
                        'original_reply_sha256', 'original_reply_bytes'):
                data.pop(key, None)
        return selected

    def record_request(self, ticket, row):
        self._check()
        selected, size = self._copy_row(row)
        identity = self._request_identity(selected)
        with self._lock:
            pending = self._pending.get(ticket)
            if (pending is None or pending['row'] is not None or size > pending['bytes']
                    or (selected['kind'] == 'supervision_projection')
                       != (pending['kind'] == 'supervision_projection')):
                c.fail('evidence_invalid')
            pending['request'], pending['row'] = identity, selected

    def finalize(self, ticket, row):
        self._check()
        selected, size = self._copy_row(row)
        identity = self._request_identity(selected)
        with self._lock:
            pending = self._pending.get(ticket)
            if (pending is None or size > pending['bytes']
                    or (selected['kind'] == 'supervision_projection')
                       != (pending['kind'] == 'supervision_projection')
                    or (pending['request'] is not None and pending['request'] != identity)
                    or (pending['row'] is not None
                        and selected['observed_at_ns'] < pending['row']['observed_at_ns'])):
                c.fail('evidence_invalid')
            self._rows.append(selected)
            self._bytes += size
            self._supervision += pending['kind'] == 'supervision_projection'
            del self._pending[ticket]

    def release(self, ticket):
        self._check()
        with self._lock:
            pending = self._pending.get(ticket)
            if pending is None or pending['row'] is not None:
                c.fail('evidence_invalid')
            del self._pending[ticket]

    def snapshot(self):
        self._check()
        with self._lock:
            return {'rows': deepcopy(self._rows + [row['row'] for row in self._pending.values()
                                                   if row['row'] is not None]),
                    'unresolved_tickets': len(self._pending),
                    'reserved_bytes': sum(row['bytes'] for row in self._pending.values()),
                    'reserved_rows': len(self._pending)}


class _CleanupEpoch:
    """The first stop fixes cleanup time; no caller can restart the clock."""

    def __init__(self, control, *, stop_event=None, on_stop=None):
        self._pid = os.getpid()
        self._bound_ns = int(control.deadline * c.SECOND)
        self._lock = threading.Lock()
        self._value = None
        self._stop_event = threading.Event() if stop_event is None else stop_event
        self._on_stop = on_stop

    @property
    def stopped(self):
        return self._stop_event.is_set()

    def stop(self, *, bound_deadline_ns=None):
        if self._pid != os.getpid():
            c.fail('foreign_owner')
        now = time.monotonic_ns()
        bound = self._bound_ns
        if bound_deadline_ns is not None:
            bound = min(bound, c.integer(bound_deadline_ns, 1, c.INTEGER_MAX))
        with self._lock:
            first = self._value is None
            if first:
                # Reserve the contract's <=100 ms broker-death detection
                # latency even when ingress EOF or another closer wins the
                # race with the lifecycle monitor. Every stop path shares
                # this conservative allowance; later calls only narrow it.
                self._value = {'first_stop_requested_at_ns': now,
                               'deadline_ns': min(bound, now + 1_900_000_000)}
                self._stop_event.set()
            else:
                self._value['deadline_ns'] = min(self._value['deadline_ns'], bound)
        # The stop fence is already visible to every work control. Interrupting
        # a peer may clamp this epoch again, so callbacks run outside its lock.
        if first and self._on_stop is not None:
            self._on_stop()
        with self._lock:
            return dict(self._value)

    def snapshot(self):
        if self._pid != os.getpid():
            c.fail('foreign_owner')
        with self._lock:
            return None if self._value is None else dict(self._value)


class EngagementSession:
    @classmethod
    def start(cls, store_directory, audit_path, *, review_mode, control):
        return cls._start_with_host_budget(store_directory, audit_path,
            review_mode=review_mode, control=control, host_evidence_budget=_HostEvidenceBudget())

    @classmethod
    def _start_with_host_budget(cls, store_directory, audit_path, *, review_mode,
                               control, host_evidence_budget):
        from .execution import ExecutionControl
        from . import engagement_live_runtime as runtime
        from .engagement_live_broker import EngagementBroker, preallocate_role_bundle
        from .engagement_live_audit import EngagementAuditService

        if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                or review_mode not in {'terminal', 'graphical_v1'}):
            c.fail('invalid_input')
        control.check()
        if type(host_evidence_budget) is not _HostEvidenceBudget:
            c.fail('invalid_input')
        host_evidence_budget._check()
        self = cls.__new__(cls)
        self._pid = os.getpid()
        self._control = control
        self._mode = review_mode
        self._store_directory = store_directory
        self._audit_path = audit_path
        self._runtime = None
        self._recovery_owner = None
        self._recovery_helpers = []
        self._recovery_in_progress = False
        self._bundle = self._broker = self._audit = None
        self._monitor_thread = None
        self._stop = threading.Event()
        self._closing = threading.Event()
        self._close_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._slot_locks = (threading.Lock(), threading.Lock())
        self._sessions = {}
        self._used_slots = set()
        self._operations = {}
        self._roles = []
        self._readiness = []
        self._cleanup_receipts = []
        self._startup_observations = []
        self._failure = None
        self._cleanup = None
        self._closed = False
        self._startup_quiesced = False
        self._started_at_ns = time.monotonic_ns()
        self._observer_rows = []
        self._child_slots = []
        self._unstarted_supervisors = []
        self._remaining_channels_closed = False
        self._host_evidence_budget = host_evidence_budget
        self._cleanup_epoch = _CleanupEpoch(control, stop_event=self._stop, on_stop=self._request_stop)
        try:
            self._host_evidence_budget._attach_session(self)
            self._runtime = runtime.inspect_runtime(control)
            self._bundle = preallocate_role_bundle(review_mode)
            self._broker = EngagementBroker(runtime=self._runtime, store_directory=store_directory,
                                             control=control, role_bundle=self._bundle,
                                             cleanup_epoch=self._cleanup_epoch)
            self._roles.append(self._broker)
            self._broker_ready = self._broker.start()
            self._readiness.append(self._broker_ready['readiness'])
            for slot, allocated in zip(self._bundle.slots, self._broker_ready['allocated_slots']):
                for declaration in slot.child_slot_bindings:
                    self._child_slots.append({'schema_version': '1',
                        'broker_id': self._broker_ready['broker_id'],
                        'session_id': allocated['session_id'], 'launcher_id': slot.launcher_id,
                        **declaration, 'prepared_sha256': None, 'bootstrap': None, 'entry_sha256': None})
            self._audit = EngagementAuditService(audit_path, runtime=self._runtime,
                                                 role_bundle=self._bundle, control=control,
                                                 cleanup_epoch=self._cleanup_epoch)
            self._roles.append(self._audit)
            self._audit.start()
            self._broker.observe_audit(self._audit.readiness)
            self._check()
            self._monitor_thread = threading.Thread(target=self._monitor,
                name='engagement-live-lifecycle', daemon=True)
            self._monitor_thread.start()
            return self
        except BaseException as error:
            self._remember_failure(error)
            try:
                self.close()
            except BaseException as cleanup_error:
                error.cleanup_error = cleanup_error
            # An owner is retained for diagnostics even when startup produced
            # only partial observations. It is never represented as READY.
            error.engagement_session = self
            raise

    def _owner_check(self):
        if self._pid != os.getpid():
            c.fail('foreign_owner')

    def _check(self, control=None):
        self._owner_check()
        if control is not None and control is not self._control:
            c.fail('invalid_input')
        if self._closed or self._stop.is_set() or self._closing.is_set():
            c.fail('session_unavailable')
        self._control.check()

    def _remember_failure(self, error):
        if self._failure is None:
            self._failure = error
        receipt = getattr(error, 'startup_cleanup', None)
        if receipt is None:
            receipt = getattr(error, 'cleanup', None)
        if receipt is not None and receipt not in self._cleanup_receipts:
            self._cleanup_receipts.append(receipt)
        observation = getattr(error, 'startup_observation', None)
        if observation is not None:
            self._startup_observations.append(observation)

    def _supervisor_failed(self, error):
        # This fixed notification may run on a supervisor. It must never join
        # that thread or acquire a Session operation/cleanup lock.
        self._cleanup_epoch.stop()
        self._remember_failure(error)
        self._stop.set()

    def _request_stop(self):
        """Publish the stop fence and interrupt peers without waiting for locks."""
        self._owner_check()
        self._stop.set()
        for role in list(self._roles):
            if role is self._broker:
                continue
            interrupt = getattr(role, '_interrupt', None)
            if interrupt is not None:
                try:
                    interrupt()
                except BaseException as error:
                    self._remember_failure(error)

    def _session(self, session_id):
        c.uuid(session_id)
        with self._state_lock:
            row = self._sessions.get(session_id)
        if row is None or row['stopped']:
            c.fail('session_unavailable')
        return row

    def _register(self, row, role, owner, readiness):
        self._roles.append(owner)
        row[role] = owner
        self._readiness.append(readiness)
        self._broker.observe_role(row['ingress'], role, readiness)

    def open_session(self, *, ingress=0):
        self._check()
        try:
            return self._open_session(ingress=ingress)
        except BaseException as error:
            self._remember_failure(error)
            try:
                self.close()
            except BaseException as cleanup_error:
                error.cleanup_error = cleanup_error
            raise

    def _open_session(self, *, ingress=0):
        from .engagement_live_endpoint import prepare_endpoint
        from .engagement_live_launcher import EngagementLauncher
        from .engagement_live_approval import EngagementApprovalService
        from .engagement_live_approval import _clipped_control, _bounded_lock

        self._check()
        c.integer(ingress, 0, 1)
        startup = _clipped_control(self._control, int(self._control.deadline*c.SECOND),
                                   self._stop, self._cleanup_epoch)
        # The same finite setup slot covers persistent namespace/nft builders
        # and later child construction. Two API submitters cannot create a
        # second helper outside the explicit process-graph bound.
        with _bounded_lock(self._slot_locks[ingress], startup), \
                _bounded_lock(self._bundle._child_setup_lock, startup):
            self._check()
            with self._state_lock:
                if ingress in self._used_slots:
                    c.fail('limit_exceeded')
                self._used_slots.add(ingress)
            peers = None
            try:
                opened = c.validate_session_opened(self._broker.open_session(ingress=ingress))
                binding = opened['binding']
                slot = self._bundle.slots[ingress]
                allocated = self._broker_ready['allocated_slots'][ingress]
                if (binding['session_id'] != allocated['session_id']
                        or binding['reviewer_id'] != slot.reviewer_id
                        or binding['broker_id'] != self._broker_ready['broker_id']
                        or binding['ledger_owner_id'] != self._broker_ready['ledger_owner_id']
                        or opened['roe'] != self._broker_ready['roe']
                        or opened['scope'] != self._broker_ready['scope']
                        or opened['policy'] != self._broker_ready['policy']):
                    c.fail('invalid_prepared')
                row = {'opened': opened, 'ingress': ingress, 'stopped': False,
                       'endpoint': None, 'launcher': None, 'reviewer': None}
                with self._state_lock:
                    self._sessions[binding['session_id']] = row
                peers = slot.take_endpoint_bootstrap()
                endpoint_peers = {name: peers.pop(name) for name in ('host', 'child', 'broker_control')}
                endpoint_peers['endpoint_id'] = slot.endpoint_id
                arm = peers.pop('launcher_arm')
                endpoint = prepare_endpoint(runtime=self._runtime, session_binding=opened,
                    broker_peer=endpoint_peers, arm_peer=arm, control=_clipped_control(
                        self._control, binding['session_deadline_ns'], self._stop, self._cleanup_epoch))
                self._register(row, 'endpoint', endpoint, endpoint.ready)
                launcher = EngagementLauncher(self._runtime, endpoint=endpoint, role_slot=slot,
                    host_evidence_budget=self._host_evidence_budget,
                    cleanup_epoch=self._cleanup_epoch, failure_sink=self._supervisor_failed)
                # Register ownership before any launch can partially succeed.
                self._roles.append(launcher)
                row['launcher'] = launcher
                self._check()
                launcher.start(opened, self._bundle, self._control)
                self._readiness.append(launcher.readiness)
                self._broker.observe_role(ingress, 'launcher', launcher.readiness)
                endpoint.close_namespaces()
                reviewer = EngagementApprovalService(parse_policy(opened['policy']), binding['session_id'],
                    frontend=self._mode, session_binding=opened, runtime_manifest=self._runtime,
                    witness_slot=slot, control=self._control,
                    host_evidence_budget=self._host_evidence_budget,
                    cleanup_epoch=self._cleanup_epoch, failure_sink=self._supervisor_failed)
                self._roles.append(reviewer)
                row['reviewer'] = reviewer
                self._check()
                reviewer.start()
                self._readiness.append(reviewer.readiness)
                self._broker.observe_role(ingress,
                    'terminal' if self._mode == 'terminal' else 'graphical', reviewer.readiness)
                self._check()
                return deepcopy(opened)
            except BaseException as error:
                self._remember_failure(error)
                # Do not call close while holding this slot's startup lock.
                # The monitor or the caller's finally block owns total cleanup.
                self._cleanup_epoch.stop()
                self._stop.set()
                self._interrupt_roles(self._roles)
                raise
            finally:
                if peers is not None:
                    for peer in peers.values():
                        peer.close()

    def prepare(self, session_id, slot, *, ingress=0):
        self._check()
        row = self._session(session_id)
        reply = self._broker.prepare(session_id, slot, ingress=ingress)
        value = c.validate_prepared_context(reply['prepared'], row['opened'])
        if value['envelope']['slot'] != slot:
            c.fail('invalid_prepared')
        dispatch_id = value['envelope']['dispatch_id']
        with self._state_lock:
            if dispatch_id in self._operations or len(self._operations) >= 4:
                c.fail('invalid_prepared')
            self._operations[dispatch_id] = {'session': row['opened'], 'prepared': value,
                'result': None, 'client': None, 'meter': None, 'host_capture': None,
                'elapsed_ms': dict.fromkeys(('review', 'admission', 'native', 'parser', 'cleanup', 'action'))}
        row['launcher'].prepare(value, self._control)
        self._check()
        return deepcopy(value)

    def _prepared(self, value):
        value = c.validate_prepared(value)
        row = self._session(value['envelope']['session_id'])
        with self._state_lock:
            operation = self._operations.get(value['envelope']['dispatch_id'])
        if operation is None or operation['prepared'] != value:
            c.fail('invalid_prepared')
        c.validate_prepared_context(value, row['opened'])
        return value, row, operation

    def review(self, prepared, *, control):
        self._check(control)
        prepared, row, operation = self._prepared(prepared)
        began = time.monotonic_ns()
        try:
            return row['reviewer'].review(parse_action(prepared['action']),
                parse_policy(prepared['policy']), prepared['envelope'], control=control)
        finally:
            operation['elapsed_ms']['review'] = (time.monotonic_ns() - began) // 1000000

    def execute(self, prepared, reference, *, ingress=0, control):
        from .engagement_live_witness import started_event

        self._check(control)
        prepared, row, operation = self._prepared(prepared)
        if type(reference) is not str:
            c.fail('approval_unknown_or_replayed')
        consumed = row['reviewer'].consume(reference, parse_action(prepared['action']),
            parse_policy(prepared['policy']), prepared['envelope'], control=control)
        if not consumed['accepted']:
            c.fail('approval_unknown_or_replayed')
        # Original exact started event is fsynced by the isolated audit owner.
        # The broker requires its independent direct witness for this sequence.
        receipt = self._audit.emit(started_event(prepared), control=control)
        self._check(control)
        result = c.validate_live_result(self._broker._dispatch_with_control(c.prepared_digest(prepared),
            consumed['reference_sha256'], consumed['consume_sequence'], receipt['sequence'],
            ingress=ingress, control=control))
        if (result['session_id'] != prepared['envelope']['session_id']
                or result['dispatch_id'] != prepared['envelope']['dispatch_id']):
            c.fail('invalid_frame')
        with self._state_lock:
            # A missing reply stays null. An actual known refusal/uncertainty is
            # retained verbatim, even when the action already consumed quota.
            operation['result'] = result
        self._check(control)
        return deepcopy(result)

    def cancel(self, session_id):
        self._check()
        row = self._session(session_id)
        row['stopped'] = True
        self._cleanup_epoch.stop()
        self._interrupt_roles([row[key] for key in ('reviewer', 'launcher', 'endpoint')])
        try:
            return self._broker.cancel(session_id)
        finally:
            self._stop.set()

    def revoke(self, *, expected_revision, expected_generation, event_id):
        self._check()
        return self._broker.revoke(expected_revision=expected_revision,
                                  expected_generation=expected_generation, event_id=event_id)

    def snapshot(self):
        self._check()
        return self._broker.snapshot()

    def _verified_reaped(self):
        """Packaging can retain a timed-out cleanup only after actual reaping."""
        if getattr(self, '_recovery_in_progress', False):
            return False
        recovery = getattr(self, '_recovery_owner', None)
        if recovery is not None and not recovery.quiescent:
            return False
        if not self._closed or self._cleanup is None or not self._startup_quiesced:
            return False
        if self._child_slots and not self._remaining_channels_closed:
            return False
        monitor = self._monitor_thread
        if monitor is not None and monitor is not threading.current_thread() and monitor.is_alive():
            return False
        for session in self._sessions.values():
            launcher = session['launcher']
            if launcher is not None and not launcher.supervisor_resolved:
                return False
        reaped = set()
        for receipt in self._cleanup_receipts:
            if not receipt['descriptors_closed']:
                return False
            for process in receipt['processes']:
                if (not process['exit_observed'] or not process['reaped_observed']
                        or process['wrapper_pid'] is None or process['wrapper_returncode'] is None
                        or process['pid'] is None or process['start_time_ticks'] is None):
                    return False
                reaped.add((process['pid'],process['start_time_ticks']))
        observations = list(self._startup_observations) + [
            row['parent_observation'] for row in self._readiness]
        return all((row['payload']['pid'],row['payload']['start_time_ticks']) in reaped
                   for row in observations)

    def _recover_ledger(self, *, deadline=None):
        """Fresh read-only data custody after all live authority is reaped."""
        self._owner_check()
        began = time.monotonic_ns()
        limit_ns = min(began+2000000000, 9223372036854775807 if deadline is None else int(deadline*1e9))
        budget = self._host_evidence_budget
        budget._check()
        if not budget._lock.acquire(timeout=max(0, (limit_ns-time.monotonic_ns())/1e9)):
            c.fail('cleanup_incomplete')
        try:
            c._check_deadline(limit_ns/1e9)
            if (not budget._session_owners or budget._session_owners[-1] is not self
                    or not self._verified_reaped()):
                c.fail('cleanup_incomplete')
            if getattr(self, '_recovery_owner', None) is not None:
                c.fail('evidence_incomplete')
            self._recovery_in_progress = True
        finally:
            budget._lock.release()
        # Only registration/predicate changes use the shared budget lock. No
        # file access, lifecycle lock or cleanup waits occur while it is held.
        try:
            result = self._recover_ledger_registered(began=began, limit_ns=limit_ns)
        finally:
            if not budget._lock.acquire(timeout=max(0, (limit_ns-time.monotonic_ns())/1e9)):
                # An uncleared registration remains a visible fence; never
                # pretend a successor may overlap unresolved finalization.
                c.fail('cleanup_incomplete')
            try:
                self._recovery_in_progress = False
            finally:
                budget._lock.release()
        c._check_deadline(limit_ns/1e9)
        return result

    def _recover_ledger_registered(self, *, began, limit_ns):
        from .engagement_dispatch_store import DispatchLedger, DATABASE
        from . import engagement_dispatch_contract as ledger

        limit = limit_ns/1e9
        # Path selection uses directory capabilities and named metadata only.
        # The parent must never acquire/close a raw original SQLite descriptor.
        requested = Path(self._store_directory).absolute()
        parent_path = requested.parent.resolve(strict=True)
        parent_fd = directory_fd = None
        try:
            parent_fd = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            directory_fd = os.open(requested.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=parent_fd)
            names = sorted(os.listdir(directory_fd))
            if names not in ([_RECOVERY_MAIN], sorted(_RECOVERY_NAMES)):
                c.fail('evidence_invalid')
            if _RECOVERY_JOURNAL in names:
                if not hasattr(self, '_recovery_helpers'):
                    self._recovery_helpers = []
                lock = self._state_lock
                if not lock.acquire(timeout=max(0, (min(began+1500000000, limit_ns-500000000)-time.monotonic_ns())/1e9)):
                    c.fail('cleanup_incomplete')
                try:
                    if getattr(self, '_recovery_owner', None) is not None:
                        c.fail('evidence_incomplete')
                    owner = _RecoveryOwner(self, parent_fd, directory_fd, began, limit_ns)
                    self._recovery_owner = owner
                    parent_fd = directory_fd = None
                finally:
                    lock.release()
                try:
                    return owner.run()
                except _RecoveryError:
                    c.fail('evidence_incomplete' if owner.resolved else 'cleanup_incomplete')
        finally:
            for fd in (directory_fd, parent_fd):
                if fd is not None:
                    os.close(fd)
        def identity(info):
            return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
                    'uid': info.st_uid, 'gid': info.st_gid}
        def observe(store):
            store._check_parent()
            store._check_directory()
            store._check_files(read_entry=True)
            return {'parent': identity(os.fstat(store._parent_fd)),
                    'directory': identity(os.fstat(store._directory_fd)),
                    'database': identity(os.stat(DATABASE, dir_fd=store._directory_fd, follow_symlinks=False))}
        with ledger._deadline_context(limit):
            store = DispatchLedger.open(self._store_directory, read_only=True)
            try:
                before = observe(store)
                owner_id = store.owner_reference
                if self._broker is not None and self._broker.readiness is not None:
                    if owner_id == self._broker.readiness['ledger_owner_id']:
                        c.fail('foreign_owner')
                snapshot = store.snapshot()
                raw = ledger.canonical(snapshot)
                if not 0 < len(raw) <= 2097152 or observe(store) != before:
                    c.fail('evidence_invalid')
            finally:
                store.close()
        c._check_deadline(limit)
        finished = time.monotonic_ns()
        return raw, {'schema_version': '1', 'source': 'postcleanup_readonly', 'owner_id': owner_id,
            'started_at_ns': began, 'finished_at_ns': finished, 'read_only': True,
            'store_identity': before, 'bytes': len(raw), 'sha256': c.digest(raw),
            'ledger_state_sha256': snapshot['events'][-1]['receipt']['state_sha256'], 'closed': True}

    def _saved_audit(self, deadline):
        if self._audit is None or self._audit._file_identity is None:
            return b''
        path = Path(self._audit_path).absolute()
        parent = path.parent.resolve(strict=True)
        directory = os.open(parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fd = None
        try:
            parent_info = os.fstat(directory)
            if (parent_info.st_dev,parent_info.st_ino) != self._audit._parent_identity:
                c.fail('evidence_invalid')
            fd = os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid()
                    or (before.st_dev,before.st_ino) != self._audit._file_identity
                    or before.st_size > 1048576):
                c.fail('evidence_invalid')
            raw = bytearray()
            while len(raw) < before.st_size:
                c._check_deadline(deadline)
                part = os.read(fd,min(65536,before.st_size-len(raw)))
                if not part:
                    c.fail('evidence_invalid')
                raw.extend(part)
            after = os.fstat(fd)
            named = os.stat(path.name,dir_fd=directory,follow_symlinks=False)
            key = lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_nlink,item.st_mode)
            if key(before) != key(after) or key(after) != key(named):
                c.fail('evidence_invalid')
            c._check_deadline(deadline)
            return bytes(raw)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)

    def _recovery_packaging_snapshot(self, *, deadline, expected=None):
        budget = self._host_evidence_budget
        budget._check()
        if not budget._lock.acquire(timeout=max(0, deadline-time.monotonic())):
            c.fail('cleanup_incomplete')
        try:
            # This predicate reads only published state. It never acquires a
            # lifecycle/close lock or waits for physical cleanup.
            if not self._verified_reaped():
                c.fail('cleanup_incomplete')
            owner = getattr(self, '_recovery_owner', None)
            with c._deadline_context(deadline):
                raw = c.canonical(getattr(self, '_recovery_helpers', []), max_bytes=524288)
            if expected is not None and (owner is not expected[0] or raw != expected[1]):
                c.fail('evidence_incomplete')
            return owner, raw
        finally:
            budget._lock.release()

    def _evidence_payload(self, *, deadline=None, case_id=None, instrumentation=(),
                          boundary_proofs=(), core_proofs=(), boundary_observations=(), recover=False):
        """Copy actual retained observations after cleanup; never fill gaps."""
        from . import engagement_live_runtime as runtime
        from . import engagement_live_evidence as evidence
        from .engagement_live_witness import validate_transcript_row

        self._owner_check()
        if not self._verified_reaped():
            c.fail('cleanup_incomplete')
        if self._runtime is None:
            c.fail('invalid_runtime')
        limit = min(time.monotonic()+15,float('inf') if deadline is None else deadline)
        c._check_deadline(limit)
        members = {}
        readies = deepcopy(self._readiness)
        natives = []
        receipts = deepcopy(self._cleanup_receipts)
        # Keep the actual whole-graph timing result as well as individual role
        # receipts. Readers count distinct PID/start identities, so this cannot
        # inflate process counts or hide a shared-deadline cleanup failure.
        receipts.append(deepcopy(self._cleanup))
        operations = deepcopy(list(self._operations.values()))
        by_dispatch = {row['prepared']['envelope']['dispatch_id']:row for row in operations}
        child_slots = deepcopy(self._child_slots)
        supervisors = deepcopy(self._unstarted_supervisors)
        startups = deepcopy(self._startup_observations)
        exports, instances, segments, raw_segments = [], [], [], []
        captures = set()
        def retain_prepared(actual):
            did = actual['envelope']['dispatch_id']
            if did not in by_dispatch:
                session = self._sessions.get(actual['envelope']['session_id'])
                if session is None or len(operations) >= 4:
                    c.fail('evidence_invalid')
                c.validate_prepared_context(actual, session['opened'])
                pending = {'session': session['opened'], 'prepared': actual, 'result': None,
                    'client': None, 'meter': None, 'host_capture': None,
                    'elapsed_ms': dict.fromkeys(('review','admission','native','parser','cleanup','action'))}
                operations.append(pending)
                by_dispatch[did] = pending
            elif by_dispatch[did]['prepared'] != actual:
                c.fail('evidence_invalid')
            return by_dispatch[did]
        for session in self._sessions.values():
            launcher = session['launcher']
            if launcher is None:
                continue
            actual = launcher.supervision_snapshot()
            startups.extend(actual['startup'])
            readies.extend(actual['readiness'])
            natives.extend(actual['native'])
            receipts.extend(actual['receipts'])
            supervisors.extend(actual['supervisors'])
            for slot in actual['child_slots']:
                matching = [i for i, old in enumerate(child_slots)
                            if (old['broker_id'], old['session_id'], old['child_slot'])
                            == (slot['broker_id'], slot['session_id'], slot['child_slot'])]
                if len(matching) != 1:
                    c.fail('evidence_invalid')
                old = child_slots[matching[0]]
                if any(old[key] != slot[key] for key in
                       ('schema_version','broker_id','session_id','launcher_id','child_slot','role','worker_id','pair')):
                    c.fail('evidence_invalid')
                child_slots[matching[0]] = slot
            for prepared in actual['prepared']:
                retain_prepared(c.validate_prepared(prepared))
            for did, capture in actual['captures'].items():
                operation = by_dispatch.get(did)
                if operation is None or operation['host_capture'] is not None:
                    c.fail('evidence_invalid')
                operation['host_capture'] = deepcopy(capture['host_capture'])
                for stream in ('stdout','stderr'):
                    raw_capture = capture[stream]
                    if (type(raw_capture) is not bytes
                            or len(raw_capture) != capture['host_capture'][stream+'_bytes']
                            or c.digest(raw_capture) != capture['host_capture'][stream+'_sha256']):
                        c.fail('evidence_invalid')
                    members['client-'+did+'.'+stream+'.bin'] = raw_capture
                captures.add(did)
        unavailable = {'status':'unavailable','source':None,'file':None,'reason':'not_started','broker_id':None}
        ledger_exports = {key:dict(unavailable) for key in ('initial','final','recovery')}
        saved = None
        try:
            if (self._broker is not None and self._broker._cleanup is not None
                    and self._broker._owner is not None):
                saved = self._broker.close_evidence(deadline=limit)
            ready = None if self._broker is None else self._broker.readiness
            if ready is not None:
                instances.append({'broker_id':ready['broker_id'],'ledger_owner_id':ready['ledger_owner_id']})
            if saved is not None and saved['broker_id'] is not None:
                for phase in ('initial','final'):
                    row = saved[phase]
                    if row is None:
                        ledger_exports[phase]['reason'] = 'not_acknowledged'
                        continue
                    name = phase+'-ledger.json'
                    members[name] = row['raw']
                    ledger_exports[phase] = {'status':'complete','source':'sealed_broker','file':name,
                                              'reason':None,'broker_id':saved['broker_id']}
                    exports.append({'broker_id':saved['broker_id'], **{key:row[key] for key in
                                   ('reference','host_descriptor','broker_descriptor')}})
                transcript = saved['transcript']
                if transcript is not None:
                    raw = transcript['raw']
                    segments.append({'source':'broker_memfd','broker_id':saved['broker_id'],
                        'offset':0,'bytes':len(raw),'sha256':c.digest(raw),'seals':transcript['seals'],
                        'status':transcript['status']})
                    raw_segments.append(raw)
                    # Only complete individual canonical rows are observations.
                    # A crash tail is retained verbatim in its own segment.
                    for line in raw.split(b'\n')[:-1]:
                        c._check_deadline(limit)
                        row = validate_transcript_row(c.decode(line))
                        if row['kind'] != 'protocol':
                            continue
                        frame = row['data']['frame']
                        if (row['data']['direction'] == 'sent' and frame['operation'] == 'PREPARE'
                                and row['data']['channel_role'] in ('launcher','endpoint')):
                            # Retain actual broker preparation even if the final
                            # host acknowledgment was lost during child setup.
                            actual = c.validate_prepared(frame['body'])
                            retain_prepared(actual)
                        if row['data']['direction'] != 'received':
                            continue
                        operation = by_dispatch.get(row['dispatch_id'])
                        if frame['operation'] == 'METER' and row['data']['channel_role'] == 'endpoint':
                            if operation is not None:
                                operation['meter'] = frame['body']
                        elif frame['operation'] == 'RESULT' and row['data']['channel_role'] == 'launcher':
                            if operation is not None:
                                operation['client'] = frame['body']
                        elif frame['operation'] == 'NATIVE_OBSERVED':
                            # The original relay remains in the transcript;
                            # only independently retained host facts enter the
                            # process arrays. Replay decides missing/conflict.
                            pass
                        elif frame['operation'] == 'OBSERVATION' and row['data']['channel_role'] == 'launcher':
                            observation = frame['body']
                            did = observation['dispatch_id']
                            if operation is None or did != row['dispatch_id']:
                                c.fail('evidence_invalid')
                            data = observation['data']
                            if observation['kind'] == 'capture':
                                for stream in ('stdout','stderr'):
                                    encoded = data[stream+'_base64']
                                    raw_capture = base64.b64decode(encoded,validate=True)
                                    if (base64.b64encode(raw_capture).decode('ascii') != encoded
                                            or len(raw_capture) != data[stream+'_bytes']
                                            or c.digest(raw_capture) != data[stream+'_sha256']):
                                        c.fail('evidence_invalid')
                                    name = 'client-'+did+'.'+stream+'.bin'
                                    if name in members and members[name] != raw_capture:
                                        c.fail('evidence_invalid')
            host = self._host_evidence_budget.snapshot()
            if any(host[key] for key in ('unresolved_tickets','reserved_bytes','reserved_rows')):
                c.fail('evidence_incomplete')
            broker_ids = {row['broker_id'] for row in instances}
            if self._broker is not None:
                broker_ids.add(self._broker._broker_id)
            observer_rows = [row for row in host['rows'] if row['broker_id'] in broker_ids]
            if observer_rows:
                observer_rows.sort(key=lambda row:row['observed_at_ns'])
                for index,row in enumerate(observer_rows,1):
                    row['row_sequence'] = index
                    validate_transcript_row(row)
                raw = b''.join(c.canonical(row)+b'\n' for row in observer_rows)
                segments.append({'source':'role_observer','broker_id':None,'offset':sum(map(len,raw_segments)),
                    'bytes':len(raw),'sha256':c.digest(raw),'seals':None,'status':'observer_complete'})
                raw_segments.append(raw)
            recovery = None
            if recover:
                members['recovery-ledger.json'], recovery = self._recover_ledger(deadline=limit)
                ledger_exports['recovery'] = {'status':'complete','source':recovery['source'],
                    'file':'recovery-ledger.json','reason':None,'broker_id':None}
            else:
                ledger_exports['recovery']['reason'] = 'not_applicable'
            def unique(values):
                result, hashes = [], set()
                for value in values:
                    digest = c.digest(c.canonical(value))
                    if digest not in hashes:
                        hashes.add(digest)
                        result.append(value)
                return result
            helper_snapshot = self._recovery_packaging_snapshot(deadline=limit)
            helper_records = c.decode(helper_snapshot[1], max_bytes=524288)
            cleanup_member = {'schema_version':'2' if helper_records else '1', 'receipts':unique(receipts),
                'supervisors':supervisors, 'exports':exports, 'recovery':recovery}
            if helper_records:
                cleanup_member['recovery_helpers'] = helper_records
            members.update({
                'runtime.json':c.canonical({'schema_version':'1','runtime':self._runtime,
                                            'instrumentation':list(instrumentation)},max_bytes=2097152),
                'processes.json':c.canonical({'schema_version':'1','startup':unique(startups),
                    'readiness':unique(readies),
                    'native':unique(natives),'child_slots':child_slots,
                    'boundary_observations':list(boundary_observations)},max_bytes=1048576),
                'results.json':c.canonical({'schema_version':'1','operations':operations,
                    'boundary_proofs':list(boundary_proofs),'core_proofs':list(core_proofs)},max_bytes=524288),
                'cleanup.json':c.canonical(cleanup_member,max_bytes=524288),
                'audit.jsonl':self._saved_audit(limit), 'transcript.jsonl':b''.join(raw_segments)})
            case = None if case_id is None else evidence._case(case_id)
            manifest = {'schema_version':'1','contract_sha256':c.CONTRACT_SHA256,
                'gates_sha256':c.INVENTORY_SHA256,'runtime_sha256':runtime.runtime_digest(self._runtime),
                'evidence_class':'production_run' if case is None else 'owned_gate',
                'proof_kind':'role_boundary' if case is not None and case['group']=='native_runtime' else 'live_operation',
                'case_id':case_id,'configuration':None if case is None else case.get('configuration'),
                'review_mode':self._mode,'instrumentation':[{key:item[key] for key in
                    ('kind','source_sha256','configuration_sha256')} for item in instrumentation],
                'broker_instances':instances,'ledger_exports':ledger_exports,
                'transcript':{'status':'unavailable' if not segments else
                    'partial' if any(s['status'].endswith('partial') for s in segments) else 'complete',
                    'segments':segments,'reason':'not_started' if not segments else
                    'broker_lost' if any(s['status'].endswith('partial') for s in segments) else None},
                'dispatches':[{'dispatch_id':op['prepared']['envelope']['dispatch_id'],
                    'session_id':op['prepared']['envelope']['session_id'],'slot':op['prepared']['envelope']['slot'],
                    **{stream+'_file':('client-'+op['prepared']['envelope']['dispatch_id']+'.'+stream+'.bin'
                        if op['prepared']['envelope']['dispatch_id'] in captures else None)
                       for stream in ('stdout','stderr')}} for op in operations],
                'members':[{'name':name,'bytes':len(raw),'sha256':c.digest(raw)} for name,raw in sorted(members.items())]}
            c._check_deadline(limit)
            self._recovery_packaging_snapshot(deadline=limit, expected=helper_snapshot)
            c._check_deadline(limit)
            return manifest,members
        finally:
            if self._bundle is not None:
                self._bundle.close()

    @staticmethod
    def _interrupt_roles(roles):
        for owner in roles:
            interrupt = getattr(owner, '_interrupt', None)
            if interrupt is not None:
                interrupt()

    def _monitor(self):
        work_deadline_ns=int(self._control.deadline*c.SECOND)-c.CLEANUP_NS
        try:
            while not self._closing.wait(min(.05,max(0,(work_deadline_ns-time.monotonic_ns())/c.SECOND))):
                if self._stop.is_set():
                    c.fail('session_unavailable')
                self._control.check()
                if time.monotonic_ns()>=work_deadline_ns:
                    c.fail('timeout')
                if self._broker.pidfd is not None:
                    import select
                    if select.select([self._broker.pidfd], [], [], 0)[0]:
                        c.fail('session_unavailable')
                event = self._broker.poll_lifecycle()
                if event is None:
                    continue
                if event['operation'] == 'BROKER_STOP':
                    self._cleanup_epoch.stop(bound_deadline_ns=event['body']['cleanup_deadline_ns'])
                    c.fail('session_unavailable')
                with self._state_lock:
                    row = self._sessions.get(event['body']['session_id'])
                if row is None:
                    c.fail('invalid_frame')
                if row['stopped']:
                    continue
                row['stopped'] = True
                # The shared stop epoch covers both supervisors. A terminal
                # event cannot leave another owner running beyond that epoch.
                self._cleanup_epoch.stop(bound_deadline_ns=event['body']['cleanup_deadline_ns'])
                c.fail('session_unavailable')
        except BaseException as error:
            self._remember_failure(error)
            try:
                self.close()
            except BaseException as cleanup_error:
                self._remember_failure(cleanup_error)

    def _close_unstarted_supervisors(self, launchers, epoch):
        """Observe terminal custody of allocations whose thread never started."""
        if not self._child_slots:
            return
        from . import engagement_live_runtime as runtime

        began = time.monotonic_ns()
        # Startup is already fenced and every existing supervisor has joined.
        # This closes actual untransferred endpoints while preserving only the
        # integer export readers needed for subsequent evidence packaging.
        self._bundle.close_remaining_channels()
        active = {owner.slot.launcher_id for owner in launchers
                  if owner._supervisor is not None}
        for owner in launchers:
            if owner._supervisor is None and owner._owner is not None:
                if owner._owner.channel.fileno() != -1:
                    c.fail('cleanup_incomplete')
        existing = {(row['broker_id'],row['session_id'],row['launcher_id'])
                    for row in self._unstarted_supervisors}
        missing = sorted({(row['broker_id'],row['session_id'],row['launcher_id'])
                          for row in self._child_slots if row['launcher_id'] not in active} - existing)
        observer = runtime._observer() if missing else None
        finished = time.monotonic_ns()
        epoch = self._cleanup_epoch.snapshot()
        for broker_id,session_id,launcher_id in missing:
            self._unstarted_supervisors.append({'schema_version':'1','broker_id':broker_id,
                'session_id':session_id,'launcher_id':launcher_id,'host_observer':deepcopy(observer),
                'thread_native_id':None,'thread_started_at_ns':None,'state':'not_started',
                'first_stop_requested_at_ns':epoch['first_stop_requested_at_ns'],
                'cleanup_started_at_ns':max(began,epoch['first_stop_requested_at_ns']),
                'cleanup_finished_at_ns':finished,'cleanup_deadline_ns':epoch['deadline_ns'],
                'join_attempted':False,'thread_alive_observed':False,'channel_closed':True,
                'pending_slots':[],'status':'complete' if finished <= epoch['deadline_ns'] else 'failed'})
        self._remaining_channels_closed = True

    def close(self):
        self._owner_check()
        recovery = getattr(self, '_recovery_owner', None)
        if recovery is not None and not recovery.quiescent:
            try:
                recovery._cleanup()
            except _RecoveryError:
                c.fail('cleanup_incomplete')
        if getattr(self, '_recovery_in_progress', False):
            c.fail('cleanup_incomplete')
        epoch = self._cleanup_epoch.stop()
        deadline = epoch['deadline_ns'] / c.SECOND
        self._closing.set()
        self._stop.set()
        # All blocking view/client channels are interrupted before any lock is
        # acquired. Cleanup shares one budget across the entire live graph.
        self._interrupt_roles([r for r in self._roles if r is not self._broker])
        # Interrupting a live child may narrow the shared epoch to its earlier
        # action deadline. All later roles inherit that same actual bound.
        epoch = self._cleanup_epoch.snapshot()
        deadline = epoch['deadline_ns'] / c.SECOND
        if not self._close_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            c.fail('cleanup_incomplete')
        errors = []
        try:
            already_failed = self._cleanup is not None and self._cleanup['status'] != 'complete'
            if self._closed and self._verified_reaped():
                if already_failed:
                    c.fail('cleanup_incomplete')
                return deepcopy(self._cleanup)
            began = time.monotonic_ns()
            held = []
            try:
                for lock in self._slot_locks:
                    if not lock.acquire(timeout=max(0, deadline-time.monotonic())):
                        c.fail('cleanup_incomplete')
                    held.append(lock)
                self._startup_quiesced = True
            except BaseException as error:
                errors.append(error)
            finally:
                for lock in reversed(held):
                    lock.release()
            launchers = [row['launcher'] for row in self._sessions.values()
                         if row['launcher'] is not None]
            endpoints = [row['endpoint'] for row in self._sessions.values()
                         if row['endpoint'] is not None]
            # Signal all roles above, then join every supervisor before an
            # endpoint pin can be closed/recycled during a namespace lease.
            ordered = launchers + [owner for owner in reversed(self._roles) if owner not in launchers]
            for owner in ordered:
                try:
                    epoch = self._cleanup_epoch.snapshot()
                    deadline = min(deadline, epoch['deadline_ns']/c.SECOND)
                    if owner in endpoints and any(not item.supervisor_resolved for item in launchers):
                        c.fail('cleanup_incomplete')
                    receipt = owner._close(deadline)
                    if receipt is not None and receipt not in self._cleanup_receipts:
                        self._cleanup_receipts.append(receipt)
                except BaseException as error:
                    self._remember_failure(error)
                    errors.append(error)
            supervisors_resolved = all(owner.supervisor_resolved for owner in launchers)
            if self._startup_quiesced and supervisors_resolved:
                try:
                    self._close_unstarted_supervisors(launchers, epoch)
                except BaseException as error:
                    self._remember_failure(error)
                    errors.append(error)
            finished = time.monotonic_ns()
            epoch = self._cleanup_epoch.snapshot()
            deadline = min(deadline, epoch['deadline_ns']/c.SECOND)
            resolved = all(r['status'] == 'complete' and r['descriptors_closed']
                           for r in self._cleanup_receipts)
            channels_closed = not self._child_slots or self._remaining_channels_closed
            resolved = resolved and supervisors_resolved and self._startup_quiesced and channels_closed
            self._cleanup = {'schema_version': '1', 'started_at_ns': began,
                'finished_at_ns': finished, 'deadline_ns': epoch['deadline_ns'],
                'status': 'failed' if already_failed or errors or not resolved or finished > epoch['deadline_ns'] else 'complete',
                'processes': [p for receipt in self._cleanup_receipts for p in receipt['processes']],
                'descriptors_closed': supervisors_resolved and self._startup_quiesced and channels_closed
                    and all(r['descriptors_closed'] for r in self._cleanup_receipts)}
            self._closed = True
        finally:
            self._close_lock.release()
        monitor = self._monitor_thread
        deadline = min(deadline, self._cleanup_epoch.snapshot()['deadline_ns']/c.SECOND)
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=max(0, deadline-time.monotonic()))
            if monitor.is_alive():
                self._cleanup['status'] = 'failed'
                errors.append(c.LiveError('engagement_live_cleanup_incomplete'))
        self._cleanup['deadline_ns'] = min(self._cleanup['deadline_ns'],
            self._cleanup_epoch.snapshot()['deadline_ns'])
        self._cleanup['finished_at_ns'] = time.monotonic_ns()
        if self._cleanup['finished_at_ns'] > self._cleanup['deadline_ns']:
            self._cleanup['status'] = 'failed'
        if errors or self._cleanup['status'] != 'complete':
            error = c.LiveError('engagement_live_cleanup_incomplete')
            error.cleanup = self._cleanup
            raise error
        return deepcopy(self._cleanup)
