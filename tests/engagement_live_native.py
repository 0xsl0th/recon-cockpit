"""Fixed S4.2c physical-case harness. Imported helpers do not launch anything.

Test source variants are committed in the inspected runtime. The host may supply
only a fixed case selector; no fake grant, fabricated readiness or pass flag is
accepted as physical proof. Every failed attempt remains in its private directory.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from recon_cockpit.secure_agent import engagement_live_runtime as runtime
from recon_cockpit.secure_agent import engagement_live_contract as contract
from recon_cockpit.secure_agent.engagement_live_context import BOUNDARY_CASES

RUNTIME_CASES={row['variant']:{'case_id':case_id,**row} for case_id,row in BOUNDARY_CASES.items()}
CONFIGURATIONS={
 'A':{'schema_version':'1','scope_id':'owned-example','http':{'target':'10.77.0.10','port':8080,'path':'/'},'ssh':{'target':'10.77.0.20','port':2222}},
 'B':{'schema_version':'1','scope_id':'owned-example-alternate','http':{'target':'172.23.0.10','port':18080,'path':'/'},'ssh':{'target':'172.23.0.20','port':12222}}}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def sha(raw):return hashlib.sha256(raw).hexdigest()


def private_write(path,raw):
    path=Path(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    try:
        offset=0
        while offset<len(raw):
            count=os.write(fd,raw[offset:])
            if count<=0:raise OSError('private short write')
            offset+=count
        os.fsync(fd)
    finally:os.close(fd)


class SourceVariants:
    """Fixed new-module source overrides before actual runtime inspection."""
    def __init__(self,directory,*,case_id,variant,role):
        if type(case_id)is not str or not case_id.startswith(('S42C-N','S42C-X')):raise ValueError('case_id')
        self.directory=Path(directory);self.directory.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.configuration={'case_id':case_id,'variant':variant,'role':role}
        self.paths={};self.records=[];self._original=None;self._host_runtime=False;self._saved_runtime=None;self.runtime_globals=None
    @property
    def instrumentation(self):
        result=[]
        for row in self.records:
            configuration=row.get('configuration',self.configuration)
            result.append({'kind':'sealed_fault','configuration':deepcopy(configuration),
                'configuration_sha256':sha(canonical(configuration)),'source_sha256':row['after_sha256']})
        return result
    def source(self,module,transform):
        audit_case=module=='audit_worker' and self.configuration['case_id']=='S42C-N51' and self.configuration['variant']=='audit_fsync_failure'
        if module not in runtime.source_modules() or not (module.startswith('engagement_live_') or audit_case) or module in self.paths:raise ValueError('fixed_source_only')
        original=ROOT/'recon_cockpit'/'secure_agent'/(module+'.py');before=original.read_bytes()
        changed=transform(before.decode('utf-8'))
        if type(changed)is not str or changed==before.decode('utf-8'):raise ValueError('source_variant_required')
        compile(changed,str(original),'exec');raw=changed.encode('utf-8')
        if len(raw)>262144:raise ValueError('source_variant_limit')
        path=self.directory/(module+'.py');private_write(path,raw);self.paths[module]=path
        self.records.append({'module':module,'before_sha256':sha(before),'after_sha256':sha(raw),'bytes':len(raw)})
        return path
    def __enter__(self):
        if self._original is not None:raise RuntimeError('nested_source_override')
        self._original=runtime._source_path
        if self._host_runtime:
            # Execute the exact sealed test-wrapper source in the trusted test
            # parent too. Its fault values are fixed in that committed source.
            path=self.paths['engagement_live_runtime']
            namespace={key:runtime.__dict__[key] for key in ('__name__','__package__','__file__','__builtins__')}
            exec(compile(path.read_bytes(),str(path),'exec'),namespace)
            self._saved_runtime=dict(runtime.__dict__)
            runtime.__dict__.update({key:value for key,value in namespace.items() if not key.startswith('__')})
            self.runtime_globals=namespace
        resolver=lambda module:self.paths.get(module,self._original(module))
        runtime._source_path=resolver
        if self.runtime_globals is not None:self.runtime_globals['_source_path']=resolver
        return self
    def __exit__(self,*unused):
        if self._saved_runtime is not None:
            runtime.__dict__.clear();runtime.__dict__.update(self._saved_runtime);self._saved_runtime=None
        runtime._source_path=self._original;self._original=None
        private_write(self.directory/'source-variants.json',canonical({'schema_version':'1','configuration':self.configuration,'sources':self.records}))


@contextmanager
def native_session(directory,*,configuration='A',review_mode='terminal',source_variants=None,
                   roe_transform=None,store_directory=None,control=None,host_evidence_budget=None):
    """Actual fresh v2 owner and live broker; no approval shortcut is installed."""
    from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger
    from recon_cockpit.secure_agent.engagement_live_session import EngagementSession,_HostEvidenceBudget
    from recon_cockpit.secure_agent.execution import ExecutionControl
    directory=Path(directory);directory.mkdir(mode=0o700,parents=True,exist_ok=False)
    roe=json.loads((ROOT/'examples/secure-agent-engagement-roe.json').read_bytes())
    if configuration not in CONFIGURATIONS:raise ValueError('fixed_configuration')
    roe['scope']=deepcopy(CONFIGURATIONS[configuration])
    now=datetime.now(timezone.utc)
    roe['window']={'start_utc':(now-timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                   'end_utc':(now+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')}
    roe['limits']['max_engagement_ms']=600000
    if roe_transform is not None:roe=roe_transform(deepcopy(roe))
    if store_directory is None:
        store=directory/'store'
        with DispatchLedger.create(store,roe=roe,engagement_id=str(uuid4()),event_id=str(uuid4())):pass
    else:
        store=Path(store_directory)
        if not store.is_dir() or roe_transform is not None:raise ValueError('existing_store_required')
        # A recovery invocation retains the actual existing record, not a fresh
        # clock-window declaration which the broker never read.
        with DispatchLedger.open(store,read_only=True) as previous:
            roe=deepcopy(previous.snapshot()['revisions'][-1]['roe'])
        if roe['scope']!=CONFIGURATIONS[configuration]:raise ValueError('fixed_configuration')
    private_write(directory/'roe.json',canonical(roe))
    control=ExecutionControl(time.monotonic()+120) if control is None else control
    if type(control)is not ExecutionControl or control.clock is not time.monotonic or control.deadline>time.monotonic()+120:raise ValueError('original_control')
    service=None;failure=None
    try:
        if source_variants is not None and source_variants._original is None:
            raise ValueError('source_variants_context_required')
        service=EngagementSession._start_with_host_budget(store,directory/'audit.jsonl',review_mode=review_mode,control=control,
            host_evidence_budget=_HostEvidenceBudget() if host_evidence_budget is None else host_evidence_budget)
        yield service
    except BaseException as error:
        failure=error
        if service is None:service=getattr(error,'engagement_session',None)
        if service is not None:error.engagement_session=service
        raise
    finally:
        if service is not None:
            try:service.close()
            except BaseException as error:
                error.engagement_session=service
                if failure is None:raise
                failure.cleanup_error=error


def _file_inventory(directory):
    result={}
    for path in sorted(Path(directory).iterdir()):
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise AssertionError('private evidence file')
        raw=path.read_bytes();after=path.stat()
        if (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns):raise AssertionError('evidence changed')
        result[path.name]={'bytes':len(raw),'sha256':sha(raw),'mode':info.st_mode,'mtime_ns':info.st_mtime_ns,'inode':info.st_ino,'device':info.st_dev}
    return result


def _bounded_inspector(command,deadline,directory):
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        close_fds=True,start_new_session=True)
    captured={process.stdout:bytearray(),process.stderr:bytearray()};pending=set(captured)
    try:
        for stream in pending:os.set_blocking(stream.fileno(),False)
        while pending or process.poll()is None:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('CLI replay deadline')
            for stream in select.select(list(pending),[],[],min(.01,remaining))[0]:
                chunk=os.read(stream.fileno(),min(4096,8193-sum(map(len,captured.values()))))
                if chunk:captured[stream].extend(chunk)
                else:pending.remove(stream)
                if sum(map(len,captured.values()))>8192:raise AssertionError('CLI replay output cap')
        if time.monotonic()>deadline:raise TimeoutError('CLI replay deadline')
        if process.returncode!=0 or captured[process.stderr]:raise AssertionError('CLI replay refused')
        return subprocess.CompletedProcess(command,process.returncode,bytes(captured[process.stdout]),bytes(captured[process.stderr]))
    except BaseException as error:
        reaped=_terminate_watchdog(process) if process.poll()is None else None
        private_write(directory/'inspection-cli-failure.json',canonical({'error_type':type(error).__name__,
            'wrapper_returncode':process.returncode,'emergency_reaped':reaped,'acceptance':False}))
        private_write(directory/'inspection-cli-failure.stdout',bytes(captured[process.stdout]))
        private_write(directory/'inspection-cli-failure.stderr',bytes(captured[process.stderr]))
        raise
    finally:
        process.stdout.close();process.stderr.close()


def inspect_saved_case(path,case_id):
    """Fresh bounded Python/CLI replay; retain exact unchanged bundle inventory."""
    from recon_cockpit.secure_agent.engagement_live_evidence import inspect_live_bundle
    path=Path(path);before=_file_inventory(path);started=time.monotonic()
    report=inspect_live_bundle(path,deadline=started+15)
    python_elapsed=time.monotonic()-started
    if python_elapsed>15:raise AssertionError('Python replay deadline')
    command=[sys.executable,str(ROOT/'scripts/engagement_live_inspect.py'),str(path)]
    cli_started=time.monotonic()
    completed=_bounded_inspector(command,min(cli_started+15,started+30),path.parent)
    cli_elapsed=time.monotonic()-cli_started
    if cli_elapsed>15 or time.monotonic()-started>30:raise AssertionError('CLI replay deadline')
    if completed.stderr or completed.returncode!=0 or len(completed.stdout)>8192:raise AssertionError('CLI replay refused')
    other=json.loads(completed.stdout)
    if other!=report or report['case_id']!=case_id or report['case_passed']is not True:raise AssertionError('case replay mismatch')
    after=_file_inventory(path)
    if before!=after:raise AssertionError('evidence mutation')
    receipt={'schema_version':'1','case_id':case_id,'python_elapsed_ms':round(python_elapsed*1000),'cli_elapsed_ms':round(cli_elapsed*1000),'cli_returncode':completed.returncode,
             'python_report_sha256':sha(canonical(report)),'cli_stdout_sha256':sha(completed.stdout),'inputs_before':before,'inputs_after':after,
             'native_target_execution_in_inspector':False,'isolated_parser_replay_permitted':True}
    private_write(path.parent/'inspection-receipt.json',canonical(receipt))
    private_write(path.parent/'inspection-cli.stdout.json',completed.stdout)
    return report,receipt


def _descendants(parent):
    rows={}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():continue
        try:
            raw=(path/'stat').read_text();end=raw.rindex(')');fields=raw[end+2:].split()
            rows[int(path.name)]=(int(fields[1]),int(fields[19]))
        except (OSError,ValueError,IndexError):continue
    selected={parent};changed=True
    while changed:
        before=len(selected);selected|={pid for pid,(ppid,_) in rows.items() if ppid in selected};changed=len(selected)!=before
        if len(selected)>100:raise AssertionError('owned test process bound')
    return {pid:rows[pid] for pid in selected if pid!=parent and pid in rows}


def _terminate_watchdog(process):
    """Emergency test failure only; never creates passing cleanup evidence."""
    end=time.monotonic()+2;pins=[]
    try:
        for pid,identity in _descendants(process.pid).items():
            try:
                fd=os.pidfd_open(pid,0)
                current=runtime._process_identity(pid)
                if current['parent_pid']!=identity[0] or current['start_time_ticks']!=identity[1]:os.close(fd);continue
                pins.append(fd);signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
            except ProcessLookupError:pass
        try:process.kill()
        except ProcessLookupError:pass
        process.wait(timeout=max(0,end-time.monotonic()))
        while time.monotonic()<end and any(runtime._payload_state(fd)!='reaped' for fd in pins):time.sleep(.005)
        return all(runtime._payload_state(fd)=='reaped' for fd in pins)
    finally:
        for fd in pins:os.close(fd)


def run_case_watchdog(kind,variant,directory,*,timeout=360):
    if kind not in ('runtime','core') or type(variant)is not str or type(timeout)is not int or not 1<=timeout<=360:raise ValueError('fixed_case_runner')
    directory=Path(directory);directory.mkdir(mode=0o700,parents=True,exist_ok=True);directory.chmod(0o700)
    command=[sys.executable,str(Path(__file__).resolve()),'--'+kind,variant,str(directory)]
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True)
    started=time.monotonic();buffers={process.stdout:bytearray(),process.stderr:bytearray()};failure=None
    try:
        for stream in buffers:os.set_blocking(stream.fileno(),False)
        pending=set(buffers)
        while pending or process.poll()is None:
            if time.monotonic()-started>=timeout:raise TimeoutError('native case outer watchdog')
            ready=select.select(list(pending),[],[],.05)[0]
            for stream in ready:
                raw=os.read(stream.fileno(),4096)
                if not raw:pending.remove(stream)
                else:
                    buffers[stream].extend(raw)
                    if len(buffers[stream])>65536:raise AssertionError('native case diagnostic cap')
        if process.returncode!=0:raise AssertionError('native case failed; retained diagnostics')
    except BaseException as error:
        failure=error
        reaped=_terminate_watchdog(process) if process.poll()is None else None
        private_write(directory/'watchdog-failure.json',canonical({'error_type':type(error).__name__,'wrapper_returncode':process.returncode,'emergency_reaped':reaped,'acceptance':False}))
        raise
    finally:
        private_write(directory/'driver.stdout',bytes(buffers[process.stdout]));private_write(directory/'driver.stderr',bytes(buffers[process.stderr]))
        process.stdout.close();process.stderr.close()
    result=json.loads(bytes(buffers[process.stdout]))
    path=Path(result['bundle'])
    if set(result)!={'bundle'} or path.parent!=directory or not path.is_dir():raise AssertionError('fixed bundle path')
    return path


def run_runtime_case(variant,directory):
    if variant not in RUNTIME_CASES:raise ValueError('fixed_runtime_case')
    return run_case_watchdog('runtime',variant,directory)


def run_core_case(variant,directory):return run_case_watchdog('core',variant,directory)


def _failure_json(value,*,maximum=131072):
    # Copy only bounded JSON facts. Do not stringify arbitrary objects, inspect
    # new processes, recover a ledger, or normalize a failed cleanup receipt.
    nodes=0
    def copy(value,depth=0):
        nonlocal nodes
        nodes+=1
        if depth>20 or nodes>16384:raise ValueError('failure_value_limit')
        if value is None or type(value)is bool:return value
        if type(value)is int:
            if value.bit_length()>128:raise ValueError('failure_value_limit')
            return value
        if type(value)is str:
            if len(value)>8192:raise ValueError('failure_value_limit')
            return value
        if type(value)is list:
            if len(value)>94:raise ValueError('failure_value_limit')
            return [copy(item,depth+1) for item in value]
        if type(value)is dict:
            if len(value)>128 or any(type(key)is not str or len(key)>128 for key in value):
                raise ValueError('failure_value_limit')
            return {key:copy(item,depth+1) for key,item in value.items()}
        raise ValueError('failure_value_type')
    detached=copy(value)
    if len(canonical(detached))>maximum:raise ValueError('failure_value_limit')
    return detached


def _save_case_failure(directory,kind,variant,error):
    """Private diagnostic only; preserve actual failure and never emit a report."""
    import base64
    maximum=262144;budget=maximum-32768;observations=[];omitted=[];exceptions=[];sessions=[]
    queue=[error];seen={id(error):0};session_ids={}
    def retain(owner,name,value,*,binary=False):
        nonlocal budget
        try:
            if binary:
                if type(value)is not bytes:raise ValueError('failure_value_type')
                captured=value[:4096]
                value={'original_bytes':len(value),'retained_bytes':len(captured),
                    'retained_sha256':sha(captured),'base64':base64.b64encode(captured).decode('ascii'),
                    'truncated':len(captured)!=len(value)}
                if value['truncated']:omitted.append({'owner':owner,'attribute':name,'reason':'raw_limit'})
            else:value=_failure_json(value)
            row={'owner':owner,'attribute':name,'value':value};encoded=canonical(row)
            if len(encoded)>budget:raise ValueError('failure_total_limit')
            budget-=len(encoded);observations.append(row)
        except (ValueError,TypeError,OverflowError,RecursionError,RuntimeError):
            omitted.append({'owner':owner,'attribute':name,'reason':'unretained_value'})
    def link(owner,name,linked):
        if linked is None:return None
        if not isinstance(linked,BaseException):
            omitted.append({'owner':owner,'attribute':name,'reason':'not_exception'});return None
        identity=id(linked)
        if identity not in seen:
            if len(queue)>=8:
                omitted.append({'owner':owner,'attribute':name,'reason':'chain_limit'});return None
            seen[identity]=len(queue);queue.append(linked)
        return seen[identity]
    def plain_state(value):
        try:state=object.__getattribute__(value,'__dict__')
        except (AttributeError,TypeError):return None
        return state if type(state)is dict else None
    def traceback_tail(item,owner):
        # Code locations only: never frame locals, source, or exception strings.
        tb=BaseException.__getattribute__(item,'__traceback__')
        frames=[];visited=0;field_truncated=False
        while tb is not None and visited<64:
            code=tb.tb_frame.f_code
            filename,name=code.co_filename,code.co_name
            field_truncated |= len(filename)>512 or len(name)>128
            frames.append({'filename':filename[:512],'function':name[:128],'line':tb.tb_lineno})
            if len(frames)>8:frames.pop(0)
            visited+=1;tb=tb.tb_next
        if visited>8:omitted.append({'owner':owner,'attribute':'traceback','reason':'traceback_frames_limit'})
        if tb is not None:omitted.append({'owner':owner,'attribute':'traceback','reason':'traceback_traversal_limit'})
        if field_truncated:omitted.append({'owner':owner,'attribute':'traceback','reason':'traceback_field_limit'})
        retain(owner,'traceback',{'frames':frames,'visited_frames':visited,
            'scope':'last_frames' if tb is None else 'tail_of_visited_prefix',
            'earlier_visited_frames_omitted':max(0,visited-len(frames)),
            'traversal_truncated':tb is not None,'field_truncated':field_truncated})
    def session_facts(state,record):
        owner='session:'+str(record['index'])
        record['first_failure_index']=link(owner,'_failure',state.get('_failure'))
        record['supervisors']=[]
        groups=state.get('_sessions')
        if groups is None:return
        if type(groups)is not dict or len(groups)>2:
            omitted.append({'owner':owner,'attribute':'_sessions','reason':'unretained_value'});return
        try:items=list(groups.items())
        except RuntimeError:
            omitted.append({'owner':owner,'attribute':'_sessions','reason':'concurrent_change'});return
        if len(items)>2:
            omitted.append({'owner':owner,'attribute':'_sessions','reason':'concurrent_change'});return
        session_keys=set()
        for key,group in items:
            if type(key)is not str or len(key)>128 or type(group)is not dict:
                omitted.append({'owner':owner,'attribute':'_sessions','reason':'unretained_value'});continue
            session_keys.add(key)
            launcher_object=group.get('launcher')
            if launcher_object is None:continue
            launcher=plain_state(launcher_object)
            if launcher is None:
                omitted.append({'owner':owner,'attribute':'launcher','reason':'unretained_value'});continue
            supervisor_object=launcher.get('_supervisor')
            if supervisor_object is None:continue
            supervisor=plain_state(supervisor_object)
            if supervisor is None:
                omitted.append({'owner':owner,'attribute':'supervisor','reason':'unretained_value'});continue
            entry={'index':len(record['supervisors']),'session_key':key,'failure_index':None}
            subowner=owner+':supervisor:'+str(entry['index'])
            entry['failure_index']=link(subowner,'failure',supervisor.get('failure'))
            record['supervisors'].append(entry)
            if 'closure' in supervisor:retain(subowner,'closure',supervisor['closure'])
        allocator_object=state.get('_host_evidence_budget')
        if allocator_object is None:return
        allocator=plain_state(allocator_object)
        if allocator is None:
            omitted.append({'owner':owner,'attribute':'_host_evidence_budget','reason':'unretained_value'});return
        rows=allocator.get('_rows')
        if type(rows)is not list or len(rows)>128:
            for name in ('finalized_supervision_rows','finalized_phase_rows'):
                omitted.append({'owner':owner,'attribute':name,'reason':'unretained_value'})
            return
        # Only already-finalized plain rows, without snapshot/locks/new actions.
        # These bounded diagnostic tails are never a complete wire transcript.
        for kind,name in (('supervision_projection','finalized_supervision_rows'),('phase','finalized_phase_rows')):
            relevant=[row for row in rows[:128] if type(row)is dict and row.get('kind')==kind
                and type(row.get('session_id'))is str and row['session_id'] in session_keys]
            if len(relevant)>8:
                omitted.append({'owner':owner,'attribute':name,'reason':'row_tail_limit'})
            retain(owner,name,{'rows':relevant[-8:],
                'observed_matching_rows':len(relevant),'earlier_rows_omitted':max(0,len(relevant)-8),
                'scope':'finalized_rows_only_nonatomic_diagnostic_tail'})
    def recovery_facts(owner,value):
        # Keep bounded process/closure facts even when a large complete journal
        # record list cannot fit the independent failure diagnostic capsule.
        if type(value)is not list:
            omitted.append({'owner':owner,'attribute':'recovery_helper_closure_rows','reason':'unretained_value'});return
        fields=('schema_version','helper_id','broker_id','generation','status','started_at_ns',
            'work_deadline_ns','deadline_ns','finished_at_ns','parent_observer','process','cleanup','error')
        rows=[{key:row[key] for key in fields if key in row} for row in value[:2] if type(row)is dict]
        missing=len(value)-len(rows)
        if missing:omitted.append({'owner':owner,'attribute':'recovery_helper_closure_rows','reason':'row_limit_or_type'})
        retain(owner,'recovery_helper_closure_rows',{'rows':rows,'observed_helper_rows':len(value),
            'retained_helper_rows':len(rows),'omitted_helper_rows':missing,'work_included':False,
            'scope':'retained_state_only_nonatomic_diagnostic_projection'})
    for index,item in enumerate(queue):
        attrs=BaseException.__getattribute__(item,'__dict__')
        typename=type(item).__name__
        row={'index':index,'type':typename[:128],'code':attrs.get('code') if type(attrs.get('code'))is str and attrs['code'] in contract.ERROR_CODES else None,
             'links':{},'session_index':None}
        exceptions.append(row)
        traceback_tail(item,'exception:'+str(index))
        for name in ('startup_cleanup','startup_observation','cleanup','process_cleanup','owned_startup_guard'):
            if name in attrs:retain('exception:'+str(index),name,attrs[name])
        for name in ('startup_diagnostics','startup_info'):
            if name in attrs:retain('exception:'+str(index),name,attrs[name],binary=True)
        session=attrs.get('engagement_session')
        if session is not None:
            identity=id(session)
            if identity not in session_ids:
                state=plain_state(session)
                if state is not None:
                    session_ids[identity]=len(sessions);record={'index':len(sessions)};sessions.append(record)
                    for name in ('_cleanup','_cleanup_receipts','_startup_observations'):
                        if name in state:retain('session:'+str(record['index']),name,state[name])
                    if '_recovery_helpers' in state:
                        owner='session:'+str(record['index'])
                        recovery_facts(owner,state['_recovery_helpers'])
                        retain(owner,'_recovery_helpers',state['_recovery_helpers'])
                    session_facts(state,record)
                else:omitted.append({'owner':'exception:'+str(index),'attribute':'engagement_session','reason':'unretained_value'})
            row['session_index']=session_ids.get(identity)
        for name in ('__cause__','__context__','startup_failure','cleanup_error','resource_cleanup_error'):
            linked=BaseException.__getattribute__(item,name) if name.startswith('__') else attrs.get(name)
            target=link('exception:'+str(index),name,linked)
            if target is not None:row['links'][name]=target
    value={'schema_version':'1','acceptance':False,'kind':kind,
        'variant':variant if type(variant)is str and len(variant)<=128 else None,
        'observer_pid':os.getpid(),'observed_at_ns':time.monotonic_ns(),
        'exception_chain':exceptions,'sessions':sessions,'observations':observations,
        'omitted':omitted,'capture_complete':not omitted}
    raw=canonical(value)
    if len(raw)>maximum:raise ValueError('failure_artifact_limit')
    private_write(Path(directory)/'case-failure.json',raw)

def _main(arguments):
    if len(arguments)!=3 or arguments[0] not in ('--runtime','--core'):raise ValueError('fixed case arguments')
    variant,directory=arguments[1],Path(arguments[2])
    try:
        if arguments[0]=='--runtime':path=_run_runtime_case(variant,directory)
        else:path=_run_core_case(variant,directory)
        sys.stdout.buffer.write(canonical({'bundle':str(path)})+b'\n');sys.stdout.buffer.flush()
    except BaseException as error:
        try:_save_case_failure(directory,arguments[0][2:],variant,error)
        except BaseException:pass # Diagnostic retention cannot replace the original failure.
        raise



class _TestOwnedRole:
    """Actual extra preparation-only leaf retained in the case's common cleanup."""
    def __init__(self,owner):self.owner=owner
    def _interrupt(self):
        import socket
        try:self.owner.channel.shutdown(socket.SHUT_RDWR)
        except OSError:pass
    def _close(self,deadline=None):return self.owner.close(deadline=deadline)


def _actual_role(case):
    return {'client':'nmap','client_to_parser':'nmap','endpoint_to_broker':'endpoint',
            'waiting_python':'nmap','all':'launcher'}.get(case['role'],case['role'])


def _exercise_runtime_role(service,case):
    """Preparation only: no supplied reference, forged GO or native effect."""
    role=_actual_role(case)
    if role=='broker':return service._broker._owner
    opened=service.open_session()
    row=service._sessions[opened['binding']['session_id']]
    if role=='endpoint':return row['endpoint'].owner
    if role in ('terminal','graphical'):return row['reviewer']._owner
    if role=='launcher':return row['launcher']._owner
    if role=='parser':
        bounded=runtime._ClippedControl(service._control,time.monotonic()+2)
        owner=runtime._start_role(runtime=service._runtime,role='parser',payload={'slot':'http_identify','scope':opened['scope']},rights={},control=bounded)
    elif role in ('nmap','headers'):
        # The same reviewed namespace construction used for the launcher is
        # applied by this sealed test wrapper to a waiting preparation-only leaf.
        endpoint=row['endpoint'].owner
        held=[os.open('ns/'+name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=endpoint.pin.directory) for name in ('user','net')]
        try:
            prepared=contract.derive_prepared(opened,'http_identify' if role=='nmap' else 'http_headers',dispatch_id=str(uuid4()),clock=contract.sample_clock())
            owner=runtime._start_role(runtime=service._runtime,role=role,payload={'prepared':prepared,'endpoint_identity':endpoint.ready,'scope':opened['scope']},rights={},control=service._control,
                namespace_fds=tuple(held),expected_net=endpoint.ready['parent_observation']['namespaces']['net'])
        finally:
            for fd in held:os.close(fd)
    else:raise AssertionError('fixed preparation role')
    service._roles.append(_TestOwnedRole(owner));service._readiness.append(owner.ready)
    return owner


_SNAPSHOT_PROBE = r"""
_LIVE_CASE = __CASE__
_LIVE_FAULT_ACTIVE = False
_LIVE_FAULT_RECORDS = []


def _live_fault_snapshot(snapshot):
    if not _LIVE_FAULT_ACTIVE or snapshot.role!=_LIVE_CASE['actual_role']:return
    import fcntl
    variant=_LIVE_CASE['variant'];kind=_LIVE_CASE['kind']
    if kind!='pin_mutation':return
    if variant.startswith('role_manifest_'):
        selected='parser' if variant.endswith('client_to_parser') else 'broker'
        # Exact foreign role object from the already validated full bundle.
        foreign=next(row for row in _LIVE_FAULT_BUNDLE['roles'] if row['role']==selected)
        destination=MANIFEST_PATH;old=snapshot.manifest_fd;before=os.pread(old,131072,0);after=_json(foreign);target=None
    else:
        if variant.startswith('sealed_source_'):
            target=snapshot.sources
            name={'broker':'broker_worker','launcher':'launcher_worker','endpoint':'endpoint_worker','nmap':'client_worker','parser':'parser_worker','terminal':'approval_worker','graphical':'approval_worker'}[snapshot.role]
            destination='/app/recon_cockpit/secure_agent/engagement_live_'+name+'.py'
        else:
            target=snapshot.native
            if variant=='sealed_nmap_executable_changed':destination='/tool/nmap'
            elif variant=='sealed_broker_sqlite_library_changed':destination=next(path for path in target if 'libsqlite3.so' in path)
            elif variant=='sealed_graphical_tk_library_changed':destination=next(path for path in target if 'libtk8.6.so' in path)
            else:destination=next(path for path in target if 'libc.so' in path)
        old=target[destination];before=os.pread(old,16777216,0)
        after=before+b'\n# fixed sealed source mutation\n' if variant.startswith('sealed_source_') else before[:-1]+bytes([before[-1]^1])
    new=_sealed(after,name='fixed-live-case-mutation')
    observed=fcntl.fcntl(new,fcntl.F_GET_SEALS)
    snapshot._fds[snapshot._fds.index(old)]=new
    if target is None:snapshot.manifest_fd=new
    else:target[destination]=new
    os.close(old)
    _LIVE_FAULT_RECORDS.append({'destination':destination,'before_sha256':hashlib.sha256(before).hexdigest(),
        'after_sha256':hashlib.sha256(after).hexdigest(),'expected_seals':15,'observed_seals':observed,
        'rejected_stage':'role_manifest' if target is None else 'parent_image','ready_emitted':False,'arm_emitted':False})


def _live_fault_rights(role,rights,bootstrap):
    selected=list(rights.values())
    if not _LIVE_FAULT_ACTIVE or role!=_LIVE_CASE['actual_role'] or _LIVE_CASE['kind']!='descriptor_custody':return selected
    if _LIVE_CASE['variant'].startswith('unexpected_'):
        fd=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC);_LIVE_FAULT_EXTRA_FDS.append(fd);selected.append(fd)
    else:selected.pop()
    return selected


def _live_received_rights(role,rights,rows):
    if role!=_LIVE_CASE['actual_role'] or _LIVE_CASE['kind']!='descriptor_custody' or len(rights)==len(rows):return
    actual=[]
    for fd in rights:
        purpose=next((row['purpose'] for row in rows if row['fd']==fd),'observed')
        row=_descriptor(fd,purpose)
        mode=row['mode'];row['kind']='regular' if stat.S_ISREG(mode) else 'character' if stat.S_ISCHR(mode) else 'seqpacket'
        actual.append(row)
    expected=[]
    for row in rows:
        selected=dict(row);mode=selected['mode'];selected['kind']='regular' if stat.S_ISREG(mode) else 'character' if stat.S_ISCHR(mode) else 'seqpacket';expected.append(selected)
    changed=actual[-1] if len(actual)>len(expected) else expected[-1]
    result={'phase':'initial_bootstrap','expected_inventory_sha256':_hash(expected),'actual_inventory_sha256':_hash(actual),'changed_descriptor':changed,'refused':True}
    raw=b'LIVE-RUNTIME-OBS '+_json(result)+b'\n'
    if len(raw)>2048:_fail('limit_exceeded')
    if os.write(2,raw)!=len(raw):_fail('unavailable')

_LIVE_FAULT_EXTRA_FDS = []
_LIVE_FAULT_BUNDLE = None
"""


def _startup_variant(variants,case):
    fixed={**case,'actual_role':_actual_role(case)}
    def transform(source):
        needle='            _check(control)\n        except BaseException:\n            self.close();raise\n    def _stage'
        if source.count(needle)!=1:raise AssertionError('snapshot insertion point changed')
        source=source.replace(needle,'            _check(control)\n            _live_fault_snapshot(self)\n        except BaseException:\n            self.close();raise\n    def _stage',1)
        needle="if role!='launcher' or len(namespace_fds)!=2:_fail('invalid_role')"
        if source.count(needle)!=1:raise AssertionError('namespace insertion point changed')
        source=source.replace(needle,"if role not in ('launcher','nmap','headers') or len(namespace_fds)!=2:_fail('invalid_role')",1)
        needle="        ancillary=[] if not rights else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',tuple(rights.values())))]"
        if source.count(needle)!=1:raise AssertionError('rights insertion point changed')
        source=source.replace(needle,"        selected_rights=_live_fault_rights(role,rights,bootstrap)\n        ancillary=[] if not selected_rights else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',tuple(selected_rights)))]",1)
        needle="        if type(rows)is not list or len(rows)!=len(RIGHTS[role]) or len(rights)!=len(rows):_fail('invalid_role')"
        if source.count(needle)!=1:raise AssertionError('receiver insertion point changed')
        source=source.replace(needle,"        _live_received_rights(role,rights,rows)\n"+needle,1)
        return source+_SNAPSHOT_PROBE.replace('__CASE__',repr(fixed))
    variants.source('engagement_live_runtime',transform);variants._host_runtime=True


def _merge_role_payloads(payloads,case,instrumentation,proof,observations):
    """Use one aggregate host segment and both actual broker histories."""
    if not 1<=len(payloads)<=2:raise AssertionError('sequential owner bound')
    if len(payloads)==2:
        manifest,members=_merge_core_payloads(payloads)
    else:
        manifest,members=deepcopy(payloads[0])
    processes=json.loads(members['processes.json'])
    processes['boundary_observations']=list(observations)
    results=json.loads(members['results.json'])
    results['boundary_proofs']=[proof];results['core_proofs']=[]
    members['processes.json']=canonical(processes);members['results.json']=canonical(results)
    manifest['members']=[{'name':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(members.items())]
    return manifest,members,time.monotonic()+15


@contextmanager
def _startup_diagnostic_readback(variants,case):
    """Retain already available fixture bytes before owned startup cleanup."""
    if case['kind']!='descriptor_custody':
        yield;return
    namespace=variants.runtime_globals;original=namespace['_read_startup']
    def available(control):
        # Read only already-published bounds; never start/renew cleanup or wait.
        end=int(control.deadline*1000000000)
        for _ in range(4):
            if control is None:return time.monotonic_ns()<end
            end=min(end,int(control.deadline*1000000000))
            if time.monotonic_ns()>=end:return False
            epoch=getattr(control,'_cleanup_epoch',None)
            if epoch is not None:
                if not epoch._lock.acquire(blocking=False):return False
                try:
                    value=epoch._value
                    if value is not None:end=min(end,value['deadline_ns'])
                finally:epoch._lock.release()
            control=getattr(control,'parent',getattr(control,'original',None))
        return control is None and time.monotonic_ns()<end
    def read(process,info_read,control,*,initial_info=b''):
        try:return original(process,info_read,control,initial_info=initial_info)
        except BaseException as error:
            if namespace['_LIVE_FAULT_ACTIVE']:
                retained=getattr(error,'startup_diagnostics',b'')
                try:
                    fd=process.stderr.fileno()
                    if type(retained)is bytes and len(retained)<4096 and not os.get_blocking(fd)and available(control):
                        part=os.read(fd,4096-len(retained))
                        if available(control):error.startup_diagnostics=retained+part
                except (OSError,ValueError):pass
            raise
    namespace['_read_startup']=read
    try:yield
    finally:namespace['_read_startup']=original


def _startup_runtime_case(case,directory):
    from recon_cockpit.secure_agent.engagement_live_session import _HostEvidenceBudget
    host_evidence_budget=_HostEvidenceBudget()
    role=_actual_role(case);mode='graphical_v1' if role=='graphical' else 'terminal'
    variants=SourceVariants(directory/'sources',case_id=case['case_id'],variant=case['variant'],role=case['role'])
    _startup_variant(variants,case);payloads=[];control_ready=None;fault=None;began=time.monotonic_ns()
    with variants,terminal_input(),_startup_diagnostic_readback(variants,case):
        for phase in ('control','fault'):
            variants.runtime_globals['_LIVE_FAULT_ACTIVE']=phase=='fault'
            service=None;failure=None
            try:
                with native_session(directory/phase,review_mode=mode,source_variants=variants,
                        store_directory=None if phase=='control' else directory/'control'/'store',
                        host_evidence_budget=host_evidence_budget) as service:
                    variants.runtime_globals['_LIVE_FAULT_BUNDLE']=service._runtime
                    owner=_exercise_runtime_role(service,case)
                    if phase=='fault':raise AssertionError('actual fault did not refuse isolated startup')
                    control_ready=deepcopy(owner.ready)
            except contract.LiveError as error:
                failure=error
                service=service or getattr(error,'engagement_session',None)
                if phase=='control':raise
                if service is not None:
                    service._remember_failure(error)
                    service.close()
            finally:
                for fd in variants.runtime_globals['_LIVE_FAULT_EXTRA_FDS']:
                    try:os.close(fd)
                    except OSError:pass
                variants.runtime_globals['_LIVE_FAULT_EXTRA_FDS'].clear()
            try:
                if service is None or phase=='fault' and failure is None:raise AssertionError('actual owned startup refusal required')
                if phase=='fault':
                    records=variants.runtime_globals['_LIVE_FAULT_RECORDS']
                    if case['kind']=='pin_mutation':
                        if len(records)!=1:raise AssertionError('one actual sealed input mutation')
                        fault=deepcopy(records[0])
                    else:
                        diagnostic=getattr(failure,'startup_diagnostics',b'')
                        lines=[line.removeprefix(b'LIVE-RUNTIME-OBS ') for line in diagnostic.splitlines() if line.startswith(b'LIVE-RUNTIME-OBS ')]
                        if len(lines)!=1:raise AssertionError('actual received descriptor observation required')
                        fault=json.loads(lines[0])
                if not service._verified_reaped():raise AssertionError('previous owner must be actually reaped before reuse')
                manifest,members=service._evidence_payload(case_id=case['case_id'],instrumentation=variants.instrumentation,recover=True)
                payloads.append((manifest,members))
            except BaseException as error:
                if service is not None:error.engagement_session=service
                if failure is not None:error.startup_failure=failure
                raise
    if control_ready is None or fault is None:raise AssertionError('physical control and refusal required')
    proof={'schema_version':'1','case_id':case['case_id'],'role':case['role'],'kind':case['kind'],
        'runtime_sha256':payloads[0][0]['runtime_sha256'],'source_sha256':variants.records[0]['after_sha256'],
        'observation_sha256':sha(canonical(fault)),'control_observation_sha256':sha(canonical(control_ready)),
        'started_at_ns':began,'finished_at_ns':time.monotonic_ns(),'checks':{case['variant']:True}}
    # The inspector recomputes that one predicate from the actual raw inputs.
    return _write_case_payload(directory,_merge_role_payloads(payloads,case,variants.instrumentation,proof,[{'kind':case['kind'],'observation':fault}]))


# Fixed post-seal probes use the same role image, readiness and cleanup as normal
# startup. The private token is test instrumentation, never an authority frame.
_KERNEL_PROBE_SOURCE = r'''
_LIVE_KERNEL_CASE = __CASE__
_LIVE_KERNEL_ROWS = []
_live_original_emit_ready = _emit_ready
_live_original_finish_start = _finish_start


def _live_task_ids():
    import ctypes
    try:return sorted(int(n) for n in os.listdir('/proc/self/task'))
    except OSError:
        # Landlocked single-task leaves may not reopen proc. gettid observes the
        # actual remaining task; their parent separately checks the exact count.
        return [ctypes.CDLL(None).gettid()]


def _live_try_creation(operation):
    import ctypes
    before=_live_task_ids();lib=ctypes.CDLL(None,use_errno=True);ctypes.set_errno(0)
    if operation=='fork':
        try:
            child=os.fork()
            if child==0:os._exit(79)
            os.waitpid(child,0);result=child;error=0
        except OSError as exc:result=-1;error=exc.errno
        flags=0
    elif operation=='unshare':
        flags=0x10000000;result=lib.unshare(flags);error=ctypes.get_errno() if result==-1 else 0
    else:
        flags=0;argv=(ctypes.c_char_p*2)(b'/usr/bin/python3',None);env=(ctypes.c_char_p*1)(None)
        result=lib.execve(b'/usr/bin/python3',argv,env);error=ctypes.get_errno() if result==-1 else 0
    return {'operation':operation,'flags':flags,'return_value':result,'errno':error,
            'tasks_before':before,'tasks_after':_live_task_ids()}


def _emit_ready(ready):
    _live_original_emit_ready(ready)
    if ready['role']!=_LIVE_KERNEL_CASE['actual_role']:return
    import select,socket
    channel=socket.socket(fileno=0)
    try:
        if not select.select([channel],[],[],2)[0] or channel.recv(65)!=b'LIVE-KERNEL-PROBE':_fail('invalid_input')
        if _LIVE_KERNEL_CASE['kind']=='creation_denial':
            rows=[_live_try_creation(op) for op in ('fork','unshare','execve')]
        else:
            def attempted(call,close):
                try:
                    value=call();close(value);return 0,0
                except OSError as error:return -1,error.errno
            network=attempted(lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM),lambda value:value.close())
            filesystem=attempted(lambda:os.open(MANIFEST_PATH,os.O_WRONLY|os.O_CLOEXEC),os.close)
            created=_live_try_creation('fork')
            actual=[]
            for fd in range(32):
                try:os.fstat(fd);actual.append(fd)
                except OSError:pass
            rows=[{'network_return':network[0],'network_errno':network[1],
                   'filesystem_return':filesystem[0],'filesystem_errno':filesystem[1],
                   'process_return':created['return_value'],'process_errno':created['errno'],
                   'authority_fds_absent':actual==[0,1,2]}]
        raw=b'LIVE-KERNEL-OBS '+_json(rows)+b'\n'
        if len(raw)>4096 or os.write(2,raw)!=len(raw):_fail('limit_exceeded')
    finally:channel.detach()


def _finish_start(**kwargs):
    owner=_live_original_finish_start(**kwargs)
    if kwargs['role']!=_LIVE_KERNEL_CASE['actual_role']:return owner
    import select
    _send_bytes(owner.channel,b'LIVE-KERNEL-PROBE',kwargs['control'])
    raw=bytearray()
    while not raw.endswith(b'\n'):
        _check(kwargs['control'])
        if not select.select([owner.process.stderr],[],[],_remaining(kwargs['control'],.01))[0]:continue
        part=os.read(owner.process.stderr.fileno(),4097-len(raw))
        if not part or len(raw)+len(part)>4096:_fail('invalid_role')
        raw.extend(part)
    if not raw.startswith(b'LIVE-KERNEL-OBS '):_fail('invalid_role')
    rows=_decode(bytes(raw[len(b'LIVE-KERNEL-OBS '):-1]),4096)
    _LIVE_KERNEL_ROWS.append({'role':kwargs['role'],'readiness':owner.ready,'observations':rows})
    return owner
'''


def _namespace_probe_source(text):
    before="if role!='launcher' or len(namespace_fds)!=2:"
    if text.count(before)!=1:raise AssertionError('fixed namespace source boundary')
    return text.replace(before,"if role not in ('launcher','nmap','headers') or len(namespace_fds)!=2:")


def _kernel_runtime_case(case,directory):
    selected=dict(case);selected['actual_role']='headers' if case['role']=='client' else _actual_role(case)
    variants=SourceVariants(directory/'sources',case_id=case['case_id'],variant=case['variant'],role=case['role'])
    addition=_KERNEL_PROBE_SOURCE.replace('__CASE__',repr(selected))
    variants.source('engagement_live_runtime',lambda text:_namespace_probe_source(text)+addition)
    variants._host_runtime=True;started=time.monotonic_ns()
    with variants,terminal_input():
        with native_session(directory/'trial',review_mode='graphical_v1' if selected['actual_role']=='graphical' else 'terminal',source_variants=variants) as service:
            actual_case={**case,'role':selected['actual_role']}
            owner=_exercise_runtime_role(service,actual_case)
            control=deepcopy(owner.ready)
        rows=variants.runtime_globals['_LIVE_KERNEL_ROWS']
        if len(rows)!=1 or rows[0]['readiness']!=control:raise AssertionError('actual single selected role required')
        observations=rows[0]['observations']
        expected=3 if case['kind']=='creation_denial' else 1
        if len(observations)!=expected:raise AssertionError('complete kernel probe inventory')
        from recon_cockpit.secure_agent.engagement_live_context import validate_boundary_observation
        for raw in observations:validate_boundary_observation(case['kind'],raw)
        proof={'schema_version':'1','case_id':case['case_id'],'role':case['role'],'kind':case['kind'],
            'runtime_sha256':runtime.runtime_digest(service._runtime),'source_sha256':variants.records[0]['after_sha256'],
            'observation_sha256':sha(canonical(observations[0])),'control_observation_sha256':sha(canonical(control)),
            'started_at_ns':started,'finished_at_ns':time.monotonic_ns(),'checks':{case['variant']:True}}
        manifest,members=service._evidence_payload(case_id=case['case_id'],instrumentation=variants.instrumentation,
            boundary_proofs=[proof],boundary_observations=[{'kind':case['kind'],'observation':raw} for raw in observations],recover=True)
    return _write_case_payload(directory,(manifest,members,time.monotonic()+15))


_SOCKET_RUNTIME_SOURCE = r'''
_LIVE_SOCKET_CASE=__CASE__
_LIVE_SOCKET_HOST_PID=__HOST_PID__
_LIVE_SOCKET_ROWS=[]
_live_socket_finish_start=_finish_start
_live_socket_start_child=SupervisorChannel.start_child


def _live_supervised_socket_start(self,**kwargs):
    owner=_live_socket_start_child(self,**kwargs)
    if self.slots[owner.slot]['role']==_LIVE_SOCKET_CASE['probe_role']:
        _send_bytes(owner.channel,b'LIVE-SOCKET-PROBE',kwargs['control'])
    return owner


SupervisorChannel.start_child=_live_supervised_socket_start


def _finish_start(**kwargs):
    owner=_live_socket_finish_start(**kwargs)
    role=kwargs['role'];selected=_LIVE_SOCKET_CASE['probe_role']
    if role!=selected:return owner
    import select
    _send_bytes(owner.channel,b'LIVE-SOCKET-PROBE',kwargs['control'])
    raw=bytearray()
    while not raw.endswith(b'\n'):
        _check(kwargs['control'])
        if not select.select([owner.process.stderr],[],[],_remaining(kwargs['control'],.01))[0]:continue
        part=os.read(owner.process.stderr.fileno(),4097-len(raw))
        if not part or len(raw)+len(part)>4096:_fail('invalid_role')
        raw.extend(part)
    if not raw.startswith(b'LIVE-SOCKET-OBS '):_fail('invalid_role')
    value=_decode(bytes(raw[len(b'LIVE-SOCKET-OBS '):-1]),4096)
    _LIVE_SOCKET_ROWS.append({'readiness':owner.ready,'observation':value})
    if os.getpid()!=_LIVE_SOCKET_HOST_PID and os.write(2,raw)!=len(raw):_fail('unavailable')
    return owner
'''

_SOCKET_COMMON_SOURCE = r'''
_LIVE_SOCKET_CASE=__CASE__


def _live_probe_target(scope):
    variant=_LIVE_SOCKET_CASE['boundary_variant']
    if variant=='forbidden_destination_ssh_endpoint':return scope['ssh']['target'],scope['ssh']['port']
    if variant=='forbidden_destination_wrong_target':return '10.255.255.254',scope['http']['port']
    if variant=='forbidden_destination_wrong_port':return scope['http']['target'],scope['http']['port']+1
    return scope['http']['target'],scope['http']['port']


def _live_socket_attempt(scope):
    target=_live_probe_target(scope);variant=_LIVE_SOCKET_CASE['boundary_variant']
    operation=variant.rsplit('_',1)[-1] if variant.startswith('endpoint_denies_') else 'connect'
    stream=socket.socket(socket.AF_INET,socket.SOCK_STREAM);stream.settimeout(.1)
    flags=0 if operation=='connect' else 0x20000000
    try:
        try:
            if operation=='connect':stream.connect(target);result=0
            elif operation=='sendto':result=stream.sendto(b'x',flags,target)
            elif operation=='sendmsg':result=stream.sendmsg([b'x'],[],flags,target)
            else:result=_sendmmsg_fastopen(stream,target)
            error=0
        except TimeoutError:result=-1;error=errno.ETIMEDOUT
        except OSError as exc:result=-1;error=exc.errno
        return {'operation':operation,'family':socket.AF_INET,'socket_type':socket.SOCK_STREAM,'protocol':0,
                'target':target[0],'port':target[1],'flags':flags,'return_value':result,'errno':error}
    finally:stream.close()


def _live_socket_probe(scope):
    channel=socket.socket(fileno=0)
    try:
        if not select.select([channel],[],[],2)[0] or channel.recv(65)!=b'LIVE-SOCKET-PROBE':runtime._fail('invalid_input')
        raw=b'LIVE-SOCKET-OBS '+runtime._json(_live_socket_attempt(scope))+b'\n'
        if len(raw)>4096 or os.write(2,raw)!=len(raw):runtime._fail('limit_exceeded')
    finally:channel.detach()
'''

_SOCKET_ENDPOINT_SOURCE = r'''
_LIVE_SOCKET_LISTENER=None
_LIVE_SOCKET_CONTROL=None


def _live_listener_control(scope,listener=None):
    global _LIVE_SOCKET_LISTENER,_LIVE_SOCKET_CONTROL
    target=_live_probe_target(scope)
    if listener is None:
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.bind(target);listener.listen(1)
    peer=socket.socket(socket.AF_INET,socket.SOCK_STREAM);peer.settimeout(.1)
    accepted=None
    try:
        peer.connect(target)
        listener.settimeout(.1);accepted,_=listener.accept();accepted.settimeout(.1)
        if peer.send(b'P')!=1 or accepted.recv(2)!=b'P':runtime._fail('invalid_role')
        _LIVE_SOCKET_CONTROL={'paired_control_connected':True,'target':target[0],'port':target[1]}
    finally:
        peer.close()
        if accepted is not None:accepted.close()
    listener.setblocking(False);_LIVE_SOCKET_LISTENER=listener


def _live_listener_collect(channel,listener):
    global _LIVE_SOCKET_LISTENER
    raw=channel.recv(65)
    if raw!=b'LIVE-SOCKET-COLLECT':runtime._fail('invalid_input')
    selected=_LIVE_SOCKET_LISTENER
    if selected is None or _LIVE_SOCKET_CONTROL is None:runtime._fail('invalid_role')
    accepts=0;payload=0
    while accepts<4:
        try:peer,_=selected.accept()
        except BlockingIOError:break
        try:
            accepts+=1;peer.setblocking(False)
            try:payload+=len(peer.recv(257))
            except BlockingIOError:pass
        finally:peer.close()
    result={**_LIVE_SOCKET_CONTROL,'listener_accepts':accepts,'listener_payload_bytes':payload}
    raw=b'LIVE-LISTENER-OBS '+runtime._json(result)+b'\n'
    if len(raw)>4096 or os.write(2,raw)!=len(raw):runtime._fail('limit_exceeded')
    if selected is not listener:selected.close()
    _LIVE_SOCKET_LISTENER=None
'''


def _socket_case(value):
    if type(value)is str:
        if value in RUNTIME_CASES:return RUNTIME_CASES[value]
        identifier=value
    else:identifier=value.get('id',value.get('case_id'))
    mapping={'S42C-N08':'S42C-X26','S42C-N09':'S42C-X27','S42C-N15':'S42C-X28'}
    wanted=mapping.get(identifier,identifier)
    match=next((row for row in RUNTIME_CASES.values() if row['case_id']==wanted),None)
    if match is None or match['kind']!='socket_denial':raise ValueError('fixed_socket_case')
    return match


def supporting_socket_source(variants,case):
    """Install the one fixed owned listener plus actual sealed caller probe."""
    selected=_socket_case(case)
    config={**selected,'boundary_variant':selected['variant'],'probe_role':'endpoint' if selected['role']=='endpoint' else 'nmap'}
    common=_SOCKET_COMMON_SOURCE.replace('__CASE__',repr(config))
    endpoint=selected['role']=='endpoint'
    def endpoint_source(text):
        marker="\ndef main():\n"
        if text.count(marker)!=1:raise AssertionError('fixed endpoint source')
        text=text.replace(marker,'\n'+common+_SOCKET_ENDPOINT_SOURCE+marker)
        if endpoint:
            line="    listener=prepare_network(payload['scope'],bootstrap['deadline_ns'])"
            text=text.replace(line,line+"\n    _live_listener_control(payload['scope'],listener)")
            text=text.replace('    runtime._emit_ready(ready)\n','    runtime._emit_ready(ready)\n    _live_socket_probe(payload[\'scope\'])\n')
        else:
            line="        send(20,struct.pack('=BBBBI',socket.AF_INET,32,0,0,index)+attribute(1,packed)+attribute(2,packed),2,True)"
            if text.count(line)!=1:raise AssertionError('fixed owned-address setup')
            text=text.replace(line,line+"\n        probe_target=_live_probe_target(scope)[0]\n        if probe_target!=scope['http']['target']:\n            probe=socket.inet_aton(probe_target)\n            send(20,struct.pack('=BBBBI',socket.AF_INET,32,0,0,index)+attribute(1,probe)+attribute(2,probe),3,True)")
            text=text.replace("    target=scope['http']['target'];port=scope['http']['port']", "    _live_listener_control(scope)\n    target=scope['http']['target'];port=scope['http']['port']")
        text=text.replace("    outgoing={'broker':0,'arm':0};incoming={'broker':0,'arm':0}", "    test_host=socket.socket(fileno=0)\n    outgoing={'broker':0,'arm':0};incoming={'broker':0,'arm':0}")
        text=text.replace('            reads=[broker,arm]','            reads=[broker,arm,test_host]')
        text=text.replace('            # Broker cancellation always wins', "            if test_host in readable:_live_listener_collect(test_host,listener)\n            # Broker cancellation always wins")
        text=text.replace('        broker.close();arm.close()','        test_host.detach()\n        if _LIVE_SOCKET_LISTENER is not None and _LIVE_SOCKET_LISTENER is not listener:_LIVE_SOCKET_LISTENER.close()\n        broker.close();arm.close()')
        return text
    variants.source('engagement_live_endpoint_worker',endpoint_source)
    if not endpoint:
        def client_source(text):
            marker='\ndef main():\n'
            if text.count(marker)!=1:raise AssertionError('fixed client source')
            return text.replace(marker,'\n'+common+marker).replace('    runtime._emit_ready(ready)\n','    runtime._emit_ready(ready)\n    _live_socket_probe(scope)\n')
        variants.source('engagement_live_client_worker',client_source)
    addition=_SOCKET_RUNTIME_SOURCE.replace('__CASE__',repr(config)).replace('__HOST_PID__',str(os.getpid()))
    variants.source('engagement_live_runtime',lambda text:_namespace_probe_source(text)+addition)
    variants._host_runtime=True
    return selected


def _read_test_observation(process,prefix,control,*,maximum=4096,stderr_fd=None):
    raw=bytearray();stream=process.stderr if stderr_fd is None else stderr_fd
    while not raw.endswith(b'\n'):
        control.check()
        if not select.select([stream],[],[],min(.01,control.remaining()))[0]:continue
        part=os.read(stream.fileno() if stderr_fd is None else stderr_fd,maximum+1-len(raw))
        if not part or len(raw)+len(part)>maximum:raise AssertionError('bounded actual probe observation')
        raw.extend(part)
    if not raw.startswith(prefix):raise AssertionError('fixed probe frame')
    return json.loads(raw[len(prefix):-1])


def supporting_socket_case(service,prepared,case,directory):
    """Collect the actual same-listener paired control and confined refusal.

    Preparation already created the real waiting client. This function does not
    create a grant, release, native process or separate counted physical case.
    """
    selected=_socket_case(case);started=time.monotonic_ns()
    row=service._sessions[prepared['envelope']['session_id']]
    endpoint=row['endpoint'].owner
    if selected['role']=='endpoint':
        actual=runtime._LIVE_SOCKET_ROWS
        if len(actual)!=1:raise AssertionError('one actual endpoint syscall probe')
        raw=deepcopy(actual[0]['observation']);control=deepcopy(actual[0]['readiness'])
    else:
        # A08 keeps stderr and actual process custody with the trusted host.
        # The sealed launcher alone sent the fixed probe on its inherited peer.
        child=row['launcher']._supervisor.children['identify_client']['owner']
        if child is None or child.ready is None:raise AssertionError('actual selected waiting child')
        raw=_read_test_observation(child.process,b'LIVE-SOCKET-OBS ',service._control)
        control=deepcopy(child.ready)
        did=prepared['envelope']['dispatch_id']
        controls=[item['data']['frame']['body']['data'] for item in _live_rows(service)
            if item['dispatch_id']==did and item['kind']=='protocol'
            and item['data']['direction']=='received' and item['data']['channel_role']=='launcher'
            and item['data']['frame']['operation']=='OBSERVATION'
            and item['data']['frame']['body']['kind']=='role_readiness'
            and item['data']['frame']['body']['data']['role']=='nmap']
        if len(controls)!=1 or controls[0]!=control:raise AssertionError('direct host observation and exact launcher relay')
    runtime._send_bytes(endpoint.channel,b'LIVE-SOCKET-COLLECT',service._control)
    listener=_read_test_observation(endpoint.process,b'LIVE-LISTENER-OBS ',service._control)
    if (raw['target'],raw['port'])!=(listener['target'],listener['port']):raise AssertionError('same actual paired listener')
    raw.update({name:listener[name] for name in ('paired_control_connected','listener_accepts','listener_payload_bytes')})
    from recon_cockpit.secure_agent.engagement_live_context import validate_boundary_observation
    validate_boundary_observation('socket_denial',raw)
    sources={item['module']:item['sha256'] for item in service._runtime['sources']}
    module='engagement_live_endpoint_worker' if selected['role']=='endpoint' else 'engagement_live_client_worker'
    proof={'schema_version':'1','case_id':selected['case_id'],'role':selected['role'],'kind':'socket_denial',
        'runtime_sha256':runtime.runtime_digest(service._runtime),'source_sha256':sources[module],
        'observation_sha256':sha(canonical(raw)),'control_observation_sha256':sha(canonical(control)),
        'started_at_ns':started,'finished_at_ns':time.monotonic_ns(),'checks':{selected['variant']:True}}
    return proof,{'kind':'socket_denial','observation':raw}


def _socket_runtime_case(case,directory):
    variants=SourceVariants(directory/'sources',case_id=case['case_id'],variant=case['variant'],role=case['role'])
    supporting_socket_source(variants,case)
    with variants,terminal_input():
        with native_session(directory/'trial',source_variants=variants) as service:
            opened=service.open_session();prepared=service.prepare(opened['binding']['session_id'],'http_identify')
            proof,observation=supporting_socket_case(service,prepared,case,directory)
        manifest,members=service._evidence_payload(case_id=case['case_id'],instrumentation=variants.instrumentation,
            boundary_proofs=[proof],boundary_observations=[observation],recover=True)
    return _write_case_payload(directory,(manifest,members,time.monotonic()+15))


_EOF_ACTION_SOURCE=r'''
_LIVE_EOF_PAUSED=False
_LIVE_EOF_BROKER=None


def _live_eof_pause(meter):
    global _LIVE_EOF_PAUSED
    if _LIVE_EOF_PAUSED:return
    _LIVE_EOF_PAUSED=True
    observation={'dispatch_id':meter.envelope['dispatch_id'],'envelope_sha256':contract.envelope_digest(meter.envelope),
                 'received_request_bytes':len(meter.requests),'request_sha256':hashlib.sha256(meter.requests).hexdigest(),
                 'observed_at_ns':time.monotonic_ns()}
    raw=b'LIVE-EOF-ACTIVE '+runtime._json(observation)+b'\n'
    if len(raw)>4096 or os.write(2,raw)!=len(raw):runtime._fail('limit_exceeded')
    while True:
        meter.check()
        if select.select([0,_LIVE_EOF_BROKER],[],[],.01)[0]:runtime._fail('cancelled')
'''


def _eof_action_source(variants):
    def transform(text):
        marker='\ndef main():\n'
        line="        self._event('recv',requested=left,actual=len(raw),before=left)"
        if text.count(marker)!=1 or text.count(line)!=1:raise AssertionError('fixed active receive boundary')
        text=text.replace(marker,'\n'+_EOF_ACTION_SOURCE+marker)
        text=text.replace(line,line+'\n        _live_eof_pause(self)')
        text=text.replace('    # Ordinary channel identity and sequence derive solely','    global _LIVE_EOF_BROKER\n    # Ordinary channel identity and sequence derive solely')
        text=text.replace('    broker.setblocking(False);arm.setblocking(False)','    broker.setblocking(False);arm.setblocking(False)\n    _LIVE_EOF_BROKER=broker')
        return text
    variants.source('engagement_live_endpoint_worker',transform)


def _wait_lifecycle_capture(service,prepared,pending):
    """Observe the real in-flight CAPTURE before applying this fixed fault."""
    env=prepared['envelope'];digest=contract.prepared_digest(prepared)
    limit=min(env[k] for k in ('action_deadline_ns','session_deadline_ns','broker_deadline_ns'))-contract.CLEANUP_NS
    while time.monotonic_ns()<limit:
        service._control.check()
        rows=[row for row in service._host_evidence_budget.snapshot()['rows']
            if row['kind']=='supervision_projection' and row['dispatch_id']==env['dispatch_id']
            and row['data']['kind']=='rpc' and row['data']['request']['operation']=='CAPTURE']
        if rows:
            if len(rows)!=1:raise AssertionError('one actual pending CAPTURE')
            row=rows[0];data=row['data']
            if (data['prepared_sha256']!=digest or data['reply'] is not None or data['local_error'] is not None
                    or any(row[k]!=env[k]for k in ('broker_id','session_id','dispatch_id'))):
                raise AssertionError('actual CAPTURE still in flight')
            return row
        if pending.done():raise AssertionError('action ended before pending CAPTURE')
        time.sleep(min(.005,max(0,(limit-time.monotonic_ns())/contract.SECOND)))
    raise TimeoutError('original pending CAPTURE boundary')


def _lifecycle_stop_observed(service,prepared,owner,pending,variant):
    """No explicit close can stand for the EOF detector under test."""
    import socket
    _wait_lifecycle_capture(service,prepared,pending)
    if pending.done() or service._stop.is_set() or service._cleanup_epoch.snapshot() is not None:
        raise AssertionError('live unfenced action before lifecycle stimulus')
    terminal_ticket=_phase_ticket(service)
    cleanup=None;env=prepared['envelope']
    hard=min(env[k]for k in ('action_deadline_ns','session_deadline_ns','broker_deadline_ns'))
    try:
        begin=_phase_observation(service,prepared,'client','begin',clock=contract.sample_clock())
        triggered=begin['observed_at_ns'];hard=min(hard,triggered+contract.CLEANUP_NS)
        if variant=='actual_payload_and_wrapper_reaped':
            service._cleanup_epoch.stop(bound_deadline_ns=hard)
            cleanup=service.close()
        else:
            owner.channel.shutdown(socket.SHUT_RDWR)
            # Same original two-second budget; reserve 1900ms for cleanup.
            detect=min(triggered+100000000,hard-1900000000)
            while not (service._stop.is_set() and service._cleanup_epoch.snapshot() is not None):
                # Ingress EOF may finish execute before the separate monitor
                # publishes its stop fence. Observe that fence under the same
                # original detector budget; a failed future is not its proof.
                if time.monotonic_ns()>=detect:
                    raise AssertionError('autonomous EOF stop not observed before cleanup reserve')
                time.sleep(min(.001,max(0,(detect-time.monotonic_ns())/contract.SECOND)))
            if time.monotonic_ns()>=detect:
                raise AssertionError('autonomous EOF stop not observed before cleanup reserve')
        _phase_observation(service,prepared,'client','end',clock=contract.sample_clock(),ticket=terminal_ticket)
        terminal_ticket=None
    finally:
        if terminal_ticket is not None:service._host_evidence_budget.release(terminal_ticket)
        service._cleanup_epoch.stop(bound_deadline_ns=hard)
        if cleanup is None:cleanup=service.close()
    try:pending.result(timeout=max(0,(hard-time.monotonic_ns())/contract.SECOND))
    except contract.LiveError:pass
    else:raise AssertionError('terminal lifecycle fault must not settle the action')
    if (not pending.done() or cleanup['status']!='complete' or cleanup['finished_at_ns']>hard
            or cleanup['finished_at_ns']-triggered>contract.CLEANUP_NS):
        raise AssertionError('one original physical cleanup budget')
    return triggered,cleanup


def _lifecycle_runtime_case(case,directory):
    import socket
    from concurrent.futures import ThreadPoolExecutor
    variants=SourceVariants(directory/'sources',case_id=case['case_id'],variant=case['variant'],role=case['role'])
    _eof_action_source(variants)
    with variants,terminal_input():
        with native_session(directory/'trial',source_variants=variants) as service:
            opened=service.open_session();sid=opened['binding']['session_id']
            prepared=service.prepare(sid,'http_identify');reference=review_actual(service,prepared)
            session=service._sessions[sid]
            owner=service._broker._owner if case['role']=='broker' else session['endpoint'].owner if case['role']=='endpoint' else session['launcher']._owner
            control=deepcopy(owner.ready);pool=ThreadPoolExecutor(max_workers=1)
            pending=pool.submit(service.execute,prepared,reference,control=service._control)
            try:
                active=_read_test_observation(session['endpoint'].owner.process,b'LIVE-EOF-ACTIVE ',service._control)
                if active['dispatch_id']!=prepared['envelope']['dispatch_id'] or active['envelope_sha256']!=contract.envelope_digest(prepared['envelope']) or not 0<active['received_request_bytes']<=4096:raise AssertionError('actual admitted request before EOF')
                private_write(directory/'lifecycle-active.json',canonical(active))
                triggered,cleanup=_lifecycle_stop_observed(service,prepared,owner,pending,case['variant'])
            finally:pool.shutdown(wait=False,cancel_futures=True)
        final=max(service._cleanup_receipts,key=lambda value:value['finished_at_ns'])
        origin={'role_EOF_broker':'broker_eof','role_EOF_endpoint':'endpoint_eof',
                'role_EOF_launcher':'launcher_eof','actual_payload_and_wrapper_reaped':'payload_and_wrapper_cleanup'}[case['variant']]
        raw={'origin':origin,'triggered_at_ns':triggered,'cleanup_sha256':sha(canonical(final)),
             'meter_transcript_sha256':None,'last_ack_sha256':sha(canonical(active)),
             'cleanup_finished_at_ns':final['finished_at_ns']}
        proof={'schema_version':'1','case_id':case['case_id'],'role':case['role'],'kind':case['kind'],
            'runtime_sha256':runtime.runtime_digest(service._runtime),'source_sha256':variants.records[0]['after_sha256'],
            'observation_sha256':sha(canonical(raw)),'control_observation_sha256':sha(canonical(control)),
            'started_at_ns':triggered,'finished_at_ns':cleanup['finished_at_ns'],'checks':{case['variant']:True}}
        host=_core_instrumentation({'id':case['case_id'],'variant':case['variant']})
        manifest,members=service._evidence_payload(case_id=case['case_id'],instrumentation=[*variants.instrumentation,host],
            boundary_proofs=[proof],boundary_observations=[{'kind':case['kind'],'observation':raw}],recover=True)
    return _write_case_payload(directory,(manifest,members,time.monotonic()+15))


def _run_runtime_case(variant,directory):
    case=RUNTIME_CASES.get(variant)
    if case is None:raise ValueError('fixed_runtime_case')
    directory=Path(directory)
    if case['kind'] in ('pin_mutation','descriptor_custody'):return _startup_runtime_case(case,directory)
    if case['kind'] in ('creation_denial','parser_absence'):return _kernel_runtime_case(case,directory)
    if case['kind']=='socket_denial':return _socket_runtime_case(case,directory)
    if case['kind']=='lifecycle':return _lifecycle_runtime_case(case,directory)
    if case['kind']=='image_identity':return _image_runtime_case(case,directory)
    if case['kind'] in ('meter_boundary','clock_boundary'):return _meter_runtime_case(case,directory)
    raise AssertionError('fixed physical runtime case is not implemented: '+case['case_id'])


_IMAGE_PROBE_SOURCE = r'''
_LIVE_IMAGE_CASE=__CASE__
_LIVE_IMAGE_ARMED=False
_LIVE_IMAGE_LAST=None
_LIVE_IMAGE_NATIVE=None
_live_image_read=_image
_live_image_observe_native=observe_native


def _image(directory,path,destination):
    global _LIVE_IMAGE_LAST
    value=_live_image_read(directory,path,destination)
    if _LIVE_IMAGE_ARMED and path=='exe':
        observed=dict(value);observed['sha256']=('1' if value['sha256'][0]=='0' else '0')+value['sha256'][1:]
        _LIVE_IMAGE_LAST={'expected_image_sha256':value['sha256'],'observed_image_sha256':observed['sha256']}
        return observed
    return value


def _live_parent_image_refusal(owner,bundle):
    global _LIVE_IMAGE_ARMED
    manifest=next(row for row in bundle['roles'] if row['role']==owner.ready['role'])
    _LIVE_IMAGE_ARMED=True
    try:
        _process_observation(owner.pin,manifest,owner.bootstrap['observer'],owner.ready['parent_observation']['namespaces']['net'])
    finally:_LIVE_IMAGE_ARMED=False


def observe_native(pin,manifest,*,waiting_image,control):
    global _LIVE_IMAGE_ARMED,_LIVE_IMAGE_NATIVE
    observed=_live_image_observe_native(pin,manifest,waiting_image=waiting_image,control=control)
    if _LIVE_IMAGE_CASE['variant']=='native_image_observation_missing_no_ARM':
        value={'expected_image_sha256':observed['parent_observation']['executable']['sha256'],
               'observed_image_sha256':observed['parent_observation']['executable']['sha256']}
    else:
        _LIVE_IMAGE_ARMED=True
        try:_process_observation(pin,manifest,pin.receipt['observer'],pin.receipt['namespaces']['net'],stage='native')
        except Exception:value=dict(_LIVE_IMAGE_LAST)
        else:_fail('invalid_role')
        finally:_LIVE_IMAGE_ARMED=False
    _LIVE_IMAGE_NATIVE={'image':value,'native':observed}
    if len(_json(_LIVE_IMAGE_NATIVE))>16384:_fail('limit_exceeded')
    _fail('invalid_runtime')
'''


def _image_runtime_case(case,directory):
    variants=SourceVariants(directory/'sources',case_id=case['case_id'],variant=case['variant'],role=case['role'])
    variants.source('engagement_live_runtime',lambda text:_namespace_probe_source(text)+_IMAGE_PROBE_SOURCE.replace('__CASE__',repr(case)))
    variants._host_runtime=True;started=time.monotonic_ns();native=None
    native_case=case['case_id'] in ('S42C-X40','S42C-X44')
    with variants,terminal_input():
        with native_session(directory/'trial',source_variants=variants) as service:
            if native_case:
                opened=service.open_session();prepared=service.prepare(opened['binding']['session_id'],'http_identify')
                reference=review_actual(service,prepared)
                try:service.execute(prepared,reference,control=service._control)
                except contract.LiveError:pass
                else:raise AssertionError('native image failure must refuse dispatch')
                observed=deepcopy(variants.runtime_globals['_LIVE_IMAGE_NATIVE'])
                if observed is None:raise AssertionError('actual host native readback required')
                private_write(directory/'native-image-observation.json',canonical(observed))
                native=observed['native'];image=observed['image']
                did=prepared['envelope']['dispatch_id']
            else:
                owner=_exercise_runtime_role(service,case);control=deepcopy(owner.ready)
                try:runtime._live_parent_image_refusal(owner,service._runtime)
                except contract.LiveError:pass
                else:raise AssertionError('actual parent readback mutation did not refuse')
                image=deepcopy(variants.runtime_globals['_LIVE_IMAGE_LAST'])
        if native_case:
            from recon_cockpit.secure_agent.engagement_live_witness import validate_transcript_row
            with contract._deadline_context(service._control.deadline):
                saved=service._broker.close_evidence(deadline=service._control.deadline)
                transcript=saved['transcript']
                if (transcript is None or transcript['status']!='sealed_complete' or transcript['seals']!=15
                        or not transcript['raw'].endswith(b'\n')):
                    raise AssertionError('actual sealed image-refusal transcript required')
                rows=[]
                for line in transcript['raw'].split(b'\n')[:-1]:
                    contract._check_deadline(service._control.deadline)
                    rows.append(validate_transcript_row(contract.decode(line)))
                controls=[row['data']['frame']['body']['data'] for row in rows
                    if row['kind']=='protocol' and row['dispatch_id']==did and row['data']['direction']=='received'
                    and row['data']['frame']['operation']=='OBSERVATION' and row['data']['frame']['body']['kind']=='role_readiness'
                    and row['data']['frame']['body']['data']['role']=='nmap']
                if len(controls)!=1:raise AssertionError('same actual waiting native control')
                control=controls[0]
                if any(row['kind']=='protocol' and row['dispatch_id']==did and row['data']['frame']['operation']=='NATIVE_OBSERVED' for row in rows):
                    raise AssertionError('failed observation must not publish readiness')
        raw={**image,'waiting_observation_sha256':sha(canonical(control)),
             'native_observation_sha256':None if native is None or case['case_id']=='S42C-X44' else sha(canonical(native)),
             'arm_emitted':False,'refused':True}
        proof={'schema_version':'1','case_id':case['case_id'],'role':case['role'],'kind':case['kind'],
            'runtime_sha256':runtime.runtime_digest(service._runtime),'source_sha256':variants.records[0]['after_sha256'],
            'observation_sha256':sha(canonical(raw)),'control_observation_sha256':sha(canonical(control)),
            'started_at_ns':started,'finished_at_ns':time.monotonic_ns(),'checks':{case['variant']:True}}
        manifest,members=service._evidence_payload(case_id=case['case_id'],instrumentation=variants.instrumentation,
            boundary_proofs=[proof],boundary_observations=[{'kind':case['kind'],'observation':raw}],recover=True)
        if native is not None:
            processes=json.loads(members['processes.json']);processes['native'].append(native)
            members['processes.json']=canonical(processes)
            manifest['members']=[{'name':name,'bytes':len(data),'sha256':sha(data)} for name,data in sorted(members.items())]
    return _write_case_payload(directory,(manifest,members,time.monotonic()+15))


_METER_PRIMITIVE_SOURCE = r'''
_LIVE_METER_CASE=__CASE__
_LIVE_METER_LISTENER=None
_LIVE_METER_PEERS=[]
_LIVE_METER_SENT=False
_LIVE_BYTE_ACTIVE=False


def _live_prepare_meter_peers(endpoint_id):
    global _LIVE_METER_LISTENER
    if _LIVE_METER_CASE.get('metric')!='connections':return
    # This fixed primitive fixture is separate from native-valid HTTP traffic.
    # Unix stream endpoints are created before the normal role seal, in this
    # endpoint's private network namespace, and never supplied after bootstrap.
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    server.bind('\x00recon-live-meter-'+endpoint_id);server.listen(4);server.setblocking(False)
    count=(4 if _LIVE_METER_CASE['slot']=='http_identify' else 2) if 'connection_cap' in _LIVE_METER_CASE['variant'] else 2 if _LIVE_METER_CASE['slot']=='http_identify' else 1
    for _ in range(count):
        peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.settimeout(.1)
        peer.connect('\x00recon-live-meter-'+endpoint_id);peer.setblocking(False);_LIVE_METER_PEERS.append(peer)
    _LIVE_METER_LISTENER=server


class _LiveShortSocket:
    def __init__(self,stream,*,read=None,write=None):self.stream=stream;self.read=read;self.write=write
    def recv(self,maximum):
        size=maximum if self.read is None else min(maximum,self.read)
        self.read=None
        return self.stream.recv(size)
    def send(self,raw):
        selected=raw if self.write is None else raw[:self.write]
        self.write=None
        return self.stream.send(selected)


def _live_meter_clock(meter,stimulus):
    anchor=meter.envelope['clock_anchor'];now=contract.sample_clock()
    if stimulus=='deadline_after_partial':
        mono=meter.envelope['action_deadline_ns']
        return {'utc_ns':anchor['utc_ns']+mono-anchor['mono_after_ns'],'mono_before_ns':mono,'mono_after_ns':mono}
    return {**now,'utc_ns':meter.envelope['window_end_utc_ns']}


def _live_drive_meter(meter):
    global _LIVE_BYTE_ACTIVE
    variant=_LIVE_METER_CASE['variant'];metric=_LIVE_METER_CASE.get('metric')
    streams=[];refused=False;trigger=None;before=None;host=None
    clock=contract.sample_clock
    try:
        stimulus_bytes=0
        if metric=='connections':
            server=_LIVE_METER_LISTENER
            for index in range(meter.max_connections):
                meter.check()
                meter.admit();stream,_=server.accept();stream.setblocking(False);streams.append(stream);stream.close()
            stimulus_bytes=meter.max_connections+1
            if not select.select([server],[],[],.1)[0]:runtime._fail('invalid_role')
            try:meter.admit()
            except contract.LiveError:refused=True
        else:
            # One actual inherited socket peer is admitted for the byte-only
            # primitive. This fixture does not claim native HTTP TCP grammar.
            host=socket.socket(fileno=0);host.setblocking(False);meter.admit();_LIVE_BYTE_ACTIVE=True
            if metric=='request':meter.expected=b'x'*(meter.request_limit+1)
            if metric=='response':meter.reply=b'x'*(meter.response_limit+1)
            stimulus_bytes=len(meter.expected) if metric in ('request','partial_request') else len(meter.reply)
            adapter=_LiveShortSocket(host,read=7 if metric=='partial_request' else None,
                                     write=7 if metric=='partial_response' or variant.endswith('after_partial') else None)
            stimulus=_LIVE_METER_CASE.get('stimulus')
            if stimulus=='forward_before_recv':
                trigger=time.monotonic_ns();before=(meter.connections,len(meter.responses))
                sampled=_live_meter_clock(meter,stimulus);contract.sample_clock=lambda:dict(sampled)
            try:
                while True:
                    response=meter.receive(adapter)
                    if response is not None:break
                    meter.check()
                    if not select.select([host],[],[],.1)[0]:runtime._fail('invalid_role')
                if stimulus=='forward_before_send':
                    trigger=time.monotonic_ns();before=(meter.connections,len(meter.responses))
                    sampled=_live_meter_clock(meter,stimulus);contract.sample_clock=lambda:dict(sampled)
                while True:
                    complete=meter.send(adapter)
                    if complete:break
                    if stimulus=='deadline_after_partial' and trigger is None:
                        trigger=time.monotonic_ns();before=(meter.connections,len(meter.responses))
                        sampled=_live_meter_clock(meter,stimulus);contract.sample_clock=lambda:dict(sampled)
            except contract.LiveError as error:
                refused=True
                if meter.reason is None:
                    reason={'engagement_live_window_closed':'window_closed','engagement_live_clock_changed':'clock_invalid','engagement_live_timeout':'timeout'}.get(error.code,'unresolved')
                    meter.stop(reason)
        if meter.reason is None:runtime._fail('invalid_role')
        actual=meter.snapshot()
        if _LIVE_METER_CASE['kind']=='clock_boundary':
            if trigger is None or before is None:runtime._fail('invalid_role')
            raw={'stimulus':_LIVE_METER_CASE['stimulus'],'triggered_at_ns':trigger,
                'meter_transcript_sha256':runtime._hash(actual),'accepted_before':before[0],
                'accepted_after':meter.connections,'sent_before':before[1],
                'sent_after':len(meter.responses),'refused':refused}
        else:
            raw={'slot':meter.slot,'metric':metric,'stimulus_bytes':stimulus_bytes,
                'meter_transcript_sha256':runtime._hash(actual),'input_sha256':actual['request_sha256'],
                'output_sha256':actual['response_sha256'],'delivery_known':actual['delivery_known'],'refused':refused}
        encoded=b'LIVE-METER-OBS '+runtime._json(raw)+b'\n'
        if len(encoded)>4096 or os.write(2,encoded)!=len(encoded):runtime._fail('limit_exceeded')
        return actual
    finally:
        contract.sample_clock=clock;_LIVE_BYTE_ACTIVE=False
        if host is not None:host.detach()
        for stream in streams:
            try:stream.close()
            except OSError:pass
        for peer in _LIVE_METER_PEERS:peer.close()
        if _LIVE_METER_LISTENER is not None:_LIVE_METER_LISTENER.close()
'''


def _meter_primitive_source(variants,case):
    slot='http_headers' if case['variant'].endswith('_headers') or case['kind']=='clock_boundary' or 'partial_' in case['variant'] else 'http_identify'
    selected={**case,'slot':slot,'source_sha256':'0'*64}
    if case['kind']=='clock_boundary':
        selected['stimulus']={'endpoint_clock_forward_before_recv':'forward_before_recv',
            'endpoint_clock_forward_before_send':'forward_before_send','endpoint_deadline_before_send_after_partial':'deadline_after_partial'}[case['variant']]
    else:
        selected['metric']='partial_request' if case['variant']=='meter_partial_request' else 'partial_response' if case['variant']=='meter_partial_response' else case['variant'].split('_')[1]
        if selected['metric']=='connection':selected['metric']='connections'
    addition=_METER_PRIMITIVE_SOURCE.replace('__CASE__',repr(selected))
    def transform(text):
        marker='\ndef main():\n'
        if text.count(marker)!=1:raise AssertionError('fixed primitive source boundary')
        text=text.replace(marker,'\n'+addition+marker)
        text=text.replace("if self.slot=='http_identify' and self.connections not in (2,3):", "if self.slot=='http_identify' and not _LIVE_BYTE_ACTIVE and self.connections not in (2,3):")
        line="    listener=prepare_network(payload['scope'],bootstrap['deadline_ns'])"
        text=text.replace(line,line+"\n    _live_prepare_meter_peers(payload['endpoint_id'])")
        text=text.replace('    # Ordinary channel identity and sequence derive solely', '    global _LIVE_METER_SENT\n    # Ordinary channel identity and sequence derive solely')
        line="                    'slot':meter.slot,'arm_sequence':1,'effective_lease_deadline_ns':release['effective_lease_deadline_ns'],'armed_at_ns':meter.armed_at})"
        if text.count(line)!=1:raise AssertionError('fixed real ARM boundary')
        text=text.replace(line,line+"\n                if meter.slot==_LIVE_METER_CASE['slot']:\n                    actual=_live_drive_meter(meter)\n                    send(broker,'broker','METER',actual);_LIVE_METER_SENT=True")
        text=text.replace("if meter is not None and meter.release is not None and meter.reason!='complete':", "if meter is not None and meter.release is not None and meter.reason!='complete' and not _LIVE_METER_SENT:")
        text=text.replace('        broker.close();arm.close()', '        for peer in _LIVE_METER_PEERS:peer.close()\n        if _LIVE_METER_LISTENER is not None:_LIVE_METER_LISTENER.close()\n        broker.close();arm.close()')
        return text
    variants.source('engagement_live_endpoint_worker',transform)
    if selected.get('metric')=='connections':
        fixture=runtime.SPEC['owned_meter_connection_fixture']['cases'][case['case_id']]
        steady=fixture['steady_descriptors'];peers=fixture['preconnected_peers']
        def fixture_runtime(text):return runtime._fixed_meter_runtime_source(text,case['case_id'])
        variants.source('engagement_live_runtime',fixture_runtime)
        variants._host_runtime=True
    return slot


def _drain_meter_peer(channel,directory,case,raw,deadline):
    """Retain actual nonblocking fixture output, including peer termination."""
    import errno
    output=bytearray();received=0;ending='quiescent';error_number=None;failure=None
    expected=None;checked=False;overflow=False
    try:
        if channel.getblocking():raise AssertionError('primitive peer must remain nonblocking')
        while True:
            if time.monotonic()>=deadline:raise AssertionError('primitive peer original deadline')
            if not select.select([channel],[],[],0)[0]:break
            try:data=channel.recv(4097-len(output))
            except ConnectionResetError as error:
                if error.errno!=errno.ECONNRESET:raise
                ending='reset';error_number=error.errno;break
            if not data:ending='eof';break
            received+=len(data);remaining=4096-len(output);output.extend(data[:remaining])
            if len(data)>remaining:
                overflow=True;raise AssertionError('primitive peer response cap')
        if time.monotonic()>=deadline:raise AssertionError('primitive peer original deadline')
        if case['kind']=='meter_boundary':
            expected=raw['output_sha256'];checked=True
            if sha(bytes(output))!=expected:raise AssertionError('actual received peer output matches meter')
        return bytes(output)
    except BaseException as error:
        failure=error
        if ending not in ('eof','reset'):ending='error';error_number=getattr(error,'errno',None)
        raise
    finally:
        # A failed drain retains its bounded prefix without replacing its cause.
        try:
            private_write(directory/'meter-peer-output.bin',bytes(output))
            private_write(directory/'meter-peer-drain.json',canonical({'acceptance':False,
                'termination':ending,'errno':error_number,'received_return_bytes':received,
                'retained_bytes':len(output),'retained_sha256':sha(bytes(output)),
                'output_overflow':overflow,'output_hash_checked':checked,
                'expected_output_sha256':expected,'error_type':None if failure is None else type(failure).__name__}))
        except BaseException as error:
            if failure is None:raise
            failure.meter_peer_retention_error=error


@contextmanager
def _meter_probe_custody(endpoint,control,*,with_peer):
    """Passive host copies of existing probe readers, never new worker rights."""
    stderr_fd=None;peer=None;failure=None
    def identity(fd):
        value=os.fstat(fd);return value.st_dev,value.st_ino,value.st_mode
    try:
        with contract._deadline_context(control.deadline):
            control.check()
            original=endpoint.process.stderr.fileno();expected=identity(original)
            if not stat.S_ISFIFO(expected[2]):raise AssertionError('actual meter stderr pipe')
            stderr_fd=os.dup(original)
            if (identity(stderr_fd)!=expected or endpoint.process.stderr.fileno()!=original
                    or identity(original)!=expected or os.get_inheritable(stderr_fd)
                    or os.get_blocking(stderr_fd)
                    or fcntl.fcntl(stderr_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY):
                raise AssertionError('fixed nonblocking meter stderr reader')
            if with_peer:
                original_peer=endpoint.channel.fileno();expected_peer=identity(original_peer)
                if not stat.S_ISSOCK(expected_peer[2]):raise AssertionError('actual meter peer socket')
                peer=endpoint.channel.dup()
                if (identity(peer.fileno())!=expected_peer or endpoint.channel.fileno()!=original_peer
                        or identity(original_peer)!=expected_peer or os.get_inheritable(peer.fileno())
                        or peer.getblocking() or os.get_blocking(peer.fileno())):
                    raise AssertionError('fixed nonblocking meter peer reader')
            control.check()
            yield stderr_fd,peer
            control.check()
    except BaseException as error:
        failure=error;raise
    finally:
        errors=[]
        if peer is not None:
            try:peer.close()
            except BaseException as error:errors.append(error)
        if stderr_fd is not None:
            try:os.close(stderr_fd)
            except BaseException as error:errors.append(error)
        if errors:
            if failure is not None:failure.meter_probe_custody_errors=errors
            else:raise errors[0]
        if failure is None:control.check()


def _meter_runtime_case(case,directory):
    variants=SourceVariants(directory/'sources',case_id=case['case_id'],variant=case['variant'],role=case['role'])
    slot=_meter_primitive_source(variants,case);began=time.monotonic_ns()
    with variants,terminal_input():
        with native_session(directory/'trial',source_variants=variants) as service:
            opened=service.open_session();sid=opened['binding']['session_id']
            if slot=='http_headers':_useful(service,opened,'http_identify')
            prepared=service.prepare(sid,slot);reference=review_actual(service,prepared)
            endpoint=service._sessions[sid]['endpoint'].owner;control=deepcopy(endpoint.ready)
            probe_control=runtime._ClippedControl(service._control,prepared['envelope']['action_deadline_ns']/contract.SECOND)
            with _meter_probe_custody(endpoint,probe_control,with_peer='connection_cap' not in case['variant']) as (stderr_fd,peer):
                if peer is not None:
                    from recon_cockpit.secure_agent.engagement_live_endpoint_worker import IDENTIFY_REQUEST,headers_request
                    request=IDENTIFY_REQUEST if slot=='http_identify' else headers_request(opened['scope'])
                    if 'request_cap' in case['variant']:
                        cap=4096 if slot=='http_identify' else 256;parts=[b'x'*cap,b'x']
                    elif case['variant']=='meter_partial_request':parts=[request[:7],request[7:]]
                    else:parts=[request]
                    for part in parts:runtime._send_bytes(endpoint.channel,part,service._control)
                    private_write(directory/'meter-peer-input.bin',b''.join(parts))
                try:service.execute(prepared,reference,control=service._control)
                except contract.LiveError:pass
                # Cleanup can close original wrappers before execute returns.
                # Retained copies only drain actual bytes, under the same stop
                # epoch when present; neither input nor work can be resumed.
                epoch=service._cleanup_epoch.snapshot()
                if epoch is not None:probe_control.deadline=min(probe_control.deadline,epoch['deadline_ns']/contract.SECOND)
                raw=_read_test_observation(endpoint.process,b'LIVE-METER-OBS ',probe_control,stderr_fd=stderr_fd)
                observation=canonical(raw)
                if len(observation)>4096:raise AssertionError('bounded actual meter observation')
                private_write(directory/'meter-observation.json',observation)
                if peer is not None:_drain_meter_peer(peer,directory,case,raw,probe_control.deadline)
                if case['kind']=='clock_boundary':raw['clock_source_sha256']=variants.records[0]['after_sha256']
        proof={'schema_version':'1','case_id':case['case_id'],'role':case['role'],'kind':case['kind'],
            'runtime_sha256':runtime.runtime_digest(service._runtime),'source_sha256':variants.records[0]['after_sha256'],
            'observation_sha256':sha(canonical(raw)),'control_observation_sha256':sha(canonical(control)),
            'started_at_ns':began,'finished_at_ns':time.monotonic_ns(),'checks':{case['variant']:True}}
        manifest,members=service._evidence_payload(case_id=case['case_id'],instrumentation=variants.instrumentation,
            boundary_proofs=[proof],boundary_observations=[{'kind':case['kind'],'observation':raw}],recover=True)
    return _write_case_payload(directory,(manifest,members,time.monotonic()+15))


# Fixed physical runtime dispatchers are defined below; root owns _run_core_case.

# ROOT CORE HARNESS: keep this fragment after the runtime dispatchers.
_terminal_master = None


@contextmanager
def terminal_input():
    """Owned PTY input to the unchanged isolated terminal reviewer."""
    from recon_cockpit.secure_agent import engagement_live_approval as approval
    import pty
    global _terminal_master
    if _terminal_master is not None:raise RuntimeError('nested terminal driver')
    master,slave=pty.openpty();original=approval.os
    class TerminalOS:
        def __getattr__(self,name):return getattr(original,name)
        def open(self,path,flags,*args,**kwargs):
            if path=='/dev/tty':
                fd=original.dup(slave);original.set_inheritable(fd,False)
                original.set_blocking(fd,False);return fd
            return original.open(path,flags,*args,**kwargs)
    os.set_blocking(master,False);approval.os=TerminalOS();_terminal_master=master
    try:yield master
    finally:
        approval.os=original;_terminal_master=None
        os.close(master);os.close(slave)


def review_actual(service,prepared,*,control=None,answer='approve'):
    """Script real input; the isolated reviewer alone issues the fresh grant."""
    from concurrent.futures import ThreadPoolExecutor
    import re
    import shutil
    if answer not in ('approve','deny'):raise ValueError('fixed_review_answer')
    control=service._control if control is None else control
    limit=min(control.deadline,prepared['envelope']['action_deadline_ns']/contract.SECOND)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending=pool.submit(service.review,prepared,control=control)
        if service._mode=='terminal':
            if _terminal_master is None:raise AssertionError('owned terminal context required')
            data=bytearray()
            while not pending.done():
                control.check()
                if time.monotonic()>=limit:break
                if select.select([_terminal_master],[],[],min(.02,max(0,limit-time.monotonic())))[0]:
                    part=os.read(_terminal_master,4096)
                    if not part:raise AssertionError('owned terminal EOF')
                    data.extend(part)
                    if len(data)>32768:raise AssertionError('review text bound')
                    match=re.search(rb"Type '([^'\r\n]+)' to approve once \(blank denies\): ",data)
                    if match:
                        response=match.group(1) if answer=='approve' else b''
                        written=os.write(_terminal_master,response+b'\n')
                        if written!=len(response)+1:raise AssertionError('review input short write')
                        break
        else:
            executable=shutil.which('xdotool')
            if executable is None:raise AssertionError('owned XTEST input required')
            def xinput(*args,check=True):
                control.check()
                return subprocess.run([executable,*map(str,args)],capture_output=True,text=True,
                    timeout=min(2,max(.001,limit-time.monotonic())),check=check)
            window=None
            while not pending.done() and time.monotonic()<limit:
                result=xinput('search','--onlyvisible','--name',r'^Recon Cockpit \| Review exact action$',check=False)
                if result.returncode==0 and result.stdout.strip():
                    identifiers=result.stdout.splitlines()
                    if len(identifiers)!=1:raise AssertionError('one owned review window required')
                    window=identifiers[0];break
                time.sleep(.02)
            if window is None:raise AssertionError('review window not observed')
            geometry=xinput('getwindowgeometry','--shell',window).stdout
            if 'WIDTH=900\n' not in geometry or 'HEIGHT=740\n' not in geometry:raise AssertionError('review geometry')
            xinput('windowfocus',window);time.sleep(.08)
            if answer=='approve':
                xinput('mousemove','--window',window,814,573,'click',1)
                xinput('key','ctrl+v')
                xinput('mousemove','--window',window,802,700,'click',1)
            else:xinput('mousemove','--window',window,686,700,'click',1)
        reference=pending.result(timeout=max(.001,limit-time.monotonic()+2))
    if bool(reference)!=(answer=='approve'):raise AssertionError('actual review decision')
    return reference


def _core_instrumentation(case,kind='scripted_review',role='host'):
    config={'case_id':case['id'],'variant':case['variant'],'role':role}
    return {'kind':kind,'configuration':config,'configuration_sha256':sha(canonical(config)),
            'source_sha256':sha(Path(__file__).read_bytes())}


def _phase_ticket(service):
    return service._host_evidence_budget.reserve(kind='other_host',maximum_bytes=2048,
        maximum_rows=1,control=service._control)


def _phase_observation(service,prepared,phase,stage,*,reason=None,related=None,clock=None,observer_id=None,ticket=None):
    """Retain the actual caller's phase; never impersonate a broker observation."""
    from recon_cockpit.secure_agent.engagement_live_witness import validate_transcript_row
    if ticket is None:ticket=_phase_ticket(service)
    e=prepared['envelope'] if prepared is not None else None
    ready=service._broker.readiness if service._broker is not None else None
    broker_id=ready['broker_id'] if ready is not None else service._broker._broker_id
    row={'schema_version':'1','broker_id':broker_id,'observer_id':observer_id or broker_id,
        'session_id':None if e is None else e['session_id'],'dispatch_id':None if e is None else e['dispatch_id'],
        'row_sequence':1,'observed_at_ns':time.monotonic_ns(),'kind':'phase','data':{
            'clock':clock,'original_deadline_ns':int(service._control.deadline*contract.SECOND) if e is None else e['action_deadline_ns'],
            'phase':phase,'reason':reason,'related_sha256':related if related is not None else
            None if prepared is None else contract.prepared_digest(prepared),'stage':stage}}
    validate_transcript_row(row);service._host_evidence_budget.finalize(ticket,row);return row


def _failure_code(error):
    code=getattr(error,'code',None)
    if code in contract.ERROR_CODES:return code
    from recon_cockpit.secure_agent.execution import ExecutionStopped
    return 'engagement_live_timeout' if isinstance(error,(TimeoutError,ExecutionStopped)) else 'engagement_live_unavailable'


def _expected_failure(service,prepared,phase,operation,*,related=None):
    from recon_cockpit.secure_agent.execution import ExecutionStopped
    _phase_observation(service,prepared,phase,'begin',related=related)
    terminal_ticket=_phase_ticket(service)
    try:value=operation()
    except (contract.LiveError,OSError,TimeoutError,ExecutionStopped) as error:
        _phase_observation(service,prepared,phase,'refused',related=related,reason=_failure_code(error),clock=contract.sample_clock(),ticket=terminal_ticket)
        return error
    if isinstance(value,dict) and value.get('outcome') in ('denied','unresolved'):
        _phase_observation(service,prepared,phase,'refused',related=related,reason=value['reason'],clock=contract.sample_clock(),ticket=terminal_ticket)
        return value
    raise AssertionError('expected actual refusal was not observed')


def _last_state(snapshot):return snapshot['events'][-1]['receipt']['state_sha256']


def _useful(service,session,slot,*,ingress=0):
    prepared=service.prepare(session['binding']['session_id'],slot,ingress=ingress)
    reference=review_actual(service,prepared)
    result=service.execute(prepared,reference,ingress=ingress,control=service._control)
    if result['outcome']!='useful':raise AssertionError('actual useful native result required')
    return prepared


@contextmanager
def _retain_payload_failure(service):
    """Associate retained owner facts without reopening or retrying anything."""
    try:
        yield
    except BaseException as error:
        attributes=BaseException.__getattribute__(error,'__dict__')
        if attributes.get('engagement_session') is None:
            attributes['engagement_session']=service
        raise


def _seal_case_payload(service,case,*,before,selected=None,instrumentation=(),recover=False,
                       boundary_proofs=(),boundary_observations=()):
    """Selectors name retained observations; they never supply a passing claim."""
    with _retain_payload_failure(service):
        limit=time.monotonic()+15
        manifest,members=service._evidence_payload(deadline=limit,case_id=case['id'],
            instrumentation=instrumentation,recover=recover,boundary_proofs=boundary_proofs,
            boundary_observations=boundary_observations)
        return _annotate_core_payload(manifest,members,case,before=before,selected=selected,deadline=limit)


def _annotate_core_payload(manifest,members,case,*,before,selected=None,deadline):
    from recon_cockpit.secure_agent import engagement_live_evidence as evidence
    result=json.loads(members['results.json']);operations=result['operations']
    histories=[json.loads(members[name]) for name in ('initial-ledger.json','final-ledger.json','recovery-ledger.json') if name in members]
    if not histories:raise AssertionError('actual durable state required')
    final=max(histories,key=lambda value:len(value['events']))
    before=_last_state(histories[0]) if before is None else before
    ids=[op['prepared']['envelope']['dispatch_id'] for op in operations]
    chosen=ids if selected is None else selected
    if chosen!=[did for did in ids if did in chosen]:raise AssertionError('selected manifest order')
    rows,_=evidence._transcript(manifest,members['transcript.jsonl'])
    references=[{'segment':row['segment'],'row_sequence':row['row']['row_sequence']} for row in rows
                if row['row']['kind'] in ('phase','capability_projection','watch') or
                row['row']['kind']=='protocol' and row['row']['data']['channel_role']=='ingress']
    if not references:raise AssertionError('actual selected transcript required')
    # Keep every phase/projection/ingress; watch polling only needs the actual
    # changed/refused observations. Never trim contradictory release evidence.
    if len(references)>128:
        references=[{'segment':row['segment'],'row_sequence':row['row']['row_sequence']} for row in rows
            if row['row']['kind'] in ('phase','capability_projection') or
            row['row']['kind']=='watch' and row['row']['data']['status']!='unchanged' or
            row['row']['kind']=='protocol' and row['row']['data']['channel_role']=='ingress']
    if len(references)>128:raise AssertionError('fixed core selector bound')
    result['core_proofs']=[{'schema_version':'1','case_id':case['id'],'variant':case['variant'],
        'dispatch_ids':chosen,'transcript_refs':references,'before_state_sha256':before,
        'after_state_sha256':_last_state(final),'recovery_state_sha256':
        _last_state(json.loads(members['recovery-ledger.json'])) if 'recovery-ledger.json' in members else None}]
    members['results.json']=canonical(result)
    manifest['members']=[{'name':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(members.items())]
    return manifest,members,deadline


def _write_case_payload(directory,payload):
    from recon_cockpit.secure_agent.engagement_live_evidence import write_live_bundle
    manifest,members,deadline=payload
    destination=Path(directory)/'bundle'
    write_live_bundle(destination,manifest=manifest,members=members,deadline=deadline)
    return destination


def _reject_candidate(service,prepared,variant):
    """Send the finite hostile body to the actual isolated reviewer decoder."""
    from recon_cockpit.secure_agent.engagement_live_evidence import _core_candidate
    row=service._sessions[prepared['envelope']['session_id']];reviewer=row['reviewer']
    candidate=_core_candidate(variant,prepared,row['opened']);digest=sha(canonical(candidate))
    _phase_observation(service,prepared,'prepare','begin',related=digest,
                       observer_id=reviewer._binding['reviewer_id'])
    terminal_ticket=_phase_ticket(service)
    # Deliberately bypass only the host encoder's validation. The real worker
    # receives the malformed packet on its existing private channel.
    with reviewer._lock:
        request=reviewer._sequence.make('REVIEW',prepared);request['body']=candidate
        raw=canonical(request)
        if len(raw)>32768:raise AssertionError('fixed malformed request bound')
        end=min(service._control.deadline,time.monotonic()+2)
        if not select.select([], [reviewer._channel], [], max(0,end-time.monotonic()))[1]:raise TimeoutError('reviewer input')
        if reviewer._channel.send(raw)!=len(raw):raise AssertionError('malformed packet short send')
        if not select.select([reviewer._channel],[],[],max(0,end-time.monotonic()))[0]:raise TimeoutError('reviewer refusal')
        received=reviewer._channel.recv(32769)
        if received:raise AssertionError('invalid Prepared unexpectedly received a reply')
        code=reviewer._owner.process.wait(timeout=max(.001,end-time.monotonic()))
        if code!=78:raise AssertionError('actual isolated decoder refusal required')
    _phase_observation(service,prepared,'prepare','refused',related=digest,
        reason='engagement_live_approval_unavailable',observer_id=reviewer._binding['reviewer_id'],ticket=terminal_ticket)


def _consume_actual(service,prepared,reference):
    from recon_cockpit.secure_agent.models import parse_action,parse_policy
    row=service._sessions[prepared['envelope']['session_id']]
    result=row['reviewer'].consume(reference,parse_action(prepared['action']),parse_policy(prepared['policy']),
        prepared['envelope'],control=service._control)
    if not result['accepted']:contract.fail('approval_unknown_or_replayed')
    return result


def _pointers_actual(service,prepared,reference):
    from recon_cockpit.secure_agent.engagement_live_witness import started_event
    consumed=_consume_actual(service,prepared,reference)
    receipt=service._audit.emit(started_event(prepared),control=service._control)
    return {'prepared_sha256':contract.prepared_digest(prepared),
        'reference_sha256':consumed['reference_sha256'],'consume_sequence':consumed['consume_sequence'],
        'audit_sequence':receipt['sequence']}


@contextmanager
def _observe_ingress(service,*,simultaneous=False):
    """Retain actual completed primitives before a later deadline can refuse."""
    from recon_cockpit.secure_agent import engagement_live_protocol as protocol
    import threading
    send,receive=protocol.send_packet,protocol.receive_packet
    send_once,decode_frame=protocol.send_once,protocol.decode_frame
    barrier=threading.Barrier(2) if simultaneous else None
    requests={};reply_tickets={};lock=threading.Lock();local=threading.local();observed=[]
    def record(frame,direction,at,ticket):
        key=frame['channel_id'];body=frame['body']
        original=body if direction=='sent' else requests[(key,body['request_sequence'])]
        operation=next(op for op in service._operations.values()
            if contract.prepared_digest(op['prepared'])==original['prepared_sha256'])
        e=operation['prepared']['envelope']
        row={'schema_version':'1','broker_id':e['broker_id'],
            'observer_id':e['broker_id'],'session_id':e['session_id'],'dispatch_id':e['dispatch_id'],
            'row_sequence':1,'observed_at_ns':at,'kind':'protocol',
            'data':{'channel_role':'ingress','direction':direction,'frame':frame}}
        service._host_evidence_budget.finalize(ticket,row)
    def primitive_send(channel,raw):
        count=send_once(channel,raw)
        active=getattr(local,'active',None)
        if active is not None and active['direction']=='sent' and channel is active['channel'] and count==len(raw):
            at=time.monotonic_ns()
            if raw!=active['raw'] or active['observed']:raise AssertionError('fixed dispatch send changed')
            frame=active['frame'];active['observed']=True
            with lock:
                requests[(frame['channel_id'],frame['sequence'])]=frame['body']
                observed.append((frame,'sent',at,active['ticket']))
        return count
    def primitive_decode(raw,*,role,**kwargs):
        frame=decode_frame(raw,role=role,**kwargs)
        active=getattr(local,'active',None)
        if active is not None and active['direction']=='received' and role=='ingress' and frame['operation']=='DISPATCH':
            at=time.monotonic_ns()
            with lock:
                slots=reply_tickets[(frame['channel_id'],frame['body']['request_sequence'])]
                ticket=slots.pop('pending' if frame['body']['status']=='pending' else 'final')
                observed.append((deepcopy(frame),'received',at,ticket))
        return frame
    def sent(channel,frame,*,role,control,**kwargs):
        selected=role=='ingress' and frame['operation']=='DISPATCH'
        if not selected:return send(channel,frame,role=role,control=control,**kwargs)
        raw=canonical(frame);ticket=service._host_evidence_budget.reserve(kind='other_host',
            maximum_bytes=len(raw)+1024,maximum_rows=1,control=control)
        reserved=[]
        try:
            for maximum in (1024,17408):
                reserved.append(service._host_evidence_budget.reserve(kind='other_host',
                    maximum_bytes=maximum,maximum_rows=1,control=control))
        except BaseException:
            service._host_evidence_budget.release(ticket)
            for unused in reserved:service._host_evidence_budget.release(unused)
            raise
        with lock:
            key=(frame['channel_id'],frame['sequence']);duplicate=key in reply_tickets
            if not duplicate:reply_tickets[key]=dict(zip(('pending','final'),reserved))
        if duplicate:
            service._host_evidence_budget.release(ticket)
            for unused in reserved:service._host_evidence_budget.release(unused)
            raise AssertionError('duplicate fixed dispatch request')
        active={'direction':'sent','channel':channel,'frame':deepcopy(frame),'raw':raw,
                'ticket':ticket,'observed':False}
        previous=getattr(local,'active',None);local.active=active
        try:
            value=send(channel,frame,role=role,control=control,**kwargs)
            if not active['observed']:raise AssertionError('dispatch send primitive not observed')
            if barrier is not None:barrier.wait(timeout=2)
            return value
        finally:
            local.active=previous
            if not active['observed']:service._host_evidence_budget.release(ticket)
    def received(channel,*,role,control,**kwargs):
        if role!='ingress':return receive(channel,role=role,control=control,**kwargs)
        previous=getattr(local,'active',None);local.active={'direction':'received','channel':channel}
        try:return receive(channel,role=role,control=control,**kwargs)
        finally:local.active=previous
    protocol.send_packet,protocol.receive_packet=sent,received
    protocol.send_once,protocol.decode_frame=primitive_send,primitive_decode
    try:yield
    finally:
        protocol.send_packet,protocol.receive_packet=send,receive
        protocol.send_once,protocol.decode_frame=send_once,decode_frame
        # The caller's RPC context has unwound. These are already-observed,
        # capacity-reserved data facts, never a retry or a renewed operation.
        try:
            for frame,direction,at,ticket in sorted(observed,key=lambda row:row[2]):record(frame,direction,at,ticket)
        finally:
            for slots in reply_tickets.values():
                for ticket in slots.values():service._host_evidence_budget.release(ticket)


def _dispatch_pointers(service,prepared,pointers,ingress):
    result=service._broker.dispatch(**pointers,ingress=ingress)
    result=contract.validate_live_result(result)
    service._operations[prepared['envelope']['dispatch_id']]['result']=result
    return result


def _concurrent_dispatch(service,attempts):
    from concurrent.futures import ThreadPoolExecutor
    if len(attempts)!=2:raise AssertionError('two actual ingress callers')
    with _observe_ingress(service,simultaneous=True),ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(_dispatch_pointers,service,prepared,pointers,index)
                 for index,(prepared,pointers) in enumerate(attempts)]
        observed=[]
        for future in futures:
            try:observed.append(future.result(timeout=max(.001,service._control.deadline-time.monotonic())))
            except Exception as error:observed.append(error)
    return observed


def _core_configuration(case):
    return case.get('configuration') or 'A'


STARTUP_GUARD_CASES={
    'S42C-N10':('validate_live_roe','engagement_live_invalid_prepared'),
    'S42C-N11':('validate_live_roe','engagement_live_invalid_prepared'),
    'S42C-N12':('validate_live_roe','engagement_live_invalid_prepared'),
    'S42C-N28':('_check_current','engagement_live_window_not_open'),
    'S42C-N41':('_check_current','engagement_live_revoked')}
STARTUP_GUARD_PREFIX=b'ENGAGEMENT-LIVE-OWNED-STARTUP '


def _startup_guard_transform(case_id):
    """Observe only the actual selected startup guard; never alter its result."""
    guard,code=STARTUP_GUARD_CASES[case_id]
    def change(source):
        if guard=='validate_live_roe':
            old="        self.roe=c.validate_live_roe(self.snapshot_value['revisions'][-1]['roe']);self.policy=ledger.policy_for_roe(self.roe)"
            new="""        try:self.roe=c.validate_live_roe(self.snapshot_value['revisions'][-1]['roe'])
        except c.LiveError as error:
            _owned_startup_guard_refused(self,error)
            raise
        self.policy=ledger.policy_for_roe(self.roe)"""
        else:
            old="        self._check_current(self.snapshot_value)"
            new="""        try:self._check_current(self.snapshot_value)
        except c.LiveError as error:
            _owned_startup_guard_refused(self,error)
            raise"""
        if source.count(old)!=1:raise AssertionError('exact startup guard source')
        source=source.replace(old,new,1)
        helper="""
def _owned_startup_guard_refused(self,error):
    if error.code!=__CODE__:return
    marker={'schema_version':'1','case_id':__CASE__,'guard':__GUARD__,
        'roe_sha256':c.digest(c.canonical(self.snapshot_value['revisions'][-1]['roe'])),
        'code':error.code,'clock':c.sample_clock()}
    raw=__PREFIX__+c.canonical(marker)+b'\\n'
    if len(raw)>1024:c.fail('limit_exceeded')
    if os.write(2,raw)!=len(raw):c.fail('unavailable')

""".replace('__CODE__',repr(code)).replace('__CASE__',repr(case_id)).replace('__GUARD__',repr(guard)).replace('__PREFIX__',repr(STARTUP_GUARD_PREFIX))
        tail="if __name__=='__main__':raise SystemExit(main())"
        if source.count(tail)!=1:raise AssertionError('exact broker main source')
        return source.replace(tail,helper+tail,1)
    return change


def _parse_startup_guard(raw,case_id,*,received_at_ns):
    if type(raw)is not bytes or len(raw)>4096:raise AssertionError('bounded actual startup diagnostics required')
    lines=raw.splitlines(keepends=True)
    if (len(lines)!=2 or not lines[0].startswith(STARTUP_GUARD_PREFIX)
            or not lines[0].endswith(b'\n') or lines[1]!=b'engagement_live_broker_refused\n'):
        raise AssertionError('actual selected startup guard marker required')
    encoded=lines[0][len(STARTUP_GUARD_PREFIX):-1]
    marker=contract.decode(encoded,max_bytes=1024)
    contract.obj(marker,('schema_version','case_id','guard','roe_sha256','code','clock'))
    guard,code=STARTUP_GUARD_CASES[case_id]
    if (canonical(marker)!=encoded or marker['schema_version']!='1' or marker['case_id']!=case_id
            or marker['guard']!=guard or marker['code']!=code):
        raise AssertionError('selected actual startup guard identity required')
    contract.digest_string(marker['roe_sha256']);contract.ledger.validate_clock(marker['clock'])
    if marker['clock']['mono_after_ns']>received_at_ns:raise AssertionError('future startup guard observation')
    return marker


@contextmanager
def _capture_startup_guard(case,directory):
    """Copy existing stderr before its normal cleanup; retain every failure."""
    original=runtime._read_startup
    def observed(process,info_read,control,*,initial_info=b''):
        try:return original(process,info_read,control,initial_info=initial_info)
        except BaseException as error:
            if getattr(process,'_engagement_role',None)!='broker':raise
            raw=bytearray(getattr(error,'startup_diagnostics',b''));eof=False
            end=min(control.deadline,time.monotonic()+2)
            try:
                fd=process.stderr.fileno();os.set_blocking(fd,False)
                while len(raw)<=4096 and time.monotonic()<end:
                    if not select.select([fd],[],[],min(.01,max(0,end-time.monotonic())))[0]:continue
                    try:part=os.read(fd,4097-len(raw))
                    except BlockingIOError:continue
                    if not part:eof=True;break
                    raw.extend(part)
                received=time.monotonic_ns()
                private_write(Path(directory)/'startup-guard-stderr.bin',bytes(raw))
                if not eof or len(raw)>4096:raise AssertionError('complete bounded startup diagnostics required')
                marker=_parse_startup_guard(bytes(raw),case['id'],received_at_ns=received)
                error.owned_startup_guard=marker
            except BaseException as observation_error:
                # Keep the original real startup refusal and its cleanup path;
                # missing/invalid observation can never acquire a marker later.
                error.owned_startup_guard_error=observation_error
            raise
    runtime._read_startup=observed
    try:yield
    finally:runtime._read_startup=original


def _record_startup_guard(service,error,case,roe,*,ticket):
    marker=getattr(error,'owned_startup_guard',None)
    if marker is None:raise AssertionError('actual business guard refusal was not observed') from error
    if marker['case_id']!=case['id'] or marker['roe_sha256']!=sha(canonical(roe)):
        raise AssertionError('actual startup guard ROE mismatch')
    return _phase_observation(service,None,'prepare','refused',related=sha(canonical(marker)),
        reason=marker['code'],clock=marker['clock'],ticket=ticket)


def _core_roe(case):
    """Finite valid ROE changes; production validators still inspect every one."""
    number=int(case['id'][-2:])
    def transform(roe):
        if number==10:roe['excluded_services']=['http']
        if number in (11,12):
            profile='configurable_nmap_service_v1' if number==11 else 'configurable_http_headers_v1'
            roe['allowed_profiles'].remove(profile)
        if number in (18,19,20,21,22,23,24):
            key,value={18:('max_actions',1),19:('max_connections',3),20:('max_request_bytes',4096),
                21:('max_response_bytes',4096),22:('max_engagement_ms',30000),
                23:('max_actions',1),24:('max_actions',2)}[number]
            roe['limits'][key]=value
            if number==22:roe['limits']['max_action_ms']=30000
        if number==28:
            now=datetime.now(timezone.utc)
            roe['window']={'start_utc':(now+timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'end_utc':(now+timedelta(minutes=11)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        if number==29:
            start=datetime.fromtimestamp(case['_clock']['utc_ns']/contract.SECOND,timezone.utc)
            roe['window']={'start_utc':start.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'end_utc':(start+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        if number in (30,31,32):
            now=datetime.now(timezone.utc)
            roe['window']={'start_utc':(now-timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                           'end_utc':(now+timedelta(seconds=24)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        return roe
    return transform


def _single_core(case,directory,*,variants=None):
    from contextlib import nullcontext
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.engagement_live_session import _HostEvidenceBudget
    number=int(case['id'][-2:]);mode='graphical_v1' if case.get('frontend')=='graphical' else 'terminal'
    before=None;selected=None;recover=False;service=None;support=[];observations=[]
    instrumentation=[_core_instrumentation(case)]
    if variants is not None:instrumentation+=variants.instrumentation
    if number==29:
        for item in instrumentation[1:]:item['kind']='sealed_clock'
    control=ExecutionControl(time.monotonic()+120)
    host_evidence_budget=_HostEvidenceBudget()
    startup_ticket=None
    if number==29:
        import math
        # The pinned initial clock predates source preparation. Charge that
        # elapsed work to the original broker limit; never renew it afterward.
        deadline=math.nextafter((case['_clock']['mono_after_ns']+120*contract.SECOND)/contract.SECOND,-math.inf)
        control=ExecutionControl(deadline)
    if number in (10,11,12,28):
        startup_ticket=host_evidence_budget.reserve(kind='other_host',maximum_bytes=2048,
            maximum_rows=1,control=control)
    try:
        with terminal_input() if mode=='terminal' else nullcontext():
            with native_session(directory/'live',configuration=_core_configuration(case),review_mode=mode,
                    source_variants=variants,roe_transform=_core_roe(case),control=control,
                    host_evidence_budget=host_evidence_budget) as service:
                opened=service.open_session();before=service.snapshot()['ledger_state_sha256']
                if number in (4,5,6,7,29):
                    _useful(service,opened,'http_identify');_useful(service,opened,'http_headers')
                elif number in (1,2,3,8,9,13,14,15):
                    if number in (13,14):
                        _useful(service,opened,'http_identify');before=service.snapshot()['ledger_state_sha256']
                    prepared=service.prepare(opened['binding']['session_id'],
                        'http_headers' if number in (13,14) else 'http_identify')
                    selected=[prepared['envelope']['dispatch_id']]
                    if number in (8,9,15):
                        proof,observation=supporting_socket_case(service,prepared,case,directory)
                        support.append(proof);observations.append(observation)
                    _reject_candidate(service,prepared,case['variant'])
                elif number in (18,19,20,21,22):
                    _useful(service,opened,'http_identify');before=service.snapshot()['ledger_state_sha256']
                    prepared=service.prepare(opened['binding']['session_id'],'http_headers')
                    selected=[prepared['envelope']['dispatch_id']];reference=review_actual(service,prepared)
                    _expected_failure(service,prepared,'reserve',lambda:service.execute(prepared,reference,control=service._control))
                elif number==24:
                    _useful(service,opened,'http_identify')
                    second=service.open_session(ingress=1);before=service.snapshot()['ledger_state_sha256']
                    a=service.prepare(opened['binding']['session_id'],'http_headers')
                    b=service.prepare(second['binding']['session_id'],'http_identify',ingress=1)
                    selected=[a['envelope']['dispatch_id'],b['envelope']['dispatch_id']]
                    ra=review_actual(service,a);rb=review_actual(service,b)
                    pa=_pointers_actual(service,a,ra);pb=_pointers_actual(service,b,rb)
                    _concurrent_dispatch(service,[(a,pa),(b,pb)])
                elif number in (25,26,27):
                    prepared=service.prepare(opened['binding']['session_id'],'http_identify')
                    reference=review_actual(service,prepared)
                    if number==25:
                        # A copied real reference reaches a different actual
                        # isolated store; its bytes carry no authority there.
                        second=service.open_session(ingress=1)
                        target=service.prepare(second['binding']['session_id'],'http_identify',ingress=1)
                        _expected_failure(service,target,'consume',lambda:_consume_actual(service,target,reference))
                    elif number==26:
                        _consume_actual(service,prepared,reference)
                        _expected_failure(service,prepared,'consume',lambda:_consume_actual(service,prepared,reference))
                    else:
                        pointers=_pointers_actual(service,prepared,reference)
                        _concurrent_dispatch(service,[(prepared,pointers),(prepared,pointers)])
                elif number==33:
                    prepared=service.prepare(opened['binding']['session_id'],'http_identify')
                    _expected_failure(service,prepared,'consume',lambda:service.review(prepared,control=service._control))
                    hard=prepared['envelope']['action_deadline_ns']
                    while time.monotonic_ns()<hard:
                        if time.monotonic()>=service._control.deadline:raise TimeoutError('original broker deadline')
                        time.sleep(min(.01,max(0,(hard-time.monotonic_ns())/contract.SECOND)))
                    if not (service._closed or service._stop.is_set() or service._closing.is_set()):
                        raise AssertionError('timed-out review graph must already be stopped')
                    _expected_failure(service,prepared,'consume',lambda:service.review(prepared,control=service._control))
                elif number in (10,11,12,28):
                    raise AssertionError('invalid live ROE unexpectedly admitted a session')
                else:
                    before,selected,recover=_core_phase_case(case,directory,service,opened,before,instrumentation)
    except Exception as error:
        if number not in (10,11,12,28):raise
        if isinstance(error,AssertionError):raise
        service=getattr(error,'engagement_session',service)
        if service is None or service._cleanup is None:raise
        recover=True
        roe=json.loads((directory/'live'/'roe.json').read_bytes())
        _record_startup_guard(service,error,case,roe,ticket=startup_ticket)
    if service is None:raise AssertionError('actual service owner required')
    with _retain_payload_failure(service):
        return _write_case_payload(directory,_seal_case_payload(service,case,before=before,selected=selected,
            instrumentation=instrumentation,recover=recover,boundary_proofs=support,boundary_observations=observations))


def _external_change(service,prepared,*,revision=False):
    from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    ticket=_phase_ticket(service)
    end=min(service._control.deadline,time.monotonic()+2)
    with ledger._deadline_context(end),DispatchLedger.open(service._store_directory) as store:
        actual=store.snapshot();state=actual['state']
        kwargs={'expected_revision':state['revision'],'expected_generation':state['generation'],'event_id':str(uuid4())}
        if revision:
            roe=deepcopy(actual['revisions'][-1]['roe'])
            roe['limits']['max_actions']-=1
            result=store.append_revision(roe,**kwargs)
        else:result=store.revoke(**kwargs)
    if result['disposition']!='recorded':raise AssertionError('actual external change required')
    _phase_observation(service,prepared,'watch','end',related=result['receipt']['state_sha256'],clock=contract.sample_clock(),ticket=ticket)
    return result


def _wait_roe_end(service,prepared):
    end=prepared['envelope']['window_end_utc_ns']
    # Actual elapsed time; no mutable deadline or fabricated clock jump.
    while time.time_ns()<end:
        if time.monotonic()>=service._control.deadline:raise TimeoutError('original broker deadline')
        time.sleep(min(.01,max(0,(end-time.time_ns())/contract.SECOND)))


def _live_rows(service):
    """Temporary read-only barrier data. Final evidence uses the sealed copy."""
    from recon_cockpit.secure_agent.engagement_live_witness import validate_transcript_row
    readers=service._broker.evidence_readers
    fd=readers['transcript']
    raw=os.pread(fd,2097153,0)
    if len(raw)>2097152:raise AssertionError('actual transcript limit')
    return [validate_transcript_row(json.loads(line)) for line in raw.split(b'\n')[:-1]]


def _wait_actual_phase(service,prepared,phase,stage,*,pending=None):
    end=min(service._control.deadline,prepared['envelope']['action_deadline_ns']/contract.SECOND)
    while time.monotonic()<end:
        rows=_live_rows(service)
        found=[row for row in rows if row['dispatch_id']==prepared['envelope']['dispatch_id']
            and row['kind']=='phase' and row['data']['phase']==phase and row['data']['stage']==stage]
        if found:return found[-1]
        if pending is not None and pending.done():pending.result();raise AssertionError('actual requested phase absent')
        time.sleep(.005)
    raise TimeoutError('actual phase barrier')


def _signal_at_fixed_crash_phase(service,prepared,phase,stage,*,pending):
    """Signal the owned broker only after its exact fixed crash barrier."""
    env=prepared['envelope'];digest=sha(canonical(prepared))
    end=min(service._control.deadline,env['action_deadline_ns']/contract.SECOND)
    while time.monotonic()<end:
        found=[row for row in _live_rows(service) if row['kind']=='phase'
            and row['broker_id']==row['observer_id']==env['broker_id']
            and row['session_id']==env['session_id'] and row['dispatch_id']==env['dispatch_id']
            and row['data']['phase']==phase and row['data']['stage']==stage
            and row['data']['related_sha256']==digest
            and row['data']['original_deadline_ns']==env['action_deadline_ns']
            and row['data']['reason'] is None and row['data']['clock'] is not None
            and row['data']['clock']['mono_before_ns']<=row['data']['clock']['mono_after_ns']
                <=row['observed_at_ns']<env['action_deadline_ns']]
        if found:
            if len(found)!=1:raise AssertionError('one exact fixed crash marker required')
            end=min(end,(found[0]['observed_at_ns']+contract.SECOND)/contract.SECOND)
            break
        if pending.done():pending.result();raise AssertionError('actual crash marker absent')
        time.sleep(min(.005,max(0,end-time.monotonic())))
    else:raise TimeoutError('actual fixed crash barrier')
    _phase_observation(service,prepared,phase,'begin',clock=contract.sample_clock())
    terminal_ticket=_phase_ticket(service)
    if time.monotonic()>=end or pending.done():raise TimeoutError('fixed crash barrier expired')
    # Namespace PID1 is terminated from its existing owner, using the same
    # pinned pidfd as the other owned crash cases. No numeric PID fallback.
    signal.pidfd_send_signal(service._broker.pidfd,signal.SIGKILL,None,0)
    _phase_observation(service,prepared,phase,'end',clock=contract.sample_clock(),ticket=terminal_ticket)


def _wait_actual_progress(service,prepared,kind,*,pending):
    end=min(service._control.deadline,prepared['envelope']['action_deadline_ns']/contract.SECOND)
    while time.monotonic()<end:
        for row in _live_rows(service):
            if row['dispatch_id']!=prepared['envelope']['dispatch_id']:continue
            if row['kind']=='meter' and row['data']['kind']==kind and row['data']['actual_bytes']>0:return row
            if row['kind']!='protocol':continue
            data=row['data'];frame=data['frame']
            if data['channel_role']!='endpoint' or data['direction']!='received' or frame['operation']!='METER':continue
            if any(event['kind']==kind and event['actual_bytes']>0 for event in frame['body']['events']):return row
        if pending.done():pending.result();raise AssertionError('actual partial progress absent')
        time.sleep(.005)
    raise TimeoutError('actual partial progress barrier')


def _core_phase_case(case,directory,service,opened,before,instrumentation):
    from concurrent.futures import ThreadPoolExecutor
    number=int(case['id'][-2:]);prepared=service.prepare(opened['binding']['session_id'],'http_identify')
    selected=[prepared['envelope']['dispatch_id']];recover=False
    if number in (16,17,36,37):
        reference=None if number==36 else review_actual(service,prepared)
        instrumentation.append(_core_instrumentation(case,'external_admin','broker'))
        _external_change(service,prepared,revision=number in (16,17))
        operation=(lambda:service.review(prepared,control=service._control)) if number==36 else (
            lambda:service.execute(prepared,reference,control=service._control))
        _expected_failure(service,prepared,'prepare' if number==36 else 'guard',operation)
    elif number in (30,31):
        reference=review_actual(service,prepared)
        pointers=_pointers_actual(service,prepared,reference) if number==31 else None
        _wait_roe_end(service,prepared)
        operation=(lambda:_consume_actual(service,prepared,reference)) if number==30 else (
            lambda:_dispatch_pointers(service,prepared,pointers,0))
        _expected_failure(service,prepared,'consume' if number==30 else 'audit',operation)
    elif number==42:
        reference=review_actual(service,prepared)
        instrumentation.append(_core_instrumentation(case,'process_signal','broker'))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending=pool.submit(service.execute,prepared,reference,control=service._control)
            _signal_at_fixed_crash_phase(service,prepared,'reserve','begin',pending=pending)
            _expected_failure(service,prepared,'reserve',
                lambda:pending.result(timeout=max(.001,service._control.deadline-time.monotonic())))
        recover=True
    elif number in (32,34,35,47,48,49,50):
        reference=review_actual(service,prepared)
        phase='complete' if number in (47,48) else 'guard' if number==32 else 'native_observation' if number==34 else 'cleanup' if number==35 else 'reserve'
        _expected_failure(service,prepared,phase,lambda:service.execute(prepared,reference,control=service._control))
        if number==32:
            # Retain the earlier actual cancellation separately. After the real
            # ROE end, the original Prepared/reference must still be refused by
            # the stopped graph before approval consumption or any new effect.
            _wait_roe_end(service,prepared)
            if not (service._closed or service._stop.is_set() or service._closing.is_set()):
                raise AssertionError('original graph must be stopped before post-end continuation')
            _expected_failure(service,prepared,'guard',
                lambda:service.execute(prepared,reference,control=service._control))
        recover=number in (47,48,49,50)
    elif number==51:
        from recon_cockpit.secure_agent.engagement_live_witness import started_event
        reference=review_actual(service,prepared);_consume_actual(service,prepared,reference)
        _expected_failure(service,prepared,'audit',lambda:service._audit.emit(started_event(prepared),control=service._control))
        recover=True
    elif number in (38,39,40,45,46):
        reference=review_actual(service,prepared)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending=pool.submit(service.execute,prepared,reference,control=service._control)
            if number in (38,39):_wait_actual_phase(service,prepared,'reserve' if number==38 else 'guard',
                'begin' if number==38 else 'end',pending=pending)
            else:_wait_actual_progress(service,prepared,'recv' if number==45 else 'send',pending=pending)
            if number in (38,39,40):
                instrumentation.append(_core_instrumentation(case,'external_admin','broker'))
                _external_change(service,prepared)
            else:
                instrumentation.append(_core_instrumentation(case,'process_signal','broker'))
                _phase_observation(service,prepared,'client','begin')
                terminal_ticket=_phase_ticket(service)
                # The actual pinned pidfd is used; a numeric PID is never a
                # substitute for owned process identity.
                signal.pidfd_send_signal(service._broker.pidfd,signal.SIGKILL,None,0)
                _phase_observation(service,prepared,'client','end',ticket=terminal_ticket)
            _expected_failure(service,prepared,'guard' if number in (38,39,40) else 'client',
                lambda:pending.result(timeout=max(.001,service._control.deadline-time.monotonic())))
        recover=number in (45,46)
    elif number==53:
        reference=review_actual(service,prepared)
        result=service.execute(prepared,reference,control=service._control)
        if result['outcome']!='useful':raise AssertionError('prior consumed allowance required')
        # Close the actual inherited broker control endpoint before retrying
        # the existing prepared dispatch pointer. The other owners are reaped.
        service._broker._owner.channel.close()
        _expected_failure(service,prepared,'prepare',lambda:service._broker.dispatch(
            contract.prepared_digest(prepared),'0'*64,1,1))
        recover=True
    else:raise AssertionError('fixed phase case lacks an implementation: '+case['id'])
    return before,selected,recover


BROKER_FAULT_CASES={
 'S42C-N32':('end_after_reservation_before_GO','roe_end'),
 'S42C-N38':('external_v2_revoke_commits_before_release_guard','revoke_before'),
 'S42C-N39':('GO_guard_precedes_external_revoke','revoke_after'),
 'S42C-N42':('kill_before_reservation_COMMIT','kill_precommit'),
 'S42C-N43':('kill_broker_after_reservation_before_GO','kill_reserved'),
 'S42C-N44':('kill_broker_after_GO_before_observation','kill_go'),
 'S42C-N47':('completion_write_failure','complete_write'),
 'S42C-N48':('completion_commit_failure','complete_commit'),
 'S42C-N49':('admission_database_write_failure','reserve_write'),
 'S42C-N50':('admission_fsync_failure','reserve_fsync'),
}

_BROKER_FAULT_CODE=r'''
# BEGIN fixed S42C owned-gate variant: __CASE__ / __KIND__.
# This block exists only in the sealed, manifest-labelled test source.
import sqlite3 as _fault_sqlite
import select as _fault_select

_fault_original_mark=BrokerCore.mark
def _fixed_crash_hold(self,row):
    # A finite test-only barrier gives the existing host owner time to signal
    # its broker pidfd. Missing/late signals fail; execution never resumes.
    stop=min(row['prepared']['envelope']['action_deadline_ns'],time.monotonic_ns()+1000000000)
    while time.monotonic_ns()<stop:
        time.sleep(min(.005,max(0,(stop-time.monotonic_ns())/c.SECOND)))
    raise RuntimeError('owned crash barrier expired without host signal')

class _FixedFaultConnection:
    def __init__(self,connection,owner,row,phase,target,kind):
        self.connection=connection;self.owner=owner;self.row=row
        self.phase=phase;self.target=target;self.kind=kind;self.wrote=False;self.fired=False
    def __getattr__(self,key):return getattr(self.connection,key)
    def execute(self,sql,*args,**kwargs):
        result=self.connection.execute(sql,*args,**kwargs)
        if sql.startswith('INSERT INTO '+self.target+' '):self.wrote=True
        return result
    def commit(self):
        if self.wrote and not self.fired:
            self.fired=True
            _fault_original_mark(self.owner,self.row,self.phase,
                'begin' if self.kind=='kill_precommit' else 'refused',
                related=self.row['prepared'],
                reason=None if self.kind=='kill_precommit' else 'engagement_live_unavailable')
            if self.kind=='kill_precommit':
                _fixed_crash_hold(self.owner,self.row)
            error=_fault_sqlite.OperationalError('fixed owned simulated durability failure')
            if self.kind=='reserve_fsync':
                error.sqlite_errorcode=_fault_sqlite.SQLITE_IOERR_FSYNC
                error.sqlite_errorname='SQLITE_IOERR_FSYNC'
            else:
                error.sqlite_errorcode=_fault_sqlite.SQLITE_IOERR
                error.sqlite_errorname='SQLITE_IOERR'
            raise error
        return self.connection.commit()

def _fixed_fault_mark(self,row,phase,stage,*,related=None,reason=None):
    result=_fault_original_mark(self,row,phase,stage,related=related,reason=reason)
    kind='__KIND__'
    if getattr(self,'_owned_fault_installed',False):return result
    if kind in {'reserve_write','reserve_fsync','kill_precommit','complete_write','complete_commit'}:
        selected='complete' if kind.startswith('complete_') else 'reserve'
        if phase!=selected or stage!='begin':return result
        self._owned_fault_installed=True
        target='completions' if selected=='complete' else 'reservations'
        if kind.endswith('_write'):
            def deny_write(operation,arg1,arg2,database,trigger):
                if operation==_fault_sqlite.SQLITE_INSERT and arg1==target:
                    _fault_original_mark(self,row,selected,'refused',related=row['prepared'],reason='engagement_live_unavailable')
                    return _fault_sqlite.SQLITE_DENY
                return _fault_sqlite.SQLITE_OK
            self.store._db.set_authorizer(deny_write)
        else:
            self.store._db=_FixedFaultConnection(self.store._db,self,row,selected,target,kind)
    elif kind=='kill_reserved' and phase=='reserve' and stage=='end':
        self._owned_fault_installed=True
        _fault_original_mark(self,row,'reserve','end',related=row['prepared'])
        _fixed_crash_hold(self,row)
    elif kind=='kill_go' and phase=='go' and stage=='end':
        self._owned_fault_installed=True
        _fault_original_mark(self,row,'go','end',related=row['prepared'])
        _fixed_crash_hold(self,row)
    elif ((kind=='revoke_before' and phase=='reserve' and stage=='begin')
          or (kind=='revoke_after' and phase=='guard' and stage=='end')):
        self._owned_fault_installed=True
        # A fixed observational barrier, not permission or a callback. The host
        # must observe this actual row, attempt its real v2 transaction, and
        # retain that transaction's actual ordering. Timing alone never passes.
        # Post-GO guard/end is outside the writer transaction. Holding go/end
        # would artificially block the external owner beyond its busy timeout.
        _fault_original_mark(self,row,phase,stage,related=row['prepared'])
        stop=time.monotonic()+(.75 if kind=='revoke_before' else .5)
        while time.monotonic()<stop:
            if time.monotonic_ns()>=row['prepared']['envelope']['action_deadline_ns']:
                c.fail('timeout')
            time.sleep(min(.005,max(0,stop-time.monotonic())))
    elif kind=='roe_end' and phase=='reserve' and stage=='end':
        self._owned_fault_installed=True
        end=row['prepared']['envelope']['window_end_utc_ns']
        original=row['prepared']['envelope']['action_deadline_ns']
        # The immutable action deadline is conservatively clipped to UTC end.
        # This fixed instrumentation may only observe that actual end for <=50ms
        # after the deadline. It performs no authority/effect work and grants no
        # renewed operation allowance. The next unchanged guard must refuse.
        while time.time_ns()<end:
            if time.monotonic_ns()>=original+50000000:
                raise RuntimeError('actual ROE end not observed within fixed tail')
            # There is no valid launcher continuation before GO. Actual EOF or
            # traffic on its existing peer ends this observational hold without
            # consuming a frame or granting authority, so normal teardown can
            # seal the committed reservation within the original cleanup bound.
            peer=self.launcher_channels[row['slot_index']][0]
            if _fault_select.select([peer],[],[],min(.01,max(0,(end-time.time_ns())/c.SECOND)))[0]:
                c.fail('cancelled')
        _fault_original_mark(self,row,'reserve','end',related=row['prepared'])
        # The next unchanged fresh guard performs the actual window refusal.
    return result
BrokerCore.mark=_fixed_fault_mark
# END fixed S42C owned-gate variant.
'''


def broker_fault_transform(case_id):
    """Return one fixed source-only transform accepted by SourceVariants.source."""
    if case_id not in BROKER_FAULT_CASES:raise ValueError('unsupported fixed fault')
    variant,kind=BROKER_FAULT_CASES[case_id]
    addition=_BROKER_FAULT_CODE.replace('__CASE__',case_id).replace('__KIND__',kind)
    def transform(source):
        tail="if __name__=='__main__':raise SystemExit(main())"
        if source.count(tail)!=1 or 'def mark(self,row,phase,stage,'not in source:
            raise ValueError('reviewed broker source boundary changed')
        changed=source.replace(tail,addition+'\n'+tail)
        compile(changed,'engagement_live_broker_worker.py','exec')
        return changed
    return transform


def install_broker_fault(variants,case_id):
    variant,_=BROKER_FAULT_CASES[case_id]
    if variants.configuration!={'case_id':case_id,'variant':variant,'role':'broker'}:
        raise ValueError('fixed source configuration mismatch')
    return variants.source('engagement_live_broker_worker',broker_fault_transform(case_id))


_N44_LAUNCHER_HOLD_CODE=r'''
# BEGIN fixed S42C-N44 launcher synchronization.
def _fixed_n44_go_hold(owner,control):
    # The real GO was already validated and assigned. Hold before the run
    # try/finally so cancellation cannot start a new child REAP exchange.
    # Existing transport EOF/cancellation checks stay active; expiry refuses.
    stop=min(owner.pending['envelope']['action_deadline_ns'],owner.deadline_ns,
        int(control.deadline*c.SECOND),time.monotonic_ns()+c.SECOND)
    while time.monotonic_ns()<stop:
        control.check()
        time.sleep(min(.005,max(0,(stop-time.monotonic_ns())/c.SECOND)))
    c.fail('timeout')
# END fixed S42C-N44 launcher synchronization.
'''


def n44_launcher_hold_transform(source):
    """Freeze only the reviewed N44 launcher after its actual validated GO."""
    tail="if __name__=='__main__':raise SystemExit(main())"
    boundary="        parsed=parser_receipt=None;failure=None;capture=None\n        try:\n            self.admission_rpc('REDEEM',"
    if (source.count(tail)!=1 or source.count(boundary)!=1 or 'def _fixed_n44_go_hold(' in source
            or source.count("release=c.validate_release_binding(release,self.pending,clock=c.sample_clock());self.release=release")!=1):
        raise ValueError('reviewed N44 launcher boundary changed')
    changed=source.replace(boundary,
        "        _fixed_n44_go_hold(self,effect)\n"+boundary)
    changed=changed.replace(tail,_N44_LAUNCHER_HOLD_CODE+'\n'+tail)
    compile(changed,'engagement_live_launcher_worker.py','exec')
    return changed


def _install_n44_launcher_hold(variants):
    expected={'case_id':'S42C-N44','variant':'kill_broker_after_GO_before_observation','role':'broker'}
    if variants.configuration!=expected:raise ValueError('fixed N44 source configuration mismatch')
    path=variants.source('engagement_live_launcher_worker',n44_launcher_hold_transform)
    # Retain each role's exact source/configuration projection. The broker
    # marker/signal variant and its existing configuration remain unchanged.
    variants.records[-1]['configuration']={**expected,'role':'launcher'}
    return path


def _replace_once(source,old,new):
    if source.count(old)!=1:raise ValueError('fixed reviewed source phase changed')
    return source.replace(old,new)


def _install_progress(variants,case):
    """One fixed instrumentation packet; ordinary METER stays unchanged."""
    case_id=case['id'];kind='recv' if case_id=='S42C-N45' else 'send'
    if case_id not in ('S42C-N40','S42C-N45','S42C-N46'):raise ValueError('fixed partial case')
    def endpoint(source):
        source=_replace_once(source,'        self.events.append(row)',
            '        self.events.append(row)\n'
            "        if kind=="+repr(kind)+" and actual>0 and not getattr(self,'_owned_progress_sent',False):\n"
            "            self._owned_progress_sent=True;self._owned_progress(self)\n")
        if kind=='recv':source=_replace_once(source,'raw=stream.recv(left)','raw=stream.recv(min(left,1))')
        else:source=_replace_once(source,'payload=self.reply[self.reply_offset:self.reply_offset+left]',
            'payload=self.reply[self.reply_offset:self.reply_offset+min(left,1)]')
        callback='''    def owned_progress(value):
        if value.release is None or len(value.events)>64:runtime._fail('invalid_input')
        frame={'schema_version':'1','channel_id':payload['endpoint_id'],'sequence':1,
            'operation':'OWNED_PROGRESS','body':{'case_id':__CASE__,
                'prepared_sha256':contract.prepared_digest(value.prepared),'events':list(value.events)}}
        raw=contract.canonical(frame,max_bytes=32768)
        if not select.select([],[broker],[],min(.1,control.remaining()))[1]:runtime._fail('unavailable')
        if broker.send(raw)!=len(raw):runtime._fail('unavailable')
        # Stop this held effect at its original effect lease or a real
        # cancellation/EOF. No fresh execution allowance is introduced.
        limit=min(deadline_ns,value.release['effect_stop_ns'])
        while time.monotonic_ns()<limit:
            if select.select([broker],[],[],min(.02,max(0,(limit-time.monotonic_ns())/1e9)))[0]:break
'''.replace('__CASE__',repr(case_id))
        source=_replace_once(source,"    try:\n        send(broker,'broker','READY',ready)",callback+"    try:\n        send(broker,'broker','READY',ready)")
        return _replace_once(source,"                meter=Meter(pending,payload['endpoint_id'],payload['scope'])",
            "                meter=Meter(pending,payload['endpoint_id'],payload['scope']);meter._owned_progress=owned_progress")
    def broker(source):
        inserted='''        if role=='endpoint':
            raw=peer.recv(32769,socket.MSG_PEEK)
            if len(raw)>32768:c.fail('limit_exceeded')
            candidate=c.decode(raw)
            if candidate.get('operation')=='OWNED_PROGRESS':
                from .engagement_live_runtime import validate_meter_event
                c.obj(candidate,('schema_version','channel_id','sequence','operation','body'))
                key=(role,index);slot=self.core.slots[index];row=self.core.dispatches.get(slot['dispatch_id'])
                if (candidate['schema_version']!='1' or candidate['sequence']!=1 or row is None
                        or key not in self.sequences or candidate['channel_id']!=self.sequences[key].channel_id
                        or row['release'] is None or row.get('_owned_progress_seen')):c.fail('invalid_frame')
                body=candidate['body'];c.obj(body,('case_id','prepared_sha256','events'))
                if body['case_id']!=__CASE__ or body['prepared_sha256']!=c.prepared_digest(row['prepared']):c.fail('invalid_frame')
                events=body['events']
                if type(events)is not list or not 1<=len(events)<=64:c.fail('invalid_frame')
                for sequence,event in enumerate(events,1):
                    validate_meter_event(event)
                    if event['sequence']!=sequence:c.fail('invalid_sequence')
                if events[-1]['kind']!=__KIND__ or events[-1]['actual_bytes']<=0:c.fail('invalid_frame')
                if peer.recv(32769)!=raw:c.fail('invalid_frame')
                row['_owned_progress_seen']=True;e=row['prepared']['envelope']
                for event in events:
                    self.core.transcript.record('meter',event,session_id=e['session_id'],dispatch_id=e['dispatch_id'])
                return
'''.replace('__CASE__',repr(case_id)).replace('__KIND__',repr(kind))
        return _replace_once(source,"        frame=p.receive_packet(peer,role=role,control=self.control());key=(role,index)",
            inserted+"        frame=p.receive_packet(peer,role=role,control=self.control());key=(role,index)")
    variants.source('engagement_live_endpoint_worker',endpoint)
    variants.source('engagement_live_broker_worker',broker)


def _install_inclusive_clock(variants,case):
    # Project the entire real bracket to the preceding exact UTC second.
    # Moving UTC alone creates a false clock jump in unchanged host/role checks.
    # All later samples use ordinary clocks; parser source stays replayable.
    sample=contract.sample_clock();fraction=sample['utc_ns']%contract.SECOND
    sample={key:value-fraction for key,value in sample.items()};case['_clock']=sample
    def broker(source):
        marker='\ndef main():\n'
        patch='\n_OWNED_INCLUSIVE_ANCHOR='+repr(sample)+'\n'+'''
# Exact inclusive-boundary inputs only for initial ownership and the first
# actual session record. All later witness/window checks use advancing clocks.
_owned_inclusive_init=BrokerCore.__init__
_owned_inclusive_open=BrokerCore.open_session
def _owned_at_inclusive_boundary(operation):
    advancing=c.sample_clock
    try:
        c.sample_clock=lambda:dict(_OWNED_INCLUSIVE_ANCHOR)
        return operation()
    finally:
        c.sample_clock=advancing
def _owned_inclusive_initialize(self,*args,**kwargs):
    return _owned_at_inclusive_boundary(lambda:_owned_inclusive_init(self,*args,**kwargs))
def _owned_inclusive_session(self,index):
    if index!=0 or any(slot['state']!='allocated' for slot in self.slots):
        c.fail('invalid_input')
    return _owned_at_inclusive_boundary(lambda:_owned_inclusive_open(self,index))
BrokerCore.__init__=_owned_inclusive_initialize
BrokerCore.open_session=_owned_inclusive_session
'''
        return _replace_once(source,marker,'\n'+patch+marker)
    variants.source('engagement_live_broker_worker',broker)


def _install_audit_fsync(variants):
    variants.source('audit_worker',lambda source:_replace_once(source,'        os.fsync(fd)',
        "        # Fixed owned N51 simulation at the actual append fsync boundary.\n"
        "        raise OSError(errno.EIO, 'owned injected audit fsync EIO')"))


DEADLINE_FAULT_CASES={'S42C-N34':('deadline_during_native','native_observation'),
       'S42C-N35':('deadline_during_result_cleanup','cleanup')}


def _deadline_once(source,old,new):
    if source.count(old)!=1:raise ValueError('fixed deadline phase changed')
    return source.replace(old,new)


_LAUNCHER_HELPERS=r'''
# Fixed owned __CASE__ instrumentation, absent from production source.
class _OwnedExpiredOriginal:
    def __init__(self,parent,original):
        self.parent=parent;self.deadline=parent.deadline
        self.original=original;self.clock=lambda:original/c.SECOND
        self.cancelled=getattr(parent,'cancelled',None)
    def check(self):
        self.parent.check()
        if self.original/c.SECOND>=self.deadline:c.fail('timeout')
        raise RuntimeError('fixed expired original deadline did not expire')
    def remaining(self):self.check();return 0

def _owned_deadline_marker(self,phase):
    if getattr(self,'_owned_deadline_seen',False):raise RuntimeError('duplicate deadline stimulus')
    e=self.pending['envelope'];anchor=e['clock_anchor'];original=e['action_deadline_ns']
    if self.client.native_ready is None:raise RuntimeError('actual native observation required')
    projected={'mono_before_ns':original,'mono_after_ns':original,
        'utc_ns':anchor['utc_ns']+original-anchor['mono_after_ns']}
    c.ledger.validate_clock(projected)
    frame={'schema_version':'1','channel_id':self.worker_id,'sequence':1,
        'operation':'OWNED_DEADLINE','body':{'case_id':'__CASE__',
        'prepared_sha256':c.prepared_digest(self.pending),'phase':phase,
        'original_deadline_ns':original,'clock':projected}}
    raw=c.canonical(frame,max_bytes=4096)
    # One existing 100ms phase cap includes send and acknowledgement. The
    # logical projected clock is evidence only, never a new transport budget.
    limit=min(time.monotonic_ns()+100000000,self.deadline_ns,
        *(e[key] for key in ('action_deadline_ns','session_deadline_ns','broker_deadline_ns')),
        self.release['effect_stop_ns'],int(self.client.native_deadline*c.SECOND))
    expected={'schema_version':'1','channel_id':self.worker_id,'sequence':1,
        'operation':'OWNED_DEADLINE_ACK','body':{'marker_sha256':c.digest(raw)}}
    original_poll=self.poll_stop;sent=False;acknowledged=False
    def poll():
        nonlocal acknowledged
        if not self.stopped and not self._polling and select.select([self.broker],[],[],0)[0]:
            pending=self.broker.recv(32769,socket.MSG_PEEK)
            if pending and c.decode(pending).get('operation')=='OWNED_DEADLINE_ACK':
                import array
                received,ancillary,flags,_=self.broker.recvmsg(4097,socket.CMSG_SPACE(256),
                    socket.MSG_DONTWAIT|socket.MSG_CMSG_CLOEXEC)
                if ancillary:
                    for level,kind,data in ancillary:
                        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                            fds=array.array('i');fds.frombytes(data[:len(data)-len(data)%fds.itemsize])
                            for fd in fds:os.close(fd)
                    c.fail('invalid_channel')
                if (not sent or acknowledged or flags & ~socket.MSG_CMSG_CLOEXEC
                        or received!=pending or received!=c.canonical(expected,max_bytes=4096)):
                    c.fail('invalid_frame')
                acknowledged=True
        # Normal METER, STOP/CANCEL, EOF and host cancellation retain their
        # production validation and precedence, including after a valid ACK.
        original_poll()
    self.poll_stop=poll
    try:
        control=self._control(limit)
        with c._deadline_context(control.deadline):
            p._ready(self.broker,writing=True,control=control)
            if p.send_once(self.broker,raw)!=len(raw):c.fail('unavailable')
            sent=True
            while not acknowledged:
                control.check()
                if not acknowledged:
                    select.select([self.broker,self.host],[],[],min(.01,control.remaining()))
            control.check()
            self._owned_deadline_seen=True
    finally:self.poll_stop=original_poll
'''

_BROKER=r'''        if role=='launcher':
            raw=peer.recv(32769,socket.MSG_PEEK)
            if len(raw)>32768:c.fail('limit_exceeded')
            candidate=c.decode(raw)
            if candidate.get('operation')=='OWNED_DEADLINE':
                c.obj(candidate,('schema_version','channel_id','sequence','operation','body'))
                key=(role,index);slot=self.core.slots[index];row=self.core.dispatches.get(slot['dispatch_id'])
                if (len(raw)>4096 or candidate['schema_version']!='1' or candidate['sequence']!=1
                        or key not in self.sequences or row is None or row['release']is None
                        or 'native'not in row or candidate['channel_id']!=self.sequences[key].channel_id
                        or row.get('_owned_deadline_seen')):c.fail('invalid_frame')
                body=candidate['body'];c.obj(body,('case_id','prepared_sha256','phase','original_deadline_ns','clock'))
                e=row['prepared']['envelope'];anchor=e['clock_anchor'];original=e['action_deadline_ns']
                expected={'mono_before_ns':original,'mono_after_ns':original,
                    'utc_ns':anchor['utc_ns']+original-anchor['mono_after_ns']}
                if (body['case_id']!='__CASE__' or body['phase']!='__PHASE__'
                        or body['prepared_sha256']!=c.prepared_digest(row['prepared'])
                        or body['original_deadline_ns']!=original or body['clock']!=expected):c.fail('invalid_frame')
                c.ledger.validate_clock(body['clock'])
                if peer.recv(32769)!=raw:c.fail('invalid_frame')
                row['_owned_deadline_seen']=True
                hard=min(self.core.deadline_ns,*(e[key] for key in
                    ('action_deadline_ns','session_deadline_ns','broker_deadline_ns')))
                with self.core.phase(hard):
                    self.core.transcript.record('phase',{'clock':body['clock'],
                        'original_deadline_ns':original,'phase':body['phase'],'stage':'refused',
                        'related_sha256':body['prepared_sha256'],'reason':'engagement_live_timeout'},
                        session_id=e['session_id'],dispatch_id=e['dispatch_id'])
                    # Private barrier only after the actual journal append.
                    # This packet does not alter normal role channel sequences.
                    ack={'schema_version':'1','channel_id':candidate['channel_id'],'sequence':1,
                        'operation':'OWNED_DEADLINE_ACK','body':{'marker_sha256':c.digest(raw)}}
                    encoded=c.canonical(ack,max_bytes=4096)
                    from .engagement_live_runtime import _WorkerControl
                    control=_WorkerControl(min(hard,time.monotonic_ns()+100000000))
                    p._ready(peer,writing=True,control=control)
                    if p.send_once(peer,encoded)!=len(encoded):c.fail('unavailable')
                    control.check()
                return
'''


def deadline_fault_transforms(case_id):
    if case_id not in DEADLINE_FAULT_CASES:raise ValueError('fixed deadline case')
    variant,phase=DEADLINE_FAULT_CASES[case_id]
    def launcher(source):
        tail="if __name__=='__main__':raise SystemExit(main())"
        source=_deadline_once(source,tail,_LAUNCHER_HELPERS.replace('__CASE__',case_id)+'\n'+tail)
        old="            capture=self.client.collect(effect);self.cleanups.append(capture['cleanup']);self.observe('cleanup',capture['cleanup'])"
        if case_id=='S42C-N34':
            trigger="""            if self.client.native_ready is None:c.fail('invalid_role')
            rt.validate_protocol_value('native_readiness',self.client.native_ready)
            _owned_deadline_marker(self,'native_observation')
            effect=_OwnedExpiredOriginal(effect,self.pending['envelope']['action_deadline_ns'])
            whole=_OwnedExpiredOriginal(whole,self.pending['envelope']['action_deadline_ns'])
"""
        else:
            trigger="""            _owned_original_collect=self.client.collect
            def _owned_cleanup_collect(control):
                self.client.collect=_owned_original_collect
                # CAPTURE returns actual host reaping before this sealed fault.
                # A proxy has no fabricated Popen or process pin to intercept.
                captured=_owned_original_collect(control)
                if captured['cleanup'] is None or captured['cleanup']['status']!='complete':
                    c.fail('cleanup_incomplete')
                _owned_deadline_marker(self,'cleanup')
                error=c.LiveError('engagement_live_timeout')
                error.cleanup=captured['cleanup'];error.client_capture=captured
                raise error
            self.client.collect=_owned_cleanup_collect
"""
        return _deadline_once(source,old,trigger+old)
    def broker(source):
        old="        frame=p.receive_packet(peer,role=role,control=self.control());key=(role,index)"
        return _deadline_once(source,old,_BROKER.replace('__CASE__',case_id).replace('__PHASE__',phase)+old)
    return {'engagement_live_launcher_worker':launcher,'engagement_live_broker_worker':broker}


def install_deadline_fault(variants,case_id):
    variant,_=DEADLINE_FAULT_CASES[case_id]
    if variants.configuration!={'case_id':case_id,'variant':variant,'role':'launcher'}:
        raise ValueError('fixed deadline configuration mismatch')
    return {name:variants.source(name,transform) for name,transform in deadline_fault_transforms(case_id).items()}


def _merge_core_payloads(payloads):
    """Retain two actual broker histories and one explicitly host-only segment."""
    from recon_cockpit.secure_agent.engagement_live_witness import validate_transcript_row
    if len(payloads)!=2:raise AssertionError('two sequential actual owners required')
    manifest=deepcopy(payloads[-1][0]);members={};segments=[];chunks=[];observers=[]
    processes={'schema_version':'1','startup':[],'readiness':[],'native':[],'child_slots':[],'boundary_observations':[]}
    results={'schema_version':'1','operations':[],'boundary_proofs':[],'core_proofs':[]}
    cleanup={'schema_version':'1','receipts':[],'supervisors':[],'exports':[],'recovery':None}
    instances=[];dispatches=[];audit=[];recovery_helpers=[]
    def extend_unique(target,values):
        seen={sha(canonical(row)) for row in target}
        for row in values:
            digest=sha(canonical(row))
            if digest not in seen:target.append(deepcopy(row));seen.add(digest)
    for current,files in payloads:
        if (current['runtime_sha256']!=manifest['runtime_sha256'] or
                files['runtime.json']!=payloads[0][1]['runtime.json']):
            raise AssertionError('one immutable runtime per restart case')
        for name in ('startup','readiness','native','child_slots','boundary_observations'):
            extend_unique(processes[name],json.loads(files['processes.json'])[name])
        old=json.loads(files['cleanup.json'])
        extend_unique(cleanup['receipts'],old['receipts']);extend_unique(cleanup['exports'],old['exports'])
        extend_unique(cleanup['supervisors'],old['supervisors'])
        # Every actual attempt survives the restart merge, including failure.
        # An earlier successful export cannot stand in for the later owner.
        recovery_helpers.extend(deepcopy(old.get('recovery_helpers',[])))
        cleanup['recovery']=deepcopy(old['recovery'])
        observed=json.loads(files['results.json'])
        results['operations'].extend(observed['operations'])
        results['boundary_proofs'].extend(observed['boundary_proofs'])
        extend_unique(instances,current['broker_instances']);dispatches.extend(current['dispatches'])
        audit.append(files['audit.jsonl'])
        for original in current['transcript']['segments']:
            raw=files['transcript.jsonl'][original['offset']:original['offset']+original['bytes']]
            if sha(raw)!=original['sha256']:raise AssertionError('original segment changed')
            if original['source']=='role_observer':
                if original['status']!='observer_complete':raise AssertionError('complete actual host observation required')
                observers.extend(validate_transcript_row(json.loads(line)) for line in raw.splitlines())
            else:
                segment=deepcopy(original);segment['offset']=sum(map(len,chunks))
                segments.append(segment);chunks.append(raw)  # includes any actual crash tail verbatim
        for name,raw in files.items():
            if name.startswith('client-'):
                if name in members:raise AssertionError('distinct dispatch capture required')
                members[name]=raw
    if observers:
        observers.sort(key=lambda row:row['observed_at_ns'])
        for index,row in enumerate(observers,1):row['row_sequence']=index;validate_transcript_row(row)
        raw=b''.join(canonical(row)+b'\n' for row in observers)
        if len(observers)>128 or len(raw)>262144:raise AssertionError('shared actual host evidence limit')
        segments.append({'source':'role_observer','broker_id':None,'offset':sum(map(len,chunks)),
            'bytes':len(raw),'sha256':sha(raw),'seals':None,'status':'observer_complete'})
        chunks.append(raw)
    for phase in ('initial','final','recovery'):
        candidates=[(m,f) for m,f in (payloads[-1:] if phase=='recovery' else payloads)
            if m['ledger_exports'][phase]['status']=='complete']
        if candidates:
            m,f=candidates[0] if phase=='initial' else candidates[-1]
            manifest['ledger_exports'][phase]=deepcopy(m['ledger_exports'][phase])
            name=manifest['ledger_exports'][phase]['file'];members[name]=f[name]
    if recovery_helpers:
        if (len(recovery_helpers)>2 or len({row['helper_id'] for row in recovery_helpers})!=len(recovery_helpers)
                or len({row['broker_id'] for row in recovery_helpers})!=len(recovery_helpers)):
            raise AssertionError('one retained recovery helper per actual owner')
        cleanup.update(schema_version='2',recovery_helpers=recovery_helpers)
    manifest['broker_instances']=instances;manifest['dispatches']=dispatches
    partial=any(row['status'].endswith('partial') for row in segments)
    manifest['transcript']={'status':'partial' if partial else 'complete',
        'segments':segments,'reason':'broker_lost' if partial else None}
    members.update({'runtime.json':payloads[0][1]['runtime.json'],'processes.json':canonical(processes),
        'results.json':canonical(results),'cleanup.json':canonical(cleanup),'audit.jsonl':b''.join(audit),
        'transcript.jsonl':b''.join(chunks)})
    manifest['members']=[{'name':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(members.items())]
    return manifest,members


def _old_dispatch_attempt(service,prepared,pointers):
    # The request reaches the new actual broker, which has never prepared this
    # old digest. No new reviewer reference is manufactured for the old owner.
    return _expected_failure(service,None,'prepare',
        lambda:service._broker.dispatch(**pointers),related=contract.prepared_digest(prepared))


def _send_copied_go(service,prepared,frame,directory):
    raw=canonical(frame);digest=sha(raw)
    private_write(directory/'copied-go.json',raw)
    _phase_observation(service,None,'go','begin',related=digest)
    sent_ticket,refused_ticket=_phase_ticket(service),_phase_ticket(service)
    channel=service._bundle.slots[0].ingress_host
    count=channel.send(raw)
    if count!=len(raw):raise AssertionError('one complete original GO packet required')
    _phase_observation(service,None,'go','end',related=digest,ticket=sent_ticket)
    private_write(directory/'copied-go-send.json',canonical({'sha256':digest,'bytes':len(raw),
        'actual_sent_bytes':count,'channel_id':service._bundle.slots[0].ingress_channel_id}))
    end=min(service._control.deadline,time.monotonic()+2)
    while time.monotonic()<end:
        for row in _live_rows(service):
            if row['kind']!='protocol':continue
            data=row['data'];actual=data['frame']
            if (data['channel_role']=='lifecycle' and data['direction']=='sent' and
                    actual['operation']=='BROKER_STOP'):
                _phase_observation(service,None,'go','refused',related=digest,
                    reason=actual['body']['reason'],ticket=refused_ticket)
                return
        time.sleep(.005)
    raise AssertionError('actual isolated copied-GO refusal not observed')


def _multi_core(case,directory,*,variants=None):
    from concurrent.futures import ThreadPoolExecutor
    from recon_cockpit.secure_agent.engagement_live_session import _HostEvidenceBudget
    from recon_cockpit.secure_agent.execution import ExecutionControl

    number=int(case['id'][-2:]);instrumentation=[_core_instrumentation(case)]
    if variants is not None:instrumentation+=variants.instrumentation
    if number==41:instrumentation.append(_core_instrumentation(case,'external_admin','broker'))
    payloads=[];before=None;selected=None;first=None;prepared=None;pointers=None
    host_evidence_budget=_HostEvidenceBudget()
    with terminal_input():
        with native_session(directory/'first',source_variants=variants,roe_transform=_core_roe(case),
                            host_evidence_budget=host_evidence_budget) as first:
            opened=first.open_session();before=first.snapshot()['ledger_state_sha256']
            if number==41:
                _external_change(first,None)
                _expected_failure(first,None,'prepare',lambda:first.prepare(opened['binding']['session_id'],'http_identify'))
            else:
                prepared=first.prepare(opened['binding']['session_id'],'http_identify')
                reference=review_actual(first,prepared)
                pointers=_pointers_actual(first,prepared,reference)
                if number in (43,44):
                    phase='reserve' if number==43 else 'go'
                    instrumentation.append(_core_instrumentation(case,'process_signal','broker'))
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        pending=pool.submit(_dispatch_pointers,first,prepared,pointers,0)
                        _signal_at_fixed_crash_phase(first,prepared,phase,'end',pending=pending)
                        _expected_failure(first,prepared,phase,
                            lambda:pending.result(timeout=max(.001,first._control.deadline-time.monotonic())))
                else:
                    result=_dispatch_pointers(first,prepared,pointers,0)
                    if result['outcome']!='useful':raise AssertionError('actual consumed allowance required')
        if not first._verified_reaped():raise AssertionError('first generation must be actually reaped')
        with _retain_payload_failure(first):
            payloads.append(first._evidence_payload(deadline=time.monotonic()+15,case_id=case['id'],
                instrumentation=instrumentation,recover=True))
        if number==23:
            before=_last_state(json.loads(payloads[0][1]['recovery-ledger.json']))
        old_go=None
        if number==54:
            from recon_cockpit.secure_agent import engagement_live_evidence as evidence
            rows,_=evidence._transcript(payloads[0][0],payloads[0][1]['transcript.jsonl'])
            releases=[r['row']['data']['frame'] for r in rows if r['source']=='broker_memfd' and
                r['row']['kind']=='protocol' and r['row']['data']['direction']=='sent' and
                r['row']['data']['channel_role']=='launcher' and r['row']['data']['frame']['operation']=='GO']
            if len(releases)!=1:raise AssertionError('one actual prior GO required')
            old_go=releases[0]
        second=None
        control=ExecutionControl(time.monotonic()+120)
        startup_ticket=(host_evidence_budget.reserve(kind='other_host',maximum_bytes=2048,
            maximum_rows=1,control=control) if number==41 else None)
        try:
            with native_session(directory/'second',source_variants=variants,
                    store_directory=first._store_directory,control=control,
                    host_evidence_budget=host_evidence_budget) as second:
                if number==41:raise AssertionError('revoked store unexpectedly started a broker')
                # An actual fresh session event independently binds the second
                # ledger owner. No new action is prepared for a stale retry.
                opened=second.open_session()
                if number==23:
                    target=second.prepare(opened['binding']['session_id'],'http_identify')
                    selected=[target['envelope']['dispatch_id']];reference=review_actual(second,target)
                    _expected_failure(second,target,'reserve',lambda:second.execute(target,reference,control=second._control))
                elif number==54:_send_copied_go(second,prepared,old_go,directory)
                else:_old_dispatch_attempt(second,prepared,pointers)
        except Exception as error:
            if number!=41 or isinstance(error,AssertionError):raise
            second=getattr(error,'engagement_session',second)
            if second is None:raise
            roe=json.loads((directory/'second'/'roe.json').read_bytes())
            _record_startup_guard(second,error,case,roe,ticket=startup_ticket)
        if second is None or not second._verified_reaped():raise AssertionError('second generation must be actually reaped')
        with _retain_payload_failure(second):
            payloads.append(second._evidence_payload(deadline=time.monotonic()+15,case_id=case['id'],
                instrumentation=instrumentation,recover=True))
    with _retain_payload_failure(second):
        manifest,members=_merge_core_payloads(payloads)
        return _write_case_payload(directory,_annotate_core_payload(manifest,members,case,
            before=before,selected=selected,deadline=time.monotonic()+15))


def _run_core_case(variant,directory):
    from recon_cockpit.secure_agent.engagement_live_evidence import _case
    matches=[_case('S42C-N'+str(i).zfill(2)) for i in range(1,55)]
    selected=[row for row in matches if row['variant']==variant]
    if len(selected)!=1:raise ValueError('fixed_core_case')
    case=deepcopy(selected[0]);directory=Path(directory)
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    if any(directory.iterdir()):raise AssertionError('fresh core case directory required')
    private_write(directory/'driver-source.py',Path(__file__).read_bytes())
    number=int(case['id'][-2:]);variants=None
    if case['id'] in STARTUP_GUARD_CASES:role='broker'
    elif case['id'] in BROKER_FAULT_CASES:role='broker'
    elif case['id'] in DEADLINE_FAULT_CASES:role='launcher'
    elif number in (40,45,46):role='endpoint'
    elif number in (8,9,15):role=_socket_case(case)['role']
    elif number==29:role='broker'
    elif number==51:role='audit'
    else:role=None
    if role is not None:
        variants=SourceVariants(directory/'source',case_id=case['id'],variant=variant,role=role)
        if case['id'] in STARTUP_GUARD_CASES:variants.source('engagement_live_broker_worker',_startup_guard_transform(case['id']))
        elif case['id'] in BROKER_FAULT_CASES:
            install_broker_fault(variants,case['id'])
            if number==44:_install_n44_launcher_hold(variants)
        elif case['id'] in DEADLINE_FAULT_CASES:install_deadline_fault(variants,case['id'])
        elif number in (40,45,46):_install_progress(variants,case)
        elif number in (8,9,15):supporting_socket_source(variants,case)
        elif number==29:_install_inclusive_clock(variants,case)
        elif number==51:_install_audit_fsync(variants)
    from contextlib import nullcontext
    with variants if variants is not None else nullcontext(), \
            _capture_startup_guard(case,directory) if case['id'] in STARTUP_GUARD_CASES else nullcontext():
        if number in (23,41,43,44,52,54):return _multi_core(case,directory,variants=variants)
        return _single_core(case,directory,variants=variants)


if __name__=='__main__':
    raise SystemExit(_main(sys.argv[1:]))
