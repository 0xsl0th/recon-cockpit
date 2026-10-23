"""S42C-I01..I20: saved synthetic evidence, not physical Linux witnesses."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import engagement_live_evidence as e
from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent import engagement_live_runtime as r

ROOT=Path(__file__).resolve().parents[1]
CLI=ROOT/'scripts/engagement_live_inspect.py'


def uid(n):return str(UUID(int=n,version=4))
def raw(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def sha(v):return hashlib.sha256(v).hexdigest()


def runtime():
    """Declared fixture rows only. No native image/process/kernel claim is made."""
    def file(destination):
        return {'source':'/usr/bin/python3' if destination.startswith('/tool/') else destination,
                'destination':destination,'size':1,'sha256':'a'*64}
    sources=[{'module':m,'destination':r._destination(m),'size':1,'sha256':'b'*64} for m in r.source_modules()]
    roles=[]
    for role in r.ROLES:
        destinations={'/usr/bin/python3','/lib64/ld-linux-x86-64.so.2'}
        if role=='nmap':destinations.add('/tool/nmap')
        if role=='endpoint':destinations.add('/usr/sbin/nft')
        if role=='parser':destinations.add('/lib/x86_64-linux-gnu/libffi.so.8')
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


def fixture():
    runtime_value=runtime()
    members={'runtime.json':raw({'schema_version':'1','runtime':runtime_value,'instrumentation':[]}),
        'processes.json':raw({'schema_version':'1','startup':[],'readiness':[],'native':[],'boundary_observations':[],'child_slots':[]}),
        'results.json':raw({'schema_version':'1','operations':[],'boundary_proofs':[],'core_proofs':[]}),
        'cleanup.json':raw({'schema_version':'1','receipts':[],'exports':[],'recovery':None,'supervisors':[]}),
        'audit.jsonl':b'','transcript.jsonl':b''}
    unavailable={'status':'unavailable','source':None,'file':None,'reason':'not_started','broker_id':None}
    manifest={'schema_version':'1','contract_sha256':e.CONTRACT_SHA256,'gates_sha256':e.GATES_SHA256,
        'evidence_class':'diagnostic','proof_kind':'role_boundary','case_id':None,'configuration':None,
        'review_mode':None,'runtime_sha256':sha(raw(runtime_value)),'instrumentation':[],
        'ledger_exports':{k:dict(unavailable) for k in ('initial','final','recovery')},
        'transcript':{'status':'unavailable','segments':[],'reason':'not_started'},
        'dispatches':[],'members':[],'broker_instances':[]}
    return repin(manifest,members)


def repin(manifest,members):
    manifest['members']=[{'name':n,'bytes':len(v),'sha256':sha(v)} for n,v in sorted(members.items())]
    return manifest,members


def attach_supervision_fixture(loaded, rows):
    """Declared host/child facts for pure replay tests, never a kernel witness.

    Rebuild after callers finalize their raw captures and process observations.
    This does not call the authority fixture, execute a child, or inspect files.
    """
    import base64
    from test_secure_engagement_live_runtime import declared_readiness, declared_cleanup
    from recon_cockpit.secure_agent import engagement_live_context as context
    bundle=loaded['runtime.json']['runtime']
    processes=loaded.setdefault('processes.json',{})
    processes.setdefault('schema_version','1');processes.setdefault('startup',[])
    processes.setdefault('readiness',[]);processes.setdefault('native',[])
    processes.setdefault('boundary_observations',[])
    cleanup=loaded.setdefault('cleanup.json',{'schema_version':'1','receipts':[],'exports':[],'recovery':None})
    cleanup.setdefault('supervisors',[]);processes['child_slots']=[]
    rows=[deepcopy(x) for x in rows if x['row']['kind']!='supervision_projection']
    sequences={}
    for index,op in enumerate(loaded['results.json']['operations']):
        op.setdefault('host_capture',None)
        p=op['prepared'];env=p['envelope'];did=env['dispatch_id'];broker=env['broker_id'];sid=env['session_id']
        go=next((x['row'] for x in rows if x['row']['kind']=='protocol' and
            x['row']['data']['frame']['operation']=='GO' and x['row']['dispatch_id']==did),None)
        if go is None:continue
        release=go['data']['frame']['body'];launcher_id=go['data']['frame']['channel_id'];anchor=env['clock_anchor']['mono_after_ns']
        def existing(role,worker=None):
            found=[x for x in processes['readiness'] if x['role']==role and
                   (worker is None or x['worker_ready']['worker_id']==worker)]
            if found:return found[0]
            value=declared_readiness(bundle,role,pid=500+index*100+len(processes['readiness'])*3,worker_id=worker)
            processes['readiness'].append(value);return value
        launcher=existing('launcher',launcher_id);endpoint=existing('endpoint',uid(60))
        observer=launcher['parent_observation']['observer']
        prefix='identify_' if env['slot']=='http_identify' else 'headers_'
        children={name:existing(role,uid(61) if name.endswith('admission') else None)
                  for name,(role,slot,fd) in context._CHILD_SLOTS.items() if slot==env['slot']}
        old_hashes={r._hash(value):value for value in children.values()}
        client_pid=children[prefix+'client']['parent_observation']['payload']['pid']
        client_finish=next((x['finished_at_ns'] for x in cleanup['receipts'] if
            len(x['processes'])==1 and x['processes'][0]['pid']==client_pid),anchor+150)
        slots={}
        for number,(name,(role,action,fd)) in enumerate(context._CHILD_SLOTS.items()):
            active=action==env['slot'];child=children.get(name)
            worker=child['worker_ready']['worker_id'] if active else uid(700+index*10+number)
            def endpoint_id(inode):return {'device':1,'inode':inode,'mode':stat.S_IFSOCK|0o600,'flags':2050}
            pair={'launcher_fd':fd,'request_endpoint':endpoint_id(10000+index*100+number*2),
                  'child_endpoint':endpoint_id(10001+index*100+number*2)}
            desc=next(x for x in launcher['parent_observation']['descriptors'] if x['fd']==fd)
            desc.update(pair['request_endpoint'])
            record={'schema_version':'1','broker_id':broker,'session_id':sid,'launcher_id':launcher_id,
                'child_slot':name,'role':role,'worker_id':worker,'pair':pair,
                'prepared_sha256':c.prepared_digest(p) if active else None,'bootstrap':None,'entry_sha256':None}
            processes['child_slots'].append(record);slots[name]=record
            if active:
                child['parent_observation']['sampled_at_ns']=(anchor-78 if name.endswith('client') else
                    anchor-68 if name.endswith('admission') else client_finish+4)
                desc=next(x for x in child['parent_observation']['descriptors'] if x['fd']==0)
                desc.update(pair['child_endpoint'])
                child['worker_ready']['descriptor_sha256']=r._hash(child['parent_observation']['descriptors'])
                binding={k:record[k] for k in ('child_slot','role','worker_id','pair')}
                boot=r.reconstruct_child_bootstrap(runtime=bundle,child_slot=binding,prepared=p,session=op['session'],
                    endpoint_identity=endpoint,observer=observer,deadline_ns=min(env['action_deadline_ns'],anchor+1000000000),launcher_id=launcher_id)
                record['bootstrap']={'deadline_ns':boot['deadline_ns'],'bytes':len(raw(boot)),'sha256':sha(raw(boot))}
                child['worker_ready']['bootstrap_sha256']=record['bootstrap']['sha256']
                entry=deepcopy(child['parent_observation']);entry['stage']='entry';entry['sampled_at_ns']-=2
                processes['startup']=[x for x in processes['startup'] if x['payload']!=entry['payload']]+[entry]
                record['entry_sha256']=sha(raw(entry))
        launcher['worker_ready']['descriptor_sha256']=r._hash(launcher['parent_observation']['descriptors'])
        child_cleanups={}
        for name,child in children.items():
            payload=child['parent_observation']['payload']
            found=[x for x in cleanup['receipts'] if len(x['processes'])==1 and
                x['processes'][0]['pid']==payload['pid'] and x['processes'][0]['start_time_ticks']==payload['start_time_ticks']]
            receipt=found[0] if found else declared_cleanup(child,started=anchor+120,finished=anchor+150)
            if name.endswith('admission'):receipt.update(started_at_ns=anchor+5,finished_at_ns=anchor+6,deadline_ns=anchor+2000000005)
            if name.endswith('parser'):receipt.update(started_at_ns=client_finish+6,finished_at_ns=client_finish+7,deadline_ns=client_finish+2000000006)
            if not found:cleanup['receipts'].append(receipt)
            child_cleanups[name]=receipt
        client_ready=children[prefix+'client'];parser_ready=children[prefix+'parser']
        native=next((x for x in processes['native'] if x['parent_observation']['payload']==client_ready['parent_observation']['payload']),None)
        if env['slot']=='http_identify':
            if native is None:
                parent=deepcopy(client_ready['parent_observation']);parent['stage']='native';parent['sampled_at_ns']=anchor+50
                image=next(x for x in next(z for z in bundle['roles'] if z['role']=='nmap')['native_files'] if x['destination']=='/tool/nmap')
                parent['executable'].update(destination='/tool/nmap',sha256=image['sha256'],size=image['size'])
                native={'schema_version':'1','role':'nmap','waiting_image':deepcopy(client_ready['parent_observation']['executable']),
                    'parent_observation':parent,'observed_at_ns':anchor+50};processes['native'].append(native)
            native['parent_observation']['descriptors']=deepcopy(client_ready['parent_observation']['descriptors'])
        client=op.get('client')
        if client is not None:
            client['readiness']['client_sha256']=sha(raw(client_ready))
            client['readiness']['native_sha256']=None if native is None else sha(raw(native))
            client['cleanup']=deepcopy(child_cleanups[prefix+'client'])
            if client['parser_receipt']is not None:
                client['parser_receipt']['readiness']=sha(raw(parser_ready))
                client['parser_receipt']['cleanup']=deepcopy(child_cleanups[prefix+'parser'])
            if op['result']is not None:
                op['result']['client_result_sha256']=sha(raw(client))
                op['result']['cleanup_sha256']=sha(raw(client['cleanup']))
        streams={name:loaded.setdefault('client-'+did+'.'+name+'.bin',b'x' if name=='stdout' else b'')
                 for name in ('stdout','stderr')}
        capture={'schema_version':'1','slot':env['slot'],'exit_code':0 if client is None else client['exit_code'],
                 'truncated':False if client is None else client['truncated']}
        for name,data in streams.items():capture.update({name+'_base64':base64.b64encode(data).decode(),
            name+'_bytes':len(data),name+'_sha256':sha(data)})
        op['host_capture']={k:v for k,v in capture.items() if not k.endswith('_base64')}
        op['host_capture'].update(status='succeeded' if client is None else client['status'],
            cleanup_sha256=sha(raw(child_cleanups[prefix+'client'])))
        for wrapped in rows:
            value=wrapped['row']
            if value['kind']!='protocol':continue
            frame=value['data']['frame'];body=frame['body']
            if frame['operation']=='OBSERVATION' and body['kind']=='role_readiness':
                old=sha(raw(body['data']))
                if old in old_hashes:body['data']=deepcopy(old_hashes[old])
            elif frame['operation']=='OBSERVATION' and body['kind']=='cleanup':
                identity=[(x['pid'],x['start_time_ticks']) for x in body['data']['processes']]
                match=next((x for x in child_cleanups.values() if
                    [(p['pid'],p['start_time_ticks']) for p in x['processes']]==identity),None)
                if match is not None:body['data']=deepcopy(match)
            if frame['operation']=='DISPATCH' and body.get('status')=='ok' and body.get('data',{}).get('dispatch_id')==did:
                body['data']=deepcopy(op['result'])
        def exchange(name,operation,body,result,projection,at):
            number=sequences.get(launcher_id,0)+1;sequences[launcher_id]=number
            response={'START':'BOOTSTRAP','OBSERVE_READY':'READY','NATIVE_BEGIN':'NATIVE_BUDGET',
                      'OBSERVE_NATIVE':'NATIVE','CAPTURE':'CAPTURED','REAP':'REAPED'}[operation]
            request={'schema_version':'1','channel_id':launcher_id,'sequence':number,'operation':operation,'body':body}
            reply={'schema_version':'1','channel_id':launcher_id,'sequence':number,'operation':response,
                'body':{'request_sequence':number,'status':'ok','code':None,'data':result}}
            projected={'child_slot':name}
            if operation=='START':projected['prepared_sha256']=c.prepared_digest(p)
            elif operation=='OBSERVE_READY':projected['bootstrap_sha256']=body['bootstrap_sha256']
            elif operation=='NATIVE_BEGIN':projected['release_sha256']=sha(raw(body['release']))
            def observed(frame,part,time):return {'sequence':number,'operation':frame['operation'],'observed_at_ns':time,
                'bytes':len(raw(frame)),'sha256':sha(raw(frame)),'projection':part,'projection_sha256':sha(raw(part))}
            reply_part={'request_sequence':number,'status':'ok','code':None,'data':projection}
            data={'kind':'rpc','launcher_id':launcher_id,'child_slot':name,'child_worker_id':slots[name]['worker_id'],
                'prepared_sha256':c.prepared_digest(p),'request':observed(request,projected,at),
                'reply':observed(reply,reply_part,at+1),'local_error':None}
            rows.append({'segment':1,'source':'role_observer','row':{'schema_version':'1','broker_id':broker,'session_id':sid,
                'dispatch_id':did,'observer_id':launcher_id,'row_sequence':1,'observed_at_ns':at+1,
                'kind':'supervision_projection','data':data}})
        def start(name,at):
            slot=slots[name];binding={k:slot[k] for k in ('child_slot','role','worker_id','pair')}
            boot=r.reconstruct_child_bootstrap(runtime=bundle,child_slot=binding,prepared=p,session=op['session'],
                endpoint_identity=endpoint,observer=observer,deadline_ns=slot['bootstrap']['deadline_ns'],launcher_id=launcher_id)
            exchange(name,'START',{'child_slot':name,'prepared':p},{'child_slot':name,'bootstrap':boot},
                {'child_slot':name,'bootstrap_sha256':sha(raw(boot)),'bootstrap_bytes':len(raw(boot))},at)
            ready=children[name]
            exchange(name,'OBSERVE_READY',{'child_slot':name,'bootstrap_sha256':sha(raw(boot))},
                {'child_slot':name,'readiness':ready},{'child_slot':name,'readiness_sha256':sha(raw(ready))},at+2)
        start(prefix+'client',anchor-80);start(prefix+'admission',anchor-70)
        name=prefix+'admission';receipt=child_cleanups[name]
        exchange(name,'REAP',{'child_slot':name},{'child_slot':name,'cleanup':receipt},
            {'child_slot':name,'cleanup_sha256':sha(raw(receipt))},anchor+5)
        name=prefix+'client';begin=anchor+7;stop=min(release['effect_stop_ns'],begin+(5000000000 if prefix=='identify_' else 1000000000))
        budget={'child_slot':name,'started_at_ns':begin,'native_deadline_ns':stop}
        exchange(name,'NATIVE_BEGIN',{'child_slot':name,'release':release},budget,budget,begin)
        if native is not None:exchange(name,'OBSERVE_NATIVE',{'child_slot':name},
            {'child_slot':name,'native_readiness':native},{'child_slot':name,'native_readiness_sha256':sha(raw(native))},anchor+50)
        receipt=child_cleanups[name];finished=receipt['finished_at_ns']
        exchange(name,'CAPTURE',{'child_slot':name},{'child_slot':name,'capture':capture,'status':op['host_capture']['status'],'cleanup':receipt},
            {'child_slot':name,'capture_sha256':sha(raw(capture)),'host_capture_sha256':sha(raw(op['host_capture'])),
             'status':op['host_capture']['status'],'cleanup_sha256':sha(raw(receipt))},finished)
        name=prefix+'parser';start(name,finished+2);receipt=child_cleanups[name]
        exchange(name,'REAP',{'child_slot':name},{'child_slot':name,'cleanup':receipt},
            {'child_slot':name,'cleanup_sha256':sha(raw(receipt))},max(finished+6,receipt['finished_at_ns']))
        end=max(x['row']['observed_at_ns'] for x in rows)+10
        cleanup['supervisors']=[row for row in cleanup['supervisors'] if row['launcher_id']!=launcher_id]+[{'schema_version':'1','broker_id':broker,'session_id':sid,'launcher_id':launcher_id,
            'host_observer':observer,'thread_native_id':1000+index,'thread_started_at_ns':anchor-1000,'state':'joined',
            'first_stop_requested_at_ns':end,'cleanup_started_at_ns':end,'cleanup_finished_at_ns':end+1,
            'cleanup_deadline_ns':end+2000000000,'join_attempted':True,'thread_alive_observed':False,
            'channel_closed':True,'pending_slots':[],'status':'complete'}]
        for ready in (launcher,endpoint):
            parent=ready['parent_observation']
            if not any(p['pid']==parent['payload']['pid'] and p['start_time_ticks']==parent['payload']['start_time_ticks']
                       for receipt in cleanup['receipts'] for p in receipt['processes']):
                cleanup['receipts'].append(declared_cleanup(ready,started=end,finished=end+1))
    counters={}
    for wrapped in rows:
        segment=wrapped['segment'];counters[segment]=counters.get(segment,0)+1
        wrapped['row']['row_sequence']=counters[segment]
    return loaded,rows


def unchecked_saved(path,manifest,members):
    """An edited private bundle bypasses the writer, never the inspector."""
    repin(manifest,members);path.mkdir(mode=0o700)
    for name,content in {**members,'manifest.json':raw(manifest)}.items():
        item=path/name;item.write_bytes(content);item.chmod(0o600)
    return path


def rewrite_audit(manifest,members,change):
    parts=[];found=0
    for segment in manifest['transcript']['segments']:
        encoded=members['transcript.jsonl'][segment['offset']:segment['offset']+segment['bytes']]
        rows=[json.loads(line) for line in encoded.splitlines()]
        for row in rows:
            if row['kind']=='protocol' and row['data']['frame']['operation']=='AUDIT_OBSERVED':
                change(row);found+=1
        parts.append((b''.join(raw(row)+b'\n' for row in rows),segment['source'],segment['broker_id'],segment['status']))
    assert found==1
    return with_transcript(manifest,members,parts)


def saved(tmp_path,manifest=None,members=None):
    tmp_path.chmod(0o700)
    if manifest is None:manifest,members=fixture()
    path=tmp_path/'bundle'
    result=e.write_live_bundle(path,manifest=manifest,members=members)
    assert result['status']=='packaged'
    return path


def denied_fixture():
    """Complete declared consistency fixture, never physical Linux evidence."""
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    manifest,members=fixture();bundle=json.loads(members['runtime.json'])['runtime']
    session,final=opened();session['binding']['runtime_sha256']=manifest['runtime_sha256']
    session=c.validate_session_opened(session)
    p=c.derive_prepared(session,'http_identify',dispatch_id=uid(8),clock=session['binding']['clock_anchor'])
    initial,_=ledger._apply(None,final['events'][0]['request'])
    ready=declared_readiness(bundle,'broker',pid=201,worker_id=uid(6))
    cleanup=declared_cleanup(ready,started=40000000000,finished=40100000000)
    result={'schema_version':'1','broker_id':uid(6),'session_id':uid(5),'dispatch_id':uid(8),
        'envelope_sha256':c.envelope_digest(p['envelope']),'slot':'http_identify','outcome':'denied',
        'reason':'engagement_live_approval_unknown_or_replayed','admission':None,'release':None,'completion':None,
        'observation':None,'client_result_sha256':None,'cleanup_sha256':None}
    c.validate_live_result(result)
    manifest.update({'evidence_class':'production_run','proof_kind':'live_operation','review_mode':'terminal',
        'broker_instances':[{'broker_id':uid(6),'ledger_owner_id':uid(4)}],
        'dispatches':[{'dispatch_id':uid(8),'session_id':uid(5),'slot':'http_identify','stdout_file':None,'stderr_file':None}]})
    exports=[]
    for i,(phase,value) in enumerate((('initial',initial),('final',final))):
        encoded=raw(value);name=phase+'-ledger.json';members[name]=encoded
        manifest['ledger_exports'][phase]={'status':'complete','source':'sealed_broker','file':name,'reason':None,'broker_id':uid(6)}
        reference={'phase':phase,'bytes':len(encoded),'device':11,'inode':20+i,'seals':15,'sha256':sha(encoded)}
        def descriptor(access):return {'fd':20+i,'purpose':phase+'_export_memfd','kind':'regular',
            'device':11,'inode':20+i,'mode':stat.S_IFREG|0o600,'flags':access}
        exports.append({'broker_id':uid(6),'reference':reference,'host_descriptor':descriptor(os.O_RDONLY),
            'broker_descriptor':descriptor(os.O_RDWR)})
    members['processes.json']=raw({'schema_version':'1','startup':[],'readiness':[ready],'native':[],'boundary_observations':[],'child_slots':[]})
    members['cleanup.json']=raw({'schema_version':'1','receipts':[cleanup],'exports':exports,'recovery':None,'supervisors':[]})
    members['results.json']=raw({'schema_version':'1','operations':[{'session':session,'prepared':p,'result':result,
        'client':None,'meter':None,'host_capture':None,'elapsed_ms':{key:None for key in e.TIMINGS}}],'core_proofs':[],'boundary_proofs':[]})
    rows=[]
    for i,(direction,body) in enumerate((('received',{'prepared_sha256':c.prepared_digest(p),'reference_sha256':'f'*64,
            'consume_sequence':1,'audit_sequence':1}),('sent',{'request_sequence':1,'status':'ok','code':None,'data':result})),1):
        rows.append({'schema_version':'1','broker_id':uid(6),'session_id':uid(5),'dispatch_id':uid(8),'observer_id':uid(6),
            'row_sequence':i,'observed_at_ns':11000000000+i,'kind':'protocol','data':{'channel_role':'ingress','direction':direction,
                'frame':{'schema_version':'1','channel_id':uid(98),'sequence':1,'operation':'DISPATCH','body':body}}})
    return with_transcript(manifest,members,[(b''.join(raw(row)+b'\n' for row in rows),'broker_memfd',uid(6),'sealed_complete')])


def useful_fixture(monkeypatch):
    """Declared native receipts plus actual pure codecs/meter; no kernel claim.

    Only the parser subprocess boundary is substituted by the accepted pure
    parser. The public writer/inspector and every consistency validator remain
    active, so coherently rewriting a manifest cannot bypass their crosslinks.
    """
    import base64
    from test_secure_engagement_live_witness import complete_authority_fixture
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    from test_secure_engagement_live_contract import M,clock
    from test_secure_engagement_live_meter import Stream
    from test_secure_network_tools_b7_parser import service_xml
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    from recon_cockpit.secure_agent import engagement_live_endpoint_worker as endpoint
    from recon_cockpit.secure_agent import engagement_live_context as context
    from recon_cockpit.secure_agent import configurable_parser
    manifest,members=fixture();bundle=json.loads(members['runtime.json'])['runtime']
    for role in bundle['roles']:
        for entry in role['native_files']:
            if entry['destination']=='/tool/nmap':entry['sha256']='d'*64
    bundle=r.validate_runtime(bundle);manifest['runtime_sha256']=sha(raw(bundle))
    loaded,rows=complete_authority_fixture(runtime_sha256=manifest['runtime_sha256'],runtime_bundle=bundle)
    operation=loaded['results.json']['operations'][0];p=operation['prepared'];env=p['envelope'];scope=operation['session']['scope']
    release=next(x['row']['data']['frame']['body'] for x in rows if x['row']['kind']=='protocol' and x['row']['data']['frame']['operation']=='GO')
    with monkeypatch.context() as local:
        local.setattr(c,'sample_clock',lambda:clock(100))
        local.setattr(endpoint.time,'monotonic_ns',lambda:M+100)
        meter=endpoint.Meter(p,uid(60),scope);meter.arm(release)
        meter.admit();assert meter.receive(Stream([b'']))==b''
        meter.admit();stream=Stream([endpoint.IDENTIFY_REQUEST])
        assert meter.receive(stream)==endpoint.IDENTIFY_RESPONSE and meter.send(stream)
        meter=meter.snapshot()
    output=service_xml().replace(b'127.0.0.1',scope['http']['target'].encode())
    parsed=configurable_parser.parse_output(p['action']['tool_id'],output,scope=scope,endpoint_id='http')
    readies=[declared_readiness(bundle,role,pid=200+20*i,worker_id=uid(2) if role=='broker' else uid(61) if role=='admission' else None)
             for i,role in enumerate(('broker','nmap','parser','admission'))]
    readies[0]=next(row for row in loaded['processes.json']['readiness'] if row['role']=='broker')
    cleanups=[declared_cleanup(ready,started=M+1000000,finished=M+2000000) for ready in readies]
    audit_ready=next(row['row']['data']['frame']['body'] for row in rows if
        row['row']['kind']=='protocol' and row['row']['data']['frame']['operation']=='AUDIT_OBSERVED')
    audit_cleanup=declared_cleanup({'role':'audit','parent_observation':audit_ready['parent_observation']},
        started=M+1000000,finished=M+2000000)
    native_parent=deepcopy(readies[1]['parent_observation']);native_parent['stage']='native';native_parent['sampled_at_ns']=M+50
    native_parent['executable'].update(destination='/tool/nmap',sha256='d'*64,inode=199)
    native={'schema_version':'1','role':'nmap','waiting_image':readies[1]['parent_observation']['executable'],
            'parent_observation':native_parent,'observed_at_ns':M+50}
    request={'schema_version':'1','slot':'http_identify','scope':scope,
             'raw_base64':base64.b64encode(output).decode(),'stderr_base64':'','truncated':False}
    reply={'schema_version':'1','slot':'http_identify','parsed':parsed}
    receipt={'schema_version':'1','slot':'http_identify','input_sha256':sha(raw(request)),
        'output_sha256':sha(raw(reply)),'input_bytes':len(raw(request)),'output_bytes':len(raw(reply)),
        'elapsed_ms':1,'readiness':sha(raw(readies[2])),'cleanup':cleanups[2]}
    client={'schema_version':'1','dispatch_id':env['dispatch_id'],'envelope_sha256':c.envelope_digest(env),
        'runtime_sha256':manifest['runtime_sha256'],'slot':'http_identify','status':'succeeded','exit_code':0,
        'stop_reason':None,'stdout_sha256':sha(output),'stderr_sha256':sha(b''),'stdout_bytes':len(output),
        'stderr_bytes':0,'truncated':False,'readiness':{'client_sha256':sha(raw(readies[1])),'native_sha256':sha(raw(native))},
        'meter':context.meter_summary(meter),'parsed':parsed,'parser_receipt':receipt,'cleanup':cleanups[1]}
    observation={'connections':meter['accepted_connections'],'request_bytes':meter['received_request_bytes'],
        'response_bytes':meter['sent_response_bytes'],'client_output_bytes':len(output),
        'parsed_sha256':sha(raw(parsed)),'meter_sha256':sha(raw(meter))}
    state=None
    for event in loaded['final-ledger.json']['events'][:-1]:state,_=ledger._apply(state,event['request'])
    completion_request=deepcopy(loaded['final-ledger.json']['events'][-1]['request'])
    completion_request['body']['clock']=clock(3000000)
    completion_request['body']['observation']={**{k:observation[k] for k in ('connections','request_bytes','response_bytes')},
        'evidence_sha256':sha(raw(observation))}
    state,completion=ledger._apply(state,completion_request);loaded['final-ledger.json']=state
    operation['result'].update(observation=observation,client_result_sha256=sha(raw(client)),cleanup_sha256=sha(raw(cleanups[1])),
        completion={'schema_version':'2','kind':'data_only','disposition':'recorded','receipt':completion})
    operation.update(client=client,meter=meter)
    manifest.update(evidence_class='production_run',proof_kind='live_operation',review_mode='terminal',
        broker_instances=[{'broker_id':uid(2),'ledger_owner_id':uid(3)}],
        dispatches=[{'dispatch_id':env['dispatch_id'],'session_id':env['session_id'],'slot':'http_identify',
                     'stdout_file':'client-'+env['dispatch_id']+'.stdout.bin','stderr_file':'client-'+env['dispatch_id']+'.stderr.bin'}])
    members.update({'runtime.json':raw({'schema_version':'1','runtime':bundle,'instrumentation':[]}),
        'processes.json':raw({'schema_version':'1','startup':[],'readiness':readies,'native':[native],'boundary_observations':[],'child_slots':[]}),
        'results.json':raw({'schema_version':'1','operations':[operation],'boundary_proofs':[],'core_proofs':[]}),
        'audit.jsonl':loaded['audit.jsonl'],'client-'+env['dispatch_id']+'.stdout.bin':output,
        'client-'+env['dispatch_id']+'.stderr.bin':b''})
    exports=[]
    for i,phase in enumerate(('initial','final')):
        name=phase+'-ledger.json';encoded=raw(loaded[name]);members[name]=encoded
        manifest['ledger_exports'][phase]={'status':'complete','source':'sealed_broker','file':name,'reason':None,'broker_id':uid(2)}
        reference={'phase':phase,'bytes':len(encoded),'device':11,'inode':20+i,'seals':15,'sha256':sha(encoded)}
        def descriptor(access):return {'fd':20+i,'purpose':phase+'_export_memfd','kind':'regular',
            'device':11,'inode':20+i,'mode':stat.S_IFREG|0o600,'flags':access}
        exports.append({'broker_id':uid(2),'reference':reference,'host_descriptor':descriptor(os.O_RDONLY),'broker_descriptor':descriptor(os.O_RDWR)})
    members['cleanup.json']=raw({'schema_version':'1','receipts':[*cleanups,audit_cleanup],'exports':exports,'recovery':None,'supervisors':[]})
    capture={'schema_version':'1','slot':'http_identify','stdout_base64':request['raw_base64'],
        'stderr_base64':'','stdout_sha256':sha(output),'stderr_sha256':sha(b''),
        'stdout_bytes':len(output),'stderr_bytes':0,'exit_code':0,'truncated':False}
    observations=[('role_readiness',ready) for ready in readies[1:]]+[
        ('cleanup',cleanup) for cleanup in cleanups[1:]]+[('capture',capture)]
    terminal=[row for row in rows if row['segment']==0 and row['row']['kind']=='protocol' and
        row['row']['data']['channel_role']=='ingress' and row['row']['data']['frame']['body'].get('status')=='ok']
    assert len(terminal)==1
    terminal[0]['row']['data']['frame']['body']['data']=deepcopy(operation['result'])
    terminal[0]['row']['observed_at_ns']=M+3000001
    broker_rows=[row for row in rows if row['segment']==0 and row is not terminal[0]]
    sequence=max(row['row']['data']['frame']['sequence'] for row in broker_rows if
        row['row']['kind']=='protocol' and row['row']['data']['frame']['channel_id']==uid(92) and
        row['row']['data']['direction']=='received')
    for index,(kind,data) in enumerate(observations,1):
        broker_rows.append({'segment':0,'source':'broker_memfd','row':{'schema_version':'1','broker_id':uid(2),
            'session_id':uid(4),'dispatch_id':env['dispatch_id'],'observer_id':uid(2),
            'row_sequence':len(broker_rows)+1,'observed_at_ns':M+2500000+index,'kind':'protocol',
            'data':{'channel_role':'launcher','direction':'received','frame':{'schema_version':'1',
                'channel_id':uid(92),'sequence':sequence+index,'operation':'OBSERVATION',
                'body':{'dispatch_id':env['dispatch_id'],'kind':kind,'data':deepcopy(data)}}}}})
    terminal[0]['row']['row_sequence']=len(broker_rows)+1
    rows=[*broker_rows,*terminal]+[row for row in rows if row['segment']==1]
    final_loaded={'manifest.json':manifest,**{name:(json.loads(data) if name.endswith('.json') else data)
        for name,data in members.items()}}
    final_loaded,rows=attach_supervision_fixture(final_loaded,rows)
    for name,data in final_loaded.items():
        if name!='manifest.json' and name!='transcript.jsonl':members[name]=raw(data) if name.endswith('.json') else data
    parts=[(b''.join(raw(row['row'])+b'\n' for row in rows if row['segment']==segment),source,
            uid(2) if segment==0 else None,'sealed_complete' if segment==0 else 'observer_complete')
           for segment,source in ((0,'broker_memfd'),(1,'role_observer'))]
    return with_transcript(manifest,members,parts)


def test_accepts_complete_useful_and_negative_reports(tmp_path,monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_parser,configurable_parser
    calls=[]
    def pure_parser(**kwargs):
        calls.append(kwargs)
        return configurable_parser.parse_output(kwargs['tool_id'],kwargs['raw'],kwargs['stderr'],
            scope=kwargs['scope'],endpoint_id='http',truncated=kwargs['truncated']),{}
    monkeypatch.setattr(engagement_live_parser,'parse',pure_parser)
    good=tmp_path/'useful';good.mkdir(mode=0o700)
    manifest,members=useful_fixture(monkeypatch)
    path=saved(good,manifest,members);before=snapshot(path)
    report=e.inspect_live_bundle(path)
    assert report['status']=='complete' and report['useful_operation_count']==1 and report['parser_replay_count']==1
    assert report['operations'][0]['reservation_observed'] is True and report['operations'][0]['go_observed'] is True
    assert snapshot(path)==before and len(calls)==1
    assert report['operations'][0]['counts']['connections']==2
    # Rewrite the entire durable completion, result and export custody hashes.
    # The unchanged real-model meter/raw/parser/cleanup still contradict it;
    # neither canonical rehashing nor a data-only receipt authenticates bytes.
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    for index,(field,value) in enumerate((('connections',1),('request_bytes',1),('response_bytes',1),
            ('client_output_bytes',1),('parsed_sha256','e'*64),('meter_sha256','e'*64),('cleanup_sha256','e'*64))):
        changed_manifest=deepcopy(manifest);changed_members=dict(members)
        results=json.loads(members['results.json']);result=results['operations'][0]['result']
        if field=='cleanup_sha256':result[field]=value
        else:result['observation'][field]=value
        export=json.loads(members['final-ledger.json']);state=None
        for event in export['events'][:-1]:state,_=ledger._apply(state,event['request'])
        request=deepcopy(export['events'][-1]['request'])
        request['body']['observation']={**{key:result['observation'][key] for key in
            ('connections','request_bytes','response_bytes')},'evidence_sha256':sha(raw(result['observation']))}
        state,receipt=ledger._apply(state,request);result['completion']['receipt']=receipt
        changed_members['final-ledger.json']=raw(state);changed_members['results.json']=raw(results)
        cleanup=json.loads(members['cleanup.json'])
        reference=next(row['reference'] for row in cleanup['exports'] if row['reference']['phase']=='final')
        reference.update(bytes=len(changed_members['final-ledger.json']),sha256=sha(changed_members['final-ledger.json']))
        changed_members['cleanup.json']=raw(cleanup)
        # Keep the actual-shaped terminal ACK coherent too: rejection must
        # still come from the unchanged raw/meter/client/process observations.
        parts=[]
        for segment in changed_manifest['transcript']['segments']:
            encoded=changed_members['transcript.jsonl'][segment['offset']:segment['offset']+segment['bytes']]
            segment_rows=[json.loads(line) for line in encoded.splitlines()]
            for row in segment_rows:
                if row['kind']=='protocol' and row['data']['channel_role']=='ingress' and row['data']['frame']['body'].get('status')=='ok':
                    row['data']['frame']['body']['data']=deepcopy(result)
            parts.append((b''.join(raw(row)+b'\n' for row in segment_rows),segment['source'],segment['broker_id'],segment['status']))
        with_transcript(changed_manifest,changed_members,parts)
        target=tmp_path/('coherent-rewrite-'+str(index))
        refused(e.write_live_bundle,target,manifest=changed_manifest,members=changed_members)
        assert not target.exists()
        # An attacker can bypass the writer; the inspector must independently
        # reject the same coherently rewritten private files.
        target.mkdir(mode=0o700)
        for name,content in {**changed_members,'manifest.json':raw(changed_manifest)}.items():
            child=target/name;child.write_bytes(content);child.chmod(0o600)
        refused(e.inspect_live_bundle,target)
    manifest,members=denied_fixture()
    report=e.inspect_live_bundle(saved(tmp_path,manifest,members))
    assert report['status']=='complete' and report['case_passed'] is None
    assert report['operations'][0]['outcome']=='denied' and report['useful_operation_count']==0
    assert report['operations'][0]['reservation_observed'] is False and report['operations'][0]['go_observed'] is False
    assert report['authority_restored'] is False and report['live_execution_started_by_inspection'] is False
    # Missing data is not upgraded to a known refusal merely by packaging it.
    altered=tmp_path/'incomplete';altered.mkdir(mode=0o700)
    values=json.loads(members['results.json']);values['operations'][0]['result']=None
    members['results.json']=raw(values);repin(manifest,members)
    report=e.inspect_live_bundle(saved(altered,manifest,members))
    assert report['status']=='incomplete' and report['operations'][0]['outcome']=='unresolved'
    assert report['operations'][0]['reservation_observed'] is None


def refused(function,*args,code=None,**kwargs):
    with pytest.raises(c.LiveError) as caught:function(*args,**kwargs)
    if code:assert caught.value.code=='engagement_live_'+code
    assert caught.value.code in c.ERROR_CODES
    return caught.value.code


def snapshot(path):
    return {p.name:(p.read_bytes(),p.stat().st_mode,p.stat().st_mtime_ns) for p in path.iterdir()}


def load_cli():
    spec=importlib.util.spec_from_file_location('live_inspect_test',CLI)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def test_rejects_unknown_duplicate_or_unbounded_fields():
    manifest,members=fixture()
    for key,value in [('unexpected',None),('schema_version',1),('contract_sha256','0'*64)]:
        changed=deepcopy(manifest);changed[key]=value;refused(e._manifest,changed)
    changed=deepcopy(manifest);changed['members'][0]['bytes']=True;refused(e._manifest,changed)
    refused(e._decode,b'{"x":1,"x":2}',1024)
    refused(e._decode,b'{"x":NaN}',1024)
    refused(e._decode,b'{"x":1.0}',1024)
    refused(e._decode,b'\xff',1024)
    refused(e._decode,b'[] ',1024)
    refused(e._decode,b'['*14+b'0'+b']'*14,1024,code='limit_exceeded')
    refused(e._decode,b'{}',1,code='limit_exceeded')
    assert (e.MAX_BUNDLE,e.MAX_REPORT,e.MAX_TRANSCRIPT_ROWS)==(16777216,8192,4096)
    bad=deepcopy(manifest);bad['members'].append(bad['members'][0]);refused(e._manifest,bad)
    assert e._manifest(manifest)==manifest


def test_refuses_unsafe_evidence_input_custody(tmp_path):
    path=saved(tmp_path)
    before=snapshot(path)
    link=tmp_path/'link';link.symlink_to(path,target_is_directory=True)
    refused(e.inspect_live_bundle,link,code='invalid_input')
    path.chmod(0o755);refused(e.inspect_live_bundle,path,code='invalid_input');path.chmod(0o700)
    member=path/'audit.jsonl';member.chmod(0o644);refused(e.inspect_live_bundle,path,code='invalid_input');member.chmod(0o600)
    extra=path/'extra';extra.write_bytes(b'');extra.chmod(0o600);refused(e.inspect_live_bundle,path);extra.unlink()
    backup=tmp_path/'hardlink';os.link(member,backup);refused(e.inspect_live_bundle,path,code='invalid_input');backup.unlink()
    original=member.read_bytes();member.unlink();member.symlink_to(tmp_path/'missing');refused(e.inspect_live_bundle,path,code='invalid_input')
    member.unlink();os.mkfifo(member,0o600);refused(e.inspect_live_bundle,path,code='invalid_input');member.unlink();member.write_bytes(original);member.chmod(0o600)
    # Store guard runs before any database file is opened, preserving POSIX locks.
    store=tmp_path/'store';store.mkdir(mode=0o700);(store/'records.sqlite3').write_bytes(b'not opened')
    refused(e.inspect_live_bundle,store,code='invalid_input')
    manifest,members=fixture();refused(e.write_live_bundle,path,manifest=manifest,members=members,code='output_exists')
    refused(e.write_live_bundle,tmp_path/'records.sqlite3',manifest=manifest,members=members,code='invalid_input')
    assert not (tmp_path/'records.sqlite3').exists()
    assert all((path/n).read_bytes()==value[0] for n,value in before.items())


def test_detects_evidence_identity_or_byte_changes(tmp_path,monkeypatch):
    path=saved(tmp_path)
    original=e._authority
    def mutate(loaded,rows,deadline):
        result=original(loaded,rows,deadline)
        member=path/'audit.jsonl';replacement=path/'replacement'
        replacement.write_bytes(member.read_bytes());replacement.chmod(0o600);replacement.replace(member)
        return result
    monkeypatch.setattr(e,'_authority',mutate)
    refused(e.inspect_live_bundle,path)
    monkeypatch.setattr(e,'_authority',original)
    manifest,members=fixture()
    target=tmp_path/'failed-output'
    fsync=e.os.fsync
    calls=[]
    def fault(fd):
        calls.append(fd)
        if len(calls)==2:raise OSError('private raw path must not escape')
        return fsync(fd)
    monkeypatch.setattr(e.os,'fsync',fault)
    refused(e.write_live_bundle,target,manifest=manifest,members=members,code='unavailable')
    assert target.is_dir() and list(target.iterdir()) and not (target/'manifest.json').exists()
    monkeypatch.setattr(e.os,'fsync',fsync)
    refused(e.write_live_bundle,target,manifest=manifest,members=members,code='output_exists')


def test_bounds_inspection_and_parser_cleanup(tmp_path,monkeypatch):
    path=saved(tmp_path)
    refused(e.inspect_live_bundle,path,deadline=time.monotonic()-1,code='timeout')
    original=e._context
    fake=[100.0]
    monkeypatch.setattr(e.time,'monotonic',lambda:fake[0])
    def consume(loaded,deadline):
        value=original(loaded,deadline);fake[0]=115.01;return value
    monkeypatch.setattr(e,'_context',consume)
    refused(e.inspect_live_bundle,path,code='timeout')
    monkeypatch.setattr(e,'_context',original)
    fake[0]=100.0
    close=e.os.close
    def slowclose(fd):
        close(fd);fake[0]+=16
    monkeypatch.setattr(e.os,'close',slowclose)
    refused(e.inspect_live_bundle,path,code='timeout')


def test_matches_immutable_python_and_cli_inspection(tmp_path):
    path=saved(tmp_path);before=snapshot(path)
    report=e.inspect_live_bundle(path)
    result=subprocess.run([sys.executable,'-B',str(CLI),str(path)],cwd=ROOT,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    assert result.returncode==1 and result.stderr==b''
    assert result.stdout==raw(report)+b'\n'
    assert snapshot(path)==before
    assert report['authority_restored'] is False and report['live_execution_started_by_inspection'] is False


def test_closes_cli_errors_and_stdout_failures(tmp_path,monkeypatch):
    for args in ([],['--exec'],['--help','--help'],['--store','sensitive-path'],['one','two']):
        result=subprocess.run([sys.executable,'-B',str(CLI),*args],cwd=ROOT,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        assert result.returncode==2 and result.stderr==b''
        assert json.loads(result.stdout)['error']=='engagement_live_invalid_input'
        assert b'sensitive-path' not in result.stdout
    child='import importlib.util,time; s=importlib.util.spec_from_file_location("cli",'+repr(str(CLI))+');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);raise SystemExit(0 if m._emit("{}",time.monotonic()+.05) else 2)'
    read_fd,write_fd=os.pipe()
    os.close(read_fd)
    try:
        result=subprocess.run([sys.executable,'-B','-c',child],stdout=write_fd,stderr=subprocess.PIPE,timeout=5)
        assert result.returncode==2 and result.stderr==b''
    finally:os.close(write_fd)
    read_fd,write_fd=os.pipe();os.set_blocking(write_fd,False)
    filled=0
    try:
        while True:
            try:filled+=os.write(write_fd,b'x'*4096)
            except BlockingIOError:break
        result=subprocess.run([sys.executable,'-B','-c',child],stdout=write_fd,stderr=subprocess.PIPE,timeout=5)
        assert result.returncode==2 and result.stderr==b''
    finally:os.close(write_fd)
    drained=b''
    try:
        while True:
            part=os.read(read_fd,65536)
            if not part:break
            drained+=part
    finally:os.close(read_fd)
    assert drained==b'x'*filled
    cli=load_cli()
    class Output:
        def fileno(self):return 1
        def flush(self):pass
    with monkeypatch.context() as patch:
        clock=[0.0];writes=[]
        patch.setattr(cli.time,'monotonic',lambda:clock[0])
        patch.setattr(cli.sys,'stdout',Output())
        patch.setattr(cli.os,'get_blocking',lambda fd:True)
        patch.setattr(cli.os,'set_blocking',lambda fd,value:None)
        patch.setattr(cli.os,'dup2',lambda source,target:None)
        def short(fd,content):
            writes.append((fd,content));clock[0]+=.6;return 1
        patch.setattr(cli.os,'write',short)
        assert cli._emit('{"long":"output"}',1.0) is False
        assert len(writes)==2 and all(fd==1 for fd,_ in writes)
    class Short:
        def write(self,value):return len(value)-1
        def flush(self):raise AssertionError('short write must stop before flush')
        def fileno(self):return 77
    monkeypatch.setattr(cli.sys,'stdout',Short())
    touched=[];monkeypatch.setattr(cli.os,'dup2',lambda a,b:touched.append((a,b)))
    assert cli._emit('{}',time.monotonic()+1) is False and touched==[]


def test_inspection_starts_no_live_authority_or_network(tmp_path,monkeypatch):
    path=saved(tmp_path)
    import socket
    def forbidden(*args,**kwargs):raise AssertionError('unexpected live execution')
    monkeypatch.setattr(socket,'socket',forbidden)
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    report=e.inspect_live_bundle(path)
    assert report['parser_replay_count']==0 and report['operation_count']==0
    assert not report['authority_restored'] and not report['live_execution_started_by_inspection']
    child='import runpy,sys;sys.argv=["inspect","--help"];\ntry: runpy.run_path('+repr(str(CLI))+',run_name="__main__")\nexcept SystemExit as e: assert e.code==0\nassert "sqlite3" not in sys.modules\n'
    # Deliberately separate help process after restoring the local Popen trap.
    monkeypatch.undo()
    result=subprocess.run([sys.executable,'-B','-c',child],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    assert result.returncode==0 and result.stderr==b''


def opened(mode='terminal'):
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    roe=json.loads((ROOT/'examples/secure-agent-engagement-roe.json').read_bytes())
    roe['window']={'start_utc':'2000-01-02T00:00:00Z','end_utc':'2000-01-03T00:00:00Z'}
    clock={'utc_ns':946771200000000000,'mono_before_ns':10000000000,'mono_after_ns':10000000000}
    create={'schema_version':'2','engagement_id':uid(1),'event_id':uid(2),'operation':'create',
            'expected_revision':None,'expected_generation':None,'body':roe}
    state,_=ledger._apply(None,create)
    session={'schema_version':'2','engagement_id':uid(1),'event_id':uid(3),'operation':'session',
        'expected_revision':1,'expected_generation':0,'body':{'owner_id':uid(4),'session_id':uid(5),
        'clock':clock,'original_deadline_ns':70000000000}}
    state,receipt=ledger._apply(state,session)
    binding=c.derive_session_binding(roe,engagement_id=uid(1),revision=1,generation=0,
        broker_id=uid(6),ledger_owner_id=uid(4),session_id=uid(5),reviewer_id=uid(7),review_mode=mode,
        runtime_sha256='a'*64,clock=clock,session_deadline_ns=70000000000,broker_deadline_ns=130000000000)
    value={'schema_version':'1','binding':binding,'session_receipt':{'schema_version':'2','kind':'data_only',
        'disposition':'recorded','receipt':receipt},'roe':roe,'scope':roe['scope'],'policy':ledger.policy_for_roe(roe)}
    return c.validate_session_opened(value),state


def prepared(mode='terminal'):
    session,_=opened(mode)
    return session,c.derive_prepared(session,'http_identify',dispatch_id=uid(8),clock=session['binding']['clock_anchor'])


def test_binds_both_review_views_to_current_action():
    for mode in ('terminal','graphical_v1'):
        session,p=prepared(mode)
        assert c.validate_prepared_context(p,session)==p
        for field,value in [('engagement_id',uid(99)),('ledger_owner_id',uid(99)),('session_id',uid(99)),
                            ('reviewer_id',uid(99)),('revision',2),('generation',1),('action_sha256','b'*64),
                            ('policy_sha256','b'*64),('runtime_sha256','b'*64),
                            ('review_mode','terminal' if mode=='graphical_v1' else 'graphical_v1')]:
            changed=deepcopy(p);changed['envelope'][field]=value
            refused(c.validate_prepared_context,changed,session)
        changed=deepcopy(p);changed['action']['parameters']['port']=8081
        refused(c.validate_prepared_context,changed,session)
        changed=deepcopy(p);changed['policy']['version']='different'
        refused(c.validate_prepared_context,changed,session)
        assert p['envelope']['review_mode']==mode


def audit_observation(p):
    """Actual legacy encoding of declared test data, not a live writer witness."""
    import base64
    from recon_cockpit.secure_agent import audit_protocol,audit_witness
    from recon_cockpit.secure_agent import engagement_live_witness as witness
    event=witness.started_event(p)
    packet={'version':'1','writer_id':uid(91),'audit_sequence':3,'sequence':1,
        'issued_at':10.0,'intent':audit_witness.claims(event),'event_digest':sha(audit_protocol.event_bytes(event))}
    encoded=audit_protocol.encode(packet)
    value={'producer_event':event,'producer_sha256':packet['event_digest'],
        'raw_base64':base64.b64encode(encoded).decode(),'raw_sha256':sha(encoded),'received_at_ns':10000000001}
    return value,{'version':'1','writer_id':uid(91),'device':10,'inode':11}


def test_requires_full_durable_audit_event_envelope(tmp_path,monkeypatch):
    import base64
    from recon_cockpit.secure_agent import audit_protocol,audit_witness
    from recon_cockpit.secure_agent import engagement_live_witness as witness
    session,p=prepared();value,source=audit_observation(p)
    observed=witness.validate_audit_observation(value,p,source=source,sequence=1)
    assert observed['event_sha256']==sha(audit_protocol.event_bytes(value['producer_event']))
    wrapper={**value['producer_event'],'event_schema_version':'1','event_id':uid(92),
        'timestamp':'2000-01-02T00:00:00Z','source':'recon-cockpit.secure-agent'}
    assert sha(audit_protocol.encode(wrapper))!=observed['event_sha256']
    assert witness._audit_events(audit_protocol.encode(wrapper)+b'\n')=={
        observed['event_sha256']:value['producer_event']}
    for field,change in [('producer_event',audit_witness.claims(value['producer_event'])),
            ('producer_sha256',sha(audit_protocol.encode(wrapper))),('raw_sha256','a'*64)]:
        bad=deepcopy(value);bad[field]=change
        refused(witness.validate_audit_observation,bad,p,source=source,sequence=1)
    for field,change in [('writer_id',uid(93)),('sequence',2),('audit_sequence',0),('event_digest','b'*64)]:
        bad=deepcopy(value);packet=audit_protocol.decode(base64.b64decode(bad['raw_base64']))
        packet[field]=change;encoded=audit_protocol.encode(packet)
        bad['raw_base64']=base64.b64encode(encoded).decode();bad['raw_sha256']=sha(encoded)
        refused(witness.validate_audit_observation,bad,p,source=source,sequence=1)
    # A coherently rehashed full event is still bound to the actual Prepared.
    bad=deepcopy(value);bad['producer_event']['engagement_live']['generation']+=1
    bad['producer_sha256']=sha(audit_protocol.event_bytes(bad['producer_event']))
    packet=audit_protocol.decode(base64.b64decode(bad['raw_base64']));packet['event_digest']=bad['producer_sha256']
    encoded=audit_protocol.encode(packet);bad['raw_base64']=base64.b64encode(encoded).decode();bad['raw_sha256']=sha(encoded)
    refused(witness.validate_audit_observation,bad,p,source=source,sequence=1)
    # Public saved replay enforces A07 custody too. These are declared portable
    # observations, not claims that a process or mounted image was inspected.
    from recon_cockpit.secure_agent import engagement_live_parser,configurable_parser
    monkeypatch.setattr(engagement_live_parser,'parse',lambda **kwargs:(
        configurable_parser.parse_output(kwargs['tool_id'],kwargs['raw'],kwargs['stderr'],
            scope=kwargs['scope'],endpoint_id='http',truncated=kwargs['truncated']),{}))
    manifest,members=useful_fixture(monkeypatch)
    original=unchecked_saved(tmp_path/'audit-good',deepcopy(manifest),dict(members))
    assert e.inspect_live_bundle(original)['status']=='complete'
    for variant in ('runtime_hash','mapping_identity','writable_mount','append_identity',
                    'writer_identity','reader_identity','direction','observer','channel'):
        changed_manifest=deepcopy(manifest);changed_members=dict(members)
        def mutate(row):
            data=row['data'];ready=data['frame']['body']
            if variant=='runtime_hash':ready['import_image']['sha256']='e'*64
            elif variant=='mapping_identity':
                image=ready['import_image'];image['inode']+=1
                next(d for d in ready['parent_observation']['descriptors'] if d['purpose']=='audit_import_libffi')['inode']=image['inode']
            elif variant=='writable_mount':ready['import_image']['read_only_mount']=False
            elif variant=='append_identity':ready['initial']['inode']+=1
            elif variant=='writer_identity':ready['initial']['witness'][1]+=1
            elif variant=='reader_identity':ready['source_manifest']['inode']+=1
            elif variant=='direction':data['direction']='sent'
            elif variant=='observer':row['observer_id']=uid(999)
            else:data['frame']['channel_id']=uid(999)
        rewrite_audit(changed_manifest,changed_members,mutate)
        path=unchecked_saved(tmp_path/('audit-'+variant),changed_manifest,changed_members);before=snapshot(path)
        refused(e.inspect_live_bundle,path)
        assert snapshot(path)==before
    changed_manifest=deepcopy(manifest);changed_members=dict(members)
    processes=json.loads(members['processes.json'])
    processes['readiness']=[row for row in processes['readiness'] if row['role']!='broker']
    changed_members['processes.json']=raw(processes)
    path=unchecked_saved(tmp_path/'audit-missing-broker',changed_manifest,changed_members)
    report=e.inspect_live_bundle(path)
    assert report['status']=='incomplete' and 'process_identity' in report['missing_evidence']
    assert report['operations'][0]['outcome']=='useful' # Retained result is not rewritten.


def test_replays_ledger_and_broker_state_together():
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    from recon_cockpit.secure_agent import engagement_live_witness as witness
    session,state=opened();p=c.derive_prepared(session,'http_identify',dispatch_id=uid(8),clock=session['binding']['clock_anchor'])
    op={'session':session,'prepared':p,'result':None,'client':None,'meter':None,'host_capture':None,
        'elapsed_ms':{key:None for key in e.TIMINGS}}
    manifest,members=fixture()
    loaded={name:(json.loads(value) if name.endswith('.json') else value) for name,value in members.items()}
    loaded.update({'manifest.json':manifest,'results.json':{'operations':[op]},'final-ledger.json':state,'audit.jsonl':b''})
    proof=witness.validate_evidence_transcript(loaded,[],deadline=time.monotonic()+15)
    assert proof['linkage']['dispatches'][uid(8)]['reservation_observed'] is None
    assert 'unsettled_dispatch' in proof['missing_evidence']
    for field,change in [('owner_id',uid(93)),('session_id',uid(94)),('original_deadline_ns',69000000000)]:
        requests=[deepcopy(row['request']) for row in state['events']]
        requests[1]['body'][field]=change
        rewritten=None
        for request in requests:rewritten,_=ledger._apply(rewritten,request)
        assert ledger.validate_export(rewritten)==rewritten
        bad=deepcopy(loaded);bad['final-ledger.json']=rewritten
        refused(witness.validate_evidence_transcript,bad,[],deadline=time.monotonic()+15)
    # Two individually valid exports with a rewritten ancestor cannot be joined.
    bad=deepcopy(loaded);bad['initial-ledger.json']=rewritten
    refused(witness.validate_evidence_transcript,bad,[],deadline=time.monotonic()+15)


def test_requires_single_winner_and_durable_race_order():
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    from recon_cockpit.secure_agent import engagement_live_witness as witness
    session,state=opened();p=c.derive_prepared(session,'http_identify',dispatch_id=uid(8),clock=session['binding']['clock_anchor'])
    before=deepcopy(state);sample=deepcopy(session['binding']['clock_anchor'])
    sample['utc_ns']+=1;sample['mono_before_ns']+=1;sample['mono_after_ns']+=1
    request={'schema_version':'2','engagement_id':uid(1),'event_id':uid(95),'operation':'reserve',
        'expected_revision':1,'expected_generation':0,'body':{'owner_id':uid(4),'session_id':uid(5),
        'dispatch_id':uid(8),'slot':'http_identify','clock':sample,
        'approval':{'broker_id':uid(7),'consume_sequence':1,'witness_sha256':'a'*64},
        'audit':{'writer_id':uid(91),'audit_sequence':1,'event_sha256':'b'*64}}}
    state,receipt=ledger._apply(state,request)
    release={'schema_version':'1','broker_id':uid(6),'ledger_owner_id':uid(4),'session_id':uid(5),'dispatch_id':uid(8),
        'envelope_sha256':c.envelope_digest(p['envelope']),'prepared_sha256':c.prepared_digest(p),
        'reservation_event_id':receipt['event_id'],'reservation_sequence':receipt['sequence'],
        'reservation_state_sha256':receipt['state_sha256'],'approval_witness_sha256':'a'*64,'audit_witness_sha256':'b'*64,
        'guard_clock':sample,'effective_lease_deadline_ns':20000000000,'effect_stop_ns':c.effect_stop(p,20000000000),'release_sequence':1}
    c.validate_release_binding(release,p,clock=sample)
    row={'schema_version':'1','broker_id':uid(6),'session_id':uid(5),'dispatch_id':uid(8),'observer_id':uid(6),
        'row_sequence':1,'observed_at_ns':sample['mono_after_ns'],'kind':'protocol','data':{'channel_role':'launcher',
        'direction':'sent','frame':{'schema_version':'1','channel_id':uid(96),'sequence':1,'operation':'GO','body':release}}}
    rows=[{'segment':0,'source':'broker_memfd','row':row}]
    op={'session':session,'prepared':p,'result':None,'client':None,'meter':None,'host_capture':None,'elapsed_ms':{key:None for key in e.TIMINGS}}
    manifest,members=fixture()
    loaded={name:(json.loads(value) if name.endswith('.json') else value) for name,value in members.items()}
    loaded.update({'manifest.json':manifest,'results.json':{'operations':[op]},'final-ledger.json':state,'audit.jsonl':b''})
    result=witness.validate_evidence_transcript(loaded,rows,deadline=time.monotonic()+15)
    assert result['linkage']['dispatches'][uid(8)]['go_observed'] is True
    assert 'transcript' in result['missing_evidence'] and 'unsettled_dispatch' in result['missing_evidence']
    # A second actual-shaped GO for one reservation cannot become a second winner.
    duplicate=deepcopy(rows[0]);duplicate['row']['row_sequence']=2;duplicate['row']['data']['frame']['sequence']=2
    refused(witness.validate_evidence_transcript,loaded,[*rows,duplicate],deadline=time.monotonic()+15)
    # No local result declaration can make a GO precede durable admission.
    bad=deepcopy(loaded);bad['final-ledger.json']=before
    refused(witness.validate_evidence_transcript,bad,rows,deadline=time.monotonic()+15)
    revoke={'schema_version':'2','engagement_id':uid(1),'event_id':uid(97),'operation':'revoke',
        'expected_revision':1,'expected_generation':0,'body':None}
    revoked_first,_=ledger._apply(before,revoke)
    bad['final-ledger.json']=revoked_first
    refused(witness.validate_evidence_transcript,bad,rows,deadline=time.monotonic()+15)
    with pytest.raises(ledger.DispatchLedgerError):ledger._apply(revoked_first,request)
    # Admission before revocation remains possibly sent, never rewritten as zero.
    admitted_first,_=ledger._apply(state,revoke);loaded['final-ledger.json']=admitted_first
    result=witness.validate_evidence_transcript(loaded,rows,deadline=time.monotonic()+15)
    assert result['linkage']['dispatches'][uid(8)]['reservation_observed'] is True
    assert result['linkage']['dispatches'][uid(8)]['go_observed'] is True
    assert result['linkage']['dispatches'][uid(8)]['result'] is None
    # The real reserve failure is an ok transport reply carrying a terminal
    # denied result; duplicate ingress rejection remains a refused reply.
    manifest,members=denied_fixture();operation=json.loads(members['results.json'])['operations'][0]
    operation['result']['reason']='engagement_live_allowance_exhausted'
    call={'request':{'prepared_sha256':c.prepared_digest(operation['prepared'])},
          'reply':{'status':'ok','code':None,'data':deepcopy(operation['result'])}}
    assert e._core_losing_call(call,[operation],24)
    assert not e._core_losing_call(call,[operation],27)
    for field,value in (('dispatch_id',uid(94)),('reason','engagement_live_revoked'),('outcome','unresolved')):
        changed=deepcopy(call);changed['reply']['data'][field]=value
        assert not e._core_losing_call(changed,[operation],24)
    changed=deepcopy(call);changed['request']['prepared_sha256']='e'*64
    assert not e._core_losing_call(changed,[operation],24)
    changed=deepcopy(operation);changed['result']=None
    assert not e._core_losing_call(call,[changed],24)
    duplicate=deepcopy(call);duplicate['reply']={'status':'refused','code':'engagement_live_dispatch_replayed','data':None}
    assert e._core_losing_call(duplicate,[operation],27) and not e._core_losing_call(duplicate,[operation],24)


def transcript_row(sequence=1,broker=None):
    return {'schema_version':'1','broker_id':broker,'session_id':None,'dispatch_id':None,
        'observer_id':uid(70),'row_sequence':sequence,'observed_at_ns':100,
        'kind':'phase','data':{'phase':'cleanup','stage':'end','original_deadline_ns':200,
                              'clock':None,'related_sha256':None,'reason':None}}


def with_transcript(manifest,members,parts):
    offset=0;segments=[]
    for content,source,broker,status in parts:
        segments.append({'source':source,'broker_id':broker,'offset':offset,'bytes':len(content),
            'sha256':sha(content),'seals':15 if status=='sealed_complete' else 0 if source=='broker_memfd' else None,
            'status':status});offset+=len(content)
    manifest['transcript']={'status':'partial' if any(x[-1].endswith('partial') for x in parts) else 'complete',
        'segments':segments,'reason':'broker_lost' if any(x[-1].endswith('partial') for x in parts) else None}
    members['transcript.jsonl']=b''.join(x[0] for x in parts)
    return repin(manifest,members)


def test_rejects_replayed_foreign_or_missing_channel_records(monkeypatch):
    manifest,members=fixture();broker=uid(80)
    manifest['broker_instances']=[{'broker_id':broker,'ledger_owner_id':uid(81)}]
    first=raw(transcript_row(1,broker))+b'\n'
    with_transcript(manifest,members,[(first,'broker_memfd',broker,'sealed_complete')])
    assert len(e._transcript(e._manifest(manifest),members['transcript.jsonl'])[0])==1
    for changed in (raw(transcript_row(2,broker))+b'\n',first+first,raw(transcript_row(1,uid(82)))+b'\n'):
        with_transcript(manifest,members,[(changed,'broker_memfd',broker,'sealed_complete')])
        refused(e._transcript,manifest,members['transcript.jsonl'])
    with_transcript(manifest,members,[(first+b'{"partial":','broker_memfd',broker,'reaped_partial'),
        (raw(transcript_row())+b'\n','role_observer',None,'observer_complete')])
    rows,tails=e._transcript(e._manifest(manifest),members['transcript.jsonl'])
    assert len(rows)==2 and tails==[0] and rows[1]['row']['row_sequence']==1
    # Moving the boundary may not splice an unfinished JSON row into host bytes.
    changed=deepcopy(manifest);changed['transcript']['segments'][1]['offset']-=1
    refused(e._manifest,changed)
    changed=deepcopy(manifest);changed['transcript']['segments'][0]['status']='sealed_complete'
    changed['transcript']['segments'][0]['seals']=15
    refused(e._transcript,changed,members['transcript.jsonl'])
    # Declared cross-generation observations exercise exact rejection layers;
    # no fake foreign-owner reply or new operation replaces the useful control.
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    from test_secure_engagement_live_contract import M,clock
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    manifest,members=useful_fixture(monkeypatch)
    loaded,original_rows,_=e._load_members(manifest,members,time.monotonic()+15)
    from recon_cockpit.secure_agent import engagement_live_context as context
    supervision=context.validate_supervision_transcript(loaded,original_rows)
    assert supervision['missing_evidence']==[] and supervision['all_closed']
    for variant in ('pair','worker','bootstrap','observer','capture','raw','source','wire','projection','sequence','late_begin'):
        bad=deepcopy(loaded);changed_rows=deepcopy(original_rows)
        slots=bad['processes.json']['child_slots'];slot=next(x for x in slots if x['child_slot']=='identify_client')
        rpc=next(x for x in changed_rows if x['row']['kind']=='supervision_projection')
        if variant=='pair':slot['pair']['child_endpoint']['inode']+=1000
        elif variant=='worker':slot['worker_id']=slots[1]['worker_id']
        elif variant=='bootstrap':slot['bootstrap']['sha256']='d'*64
        elif variant=='observer':bad['cleanup.json']['supervisors'][0]['host_observer']['namespaces']['pid']='pid:[999]'
        elif variant=='capture':bad['results.json']['operations'][0]['host_capture']['status']='failed'
        elif variant=='raw':
            name=bad['manifest.json']['dispatches'][0]['stdout_file'];bad[name]=bad[name]+b'!'
        elif variant=='source':rpc['source']='broker_memfd'
        elif variant=='wire':rpc['row']['data']['request']['sha256']='d'*64
        elif variant=='projection':
            request=rpc['row']['data']['request'];request['projection']['prepared_sha256']='d'*64
            request['projection_sha256']=sha(raw(request['projection']))
        elif variant=='sequence':rpc['row']['data']['request']['sequence']=2
        else:
            rpc=next(x for x in changed_rows if x['row']['kind']=='supervision_projection' and x['row']['data']['request']['operation']=='NATIVE_BEGIN')
            rpc['row']['data']['reply']['projection']['data']['started_at_ns']=rpc['row']['data']['reply']['observed_at_ns']+1
            rpc['row']['data']['reply']['projection_sha256']=sha(raw(rpc['row']['data']['reply']['projection']))
        refused(context.validate_supervision_transcript,bad,changed_rows)
    # Lost direct source remains missing evidence, even if a valid broker relay
    # still contains it. No digest-only row can reconstruct the absent fact.
    missing=deepcopy(loaded)
    missing['processes.json']['native']=[]
    assert 'transcript' in context.validate_supervision_transcript(missing,original_rows)['missing_evidence']
    # The causal error may be finalized before its already-received RPC. Keep
    # its actual timestamp and an absent reply; never manufacture a CAPTURED.
    partial=deepcopy(loaded);partial['results.json']['operations'][0].update(result=None,client=None)
    failed_rows=deepcopy(original_rows)
    capture_index=next(i for i,x in enumerate(failed_rows) if x['row']['kind']=='supervision_projection' and
        x['row']['data']['request']['operation']=='CAPTURE')
    request_row=failed_rows[capture_index];at=request_row['row']['data']['request']['observed_at_ns']
    failed_rows=[x for x in failed_rows[:capture_index+1] if x['row']['kind']!='supervision_projection' or
        x['row']['data']['request']['observed_at_ns']<=at]
    request_row['row']['data'].update(reply=None,local_error='engagement_live_timeout')
    request_row['row']['observed_at_ns']=at+3
    data=request_row['row']['data'];cause=deepcopy(request_row)
    cause['row']['observed_at_ns']=at+1
    cause['row']['data']={key:data[key] for key in ('launcher_id','child_slot','child_worker_id','prepared_sha256')}
    cause['row']['data'].update(kind='local_failure',code='engagement_live_timeout',observed_at_ns=at+1,
        capture_sha256=None,cleanup_sha256=None)
    final=deepcopy(cause);final['row']['observed_at_ns']=at+4;final['row']['data']['observed_at_ns']=at+4
    host=partial['results.json']['operations'][0]['host_capture']
    final['row']['data'].update(capture_sha256=sha(raw(host)),cleanup_sha256=host['cleanup_sha256'])
    failed_rows.remove(request_row);failed_rows.extend((cause,request_row,final))
    replay=context.validate_supervision_transcript(partial,failed_rows)
    assert 'transcript' in replay['missing_evidence'] and replay['dispatches'][uid(10)]['capture'] is not None
    late=deepcopy(failed_rows);extra=deepcopy(request_row)
    extra['row']['data']['request'].update(observed_at_ns=at+5,sequence=extra['row']['data']['request']['sequence']+1)
    late.append(extra);refused(context.validate_supervision_transcript,partial,late)
    operations=loaded['results.json']['operations'];op=operations[0];env=op['prepared']['envelope']
    second,owner,session=uid(201),uid(202),uid(203)
    ready=declared_readiness(loaded['runtime.json']['runtime'],'broker',pid=400,worker_id=second)
    ready['parent_observation']['sampled_at_ns']=M+5000000
    loaded['processes.json']['readiness'].append(ready)
    loaded['cleanup.json']['receipts'].append(declared_cleanup(ready,started=M+8000000,finished=M+9000000))
    loaded['manifest.json']['broker_instances'].append({'broker_id':second,'ledger_owner_id':owner})
    final,_=ledger._apply(loaded['final-ledger.json'],{'schema_version':'2','engagement_id':env['engagement_id'],
        'event_id':uid(204),'operation':'session','expected_revision':1,'expected_generation':0,
        'body':{'owner_id':owner,'session_id':session,'clock':clock(6000000),'original_deadline_ns':M+60000000000}})
    def observed(kind,data,at,source='broker_memfd'):
        return {'source':source,'segment':1,'row':{'schema_version':'1','row_sequence':1,
            'broker_id':second,'observer_id':second,'session_id':None,'dispatch_id':None,
            'observed_at_ns':M+at,'kind':kind,'data':data}}
    def packet(direction,operation,body,at,role='ingress'):
        return observed('protocol',{'channel_role':role,'direction':direction,'frame':{
            'schema_version':'1','channel_id':uid(205),'sequence':1,'operation':operation,'body':body}},at)
    digest=c.prepared_digest(op['prepared'])
    request=packet('received','DISPATCH',{'prepared_sha256':digest},7000000)
    reply=packet('sent','DISPATCH',{'request_sequence':1,'status':'refused',
        'code':'engagement_live_dispatch_replayed','data':None},7000001)
    def phase(name,stage,digest,at,reason=None):
        return observed('phase',{'phase':name,'stage':stage,'reason':reason,
            'related_sha256':digest,'original_deadline_ns':M+60000000000,'clock':None},at,'role_observer')
    attempt=phase('prepare','refused',digest,7000002,'engagement_live_dispatch_replayed')
    rows=[*original_rows,request,reply,attempt]
    assert operations[0]['result']['outcome']=='useful'
    assert e._restart_refusal(loaded,rows,operations,final,52)
    wrong=deepcopy(rows);wrong[-2]['row']['data']['frame']['body']['code']='engagement_live_foreign_owner'
    assert not e._restart_refusal(loaded,wrong,operations,final,52)
    assert not e._restart_refusal(loaded,rows,operations,loaded['final-ledger.json'],52)
    bad=deepcopy(loaded);bad['cleanup.json']['receipts']=[]
    assert not e._restart_refusal(bad,rows,operations,final,52)
    charged,_=ledger._apply(final,{'schema_version':'2','engagement_id':env['engagement_id'],'event_id':uid(206),
        'operation':'reserve','expected_revision':1,'expected_generation':0,'body':{'owner_id':owner,
        'session_id':session,'dispatch_id':uid(207),'slot':'http_identify','clock':clock(7000000),
        'approval':{'broker_id':uid(208),'consume_sequence':1,'witness_sha256':'c'*64},
        'audit':{'writer_id':uid(209),'audit_sequence':1,'event_sha256':'d'*64}}})
    assert not e._restart_refusal(loaded,rows,operations,charged,52)
    old_go=next(row['row']['data']['frame'] for row in original_rows if row['row']['kind']=='protocol' and
        row['row']['data']['channel_role']=='launcher' and row['row']['data']['frame']['operation']=='GO')
    loaded['cleanup.json']['receipts'][-1]['processes'][0].update(wrapper_returncode=0,signal_attempted=False)
    go_digest=sha(raw(old_go))
    begin=phase('go','begin',go_digest,7000000);end=phase('go','end',go_digest,7000001)
    stop=packet('sent','BROKER_STOP',{'reason':'engagement_live_invalid_frame'},7000002,'lifecycle')
    failure=phase('go','refused',go_digest,7000003,'engagement_live_session_unavailable')
    replay=[*original_rows,begin,end,stop,failure]
    assert e._restart_refusal(loaded,replay,operations,final,54)
    killed=deepcopy(loaded);killed['cleanup.json']['receipts'][-1]['processes'][0]['wrapper_returncode']=-9
    assert not e._restart_refusal(killed,replay,operations,final,54)
    bad=deepcopy(replay);bad[-3]['row']['data']['related_sha256']='e'*64
    assert not e._restart_refusal(loaded,bad,operations,final,54)
    bad=deepcopy(replay);bad[-2]['row']['data']['frame']['body']['reason']='engagement_live_cancelled'
    assert not e._restart_refusal(loaded,bad,operations,final,54)


def test_preserves_original_deadlines_through_cleanup(monkeypatch):
    session,p=prepared()
    stop=c.effect_stop(p,p['envelope']['action_deadline_ns'])
    assert stop==p['envelope']['action_deadline_ns']-2000000000
    changed=deepcopy(p);changed['envelope']['action_deadline_ns']+=1
    refused(c.validate_prepared,changed)
    clock=dict(session['binding']['clock_anchor'])
    clock['mono_before_ns']=clock['mono_after_ns']=p['envelope']['action_deadline_ns']
    clock['utc_ns']+=30000000000
    refused(c.check_clock,clock,anchor=session['binding']['clock_anchor'],
        window_start_utc_ns=p['envelope']['window_start_utc_ns'],window_end_utc_ns=p['envelope']['window_end_utc_ns'],
        deadline_ns=p['envelope']['action_deadline_ns'],code='timeout')
    # Fixed logical-expiry instrumentation retains actual OS timestamps and
    # native/cleanup observations; it never claims 30 seconds really elapsed.
    manifest,members=useful_fixture(monkeypatch)
    loaded,rows,_=e._load_members(manifest,members,time.monotonic()+15)
    op=loaded['results.json']['operations'][0];env=op['prepared']['envelope'];anchor=env['clock_anchor']
    original=env['action_deadline_ns'];actual_time=anchor['mono_after_ns']+500000
    native=deepcopy(next(row for row in rows if row['row']['kind']=='protocol' and
        row['row']['data']['frame']['operation']=='GO'))
    native['row']['observed_at_ns']=anchor['mono_after_ns']+50
    native['row']['data'].update(direction='received')
    native['row']['data']['frame'].update(operation='NATIVE_OBSERVED',body=loaded['processes.json']['native'][0])
    rows=[*rows,native]
    for case,target,variant in (('S42C-N34','native_observation','deadline_during_native'),
                               ('S42C-N35','cleanup','deadline_during_result_cleanup')):
        loaded['runtime.json']['instrumentation']=[{'source_sha256':'b'*64,
            'configuration':{'case_id':case,'variant':variant,'role':'launcher'}}]
        phase={'source':'broker_memfd','segment':0,'row':{'kind':'phase','broker_id':env['broker_id'],
            'observer_id':env['broker_id'],'session_id':env['session_id'],'dispatch_id':env['dispatch_id'],
            'observed_at_ns':actual_time,'data':{'phase':target,'stage':'refused','reason':'engagement_live_timeout',
                'original_deadline_ns':original,'related_sha256':c.prepared_digest(op['prepared']),
                'clock':{'mono_before_ns':original,'mono_after_ns':original,
                         'utc_ns':anchor['utc_ns']+original-anchor['mono_after_ns']}}}}
        assert actual_time<original and e._logical_deadline_fault(loaded,rows,op,phase,case)
        for key,value in (('original_deadline_ns',original+1),('related_sha256','e'*64),('phase','guard')):
            bad=deepcopy(phase);bad['row']['data'][key]=value
            assert not e._logical_deadline_fault(loaded,rows,op,bad,case)
        bad=deepcopy(phase);bad['row']['data']['clock']['utc_ns']+=1
        assert not e._logical_deadline_fault(loaded,rows,op,bad,case)
        bad=deepcopy(phase);bad['source']='role_observer'
        assert not e._logical_deadline_fault(loaded,rows,op,bad,case)
        bad=deepcopy(loaded);bad['runtime.json']['instrumentation']=[]
        assert not e._logical_deadline_fault(bad,rows,op,phase,case)
        assert not e._logical_deadline_fault(loaded,rows[:-1],op,phase,case)
        bad=deepcopy(loaded);bad['cleanup.json']['receipts']=[]
        assert not e._logical_deadline_fault(bad,rows,op,phase,case)
        if case=='S42C-N35':
            earlier=deepcopy(rows)
            for row in earlier:
                if row['row']['kind']=='protocol' and row['row']['data']['frame']['operation']=='OBSERVATION' and row['row']['data']['frame']['body']['kind']=='capture':
                    row['row']['observed_at_ns']=actual_time-1
            assert not e._logical_deadline_fault(loaded,earlier,op,phase,case)


def test_binds_runtime_sources_and_excludes_diagnostics(tmp_path):
    manifest,members=fixture()
    mutated=json.loads(members['runtime.json']);mutated['runtime']['sources'][0]['sha256']='d'*64
    members['runtime.json']=raw(mutated);repin(manifest,members)
    refused(e._load_members,manifest,members,time.monotonic()+15)
    manifest,members=fixture()
    changed=deepcopy(manifest);changed['evidence_class']='production_run'
    # A role-only empty proof cannot be relabeled ordinary live operation.
    refused(e._manifest,changed)
    report=e.inspect_live_bundle(saved(tmp_path,manifest,members))
    assert report['status']=='incomplete' and 'diagnostic_only' in report['missing_evidence']
    assert report['case_passed'] is None and report['useful_operation_count']==0


def test_retains_metric_nulls_and_separate_denominators(tmp_path):
    report=e.inspect_live_bundle(saved(tmp_path))
    assert report['operation_count']==report['useful_operation_count']==report['parser_replay_count']==0
    assert report['broker_instance_count']==0 and report['operations']==[]
    assert report['cleanup']=={'status':'not_started','observed_payloads':None,'reaped_payloads':None,'reaped_wrappers':None}
    assert all(value=='unavailable' for value in report['ledger_exports'].values())
    assert report['case_id'] is None and report['case_passed'] is None
    assert len(raw(report))<=8192


def test_reparses_raw_client_output_independently(monkeypatch):
    """Use the accepted pure parser as a portable double, never claim isolation."""
    import types
    from recon_cockpit.secure_agent import configurable_parser
    session,p=prepared()
    response=b'HTTP/1.0 200 OK\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n'
    scope=session['scope'];tool='configurable_http_headers_v1'
    observation=configurable_parser.parse_output(tool,response,scope=scope,endpoint_id='http')
    calls=[]
    def parser(**kwargs):
        kwargs['control'].check();calls.append(kwargs)
        try:
            parsed=configurable_parser.parse_output(kwargs['tool_id'],kwargs['raw'],kwargs['stderr'],
                scope=kwargs['scope'],endpoint_id='http',truncated=kwargs['truncated'])
        except ValueError:raise c.LiveError('engagement_live_parser_unavailable') from None
        return parsed,{'portable_test_double':True}
    monkeypatch.setitem(sys.modules,'recon_cockpit.secure_agent.engagement_live_parser',types.SimpleNamespace(parse=parser))
    dispatch=uid(8);stdout='client-'+dispatch+'.stdout.bin';stderr='client-'+dispatch+'.stderr.bin'
    p['action']['tool_id']=tool
    loaded={'results.json':{'operations':[{'prepared':p,'session':session,'client':{'parsed':observation,'truncated':False}}]},
        'manifest.json':{'dispatches':[{'dispatch_id':dispatch,'stdout_file':stdout,'stderr_file':stderr}]},
        'runtime.json':{'runtime':{'portable_fixture':True}},stdout:response,stderr:b''}
    assert e._reparse(loaded,time.monotonic()+15)==1 and len(calls)==1
    loaded[stdout]=response.replace(b'Server: Apache',b'Content-Security-Policy: default-src none')
    refused(e._reparse,loaded,time.monotonic()+15)
    loaded[stdout]=response;loaded[stderr]=b'unexpected diagnostic'
    refused(e._reparse,loaded,time.monotonic()+15,code='parser_unavailable')
    loaded[stderr]=b'';loaded['results.json']['operations'][0]['client']['parsed']={'forged':True}
    refused(e._reparse,loaded,time.monotonic()+15)
    loaded['results.json']['operations'][0]['client']['parsed']=None
    assert e._reparse(loaded,time.monotonic()+15)==0


def meter():
    import base64
    request=b'GET / HTTP/1.1\r\nHost: 10.77.0.10:8080\r\nConnection: close\r\n\r\n'
    response=b'HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n'
    events=[]
    def event(kind,requested,actual,remaining):
        events.append({'sequence':len(events)+1,'connection':1 if kind!='arm' else 0,'kind':kind,
            'monotonic_ns':100+len(events),'requested_bytes':requested,'actual_bytes':actual,
            'remaining_before':remaining,'remaining_after':remaining-actual,'reason':None})
    event('arm',0,0,0);event('accept',0,0,0)
    event('recv',256,len(request),256)
    event('send',len(response),7,2048)
    event('send',len(response)-7,len(response)-7,2041)
    event('close',0,0,0)
    events[-1]['reason']='complete'
    return {'schema_version':'1','endpoint_id':uid(90),'session_id':uid(5),'dispatch_id':uid(8),
        'envelope_sha256':'a'*64,'go_sha256':'b'*64,'arm_sequence':1,'slot':'http_headers',
        'accepted_connections':1,'received_request_bytes':len(request),'sent_response_bytes':len(response),
        'request_sha256':sha(request),'response_sha256':sha(response),
        'request_base64':base64.b64encode(request).decode(),'response_base64':base64.b64encode(response).decode(),
        'reason':'complete','delivery_known':True,'armed_at_ns':100,'finished_at_ns':105,'events':events}


def test_crosslinks_actual_bytes_connections_and_requests():
    from recon_cockpit.secure_agent import engagement_live_context as context
    original=meter();assert context.validate_meter(original)==original
    # Actual split writes, not the sum of requested write capacities, form delivery.
    assert sum(x['actual_bytes'] for x in original['events'] if x['kind']=='send')==original['sent_response_bytes']
    for key,value in [('received_request_bytes',0),('sent_response_bytes',0),('accepted_connections',0),
                       ('request_sha256','c'*64),('response_sha256','c'*64),('delivery_known',1)]:
        changed=deepcopy(original);changed[key]=value;refused(context.validate_meter,changed)
    for key in ('actual_bytes','remaining_before','remaining_after'):
        changed=deepcopy(original);changed['events'][3][key]+=1;refused(context.validate_meter,changed)
    changed=deepcopy(original);changed['events'][3]['requested_bytes']=2049
    refused(context.validate_meter,changed)
    changed=deepcopy(original);changed['events'][3]['requested_bytes']+=1
    assert context.validate_meter(changed)==changed
    changed=deepcopy(original);changed['events'][3]['actual_bytes']=0
    changed['events'][3]['remaining_after']=changed['events'][3]['remaining_before']
    refused(context.validate_meter,changed)


def test_retains_partial_and_unobserved_outcomes(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_context as context
    unknown=meter();unknown.update({'delivery_known':False,'reason':'unresolved',
        'accepted_connections':None,'received_request_bytes':None,'sent_response_bytes':None,'finished_at_ns':None})
    unknown['events'].pop() # Retained prefix has no observed terminal close.
    assert context.validate_meter(unknown)==unknown
    for key in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns'):
        changed=deepcopy(unknown);changed[key]=0;refused(context.validate_meter,changed)
    session,p=prepared();dispatch=uid(8)
    manifest,members=fixture();manifest['dispatches']=[{'dispatch_id':dispatch,'session_id':uid(5),
        'slot':'http_identify','stdout_file':None,'stderr_file':None}]
    loaded={'manifest.json':manifest,'cleanup.json':json.loads(members['cleanup.json']),
        'processes.json':json.loads(members['processes.json']),
        'results.json':{'operations':[{'session':session,'prepared':p,'result':None,'client':None,
            'meter':None,'host_capture':None,'elapsed_ms':{key:None for key in e.TIMINGS}}]}}
    authority={'missing_evidence':['unsettled_dispatch'],'linkage':{'dispatches':{dispatch:
        {'reservation_observed':None,'go_observed':None}}}}
    report=e._report(loaded,{},authority,'d'*64,0,[])
    op=report['operations'][0]
    assert op['outcome']=='unresolved' and op['reservation_observed'] is None and op['go_observed'] is None
    assert all(value is None for value in op['counts'].values())
    assert report['status']=='incomplete' and report['useful_operation_count']==0
    # A missing client result must not sever real retained capture/METER links.
    manifest,members=useful_fixture(monkeypatch)
    results=json.loads(members['results.json']);results['operations'][0].update(result=None,client=None)
    members['results.json']=raw(results);repin(manifest,members)
    loaded,_,_=e._load_members(manifest,members,time.monotonic()+15)
    context.validate_live_context(loaded)
    stdout=manifest['dispatches'][0]['stdout_file']
    altered=deepcopy(loaded);altered[stdout]=loaded[stdout][:-1]+b'!'
    refused(context.validate_live_context,altered)
    altered=deepcopy(loaded)
    altered['results.json']['operations'][0]['meter']['events'][1]['monotonic_ns']+=1
    refused(context.validate_live_context,altered)
    altered=deepcopy(loaded);altered['results.json']['operations'][0]['meter']=None
    refused(context.validate_live_context,altered)
    # This is solely report policy after a separately verified gate predicate:
    # the absent real ACK remains null, even when a negative case is complete.
    m=loaded['manifest.json'];did=m['dispatches'][0]['dispatch_id']
    m.update(evidence_class='owned_gate',case_id='S42C-N33')
    loaded['results.json']['core_proofs']=[{'dispatch_ids':[did]}]
    authority={'missing_evidence':['unsettled_dispatch'],'linkage':{'dispatches':{did:
        {'reservation_observed':None,'go_observed':None}}}}
    monkeypatch.setattr(e,'_evaluate_case',lambda *_:True)
    report=e._report(loaded,{},authority,'d'*64,0,[])
    assert report['status']=='complete' and report['case_passed'] is True
    assert report['operations'][0]['outcome']=='unresolved' and report['useful_operation_count']==0
    assert report['operations'][0]['reservation_observed'] is None
    loaded['results.json']['core_proofs'][0]['dispatch_ids']=[]
    assert 'unsettled_dispatch' in e._report(loaded,{},authority,'d'*64,0,[])['missing_evidence']
    loaded['results.json']['core_proofs'][0]['dispatch_ids']=[did]
    missing=deepcopy(authority);missing['missing_evidence'].append('transcript')
    assert e._report(loaded,{},missing,'d'*64,0,[])['missing_evidence']==['transcript']
    monkeypatch.setattr(e,'_evaluate_case',lambda *_:False)
    assert set(e._report(loaded,{},authority,'d'*64,0,[])['missing_evidence'])=={'case_predicate','unsettled_dispatch'}
    # A no-operation restart rejection can be resolved only by its strict
    # predicate plus actual recovery, without creating a phantom dispatch.
    monkeypatch.setattr(e,'_evaluate_case',lambda *_:True)
    m.update(case_id='S42C-N41',dispatches=[])
    loaded['results.json']['operations']=[];loaded['results.json']['core_proofs']=[{'dispatch_ids':[]}]
    loaded['cleanup.json']['recovery']={'source':'postcleanup_readonly'}
    report=e._report(loaded,{}, {'missing_evidence':[],'linkage':{'dispatches':{}}},'d'*64,0,[])
    assert report['status']=='complete' and report['operation_count']==report['useful_operation_count']==0


def test_binds_cleanup_to_actual_process_identity(tmp_path,monkeypatch):
    # Independent saved-identity crosslink; no current PID or synthetic kernel claim.
    identity={'pid':1234,'parent_pid':1233,'start_time_ticks':5678}
    process={'role':'parser','pid':1234,'start_time_ticks':5678,'pin_verified':True,
        'signal_attempted':False,'exit_observed':True,'reaped_observed':True,
        'wrapper_pid':1233,'wrapper_returncode':0}
    loaded={'processes.json':{'child_slots':[],'startup':[],'readiness':[{'parent_observation':{'payload':identity}}],'native':[]},
        'manifest.json':{'transcript':{'segments':[]}},'transcript.jsonl':b'',
        'cleanup.json':{'supervisors':[],'receipts':[{'schema_version':'1','started_at_ns':100,'finished_at_ns':200,
            'deadline_ns':2000000100,'status':'complete','descriptors_closed':True,'processes':[process]}]}}
    assert e._all_reaped(loaded)
    for key,value in [('pid',4321),('start_time_ticks',5679),('reaped_observed',False),
                       ('exit_observed',False),('wrapper_returncode',None),('wrapper_pid',None)]:
        changed=deepcopy(loaded);changed['cleanup.json']['receipts'][0]['processes'][0][key]=value
        assert not e._all_reaped(changed)
    changed=deepcopy(loaded);changed['cleanup.json']['receipts']=[]
    assert not e._all_reaped(changed)
    # Verified emergency reaping can be saved despite a failed original timing.
    loaded['cleanup.json']['receipts'][0]['status']='failed'
    assert e._all_reaped(loaded) and e._cleanup_report(loaded)['status']=='incomplete'
    individual=deepcopy(loaded['cleanup.json']['receipts'][0]);individual['status']='complete'
    loaded['cleanup.json']['receipts'].insert(0,individual)
    assert e._cleanup_processes(loaded)==[process] and e._all_reaped(loaded)
    report=e._cleanup_report(loaded)
    assert report['observed_payloads']==report['reaped_payloads']==report['reaped_wrappers']==1
    assert report['status']=='incomplete' # Aggregate timing failure survives.
    for key,value in [('signal_attempted',True),('wrapper_returncode',78),('role','broker')]:
        bad=deepcopy(loaded);bad['cleanup.json']['receipts'][-1]['processes'][0][key]=value
        assert e._cleanup_processes(bad) is None and not e._all_reaped(bad)
        refused(e._cleanup_report,bad)
    # The accepted audit worker is observed in the real-shaped broker
    # transcript, not an invented new-role compound readiness record.
    from recon_cockpit.secure_agent import engagement_live_parser,configurable_parser
    from recon_cockpit.secure_agent import engagement_live_context as context
    monkeypatch.setattr(engagement_live_parser,'parse',lambda **kwargs:(
        configurable_parser.parse_output(kwargs['tool_id'],kwargs['raw'],kwargs['stderr'],
            scope=kwargs['scope'],endpoint_id='http',truncated=kwargs['truncated']),{}))
    manifest,members=useful_fixture(monkeypatch)
    complete=unchecked_saved(tmp_path/'cleanup-good',deepcopy(manifest),dict(members))
    good=e.inspect_live_bundle(complete)
    assert good['status']=='complete' and good['cleanup']['observed_payloads']==7
    direct,_,_=e._load_members(manifest,members,time.monotonic()+15)
    assert context._supervisor_closure(direct)=={'all_closed':True,'complete':True}
    # INITIAL preallocates both groups. The unused group's sockets really
    # close, but no launcher, child, thread or join is invented for it.
    unused=deepcopy(direct)
    for number,slot in enumerate(direct['processes.json']['child_slots']):
        item=deepcopy(slot)
        item.update(session_id=uid(810),launcher_id=uid(811),worker_id=uid(812+number),
            prepared_sha256=None,bootstrap=None,entry_sha256=None)
        item['pair']['request_endpoint']['inode']=20000+number*2
        item['pair']['child_endpoint']['inode']=20001+number*2
        unused['processes.json']['child_slots'].append(item)
    not_started=deepcopy(direct['cleanup.json']['supervisors'][0])
    not_started.update(session_id=uid(810),launcher_id=uid(811),state='not_started',
        thread_native_id=None,thread_started_at_ns=None,join_attempted=False)
    unused['cleanup.json']['supervisors'].append(not_started)
    assert context._supervisor_closure(unused)=={'all_closed':True,'complete':True}
    assert context.validate_supervision_transcript(unused)['missing_evidence']==[]
    unused_members=dict(members)
    for name in ('processes.json','cleanup.json'):unused_members[name]=raw(unused[name])
    unused_manifest=deepcopy(manifest);repin(unused_manifest,unused_members)
    unused_path=tmp_path/'unused-allocation'
    assert e.write_live_bundle(unused_path,manifest=unused_manifest,members=unused_members)['status']=='packaged'
    assert e.inspect_live_bundle(unused_path)['status']=='complete'
    unclosed=deepcopy(unused);unclosed['cleanup.json']['supervisors'].pop()
    assert not context._supervisor_closure(unclosed)['all_closed']
    # A started launcher with a known denial still requires its six retained
    # socket declarations and actual thread closure. Deleting both together
    # cannot turn the launcher into an unobserved/not-started allocation.
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    negative_manifest,negative_members=denied_fixture()
    negative,_,_=e._load_members(negative_manifest,negative_members,time.monotonic()+15)
    launcher=declared_readiness(negative['runtime.json']['runtime'],'launcher',pid=801,worker_id=uid(820))
    envelope=negative['results.json']['operations'][0]['prepared']['envelope']
    for number,slot in enumerate(unused['processes.json']['child_slots'][6:]):
        item=deepcopy(slot);item.update(broker_id=envelope['broker_id'],session_id=envelope['session_id'],launcher_id=uid(820))
        descriptor=next(x for x in launcher['parent_observation']['descriptors'] if x['fd']==item['pair']['launcher_fd'])
        descriptor.update(item['pair']['request_endpoint'])
        negative['processes.json']['child_slots'].append(item)
    launcher['worker_ready']['descriptor_sha256']=r._hash(launcher['parent_observation']['descriptors'])
    negative['processes.json']['readiness'].append(launcher)
    negative['cleanup.json']['receipts'].append(declared_cleanup(launcher,started=40000000000,finished=40100000000))
    thread=deepcopy(direct['cleanup.json']['supervisors'][0])
    thread.update(broker_id=envelope['broker_id'],session_id=envelope['session_id'],launcher_id=uid(820))
    negative['cleanup.json']['supervisors'].append(thread)
    assert context.validate_supervision_transcript(negative)['missing_evidence']==[]
    assert context._supervisor_closure(negative)=={'all_closed':True,'complete':True}
    for removed in ('all','one'):
        changed=deepcopy(negative)
        if removed=='all':
            changed['processes.json']['child_slots']=[];changed['cleanup.json']['supervisors']=[]
        else:changed['processes.json']['child_slots'].pop()
        assert not context._supervisor_closure(changed)['all_closed'] and not e._all_reaped(changed)
        assert {'cleanup','transcript'}<=set(context.validate_supervision_transcript(changed)['missing_evidence'])
        altered=dict(negative_members)
        for name in ('processes.json','cleanup.json'):altered[name]=raw(changed[name])
        changed_manifest=deepcopy(negative_manifest);repin(changed_manifest,altered)
        target=unchecked_saved(tmp_path/('missing-launcher-allocation-'+removed),changed_manifest,altered)
        report=e.inspect_live_bundle(target)
        assert report['status']=='incomplete' and report['operations'][0]['outcome']=='denied'
        assert {'cleanup','transcript'}<=set(report['missing_evidence'])
        refused(e.write_live_bundle,tmp_path/('refuse-missing-allocation-'+removed),
            manifest=changed_manifest,members=altered,code='cleanup_incomplete')
    for state,alive in (('alive',True),('unknown',None)):
        changed=deepcopy(direct);thread=changed['cleanup.json']['supervisors'][0]
        thread.update(state=state,thread_alive_observed=alive,status='failed',channel_closed=False)
        assert not context._supervisor_closure(changed)['all_closed'] and not e._all_reaped(changed)
    changed=deepcopy(direct);changed['cleanup.json']['supervisors']=[]
    assert not context._supervisor_closure(changed)['all_closed']
    changed=deepcopy(direct);thread=changed['cleanup.json']['supervisors'][0]
    thread.update(cleanup_finished_at_ns=thread['cleanup_deadline_ns']+1,status='failed')
    assert context._supervisor_closure(changed)=={'all_closed':True,'complete':False}
    assert e._all_reaped(changed) and e._cleanup_report(changed)['status']=='incomplete'
    for variant in ('duplicate','renewed','false_not_started','missing_tid','descriptor_open','late_thread','early_join'):
        changed=deepcopy(direct);thread=changed['cleanup.json']['supervisors'][0]
        if variant=='duplicate':changed['cleanup.json']['supervisors'].append(deepcopy(thread))
        elif variant=='renewed':thread['cleanup_deadline_ns']=thread['first_stop_requested_at_ns']+2000000001
        elif variant=='false_not_started':thread.update(state='not_started',thread_native_id=None,thread_started_at_ns=None,join_attempted=False)
        elif variant=='missing_tid':thread['thread_native_id']=None
        elif variant=='late_thread':thread['thread_started_at_ns']=thread['first_stop_requested_at_ns']
        elif variant=='early_join':
            thread['cleanup_finished_at_ns']=thread['cleanup_started_at_ns']=thread['first_stop_requested_at_ns']=10000000001
            thread['cleanup_deadline_ns']=12000000001
        else:
            child=next(row for row in changed['cleanup.json']['receipts'] if row['processes'][0]['role']=='nmap')
            child.update(descriptors_closed=False,status='failed');thread['status']='failed'
            assert not context._supervisor_closure(changed)['all_closed'] and not e._all_reaped(changed)
            continue
        refused(context._supervisor_closure,changed)
    for variant in ('missing','duplicate','role','wrapper','start','pid','chronology',
                    'descriptors','pin','reap','wrapper_exit','failed'):
        changed_manifest=deepcopy(manifest);changed_members=dict(members)
        cleanup=json.loads(members['cleanup.json'])
        actual=next(row for row in cleanup['receipts'] if row['processes'][0]['role']=='audit')
        process=actual['processes'][0]
        if variant=='missing':cleanup['receipts'].remove(actual)
        elif variant=='duplicate':cleanup['receipts'].append(deepcopy(actual))
        elif variant=='role':process['role']='parser'
        elif variant=='wrapper':process['wrapper_pid']+=1
        elif variant=='start':process['start_time_ticks']+=1
        elif variant=='pid':process['pid']+=1
        elif variant=='chronology':
            actual.update(started_at_ns=1,finished_at_ns=2,deadline_ns=2000000001)
        elif variant=='descriptors':actual.update(descriptors_closed=False,status='failed')
        elif variant=='pin':
            actual['status']='failed';process.update(pin_verified=False,signal_attempted=False)
        elif variant=='reap':
            actual['status']='failed';process.update(exit_observed=False,reaped_observed=False)
        elif variant=='wrapper_exit':
            actual['status']='failed';process['wrapper_returncode']=None
        else:actual['status']='failed'
        changed_members['cleanup.json']=raw(cleanup)
        path=unchecked_saved(tmp_path/('cleanup-'+variant),changed_manifest,changed_members)
        before=snapshot(path)
        if variant in ('missing','descriptors','pin','reap','wrapper_exit','failed','duplicate'):
            report=e.inspect_live_bundle(path)
            assert report['operations']==good['operations']
            assert report['cleanup']['observed_payloads']==7
            if variant=='duplicate':
                assert report['status']=='complete' and report['cleanup']==good['cleanup']
            else:
                assert report['status']=='incomplete' and 'cleanup' in report['missing_evidence']
                assert report['cleanup']['status']=='incomplete'
                assert report['cleanup']['reaped_payloads']==(6 if variant in ('missing','reap') else 7)
            if variant in ('missing','descriptors','pin','reap','wrapper_exit'):
                refused(e.write_live_bundle,tmp_path/('refuse-packaging-'+variant),
                    manifest=changed_manifest,members=changed_members,code='cleanup_incomplete')
        else:refused(e.inspect_live_bundle,path)
        assert snapshot(path)==before
    # The audit parent occupies a real slot in the same94-identity inventory.
    values={name:(content if name.endswith(('.jsonl','.bin')) else json.loads(content))
        for name,content in members.items()};values['manifest.json']=manifest
    assert not context._audit_process_closure(values)['missing_cleanup']
    basis=deepcopy(next(row for row in values['processes.json']['readiness'] if row['role']=='parser'))
    for i in range(87):
        item=deepcopy(basis);item['parent_observation']['payload']['pid']=2000+i
        item['parent_observation']['wrapper']['pid']=3000+i
        values['processes.json']['readiness'].append(item)
    assert not context._audit_process_closure(values)['missing_cleanup']
    last=deepcopy(basis);last['parent_observation']['payload']['pid']=2089
    last['parent_observation']['wrapper']['pid']=3089
    values['processes.json']['readiness'].append(last)
    refused(context._audit_process_closure,values)
    # Startup exit78 is not a business-cause witness. These declared receipts
    # require the exact captured guard diagnostic commitment as well.
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    bundle=runtime();ready=declared_readiness(bundle,'broker',pid=501)
    entry=deepcopy(ready['parent_observation']);entry['stage']='entry'
    entry['sampled_at_ns']=1000000000
    cleanup=declared_cleanup(ready,started=1020000000,finished=1030000000)
    cleanup['processes'][0].update(signal_attempted=False,wrapper_returncode=78)
    for number in (10,11,12,28,41):
        case='S42C-N'+str(number).zfill(2);variant=e._case(case)['variant']
        roe=json.loads((ROOT/'examples/secure-agent-engagement-roe.json').read_bytes())
        if number==10:roe['excluded_services']=['http']
        elif number in (11,12):roe['allowed_profiles'].remove(
            'configurable_nmap_service_v1' if number==11 else 'configurable_http_headers_v1')
        final,_=ledger._apply(None,{'schema_version':'2','engagement_id':uid(1),'event_id':uid(2),
            'operation':'create','expected_revision':None,'expected_generation':None,'body':roe})
        if number==41:
            final,_=ledger._apply(final,{'schema_version':'2','engagement_id':uid(1),'event_id':uid(3),
                'operation':'revoke','expected_revision':1,'expected_generation':0,'body':None})
        code='engagement_live_'+('invalid_prepared' if number in (10,11,12) else 'window_not_open' if number==28 else 'revoked')
        marker={'schema_version':'1','case_id':case,'guard':'validate_live_roe' if number in (10,11,12) else '_check_current',
            'roe_sha256':sha(raw(roe)),'code':code,'clock':{'utc_ns':ledger._window(roe)[0]-1,
                'mono_before_ns':1010000000,'mono_after_ns':1010000001}}
        observed={'source':'role_observer','segment':0,'row':{'schema_version':'1','row_sequence':1,
            'broker_id':uid(500),'observer_id':uid(500),'session_id':None,'dispatch_id':None,
            'observed_at_ns':1040000000,'kind':'phase','data':{'phase':'prepare','stage':'refused','reason':code,
                'clock':marker['clock'],'related_sha256':sha(raw(marker)),'original_deadline_ns':10000000000}}}
        declared={'manifest.json':{'broker_instances':[]},'runtime.json':{'runtime':bundle,'instrumentation':[
            {'kind':'sealed_fault','source_sha256':'b'*64,'configuration':{'case_id':case,'variant':variant,'role':'broker'}}]},
            'cleanup.json':{'supervisors':[],'receipts':[cleanup]}}
        assert e._startup_guard_refusal(declared,[observed],final,number,entry)
        assert not e._startup_guard_refusal(declared,[],final,number,entry)
        generic=deepcopy(observed);generic['row']['data']['related_sha256']=sha(raw(roe))
        assert not e._startup_guard_refusal(declared,[generic],final,number,entry)
        for field,value in [('guard','unrelated_startup_guard'),('code','engagement_live_invalid_runtime'),
                            ('roe_sha256','f'*64),('case_id','S42C-N99')]:
            wrong=deepcopy(marker);wrong[field]=value;projected=deepcopy(observed)
            projected['row']['data'].update(reason=wrong['code'],related_sha256=sha(raw(wrong)))
            assert not e._startup_guard_refusal(declared,[projected],final,number,entry)
        wrong=deepcopy(marker);wrong['clock']['mono_before_ns']=wrong['clock']['mono_after_ns']=1040000001
        projected=deepcopy(observed);projected['row']['data'].update(clock=wrong['clock'],related_sha256=sha(raw(wrong)))
        assert not e._startup_guard_refusal(declared,[projected],final,number,entry)
        unbound=deepcopy(declared);unbound['runtime.json']['instrumentation'][0]['source_sha256']='c'*64
        assert not e._startup_guard_refusal(unbound,[observed],final,number,entry)
        killed=deepcopy(declared);killed['cleanup.json']['receipts'][0]['processes'][0]['wrapper_returncode']=-9
        assert not e._startup_guard_refusal(killed,[observed],final,number,entry)
