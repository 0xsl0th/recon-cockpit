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
    rows=[deepcopy(x) for x in rows if x['row']['kind']!='supervision_projection' and not
        (x['row']['kind']=='protocol' and x['row']['data']['frame']['operation']=='ROLE_OBSERVED'
         and x['row']['data']['frame']['body']['role'] in ('endpoint','launcher'))]
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
        # Declared lifecycle records bind the two workers to one broker slot.
        # These are synthetic rows, never substitutes for retained native bytes.
        for ready in (endpoint,launcher):
            sequence=1+sum(x['row']['kind']=='protocol' and x['row']['data']['frame']['channel_id']==broker
                and x['row']['data']['direction']=='received' for x in rows)
            rows.append({'segment':0,'source':'broker_memfd','row':{'schema_version':'1','broker_id':broker,
                'observer_id':broker,'session_id':None,'dispatch_id':None,'row_sequence':1,
                'observed_at_ns':anchor-90,'kind':'protocol','data':{'channel_role':'lifecycle','direction':'received',
                    'frame':{'schema_version':'1','channel_id':broker,'sequence':sequence,'operation':'ROLE_OBSERVED',
                        'body':{'slot_index':index,'role':ready['role'],'readiness':deepcopy(ready)}}}}})
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
            'cleanup_deadline_ns':end+1900000000,'join_attempted':True,'thread_alive_observed':False,
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
    _copied_recovery_shape_cases()
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


def _copied_recovery_shape_cases():
    """Closed data shapes only; these declarations make no process claim."""
    from recon_cockpit.secure_agent import engagement_live_context as context
    config={'schema_version':'1','helper_id':uid(970),'broker_id':uid(971),
        'runtime_sha256':'a'*64,'source_manifest_sha256':'b'*64,
        'source_package_bytes':1024,'source_package_sha256':'c'*64,
        'started_at_ns':100,'work_deadline_ns':1500000100,'deadline_ns':2000000100,
        'inherited_fds':{'stdin':0,'stdout':1,'stderr':2,'source_package':8,
            'source_parent':9,'source_store':10,'scratch_parent':11,'scratch_store':12}}
    stamp={'ctime_ns':100,'mtime_ns':100,'device':1,'inode':2,'uid':1000,'gid':1000,
        'mode':stat.S_IFREG|0o600,'nlink':1,'size':4096}
    observation={'name':'records.sqlite3','fd_flags':os.O_RDONLY,'header_hex':
        (b'SQLite format 3\x00'+bytes.fromhex('10000101')+bytes(8)).hex(),
        'trailer_hex':'00'*16,'sha256':'d'*64,'held':stamp,'named':deepcopy(stamp)}
    work={'schema_version':'1','helper_id':uid(970),'broker_id':uid(971),
        'runtime_sha256':'a'*64,'source_package_sha256':'c'*64,'started_at_ns':100,
        'work_deadline_ns':1500000100,'deadline_ns':2000000100,'finished_at_ns':None,
        'copy':None,'rw':None,'ro':None,'post_rw_copy':None,'post_ro_copy':None,
        'journal_disposition':None,'progress_callbacks':0,'source_descriptors_closed':False,
        'copy_descriptors_closed':False,'source_package_closed_at_ns':None,'sqlite_file_size_limit':None}
    for name,value in (('config',config),('file_observation',observation),('work_provenance',work)):
        context._recovery_shape(value,name)
        before=deepcopy(value)
        for field in value:
            changed=deepcopy(value);changed.pop(field)
            refused(context._recovery_shape,changed,name)
        changed=deepcopy(value);changed['unreviewed_field']=None
        refused(context._recovery_shape,changed,name)
        assert value==before
    for field,value in (('source_package_bytes',True),('source_package_bytes',2097153),
            ('source_package_bytes',0),('runtime_sha256','A'*64),('helper_id',uid(970).upper()),
            ('started_at_ns',-1),('deadline_ns',2**63)):
        changed=deepcopy(config);changed[field]=value
        refused(context._recovery_shape,changed,'config')
    for field,value in (('stdin',False),('stdout',True),('stderr',3),('source_store',2),
            ('scratch_store',256),('source_package',True)):
        changed=deepcopy(config);changed['inherited_fds'][field]=value
        refused(context._recovery_shape,changed,'config')
    changed=deepcopy(config);changed['inherited_fds']['extra']=13
    refused(context._recovery_shape,changed,'config')
    for field,value in (('header_hex','0'),('header_hex','AA'),('header_hex','00'*29),
            ('trailer_hex','00'*17),('name','records.sqlite3-wal'),('sha256','e'*63)):
        changed=deepcopy(observation);changed[field]=value
        refused(context._recovery_shape,changed,'file_observation')
    for field,value in (('nlink',True),('nlink',2),('size',16777217),('inode',True)):
        changed=deepcopy(observation);changed['held'][field]=value
        refused(context._recovery_shape,changed,'file_observation')
    for count in (3999,4000):
        changed=deepcopy(work);changed['progress_callbacks']=count
        context._recovery_shape(changed,'work_provenance')
    for field,value in (('progress_callbacks',4001),('progress_callbacks',True),
            ('copy_descriptors_closed',1),('finished_at_ns','unknown')):
        changed=deepcopy(work);changed[field]=value
        refused(context._recovery_shape,changed,'work_provenance')


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


def test_matches_immutable_python_and_cli_inspection(tmp_path,monkeypatch):
    _copied_recovery_work_cases(tmp_path,monkeypatch)
    path=saved(tmp_path);before=snapshot(path)
    report=e.inspect_live_bundle(path)
    result=subprocess.run([sys.executable,'-B',str(CLI),str(path)],cwd=ROOT,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    assert result.returncode==1 and result.stderr==b''
    assert result.stdout==raw(report)+b'\n'
    assert snapshot(path)==before
    assert report['authority_restored'] is False and report['live_execution_started_by_inspection'] is False


def _copied_recovery_work_cases(tmp_path,monkeypatch):
    from test_secure_engagement_live_session import copied_recovery_work_fixture
    from recon_cockpit.secure_agent import engagement_live_context as context
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    import socket
    import sqlite3
    helper,loaded,owners=copied_recovery_work_fixture(tmp_path)
    before=deepcopy((helper,loaded));expected=loaded['recovery-ledger.json']
    def check(value,retained=loaded):
        return context._recovery_work(value,retained,set(owners),{})
    def forbidden(*args,**kwargs):raise AssertionError('offline recovery replay attempted live work')
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3,'connect',forbidden);patch.setattr(subprocess,'Popen',forbidden)
        patch.setattr(socket,'socket',forbidden);patch.setattr(os,'open',forbidden)
        assert check(helper)==expected
        # The previous generation's export is reconstructed from the latest
        # validated history, not mistaken for the latest post-revocation state.
        latest,_=ledger._apply(expected,{'schema_version':'2','engagement_id':expected['engagement_id'],
            'event_id':uid(972),'operation':'revoke','expected_revision':1,'expected_generation':0,'body':None})
        assert check(helper,{'recovery-ledger.json':latest})==expected
        refused(check,helper,{},code='evidence_incomplete')
        unavailable=deepcopy(helper['work']['ro']);latest_raw=ledger.canonical(latest)
        unavailable.update(snapshot_event_sequence=len(latest['events']),snapshot_bytes=len(latest_raw),
            snapshot_sha256=sha(latest_raw),ledger_state_sha256=latest['events'][-1]['receipt']['state_sha256'])
        refused(context._recovery_prefix,unavailable,{'recovery-ledger.json':expected},{},code='evidence_incomplete')
        for variant in ('helper_id','runtime','deadline','unclosed_source','unclosed_copy',
                'source_changed','source_hash','source_copy_alias','main_wal','journal_trailer',
                'pending_range','shared_range','reserved_owner','reserved_errno','early_unlock',
                'file_size_limit','rw_mode','same_owner','open_ro','missing_rw_snapshot','reused_budget',
                'exhausted_budget','false_total','late_work','checksum','before_image','missing_record',
                'unlink_before_validation','ro_mutation','snapshot_sequence','snapshot_hash'):
            bad=deepcopy(helper);work=bad['work'];copy=work['copy'];rw=work['rw'];ro=work['ro']
            source={row['name']:row for row in copy['source_before']['files']}
            copied={row['name']:row for row in copy['copied']['files']}
            main='records.sqlite3';journal=main+'-journal';locks=copy['locks']
            if variant=='helper_id':work['helper_id']=uid(979)
            elif variant=='runtime':work['runtime_sha256']='f'*64
            elif variant=='deadline':work['deadline_ns']+=1
            elif variant=='unclosed_source':work['source_descriptors_closed']=False
            elif variant=='unclosed_copy':work['copy_descriptors_closed']=False
            elif variant=='source_changed':
                for field in ('held','named'):source[main][field]['mtime_ns']+=1
            elif variant=='source_hash':source[main]['sha256']='e'*64
            elif variant=='source_copy_alias':
                for field in ('held','named'):
                    for identity in ('device','inode'):copied[main][field][identity]=source[main][field][identity]
            elif variant=='main_wal':source[main]['header_hex']=source[main]['header_hex'][:36]+'02'+source[main]['header_hex'][38:]
            elif variant=='journal_trailer':source[journal]['trailer_hex']='00'*8+'d9d505f920a163d7'
            elif variant=='pending_range':locks['pending']['offset']=1073741826
            elif variant=='shared_range':locks['shared']['length']=1
            elif variant=='reserved_owner':locks['reserved_after']['owner_pid']=-1
            elif variant=='reserved_errno':locks['reserved_before']['errno']=11
            elif variant=='early_unlock':locks['released_at_ns']=copy['source_after']['observed_at_ns']-1
            elif variant=='file_size_limit':work['sqlite_file_size_limit'].update(soft=16777216,hard=16777216)
            elif variant=='rw_mode':rw['mode']='read_only'
            elif variant=='same_owner':ro['owner_id']=rw['owner_id']
            elif variant=='open_ro':ro['closed']=False
            elif variant=='missing_rw_snapshot':rw['snapshot_at_ns']=None
            elif variant=='reused_budget':
                ro['progress_callbacks_before']=0 if rw['progress_callbacks_after'] else 1
                ro['progress_callbacks_after']=max(ro['progress_callbacks_after'],ro['progress_callbacks_before'])
                work['progress_callbacks']=ro['progress_callbacks_after']
            elif variant=='exhausted_budget':ro['progress_callbacks_after']=work['progress_callbacks']=4000
            elif variant=='false_total':work['progress_callbacks']+=1
            elif variant=='late_work':work['finished_at_ns']=bad['work_deadline_ns']+1
            elif variant=='checksum':work['journal_disposition']['header']['records'][0]['computed_checksum']^=1
            elif variant=='before_image':work['journal_disposition']['header']['records'][0]['main_page_sha256']='e'*64
            elif variant=='missing_record':work['journal_disposition']['header']['records']=[]
            elif variant=='unlink_before_validation':work['journal_disposition']['unlink_started_at_ns']=rw['closed_at_ns']-1
            elif variant=='ro_mutation':work['post_ro_copy']['files'][0]['sha256']='e'*64
            elif variant=='snapshot_sequence':ro['snapshot_event_sequence']+=1
            elif variant=='snapshot_hash':ro['snapshot_sha256']='e'*64
            refused(check,bad)
        # Frames bind the exact nested canonical export and provenance, not a
        # hash of an unavailable earlier generation or an alternate encoding.
        result={'schema_version':'1','status':'complete','error':None,'export':expected,'provenance':helper['work']}
        payload=raw(result);header=len(payload).to_bytes(8,'big')
        frame={'started_at_ns':1,'finished_at_ns':2,'header_hex':header.hex(),
            'declared_bytes':len(payload),'payload_bytes':len(payload),'received_bytes':len(payload)+8,
            'payload_sha256':sha(payload),'frame_sha256':sha(header+payload),'complete':True}
        context._recovery_frame(frame,result,2129920)
        for field,value in (('header_hex',(len(payload)+1).to_bytes(8,'big').hex()),
                ('received_bytes',len(payload)+9),('payload_bytes',len(payload)-1),
                ('frame_sha256','e'*64),('payload_sha256','e'*64),('finished_at_ns',None),
                ('complete',False)):
            bad=deepcopy(frame);bad[field]=value
            refused(context._recovery_frame,bad,result,2129920)
        changed=deepcopy(result);changed['export']=latest
        refused(context._recovery_frame,frame,changed,2129920)
        _copied_recovery_large_frame_cases(monkeypatch)
        _copied_recovery_failed_work_cases(helper,loaded,owners,latest)
        _copied_recovery_receipt_cases(helper,loaded)
    assert (helper,loaded)==before


def _copied_recovery_large_frame_cases(monkeypatch):
    """Bounded codec data only; large strings are not declared ledger exports."""
    from recon_cockpit.secure_agent import engagement_live_context as context
    from recon_cockpit.secure_agent import engagement_live_session as producer
    maximum=2129920
    def sized(size):
        value={'payload':''};value['payload']='x'*(size-len(raw(value)))
        encoded=raw(value);assert len(encoded)==size
        return value,encoded
    def framed(encoded):
        header=len(encoded).to_bytes(8,'big')
        return {'started_at_ns':1,'finished_at_ns':2,'header_hex':header.hex(),
            'declared_bytes':len(encoded),'payload_bytes':len(encoded),'received_bytes':len(encoded)+8,
            'payload_sha256':sha(encoded),'frame_sha256':sha(header+encoded),'complete':True}
    assert c.MAX_CANONICAL==2097152
    for size in (2097153,maximum):
        value,encoded=sized(size)
        assert context._recovery_canonical(value,maximum)==encoded
        assert producer._recovery_json(value)==encoded
        context._recovery_frame(framed(encoded),value,maximum)
        observed,decoded,consumed=producer._recovery_frame(len(encoded).to_bytes(8,'big')+encoded,maximum,1)
        assert decoded==value and consumed==len(encoded)+8 and observed['complete'] is True
        assert observed['payload_sha256']==sha(encoded)
        refused(c.canonical,value,max_bytes=c.MAX_CANONICAL,code='limit_exceeded')
    value,encoded=sized(maximum+1)
    refused(context._recovery_canonical,value,maximum,code='limit_exceeded')
    refused(context._recovery_frame,framed(encoded),value,maximum)
    with pytest.raises(producer._RecoveryError,match='framing'):
        producer._recovery_frame(len(encoded).to_bytes(8,'big')+encoded,maximum,1)
    refused(context._recovery_canonical,{},maximum+1)
    refused(c.canonical,{},max_bytes=maximum)
    # Exercise the real result byte-bound seam. These strings test allocation
    # arithmetic only and are not semantically valid ledger/provenance rows.
    export,export_bytes=sized(c.MAX_CANONICAL)
    result={'schema_version':'1','status':'complete','error':None,'export':export,'provenance':{'padding':''}}
    metadata={**result,'export':None}
    result['provenance']['padding']='m'*(32768-len(raw(metadata)))
    metadata_bytes=raw({**result,'export':None});result_bytes=raw(result)
    assert len(metadata_bytes)==32768 and len(export_bytes)==2097152
    assert len(result_bytes)==maximum-4
    assert len(result_bytes)-len(export_bytes)==32764  # The null placeholder costs four bytes.
    assert context._recovery_result_bytes(result)==result_bytes
    oversized=deepcopy(result);oversized['provenance']['padding']+='m'
    assert len(raw({**oversized,'export':None}))==32769
    assert len(raw(oversized))<=maximum
    refused(context._recovery_result_bytes,oversized,code='limit_exceeded')
    oversized_export,_=sized(c.MAX_CANONICAL+1)
    refused(context._recovery_result_bytes,{'export':oversized_export,'provenance':None},code='limit_exceeded')
    for malformed in ({'payload':1.5},{'payload':float('nan')},{'payload':'\ud800'},
            {'payload':b'bytes'},{1:'nonstring key'},{'payload':2**64}):
        refused(context._recovery_canonical,malformed,maximum)
    deep=0
    for unused in range(c.MAX_DEPTH+1):deep=[deep]
    refused(context._recovery_canonical,deep,maximum,code='limit_exceeded')
    unicode={'text':'caf\u00e9 \U0001f642','nested':['\u96ea']}
    ascii_bytes=raw(unicode)
    assert ascii_bytes.isascii() and b'\\u00e9' in ascii_bytes and b'\\ud83d' in ascii_bytes
    assert producer._recovery_json(unicode)==context._recovery_canonical(unicode,maximum)==ascii_bytes
    context._recovery_frame(framed(ascii_bytes),unicode,maximum)
    utf8=json.dumps(unicode,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    assert utf8!=ascii_bytes
    refused(context._recovery_frame,framed(utf8),unicode,maximum)
    with pytest.raises(producer._RecoveryError,match='framing') as caught:
        producer._recovery_frame(len(utf8).to_bytes(8,'big')+utf8,maximum,1)
    assert caught.value.frame['payload_sha256']==sha(utf8) and caught.value.frame['complete'] is False
    # ASCII escaping, not Python character count or UTF-8 width, consumes the cap.
    refused(context._recovery_canonical,{'payload':'\u00e9'*400000},maximum,code='limit_exceeded')
    with pytest.raises(c.LiveError,match='timeout'):
        with c._deadline_context(time.monotonic()-1):context._recovery_canonical({},maximum)
    with pytest.raises(c.LiveError,match='timeout'):
        with c._deadline_context(time.monotonic()-1):context._recovery_result_bytes({'export':None,'provenance':None})
    # Serialization's tail must remain inside the same validation interval.
    original=json.dumps;clock=[100.0]
    def serialization_crosses_deadline(*args,**kwargs):
        encoded=original(*args,**kwargs);clock[0]=100.2;return encoded
    with monkeypatch.context() as patch:
        patch.setattr(c.time,'monotonic',lambda:clock[0])
        patch.setattr(context.json,'dumps',serialization_crosses_deadline)
        with pytest.raises(c.LiveError,match='timeout'):
            with c._deadline_context(100.1):context._recovery_canonical({},maximum)
    assert c.MAX_CANONICAL==2097152


def _copied_recovery_failed_work_cases(helper,loaded,owners,latest):
    from recon_cockpit.secure_agent import engagement_live_context as context
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    def check(value,retained=loaded):
        context._recovery_shape(value['work'],'work_provenance')
        context._recovery_partial_work(value,retained,set(owners),{})
    failed=[]
    for phase in ('rw','ro'):
        value=deepcopy(helper);work=value['work'];stage=work[phase]
        for field in ('snapshot_at_ns','snapshot_event_sequence','snapshot_bytes','snapshot_sha256','ledger_state_sha256'):
            stage[field]=None
        work['post_ro_copy']=None;work['finished_at_ns']=stage['closed_at_ns']
        work['progress_callbacks']=stage['progress_callbacks_after']
        if phase=='rw':
            for field in ('ro','post_rw_copy','journal_disposition'):work[field]=None
        value['transfer']={'result_error':'sqlite_'+phase,'result_status':'failed'}
        check(value);failed.append(value)
        for mutation in ('copy_alias','lock_range','narrow','owner_reused','wrong_reason'):
            bad=deepcopy(value);work=bad['work']
            if mutation=='copy_alias':
                src=work['copy']['source_before']['files'][0];copy=work['copy']['copied']['files'][0]
                for field in ('held','named'):
                    for key in ('device','inode'):copy[field][key]=src[field][key]
            elif mutation=='lock_range':work['copy']['locks']['pending']['offset']=1073741826
            elif mutation=='narrow':work['sqlite_file_size_limit']['hard']=16777216
            elif mutation=='owner_reused':work[phase]['owner_id']=next(iter(owners))
            else:bad['transfer']['result_error']='reserved_writer'
            refused(check,bad)
    bad=deepcopy(failed[1]);bad['work']['journal_disposition']['header']['records'][0]['checksum']^=1
    refused(check,bad)
    bad=deepcopy(failed[1]);bad['work']['rw']['progress_callbacks_after']=4000
    bad['work']['ro'].update(progress_callbacks_before=4000,progress_callbacks_after=4000)
    bad['work']['progress_callbacks']=4000;bad['transfer']['result_error']='progress_limit'
    refused(check,bad)
    drift=deepcopy(helper);work=drift['work']
    for field in ('rw','ro','post_rw_copy','post_ro_copy','journal_disposition','sqlite_file_size_limit'):work[field]=None
    work['progress_callbacks']=0;work['finished_at_ns']=work['copy']['finished_at_ns']
    work['copy']['source_after']['files'][0]['sha256']='e'*64
    drift['transfer']={'result_error':'source_changed','result_status':'failed'}
    check(drift)
    bad=deepcopy(drift);bad['transfer']['result_error']='copy_custody';refused(check,bad)
    bad=deepcopy(drift);bad['work']['rw']=deepcopy(helper['work']['rw']);refused(check,bad)
    mismatch=deepcopy(helper);mismatch['work']['post_ro_copy']=None
    encoded=ledger.canonical(latest);mismatch['work']['ro'].update(snapshot_bytes=len(encoded),
        snapshot_sha256=sha(encoded),snapshot_event_sequence=len(latest['events']),
        ledger_state_sha256=latest['events'][-1]['receipt']['state_sha256'])
    mismatch['transfer']={'result_error':'snapshot_mismatch','result_status':'failed'}
    check(mismatch,{'recovery-ledger.json':latest})
    bad=deepcopy(mismatch);bad['transfer']['result_error']='sqlite_ro'
    refused(check,bad,{'recovery-ledger.json':latest})
    bad=deepcopy(mismatch);bad['work']['post_ro_copy']=deepcopy(helper['work']['post_ro_copy'])
    refused(check,bad,{'recovery-ledger.json':latest})


def _copied_recovery_receipt_cases(helper,loaded):
    """Receipt joins over validated-work inputs, not a full process witness."""
    from recon_cockpit.secure_agent import engagement_live_context as context
    value=deepcopy(helper);value.update(generation=0,status='complete')
    work=value['work'];ro=work['ro'];store=work['post_ro_copy'];main=store['files'][0]['held']
    receipt={'schema_version':'2','source':'postcleanup_copied_recovery','owner_id':ro['owner_id'],
        'started_at_ns':ro['opened_at_ns'],'finished_at_ns':ro['closed_at_ns'],'read_only':True,'closed':True,
        'store_identity':{'parent':store['parent'],'directory':store['directory'],
            'database':{key:main[key] for key in ('device','inode','mode','uid','gid')}},
        'bytes':ro['snapshot_bytes'],'sha256':ro['snapshot_sha256'],'ledger_state_sha256':ro['ledger_state_sha256'],
        'helper_id':value['helper_id'],'helper_sha256':sha(c.canonical(value,max_bytes=524288))}
    retained=deepcopy(loaded);retained['manifest.json']={'broker_instances':[{'broker_id':value['broker_id']}],
        'ledger_exports':{'recovery':{'source':'postcleanup_copied_recovery','status':'complete','broker_id':None}}}
    context._copied_recovery_receipt(receipt,[value],retained)
    for field,change in (('owner_id',uid(999)),('started_at_ns',ro['opened_at_ns']+1),
            ('sha256','e'*64),('helper_sha256','e'*64)):
        bad=deepcopy(receipt);bad[field]=change
        refused(context._copied_recovery_receipt,bad,[value],retained)
    stale=deepcopy(retained);stale['manifest.json']['broker_instances'].append({'broker_id':uid(999)})
    refused(context._copied_recovery_receipt,receipt,[value],stale)
    later=deepcopy(value);later.update(helper_id=uid(999),broker_id=uid(998),generation=1,status='failed')
    refused(context._copied_recovery_receipt,receipt,[value,later],stale)
    failed=deepcopy(value);failed['status']='failed';bad=deepcopy(receipt)
    bad['helper_sha256']=sha(c.canonical(failed,max_bytes=524288))
    refused(context._copied_recovery_receipt,bad,[failed],retained)


def test_closes_cli_errors_and_stdout_failures(tmp_path,monkeypatch):
    _native_inspector_failure_retention(tmp_path)
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
    initial,_=ledger._apply(None,state['events'][0]['request'])
    initial_hash=initial['events'][0]['receipt']['state_sha256']
    selector={'before_state_sha256':initial_hash,'after_state_sha256':initial_hash,'recovery_state_sha256':None}
    assert e._core_history({'initial-ledger.json':initial},selector) is None
    op={'session':session,'prepared':p,'result':None,'client':None,'meter':None,'host_capture':None,
        'elapsed_ms':{key:None for key in e.TIMINGS}}
    manifest,members=fixture()
    loaded={name:(json.loads(value) if name.endswith('.json') else value) for name,value in members.items()}
    loaded.update({'manifest.json':manifest,'results.json':{'operations':[op]},'final-ledger.json':state,'audit.jsonl':b''})
    manifest['broker_instances']=[{'broker_id':uid(6),'ledger_owner_id':uid(4)}]
    manifest['ledger_exports']['final'].update(status='complete',broker_id=uid(6))
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


def _copied_recovery_runtime_and_process_cases(monkeypatch):
    """Declared saved bindings only; no actual process/VFS proof is claimed."""
    from recon_cockpit.secure_agent import engagement_live_context as context
    bundle=runtime();broker=next(row for row in bundle['roles'] if row['role']=='broker')
    extension=deepcopy(next(row for row in broker['extension_files'] if '/_sqlite3.' in row['destination']))
    ctypes_extension=deepcopy(next(row for row in broker['extension_files'] if '/_ctypes.' in row['destination']))
    library={'source':'/usr/lib/libsqlite3.so.0','destination':'/usr/lib/libsqlite3.so.0','size':1,'sha256':'c'*64}
    ffi={'source':'/usr/lib/libffi.so.8','destination':'/usr/lib/libffi.so.8','size':1,'sha256':'e'*64}
    libc={'source':'/usr/lib/libc.so.6','destination':'/usr/lib/libc.so.6','size':1,'sha256':'f'*64}
    broker['native_files'].extend([library,ffi,libc]);broker['required_mapped_images'].append(libc['destination'])
    loader=next(row for row in broker['native_files'] if 'ld-linux' in row['destination'])
    loader_alias={**loader,'destination':'/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'}
    broker['native_files'].append(loader_alias);broker['required_mapped_images'].append(loader_alias['destination'])
    images=[{key:row[key] for key in ('destination','size','sha256')}|
        {'device':1,'inode':200+index,'mode':stat.S_IFREG|0o555} for index,row in
        enumerate([row for row in broker['native_files'] if row is not loader_alias]+[extension,ctypes_extension])]
    image_by_name={row['destination']:row for row in images}
    identity=lambda number:{'device':1,'inode':number,'mode':stat.S_IFDIR|0o700,'uid':1000,'gid':1000}
    source={'parent':identity(500),'directory':identity(501),
        'files':[{'name':'records.sqlite3','held':{'device':1,'inode':502}}]}
    scratch={'parent':identity(600),'directory':identity(601)}
    purposes=['bounded config then release input pipe','READY/result framed stdout pipe',
        'bounded diagnostic stderr pipe','sealed O_RDONLY source package','held source parent directory',
        'held source store directory','registered scratch parent directory','registered scratch store directory']
    descriptors=[];transports={}
    for fd,purpose in enumerate(purposes):
        kind='pipe' if fd<3 else 'regular' if fd==3 else 'directory'
        inode=700+fd if fd<4 else (500,501,600,601)[fd-4]
        mode=(stat.S_IFIFO if fd<3 else stat.S_IFREG if fd==3 else stat.S_IFDIR)|(0o600 if fd<4 else 0o700)
        flags=os.O_RDONLY if fd==0 or fd>=3 else os.O_WRONLY
        descriptors.append({'fd':fd,'purpose':purpose,'kind':kind,'device':1,'inode':inode,'mode':mode,'flags':flags})
        if fd<3:
            parent=deepcopy(descriptors[-1]);parent.update(fd=20+fd,flags=os.O_WRONLY if fd==0 else os.O_RDONLY)
            child=deepcopy(descriptors[-1]);child['fd']=23+fd
            transports[('stdin','stdout','stderr')[fd]]={'created_at_ns':12,'parent':parent,'child':child}
    config={'runtime_sha256':sha(raw(bundle)),'source_manifest_sha256':sha(raw(bundle['sources'])),
        'source_package_sha256':'d'*64,'source_package_bytes':1024,
        'inherited_fds':{'stdin':0,'stdout':1,'stderr':2,'source_package':8,'source_parent':9,
            'source_store':10,'scratch_parent':11,'scratch_store':12}}
    vfs={'observed_at_ns':24,'library_source':library['source'],'library':image_by_name[library['destination']],
        'library_version':3046001,'sqlite_module_version':[3,46,1],
        'vfs_name':'unix','vfs_name_hex':'756e697800','vfs_struct_version':3}
    ready={'schema_version':'1','helper_id':uid(970),'broker_id':uid(971),'kind':'copied_ledger_recovery_ready',
        'pid':1001,'observed_at_ns':25,'runtime_sha256':config['runtime_sha256'],
        'source_manifest_sha256':config['source_manifest_sha256'],'source_package_sha256':'d'*64,'default_vfs':vfs}
    observed={'observed_at_ns':35,'runtime_sha256':config['runtime_sha256'],
        'source_manifest_sha256':config['source_manifest_sha256'],
        'interpreter':image_by_name[bundle['python']['destination']],
        'sqlite_extension':image_by_name[extension['destination']],'mapped_images':images,
        'stdlib':{'device':bundle['stdlib']['device'],'inode':bundle['stdlib']['inode'],
            'mode':bundle['stdlib']['mode'],'uid':1000,'gid':1000},
        'descriptors':descriptors,'default_vfs_sha256':sha(raw(vfs)),'vfs':'unix','locking':'posix_rollback',
        'source_package':{'descriptor':deepcopy(descriptors[3]),'seals':15,'bytes':1024,
            'sha256':'d'*64,'source_manifest_sha256':config['source_manifest_sha256']},
        'resource_limits':{'observed_at_ns':35,**{key:{'soft':value,'hard':value} for key,value in
            (('address_space',268435456),('cpu',2),('nofile',32),('file_size',16777216))}}}
    helper={'started_at_ns':10,'config':config,'ready':ready,'runtime':observed,'scratch':scratch,
        'transports':transports,'process':{'publication_registered_at_ns':19,'publication_resolved_at_ns':20,
            'release_sent_at_ns':40,'exit_observed_at_ns':60},'transfer':{'ready':{'finished_at_ns':30}},
        'work':{'copy':{'source_before':source}}}
    def check_runtime(value):
        context._recovery_shape(value['ready'],'ready');context._recovery_shape(value['runtime'],'helper_runtime')
        context._recovery_runtime(value,bundle)
    check_runtime(helper)
    alias=deepcopy(helper)
    next(row for row in alias['runtime']['mapped_images'] if row['destination']==loader['destination'])['destination']=loader_alias['destination']
    check_runtime(alias)
    release_failed=deepcopy(helper);release_failed['process']['release_sent_at_ns']=None
    release_failed['work']=None
    check_runtime(release_failed)
    early_exit=deepcopy(release_failed);early_exit['process']['exit_observed_at_ns']=34
    refused(check_runtime,early_exit)
    for variant in ('runtime_hash','source_hash','interpreter_hash','sqlite_missing','sqlite_hash',
            'extra_image','missing_loader','missing_libc','missing_ctypes','missing_libffi',
            'wrong_library','vfs_name','vfs_bytes','vfs_version','version_number','vfs_hash',
            'vfs_before_publication','release_before_runtime','resource_limit','package_seal','package_hash',
            'package_write','package_path','extra_fd','wrong_fd_purpose','pipe_identity','pipe_access',
            'pipe_alias','pipe_parent_alias','pipe_child_alias','pipe_passfd_alias',
            'pipe_parent_path','pipe_child_path','pipe_ready_path',
            'source_directory','scratch_directory','duplicate_inherited'):
        bad=deepcopy(helper);observed=bad['runtime'];ready=bad['ready']
        if variant=='runtime_hash':observed['runtime_sha256']='e'*64
        elif variant=='source_hash':bad['config']['source_manifest_sha256']='e'*64
        elif variant=='interpreter_hash':observed['interpreter']['sha256']='e'*64
        elif variant=='sqlite_missing':observed['mapped_images']=[row for row in observed['mapped_images'] if row['destination']!=extension['destination']]
        elif variant=='sqlite_hash':observed['sqlite_extension']['sha256']='e'*64
        elif variant=='extra_image':observed['mapped_images'].append({**deepcopy(images[0]),'destination':'/unreviewed/library.so'})
        elif variant in ('missing_loader','missing_libc','missing_ctypes','missing_libffi'):
            selected={'missing_loader':loader,'missing_libc':libc,'missing_ctypes':ctypes_extension,'missing_libffi':ffi}[variant]
            observed['mapped_images']=[row for row in observed['mapped_images'] if row['destination']!=selected['destination']]
        elif variant=='wrong_library':ready['default_vfs']['library_source']='/unreviewed/libsqlite3.so'
        elif variant=='vfs_name':ready['default_vfs']['vfs_name']='unix-excl'
        elif variant=='vfs_bytes':ready['default_vfs']['vfs_name_hex']='756e6978'
        elif variant=='vfs_version':ready['default_vfs']['vfs_struct_version']=4
        elif variant=='version_number':ready['default_vfs']['library_version']+=1
        elif variant=='vfs_hash':observed['default_vfs_sha256']='e'*64
        elif variant=='vfs_before_publication':ready['default_vfs']['observed_at_ns']=19
        elif variant=='release_before_runtime':bad['process']['release_sent_at_ns']=34
        elif variant=='resource_limit':observed['resource_limits']['file_size']['hard']=16777217
        elif variant=='package_seal':observed['source_package']['seals']=7
        elif variant=='package_hash':observed['source_package']['sha256']='e'*64
        elif variant in ('package_write','package_path'):
            observed['descriptors'][3]['flags']=os.O_RDWR if variant=='package_write' else 0o10000000
            observed['source_package']['descriptor']=deepcopy(observed['descriptors'][3])
        elif variant=='extra_fd':observed['descriptors'].append({**deepcopy(observed['descriptors'][3]),'fd':8})
        elif variant=='wrong_fd_purpose':observed['descriptors'][4]['purpose']='unreviewed_directory'
        elif variant=='pipe_identity':bad['transports']['stdin']['parent']['inode']+=1
        elif variant=='pipe_access':observed['descriptors'][0]['flags']=os.O_WRONLY
        elif variant=='pipe_alias':
            for side in ('parent','child'):bad['transports']['stderr'][side]['inode']=bad['transports']['stdout'][side]['inode']
            observed['descriptors'][2]['inode']=observed['descriptors'][1]['inode']
        elif variant=='pipe_parent_alias':bad['transports']['stdin']['parent']['fd']=bad['transports']['stdout']['parent']['fd']
        elif variant=='pipe_child_alias':bad['transports']['stdin']['child']['fd']=bad['transports']['stdin']['parent']['fd']
        elif variant=='pipe_passfd_alias':bad['transports']['stderr']['child']['fd']=bad['config']['inherited_fds']['source_package']
        elif variant=='pipe_parent_path':bad['transports']['stdin']['parent']['flags']|=0o10000000
        elif variant=='pipe_child_path':bad['transports']['stdin']['child']['flags']|=0o10000000
        elif variant=='pipe_ready_path':observed['descriptors'][0]['flags']|=0o10000000
        elif variant=='source_directory':observed['descriptors'][5]['inode']+=1
        elif variant=='scratch_directory':observed['descriptors'][7]['inode']+=1
        elif variant=='duplicate_inherited':bad['config']['inherited_fds']['source_store']=bad['config']['inherited_fds']['source_parent']
        if variant in ('wrong_library','version_number','vfs_before_publication'):
            observed['default_vfs_sha256']=sha(raw(ready['default_vfs']))
        refused(check_runtime,bad)
    # Physical closure is a separate join. A digest/EOF or one unrelated reaped
    # process cannot replace the exact prior broker and sibling identities.
    observer={'pid':900,'uid':1000,'gid':1000,'namespaces':{'pid':'pid:[1]','mnt':'mnt:[2]','net':'net:[3]','user':'user:[4]'}}
    parent={'observer':observer,'sampled_at_ns':50,'payload':{'pid':1000,'start_time_ticks':2000},
        'wrapper':{'pid':999,'start_time_ticks':1999},'descriptors':[
            {'purpose':'held_store_directory','device':1,'inode':501},
            {'purpose':'sqlite_main','device':1,'inode':502}]}
    sibling=deepcopy(parent);sibling['payload'].update(pid=1010,start_time_ticks=2010);sibling['wrapper']['pid']=1009
    def cleanup(parent):
        return {'finished_at_ns':90,'descriptors_closed':True,'processes':[{
            'pid':parent['payload']['pid'],'start_time_ticks':parent['payload']['start_time_ticks'],
            'wrapper_pid':parent['wrapper']['pid'],'wrapper_returncode':0,'pin_verified':True,
            'exit_observed':True,'reaped_observed':True}]}
    physical={'broker_id':uid(971),'generation':0,'runtime':None,'started_at_ns':100,'finished_at_ns':200,'parent_observer':observer,
        'work':{'copy':{'source_before':source}}}
    loaded={'processes.json':{'startup':[],'child_slots':[],
        'readiness':[{'role':'broker','worker_ready':{'worker_id':uid(971)},'parent_observation':parent}]},
        'cleanup.json':{'receipts':[cleanup(parent),cleanup(sibling)],'supervisors':[]}}
    parents=[parent,sibling]
    # This lower-level join uses an explicitly declared generation map. The
    # separate test below derives it from sealed role/audit/allocation links.
    mapping={(row['payload']['pid'],row['payload']['start_time_ticks']):0 for row in parents}
    later=deepcopy(sibling);later['sampled_at_ns']=201;later['payload'].update(pid=1020,start_time_ticks=2020)
    later['wrapper']['pid']=1019;mapping[(1020,2020)]=1
    def check_physical(value,retained,observations):
        return context._recovery_physical_history(value,retained,observations,generation_by_identity=mapping)
    assert check_physical(physical,loaded,parents)==parent
    assert check_physical(physical,loaded,[*parents,later])==parent
    for variant in ('missing_broker','foreign_observer','wrong_pid','wrong_start','wrong_wrapper','unreaped',
            'unobserved_exit','open_descriptors','late_cleanup','missing_sibling',
            'selected_broker_late','same_generation_late','source_inode','overlap'):
        bad=deepcopy(loaded);changed=deepcopy(physical);pp=deepcopy(parents)
        receipt=bad['cleanup.json']['receipts'][0];process=receipt['processes'][0]
        if variant=='missing_broker':bad['processes.json']['readiness']=[]
        elif variant=='foreign_observer':changed['parent_observer']['pid']+=1
        elif variant=='wrong_pid':process['pid']+=1
        elif variant=='wrong_start':process['start_time_ticks']+=1
        elif variant=='wrong_wrapper':process['wrapper_pid']+=1
        elif variant=='unreaped':process['reaped_observed']=False
        elif variant=='unobserved_exit':process['exit_observed']=False
        elif variant=='open_descriptors':receipt['descriptors_closed']=False
        elif variant=='late_cleanup':receipt['finished_at_ns']=101
        elif variant=='missing_sibling':bad['cleanup.json']['receipts'].pop()
        elif variant=='selected_broker_late':bad['processes.json']['readiness'][0]['parent_observation']['sampled_at_ns']=101
        elif variant=='same_generation_late':pp[1]['sampled_at_ns']=201
        elif variant=='source_inode':changed['work']['copy']['source_before']['files'][0]['held']['inode']+=1
        elif variant=='overlap':
            other=deepcopy(later);other['sampled_at_ns']=150;pp.append(other)
        refused(check_physical,changed,bad,pp)
    _copied_recovery_generation_cases(monkeypatch)


def _copied_recovery_generation_cases(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_context as context
    manifest,members=useful_fixture(monkeypatch)
    loaded={'manifest.json':manifest,**{name:json.loads(value) if name.endswith('.json') else value
        for name,value in members.items()}}
    processes=loaded['processes.json']
    parents=[*processes['startup'],*[row['parent_observation'] for row in processes['readiness']+processes['native']],
        *context._audit_process_closure(loaded)['parents']]
    mapping,counts=context._recovery_generation_map(loaded,parents)
    assert set(mapping.values())=={0} and set(counts)=={0}
    assert counts[0]=={(parent[field]['pid'],parent[field]['start_time_ticks'])
        for parent in parents for field in ('payload','wrapper')}
    broker=next(row for row in processes['readiness'] if row['role']=='broker')
    start=max([row['finished_at_ns'] for row in loaded['cleanup.json']['receipts']]+
        [row['cleanup_finished_at_ns'] for row in loaded['cleanup.json']['supervisors']])+1
    helper={'broker_id':broker['worker_ready']['worker_id'],'generation':0,'started_at_ns':start,
        'finished_at_ns':start+10,'parent_observer':broker['parent_observation']['observer'],'work':None,'runtime':None}
    assert context._recovery_physical_history(helper,loaded,parents)==broker['parent_observation']
    for variant in ('missing_supervisor','missing_allocations','late_broker','live_supervisor','pending_supervisor'):
        bad=deepcopy(loaded)
        if variant=='missing_supervisor':bad['cleanup.json']['supervisors']=[]
        elif variant=='missing_allocations':bad['processes.json']['child_slots']=[];bad['cleanup.json']['supervisors']=[]
        elif variant=='late_broker':
            next(row for row in bad['processes.json']['readiness'] if row['role']=='broker')['parent_observation']['sampled_at_ns']=start+1
        elif variant=='live_supervisor':
            bad['cleanup.json']['supervisors'][0].update(state='alive',thread_alive_observed=True,status='failed')
        else:bad['cleanup.json']['supervisors'][0].update(pending_slots=['identify_client'],status='failed')
        refused(context._recovery_physical_history,helper,bad,parents)
    foreign=deepcopy(parents[0]);foreign['payload']['pid']+=10000
    refused(context._recovery_generation_map,loaded,[*parents,foreign],code='evidence_incomplete')
    contradiction=deepcopy(parents[0]);contradiction['wrapper']['pid']+=10000
    refused(context._recovery_generation_map,loaded,[*parents,contradiction])
    bad=deepcopy(loaded);bad['processes.json']['child_slots'][0]['broker_id']=uid(979)
    refused(context._recovery_generation_map,bad,parents)
    # Delete just the endpoint's sealed lifecycle association, coherently
    # rebuilding segment offsets, row sequences and hashes. Its retained PID
    # cannot be assigned by timestamp or by an unrelated cleanup receipt.
    bad=deepcopy(loaded);chunks=[];removed=0
    for segment in bad['manifest.json']['transcript']['segments']:
        part=bad['transcript.jsonl'][segment['offset']:segment['offset']+segment['bytes']]
        rows=[]
        for line in part.splitlines():
            row=json.loads(line);data=row['data']
            if (row['kind']=='protocol' and data['frame']['operation']=='ROLE_OBSERVED'
                    and data['frame']['body']['readiness']['role']=='endpoint'):
                removed+=1;continue
            rows.append(row)
        for index,row in enumerate(rows,1):row['row_sequence']=index
        part=b''.join(raw(row)+b'\n' for row in rows)
        segment.update(offset=sum(map(len,chunks)),bytes=len(part),sha256=sha(part));chunks.append(part)
    assert removed==1
    bad['transcript.jsonl']=b''.join(chunks)
    refused(context._recovery_generation_map,bad,parents,code='evidence_incomplete')


def test_requires_single_winner_and_durable_race_order(monkeypatch):
    _copied_recovery_runtime_and_process_cases(monkeypatch)
    _changed_stop_cancellation_cases()
    _external_revocation_race_cases()
    _fixed_fault_phase_cases()
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
    manifest['broker_instances']=[{'broker_id':uid(6),'ledger_owner_id':uid(4)}]
    manifest['ledger_exports']['final'].update(status='complete',broker_id=uid(6))
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


def _native_inspector_failure_retention(tmp_path):
    from engagement_live_native import _bounded_inspector
    for name,program,code,stdout,stderr in (
        ('nonzero','import sys;print("incomplete report");sys.exit(1)',1,b'incomplete report\n',b''),
        ('stderr','import sys;sys.stderr.write("retained failure\\n")',0,b'',b'retained failure\n'),
    ):
        directory=tmp_path/name;directory.mkdir(mode=0o700)
        with pytest.raises(AssertionError,match='CLI replay refused'):
            _bounded_inspector([sys.executable,'-I','-S','-c',program],time.monotonic()+15,directory)
        failure=json.loads((directory/'inspection-cli-failure.json').read_bytes())
        assert failure=={'error_type':'AssertionError','wrapper_returncode':code,'emergency_reaped':None,'acceptance':False}
        assert (directory/'inspection-cli-failure.stdout').read_bytes()==stdout
        assert (directory/'inspection-cli-failure.stderr').read_bytes()==stderr


def _changed_stop_cancellation_cases():
    # Declared transcript facts only. A local cancellation is not a business
    # refusal without the same broker's observed change and earlier stop.
    env={'broker_id':uid(1),'session_id':uid(2),'dispatch_id':uid(3)}
    operations=[{'prepared':{'envelope':env}}]
    for reason in ('revision_changed','revoked'):
        watch={'source':'broker_memfd','row':{'broker_id':uid(1),'observed_at_ns':100,
            'data':{'reason':'engagement_live_'+reason}}}
        attempt={'source':'role_observer','row':{**env,'observed_at_ns':300,
            'data':{'reason':'engagement_live_cancelled'}}}
        for operation in ('SESSION_STOP','BROKER_STOP'):
            body={'reason':'engagement_live_'+reason}
            if operation=='SESSION_STOP':body['session_id']=uid(2)
            stop={'source':'broker_memfd','row':{'broker_id':uid(1),'observed_at_ns':200,
                'data':{'frame':{'channel_id':uid(1),'operation':operation,'body':body}}}}
            assert e._changed_stop_cancellation(attempt,[watch],[stop],operations)
            assert not e._changed_stop_cancellation(attempt,[],[stop],operations)
            assert not e._changed_stop_cancellation(attempt,[watch],[],operations)
            assert not e._changed_stop_cancellation(attempt,[watch],[stop],[])
            for original,path,value in (
                ('attempt',('source',),'broker_memfd'),
                ('attempt',('row','broker_id'),uid(4)),
                ('attempt',('row','session_id'),uid(4)),
                ('attempt',('row','dispatch_id'),uid(4)),
                ('attempt',('row','data','reason'),'engagement_live_timeout'),
                ('attempt',('row','observed_at_ns'),199),
                ('watch',('source',),'role_observer'),
                ('watch',('row','broker_id'),uid(4)),
                ('watch',('row','observed_at_ns'),201),
                ('stop',('source',),'role_observer'),
                ('stop',('row','broker_id'),uid(4)),
                ('stop',('row','data','frame','channel_id'),uid(4)),
                ('stop',('row','data','frame','body','reason'),'engagement_live_timeout'),
                ('stop',('row','data','frame','operation'),'CLOSE'),
            ):
                changed=deepcopy({'attempt':attempt,'watch':watch,'stop':stop});target=changed[original]
                for key in path[:-1]:target=target[key]
                target[path[-1]]=value
                assert not e._changed_stop_cancellation(changed['attempt'],[changed['watch']],[changed['stop']],operations)
            if operation=='SESSION_STOP':
                stop['row']['data']['frame']['body']['session_id']=uid(4)
                assert not e._changed_stop_cancellation(attempt,[watch],[stop],operations)


def _external_revocation_race_cases():
    """Declared N38 facts exercise the full predicate, not a native witness.

    Real ledger transitions and unmocked transcript/history/cleanup checks keep
    the two failure layers separate: direct reserve denial can beat the watch.
    """
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    from recon_cockpit.secure_agent import engagement_live_context as context
    manifest,members=denied_fixture()
    loaded={name:json.loads(value) if name.endswith('.json') else value for name,value in members.items()}
    loaded['manifest.json']=manifest
    op=loaded['results.json']['operations'][0];p=op['prepared'];env=p['envelope']
    before=deepcopy(loaded['final-ledger.json']);digest=c.prepared_digest(p);at=11*c.SECOND
    revoke={'schema_version':'2','engagement_id':env['engagement_id'],'event_id':uid(900),
        'operation':'revoke','expected_revision':env['revision'],'expected_generation':env['generation'],'body':None}
    final,committed=ledger._apply(before,revoke);loaded['final-ledger.json']=final
    op['result']['reason']='engagement_live_revoked'
    case=e._case('S42C-N38')
    manifest.update(case_id=case['id'],configuration='A',evidence_class='owned_gate')
    configuration={'case_id':case['id'],'variant':case['variant'],'role':'broker'}
    loaded['runtime.json']['instrumentation']=[{'kind':'sealed_fault','source_sha256':'b'*64,
        'configuration':configuration,'configuration_sha256':sha(raw(configuration))}]
    proof={'schema_version':'1','case_id':case['id'],'variant':case['variant'],
        'dispatch_ids':[env['dispatch_id']],'before_state_sha256':before['events'][-1]['receipt']['state_sha256'],
        'after_state_sha256':committed['state_sha256'],'recovery_state_sha256':None,'transcript_refs':[]}
    bundle=loaded['runtime.json']['runtime'];ready={}
    for index,role in enumerate(('launcher','endpoint','nmap','admission')):
        ready[role]=declared_readiness(bundle,role,pid=600+index*10,worker_id=uid(600+index))
    loaded['processes.json']['readiness'].extend(ready.values())
    loaded['cleanup.json']['receipts']=[declared_cleanup(row,started=12*c.SECOND,finished=12_100_000_000)
        for row in loaded['processes.json']['readiness']]
    launcher=ready['launcher']['worker_ready']['worker_id']
    # The predicate consumes declared, prevalidated context. Keep its complete
    # allocation/join graph explicit rather than bypassing _all_reaped.
    for index,(name,(role,_,fd)) in enumerate(context._CHILD_SLOTS.items()):
        worker=ready[role]['worker_ready']['worker_id'] if name in ('identify_client','identify_admission') else uid(620+index)
        def endpoint(inode):return {'device':1,'inode':inode,'mode':stat.S_IFSOCK|0o600,'flags':2050}
        loaded['processes.json']['child_slots'].append({'schema_version':'1','broker_id':env['broker_id'],
            'session_id':env['session_id'],'launcher_id':launcher,'child_slot':name,'role':role,'worker_id':worker,
            'prepared_sha256':None,'bootstrap':None,'entry_sha256':None,
            'pair':{'launcher_fd':fd,'request_endpoint':endpoint(70000+2*index),'child_endpoint':endpoint(70001+2*index)}})
    loaded['cleanup.json']['supervisors']=[{'schema_version':'1','broker_id':env['broker_id'],
        'session_id':env['session_id'],'launcher_id':launcher,'host_observer':ready['launcher']['parent_observation']['observer'],
        'thread_native_id':601,'thread_started_at_ns':900000000,'state':'joined',
        'first_stop_requested_at_ns':12*c.SECOND,'cleanup_started_at_ns':12*c.SECOND,
        'cleanup_finished_at_ns':12_200_000_000,'cleanup_deadline_ns':13_900_000_000,
        'join_attempted':True,'thread_alive_observed':False,'channel_closed':True,'pending_slots':[],'status':'complete'}]
    def clock(when):
        anchor=env['clock_anchor']
        return {'mono_before_ns':when-1,'mono_after_ns':when,
            'utc_ns':anchor['utc_ns']+when-anchor['mono_after_ns']}
    def row(kind,data,when,source='broker_memfd',identified=True):
        return {'source':source,'row':{'schema_version':'1','broker_id':env['broker_id'],
            'observer_id':env['broker_id'],'session_id':env['session_id'] if identified else None,
            'dispatch_id':env['dispatch_id'] if identified else None,'row_sequence':1,
            'observed_at_ns':when,'kind':kind,'data':data}}
    def phase(name,stage,when,related,reason=None,source='role_observer'):
        return row('phase',{'phase':name,'stage':stage,'reason':reason,'related_sha256':related,
            'original_deadline_ns':env['action_deadline_ns'],'clock':clock(when-1)},when,source)
    def packet(operation,body,when,*,direction='sent',role='ingress',channel=uid(98),sequence=1,identified=True):
        return row('protocol',{'channel_role':role,'direction':direction,'frame':{'schema_version':'1',
            'channel_id':channel,'sequence':sequence,'operation':operation,'body':body}},when,identified=identified)
    prepared_receipt={'schema_version':'1','prepared_sha256':digest,'envelope_sha256':c.envelope_digest(env),
        'launcher_ready_sha256':sha(raw(ready['launcher']['worker_ready'])),
        'endpoint_ready_sha256':sha(raw(ready['endpoint'])),'client_ready_sha256':sha(raw(ready['nmap'])),
        'admission_ready_sha256':sha(raw(ready['admission'])),'admission_result_sha256':'c'*64,
        'admission_permit_sha256':'d'*64,'ready_at_ns':at,'preparation_deadline_ns':env['action_deadline_ns']}
    records={
        'prepared':packet('PREPARED',prepared_receipt,at+1,direction='received',role='launcher',channel=launcher),
        'request':packet('DISPATCH',{'prepared_sha256':digest,'reference_sha256':'f'*64,
            'consume_sequence':1,'audit_sequence':1},at+10,direction='received',identified=False),
        'pending':packet('DISPATCH',{'request_sequence':1,'status':'pending','code':None,
            'data':{'dispatch_id':env['dispatch_id']}},at+11,sequence=2),
        # Broker fixed reserve/begin hashes canonical Prepared bytes. Ingress
        # and host guard use the distinct domain-separated prepared_digest.
        'reserve':phase('reserve','begin',at+12,sha(raw(p)),source='broker_memfd'),
        'reply':packet('DISPATCH',{'request_sequence':1,'status':'ok','code':None,'data':deepcopy(op['result'])},at+29,sequence=3),
        'commit':phase('watch','end',at+20,committed['state_sha256']),
        'begin':phase('guard','begin',at+21,digest),
        'refused':phase('guard','refused',at+31,digest,'engagement_live_revoked')}
    def evaluate(value,observed,selected):
        parts=[];refs=[]
        for segment,(source,broker,status) in enumerate((('broker_memfd',env['broker_id'],'sealed_complete'),
                                                        ('role_observer',None,'observer_complete'))):
            values=[x['row'] for x in observed.values() if x['source']==source]
            for sequence,item in enumerate(values,1):
                item['row_sequence']=sequence;refs.append({'segment':segment,'row_sequence':sequence})
            parts.append((b''.join(raw(item)+b'\n' for item in values),source,broker,status))
        selected['transcript_refs']=refs;value['results.json']['core_proofs']=[selected]
        # Every mutation receives fresh byte/segment/export commitments so an
        # unrelated stale hash cannot supply the rejection under test.
        for export in value['cleanup.json']['exports']:
            name=export['reference']['phase']+'-ledger.json';encoded=raw(value[name])
            export['reference'].update(bytes=len(encoded),sha256=sha(encoded))
        encoded={name:raw(item) if name.endswith('.json') else item for name,item in value.items() if name!='manifest.json'}
        with_transcript(value['manifest.json'],encoded,parts);value['transcript.jsonl']=encoded['transcript.jsonl']
        return e._evaluate_core_proof(value,selected,{'dispatches':{env['dispatch_id']:{}}})
    assert records['request']['row']['observed_at_ns']<records['commit']['row']['observed_at_ns']
    assert not any(x['row']['kind']=='watch' for x in records.values())
    assert evaluate(deepcopy(loaded),deepcopy(records),deepcopy(proof)), 'N38 direct reserve denial without changed watch'
    # The terminal broker reply may finish before the host observes its pending
    # result. Only commit-before-denial and commit-before-host-attempt are needed.
    early_reply=deepcopy(records);early_reply['reply']['row']['observed_at_ns']=at+20
    assert evaluate(deepcopy(loaded),early_reply,deepcopy(proof))
    for route in ('direct','watch'):
        basis=deepcopy(loaded);original=deepcopy(records)
        if route=='watch':
            basis['results.json']['operations'][0]['result']=None;original.pop('reply')
            # Ordinary lifecycle observations have no body.reason. They remain
            # in the complete segment while STOP selection ignores them.
            original['role_observed']=packet('ROLE_OBSERVED',{'slot_index':0,'role':'launcher',
                'readiness':ready['launcher']},at+13,role='lifecycle',channel=env['broker_id'],identified=False)
            original['watch']=row('watch',{'clock':clock(at+24),'scheduled_at_ns':at+22,
                'started_at_ns':at+23,'finished_at_ns':at+24,'ledger_sequence':committed['sequence'],
                'ledger_state_sha256':committed['state_sha256'],'status':'changed','reason':'engagement_live_revoked'},at+25)
            original['stop']=packet('BROKER_STOP',{'reason':'engagement_live_revoked','observed_at_ns':at+26,
                'cleanup_deadline_ns':at+1_900_000_026},at+27,role='lifecycle',channel=env['broker_id'],identified=False)
            assert evaluate(deepcopy(basis),deepcopy(original),deepcopy(proof)), 'N38 actual watch/STOP without denial ACK'
        # The broker journals a sent packet after sending it. Host sampling
        # can interleave before that journal row; the later host refusal row
        # remains the upper bound for this cross-process observation.
        delayed_record=deepcopy(original)
        terminal=delayed_record['reply' if route=='direct' else 'stop']['row']
        terminal['observed_at_ns']=at+30
        refusal=delayed_record['refused']['row']
        assert refusal['data']['clock']['mono_before_ns']<terminal['observed_at_ns']<refusal['observed_at_ns']
        assert evaluate(deepcopy(basis),delayed_record,deepcopy(proof)), (route,'terminal journal after host clock sample')
        common=('missing_commit','commit_digest','commit_source','commit_observer','commit_broker','commit_session',
            'commit_dispatch','commit_deadline','late_commit','missing_begin','begin_digest','begin_broker','begin_session',
            'begin_dispatch','begin_before_commit','missing_refusal','refusal_digest','refusal_reason','refusal_before_commit',
            'missing_request','request_digest','missing_pending','pending_channel','pending_sequence','pending_dispatch',
            'missing_reserve_begin','reserve_digest','reserve_after_commit','reserved','extra_event','released','armed',
            'missing_waiting','waiting_hash','native_started','client_result','meter','capture','incomplete_cleanup',
            'reserve_future_clock','commit_future_clock','refusal_future_clock')
        extra=('missing_reply','reply_channel','reply_sequence','reply_dispatch','reply_digest','reply_reason',
               'reply_outcome','reply_before_commit','reply_after_refusal','result_mismatch',
               'result_broker','result_session','result_dispatch','result_slot','result_digest') if route=='direct' else (
               'missing_watch','watch_sequence','watch_digest','watch_reason','watch_before_commit',
               'missing_stop','stop_channel','stop_reason','stop_before_watch','stop_body_before_watch','stop_after_refusal')
        for variant in (*common,*extra):
            value=deepcopy(basis);changed=deepcopy(original);selected=deepcopy(proof)
            operation=value['results.json']['operations'][0]
            if variant.startswith('missing_'):
                key={'refusal':'refused','reserve_begin':'reserve','waiting':'prepared'}.get(variant[8:],variant[8:])
                changed.pop(key)
            elif variant in ('commit_digest','begin_digest','refusal_digest','reserve_digest'):
                key=variant.split('_')[0];key='refused' if key=='refusal' else key
                changed[key]['row']['data']['related_sha256']=digest if key=='reserve' else 'e'*64
            elif variant.endswith('_future_clock'):
                key=variant.split('_')[0];key='refused' if key=='refusal' else key
                phase_row=changed[key]['row']
                phase_row['data']['clock']=clock(phase_row['observed_at_ns']+2)
            elif variant.startswith('commit_') and variant.split('_')[1] in ('source','observer','broker','session','dispatch','deadline'):
                key=variant.split('_')[1]
                if key=='source':changed['commit']['source']='broker_memfd'
                elif key=='deadline':changed['commit']['row']['data']['original_deadline_ns']=env['action_deadline_ns']-1
                else:changed['commit']['row'][key+'_id']=uid(999)
            elif variant.startswith('begin_') and variant.split('_')[1] in ('broker','session','dispatch'):
                changed['begin']['row'][variant.split('_')[1]+'_id']=uid(999)
            elif variant in ('late_commit','begin_before_commit','refusal_before_commit','reserve_after_commit'):
                key,when={'late_commit':('commit',at+32),'begin_before_commit':('begin',at+19),
                    'refusal_before_commit':('refused',at+19),'reserve_after_commit':('reserve',at+22)}[variant]
                changed[key]['row']['observed_at_ns']=when;changed[key]['row']['data']['clock']=clock(when-1)
            elif variant=='refusal_reason':changed['refused']['row']['data']['reason']='engagement_live_cancelled'
            elif variant=='request_digest':changed['request']['row']['data']['frame']['body']['prepared_sha256']='e'*64
            elif variant in ('pending_channel','pending_sequence','pending_dispatch'):
                frame=changed['pending']['row']['data']['frame']
                if variant=='pending_channel':frame['channel_id']=uid(999)
                elif variant=='pending_sequence':frame['body']['request_sequence']=2
                else:frame['body']['data']['dispatch_id']=uid(999)
            elif variant=='extra_event':
                request=deepcopy(before['events'][-1]['request'])
                request['event_id']=uid(903);request['body'].update(session_id=uid(904),clock=clock(at-1))
                extra,_=ledger._apply(before,request)
                value['final-ledger.json'],revoked=ledger._apply(extra,revoke)
                selected['after_state_sha256']=revoked['state_sha256']
                changed['commit']['row']['data']['related_sha256']=revoked['state_sha256']
                if route=='watch':changed['watch']['row']['data'].update(ledger_sequence=revoked['sequence'],ledger_state_sha256=revoked['state_sha256'])
            elif variant in ('reserved','released','armed'):
                reserved,receipt=ledger._apply(before,{'schema_version':'2','engagement_id':env['engagement_id'],
                    'event_id':uid(901),'operation':'reserve','expected_revision':1,'expected_generation':0,
                    'body':{'owner_id':env['ledger_owner_id'],'session_id':env['session_id'],'dispatch_id':env['dispatch_id'],
                        'slot':env['slot'],'clock':clock(at-1),'approval':{'broker_id':env['reviewer_id'],'consume_sequence':1,'witness_sha256':'a'*64},
                        'audit':{'writer_id':uid(902),'audit_sequence':1,'event_sha256':'b'*64}}})
                if variant=='reserved':
                    value['final-ledger.json'],revoked=ledger._apply(reserved,revoke)
                    selected['after_state_sha256']=revoked['state_sha256']
                    changed['commit']['row']['data']['related_sha256']=revoked['state_sha256']
                    if route=='watch':changed['watch']['row']['data'].update(ledger_sequence=revoked['sequence'],ledger_state_sha256=revoked['state_sha256'])
                else:
                    release={'schema_version':'1','broker_id':env['broker_id'],'ledger_owner_id':env['ledger_owner_id'],
                        'session_id':env['session_id'],'dispatch_id':env['dispatch_id'],'envelope_sha256':c.envelope_digest(env),
                        'prepared_sha256':digest,'reservation_event_id':receipt['event_id'],'reservation_sequence':receipt['sequence'],
                        'reservation_state_sha256':receipt['state_sha256'],'approval_witness_sha256':'a'*64,'audit_witness_sha256':'b'*64,
                        'guard_clock':clock(at+21),'effective_lease_deadline_ns':20*c.SECOND,
                        'effect_stop_ns':c.effect_stop(p,20*c.SECOND),'release_sequence':1}
                    changed['release']=packet('GO' if variant=='released' else 'ARM',
                        release if variant=='released' else {'release':release,'slot':env['slot']},at+22,
                        role='launcher' if variant=='released' else 'arm',channel=launcher)
            elif variant=='waiting_hash':changed['prepared']['row']['data']['frame']['body']['client_ready_sha256']='e'*64
            elif variant=='native_started':
                parent=deepcopy(ready['nmap']['parent_observation']);parent['stage']='native'
                value['processes.json']['native']=[{'schema_version':'1','role':'nmap','waiting_image':parent['executable'],
                    'parent_observation':parent,'observed_at_ns':at+22}]
            elif variant in ('client_result','meter','capture'):
                operation[{'client_result':'client','capture':'host_capture'}.get(variant,variant)]={}
            elif variant=='incomplete_cleanup':value['cleanup.json']['receipts'][0]['status']='failed'
            elif variant.startswith('reply_'):
                frame=changed['reply']['row']['data']['frame'];body=frame['body']
                if variant=='reply_channel':frame['channel_id']=uid(999)
                elif variant=='reply_sequence':body['request_sequence']=2
                elif variant=='reply_dispatch':body['data']['dispatch_id']=uid(999)
                elif variant=='reply_digest':body['data']['envelope_sha256']='e'*64
                elif variant=='reply_reason':body['data']['reason']='engagement_live_allowance_exhausted'
                elif variant=='reply_outcome':body['data']['outcome']='unresolved'
                else:changed['reply']['row']['observed_at_ns']=at+19 if variant=='reply_before_commit' else at+32
            elif variant=='result_mismatch':operation['result']['reason']='engagement_live_allowance_exhausted'
            elif variant.startswith('result_'):
                key=variant.split('_')[1]
                field='envelope_sha256' if key=='digest' else 'slot' if key=='slot' else key+'_id'
                operation['result'][field]='e'*64 if key=='digest' else 'http_headers' if key=='slot' else uid(999)
                changed['reply']['row']['data']['frame']['body']['data']=deepcopy(operation['result'])
            elif variant.startswith('watch_'):
                data=changed['watch']['row']['data']
                if variant=='watch_sequence':data['ledger_sequence']-=1
                elif variant=='watch_digest':data['ledger_state_sha256']='e'*64
                elif variant=='watch_reason':data['reason']='engagement_live_revision_changed'
                else:
                    changed['watch']['row']['observed_at_ns']=at+19
                    data.update(scheduled_at_ns=at+15,started_at_ns=at+16,finished_at_ns=at+17,clock=clock(at+17))
            else:
                frame=changed['stop']['row']['data']['frame']
                if variant=='stop_channel':frame['channel_id']=uid(999)
                elif variant=='stop_reason':frame['body']['reason']='engagement_live_revision_changed'
                elif variant=='stop_body_before_watch':frame['body']['observed_at_ns']=at+24
                else:
                    when=at+24 if variant=='stop_before_watch' else at+32
                    changed['stop']['row']['observed_at_ns']=when;frame['body']['observed_at_ns']=when
            try:accepted=evaluate(value,changed,selected)
            except c.LiveError as error:assert error.code=='engagement_live_evidence_invalid',(route,variant)
            else:assert not accepted,(route,variant)


def _fixed_fault_phase_cases():
    """Declared prevalidated context for unmocked crash/durability predicates.

    These are synthetic ledger and observation facts, never physical crash
    evidence. Keep the actual producer's digest and stage distinct from host
    observations, and exercise the complete predicate rather than a stub.
    """
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    manifest,members=denied_fixture()
    baseline={name:json.loads(value) if name.endswith('.json') else value for name,value in members.items()}
    baseline['manifest.json']=manifest
    operation=baseline['results.json']['operations'][0];p=operation['prepared'];env=p['envelope']
    operation.update(result=None,client=None,meter=None,host_capture=None)
    before=deepcopy(baseline['final-ledger.json']);at=11*c.SECOND
    canonical_digest=sha(raw(p));host_digest=c.prepared_digest(p)
    assert canonical_digest!=host_digest
    def clock(when):
        anchor=env['clock_anchor']
        return {'mono_before_ns':when-1,'mono_after_ns':when,
            'utc_ns':anchor['utc_ns']+when-anchor['mono_after_ns']}
    def observed(kind,data,when,source='broker_memfd',*,broker=None,identified=True):
        bid=env['broker_id'] if broker is None else broker
        return {'source':source,'row':{'schema_version':'1','broker_id':bid,'observer_id':bid,
            'session_id':env['session_id'] if identified else None,
            'dispatch_id':env['dispatch_id'] if identified else None,'row_sequence':1,
            'observed_at_ns':when,'kind':kind,'data':data}}
    def phase(name,stage,when,digest,*,source='broker_memfd',reason=None,broker=None,identified=True):
        return observed('phase',{'phase':name,'stage':stage,'reason':reason,'related_sha256':digest,
            'original_deadline_ns':env['action_deadline_ns'],
            'clock':None if source=='role_observer' and stage=='begin' else clock(when-1)},
            when,source,broker=broker,identified=identified)
    def packet(operation,body,when,*,direction='sent',role='launcher',channel=uid(940),broker=None,identified=True):
        return observed('protocol',{'channel_role':role,'direction':direction,'frame':{'schema_version':'1',
            'channel_id':channel,'sequence':1,'operation':operation,'body':body}},when,
            broker=broker,identified=identified)
    reserve={'schema_version':'2','engagement_id':env['engagement_id'],'event_id':uid(941),'operation':'reserve',
        'expected_revision':env['revision'],'expected_generation':env['generation'],
        'body':{'owner_id':env['ledger_owner_id'],'session_id':env['session_id'],'dispatch_id':env['dispatch_id'],
            'slot':env['slot'],'clock':clock(at+3),
            'approval':{'broker_id':env['reviewer_id'],'consume_sequence':1,'witness_sha256':'a'*64},
            'audit':{'writer_id':uid(942),'audit_sequence':1,'event_sha256':'b'*64}}}
    admitted,reservation=ledger._apply(before,reserve)
    release={'schema_version':'1','broker_id':env['broker_id'],'ledger_owner_id':env['ledger_owner_id'],
        'session_id':env['session_id'],'dispatch_id':env['dispatch_id'],'envelope_sha256':c.envelope_digest(env),
        'prepared_sha256':host_digest,'reservation_event_id':reservation['event_id'],
        'reservation_sequence':reservation['sequence'],'reservation_state_sha256':reservation['state_sha256'],
        'approval_witness_sha256':'a'*64,'audit_witness_sha256':'b'*64,'guard_clock':clock(at+4),
        'effective_lease_deadline_ns':20*c.SECOND,'effect_stop_ns':c.effect_stop(p,20*c.SECOND),'release_sequence':1}
    second,owner,sid=uid(950),uid(951),uid(952)
    def fixture_for(number):
        value=deepcopy(baseline);m=value['manifest.json'];case=e._case('S42C-N'+str(number))
        m.update(case_id=case['id'],configuration='A',evidence_class='owned_gate')
        configuration={'case_id':case['id'],'variant':case['variant'],'role':'audit' if number==51 else 'broker'}
        item={'kind':'sealed_fault','source_sha256':'b'*64,'configuration':configuration,
            'configuration_sha256':sha(raw(configuration))}
        value['runtime.json']['instrumentation']=[item]
        m['instrumentation']=[{k:item[k] for k in ('kind','source_sha256','configuration_sha256')}]
        first=value['processes.json']['readiness'][0]
        value['cleanup.json']['receipts']=[declared_cleanup(first,started=12*c.SECOND,finished=12_100_000_000)]
        value['cleanup.json']['receipts'][0]['processes'][0].update(
            wrapper_returncode=137 if number in (42,43,44) else 0,signal_attempted=number in (42,43,44))
        final=deepcopy(admitted if number in (43,44,47,48) else before)
        name='go' if number==44 else 'complete' if number in (47,48) else 'audit' if number==51 else 'reserve'
        stage='end' if number in (43,44) else 'begin' if number==42 else 'refused'
        source='role_observer' if number==51 else 'broker_memfd'
        ordinary_digest=host_digest if number==51 else None
        records={'ordinary':phase(name,'begin',at+1 if number==43 else at+10,ordinary_digest,source=source)}
        if number==44:
            records['go']=packet('GO',deepcopy(release),at+12)
        elif number in (47,48):
            records={'go':packet('GO',deepcopy(release),at+5),**records}
        if number==43:
            records['durable']=phase('reserve','end',at+15,sha(raw({'schema_version':'2','kind':'data_only',
                'disposition':'recorded','receipt':reservation})))
        elif number==44:
            records['ordinary']['row']['data']['related_sha256']=sha(raw(release))
            records['released']=phase('go','end',at+15,sha(raw(release)))
        reason=None if number in (42,43,44) else 'engagement_live_audit_unavailable' if number==51 else 'engagement_live_unavailable'
        records['marker']=phase(name,stage,at+20,host_digest if number==51 else canonical_digest,
            source=source,reason=reason)
        if number in (42,43,44):
            records['signal_begin']=phase(name,'begin',at+23,host_digest,source='role_observer')
            records['signal_begin']['row']['data']['clock']=clock(at+22)
            records['signal_end']=phase(name,'end',at+25,host_digest,source='role_observer')
        if number in (43,44):
            ready=declared_readiness(value['runtime.json']['runtime'],'broker',pid=301,worker_id=second)
            ready['parent_observation']['sampled_at_ns']=13*c.SECOND
            value['processes.json']['readiness'].append(ready)
            receipt=declared_cleanup(ready,started=14*c.SECOND,finished=14_100_000_000)
            receipt['processes'][0].update(wrapper_returncode=0,signal_attempted=False)
            value['cleanup.json']['receipts'].append(receipt)
            m['broker_instances'].append({'broker_id':second,'ledger_owner_id':owner})
            m['ledger_exports']['final']['broker_id']=second
            next(x for x in value['cleanup.json']['exports'] if x['reference']['phase']=='final')['broker_id']=second
            final,_=ledger._apply(final,{'schema_version':'2','engagement_id':env['engagement_id'],'event_id':uid(953),
                'operation':'session','expected_revision':env['revision'],'expected_generation':env['generation'],
                'body':{'owner_id':owner,'session_id':sid,'clock':clock(13*c.SECOND+1),
                    'original_deadline_ns':env['session_deadline_ns']}})
            records['restart_request']=packet('DISPATCH',{'prepared_sha256':host_digest,'reference_sha256':'c'*64,
                'consume_sequence':1,'audit_sequence':1},13*c.SECOND+10,direction='received',role='ingress',
                channel=uid(954),broker=second,identified=False)
            records['restart_reply']=packet('DISPATCH',{'request_sequence':1,'status':'refused',
                'code':'engagement_live_dispatch_replayed','data':None},13*c.SECOND+12,role='ingress',
                channel=uid(954),broker=second,identified=False)
            records['restart_refusal']=phase('prepare','refused',13*c.SECOND+14,host_digest,
                source='role_observer',reason='engagement_live_dispatch_replayed',broker=second,identified=False)
        value['final-ledger.json']=deepcopy(final);value['recovery-ledger.json']=deepcopy(final)
        if number==42:
            value.pop('final-ledger.json')
            m['ledger_exports']['final']={'status':'unavailable','source':None,'file':None,'reason':'broker_lost','broker_id':None}
            value['cleanup.json']['exports']=[x for x in value['cleanup.json']['exports'] if x['reference']['phase']!='final']
        m['ledger_exports']['recovery']={'status':'complete','source':'postcleanup_readonly',
            'file':'recovery-ledger.json','reason':None,'broker_id':None}
        last=final['events'][-1]['receipt']['state_sha256']
        identity=lambda mode,inode:{'device':1,'inode':inode,'mode':mode,'uid':1000,'gid':1000}
        value['cleanup.json']['recovery']={'schema_version':'1','source':'postcleanup_readonly','owner_id':uid(955),
            'started_at_ns':15*c.SECOND,'finished_at_ns':15*c.SECOND+1000,'read_only':True,'closed':True,
            'ledger_state_sha256':last,'bytes':len(raw(final)),'sha256':sha(raw(final)),
            'store_identity':{'parent':identity(stat.S_IFDIR|0o700,900),
                'directory':identity(stat.S_IFDIR|0o700,901),'database':identity(stat.S_IFREG|0o600,902)}}
        proof={'schema_version':'1','case_id':case['id'],'variant':case['variant'],'dispatch_ids':[env['dispatch_id']],
            'before_state_sha256':before['events'][-1]['receipt']['state_sha256'],'after_state_sha256':last,
            'recovery_state_sha256':last,'transcript_refs':[]}
        return value,records,proof
    def evaluate(value,records,proof):
        number=int(proof['case_id'][-2:]);m=value['manifest.json'];parts=[];refs=[]
        sources=[('broker_memfd',entry['broker_id'],
            'reaped_partial' if number in (42,43,44) and entry['broker_id']==env['broker_id'] else 'sealed_complete')
            for entry in m['broker_instances']]+[('role_observer',None,'observer_complete')]
        for segment,(source,broker,status) in enumerate(sources):
            rows=[item['row'] for item in records.values() if item['source']==source
                and (source=='role_observer' or item['row']['broker_id']==broker)]
            for sequence,row in enumerate(rows,1):
                row['row_sequence']=sequence;refs.append({'segment':segment,'row_sequence':sequence})
            parts.append((b''.join(raw(row)+b'\n' for row in rows),source,broker,status))
        proof['transcript_refs']=refs;value['results.json']['core_proofs']=[proof]
        for export in value['cleanup.json']['exports']:
            data=raw(value[export['reference']['phase']+'-ledger.json'])
            export['reference'].update(bytes=len(data),sha256=sha(data))
        recovery=value['cleanup.json']['recovery']
        if recovery is not None:
            data=raw(value['recovery-ledger.json']);recovery.update(bytes=len(data),sha256=sha(data),
                ledger_state_sha256=value['recovery-ledger.json']['events'][-1]['receipt']['state_sha256'])
        encoded={name:raw(item) if name.endswith('.json') else item for name,item in value.items() if name!='manifest.json'}
        with_transcript(m,encoded,parts);value['transcript.jsonl']=encoded['transcript.jsonl']
        return e._evaluate_core_proof(value,proof,{'dispatches':{env['dispatch_id']:{}}})
    for number in (42,43,44,47,48,49,50,51):
        baseline_value,original,selected=fixture_for(number)
        assert evaluate(deepcopy(baseline_value),deepcopy(original),deepcopy(selected)), ('fixed fault positive',number)
        if number in (42,43,44):
            boundary=deepcopy(original);end=boundary['signal_end']['row']
            end['observed_at_ns']=boundary['marker']['row']['observed_at_ns']+c.SECOND
            end['data']['clock']=clock(end['observed_at_ns']-1)
            assert end['observed_at_ns']<env['action_deadline_ns']
            assert evaluate(deepcopy(baseline_value),boundary,deepcopy(selected)), ('fixed signal exact one second',number)
            extra_begin={'expected_failure_begin':phase(original['marker']['row']['data']['phase'],'begin',
                at+18,host_digest,source='role_observer'),**deepcopy(original)}
            assert evaluate(deepcopy(baseline_value),extra_begin,deepcopy(selected)), ('non-signal host begin',number)
            reaped=deepcopy(baseline_value);receipt=reaped['cleanup.json']['receipts'][0]
            receipt.update(started_at_ns=at+21,finished_at_ns=at+24,deadline_ns=at+21+2*c.SECOND)
            assert evaluate(reaped,deepcopy(original),deepcopy(selected)), ('reap before signal-end journal',number)
        common=('missing_marker','marker_digest','marker_source','marker_broker','marker_observer','marker_session',
            'marker_dispatch','marker_deadline','marker_future_clock','marker_expired','marker_stage','marker_reason','missing_recovery')
        crash=('missing_signal_begin','missing_signal_end','signal_begin_digest','signal_end_digest',
            'signal_begin_broker','signal_begin_observer','signal_end_source','signal_end_session','signal_end_dispatch',
            'signal_end_deadline','signal_end_future_clock','signal_begin_null_clock',
            'signal_before_marker','signal_reverse_time','signal_after_hold','not_killed',
            'duplicate_signal_begin','duplicate_signal_end','cleanup_before_signal',
            'killed_pid','killed_start','killed_wrapper') if number in (42,43,44) else ()
        durability=('missing_ordinary','ordinary_digest','ordinary_source','ordinary_broker','ordinary_observer',
            'ordinary_session','ordinary_dispatch','ordinary_deadline','ordinary_phase','ordinary_stage','ordinary_after_marker',
            'ordinary_reverse_sequence') if number in (42,47,48,49,50,51) else ()
        restart=('missing_restart_request','missing_restart_reply','missing_restart_refusal','restart_reply_channel',
            'restart_reply_reason','restart_refusal_digest','foreign_killed_broker') if number in (43,44) else ()
        terminal=('reserved','released') if number in (42,49,50,51) else ('completed',) if number in (47,48) else ()
        for variant in (*common,*crash,*durability,*restart,*terminal):
            value=deepcopy(baseline_value);records=deepcopy(original);proof=deepcopy(selected)
            if variant=='missing_recovery':
                value.pop('recovery-ledger.json');value['cleanup.json']['recovery']=None;proof['recovery_state_sha256']=None
            elif variant.startswith('missing_'):records.pop(variant[len('missing_'):])
            elif variant=='not_killed':value['cleanup.json']['receipts'][0]['processes'][0]['wrapper_returncode']=78
            elif variant.startswith('duplicate_signal_'):
                records[variant]=deepcopy(records[variant[len('duplicate_'):]])
            elif variant=='cleanup_before_signal':
                value['cleanup.json']['receipts'][0].update(
                    started_at_ns=at+20,finished_at_ns=at+21,deadline_ns=at+20+2*c.SECOND)
            elif variant in ('killed_pid','killed_start','killed_wrapper'):
                field={'killed_pid':'pid','killed_start':'start_time_ticks','killed_wrapper':'wrapper_pid'}[variant]
                value['cleanup.json']['receipts'][0]['processes'][0][field]+=1000
            elif variant=='foreign_killed_broker':
                value['cleanup.json']['receipts'][0]['processes'][0].update(wrapper_returncode=0,signal_attempted=False)
                value['cleanup.json']['receipts'][1]['processes'][0].update(wrapper_returncode=137,signal_attempted=True)
            elif variant=='marker_expired':
                row=records['marker']['row'];row['observed_at_ns']=env['action_deadline_ns']
                row['data']['clock']=clock(row['observed_at_ns']-1)
            elif variant=='signal_after_hold':
                end=records['signal_end']['row'];end['observed_at_ns']=records['marker']['row']['observed_at_ns']+c.SECOND+1
                end['data']['clock']=clock(end['observed_at_ns']-1)
                assert end['observed_at_ns']<env['action_deadline_ns']
            elif variant in ('signal_before_marker','signal_reverse_time','ordinary_after_marker'):
                key='ordinary' if variant=='ordinary_after_marker' else 'signal_begin' if variant=='signal_before_marker' else 'signal_end'
                when=at+21 if variant=='ordinary_after_marker' else at+19 if variant=='signal_before_marker' else at+22
                records[key]['row']['observed_at_ns']=when
                if records[key]['row']['data']['clock'] is not None:records[key]['row']['data']['clock']=clock(when-1)
            elif variant=='ordinary_reverse_sequence':
                ordinary=records.pop('ordinary');records['ordinary']=ordinary
            elif variant=='restart_reply_channel':records['restart_reply']['row']['data']['frame']['channel_id']=uid(999)
            elif variant=='restart_reply_reason':records['restart_reply']['row']['data']['frame']['body']['code']='engagement_live_foreign_owner'
            elif variant=='restart_refusal_digest':records['restart_refusal']['row']['data']['related_sha256']='e'*64
            elif variant in ('reserved','completed'):
                if variant=='reserved':final=deepcopy(admitted)
                else:
                    final,_=ledger._apply(value['final-ledger.json'],{'schema_version':'2','engagement_id':env['engagement_id'],
                        'event_id':uid(956),'operation':'complete','expected_revision':None,'expected_generation':None,
                        'body':{'owner_id':env['ledger_owner_id'],'session_id':env['session_id'],'dispatch_id':env['dispatch_id'],
                            'outcome':'reported_failure','observation':None,'clock':clock(at+30)}})
                value['final-ledger.json']=deepcopy(final);value['recovery-ledger.json']=final
                proof['after_state_sha256']=proof['recovery_state_sha256']=final['events'][-1]['receipt']['state_sha256']
            elif variant=='released':records['go']=packet('GO',deepcopy(release),at+30)
            else:
                key=next(key for key in ('signal_begin','signal_end','ordinary','marker') if variant.startswith(key+'_'))
                field=variant[len(key)+1:];item=records[key];row=item['row'];data=row['data']
                if field=='digest':
                    data['related_sha256']=canonical_digest if item['source']=='role_observer' else host_digest
                elif field=='source':item['source']='role_observer' if item['source']=='broker_memfd' else 'broker_memfd'
                elif field in ('broker','observer','session','dispatch'):row[field+'_id']=uid(999)
                elif field=='deadline':data['original_deadline_ns']-=1
                elif field=='future_clock':data['clock']=clock(row['observed_at_ns']+2)
                elif field=='null_clock':data['clock']=None
                elif field=='stage':data['stage']='end' if data['stage']!='end' else 'begin'
                elif field=='phase':data['phase']='guard'
                elif field=='reason':data['reason']='engagement_live_timeout'
                else:raise AssertionError(variant)
            try:accepted=evaluate(value,records,proof)
            except c.LiveError as error:assert error.code=='engagement_live_evidence_invalid',(number,variant)
            else:assert not accepted,(number,variant)


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


def _reused_namespace_replay(loaded,rows):
    """Historical namespace inode reuse cannot choose another session's endpoint."""
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    from recon_cockpit.secure_agent import engagement_live_context as context
    changed=deepcopy(loaded)
    endpoint=declared_readiness(changed['runtime.json']['runtime'],'endpoint',pid=1980,worker_id=uid(1980))
    current=next(x for x in changed['processes.json']['readiness'] if x['role']=='endpoint')
    assert endpoint['parent_observation']['namespaces']['net']==current['parent_observation']['namespaces']['net']
    changed['processes.json']['readiness'].append(endpoint)
    changed['cleanup.json']['receipts'].append(declared_cleanup(endpoint))
    assert context.validate_supervision_transcript(changed,rows)['missing_evidence']==[]
    for variant in ('missing_endpoint','missing_launcher','foreign_source','foreign_broker','foreign_slot',
                    'duplicate','late','future_sample','wrong_ready','missing_retained','wrong_observer'):
        bad=deepcopy(changed);altered=deepcopy(rows)
        target=next(x for x in altered if x['row']['kind']=='protocol' and
            x['row']['data']['frame']['operation']=='ROLE_OBSERVED' and
            x['row']['data']['frame']['body']['role']==('launcher' if variant=='missing_launcher' else 'endpoint'))
        body=target['row']['data']['frame']['body']
        if variant.startswith('missing_') and variant!='missing_retained':altered.remove(target)
        elif variant=='foreign_source':target['source']='role_observer'
        elif variant=='foreign_broker':target['row'].update(broker_id=uid(1981),observer_id=uid(1981))
        elif variant=='foreign_slot':body['slot_index']=1
        elif variant=='duplicate':altered.append(deepcopy(target))
        elif variant=='late':target['row']['observed_at_ns']=bad['results.json']['operations'][0]['prepared']['envelope']['action_deadline_ns']
        elif variant=='future_sample':
            body['readiness']['parent_observation']['sampled_at_ns']=target['row']['observed_at_ns']+1
            worker=body['readiness']['worker_ready']['worker_id']
            bad['processes.json']['readiness']=[body['readiness'] if x['worker_ready']['worker_id']==worker else x for x in bad['processes.json']['readiness']]
        elif variant=='wrong_ready':body['readiness']=deepcopy(endpoint)
        elif variant=='missing_retained':
            bad['processes.json']['readiness']=[x for x in bad['processes.json']['readiness'] if x!=current]
        else:target['row']['observer_id']=uid(1981)
        if variant in ('duplicate','late','future_sample','wrong_ready','wrong_observer'):
            refused(context.validate_supervision_transcript,bad,altered)
        else:assert 'transcript' in context.validate_supervision_transcript(bad,altered)['missing_evidence']


def _cancelled_capture_replay(loaded,original_rows):
    """Declared interrupted exchange with complete terminal source facts.

    This is a pure supervision fixture, not a native run or a fabricated
    CAPTURED acknowledgment. The earlier timeout-only fixture stays incomplete.
    """
    from recon_cockpit.secure_agent import engagement_live_context as context
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    partial=deepcopy(loaded);rows=deepcopy(original_rows)
    op=partial['results.json']['operations'][0];env=op['prepared']['envelope']
    op.update(result=None,client=None,meter=None)
    state=None
    for event in partial['final-ledger.json']['events']:
        if event['request']['operation']!='complete':state,_=ledger._apply(state,event['request'])
    partial['final-ledger.json']=state
    slots=partial['processes.json']['child_slots']
    parser=next(x for x in slots if x['child_slot']=='identify_parser')
    parser_ready=next(x for x in partial['processes.json']['readiness']
        if x['worker_ready']['worker_id']==parser['worker_id'])
    parser_payload=parser_ready['parent_observation']['payload']
    partial['processes.json']['readiness'].remove(parser_ready)
    partial['processes.json']['startup']=[x for x in partial['processes.json']['startup']
        if x['payload']!=parser_payload]
    partial['cleanup.json']['receipts']=[x for x in partial['cleanup.json']['receipts']
        if not any(p['pid']==parser_payload['pid'] and p['start_time_ticks']==parser_payload['start_time_ticks']
            for p in x['processes'])]
    parser.update(prepared_sha256=None,bootstrap=None,entry_sha256=None)
    request_row=next(x for x in rows if x['row']['kind']=='supervision_projection' and
        x['row']['data']['request']['operation']=='CAPTURE')
    data=request_row['row']['data'];channel=data['launcher_id']
    def keep(item):
        row=item['row'];value=row['data']
        if row['kind']=='supervision_projection':return value['request']['sequence']<=data['request']['sequence']
        if row['kind']!='protocol':return True
        frame=value['frame'];body=frame['body']
        if frame['operation']=='METER':return False
        if frame['operation']=='DISPATCH' and value['direction']=='sent':return False
        if frame['operation']=='OBSERVATION' and body['kind'] in ('role_readiness','cleanup','capture'):return False
        return True
    rows=[x for x in rows if keep(x)]
    # Capture cleanup may already finish before cancellation is observed. Its
    # exact raw capture and single-child receipt remain independently retained.
    host=op['host_capture'];receipt=next(x for x in partial['cleanup.json']['receipts']
        if sha(raw(x))==host['cleanup_sha256'])
    at=receipt['started_at_ns']-10;stop=receipt['finished_at_ns']+3
    data['request']['observed_at_ns']=at
    data.update(reply=None,local_error='engagement_live_cancelled')
    request_row['row']['observed_at_ns']=stop+3
    closure=next(x for x in partial['cleanup.json']['supervisors'] if x['launcher_id']==channel)
    finished=max(closure['cleanup_finished_at_ns'],stop+5)
    deadline=min(env['action_deadline_ns'],env['session_deadline_ns'],env['broker_deadline_ns'],stop+1000000000)
    wire_deadline=deadline-100000000
    closure.update(first_stop_requested_at_ns=stop,cleanup_started_at_ns=stop+1,
        cleanup_finished_at_ns=finished,cleanup_deadline_ns=deadline)
    cause=deepcopy(request_row);cause['row']['observed_at_ns']=stop+2
    cause['row']['data']={key:data[key] for key in ('launcher_id','child_slot','child_worker_id','prepared_sha256')}
    cause['row']['data'].update(kind='local_failure',code='engagement_live_cancelled',observed_at_ns=stop+2,
        capture_sha256=None,cleanup_sha256=None)
    final=deepcopy(cause);final['row']['observed_at_ns']=finished+1
    final['row']['data'].update(observed_at_ns=finished+1,capture_sha256=sha(raw(host)),
        cleanup_sha256=host['cleanup_sha256'])
    rows.remove(request_row);rows.extend((cause,request_row,final))
    stop_row={'segment':0,'source':'broker_memfd','row':{'schema_version':'1',
        'broker_id':env['broker_id'],'observer_id':env['broker_id'],'session_id':None,'dispatch_id':None,
        'row_sequence':1,'observed_at_ns':stop-1,'kind':'protocol','data':{'channel_role':'lifecycle',
            'direction':'sent','frame':{'schema_version':'1','channel_id':env['broker_id'],'sequence':1,
                'operation':'BROKER_STOP','body':{'reason':'engagement_live_revoked',
                    'observed_at_ns':stop-2,'cleanup_deadline_ns':wire_deadline}}}}}
    rows.append(stop_row)
    counters={}
    for row in rows:
        segment=row['segment'];counters[segment]=counters.get(segment,0)+1
        row['row']['row_sequence']=counters[segment]
    parts=[];offset=0
    for index,segment in enumerate(partial['manifest.json']['transcript']['segments']):
        encoded=b''.join(raw(x['row'])+b'\n' for x in rows if x['segment']==index)
        segment.update(offset=offset,bytes=len(encoded),sha256=sha(encoded))
        parts.append(encoded);offset+=len(encoded)
    partial['transcript.jsonl']=b''.join(parts)
    replay=context.validate_supervision_transcript(partial,rows)
    assert replay['missing_evidence']==[] and replay['all_closed'] and replay['cleanup_complete']
    assert replay['dispatches'][env['dispatch_id']]['capture'] is not None
    assert data['reply'] is None and op['result'] is None and op['client'] is None
    assert not partial['final-ledger.json']['completions']
    # The sealed STOP records a send, not a host receive. Another terminal
    # channel can start a later host epoch; physical completion still fits both.
    assert finished<wire_deadline<deadline<=stop+1_900_000_000
    assert all(x['finished_at_ns']<=wire_deadline for x in partial['cleanup.json']['receipts'])
    for variant in ('missing_cause','missing_final','cause_code','rpc_code','cause_dispatch',
                    'cause_capture','cause_cleanup',
                    'final_worker','final_prepared','capture_hash','cleanup_hash','missing_capture',
                    'missing_stop','foreign_stop','foreign_stop_channel','late_stop','partial_stop','early_stop',
                    'early_cause','early_final','late_final','open_channel','pending_slot','cleanup_bound',
                    'late_cleanup','wire_late_cleanup','wire_late_supervisor','wire_late_final',
                    'wire_late_global_cleanup','wire_late_sibling','extra_broker','host_epoch',
                    'missing_native','cleanup_pid','cleanup_wrapper',
                    'raw_capture','useful_result','completion','later_rpc'):
        bad=deepcopy(partial);changed=deepcopy(rows)
        rpc=next(x for x in changed if x['row']['kind']=='supervision_projection' and
            x['row']['data']['kind']=='rpc' and x['row']['data']['request']['operation']=='CAPTURE')
        failures=[x for x in changed if x['row']['kind']=='supervision_projection' and
            x['row']['data']['kind']=='local_failure']
        first,last=failures
        closed=next(x for x in bad['cleanup.json']['supervisors'] if x['launcher_id']==channel)
        terminal=next(x for x in changed if x['row']['kind']=='protocol' and
            x['row']['data']['frame']['operation']=='BROKER_STOP')
        operation=bad['results.json']['operations'][0]
        if variant=='missing_cause':changed.remove(first)
        elif variant=='missing_final':changed.remove(last)
        elif variant=='cause_code':first['row']['data']['code']='engagement_live_timeout'
        elif variant=='rpc_code':rpc['row']['data']['local_error']='engagement_live_timeout'
        elif variant=='cause_dispatch':first['row']['dispatch_id']=uid(999)
        elif variant=='cause_capture':first['row']['data']['capture_sha256']=sha(raw(operation['host_capture']))
        elif variant=='cause_cleanup':first['row']['data']['cleanup_sha256']=operation['host_capture']['cleanup_sha256']
        elif variant=='final_worker':last['row']['data']['child_worker_id']=uid(999)
        elif variant=='final_prepared':last['row']['data']['prepared_sha256']='d'*64
        elif variant=='capture_hash':last['row']['data']['capture_sha256']='d'*64
        elif variant=='cleanup_hash':last['row']['data']['cleanup_sha256']='d'*64
        elif variant=='missing_capture':operation['host_capture']=None
        elif variant=='missing_stop':changed.remove(terminal)
        elif variant=='foreign_stop':terminal['row']['broker_id']=uid(999)
        elif variant=='foreign_stop_channel':terminal['row']['data']['frame']['channel_id']=uid(999)
        elif variant=='late_stop':terminal['row']['observed_at_ns']=stop+1
        elif variant=='partial_stop':bad['manifest.json']['transcript']['segments'][0]['status']='reaped_partial'
        elif variant=='early_stop':closed['first_stop_requested_at_ns']=at-1
        elif variant=='early_cause':first['row']['data']['observed_at_ns']=stop-1
        elif variant=='early_final':
            value=closed['cleanup_finished_at_ns']-1
            last['row']['data']['observed_at_ns']=value;last['row']['observed_at_ns']=value
        elif variant=='late_final':last['row']['data']['observed_at_ns']=deadline+1;last['row']['observed_at_ns']=deadline+1
        elif variant=='open_channel':closed.update(channel_closed=False,status='failed')
        elif variant=='pending_slot':closed.update(pending_slots=['identify_client'],status='failed')
        elif variant=='cleanup_bound':closed['cleanup_deadline_ns']=env['action_deadline_ns']+1
        elif variant=='host_epoch':closed['cleanup_deadline_ns']=stop+1_900_000_001
        elif variant=='extra_broker':
            bad['manifest.json']['broker_instances'].append({'broker_id':uid(990),'ledger_owner_id':uid(991)})
        elif variant=='wire_late_global_cleanup':
            item=next(x for x in bad['cleanup.json']['receipts'] if any(p['role']=='broker' for p in x['processes']))
            item['finished_at_ns']=wire_deadline+1
            assert item['finished_at_ns']<min(item['deadline_ns'],deadline)
        elif variant=='wire_late_sibling':
            # A fully allocated but never-started sibling has its own valid
            # closure. BROKER_STOP must also bound its actual channel cleanup.
            sibling=deepcopy(closed)
            sibling.update(session_id=uid(992),launcher_id=uid(993),state='not_started',
                thread_native_id=None,thread_started_at_ns=None,join_attempted=False)
            bad['cleanup.json']['supervisors'].append(sibling)
            for index,slot in enumerate(list(bad['processes.json']['child_slots'])):
                if slot['launcher_id']!=channel:continue
                other=deepcopy(slot)
                other.update(session_id=sibling['session_id'],launcher_id=sibling['launcher_id'],
                    worker_id=uid(950+index),prepared_sha256=None,bootstrap=None,entry_sha256=None)
                for endpoint in ('request_endpoint','child_endpoint'):other['pair'][endpoint]['inode']+=50000
                bad['processes.json']['child_slots'].append(other)
            assert context.validate_supervision_transcript(bad,changed)['missing_evidence']==[]
            sibling['cleanup_finished_at_ns']=wire_deadline+1
            assert sibling['cleanup_finished_at_ns']<sibling['cleanup_deadline_ns']
        elif variant in ('wire_late_supervisor','wire_late_final'):
            if variant=='wire_late_supervisor':closed['cleanup_finished_at_ns']=wire_deadline+1
            last['row']['data']['observed_at_ns']=wire_deadline+2;last['row']['observed_at_ns']=wire_deadline+2
            assert last['row']['observed_at_ns']<closed['cleanup_deadline_ns']
        elif variant in ('late_cleanup','wire_late_cleanup','cleanup_pid','cleanup_wrapper'):
            item=next(x for x in bad['cleanup.json']['receipts'] if sha(raw(x))==operation['host_capture']['cleanup_sha256'])
            if variant=='late_cleanup':item.update(finished_at_ns=finished+1)
            elif variant=='wire_late_cleanup':
                item['finished_at_ns']=wire_deadline+1
                closed['cleanup_finished_at_ns']=wire_deadline+2
                last['row']['data']['observed_at_ns']=wire_deadline+3;last['row']['observed_at_ns']=wire_deadline+3
                assert item['finished_at_ns']<item['deadline_ns']
                assert last['row']['observed_at_ns']<closed['cleanup_deadline_ns']
            else:item['processes'][0]['pid' if variant=='cleanup_pid' else 'wrapper_pid']=999999
            digest=sha(raw(item));operation['host_capture']['cleanup_sha256']=digest
            last['row']['data'].update(cleanup_sha256=digest,capture_sha256=sha(raw(operation['host_capture'])))
        elif variant=='missing_native':bad['processes.json']['native']=[]
        elif variant=='raw_capture':
            name='client-'+env['dispatch_id']+'.stdout.bin';bad[name]+=b'!'
        elif variant=='useful_result':operation['result']=deepcopy(loaded['results.json']['operations'][0]['result'])
        elif variant=='completion':bad['final-ledger.json']=deepcopy(loaded['final-ledger.json'])
        else:
            extra=deepcopy(rpc);extra['row']['data']['request'].update(observed_at_ns=finished+2,
                sequence=extra['row']['data']['request']['sequence']+1)
            changed.append(extra)
        try:report=context.validate_supervision_transcript(bad,changed)
        except c.LiveError as error:assert error.code=='engagement_live_evidence_invalid',variant
        else:assert {'transcript','cleanup'}&set(report['missing_evidence']),variant


def _cancelled_native_begin_replay(loaded,original_rows):
    """Declared crash interruption through the complete supervision replay.

    A retained request and physical closure do not manufacture NATIVE_BUDGET,
    native execution, useful output or a refund of the committed reservation.
    The separate fixed-fault cases exercise all three complete crash predicates.
    Other missing replies and missing terminal source facts remain unresolved.
    """
    from recon_cockpit.secure_agent import engagement_live_context as context
    from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
    from test_secure_engagement_live_runtime import declared_readiness,declared_cleanup
    value=deepcopy(loaded);rows=deepcopy(original_rows)
    op=value['results.json']['operations'][0];prepared=op['prepared'];env=prepared['envelope']
    anchor=env['clock_anchor']['mono_after_ns'];digest=c.prepared_digest(prepared)
    canonical_digest=sha(raw(prepared));assert digest!=canonical_digest
    original_operation=deepcopy(op)
    op.update(result=None,client=None,meter=None)
    state=None
    for event in value['final-ledger.json']['events']:
        if event['request']['operation']!='complete':state,_=ledger._apply(state,event['request'])
    value['final-ledger.json']=state;value['recovery-ledger.json']=deepcopy(state)
    slots=value['processes.json']['child_slots']
    client_slot=next(x for x in slots if x['child_slot']=='identify_client')
    parser=next(x for x in slots if x['child_slot']=='identify_parser')
    parser_ready=next(x for x in value['processes.json']['readiness']
        if x['worker_ready']['worker_id']==parser['worker_id'])
    parser_payload=parser_ready['parent_observation']['payload']
    value['processes.json']['readiness'].remove(parser_ready)
    value['processes.json']['startup']=[x for x in value['processes.json']['startup'] if x['payload']!=parser_payload]
    value['cleanup.json']['receipts']=[x for x in value['cleanup.json']['receipts'] if not any(
        p['pid']==parser_payload['pid'] and p['start_time_ticks']==parser_payload['start_time_ticks'] for p in x['processes'])]
    parser.update(prepared_sha256=None,bootstrap=None,entry_sha256=None)
    value['processes.json']['native']=[]
    rpc=next(x for x in rows if x['row']['kind']=='supervision_projection'
        and x['row']['data']['request']['operation']=='NATIVE_BEGIN')
    data=rpc['row']['data'];channel=data['launcher_id'];sequence=data['request']['sequence']
    def keep(item):
        row=item['row'];part=row['data']
        if row['kind']=='supervision_projection':return part['request']['sequence']<=sequence
        if row['kind']=='meter':return False
        if row['kind']!='protocol':return True
        frame=part['frame'];body=frame['body']
        if frame['operation']=='METER':return False
        if frame['operation']=='DISPATCH' and part['direction']=='sent' and body['status']!='pending':return False
        if frame['operation']=='OBSERVATION' and body['kind'] in ('role_readiness','cleanup','capture'):return False
        return True
    rows=[x for x in rows if keep(x)]
    assert any(x['row']['kind']=='protocol' and x['row']['data']['frame']['operation']=='DISPATCH'
        and x['row']['data']['direction']=='sent' and x['row']['data']['frame']['body']['status']=='pending' for x in rows)
    go=next(x for x in rows if x['row']['kind']=='protocol'
        and x['row']['data']['frame']['operation']=='GO')
    request_at=anchor+100;stop=anchor+110;finished=anchor+160;deadline=stop+1_900_000_000
    data['request']['observed_at_ns']=request_at
    data.update(reply=None,local_error='engagement_live_cancelled');rpc['row']['observed_at_ns']=anchor+130
    host=op['host_capture'];client_cleanup=next(x for x in value['cleanup.json']['receipts']
        if sha(raw(x))==host['cleanup_sha256'])
    for receipt in value['cleanup.json']['receipts']:
        if any(p['role']=='admission' for p in receipt['processes']):continue
        receipt.update(started_at_ns=anchor+135,finished_at_ns=anchor+155,deadline_ns=deadline)
    client_cleanup.update(started_at_ns=anchor+140,finished_at_ns=anchor+150)
    client_cleanup['processes'][0].update(wrapper_returncode=137,signal_attempted=True)
    for stream in ('stdout','stderr'):
        value['client-'+env['dispatch_id']+'.'+stream+'.bin']=b''
        host.update({stream+'_bytes':0,stream+'_sha256':sha(b'')})
    host.update(status='unresolved',exit_code=137,truncated=False,cleanup_sha256=sha(raw(client_cleanup)))
    closed=next(x for x in value['cleanup.json']['supervisors'] if x['launcher_id']==channel)
    closed.update(first_stop_requested_at_ns=stop,cleanup_started_at_ns=stop+1,
        cleanup_finished_at_ns=finished,cleanup_deadline_ns=deadline)
    broker_ready=next(x for x in value['processes.json']['readiness'] if x['role']=='broker'
        and x['worker_ready']['worker_id']==env['broker_id'])
    broker_parent=broker_ready['parent_observation'];broker_pid=broker_parent['payload']['pid']
    broker_cleanup=next(x for x in value['cleanup.json']['receipts'] if any(
        p['role']=='broker' and p['pid']==broker_pid for p in x['processes']))
    broker_cleanup['processes'][0].update(wrapper_returncode=137,signal_attempted=False)
    def clock(when):
        base=env['clock_anchor']
        return {'mono_before_ns':when-1,'mono_after_ns':when,
            'utc_ns':base['utc_ns']+when-base['mono_after_ns']}
    def phase(stage,when,source,related):
        return {'segment':0 if source=='broker_memfd' else 1,'source':source,'row':{
            'schema_version':'1','broker_id':env['broker_id'],'session_id':env['session_id'],
            'dispatch_id':env['dispatch_id'],'observer_id':env['broker_id'],'row_sequence':1,
            'observed_at_ns':when,'kind':'phase','data':{'phase':'go','stage':stage,'reason':None,
                'related_sha256':related,'original_deadline_ns':env['action_deadline_ns'],'clock':clock(when-1)}}}
    marker=phase('end',anchor+10,'broker_memfd',canonical_digest)
    signal_begin=phase('begin',anchor+20,'role_observer',digest)
    signal_end=phase('end',anchor+30,'role_observer',digest)
    cause=deepcopy(rpc);cause['row']['observed_at_ns']=anchor+120
    cause['row']['data']={k:data[k] for k in ('launcher_id','child_slot','child_worker_id','prepared_sha256')}
    cause['row']['data'].update(kind='local_failure',code='engagement_live_cancelled',observed_at_ns=anchor+120,
        capture_sha256=None,cleanup_sha256=None)
    final=deepcopy(cause);final['row']['observed_at_ns']=anchor+170
    final['row']['data'].update(observed_at_ns=anchor+170,capture_sha256=sha(raw(host)),cleanup_sha256=host['cleanup_sha256'])
    rows.remove(rpc);rows.extend((marker,signal_begin,signal_end,cause,rpc,final))
    value['manifest.json']['transcript'].update(status='partial',reason='broker_lost')
    value['manifest.json']['transcript']['segments'][0].update(status='reaped_partial',seals=0)
    def encode(current,observations):
        parts=[];offset=0
        for index,segment in enumerate(current['manifest.json']['transcript']['segments']):
            selected=[x for x in observations if x['segment']==index]
            for number,item in enumerate(selected,1):item['row']['row_sequence']=number
            part=b''.join(raw(x['row'])+b'\n' for x in selected)
            segment.update(offset=offset,bytes=len(part),sha256=sha(part));parts.append(part);offset+=len(part)
        current['transcript.jsonl']=b''.join(parts)
    def replay(current,observations):
        encode(current,observations)
        return context.validate_supervision_transcript(current,observations)
    result=replay(value,rows)
    assert result['missing_evidence']==[] and result['all_closed'] and result['cleanup_complete']
    assert result['dispatches'][env['dispatch_id']]['native_budget'] is None
    assert result['dispatches'][env['dispatch_id']]['capture'] is not None
    assert data['reply'] is None and all(op[k] is None for k in ('result','client','meter'))
    assert len(state['reservations'])==1 and state['state']['usage']==env['cost'] and not state['completions']
    # Aggregate graph receipts repeat actual process identities. An honest
    # duplicate observation is allowed, but its earliest broker reap must also
    # follow the signal attempt; a later single-process row cannot conceal it.
    aggregate_case=deepcopy(value)
    aggregate=deepcopy(broker_cleanup)
    companion=next(x for x in value['cleanup.json']['receipts'] if len(x['processes'])==1
        and x['processes'][0]['role']=='audit')
    aggregate['processes'].extend(deepcopy(companion['processes']))
    aggregate.update(started_at_ns=anchor+135,finished_at_ns=anchor+156)
    aggregate_case['cleanup.json']['receipts'].append(aggregate)
    assert replay(aggregate_case,deepcopy(rows))['missing_evidence']==[]
    aggregate.update(started_at_ns=anchor+8,finished_at_ns=anchor+18)
    assert aggregate['finished_at_ns']<signal_begin['row']['data']['clock']['mono_after_ns']
    assert 'transcript' in replay(aggregate_case,deepcopy(rows))['missing_evidence']
    # The launcher, signal recorder and cleanup monitor run concurrently. Only
    # causal lower bounds apply: a sent GO may reach NATIVE_BEGIN before the
    # signal, and an actual reap may precede the signal's final journal row.
    for ordering in ('request_before_signal','early_broker_reap','late_signal_journal','combined'):
        reordered=deepcopy(value);observations=deepcopy(rows)
        call=next(x for x in observations if x['row']['kind']=='supervision_projection'
            and x['row']['data']['kind']=='rpc' and x['row']['data']['request']['operation']=='NATIVE_BEGIN')
        end=next(x for x in observations if x['row']['kind']=='phase' and x['source']=='role_observer'
            and x['row']['data']['stage']=='end')
        if ordering in ('request_before_signal','combined'):call['row']['data']['request']['observed_at_ns']=anchor+15
        if ordering in ('early_broker_reap','combined'):
            killed=next(x for x in reordered['cleanup.json']['receipts'] if any(
                p['role']=='broker' and p['pid']==broker_pid for p in x['processes']))
            killed.update(started_at_ns=anchor+8,finished_at_ns=anchor+25)
        if ordering in ('late_signal_journal','combined'):
            # Keep the actual signal clock; only its journal append is later.
            end['row']['observed_at_ns']=anchor+165
        report=replay(reordered,observations)
        assert report['missing_evidence']==[] and report['all_closed'] and report['cleanup_complete'],ordering
        assert report['dispatches'][env['dispatch_id']]['native_budget'] is None,ordering
    # Cancellation can happen after request retention but before capture
    # construction. Honest absent hashes are incomplete, not contradictions.
    for absent in ('capture_not_constructed','final_capture_proof_absent'):
        incomplete=deepcopy(value);observations=deepcopy(rows)
        terminal=next(x for x in observations if x['row']['kind']=='supervision_projection'
            and x['row']['data']['kind']=='local_failure' and x['row']['data']['capture_sha256'] is not None)
        terminal['row']['data'].update(capture_sha256=None,cleanup_sha256=None)
        if absent=='capture_not_constructed':incomplete['results.json']['operations'][0]['host_capture']=None
        report=replay(incomplete,observations)
        assert 'transcript' in report['missing_evidence'] and report['cleanup_complete'],absent
        assert report['dispatches'][env['dispatch_id']]['native_budget'] is None,absent
    # A later broker's complete segment cannot supply the killed broker's
    # marker, signal identity or physical closure. Its mere presence is valid.
    second=uid(1960);other=declared_readiness(value['runtime.json']['runtime'],'broker',pid=1960,worker_id=second)
    other['parent_observation']['sampled_at_ns']=anchor+200
    other_cleanup=declared_cleanup(other,started=anchor+300,finished=anchor+400)
    successor=deepcopy(value);successor_rows=deepcopy(rows)
    successor['manifest.json']['broker_instances'].append({'broker_id':second,'ledger_owner_id':uid(1961)})
    successor['processes.json']['readiness'].append(other);successor['cleanup.json']['receipts'].append(other_cleanup)
    successor['manifest.json']['transcript']['segments'].append({'source':'broker_memfd','broker_id':second,
        'status':'sealed_complete','seals':15,'bytes':0,'offset':0,'sha256':sha(b'')})
    assert replay(successor,successor_rows)['missing_evidence']==[]
    # Full supervision controls for the earlier crash cuts have no pending
    # native exchange. N42 has no reserve; N43 retains the one charged reserve.
    for number in (42,43):
        earlier=deepcopy(value);prior=[deepcopy(x) for x in rows if x not in (rpc,cause,final,go,marker,signal_begin,signal_end)]
        earlier['results.json']['operations'][0]['host_capture']=None
        if number==42:
            before=None
            for event in state['events']:
                if event['request']['operation']!='reserve':before,_=ledger._apply(before,event['request'])
            earlier['final-ledger.json']=before;earlier['recovery-ledger.json']=deepcopy(before)
            assert not before['reservations'] and not any(before['state']['usage'].values())
        else:assert len(earlier['final-ledger.json']['reservations'])==1
        assert replay(earlier,prior)['missing_evidence']==[],number
    variants=('missing_cause','missing_final','duplicate_cause','duplicate_final','cause_code','rpc_code','cause_broker','cause_session','cause_dispatch',
        'cause_observer','cause_worker','cause_prepared','cause_capture','cause_cleanup','final_capture','final_cleanup',
        'missing_capture','host_success','raw_capture','client','meter','result','completion','native',
        'missing_marker','duplicate_marker','marker_digest','marker_source','marker_broker','marker_observer',
        'marker_session','marker_dispatch','marker_stage','marker_phase','marker_deadline','marker_future_clock','marker_after_signal',
        'missing_signal_begin','missing_signal_end','duplicate_signal_begin','duplicate_signal_end',
        'signal_digest','signal_source','signal_broker','signal_observer','signal_session','signal_dispatch',
        'signal_deadline','signal_null_clock','signal_future_clock','signal_reverse','signal_after_hold','signal_after_final',
        'missing_go','go_channel','go_broker','go_source','go_after_marker','go_reservation','go_prepared',
        'release_hash','request_wire','request_sequence','request_worker','request_slot','request_prepared','reply_claim',
        'missing_reservation','wrong_reservation','wrong_charge','missing_broker_cleanup','duplicate_broker_cleanup',
        'broker_not_killed','broker_pid','broker_start','broker_wrapper','broker_unreaped','broker_cleanup_before_signal',
        'client_pid','client_start','client_wrapper','missing_client_cleanup','client_unreaped','client_open_descriptors',
        'early_stop','early_cause','early_final','late_final','late_cleanup','early_cleanup','host_epoch','original_bound',
        'open_channel','pending_slot','later_rpc','sealed_crashed_broker','foreign_first_broker','extra_operation',
        'pending_terminal','pending_dispatch','pending_after_go','stop_before_signal','native_relay','result_relay')
    for variant in variants:
        bad=deepcopy(value);changed=deepcopy(rows);operation=bad['results.json']['operations'][0]
        call=next(x for x in changed if x['row']['kind']=='supervision_projection' and x['row']['data']['kind']=='rpc'
            and x['row']['data']['request']['operation']=='NATIVE_BEGIN')
        failures=[x for x in changed if x['row']['kind']=='supervision_projection' and x['row']['data']['kind']=='local_failure']
        first,last=failures
        fault=next(x for x in changed if x['row']['kind']=='phase' and x['source']=='broker_memfd')
        begin,end=[x for x in changed if x['row']['kind']=='phase' and x['source']=='role_observer']
        release_row=next(x for x in changed if x['row']['kind']=='protocol' and x['row']['data']['frame']['operation']=='GO')
        thread=next(x for x in bad['cleanup.json']['supervisors'] if x['launcher_id']==channel)
        child=next(x for x in bad['cleanup.json']['receipts'] if sha(raw(x))==operation['host_capture']['cleanup_sha256'])
        killed=next(x for x in bad['cleanup.json']['receipts'] if any(p['role']=='broker' and p['pid']==broker_pid for p in x['processes']))
        if variant.startswith('missing_') and variant[8:] in ('cause','final','marker','signal_begin','signal_end','go'):
            changed.remove({'cause':first,'final':last,'marker':fault,'signal_begin':begin,'signal_end':end,'go':release_row}[variant[8:]])
        elif variant.startswith('duplicate_') and variant!='duplicate_broker_cleanup':
            changed.append(deepcopy({'cause':first,'final':last,'marker':fault,'signal_begin':begin,'signal_end':end}[variant[10:]]))
        elif variant in ('cause_code','rpc_code'):
            (first['row']['data'] if variant=='cause_code' else call['row']['data'])[
                'code' if variant=='cause_code' else 'local_error']='engagement_live_timeout'
        elif variant.startswith('cause_'):
            field=variant[6:]
            if field in ('capture','cleanup'):first['row']['data'][field+'_sha256']=sha(raw(operation['host_capture']))
            elif field in ('worker','prepared'):first['row']['data'][{'worker':'child_worker_id','prepared':'prepared_sha256'}[field]]=uid(1999) if field=='worker' else 'e'*64
            else:first['row'][field+'_id']=uid(1999)
        elif variant in ('final_capture','final_cleanup'):last['row']['data'][variant[6:]+'_sha256']='e'*64
        elif variant=='missing_capture':operation['host_capture']=None
        elif variant=='host_success':
            operation['host_capture']['status']='succeeded';last['row']['data']['capture_sha256']=sha(raw(operation['host_capture']))
        elif variant=='raw_capture':bad['client-'+env['dispatch_id']+'.stdout.bin']=b'!'
        elif variant in ('client','meter','result'):operation[variant]=deepcopy(original_operation[variant])
        elif variant=='completion':bad['final-ledger.json']=deepcopy(loaded['final-ledger.json'])
        elif variant=='native':bad['processes.json']['native']=deepcopy(loaded['processes.json']['native'])
        elif variant in ('native_relay','result_relay'):
            extra=deepcopy(release_row);frame=extra['row']['data']['frame']
            frame.update(operation='NATIVE_OBSERVED' if variant=='native_relay' else 'RESULT',
                body=deepcopy(loaded['processes.json']['native'][0] if variant=='native_relay' else original_operation['client']))
            frame['sequence']=1+max(x['row']['data']['frame']['sequence'] for x in changed
                if x['row']['kind']=='protocol' and x['row']['data']['frame']['channel_id']==channel
                and x['row']['data']['direction']=='received')
            extra['row']['data']['direction']='received';extra['row']['observed_at_ns']=anchor+140
            changed.append(extra)
        elif variant.startswith('marker_') or variant.startswith('signal_'):
            target=fault if variant.startswith('marker_') else end;field=variant.split('_',1)[1]
            row=target['row'];part=row['data']
            if field=='digest':part['related_sha256']=digest if target is fault else canonical_digest
            elif field=='source':target['source']='role_observer' if target is fault else 'broker_memfd'
            elif field in ('broker','observer','session','dispatch'):row[field+'_id']=uid(1999)
            elif field=='stage':part['stage']='begin'
            elif field=='phase':part['phase']='reserve'
            elif field=='deadline':part['original_deadline_ns']-=1
            elif field=='future_clock':part['clock']=clock(row['observed_at_ns']+2)
            elif field=='null_clock':part['clock']=None
            elif field=='after_final':row['observed_at_ns']=last['row']['observed_at_ns']+1
            else:
                when=anchor+21 if field=='after_signal' else anchor+19 if field=='reverse' else fault['row']['observed_at_ns']+c.SECOND+1
                row['observed_at_ns']=when;part['clock']=clock(when-1)
        elif variant.startswith('go_'):
            if variant=='go_channel':release_row['row']['data']['frame']['channel_id']=uid(1999)
            elif variant=='go_broker':release_row['row']['broker_id']=uid(1999)
            elif variant=='go_source':release_row['source']='role_observer'
            elif variant=='go_after_marker':release_row['row']['observed_at_ns']=fault['row']['observed_at_ns']+1
            else:
                # Coherently update the host request too, so rejection must
                # come from the independently retained release authority.
                release=release_row['row']['data']['frame']['body']
                release['reservation_event_id' if variant=='go_reservation' else 'prepared_sha256']=uid(1999) if variant=='go_reservation' else 'e'*64
                request=call['row']['data']['request'];request['projection']['release_sha256']=sha(raw(release))
                request['projection_sha256']=sha(raw(request['projection']))
                frame={'schema_version':'1','channel_id':channel,'sequence':sequence,'operation':'NATIVE_BEGIN',
                    'body':{'child_slot':'identify_client','release':release}}
                request.update(bytes=len(raw(frame)),sha256=sha(raw(frame)))
        elif variant=='release_hash':
            request=call['row']['data']['request'];request['projection']['release_sha256']='e'*64
            request['projection_sha256']=sha(raw(request['projection']))
        elif variant=='request_wire':call['row']['data']['request']['sha256']='e'*64
        elif variant=='request_sequence':call['row']['data']['request']['sequence']+=1
        elif variant=='request_worker':call['row']['data']['child_worker_id']=uid(1999)
        elif variant=='request_slot':call['row']['data']['child_slot']='headers_client'
        elif variant=='request_prepared':call['row']['data']['prepared_sha256']='e'*64
        elif variant=='reply_claim':
            # A copied success reply has its actual earlier timestamp/budget;
            # it cannot acknowledge this later interrupted request.
            call['row']['data']['reply']=deepcopy(next(x['row']['data']['reply'] for x in original_rows
                if x['row']['kind']=='supervision_projection' and x['row']['data']['request']['operation']=='NATIVE_BEGIN'))
        elif variant=='missing_reservation':
            for name in ('final-ledger.json','recovery-ledger.json'):bad[name]['reservations']=[]
        elif variant=='wrong_reservation':
            for name in ('final-ledger.json','recovery-ledger.json'):bad[name]['reservations'][0]['dispatch_id']=uid(1999)
        elif variant=='wrong_charge':
            for name in ('final-ledger.json','recovery-ledger.json'):
                bad[name]['reservations'][0]['reservation']['connections']-=1
                bad[name]['state']['usage']['connections']-=1
        elif variant=='missing_broker_cleanup':bad['cleanup.json']['receipts'].remove(killed)
        elif variant=='duplicate_broker_cleanup':bad['cleanup.json']['receipts'].append(deepcopy(killed))
        elif variant=='broker_not_killed':killed['processes'][0]['wrapper_returncode']=0
        elif variant=='broker_unreaped':killed['processes'][0]['reaped_observed']=False
        elif variant=='broker_cleanup_before_signal':killed.update(started_at_ns=anchor+12,finished_at_ns=anchor+13)
        elif variant in ('broker_pid','broker_start','broker_wrapper'):
            killed['processes'][0][{'broker_pid':'pid','broker_start':'start_time_ticks','broker_wrapper':'wrapper_pid'}[variant]]+=1000
        elif variant=='missing_client_cleanup':bad['cleanup.json']['receipts'].remove(child)
        elif variant in ('client_pid','client_start','client_wrapper','client_unreaped','client_open_descriptors','late_cleanup','early_cleanup'):
            if variant in ('client_pid','client_start','client_wrapper'):
                child['processes'][0][{'client_pid':'pid','client_start':'start_time_ticks','client_wrapper':'wrapper_pid'}[variant]]+=1000
            elif variant=='client_unreaped':child['processes'][0]['reaped_observed']=False
            elif variant=='client_open_descriptors':child['descriptors_closed']=False
            elif variant=='late_cleanup':child['finished_at_ns']=finished+1
            else:child.update(started_at_ns=request_at-2,finished_at_ns=request_at-1)
            operation['host_capture']['cleanup_sha256']=sha(raw(child))
            last['row']['data'].update(cleanup_sha256=sha(raw(child)),capture_sha256=sha(raw(operation['host_capture'])))
        elif variant=='early_stop':thread['first_stop_requested_at_ns']=request_at-1
        elif variant=='stop_before_signal':
            begin['row'].update(observed_at_ns=stop+3);begin['row']['data']['clock']=clock(stop+2)
            end['row'].update(observed_at_ns=stop+5);end['row']['data']['clock']=clock(stop+4)
        elif variant=='early_cause':first['row']['data']['observed_at_ns']=stop-1
        elif variant in ('early_final','late_final'):
            when=finished-1 if variant=='early_final' else deadline+1
            last['row']['observed_at_ns']=when;last['row']['data']['observed_at_ns']=when
        elif variant=='host_epoch':thread['cleanup_deadline_ns']=stop+1_900_000_001
        elif variant=='original_bound':thread['cleanup_deadline_ns']=env['action_deadline_ns']+1
        elif variant=='open_channel':thread.update(channel_closed=False,status='failed')
        elif variant=='pending_slot':thread.update(pending_slots=['identify_client'],status='failed')
        elif variant=='sealed_crashed_broker':bad['manifest.json']['transcript']['segments'][0].update(status='sealed_complete',seals=15)
        elif variant=='foreign_first_broker':bad['manifest.json']['broker_instances'][0]['broker_id']=uid(1999)
        elif variant=='extra_operation':bad['results.json']['operations'].append(deepcopy(operation))
        elif variant.startswith('pending_'):
            pending=next(x for x in changed if x['row']['kind']=='protocol'
                and x['row']['data']['frame']['operation']=='DISPATCH' and x['row']['data']['direction']=='sent')
            if variant=='pending_terminal':pending['row']['data']['frame']['body'].update(
                status='refused',code='engagement_live_cancelled',data=None)
            elif variant=='pending_dispatch':pending['row']['data']['frame']['body']['data']['dispatch_id']=uid(1999)
            else:pending['row']['observed_at_ns']=release_row['row']['observed_at_ns']+1
        elif variant=='later_rpc':
            extra=deepcopy(call);extra['row']['data']['request'].update(observed_at_ns=finished+20,sequence=sequence+1)
            changed.append(extra)
        else:raise AssertionError(variant)
        try:report=replay(bad,changed)
        except c.LiveError as error:assert error.code=='engagement_live_evidence_invalid',variant
        else:assert {'transcript','cleanup'}&set(report['missing_evidence']),variant


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
    context.validate_live_context(loaded)
    # Reusing the same loaded object must never retain validation from an
    # earlier call. Even rehashed transcript edits require fresh row checks.
    original_transcript=loaded['transcript.jsonl']
    original_segments=loaded['manifest.json']['transcript']['segments']
    segments=deepcopy(original_segments);parts=[];offset=0
    for index,segment in enumerate(original_segments):
        part=original_transcript[segment['offset']:segment['offset']+segment['bytes']]
        if index==0:
            lines=part.splitlines();changed=json.loads(lines[0]);changed['unexpected']=True
            lines[0]=raw(changed);part=b'\n'.join(lines)+b'\n'
        segments[index].update(offset=offset,bytes=len(part),sha256=sha(part))
        parts.append(part);offset+=len(part)
    loaded['transcript.jsonl']=b''.join(parts)
    loaded['manifest.json']['transcript']['segments']=segments
    try:refused(context.validate_live_context,loaded)
    finally:
        loaded['transcript.jsonl']=original_transcript
        loaded['manifest.json']['transcript']['segments']=original_segments
    supervision=context.validate_supervision_transcript(loaded,original_rows)
    assert supervision['missing_evidence']==[] and supervision['all_closed']
    _reused_namespace_replay(loaded,original_rows)
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
    _cancelled_capture_replay(loaded,original_rows)
    _cancelled_native_begin_replay(loaded,original_rows)
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
    _review_timeout_causality_cases()
    _stop_wire_deadline_cases()
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
        if case=='S42C-N35':
            # The fixed cleanup fault follows CAPTURE's actual host reaping.
            receipt=next(item for item in loaded['cleanup.json']['receipts']
                if sha(raw(item))==op['host_capture']['cleanup_sha256'])
            actual_time=receipt['finished_at_ns']+1
            for wrapped in rows:
                row=wrapped['row']
                if row['kind']=='protocol' and row['data']['frame']['operation']=='OBSERVATION' and row['data']['frame']['body']['kind']=='capture':
                    row['observed_at_ns']=actual_time+1
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
            for key,value in (('cleanup_sha256','e'*64),('stdout_sha256','e'*64)):
                changed=deepcopy(op);changed['host_capture'][key]=value
                assert not e._logical_deadline_fault(loaded,rows,changed,phase,case)
            selected=next(index for index,item in enumerate(loaded['cleanup.json']['receipts'])
                if sha(raw(item))==op['host_capture']['cleanup_sha256'])
            for key,value in (('started_at_ns',native['row']['observed_at_ns']-1),
                    ('finished_at_ns',actual_time+1),('deadline_ns',original+1),
                    ('status','incomplete'),('descriptors_closed',False)):
                bad=deepcopy(loaded);changed=deepcopy(op);receipt=bad['cleanup.json']['receipts'][selected]
                receipt[key]=value;changed['host_capture']['cleanup_sha256']=sha(raw(receipt))
                assert not e._logical_deadline_fault(bad,rows,changed,phase,case)
            for key,value in (('pid',999),('start_time_ticks',999),('wrapper_pid',999),
                    ('wrapper_returncode',None),('pin_verified',False),('exit_observed',False),('reaped_observed',False)):
                bad=deepcopy(loaded);changed=deepcopy(op);receipt=bad['cleanup.json']['receipts'][selected]
                receipt['processes'][0][key]=value;changed['host_capture']['cleanup_sha256']=sha(raw(receipt))
                assert not e._logical_deadline_fault(bad,rows,changed,phase,case)
            earlier=deepcopy(rows)
            for row in earlier:
                if row['row']['kind']=='protocol' and row['row']['data']['frame']['operation']=='OBSERVATION' and row['row']['data']['frame']['body']['kind']=='capture':
                    row['row']['observed_at_ns']=actual_time-1
            assert not e._logical_deadline_fault(loaded,earlier,op,phase,case)


def _stop_wire_deadline_cases():
    from recon_cockpit.secure_agent import engagement_live_witness as witness
    session,value=prepared();env=value['envelope'];hard=env['action_deadline_ns']
    loaded={'results.json':{'operations':[{'prepared':value}]}}
    def stop(sequence,operation,observed,end):
        body={'reason':'engagement_live_timeout','observed_at_ns':observed,'cleanup_deadline_ns':end}
        if operation=='SESSION_STOP':body['session_id']=env['session_id']
        return {'source':'broker_memfd','row':{'broker_id':env['broker_id'],'row_sequence':sequence,
            'observed_at_ns':observed+1,'kind':'protocol','data':{'channel_role':'lifecycle','direction':'sent',
                'frame':{'operation':operation,'body':body}}}}
    rows=[stop(1,'SESSION_STOP',hard-c.CLEANUP_NS,hard),stop(2,'BROKER_STOP',hard+1,hard)]
    witness._validate_stop_deadlines(loaded,rows)
    bad=deepcopy(rows);bad[0]['row']['data']['frame']['body']['cleanup_deadline_ns']=hard+1
    refused(witness._validate_stop_deadlines,loaded,bad)
    # A shorter first-stop allowance remains binding even with more original
    # action time remaining; dropping operations cannot renew an emitted bound.
    early=[stop(1,'SESSION_STOP',hard-4*c.SECOND,hard-2*c.SECOND),
        stop(2,'BROKER_STOP',hard-3*c.SECOND,hard-c.SECOND)]
    refused(witness._validate_stop_deadlines,{'results.json':{'operations':[]}},early)
    bad=deepcopy(rows);bad[0]['row']['observed_at_ns']-=2
    refused(witness._validate_stop_deadlines,loaded,bad)
    opened={'source':'broker_memfd','row':{'kind':'protocol','data':{'channel_role':'ingress','direction':'sent',
        'frame':{'operation':'OPEN_SESSION','body':{'status':'ok','data':session}}}}}
    no_operations={'results.json':{'operations':[]}}
    expired=env['session_deadline_ns']
    refused(witness._validate_stop_deadlines,no_operations,[opened,stop(1,'BROKER_STOP',expired-1,expired+1)])


def _review_timeout_causality_cases():
    """Declared portable observations; never a held native process claim."""
    session,p=prepared();env=p['envelope'];hard=env['action_deadline_ns'];cutoff=hard-c.CLEANUP_NS
    cleanup_end=min(hard,cutoff+1+1_900_000_000)
    digest=c.prepared_digest(p);launcher=uid(600)
    wire=c.canonical({'schema_version':'1','channel_id':env['reviewer_id'],'sequence':1,'operation':'REVIEW','body':p})
    operation={'prepared':p,'result':None,'client':None,'meter':None}
    def wrapped(kind,data,at,observer=None,dispatch=True):
        return {'source':'role_observer','segment':1,'row':{'kind':kind,'data':data,'observed_at_ns':at,
            'broker_id':env['broker_id'],'session_id':env['session_id'],
            'dispatch_id':env['dispatch_id'] if dispatch else None,'observer_id':observer or env['broker_id']}}
    def phase(stage,at,reason=None):
        clock={'mono_before_ns':at-1,'mono_after_ns':at,
            'utc_ns':env['clock_anchor']['utc_ns']+at-env['clock_anchor']['mono_after_ns']}
        return wrapped('phase',{'phase':'consume','stage':stage,'reason':reason,
            'related_sha256':digest,'original_deadline_ns':hard,'clock':clock},at+1)
    rows=[phase('begin',cutoff-100),
        wrapped('supervision_projection',{'kind':'local_failure','launcher_id':launcher,
            'code':'engagement_live_timeout','observed_at_ns':cutoff+2},cutoff+3,launcher,False),
        wrapped('capability_projection',{'role':'terminal','operation':'REVIEW','request':{'prepared':p},
            'reply':None,'channel_id':env['reviewer_id'],'request_sequence':1,
            'original_request_bytes':len(wire),'original_request_sha256':sha(wire)},cutoff+4,env['reviewer_id']),
        phase('refused',cutoff+6,'engagement_live_cancelled'),
        phase('begin',hard+1),phase('refused',hard+3,'engagement_live_session_unavailable')]
    closure={'broker_id':env['broker_id'],'session_id':env['session_id'],'launcher_id':launcher,
        'first_stop_requested_at_ns':cutoff+1,'cleanup_started_at_ns':cutoff+8,'cleanup_finished_at_ns':cutoff+10,
        'cleanup_deadline_ns':cleanup_end,'state':'joined','status':'complete','join_attempted':True,
        'thread_alive_observed':False,'channel_closed':True,'pending_slots':[]}
    reviewer={'role':'terminal','worker_ready':{'worker_id':env['reviewer_id']},
        'parent_observation':{'sampled_at_ns':env['action_ready_ns'],
            'payload':{'pid':701,'start_time_ticks':7000},'wrapper':{'pid':700}}}
    cleanup={'role':'terminal','pid':701,'start_time_ticks':7000,'wrapper_pid':700,
        'wrapper_returncode':137,'pin_verified':True,'exit_observed':True,'reaped_observed':True}
    loaded={'processes.json':{'readiness':[reviewer]},'cleanup.json':{'supervisors':[closure],'receipts':[{
        'started_at_ns':cutoff+7,'finished_at_ns':cutoff+11,'deadline_ns':cleanup_end,
        'status':'complete','descriptors_closed':True,'processes':[cleanup]}]}}
    assert e._review_deadline_stopped(loaded,rows,operation)
    assert cleanup_end<hard and rows[-1]['row']['data']['clock']['mono_before_ns']>=hard
    for index in range(len(rows)-1):
        assert not e._review_deadline_stopped(loaded,rows[:index]+rows[index+1:],operation)
    assert not e._review_deadline_stopped(loaded,rows[:-1],operation)
    for key,value in (('first_stop_requested_at_ns',cutoff-1),('cleanup_deadline_ns',cleanup_end+1),
            ('cleanup_deadline_ns',hard),('cleanup_deadline_ns',hard+1),
            ('cleanup_finished_at_ns',cleanup_end+1),('cleanup_finished_at_ns',hard+1),('state','not_started'),('join_attempted',False),
            ('thread_alive_observed',True),('channel_closed',False),('pending_slots',['identify_client']),
            ('launcher_id',uid(601)),('session_id',uid(602))):
        bad=deepcopy(loaded);bad['cleanup.json']['supervisors'][0][key]=value
        assert not e._review_deadline_stopped(bad,rows,operation)
    for index,key,value in ((1,'code','engagement_live_cancelled'),(2,'reply',{}),
            (2,'original_request_bytes',None),(2,'original_request_bytes',len(wire)+1),
            (2,'original_request_sha256','e'*64),(2,'channel_id',uid(604)),(2,'request_sequence',2),
            (3,'original_deadline_ns',hard+1),
            (5,'reason','engagement_live_cancelled')):
        bad=deepcopy(rows);bad[index]['row']['data'][key]=value
        assert not e._review_deadline_stopped(loaded,bad,operation)
    bad=deepcopy(rows);bad[-1]['row']['data']['clock']['mono_before_ns']=hard-1
    assert not e._review_deadline_stopped(loaded,bad,operation)
    for index in (3,5):
        bad=deepcopy(rows);bad[index]['row']['data']['clock']['utc_ns']+=60*c.SECOND
        assert not e._review_deadline_stopped(loaded,bad,operation)
    for index,at in ((0,cutoff),(4,hard-1),(4,hard+4)):
        bad=deepcopy(rows);bad[index]['row']['observed_at_ns']=at
        assert not e._review_deadline_stopped(loaded,bad,operation)
    bad=deepcopy(rows);bad[2]['row']['observer_id']=uid(603)
    assert not e._review_deadline_stopped(loaded,bad,operation)
    consumed=deepcopy(rows[2]);consumed['row']['data']['operation']='CONSUME'
    assert not e._review_deadline_stopped(loaded,[*rows,consumed],operation)
    assert not e._review_deadline_stopped(loaded,[*rows,wrapped('approval_witness',{},cutoff)],operation)
    assert not e._review_deadline_stopped(loaded,[*rows,wrapped('audit_witness',{},cutoff)],operation)
    bad=deepcopy(loaded);bad['cleanup.json']['receipts'][0]['finished_at_ns']=hard+1
    assert not e._review_deadline_stopped(bad,rows,operation)
    for deadline in (cleanup_end+1,hard,hard+1,cutoff+10):
        bad=deepcopy(loaded);bad['cleanup.json']['receipts'][0]['deadline_ns']=deadline
        assert not e._review_deadline_stopped(bad,rows,operation)
    # A separate role's otherwise valid receipt may finish before the original
    # action deadline yet still overrun the shared, earlier host cleanup epoch.
    bad=deepcopy(loaded);other=deepcopy(bad['cleanup.json']['receipts'][0])
    other.update(finished_at_ns=cleanup_end+1,deadline_ns=hard)
    other['processes'][0].update(role='broker',pid=704,start_time_ticks=7002,wrapper_pid=705)
    bad['cleanup.json']['receipts'].append(other)
    assert not e._review_deadline_stopped(bad,rows,operation)
    for readiness in ([],[reviewer,reviewer]):
        bad=deepcopy(loaded);bad['processes.json']['readiness']=readiness
        assert not e._review_deadline_stopped(bad,rows,operation)
    bad=deepcopy(loaded);bad['processes.json']['readiness'][0]['worker_ready']['worker_id']=uid(605)
    assert not e._review_deadline_stopped(bad,rows,operation)
    bad=deepcopy(loaded);bad['processes.json']['readiness'][0]['parent_observation']['sampled_at_ns']=cutoff
    assert not e._review_deadline_stopped(bad,rows,operation)
    bad=deepcopy(rows);bad[0]['row']['observed_at_ns']=env['action_ready_ns']-1
    assert not e._review_deadline_stopped(loaded,bad,operation)
    for key,value in (('pid',702),('start_time_ticks',7001),('wrapper_pid',703),
            ('wrapper_returncode',None),('pin_verified',False),('exit_observed',False),('reaped_observed',False)):
        bad=deepcopy(loaded);bad['cleanup.json']['receipts'][0]['processes'][0][key]=value
        assert not e._review_deadline_stopped(bad,rows,operation)
    for key,value in (('started_at_ns',cutoff),('status','incomplete'),('descriptors_closed',False),('processes',[])):
        bad=deepcopy(loaded);bad['cleanup.json']['receipts'][0][key]=value
        assert not e._review_deadline_stopped(bad,rows,operation)


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
    # Recovery completes durable history, but an earlier broker's final cannot
    # replace the latest broker's missing seal for an ordinary live gate.
    from recon_cockpit.secure_agent import engagement_live_witness as witness
    older=deepcopy(loaded);older['manifest.json']['broker_instances'].append({'broker_id':uid(999)})
    older['recovery-ledger.json']=deepcopy(older['final-ledger.json'])
    older['cleanup.json']['recovery']={'source':'postcleanup_readonly'}
    assert witness.terminal_history_available(older) and not witness.latest_final_available(older)
    assert 'final_export' in e._report(older,{},authority,'d'*64,0,[])['missing_evidence']
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
