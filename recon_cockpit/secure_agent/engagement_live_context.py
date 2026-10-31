"""Pure cross-checks for retained live execution observations.

This module never starts a process, reads a store, restores a handle or authorizes
an operation. Missing actual observations stay missing.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
import stat
from.import engagement_live_runtime as runtime
from.engagement_live_contract import bounded as _bounded
from.engagement_live_contract import validation as _validation
# Exact closed A10 shapes; C24 checks these values against the pinned inventory.
_SCHEMA_REF='evidence_contract.copied_recovery.schemas.'
_SHA256='lowercase SHA256'
def _integer_schema(minimum=0,maximum=9223372036854775807):
    return{'bool_allowed':False,'maximum':maximum,'minimum':minimum,'type':'integer'}
def _nullable(value):
    return{'one_of':[{'type':'null'},value]}
def _object_schema(fields):
    return{'additional_fields':False,'all_fields_required':True,'fields':fields,'type':'object'}
_RECOVERY_SCHEMAS={'config':_object_schema({'broker_id':'canonical UUID4','deadline_ns':_integer_schema(),'helper_id':'canonical UUID4','inherited_fds':_SCHEMA_REF+'inherited_descriptor_map','runtime_sha256':_SHA256,'schema_version':{'const':'1'},'source_manifest_sha256':_SHA256,'source_package_bytes':_integer_schema(1,2097152),'source_package_sha256':_SHA256,'started_at_ns':_integer_schema(),'work_deadline_ns':_integer_schema()}),'copied_receipt':_object_schema({'bytes':_integer_schema(1,2097152),'closed':{'const':True},'finished_at_ns':_integer_schema(),'helper_id':'canonical UUID4','helper_sha256':_SHA256,'ledger_state_sha256':_SHA256,'owner_id':'canonical UUID4','read_only':{'const':True},'schema_version':{'const':'2'},'sha256':_SHA256,'source':{'const':'postcleanup_copied_recovery'},'started_at_ns':_integer_schema(),'store_identity':_object_schema({'database':_object_schema({'device':_integer_schema(0,18446744073709551615),'gid':_integer_schema(0,4294967295),'inode':_integer_schema(0,18446744073709551615),'mode':_integer_schema(0,4294967295),'uid':_integer_schema(0,4294967295)}),'directory':_object_schema({'device':_integer_schema(0,18446744073709551615),'gid':_integer_schema(0,4294967295),'inode':_integer_schema(0,18446744073709551615),'mode':_integer_schema(0,4294967295),'uid':_integer_schema(0,4294967295)}),'parent':_object_schema({'device':_integer_schema(0,18446744073709551615),'gid':_integer_schema(0,4294967295),'inode':_integer_schema(0,18446744073709551615),'mode':_integer_schema(0,4294967295),'uid':_integer_schema(0,4294967295)})})}),'copy_stage':_object_schema({'copied':_nullable(_SCHEMA_REF+'store_observation'),'finished_at_ns':_nullable(_integer_schema()),'locks':_SCHEMA_REF+'source_locks','raw_copy_fds_closed_at_ns':_nullable(_integer_schema()),'raw_source_fds_closed_at_ns':_nullable(_integer_schema()),'source_after':_nullable(_SCHEMA_REF+'store_observation'),'source_before':_nullable(_SCHEMA_REF+'store_observation'),'started_at_ns':_integer_schema()}),'default_vfs_observation':_object_schema({'library':'runtime_contract.closed_objects.file_identity','library_source':{'maximum_length':4096,'minimum_length':1,'type':'string'},'library_version':_integer_schema(1,2147483647),'observed_at_ns':_integer_schema(),'sqlite_module_version':{'items':_integer_schema(0,999),'maximum_items':3,'minimum_items':3,'type':'array'},'vfs_name':{'const':'unix'},'vfs_name_hex':{'const':'756e697800'},'vfs_struct_version':_integer_schema(1,3)}),'file_observation':_object_schema({'fd_flags':_integer_schema(0,4294967295),'header_hex':{'encoding':'lowercase even-length hexadecimal','maximum_length':56,'type':'string'},'held':_SCHEMA_REF+'file_stamp','name':{'enum':['records.sqlite3','records.sqlite3-journal']},'named':_SCHEMA_REF+'file_stamp','sha256':_SHA256,'trailer_hex':{'encoding':'lowercase even-length hexadecimal','maximum_length':32,'type':'string'}}),'file_size_narrowing':_object_schema({'hard':{'const':8388608},'observed_at_ns':_integer_schema(),'soft':{'const':8388608}}),'file_stamp':_object_schema({'ctime_ns':_integer_schema(),'device':_integer_schema(0,18446744073709551615),'gid':_integer_schema(0,4294967295),'inode':_integer_schema(0,18446744073709551615),'mode':_integer_schema(0,4294967295),'mtime_ns':_integer_schema(),'nlink':{'const':1},'size':_integer_schema(0,16777216),'uid':_integer_schema(0,4294967295)}),'framed_observation':_object_schema({'complete':{'type':'boolean'},'declared_bytes':_nullable(_integer_schema(1,2129920)),'finished_at_ns':_nullable(_integer_schema()),'frame_sha256':_nullable(_SHA256),'header_hex':{'encoding':'lowercase even-length hexadecimal','maximum_length':16,'type':'string'},'payload_bytes':_integer_schema(0,2129920),'payload_sha256':_nullable(_SHA256),'received_bytes':_integer_schema(0,2134032),'started_at_ns':_nullable(_integer_schema())}),'helper_cleanup':_object_schema({'deadline_ns':_integer_schema(),'descriptors_closed':{'type':'boolean'},'directory_closed':{'type':'boolean'},'directory_removed':{'type':'boolean'},'finished_at_ns':_nullable(_integer_schema()),'parent_closed':{'type':'boolean'},'pidfd_closed':{'type':'boolean'},'removed_names':{'items':{'enum':['records.sqlite3','records.sqlite3-journal']},'maximum_items':2,'minimum_items':0,'type':'array'},'scratch_disposition':{'enum':['removed','retained','unknown']},'source_package_closed':{'type':'boolean'},'started_at_ns':_integer_schema(),'status':{'enum':['complete','failed','unknown']},'stdio_closed':{'type':'boolean'}}),'helper_error':{'enum':['source_custody','source_changed','unsupported_ofd','reserved_writer','unsupported_runtime','unsupported_vfs','source_package','publication','ready','release','copy_custody','copy_limit','journal_trailer','sqlite_rw','journal_disposition','sqlite_ro','snapshot_mismatch','progress_limit','work_deadline','framing','output_limit','helper_exit','helper_reap','scratch_cleanup','descriptor_cleanup','main_header']},'helper_observation':_object_schema({'broker_id':'canonical UUID4','cleanup':_SCHEMA_REF+'helper_cleanup','config':_SCHEMA_REF+'config','config_bytes':_integer_schema(1,4096),'config_sha256':_SHA256,'deadline_ns':_integer_schema(),'error':_nullable(_SCHEMA_REF+'helper_error'),'finished_at_ns':_nullable(_integer_schema()),'generation':_integer_schema(0,1),'helper_id':'canonical UUID4','parent_observer':'runtime_contract.closed_objects.observer','process':_SCHEMA_REF+'process','ready':_nullable(_SCHEMA_REF+'ready'),'runtime':_nullable(_SCHEMA_REF+'helper_runtime'),'schema_version':{'const':'1'},'scratch':_nullable(_SCHEMA_REF+'scratch_registration'),'started_at_ns':_integer_schema(),'status':{'enum':['complete','failed','unknown']},'transfer':_SCHEMA_REF+'transfer','transports':_SCHEMA_REF+'transports','work':_nullable(_SCHEMA_REF+'work_provenance'),'work_deadline_ns':_integer_schema()}),'helper_runtime':_object_schema({'default_vfs_sha256':_SHA256,'descriptors':{'items':'runtime_contract.closed_objects.descriptor','maximum_items':8,'minimum_items':8,'type':'array'},'interpreter':'runtime_contract.closed_objects.file_identity','locking':{'const':'posix_rollback'},'mapped_images':{'items':'runtime_contract.closed_objects.file_identity','maximum_items':64,'minimum_items':1,'type':'array'},'observed_at_ns':_integer_schema(),'resource_limits':_SCHEMA_REF+'resource_observation','runtime_sha256':_SHA256,'source_manifest_sha256':_SHA256,'source_package':_SCHEMA_REF+'package_observation','sqlite_extension':'runtime_contract.closed_objects.file_identity','stdlib':_SCHEMA_REF+'identity','vfs':{'const':'unix'}}),'identity':_object_schema({'device':_integer_schema(0,18446744073709551615),'gid':_integer_schema(0,4294967295),'inode':_integer_schema(0,18446744073709551615),'mode':_integer_schema(0,4294967295),'uid':_integer_schema(0,4294967295)}),'inactive_header':_object_schema({'header_hex':{'encoding':'lowercase even-length hexadecimal','maximum_length':56,'type':'string'},'nonce':_integer_schema(0,4294967295),'original_pages':_integer_schema(1,2048),'padding_bytes':_integer_schema(0,65508),'padding_sha256':_SHA256,'page_bytes':{'const':4096},'record_count':_integer_schema(0,2048),'records':{'items':_SCHEMA_REF+'inactive_record','maximum_items':2048,'minimum_items':0,'type':'array'},'sector_bytes':_integer_schema(512,65536)}),'inactive_record':_object_schema({'before_image_sha256':_SHA256,'checksum':_integer_schema(0,4294967295),'computed_checksum':_integer_schema(0,4294967295),'index':_integer_schema(0,2047),'main_page_sha256':_SHA256,'page_number':_integer_schema(1,2048)}),'inherited_descriptor_map':_object_schema({'scratch_parent':_integer_schema(3,255),'scratch_store':_integer_schema(3,255),'source_package':_integer_schema(3,255),'source_parent':_integer_schema(3,255),'source_store':_integer_schema(3,255),'stderr':{'const':2},'stdin':{'const':0},'stdout':{'const':1}}),'journal_disposition':_object_schema({'absence_observed_at_ns':_nullable(_integer_schema()),'header':_nullable(_SCHEMA_REF+'inactive_header'),'journal':_nullable(_SCHEMA_REF+'file_observation'),'main_after':_nullable(_SCHEMA_REF+'file_observation'),'main_before':_SCHEMA_REF+'file_observation','observed_at_ns':_integer_schema(),'status':{'enum':['absent_after_rw','removed_empty_copy','removed_inactive_copy','refused']},'unlink_finished_at_ns':_nullable(_integer_schema()),'unlink_started_at_ns':_nullable(_integer_schema())}),'limit_pair':_object_schema({'hard':_integer_schema(),'soft':_integer_schema()}),'lock_attempt':_object_schema({'command':{'const':'F_OFD_SETLK'},'errno':_nullable(_integer_schema(1,4095)),'finished_at_ns':_integer_schema(),'length':{'enum':[1,510]},'lock_type':{'const':'F_RDLCK'},'offset':{'enum':[1073741824,1073741826]},'started_at_ns':_integer_schema(),'status':{'enum':['acquired','refused','unsupported']}}),'package_observation':_object_schema({'bytes':_integer_schema(1,2097152),'descriptor':'runtime_contract.closed_objects.descriptor','seals':{'const':15},'sha256':_SHA256,'source_manifest_sha256':_SHA256}),'package_source':_object_schema({'destination':{'maximum_length':256,'minimum_length':1,'type':'string'},'module':{'maximum_length':128,'minimum_length':1,'type':'string'},'sha256':_SHA256,'size':_integer_schema(1,2097152),'source_base64':{'encoding':'canonical padded base64','maximum_length':2796204,'type':'string'}}),'pidfd_observation':_object_schema({'device':_integer_schema(0,18446744073709551615),'flags':_integer_schema(0,4294967295),'inode':_integer_schema(0,18446744073709551615),'mode':_integer_schema(0,4294967295)}),'process':_object_schema({'exit_observed_at_ns':_nullable(_integer_schema()),'observed_at_ns':_nullable(_integer_schema()),'parent_pid':_nullable(_integer_schema(1,2147483647)),'pid':_nullable(_integer_schema(1,2147483647)),'pidfd':_nullable(_SCHEMA_REF+'pidfd_observation'),'publication_registered_at_ns':_integer_schema(),'publication_resolved_at_ns':_nullable(_integer_schema()),'publication_state':{'enum':['pending','not_started','published']},'reaped_at_ns':_nullable(_integer_schema()),'release_sent_at_ns':_nullable(_integer_schema()),'returncode':_nullable(_integer_schema(-255,255)),'signal_sent_at_ns':_nullable(_integer_schema()),'start_time_ticks':_nullable(_integer_schema(0,18446744073709551615)),'task_ids':{'items':_integer_schema(1,2147483647),'maximum_items':1,'minimum_items':0,'type':'array'}}),'ready':_object_schema({'broker_id':'canonical UUID4','default_vfs':_SCHEMA_REF+'default_vfs_observation','helper_id':'canonical UUID4','kind':{'const':'copied_ledger_recovery_ready'},'observed_at_ns':_integer_schema(),'pid':_integer_schema(1,2147483647),'runtime_sha256':_SHA256,'schema_version':{'const':'1'},'source_manifest_sha256':_SHA256,'source_package_sha256':_SHA256}),'reserved_query':_object_schema({'command':{'const':'F_OFD_GETLK'},'errno':_nullable(_integer_schema(1,4095)),'finished_at_ns':_integer_schema(),'input_owner_pid':{'const':0},'length':{'const':1},'offset':{'const':1073741825},'owner_pid':_nullable(_integer_schema(-1,2147483647)),'query_type':{'const':'F_WRLCK'},'result_type':_nullable({'enum':['F_UNLCK','F_RDLCK','F_WRLCK']}),'started_at_ns':_integer_schema()}),'resource_observation':_object_schema({'address_space':_SCHEMA_REF+'limit_pair','cpu':_SCHEMA_REF+'limit_pair','file_size':_SCHEMA_REF+'limit_pair','nofile':_SCHEMA_REF+'limit_pair','observed_at_ns':_integer_schema()}),'result':_object_schema({'error':_nullable(_SCHEMA_REF+'helper_error'),'export':_nullable('exact unchanged canonical v2 ledger export'),'provenance':_SCHEMA_REF+'work_provenance','schema_version':{'const':'1'},'status':{'enum':['complete','failed']}}),'scratch_registration':_object_schema({'directory':_SCHEMA_REF+'identity','name':{'maximum_length':128,'minimum_length':1,'pattern':'[A-Za-z0-9_-]+','type':'string'},'parent':_SCHEMA_REF+'identity','registered_at_ns':_integer_schema()}),'source_locks':_object_schema({'main_device':_integer_schema(0,18446744073709551615),'main_inode':_integer_schema(0,18446744073709551615),'pending':_nullable(_SCHEMA_REF+'lock_attempt'),'released_at_ns':_nullable(_integer_schema()),'reserved_after':_nullable(_SCHEMA_REF+'reserved_query'),'reserved_before':_nullable(_SCHEMA_REF+'reserved_query'),'shared':_nullable(_SCHEMA_REF+'lock_attempt')}),'source_package':_object_schema({'runtime':'runtime_contract.runtime_manifest_schema exact bundle','runtime_sha256':_SHA256,'schema_version':{'const':'1'},'source_manifest_sha256':_SHA256,'sources':{'items':_SCHEMA_REF+'package_source','maximum_items':52,'minimum_items':52,'type':'array'}}),'sqlite_stage':_object_schema({'closed':{'type':'boolean'},'closed_at_ns':_nullable(_integer_schema()),'ledger_state_sha256':_nullable(_SHA256),'mode':{'enum':['read_write','read_only']},'opened_at_ns':_nullable(_integer_schema()),'owner_id':_nullable('canonical UUID4'),'progress_callbacks_after':_integer_schema(0,4000),'progress_callbacks_before':_integer_schema(0,4000),'snapshot_at_ns':_nullable(_integer_schema()),'snapshot_bytes':_nullable(_integer_schema(1,2097152)),'snapshot_event_sequence':_nullable(_integer_schema(1,257)),'snapshot_sha256':_nullable(_SHA256)}),'store_identity':_object_schema({'database':_SCHEMA_REF+'identity','directory':_SCHEMA_REF+'identity','parent':_SCHEMA_REF+'identity'}),'store_observation':_object_schema({'directory':_SCHEMA_REF+'identity','files':{'items':_SCHEMA_REF+'file_observation','maximum_items':2,'minimum_items':1,'type':'array'},'observed_at_ns':_integer_schema(),'parent':_SCHEMA_REF+'identity'}),'transfer':_object_schema({'export_bytes':_nullable(_integer_schema(1,2097152)),'export_sha256':_nullable(_SHA256),'provenance_bytes':_nullable(_integer_schema(1,32768)),'provenance_sha256':_nullable(_SHA256),'ready':_SCHEMA_REF+'framed_observation','result':_SCHEMA_REF+'framed_observation','result_error':_nullable(_SCHEMA_REF+'helper_error'),'result_status':_nullable({'enum':['complete','failed']}),'stderr_bytes':_integer_schema(0,4096),'stderr_eof':{'type':'boolean'},'stderr_hex':{'encoding':'lowercase even-length hexadecimal','maximum_length':8192,'type':'string'},'stderr_sha256':_SHA256,'stdout_bytes':_integer_schema(0,2134032),'stdout_eof':{'type':'boolean'}}),'transport_pair':_object_schema({'child':'runtime_contract.closed_objects.descriptor','created_at_ns':_integer_schema(),'parent':'runtime_contract.closed_objects.descriptor'}),'transports':_object_schema({'stderr':_SCHEMA_REF+'transport_pair','stdin':_SCHEMA_REF+'transport_pair','stdout':_SCHEMA_REF+'transport_pair'}),'work_provenance':_object_schema({'broker_id':'canonical UUID4','copy':_nullable(_SCHEMA_REF+'copy_stage'),'copy_descriptors_closed':{'type':'boolean'},'deadline_ns':_integer_schema(),'finished_at_ns':_nullable(_integer_schema()),'helper_id':'canonical UUID4','journal_disposition':_nullable(_SCHEMA_REF+'journal_disposition'),'post_ro_copy':_nullable(_SCHEMA_REF+'store_observation'),'post_rw_copy':_nullable(_SCHEMA_REF+'store_observation'),'progress_callbacks':_integer_schema(0,4000),'ro':_nullable(_SCHEMA_REF+'sqlite_stage'),'runtime_sha256':_SHA256,'rw':_nullable(_SCHEMA_REF+'sqlite_stage'),'schema_version':{'const':'1'},'source_descriptors_closed':{'type':'boolean'},'source_package_closed_at_ns':_nullable(_integer_schema()),'source_package_sha256':_SHA256,'sqlite_file_size_limit':_nullable(_SCHEMA_REF+'file_size_narrowing'),'started_at_ns':_integer_schema(),'work_deadline_ns':_integer_schema()})}
_CHILD_SLOTS={
    'identify_client':('nmap','http_identify',5),
    'identify_admission':('admission','http_identify',6),
    'identify_parser':('parser','http_identify',7),
    'headers_client':('headers','http_headers',8),
    'headers_admission':('admission','http_headers',9),
    'headers_parser':('parser','http_headers',10),
}
def _sequence(value,maximum):
    if type(value)is not list or len(value)>maximum:
        _bad()
    return value
def _supervisor_closure(loaded):
    """Actual thread closure is separate from process reaping and timing success."""
    from.import engagement_live_contract as c
    rows=_sequence(loaded['cleanup.json']['supervisors'],4)
    expected={(x['broker_id'],x['session_id'],x['launcher_id'])
                for x in loaded['processes.json']['child_slots']}
    launchers={x['worker_ready']['worker_id']for x in loaded['processes.json']['readiness']
                 if x.get('role')=='launcher'}
    allocated={launcher:[key for key in expected if key[2]==launcher]
                 for launcher in launchers}
    seen=set();all_closed=True;complete=True
    for row in rows:
        c.obj(row,('schema_version','broker_id','session_id','launcher_id',
            'host_observer','thread_native_id','thread_started_at_ns','state',
            'first_stop_requested_at_ns','cleanup_started_at_ns','cleanup_finished_at_ns',
            'cleanup_deadline_ns','join_attempted','thread_alive_observed',
            'channel_closed','pending_slots','status'))
        if row['schema_version']!='1':_bad()
        key=tuple(c.uuid(row[k])for k in('broker_id','session_id','launcher_id'))
        if key in seen:_bad()
        seen.add(key)
        _observer(row['host_observer'])
        for k in('first_stop_requested_at_ns','cleanup_started_at_ns',
                  'cleanup_finished_at_ns','cleanup_deadline_ns'):
            c.integer(row[k])
        if not(row['first_stop_requested_at_ns']<=row['cleanup_started_at_ns']<=row['cleanup_finished_at_ns']
                and row['cleanup_deadline_ns']<=row['first_stop_requested_at_ns']+2000000000):_bad()
        for k in('join_attempted','channel_closed'):
            if type(row[k])is not bool:_bad()
        if row['thread_alive_observed']is not None and type(row['thread_alive_observed'])is not bool:_bad()
        for k in('thread_native_id','thread_started_at_ns'):
            if row[k]is not None:c.integer(row[k],1 if k=='thread_native_id' else 0,
                2147483647 if k=='thread_native_id' else 9223372036854775807)
        if((row['thread_native_id']is None)!=(row['thread_started_at_ns']is None)
                or row['thread_started_at_ns']is not None and row['thread_started_at_ns']>row['first_stop_requested_at_ns']):_bad()
        pending=_sequence(row['pending_slots'],6)
        if len(set(pending))!=len(pending)or any(x not in _CHILD_SLOTS for x in pending):_bad()
        c.member(row['state'],{'not_started','joined','alive','unknown'})
        c.member(row['status'],{'complete','failed','unknown'})
        if row['state']=='joined':
            if(not row['join_attempted']or row['thread_alive_observed']is not False
                    or row['thread_native_id']is None or row['thread_started_at_ns']is None):_bad()
        elif row['state']=='not_started':
            if(row['join_attempted']or row['thread_alive_observed']is not False
                    or row['thread_native_id']is not None or row['thread_started_at_ns']is not None or pending):_bad()
            if any(x['prepared_sha256']is not None or x['bootstrap']is not None or x['entry_sha256']is not None
                   for x in loaded['processes.json']['child_slots']
                   if(x['broker_id'],x['session_id'],x['launcher_id'])==key):_bad()
        elif row['state']=='alive' and row['thread_alive_observed']is not True:_bad()
        elif row['state']=='unknown' and row['thread_alive_observed']is not None:_bad()
        closed=row['state']in('joined','not_started')and row['channel_closed']and not pending
        owned=[x for x in loaded['processes.json']['child_slots']
                 if(x['broker_id'],x['session_id'],x['launcher_id'])==key]
        known={x['worker_id']for x in owned}
        parents=[x['parent_observation']for x in loaded['processes.json']['readiness']
                   if x.get('worker_ready',{}).get('worker_id')in known]
        entry_hashes={x['entry_sha256']for x in owned if x['entry_sha256']is not None}
        parents+=[x for x in loaded['processes.json']['startup']if runtime._hash(x)in entry_hashes]
        if row['thread_started_at_ns']is not None and any(
                p['sampled_at_ns']<row['thread_started_at_ns']for p in parents):_bad()
        for parent in parents:
            receipts=[receipt for receipt in loaded['cleanup.json']['receipts']if any(
                p['pid']==parent['payload']['pid']and p['start_time_ticks']==parent['payload']['start_time_ticks']
                for p in receipt['processes'])]
            matches=[p for receipt in receipts for p in receipt['processes']
                       if p['pid']==parent['payload']['pid']and p['start_time_ticks']==parent['payload']['start_time_ticks']]
            closed&=bool(matches)and all(p['pin_verified']and p['exit_observed']and p['reaped_observed']
                and p['wrapper_pid']==parent['wrapper']['pid']and p['wrapper_returncode']is not None for p in matches)
            closed&=all(receipt['descriptors_closed']for receipt in receipts)
            closed&=any(len(receipt['processes'])==1 and receipt['finished_at_ns']<=row['cleanup_finished_at_ns']
                          for receipt in receipts)
        timely=row['cleanup_finished_at_ns']<=row['cleanup_deadline_ns']
        if row['status']=='complete' and not(closed and timely):_bad()
        all_closed&=closed
        complete&=closed and timely and row['status']=='complete'
    all_closed&=not(expected-seen)
    # A coherent deletion of both allocation and closure rows must not erase
    # an actual launcher which retained the six request endpoints at READY.
    all_closed&=all(len(keys)==1 and
        {x['child_slot']for x in loaded['processes.json']['child_slots']
         if(x['broker_id'],x['session_id'],x['launcher_id'])==keys[0]}==set(_CHILD_SLOTS)
        for keys in allocated.values())
    complete&=all_closed
    return{'all_closed':bool(all_closed),'complete':bool(complete)}
def _observer(value):
    from.import engagement_live_contract as c
    c.obj(value,('pid','uid','gid','namespaces'))
    c.integer(value['pid'],1,2147483647)
    c.integer(value['uid'],0,4294967295);c.integer(value['gid'],0,4294967295)
    c.obj(value['namespaces'],('user','net','mnt','pid'))
    for k,v in value['namespaces'].items():
        if type(v)is not str or len(v)>64 or not v.startswith(k+':[')or not v.endswith(']')or not v[len(k)+2:-1].isdigit():_bad()
    return value
def _retained_rows(loaded):
    """Read existing bounded segments only; never executes an inspector/role."""
    from.engagement_live_witness import validate_transcript_row
    raw=loaded['transcript.jsonl']
    if type(raw)is not bytes or len(raw)>2097152:_bad()
    rows=[];offset=0
    for index,segment in enumerate(loaded['manifest.json']['transcript']['segments']):
        if segment['offset']!=offset:_bad()
        limit=(917504,1984)if segment['source']=='broker_memfd' else(262144,128)
        part=raw[offset:offset+segment['bytes']]
        if len(part)!=segment['bytes']or len(part)>limit[0]or hashlib.sha256(part).hexdigest()!=segment['sha256']:_bad()
        offset+=len(part)
        lines=part.split(b'\n');tail=lines.pop()
        if tail and not segment['status'].endswith('partial'):_bad()
        if len(lines)>limit[1]:_bad()
        for sequence,line in enumerate(lines,1):
            row=validate_transcript_row(runtime._decode(line,32768))
            if row['row_sequence']!=sequence:_bad()
            rows.append({'segment':index,'source':segment['source'],'row':row})
    if offset!=len(raw):_bad()
    return rows
def _host_capture(loaded,operation,cleanups):
    from.import engagement_live_contract as c
    value=operation['host_capture']
    if value is None:return None
    c.obj(value,('schema_version','slot','status','exit_code','truncated',
        'stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256','cleanup_sha256'))
    envelope=operation['prepared']['envelope']
    if value['schema_version']!='1' or value['slot']!=envelope['slot']or type(value['truncated'])is not bool:_bad()
    c.member(value['status'],{'succeeded','failed','timeout','output_limit','cancelled','unresolved'})
    if value['exit_code']is not None:c.integer(value['exit_code'],-255,255)
    result={k:value[k]for k in('schema_version','slot','exit_code','truncated',
        'stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256')}
    maximum=8192 if value['slot']=='http_identify' else 2048
    for stream in('stdout','stderr'):
        c.integer(value[stream+'_bytes'],0,maximum);c.digest_string(value[stream+'_sha256'])
        raw=loaded.get('client-'+envelope['dispatch_id']+'.'+stream+'.bin')
        if type(raw)is not bytes or len(raw)!=value[stream+'_bytes']or hashlib.sha256(raw).hexdigest()!=value[stream+'_sha256']:_bad()
        result[stream+'_base64']=base64.b64encode(raw).decode('ascii')
    if value['stdout_bytes']+value['stderr_bytes']>maximum:_bad()
    if value['cleanup_sha256']is not None:
        c.digest_string(value['cleanup_sha256'])
        if value['cleanup_sha256']not in cleanups:_bad()
        receipt=cleanups[value['cleanup_sha256']]
        if len(receipt['processes'])!=1 or len(runtime._json(receipt))>2048:_bad()
    client=operation['client']
    if client is not None and any(client[k]!=value[k]for k in('status','exit_code','truncated',
            'stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256')):_bad()
    return result
@_validation('evidence_invalid')
def validate_supervision_transcript(loaded,rows=None,*,deadline=None):
    """Replay compact host observations against retained direct source objects.

    Digests of unavailable objects are never treated as complete observations.
    This performs no process, filesystem, store or engagement-clock sampling.
    """
    from.import engagement_live_contract as c
    end=c._operation_deadline()
    if deadline is not None:end=min(end,deadline)
    with c._deadline_context(end):
        return _validate_supervision(loaded,_retained_rows(loaded)if rows is None else rows,end)
def _capture_terminal_facts(loaded,rows,row,operation,slot,closure,code):
    """Common terminal ownership facts; wrappers supply a fixed failure code."""
    from.import engagement_live_contract as c
    from.import engagement_live_protocol as protocol
    data=row['data'];request=data['request'];envelope=operation['prepared']['envelope']
    if(request['operation']!='CAPTURE' or data['local_error']!=code
            or data['reply']is not None or operation['result']is not None or operation['client']is not None
            or len(loaded['manifest.json']['broker_instances'])!=1
            or slot['role']not in('nmap','headers')or not closure['complete']):return False
    did=envelope['dispatch_id'];host=operation['host_capture']
    if host is None or host['cleanup_sha256']is None:return False
    if any(x['dispatch_id']==did for name in('initial-ledger.json','final-ledger.json','recovery-ledger.json')
           for x in loaded.get(name,{}).get('completions',[])):return False
    threads=[x for x in loaded['cleanup.json']['supervisors']if
        all(x[k]==slot[k]for k in('broker_id','session_id','launcher_id'))]
    if len(threads)!=1:return False
    thread=threads[0];hard=min(envelope[k]for k in
        ('action_deadline_ns','session_deadline_ns','broker_deadline_ns'))
    if(thread['state']!='joined' or thread['status']!='complete'
            or thread['pending_slots']or not thread['channel_closed']
            or thread['cleanup_deadline_ns']>min(hard,
                thread['first_stop_requested_at_ns']+1_900_000_000)):return False
    failures=[x['row']for x in rows if x['source']=='role_observer'
        and x['row']['kind']=='supervision_projection'
        and x['row']['data']['kind']=='local_failure'
        and x['row']['data']['launcher_id']==slot['launcher_id']]
    if len(failures)!=2:return False
    failures.sort(key=lambda x:x['data']['observed_at_ns'])
    for failure in failures:
        value=protocol.validate_supervision_projection(failure['data'])
        if(any(failure[k]!=row[k]for k in('broker_id','session_id','dispatch_id','observer_id'))
                or any(value[k]!=data[k]for k in
                    ('launcher_id','child_slot','child_worker_id','prepared_sha256'))
                or value['code']!=code):return False
    cause,final=failures;first,last=cause['data'],final['data']
    if first['capture_sha256']is not None or first['cleanup_sha256']is not None:return False
    if(last['capture_sha256']!=runtime._hash(host)
            or last['cleanup_sha256']!=host['cleanup_sha256']):return False
    if not(request['observed_at_ns']<=thread['first_stop_requested_at_ns']
            <=first['observed_at_ns']<=cause['observed_at_ns']<=row['observed_at_ns']
            <=thread['cleanup_finished_at_ns']<=last['observed_at_ns']
            <=final['observed_at_ns']<=thread['cleanup_deadline_ns']):return False
    receipts=[x for x in loaded['cleanup.json']['receipts']if runtime._hash(x)==host['cleanup_sha256']]
    if len(receipts)!=1:return False
    receipt=receipts[0]
    if(receipt['status']!='complete' or not receipt['descriptors_closed']
            or len(receipt['processes'])!=1 or receipt['deadline_ns']>hard
            or not request['observed_at_ns']<=receipt['started_at_ns']<=receipt['finished_at_ns']
                <=min(thread['cleanup_finished_at_ns'],thread['cleanup_deadline_ns'],hard)):return False
    ready=[x for x in loaded['processes.json']['readiness']if x['worker_ready']['worker_id']==slot['worker_id']]
    if len(ready)!=1:return False
    parent=ready[0]['parent_observation'];process=receipt['processes'][0]
    if(process['role']!=slot['role']or process['pid']!=parent['payload']['pid']
            or process['start_time_ticks']!=parent['payload']['start_time_ticks']
            or process['wrapper_pid']!=parent['wrapper']['pid']or process['wrapper_returncode']is None
            or not all(process[k]for k in('pin_verified','exit_observed','reaped_observed'))):return False
    if slot['role']=='nmap':
        natives=[x for x in loaded['processes.json']['native']if x['parent_observation']['payload']==parent['payload']]
        if(len(natives)!=1 or natives[0]['parent_observation']['wrapper']!=parent['wrapper']
                or natives[0]['observed_at_ns']>request['observed_at_ns']):return False
    return thread,final,hard
def _cancelled_capture_terminal(loaded,rows,row,operation,slot,closure,*,native_budget=None):
    facts=_capture_terminal_facts(loaded,rows,row,operation,slot,closure,'engagement_live_cancelled')
    if facts is False:return False
    from.import engagement_live_contract as c
    from.import engagement_live_protocol as protocol
    thread,final,hard=facts;data=row['data'];request=data['request'];envelope=operation['prepared']['envelope']
    if loaded['manifest.json']['case_id']in{'S42C-X53','S42C-X54','S42C-X55','S42C-X59'}:
        return _cancelled_capture_host_cause(loaded,rows,row,operation,slot,thread,native_budget,hard)
    for wrapped in rows:
        stop=wrapped['row']
        if(wrapped['source']!='broker_memfd' or stop['kind']!='protocol'
                or stop['broker_id']!=envelope['broker_id']or stop['observer_id']!=stop['broker_id']):continue
        part=stop['data'];frame=part['frame'];body=frame['body']
        if(part['channel_role']!='lifecycle' or part['direction']!='sent'
                or frame['channel_id']!=envelope['broker_id']
                or frame['operation']not in('BROKER_STOP','SESSION_STOP')):continue
        if frame['operation']=='SESSION_STOP' and body['session_id']!=envelope['session_id']:continue
        segment=loaded['manifest.json']['transcript']['segments'][wrapped['segment']]
        if segment['status']!='sealed_complete' or segment['broker_id']!=envelope['broker_id']:continue
        protocol.validate_frame(frame,role='lifecycle',direction='request')
        # A sealed send is not a host receive acknowledgment. Preserve both
        # advertised bounds and prove physical completion within each, even
        # when another terminal channel closes before this packet is polled.
        # This narrow single-broker graph includes every sibling and root role,
        # not only the selected client's already joined supervisor.
        if(any(x['finished_at_ns']>body['cleanup_deadline_ns']for x in loaded['cleanup.json']['receipts'])
                or any(x['cleanup_finished_at_ns']>body['cleanup_deadline_ns']
                    for x in loaded['cleanup.json']['supervisors'])):continue
        # The body is the broker's decision time; the row is appended after
        # send. A host monitor can stop before that append without an ACK claim.
        brokers=[x['parent_observation']for x in loaded['processes.json']['readiness']
            if x['role']=='broker' and x['worker_ready']['worker_id']==envelope['broker_id']]
        if len(brokers)!=1:continue
        parent=brokers[0]
        finished=[x['finished_at_ns']for x in loaded['cleanup.json']['receipts']if any(
            p['pid']==parent['payload']['pid']and p['start_time_ticks']==parent['payload']['start_time_ticks']
            and p['wrapper_pid']==parent['wrapper']['pid']and p['reaped_observed']for p in x['processes'])]
        if(finished and request['observed_at_ns']<=body['observed_at_ns']<=thread['first_stop_requested_at_ns']
                and body['observed_at_ns']<=stop['observed_at_ns']<=min(finished)
                and final['observed_at_ns']<=body['cleanup_deadline_ns']
                <=min(hard,body['observed_at_ns']+c.CLEANUP_NS)):return True
    return _cancelled_capture_crash_cause(loaded,rows,row,operation,slot,thread,final,native_budget,hard)
def _boundary_unsettled_dispatch(loaded,rows):
    """Bind this fixed negative's unresolved action after context validation."""
    from.import engagement_live_contract as c
    m=loaded['manifest.json'];cid=m['case_id'];case=BOUNDARY_CASES.get(cid);number=int(cid[-2:])if case else 0
    if(case is None or number!=40 and not 26<=number<=32 and not 44<=number<=59
            or m['evidence_class']!='owned_gate' or m['proof_kind']!='role_boundary'):return None
    proofs=loaded['results.json']['boundary_proofs'];observations=loaded['processes.json']['boundary_observations']
    if len(proofs)!=1 or len(observations)!=1:return None
    proof=proofs[0];raw=observations[0]['observation'];image=case['kind']=='image_identity';eof=case['kind']=='lifecycle';socket=case['kind']=='socket_denial'
    module='engagement_live_client_worker' if socket and number<29 else 'engagement_live_runtime' if image else 'engagement_live_endpoint_worker'
    sources=[x['sha256']for x in loaded['runtime.json']['runtime']['sources']if x['module']==module]
    config={'case_id':cid,'variant':case['variant'],'role':case['role']}
    if(len(sources)!=1 or proof['case_id']!=cid or proof['kind']!=case['kind']
            or observations[0]['kind']!=case['kind']or proof['role']!=case['role']
            or proof['source_sha256']!=sources[0]or proof['runtime_sha256']!=m['runtime_sha256']
            or proof['observation_sha256']!=runtime._hash(raw)
            or proof['checks']!={case['variant']:True}
            or len([x for x in loaded['runtime.json']['instrumentation']if x['kind']=='sealed_fault'
                and x['configuration']==config and x['source_sha256']==sources[0]])!=1):return None
    controls=[x for x in loaded['processes.json']['readiness']
        if runtime._hash(x)==proof['control_observation_sha256']]
    role='nmap' if image or socket and number<29 else('launcher' if case['role']=='all' else case['role'])if eof else 'endpoint'
    if len(controls)!=1 or controls[0]['role']!=role:return None
    control=controls[0];worker=control['worker_ready']['worker_id']
    if image:
        if raw['waiting_observation_sha256']!=proof['control_observation_sha256']or not raw['refused']or raw['arm_emitted']:return None
        slots=[x for x in loaded['processes.json']['child_slots']if x['worker_id']==worker and x['role']=='nmap']
        if len(slots)!=1:return None
        chosen=[x for x in loaded['results.json']['operations']if c.prepared_digest(x['prepared'])==slots[0]['prepared_sha256']]
    elif eof or socket:chosen=loaded['results.json']['operations']
    else:
        chosen=[x for x in loaded['results.json']['operations']if x['meter']is not None
            and runtime._hash(x['meter'])==raw['meter_transcript_sha256']and x['meter']['endpoint_id']==worker]
    if len(chosen)!=1:return None
    op=chosen[0];env=op['prepared']['envelope'];did=env['dispatch_id']
    expected_slot='http_identify' if image or eof or socket or number in(45,47,49)else 'http_headers'
    if op['result']is not None or op['client']is not None or env['slot']!=expected_slot:return None
    if not image and not eof and not socket:
        if case['kind']=='meter_boundary':
            metric={45:'connections',46:'connections',47:'request',48:'request',49:'response',50:'response',51:'partial_request',52:'partial_response'}[number]
            if raw['slot']!=expected_slot or raw['metric']!=metric:return None
        elif raw['stimulus']!={56:'forward_before_recv',57:'forward_before_send',58:'deadline_after_partial'}[number]:return None
    if eof or socket:
        slots=[x for x in loaded['processes.json']['child_slots']if x['role']=='nmap'
            and x['prepared_sha256']==c.prepared_digest(op['prepared'])]
        if len(slots)!=1 or socket and op['meter']is not None:return None
        roles=_retained_role_observations(rows);launcher=slots[0]['launcher_id']
        keys=[key for key,value in roles.items()if key[0]==env['broker_id']and key[2]=='launcher'
            and value[0]['worker_ready']['worker_id']==launcher]
        if len(keys)!=1:return None
        if role=='nmap':
            if slots[0]['worker_id']!=worker:return None
        elif role=='broker':
            if worker!=env['broker_id']:return None
        else:
            selected=roles.get((env['broker_id'],keys[0][1],role))
            if selected is None or selected[0]!=control:return None
        if eof and raw['origin']!={53:'broker_eof',54:'endpoint_eof',55:'launcher_eof',59:'payload_and_wrapper_cleanup'}[number]:return None
        if eof and op['meter']is not None:
            peer=roles.get((env['broker_id'],keys[0][1],'endpoint'))
            if not _lifecycle_meter_terminal(loaded,rows,op,slots[0],None if peer is None else peer[0]):return None
    if socket:
        target=op['session']['scope']['ssh' if number==28 else 'http'].copy()
        if number==26:target['target']='10.255.255.254'
        if number==27:target['port']+=1
        if(any(raw[k]!=target[k]for k in('target','port'))or raw['protocol']!=0
                or raw['flags']!=(0x20000000 if number>=30 else 0)
                or op['host_capture']is not None or loaded['processes.json']['native']):return None
    if image:
        refused=[x['row']['data']for x in rows if x['source']=='role_observer'
            and x['row']['kind']=='supervision_projection' and x['row']['dispatch_id']==did
            and x['row']['data']['kind']=='rpc' and x['row']['data']['request']['operation']=='OBSERVE_NATIVE']
        if(env['slot']!='http_identify' or op['meter']is not None or len(refused)!=1
                or refused[0]['child_worker_id']!=worker or refused[0]['reply']is None
                or refused[0]['local_error']!='engagement_live_invalid_runtime'
                or refused[0]['reply']['projection']['status']!='refused'
                or refused[0]['reply']['projection']['code']!='engagement_live_invalid_runtime'):return None
    for wrapped in rows:
        row=wrapped['row'];kind=row['kind'];part=row['data'];frame=part.get('frame')
        if socket:
            if kind in('meter','approval_witness','audit_witness','capability_projection'):return None
            if kind=='supervision_projection' and part['kind']=='rpc' and part['request']['operation']not in('START','OBSERVE_READY','REAP'):return None
            if kind=='protocol' and(frame['operation']not in('PREPARE','PREPARED','OBSERVATION','OPEN_SESSION','READY','ROLE_OBSERVED','AUDIT_OBSERVED','BROKER_STOP','SESSION_STOP')
                    or frame['operation']=='OBSERVATION' and(frame['body']['kind']not in('role_readiness','capability_projection')
                    or frame['body']['kind']=='capability_projection' and frame['body']['data']['operation']!='ISSUE')):return None
        if row['dispatch_id']!=did:continue
        if(image or eof)and kind=='meter':return None
        if kind=='protocol':
            if frame['operation']=='RESULT' or(image or eof and op['meter']is None)and frame['operation']=='METER' or image and frame['operation']=='NATIVE_OBSERVED':return None
            if frame['operation']=='DISPATCH' and part['direction']=='sent' and frame['body']['status']!='pending':return None
    for name in('final-ledger.json','recovery-ledger.json'):
        export=loaded.get(name)
        if export is None:return None
        reserved=[x for x in export['reservations']if x['dispatch_id']==did]
        if((bool(reserved)if socket else len(reserved)!=1 or reserved[0]['reservation']!=env['cost'])
                or any(x['dispatch_id']==did for x in export['completions'])):return None
    return did
def _timeout_capture_terminal(loaded,rows,row,operation,slot,closure,*,native_budget=None):
    """A fixed headers primitive can expire its actual original native budget."""
    if(slot['role']!='headers' or native_budget is None
            or loaded['manifest.json']['case_id']not in{'S42C-X46','S42C-X48','S42C-X50',
                'S42C-X51','S42C-X52','S42C-X56','S42C-X57','S42C-X58'}
            or _boundary_unsettled_dispatch(loaded,rows)!=operation['prepared']['envelope']['dispatch_id']):return False
    facts=_capture_terminal_facts(loaded,rows,row,operation,slot,closure,'engagement_live_timeout')
    if facts is False:return False
    thread,final,hard=facts;host=operation['host_capture'];request=row['data']['request'];env=operation['prepared']['envelope']
    if(env['slot']!='http_headers' or host['status']!='timeout'
            or native_budget['child_slot']!=slot['child_slot']
            or not native_budget['started_at_ns']<=request['observed_at_ns']<native_budget['native_deadline_ns']
                <=thread['first_stop_requested_at_ns']
            or native_budget['native_deadline_ns']>min(hard,native_budget['started_at_ns']+env['native_timeout_ns'])):return False
    bound=min(hard,thread['cleanup_deadline_ns'],native_budget['native_deadline_ns']+2_000_000_000)
    for item in rows:
        value=item['row']
        if value['kind']!='protocol':continue
        part=value['data'];frame=part['frame']
        if(item['source']=='broker_memfd' and value['broker_id']==env['broker_id']
                and part['channel_role']=='lifecycle' and part['direction']=='sent'
                and frame['operation']in('BROKER_STOP','SESSION_STOP')):bound=min(bound,frame['body']['cleanup_deadline_ns'])
    return(final['observed_at_ns']<=bound
        and all(x['finished_at_ns']<=bound for x in loaded['cleanup.json']['receipts'])
        and all(x['cleanup_finished_at_ns']<=bound for x in loaded['cleanup.json']['supervisors']))
def _cancelled_capture_crash_cause(loaded,rows,row,operation,slot,thread,final,budget,hard):
    """Join a fixed partial-progress crash to the common cancelled CAPTURE proof.

    Null-clock host rows bound a signal window, not a syscall timestamp.
    """
    from.import engagement_live_contract as c
    from.import engagement_live_protocol as protocol
    manifest=loaded['manifest.json'];prepared=operation['prepared'];env=prepared['envelope']
    cases={'S42C-N45':('kill_during_partial_request','recv'),'S42C-N46':('kill_during_partial_response','send')}
    selected=cases.get(manifest['case_id'])
    if(selected is None or budget is None or len(loaded['results.json']['operations'])!=1
            or slot['role']!='nmap' or env['slot']!='http_identify'
            or operation['host_capture']['status']!='cancelled' or operation['meter']is not None):return False
    variant,progress_kind=selected;broker=env['broker_id'];did=env['dispatch_id'];digest=c.prepared_digest(prepared)
    if manifest['broker_instances']!=[{'broker_id':broker,'ledger_owner_id':env['ledger_owner_id']}]:return False
    def matches(value,observer=broker):
        return value['observer_id']==observer and all(value[k]==env[k]for k in('broker_id','session_id','dispatch_id'))
    instrumentation=loaded['runtime.json']['instrumentation'];sources=loaded['runtime.json']['runtime']['sources']
    config={'case_id':manifest['case_id'],'variant':variant,'role':'endpoint'}
    expected={x['sha256']for x in sources if x['module']in('engagement_live_endpoint_worker','engagement_live_broker_worker')}
    configured=[x['source_sha256']for x in instrumentation if x['kind']=='sealed_fault' and x['configuration']==config]
    signals=[x for x in instrumentation if x['kind']=='process_signal' and x['configuration']=={**config,'role':'broker'}]
    reviews=[x for x in instrumentation if x['kind']=='scripted_review' and x['configuration']=={**config,'role':'host'}]
    if(len(expected)!=2 or len(configured)!=2 or set(configured)!=expected or len(signals)!=1
            or len(reviews)!=1 or signals[0]['source_sha256']!=reviews[0]['source_sha256']):return False
    goes=[x for x in rows if x['row']['kind']=='protocol' and x['row']['dispatch_id']==did
        and x['row']['data']['frame']['operation']=='GO']
    if len(goes)!=1:return False
    go=goes[0];data=go['row']['data'];release=data['frame']['body'];segment=manifest['transcript']['segments'][go['segment']]
    if(go['source']!='broker_memfd' or not matches(go['row'])or data['direction']!='sent'
            or data['channel_role']!='launcher' or data['frame']['channel_id']!=slot['launcher_id']
            or segment['source']!='broker_memfd' or segment['broker_id']!=broker or segment['status']!='reaped_partial'):return False
    protocol.validate_frame(data['frame'],role='launcher',direction='request')
    if(any(release[k]!=env[k]for k in('broker_id','ledger_owner_id','session_id','dispatch_id'))
            or release['prepared_sha256']!=digest or release['envelope_sha256']!=c.envelope_digest(env)):return False
    recovery=loaded.get('recovery-ledger.json')
    if recovery is None:return False
    reserved=[x for x in recovery['reservations']if x['dispatch_id']==did]
    events=[x for x in recovery['events']if x['request']['operation']=='reserve' and x['request']['body']['dispatch_id']==did]
    if len(reserved)!=1 or len(events)!=1:return False
    reservation=reserved[0];event=events[0];receipt=event['receipt']
    if(any(reservation[k]!=env[k]for k in('session_id','slot','generation','revision','action_sha256','policy_sha256'))
            or reservation['owner_id']!=env['ledger_owner_id']or reservation['reservation']!=env['cost']
            or reservation['action_id']!=prepared['action']['action_id']
            or(event['event_id'],event['sequence'],receipt['state_sha256'])!=
                (release['reservation_event_id'],release['reservation_sequence'],release['reservation_state_sha256'])
            or any(recovery['state']['usage'][k]<receipt['usage'][k]or receipt['usage'][k]<env['cost'][k]for k in env['cost'])):return False
    if any(x['request']['operation']=='complete' and x['request']['body']['dispatch_id']==did
            for name in('initial-ledger.json','final-ledger.json','recovery-ledger.json')
            for x in loaded.get(name,{}).get('events',[])):return False
    bound=thread['cleanup_deadline_ns']# Already bounded by original/first-stop deadlines.
    roles=_retained_role_observations(rows)
    indices=[key[1]for key,value in roles.items()if key[0]==broker and key[2]=='launcher'
        and value[0]['worker_ready']['worker_id']==slot['launcher_id']]
    if len(indices)!=1 or(broker,indices[0],'endpoint')not in roles:return False
    endpoint=roles[(broker,indices[0],'endpoint')][0]
    if endpoint not in loaded['processes.json']['readiness']or endpoint['parent_observation']['sampled_at_ns']>go['row']['observed_at_ns']:return False
    progress=[x for x in rows if x['row']['kind']=='meter' and x['row']['dispatch_id']==did]
    if not 1<=len(progress)<=64:return False
    previous=release['guard_clock']['mono_after_ns'];sequence=go['row']['row_sequence'];accepted=received=sent=0
    for number,item in enumerate(progress,1):
        value=item['row'];event=runtime.validate_meter_event(value['data']);kind=event['kind']
        if(item['source']!='broker_memfd' or item['segment']!=go['segment']or not matches(value)
                or event['sequence']!=number or value['row_sequence']<=sequence or(kind=='arm')!=(number==1)
                or not previous<=event['monotonic_ns']<=value['observed_at_ns']<hard
                or not budget['started_at_ns']<=event['monotonic_ns']<min(budget['native_deadline_ns'],release['effect_stop_ns'])):return False
        previous=event['monotonic_ns'];sequence=value['row_sequence']
        if kind=='accept':accepted+=1
        if event['connection']!=accepted or accepted>3 or event['reason']is not None or kind in('close','cancel'):return False
        if kind in('recv','send'):
            if not accepted or event['remaining_before']!=4096-(received if kind=='recv' else sent)or event['actual_bytes']<1:return False
            if kind=='recv':received+=event['actual_bytes']
            else:sent+=event['actual_bytes']
        elif any(event[k]for k in('requested_bytes','actual_bytes','remaining_before','remaining_after')):return False
    last=progress[-1]['row']['data']
    if(last['kind']!=progress_kind or(last['actual_bytes'],last['requested_bytes'])!=
            (1,4096 if progress_kind=='recv' else 1)
            or any(x['row']['data']['kind']==progress_kind for x in progress[:-1])
            or(progress_kind=='recv' and sent or progress_kind=='send' and not received)):return False
    phases=[x for x in rows if x['row']['kind']=='phase' and x['row']['dispatch_id']==did
        and x['row']['data']['phase']=='client' and x['row']['data']['stage']in('begin','end')]
    ends=[x for x in phases if x['row']['data']['stage']=='end']
    if len(ends)!=1:return False
    end=ends[0];begins=[x for x in phases if x['row']['data']['stage']=='begin'
        and x['row']['observed_at_ns']<=end['row']['observed_at_ns']]
    if len(begins)!=1:return False
    begin=begins[0]
    if begin['segment']!=end['segment']or begin['row']['row_sequence']>=end['row']['row_sequence']:return False
    for item in(begin,end):
        value=item['row'];phase=value['data'];part=manifest['transcript']['segments'][item['segment']]
        if(item['source']!='role_observer' or part['source']!='role_observer' or part['status']!='observer_complete'
                or not matches(value)or phase['related_sha256']!=digest or phase['clock']is not None
                or phase['reason']is not None or phase['original_deadline_ns']!=env['action_deadline_ns']):return False
    began=begin['row']['observed_at_ns'];ended=end['row']['observed_at_ns']
    if not(progress[-1]['row']['observed_at_ns']<=began<=ended<=final['observed_at_ns']<=bound
            and began<=thread['first_stop_requested_at_ns']and ended<hard)or any(
                x['row']['observed_at_ns']>began for x in progress):return False
    ready=[x for x in loaded['processes.json']['readiness']if x['role']=='broker' and x['worker_ready']['worker_id']==broker]
    if len(ready)!=1:return False
    parent=ready[0]['parent_observation'];receipts=loaded['cleanup.json']['receipts']
    killed=[(receipt,process)for receipt in receipts for process in receipt['processes']
        if process['pid']==parent['payload']['pid']and process['start_time_ticks']==parent['payload']['start_time_ticks']]
    if(not killed or sum(len(receipt['processes'])==1 for receipt,_ in killed)!=1
            or min(receipt['finished_at_ns']for receipt,_ in killed)<began
            or any(process['role']!='broker' or process['wrapper_pid']!=parent['wrapper']['pid']
                or process['wrapper_returncode']not in(-9,137)for _,process in killed)):return False
    if(any(x['status']!='complete' or x['deadline_ns']>bound
            or any(not p['pin_verified']for p in x['processes'])for x in receipts)
            or any(x['cleanup_finished_at_ns']>bound or x['cleanup_deadline_ns']>bound
                for x in loaded['cleanup.json']['supervisors'])):return False
    return not any(x['row']['kind']=='protocol' and x['row']['dispatch_id']==did and(
        x['row']['data']['frame']['operation']in('METER','RESULT')or
        x['row']['data']['frame']['operation']=='OBSERVATION' and x['row']['data']['frame']['body']['kind']=='capture')for x in rows)
def _cancelled_native_begin_terminal(loaded,rows,row,operation,slot,closure):
    """Prove the fixed broker crash interrupted one unreplied native request.

    The host cancellation and physical closure resolve this negative exchange;
    they never supply NATIVE_BUDGET, native execution, or a completed dispatch.
    The ordinary authority/witness replay remains independently required.
    """
    from.import engagement_live_contract as c
    from.import engagement_live_protocol as protocol
    prepared=operation['prepared'];envelope=prepared['envelope']
    data=row['data'];request=data['request'];did=envelope['dispatch_id']
    broker=envelope['broker_id'];digest=c.prepared_digest(prepared)
    instances=loaded['manifest.json']['broker_instances']
    if(request['operation']!='NATIVE_BEGIN' or data['reply']is not None
            or data['local_error']!='engagement_live_cancelled'
            or len(loaded['results.json']['operations'])!=1 or not instances
            or instances[0]!={'broker_id':broker,'ledger_owner_id':envelope['ledger_owner_id']}
            or slot['role']not in('nmap','headers')or not closure['complete']
            or any(operation[k]is not None for k in('result','client','meter'))):return False
    if(any(row[k]!=envelope[k]for k in('broker_id','session_id','dispatch_id'))
            or row['observer_id']!=slot['launcher_id']
            or data['launcher_id']!=slot['launcher_id']or data['child_slot']!=slot['child_slot']
            or data['child_worker_id']!=slot['worker_id']or data['prepared_sha256']!=digest):return False
    host=operation['host_capture'];empty=hashlib.sha256(b'').hexdigest()
    if(host is None or host['cleanup_sha256']is None or host['status']!='unresolved'
            or host['exit_code']!=137 or host['truncated']
            or any(host[k+'_bytes']!=0 or host[k+'_sha256']!=empty
                   for k in('stdout','stderr'))):return False
    hard=min(envelope[k]for k in('action_deadline_ns','session_deadline_ns','broker_deadline_ns'))
    threads=[x for x in loaded['cleanup.json']['supervisors']if
        all(x[k]==slot[k]for k in('broker_id','session_id','launcher_id'))]
    if len(threads)!=1:return False
    thread=threads[0];first_stop=thread['first_stop_requested_at_ns']
    bound=min(hard,first_stop+1_900_000_000)
    if(thread['state']!='joined' or thread['status']!='complete'
            or not thread['join_attempted']or thread['thread_alive_observed']is not False
            or thread['pending_slots']or not thread['channel_closed']
            or thread['cleanup_deadline_ns']>bound):return False
    # The GO and fixed crash marker belong to the original broker's retained
    # partial stream. A later broker's sealed STOP cannot satisfy this proof.
    segments=loaded['manifest.json']['transcript']['segments']
    def same_context(value,observer):
        return(all(value[k]==envelope[k]for k in('broker_id','session_id','dispatch_id'))
            and value['observer_id']==observer)
    goes=[x for x in rows if x['source']=='broker_memfd' and x['row']['kind']=='protocol'
        and x['row']['data']['channel_role']=='launcher'
        and x['row']['data']['direction']=='sent'
        and x['row']['data']['frame']['operation']=='GO' and x['row']['dispatch_id']==did]
    if len(goes)!=1:return False
    go=goes[0];release=go['row']['data']['frame']['body']
    part=segments[go['segment']]
    if(not same_context(go['row'],broker)or part['source']!='broker_memfd'
            or part['broker_id']!=broker or part['status']!='reaped_partial'
            or go['row']['data']['frame']['channel_id']!=slot['launcher_id']):return False
    protocol.validate_frame(go['row']['data']['frame'],role='launcher',direction='request')
    if(any(release[k]!=envelope[k]for k in('broker_id','ledger_owner_id','session_id','dispatch_id'))
            or release['envelope_sha256']!=c.envelope_digest(envelope)
            or release['prepared_sha256']!=digest
            or request['projection']!={'child_slot':slot['child_slot'],'release_sha256':runtime._hash(release)}):return False
    _supervision_frame(request,slot['launcher_id'],{'child_slot':slot['child_slot'],'release':release})
    # Retained exports must still carry the exact full reservation. Neither a
    # missing response nor cancellation is a completion or a refund.
    reservations=[]
    for name in('initial-ledger.json','final-ledger.json','recovery-ledger.json'):
        export=loaded.get(name)
        if export is None:
            if name!='initial-ledger.json':return False
            continue
        if any(x['dispatch_id']==did for x in export['completions']):return False
        if any(x['request']['operation']=='complete' and x['request']['body']['dispatch_id']==did
               for x in export['events']):return False
        if name=='initial-ledger.json':continue
        found=[x for x in export['reservations']if x['dispatch_id']==did]
        events=[x for x in export['events']if x['request']['operation']=='reserve'
            and x['request']['body']['dispatch_id']==did]
        if len(found)!=1 or len(events)!=1:return False
        reserved=found[0];event=events[0];receipt=event['receipt']
        if(any(reserved[k]!=envelope[k]for k in('dispatch_id','session_id','slot','generation',
                'revision','action_sha256','policy_sha256'))
                or reserved['owner_id']!=envelope['ledger_owner_id']
                or reserved['action_id']!=prepared['action']['action_id']
                or reserved['reservation']!=envelope['cost']
                or event['event_id']!=release['reservation_event_id']
                or event['sequence']!=release['reservation_sequence']
                or receipt['state_sha256']!=release['reservation_state_sha256']
                or receipt['dispatch_id']!=did or receipt['session_id']!=envelope['session_id']
                or any(export['state']['usage'][k]<receipt['usage'][k]
                    or receipt['usage'][k]<envelope['cost'][k]for k in envelope['cost'])):return False
        reservations.append(runtime._json(reserved))
    if len(reservations)!=2 or reservations[0]!=reservations[1]:return False
    def phases(source,stage,related):
        selected=[]
        for item in rows:
            value=item['row']
            if item['source']!=source or value['kind']!='phase':continue
            phase=value['data'];clock=phase['clock']
            if(not same_context(value,broker)or phase['phase']!='go' or phase['stage']!=stage
                    or phase['reason']is not None or phase['related_sha256']!=related
                    or phase['original_deadline_ns']!=envelope['action_deadline_ns']or clock is None):continue
            if not(envelope['action_ready_ns']<=clock['mono_before_ns']<=clock['mono_after_ns']
                    <=value['observed_at_ns']<hard):continue
            selected.append(item)
        return selected
    markers=phases('broker_memfd','end',runtime._hash(prepared))
    begins=phases('role_observer','begin',digest);ends=phases('role_observer','end',digest)
    if len(markers)!=1 or len(begins)!=1 or len(ends)!=1:return False
    marker,begin,end=markers[0],begins[0],ends[0]
    if(marker['segment']!=go['segment']or begin['segment']!=end['segment']
            or segments[begin['segment']]['source']!='role_observer'
            or segments[begin['segment']]['status']!='observer_complete'
            or go['row']['row_sequence']>=marker['row']['row_sequence']
            or begin['row']['row_sequence']>=end['row']['row_sequence']
            or not(release['guard_clock']['mono_after_ns']<=go['row']['observed_at_ns']
                <=marker['row']['observed_at_ns']<=begin['row']['data']['clock']['mono_before_ns']
                <=begin['row']['observed_at_ns']<=end['row']['data']['clock']['mono_before_ns']
                <=end['row']['observed_at_ns'])
            or not go['row']['observed_at_ns']<=request['observed_at_ns']<=first_stop
            or begin['row']['data']['clock']['mono_after_ns']>first_stop
            or end['row']['observed_at_ns']>marker['row']['observed_at_ns']+c.SECOND):return False
    failures=[x['row']for x in rows if x['source']=='role_observer'
        and x['row']['kind']=='supervision_projection' and x['row']['data']['kind']=='local_failure'
        and x['row']['data']['launcher_id']==slot['launcher_id']]
    if len(failures)!=2:return False
    failures.sort(key=lambda x:x['data']['observed_at_ns'])
    for failure in failures:
        value=protocol.validate_supervision_projection(failure['data'])
        if(not same_context(failure,slot['launcher_id'])or value['code']!='engagement_live_cancelled'
                or any(value[k]!=data[k]for k in
                    ('launcher_id','child_slot','child_worker_id','prepared_sha256'))):return False
    cause,final=failures;first,last=cause['data'],final['data']
    if(first['capture_sha256']is not None or first['cleanup_sha256']is not None
            or last['capture_sha256']!=runtime._hash(host)or last['cleanup_sha256']!=host['cleanup_sha256']
            or end['row']['observed_at_ns']>final['observed_at_ns']
            or not(first_stop<=first['observed_at_ns']<=cause['observed_at_ns']<=row['observed_at_ns']
                <=thread['cleanup_finished_at_ns']<=last['observed_at_ns']
                <=final['observed_at_ns']<=thread['cleanup_deadline_ns'])):return False
    receipts=loaded['cleanup.json']['receipts'];processes=loaded['processes.json']
    child_receipts=[x for x in receipts if runtime._hash(x)==host['cleanup_sha256']]
    child_ready=[x for x in processes['readiness']if x['worker_ready']['worker_id']==slot['worker_id']]
    broker_ready=[x for x in processes['readiness']if x['role']=='broker'
        and x['worker_ready']['worker_id']==broker]
    if len(child_receipts)!=1 or len(child_ready)!=1 or len(broker_ready)!=1:return False
    child_parent=child_ready[0]['parent_observation'];broker_parent=broker_ready[0]['parent_observation']
    def matches(process,parent,role):
        return(process['role']==role and process['pid']==parent['payload']['pid']
            and process['start_time_ticks']==parent['payload']['start_time_ticks']
            and process['wrapper_pid']==parent['wrapper']['pid'])
    killed=[x for x in receipts if len(x['processes'])==1 and matches(x['processes'][0],broker_parent,'broker')]
    if len(killed)!=1:return False
    # The signal journal and monitor cleanup are concurrent. Reaping may
    # finish before the signal's end row is appended, and broker cleanup may
    # already be waiting when the signal is sent. Only causal lower bounds
    # apply; the child cleanup still follows its observed request.
    broker_finishes=[receipt['finished_at_ns']for receipt in receipts if any(
        process['pid']==broker_parent['payload']['pid']
        and process['start_time_ticks']==broker_parent['payload']['start_time_ticks']
        for process in receipt['processes'])]
    if(child_receipts[0]['started_at_ns']<request['observed_at_ns']
            or min(broker_finishes)<begin['row']['data']['clock']['mono_after_ns']):return False
    for receipt,parent,role,latest in((child_receipts[0],child_parent,slot['role'],thread['cleanup_finished_at_ns']),
            (killed[0],broker_parent,'broker',thread['cleanup_deadline_ns'])):
        if(receipt['status']!='complete' or not receipt['descriptors_closed']or len(receipt['processes'])!=1
                or receipt['deadline_ns']>bound
                or not receipt['started_at_ns']<=receipt['finished_at_ns']
                    <=min(latest,receipt['deadline_ns'])):return False
        process=receipt['processes'][0]
        if(not matches(process,parent,role)or process['wrapper_returncode']not in(-9,137)
                or not all(process[k]for k in('pin_verified','exit_observed','reaped_observed'))):return False
    if any(x['parent_observation']['payload']==child_parent['payload']for x in processes['native']):return False
    if any(x['role']=='parser' and x['launcher_id']==slot['launcher_id']
            and any(x[k]is not None for k in('prepared_sha256','bootstrap','entry_sha256'))
            for x in processes['child_slots']):return False
    for item in rows:
        value=item['row'];part=value['data']
        if value['kind']=='supervision_projection' and part['kind']=='rpc' and part['launcher_id']==slot['launcher_id']:
            if part['request']['sequence']>request['sequence']or part['request']['observed_at_ns']>request['observed_at_ns']:return False
        if value['dispatch_id']!=did:continue
        if value['kind']=='meter':return False
        if value['kind']=='protocol':
            frame=part['frame']
            if frame['operation']in('METER','NATIVE_OBSERVED','RESULT'):return False
            if frame['operation']=='DISPATCH' and part['direction']=='sent':
                if(item['source']!='broker_memfd' or not same_context(value,broker)
                        or part['channel_role']!='ingress' or frame['body']['status']!='pending'
                        or frame['body']['code']is not None or frame['body']['data']!={'dispatch_id':did}
                        or value['observed_at_ns']>go['row']['observed_at_ns']):return False
            if frame['operation']=='OBSERVATION' and(frame['body']['kind']=='capture'
                    or value['observed_at_ns']>=request['observed_at_ns']):return False
    return True
def _validate_supervision(loaded,rows,deadline):
    from.import engagement_live_contract as c
    from.import engagement_live_protocol as protocol
    processes=loaded['processes.json'];cleanup=loaded['cleanup.json']
    operations=loaded['results.json']['operations'];bundle=loaded['runtime.json']['runtime']
    missing=set();slots={};workers=set();endpoints=set();groups={}
    prepared={c.prepared_digest(op['prepared']):op for op in operations}
    readies={runtime._hash(x):x for x in processes['readiness']}
    ready_workers={}
    for ready in readies.values():
        worker=ready['worker_ready']['worker_id']
        if worker in ready_workers:_bad()
        ready_workers[worker]=ready
    entries={runtime._hash(x):x for x in processes['startup']}
    natives={runtime._hash(x):x for x in processes['native']}
    cleanups={runtime._hash(x):x for x in cleanup['receipts']}
    for receipt in cleanups.values():runtime.validate_cleanup(receipt)
    closure=_supervisor_closure(loaded)
    unstarted={(x['broker_id'],x['session_id'],x['launcher_id'])
                 for x in cleanup['supervisors']if x['state']=='not_started'}
    brokers={x['broker_id']for x in loaded['manifest.json']['broker_instances']}
    for slot in _sequence(processes['child_slots'],24):
        c._check_deadline(deadline)
        c.obj(slot,('schema_version','broker_id','session_id','launcher_id','child_slot',
            'worker_id','role','pair','prepared_sha256','bootstrap','entry_sha256'))
        if slot['schema_version']!='1':_bad()
        for key in('broker_id','session_id','launcher_id','worker_id'):c.uuid(slot[key])
        if slot['broker_id']not in brokers or slot['worker_id']in workers:_bad()
        workers.add(slot['worker_id']);c.member(slot['child_slot'],_CHILD_SLOTS)
        role,action_slot,fd=_CHILD_SLOTS[slot['child_slot']]
        if slot['role']!=role:_bad()
        key=(slot['launcher_id'],slot['child_slot'])
        if key in slots:_bad()
        slots[key]=slot
        group=(slot['broker_id'],slot['session_id'],slot['launcher_id'])
        groups.setdefault(group,set()).add(slot['child_slot'])
        pair=slot['pair'];c.obj(pair,('launcher_fd','request_endpoint','child_endpoint'))
        if type(pair['launcher_fd'])is not int or pair['launcher_fd']!=fd:_bad()
        for endpoint in('request_endpoint','child_endpoint'):
            obj=pair[endpoint];c.obj(obj,('device','inode','mode','flags'))
            for k in('device','inode'):c.integer(obj[k],0,18446744073709551615)
            for k in('mode','flags'):c.integer(obj[k],0,4294967295)
            ident=(obj['device'],obj['inode'])
            if(ident in endpoints or not stat.S_ISSOCK(obj['mode'])or obj['flags']&3!=2
                    or not obj['flags']&0x800 or obj['flags']&0x200000):_bad()
            endpoints.add(ident)
        launcher=ready_workers.get(slot['launcher_id'])
        if launcher is None:
            if group not in unstarted:missing.add('transcript')
        else:
            if launcher['role']!='launcher':_bad()
            descriptor=[x for x in launcher['parent_observation']['descriptors']if x['fd']==fd]
            if len(descriptor)!=1 or any(descriptor[0][k]!=pair['request_endpoint'][k]for k in('device','inode','mode','flags')):_bad()
        if slot['prepared_sha256']is not None:
            c.digest_string(slot['prepared_sha256'])
            op=prepared.get(slot['prepared_sha256'])
            if op is None:missing.add('transcript')
            elif any(op['prepared']['envelope'][k]!=slot[k]for k in('broker_id','session_id'))or op['prepared']['envelope']['slot']!=action_slot:_bad()
        if slot['bootstrap']is not None:
            c.obj(slot['bootstrap'],('deadline_ns','bytes','sha256'))
            c.integer(slot['bootstrap']['deadline_ns']);c.integer(slot['bootstrap']['bytes'],1,32768);c.digest_string(slot['bootstrap']['sha256'])
            if slot['prepared_sha256']is None:_bad()
        if slot['entry_sha256']is not None:
            c.digest_string(slot['entry_sha256']);parent=entries.get(slot['entry_sha256'])
            if parent is None:missing.add('transcript')
            else:
                if parent['role']!=role or parent['stage']!='entry':_bad()
                desc=[x for x in parent['descriptors']if x['fd']==0]
                if len(desc)!=1 or any(desc[0][k]!=pair['child_endpoint'][k]for k in('device','inode','mode','flags')):_bad()
                ready=ready_workers.get(slot['worker_id'])
                if ready is not None and(ready['role']!=role or ready['parent_observation']['payload']!=parent['payload']):_bad()
        ready=ready_workers.get(slot['worker_id'])
        if ready is not None and(slot['bootstrap']is None or ready['worker_ready']['bootstrap_sha256']!=slot['bootstrap']['sha256']):_bad()
    if any(names!=set(_CHILD_SLOTS)for names in groups.values()):missing.add('transcript')
    for ready in readies.values():
        if ready['role']=='launcher':
            actual=[names for key,names in groups.items()if key[2]==ready['worker_ready']['worker_id']]
            if len(actual)!=1 or actual[0]!=set(_CHILD_SLOTS):missing.add('transcript')
    if not closure['all_closed']or not closure['complete']:missing.add('cleanup')
    # Every observed process is read in one actual host PID namespace. A digest
    # or a relay label cannot translate an isolated parent's numeric PID.
    parents=list(entries.values())+[x['parent_observation']for x in readies.values()]+[x['parent_observation']for x in natives.values()]
    from.engagement_live_witness import _retained_audit_readiness
    audit=_retained_audit_readiness(loaded,rows=rows,deadline=deadline)
    parents+=[x['readiness']['parent_observation']for x in audit['observations']]
    observers={runtime._hash(_observer(x['observer']))for x in parents}
    observers.update(runtime._hash(_observer(x['host_observer']))for x in cleanup['supervisors'])
    if len(observers)>1:_bad()
    for row in cleanup['supervisors']:
        key=(row['broker_id'],row['session_id'],row['launcher_id'])
        if key not in groups:_bad()
    dispatches={op['prepared']['envelope']['dispatch_id']:{
        'capture':_host_capture(loaded,op,cleanups),'native_budget':None}for op in operations}
    releases,relays=_saved_execution(loaded,rows=rows)
    role_observations=_retained_role_observations(rows)
    for op in operations:
        did=op['prepared']['envelope']['dispatch_id'];capture=dispatches[did]['capture']
        if capture is not None and 'capture' in relays.get(did,{})and capture!=relays[did]['capture']:_bad()
        if op['client']is not None and capture is None:missing.add('transcript')
        owned={s['worker_id']:s for s in slots.values()if s['prepared_sha256']==c.prepared_digest(op['prepared'])}
        if capture is not None:
            client_slots=[s for s in owned.values()if s['role']in('nmap','headers')]
            if len(client_slots)!=1:missing.add('transcript')
            else:
                receipt=cleanups.get(op['host_capture']['cleanup_sha256'])
                _slot_cleanup(receipt,client_slots[0],ready_workers,entries)
        for ready in relays.get(did,{}).get('role_readiness',[]):
            worker=ready['worker_ready']['worker_id']
            if worker not in owned or ready['role']!=owned[worker]['role']:_bad()
            if worker not in ready_workers:missing.add('transcript')
            elif ready!=ready_workers[worker]:_bad()
    state={};sequences={};reply_sequences={};count=0;terminal=set();local_counts={};last_time={};started={}
    # A failed request can be finalized after its terminal-cause row. Replay
    # actual receive/observation times, without changing retained segment order
    # or pretending the two host rows were recorded in the reverse order.
    projected_rows=[item for item in rows if item['row']['kind']=='supervision_projection']
    def causal_time(item):
        data=item['row']['data']
        return data['request']['observed_at_ns']if data['kind']=='rpc' else data['observed_at_ns']
    for wrapper in sorted(projected_rows,key=causal_time):
        row=wrapper['row']
        if row['kind']!='supervision_projection':continue
        c._check_deadline(deadline);count+=1
        if count>96 or len(runtime._json(row))>3072 or wrapper['source']!='role_observer':_bad()
        data=protocol.validate_supervision_projection(row['data'])
        if row['observer_id']!=data['launcher_id']:_bad()
        if data['kind']=='local_failure':
            channel=data['launcher_id'];local_counts[channel]=local_counts.get(channel,0)+1
            if local_counts[channel]>2:_bad()
            if data['observed_at_ns']<last_time.get(channel,0)or row['observed_at_ns']<data['observed_at_ns']:_bad()
            last_time[channel]=data['observed_at_ns']
            terminal.add(channel)
            matches=[s for s in slots.values()if s['launcher_id']==data['launcher_id']]
            if not matches:missing.add('transcript');continue
            if row['broker_id']!=matches[0]['broker_id']or row['session_id']!=matches[0]['session_id']:_bad()
            if data['child_slot']is not None:
                slot=slots.get((data['launcher_id'],data['child_slot']))
                if slot is None or slot['worker_id']!=data['child_worker_id']or slot['prepared_sha256']!=data['prepared_sha256']:_bad()
            operation=prepared.get(data['prepared_sha256'])
            if data['capture_sha256']is not None and(operation is None or operation['host_capture']is None
                    or runtime._hash(operation['host_capture'])!=data['capture_sha256']):_bad()
            if data['cleanup_sha256']is not None:
                receipt=cleanups.get(data['cleanup_sha256'])
                if receipt is None or data['child_slot']is None:_bad()
                _slot_cleanup(receipt,slot,ready_workers,entries)
            continue
        key=(data['launcher_id'],data['child_slot']);slot=slots.get(key)
        if slot is None:missing.add('transcript');continue
        if(data['child_worker_id']!=slot['worker_id']or data['prepared_sha256']!=slot['prepared_sha256']
                or row['broker_id']!=slot['broker_id']or row['session_id']!=slot['session_id']):_bad()
        op=prepared.get(data['prepared_sha256']);request=data['request'];operation=request['operation']
        if op is None:missing.add('transcript');continue
        did=op['prepared']['envelope']['dispatch_id']
        if row['dispatch_id']!=did:_bad()
        channel=data['launcher_id'];expected=sequences.get(channel,0)+1
        if channel in terminal:_bad()
        if request['observed_at_ns']<last_time.get(channel,0):_bad()
        last_time[channel]=request['observed_at_ns']
        if request['sequence']!=expected:_bad()
        sequences[channel]=expected
        stage=state.get(key,'allocated')
        allowed={'START':{'allocated'},'OBSERVE_READY':{'entry'},'NATIVE_BEGIN':{'ready'},
            'OBSERVE_NATIVE':{'active'},'CAPTURE':{'active','native'},'REAP':{'entry','ready','active','native'}}
        if stage not in allowed[operation]:_bad()
        prefix='identify_' if op['prepared']['envelope']['slot']=='http_identify' else 'headers_'
        if operation=='NATIVE_BEGIN' and state.get((channel,prefix+'admission'))!='reaped':_bad()
        if operation=='START' and slot['role']=='parser' and state.get((channel,prefix+'client'))!='reaped':_bad()
        if operation=='START':
            active=[slots[k]for k,v in state.items()if k[0]==channel and v not in('allocated','reaped','terminal')]
            if(slot['role']=='parser' and active or slot['role']!='parser' and
                    (len(active)>=2 or any(s['role']=='parser' or s['prepared_sha256']!=slot['prepared_sha256']for s in active))):_bad()
            started[key]=request['observed_at_ns']
        body={'child_slot':data['child_slot']}
        if operation=='START':body['prepared']=op['prepared']
        elif operation=='OBSERVE_READY':
            if slot['bootstrap']is None:missing.add('transcript');continue
            body['bootstrap_sha256']=slot['bootstrap']['sha256']
        elif operation=='NATIVE_BEGIN':
            release=releases.get(did)
            if release is None:missing.add('transcript');continue
            body['release']=release
        projected={'child_slot':data['child_slot']}
        if operation=='START':projected['prepared_sha256']=c.prepared_digest(op['prepared'])
        elif operation=='OBSERVE_READY':projected['bootstrap_sha256']=body['bootstrap_sha256']
        elif operation=='NATIVE_BEGIN':projected['release_sha256']=runtime._hash(body['release'])
        if request['projection']!=projected:_bad()
        _supervision_frame(request,channel,body)
        reply=data['reply']
        state[key]='terminal'  # every missing/refused exchange consumes the slot
        if reply is None:
            terminal.add(channel)
            resolved=(_cancelled_native_begin_terminal(loaded,rows,row,op,slot,closure)
                if operation=='NATIVE_BEGIN' else _timeout_capture_terminal(loaded,rows,row,op,slot,closure,
                    native_budget=dispatches[did]['native_budget'])if data['local_error']=='engagement_live_timeout'
                else _cancelled_capture_terminal(loaded,rows,row,op,slot,closure,
                    native_budget=dispatches[did]['native_budget']if stage=='native' else None))
            if not resolved:missing.add('transcript')
            continue
        expected_reply=reply_sequences.get(channel,0)+1
        if reply['sequence']!=expected_reply or reply['operation']!=protocol.SUPERVISION_RESPONSES[operation]:_bad()
        reply_sequences[channel]=expected_reply
        projection=reply['projection']
        if projection['request_sequence']!=request['sequence']or reply['observed_at_ns']<request['observed_at_ns']:_bad()
        if row['observed_at_ns']<reply['observed_at_ns']:_bad()
        last_time[channel]=reply['observed_at_ns']
        result=None
        if projection['status']=='refused':terminal.add(channel)
        if projection['status']=='ok':
            state[key]={'START':'entry','OBSERVE_READY':'ready','NATIVE_BEGIN':'active',
                'OBSERVE_NATIVE':'native','CAPTURE':'reaped','REAP':'reaped'}[operation]
            part=projection['data'];result={'child_slot':data['child_slot']}
            if part['child_slot']!=data['child_slot']:_bad()
            if operation=='START':
                bootstrap=_reconstruct_bootstrap(slot,op,ready_workers,bundle,parents,
                    role_observations,request['observed_at_ns'])
                if bootstrap is None:missing.add('transcript');continue
                if not request['observed_at_ns']<bootstrap['deadline_ns']:_bad()
                if slot['role']=='parser' and bootstrap['deadline_ns']>request['observed_at_ns']+2000000000:_bad()
                entry=entries.get(slot['entry_sha256'])
                if entry is None:missing.add('transcript')
                elif not request['observed_at_ns']<=entry['sampled_at_ns']<=reply['observed_at_ns']:_bad()
                if part['bootstrap_sha256']!=runtime._hash(bootstrap)or part['bootstrap_bytes']!=len(runtime._json(bootstrap)):_bad()
                result['bootstrap']=bootstrap;state[key]='entry'
            elif operation=='OBSERVE_READY':
                ready=readies.get(part['readiness_sha256'])
                if ready is None:missing.add('transcript');continue
                if ready['worker_ready']['worker_id']!=slot['worker_id']or ready['role']!=slot['role']:_bad()
                limit=2000000000 if slot['role']=='parser' else 10000000000
                if ready['parent_observation']['sampled_at_ns']>min(slot['bootstrap']['deadline_ns'],started[key]+limit):_bad()
                entry=entries.get(slot['entry_sha256'])
                if entry is not None and not entry['sampled_at_ns']<=ready['parent_observation']['sampled_at_ns']<=reply['observed_at_ns']:_bad()
                result['readiness']=ready;state[key]='ready'
            elif operation=='NATIVE_BEGIN':
                release=releases[did];start=part['started_at_ns'];stop=part['native_deadline_ns']
                maximum=5000000000 if op['prepared']['envelope']['slot']=='http_identify' else 1000000000
                if not request['observed_at_ns']<=start<=reply['observed_at_ns']or not start<stop<=min(release['effect_stop_ns'],start+maximum):_bad()
                if dispatches[did]['native_budget']is not None:_bad()
                result.update(started_at_ns=start,native_deadline_ns=stop)
                dispatches[did]['native_budget']=result;state[key]='active'
            elif operation=='OBSERVE_NATIVE':
                native=natives.get(part['native_readiness_sha256']);ready=ready_workers.get(slot['worker_id'])
                if native is None or ready is None:missing.add('transcript');continue
                if native['parent_observation']['payload']!=ready['parent_observation']['payload']:_bad()
                budget=dispatches[did]['native_budget']
                if budget is None or not budget['started_at_ns']<=native['observed_at_ns']<=budget['native_deadline_ns']:_bad()
                result['native_readiness']=native;state[key]='native'
            elif operation=='CAPTURE':
                capture=dispatches[did]['capture'];host=op['host_capture']
                if capture is None:missing.add('transcript');continue
                if(part['host_capture_sha256']!=runtime._hash(host)or part['capture_sha256']!=runtime._hash(capture)
                        or part['status']!=host['status']or part['cleanup_sha256']!=host['cleanup_sha256']):_bad()
                receipt=None if host['cleanup_sha256']is None else cleanups.get(host['cleanup_sha256'])
                result.update(capture=capture,status=host['status'],cleanup=receipt);state[key]='reaped'
                _slot_cleanup(receipt,slot,ready_workers,entries)
                if receipt is None or receipt['status']!='complete':missing.add('cleanup')
                elif receipt['finished_at_ns']>reply['observed_at_ns']:_bad()
            elif operation=='REAP':
                receipt=cleanups.get(part['cleanup_sha256'])
                if receipt is None:missing.add('transcript');continue
                _slot_cleanup(receipt,slot,ready_workers,entries)
                if receipt['finished_at_ns']>reply['observed_at_ns']:_bad()
                if receipt['status']!='complete':missing.add('cleanup')
                result['cleanup']=receipt;state[key]='reaped'
        _supervision_frame(reply,channel,{'request_sequence':request['sequence'],
            'status':projection['status'],'code':projection['code'],'data':result})
    for slot in slots.values():
        key=(slot['launcher_id'],slot['child_slot'])
        if(slot['bootstrap']is not None or slot['entry_sha256']is not None)and key not in state:missing.add('transcript')
    for op in operations:
        if op['result']is not None and op['result']['outcome']=='useful':
            did=op['prepared']['envelope']['dispatch_id'];prefix='identify_' if op['prepared']['envelope']['slot']=='http_identify' else 'headers_'
            selected=[s for s in slots.values()if s['prepared_sha256']==c.prepared_digest(op['prepared'])]
            if{s['child_slot']for s in selected}!={prefix+x for x in('client','admission','parser')}:missing.add('transcript')
            if any(state.get((s['launcher_id'],s['child_slot']))!='reaped' for s in selected):missing.add('transcript')
            if dispatches[did]['native_budget']is None or dispatches[did]['capture']is None:missing.add('transcript')
    return{'missing_evidence':sorted(missing),'dispatches':dispatches,
        'child_slots':processes['child_slots'],'supervisors':cleanup['supervisors'],
        'all_closed':closure['all_closed'],'cleanup_complete':closure['complete']}
def _supervision_frame(observed,channel,body):
    frame={'schema_version':'1','channel_id':channel,'sequence':observed['sequence'],
        'operation':observed['operation'],'body':body}
    raw=runtime._json(frame)
    if len(raw)>32768 or observed['bytes']!=len(raw)or observed['sha256']!=hashlib.sha256(raw).hexdigest():_bad()
    if observed['projection_sha256']!=runtime._hash(observed['projection']):_bad()
def _slot_cleanup(receipt,slot,ready_workers,entries):
    if receipt is None:return
    if len(receipt['processes'])!=1 or len(runtime._json(receipt))>2048:_bad()
    ready=ready_workers.get(slot['worker_id'])
    parent=ready['parent_observation']if ready is not None else entries.get(slot['entry_sha256'])
    if parent is None:return
    process=receipt['processes'][0]
    if(process['role']!=slot['role']or process['pid']!=parent['payload']['pid']
            or process['start_time_ticks']!=parent['payload']['start_time_ticks']
            or process['wrapper_pid']!=parent['wrapper']['pid']):_bad()
def _retained_role_observations(rows):
    """Bind historical workers by broker slot, never by a reusable namespace ID."""
    from.engagement_live_witness import validate_transcript_row
    found={}
    for wrapper in rows:
        row=wrapper['row']
        if wrapper['source']!='broker_memfd' or row['kind']!='protocol':continue
        data=row['data'];frame=data['frame']
        if data['channel_role']!='lifecycle' or frame['operation']!='ROLE_OBSERVED':continue
        row=validate_transcript_row(row);body=row['data']['frame']['body']
        if data['direction']!='received' or row['observer_id']!=row['broker_id']:_bad()
        if body['role']not in('endpoint','launcher'):continue
        key=(row['broker_id'],body['slot_index'],body['role'])
        if key in found or body['readiness']['role']!=body['role']:_bad()
        found[key]=(body['readiness'],row['observed_at_ns'])
    return found
def _reconstruct_bootstrap(slot,op,ready_workers,bundle,parents,role_observations,started_at_ns):
    launcher=ready_workers.get(slot['launcher_id'])
    if launcher is None:return None
    matches=[(key,value)for key,value in role_observations.items()
        if key[0]==slot['broker_id']and key[2]=='launcher'
        and value[0]['worker_ready']['worker_id']==slot['launcher_id']]
    if not matches or slot['bootstrap']is None or not parents:return None
    if len(matches)!=1:_bad()
    key,observed_launcher=matches[0]
    observed_endpoint=role_observations.get((key[0],key[1],'endpoint'))
    if observed_endpoint is None:return None
    endpoint=observed_endpoint[0]
    for ready,at in(observed_launcher,observed_endpoint):
        retained=ready_workers.get(ready['worker_ready']['worker_id'])
        if retained is None:return None
        if retained!=ready or not ready['parent_observation']['sampled_at_ns']<=at<=started_at_ns:_bad()
    if endpoint['parent_observation']['namespaces']['net']!=launcher['parent_observation']['namespaces']['net']:_bad()
    binding={k:slot[k]for k in('child_slot','role','worker_id','pair')}
    value=runtime.reconstruct_child_bootstrap(runtime=bundle,child_slot=binding,
        prepared=op['prepared'],session=op['session'],endpoint_identity=endpoint,
        observer=parents[0]['observer'],deadline_ns=slot['bootstrap']['deadline_ns'],launcher_id=slot['launcher_id'])
    if runtime._hash(value)!=slot['bootstrap']['sha256']or len(runtime._json(value))!=slot['bootstrap']['bytes']:_bad()
    return value
BOUNDARY_CASES={'S42C-X01':{'variant':'sealed_nmap_executable_changed','role':'nmap','kind':'pin_mutation'},'S42C-X02':{'variant':'sealed_nmap_library_changed','role':'nmap','kind':'pin_mutation'},'S42C-X03':{'variant':'sealed_broker_sqlite_library_changed','role':'broker','kind':'pin_mutation'},'S42C-X04':{'variant':'sealed_graphical_tk_library_changed','role':'graphical','kind':'pin_mutation'},'S42C-X05':{'variant':'sealed_source_broker_changed','role':'broker','kind':'pin_mutation'},'S42C-X06':{'variant':'sealed_source_launcher_changed','role':'launcher','kind':'pin_mutation'},'S42C-X07':{'variant':'sealed_source_endpoint_changed','role':'endpoint','kind':'pin_mutation'},'S42C-X08':{'variant':'sealed_source_client_changed','role':'client','kind':'pin_mutation'},'S42C-X09':{'variant':'sealed_source_parser_changed','role':'parser','kind':'pin_mutation'},'S42C-X10':{'variant':'sealed_source_terminal_changed','role':'terminal','kind':'pin_mutation'},'S42C-X11':{'variant':'sealed_source_graphical_changed','role':'graphical','kind':'pin_mutation'},'S42C-X12':{'variant':'role_manifest_client_to_parser','role':'client_to_parser','kind':'pin_mutation'},'S42C-X13':{'variant':'role_manifest_endpoint_to_broker','role':'endpoint_to_broker','kind':'pin_mutation'},'S42C-X14':{'variant':'unexpected_descriptor_broker','role':'broker','kind':'descriptor_custody'},'S42C-X15':{'variant':'unexpected_descriptor_launcher','role':'launcher','kind':'descriptor_custody'},'S42C-X16':{'variant':'unexpected_descriptor_endpoint','role':'endpoint','kind':'descriptor_custody'},'S42C-X17':{'variant':'unexpected_descriptor_client','role':'client','kind':'descriptor_custody'},'S42C-X18':{'variant':'unexpected_descriptor_parser','role':'parser','kind':'descriptor_custody'},'S42C-X19':{'variant':'unexpected_descriptor_terminal','role':'terminal','kind':'descriptor_custody'},'S42C-X20':{'variant':'unexpected_descriptor_graphical','role':'graphical','kind':'descriptor_custody'},'S42C-X21':{'variant':'missing_descriptor_broker','role':'broker','kind':'descriptor_custody'},'S42C-X22':{'variant':'missing_descriptor_endpoint','role':'endpoint','kind':'descriptor_custody'},'S42C-X23':{'variant':'missing_descriptor_launcher','role':'launcher','kind':'descriptor_custody'},'S42C-X24':{'variant':'missing_descriptor_terminal','role':'terminal','kind':'descriptor_custody'},'S42C-X25':{'variant':'missing_descriptor_graphical','role':'graphical','kind':'descriptor_custody'},'S42C-X26':{'variant':'forbidden_destination_wrong_target','role':'client','kind':'socket_denial'},'S42C-X27':{'variant':'forbidden_destination_wrong_port','role':'client','kind':'socket_denial'},'S42C-X28':{'variant':'forbidden_destination_ssh_endpoint','role':'client','kind':'socket_denial'},'S42C-X29':{'variant':'endpoint_denies_connect','role':'endpoint','kind':'socket_denial'},'S42C-X30':{'variant':'endpoint_denies_fastopen_sendto','role':'endpoint','kind':'socket_denial'},'S42C-X31':{'variant':'endpoint_denies_fastopen_sendmsg','role':'endpoint','kind':'socket_denial'},'S42C-X32':{'variant':'endpoint_denies_fastopen_sendmmsg','role':'endpoint','kind':'socket_denial'},'S42C-X33':{'variant':'creation_denied_client','role':'client','kind':'creation_denial'},'S42C-X34':{'variant':'creation_denied_parser','role':'parser','kind':'creation_denial'},'S42C-X35':{'variant':'creation_denied_endpoint','role':'endpoint','kind':'creation_denial'},'S42C-X36':{'variant':'creation_denied_broker','role':'broker','kind':'creation_denial'},'S42C-X37':{'variant':'creation_denied_terminal','role':'terminal','kind':'creation_denial'},'S42C-X38':{'variant':'creation_denied_graphical','role':'graphical','kind':'creation_denial'},'S42C-X39':{'variant':'parser_network_filesystem_authority_absent','role':'parser','kind':'parser_absence'},'S42C-X40':{'variant':'parent_observed_identity_nmap_mismatch','role':'nmap','kind':'image_identity'},'S42C-X41':{'variant':'parent_observed_identity_waiting_python_mismatch','role':'waiting_python','kind':'image_identity'},'S42C-X42':{'variant':'parent_observed_identity_parser_mismatch','role':'parser','kind':'image_identity'},'S42C-X43':{'variant':'parent_observed_identity_endpoint_mismatch','role':'endpoint','kind':'image_identity'},'S42C-X44':{'variant':'native_image_observation_missing_no_ARM','role':'nmap','kind':'image_identity'},'S42C-X45':{'variant':'meter_connection_cap_identify','role':'endpoint','kind':'meter_boundary'},'S42C-X46':{'variant':'meter_connection_cap_headers','role':'endpoint','kind':'meter_boundary'},'S42C-X47':{'variant':'meter_request_cap_identify','role':'endpoint','kind':'meter_boundary'},'S42C-X48':{'variant':'meter_request_cap_headers','role':'endpoint','kind':'meter_boundary'},'S42C-X49':{'variant':'meter_response_cap_identify','role':'endpoint','kind':'meter_boundary'},'S42C-X50':{'variant':'meter_response_cap_headers','role':'endpoint','kind':'meter_boundary'},'S42C-X51':{'variant':'meter_partial_request','role':'endpoint','kind':'meter_boundary'},'S42C-X52':{'variant':'meter_partial_response','role':'endpoint','kind':'meter_boundary'},'S42C-X53':{'variant':'role_EOF_broker','role':'broker','kind':'lifecycle'},'S42C-X54':{'variant':'role_EOF_endpoint','role':'endpoint','kind':'lifecycle'},'S42C-X55':{'variant':'role_EOF_launcher','role':'launcher','kind':'lifecycle'},'S42C-X56':{'variant':'endpoint_clock_forward_before_recv','role':'endpoint','kind':'clock_boundary'},'S42C-X57':{'variant':'endpoint_clock_forward_before_send','role':'endpoint','kind':'clock_boundary'},'S42C-X58':{'variant':'endpoint_deadline_before_send_after_partial','role':'endpoint','kind':'clock_boundary'},'S42C-X59':{'variant':'actual_payload_and_wrapper_reaped','role':'all','kind':'lifecycle'}}
def _bad():
    runtime._fail('evidence_invalid')
def _bytes(encoded,maximum):
    if type(encoded)is not str or len(encoded)>((maximum+2)//3)*4:_bad()
    try:raw=base64.b64decode(encoded,validate=True)
    except(ValueError,TypeError):_bad()
    if len(raw)>maximum or base64.b64encode(raw).decode('ascii')!=encoded:_bad()
    return raw
@_bounded
def validate_boundary_observation(kind,value):
    """Closed raw facts, independent of a caller's desired case outcome."""
    definitions=runtime.SPEC['role_boundary_proofs']['kinds']
    if kind not in definitions:_bad()
    spec=definitions[kind];runtime._fields(value,spec['fields'])
    booleans={'refused','ready_emitted','arm_emitted','arm_emitted','paired_control_connected','authority_fds_absent','delivery_known'}
    null_hashes={'observed_image_sha256','native_observation_sha256','meter_transcript_sha256','last_ack_sha256','control_observation_sha256'}
    signed={'return_value','network_return','filesystem_return','process_return'}
    for key,field in value.items():
        if key in booleans:
            if type(field)is not bool:_bad()
        elif key.endswith('_sha256'):
            if field is not None or key not in null_hashes:runtime._digest(field)
        elif key in signed:runtime._integer(field,-1,2**31-1)
        elif key in('tasks_before','tasks_after'):
            if type(field)is not list or not 1<=len(field)<=2 or field!=sorted(set(field)):_bad()
            for task in field:runtime._integer(task,1,2**31-1)
        elif key=='changed_descriptor':
            runtime._fields(field,runtime.SPEC['closed_objects']['descriptor']['fields'])
            runtime._integer(field['fd'],0,255)
            if field['kind']not in runtime.SPEC['closed_objects']['descriptor']['kind']or type(field['purpose'])is not str or not 1<=len(field['purpose'])<=64:_bad()
            for n in('device','inode','mode','flags'):runtime._integer(field[n],0,2**64-1)
        elif key in('operation','metric','stimulus','origin'):
            if field not in spec[key]:_bad()
        elif key=='rejected_stage':
            if field not in spec['stage']:_bad()
        elif key=='slot':
            if field not in('http_identify','http_headers'):_bad()
        elif key=='destination':
            if type(field)is not str or not field.startswith('/')or len(field)>512 or '\x00' in field:_bad()
        elif key=='phase':
            if field not in('entry','initial_bootstrap','bootstrap','prepared','sealed','ready','cleanup'):_bad()
        elif key=='target':
            import ipaddress
            try:address=ipaddress.IPv4Address(field)
            except(ValueError,TypeError):_bad()
            if str(address)!=field or not address.is_private or address.is_unspecified or address.is_multicast:_bad()
        else:runtime._integer(field,0,2**63-1)
    if kind=='socket_denial':
        if value['family']!=2 or value['socket_type']!=1 or value['protocol']not in(0,6)or not 1<=value['port']<=65535 or value['errno']>4095:_bad()
    if kind=='creation_denial' and value['errno']>4095:_bad()
    if kind=='parser_absence' and any(value[k]>4095 for k in('network_errno','filesystem_errno','process_errno')):_bad()
    if kind=='clock_boundary' and value['triggered_at_ns']<1:_bad()
    if kind=='lifecycle' and value['cleanup_finished_at_ns']<value['triggered_at_ns']:_bad()
    return json.loads(runtime._json(value))
def _boundary_checks(loaded,bundle,readies,natives,cleanups,meters):
    # Linux ABI: EPERM=1 EACCES=13 EROFS=30 ENETUNREACH=101 ETIMEDOUT=110 EHOSTUNREACH=113.
    observations={}
    for row in loaded['processes.json']['boundary_observations']:
        runtime._fields(row,('kind','observation'))
        actual=validate_boundary_observation(row['kind'],row['observation'])
        digest=runtime._hash(actual)
        if digest in observations:_bad()
        observations[digest]=(row['kind'],actual)
    sources={row['sha256']for row in bundle['sources']}|{runtime._hash(role['sources'])for role in bundle['roles']}|{row['sha256']for row in bundle['compiled']}
    controls={**readies,**natives,**{key:row[1]for key,row in observations.items()}}
    proofs=loaded['results.json']['boundary_proofs']
    for proof in proofs:
        runtime._fields(proof,runtime.SPEC['role_boundary_proofs']['common_fields'])
        case=BOUNDARY_CASES.get(proof['case_id'])
        if case is None or proof['schema_version']!='1' or proof['role']!=case['role']or proof['kind']!=case['kind']or proof['runtime_sha256']!=runtime.runtime_digest(bundle)or proof['source_sha256']not in sources:_bad()
        runtime._integer(proof['started_at_ns'],1);runtime._integer(proof['finished_at_ns'],proof['started_at_ns'])
        if proof['finished_at_ns']-proof['started_at_ns']>122000000000:_bad()
        runtime._digest(proof['observation_sha256'])
        item=observations.get(proof['observation_sha256'])
        if item is None or item[0]!=case['kind']:_bad()
        control=controls.get(proof['control_observation_sha256'])
        if control is None or proof['control_observation_sha256']==proof['observation_sha256']:_bad()
        runtime._fields(proof['checks'],(case['variant'],))
        if type(proof['checks'][case['variant']])is not bool:_bad()
        v=case['variant'];kind,raw=item
        cleanup_complete=bool(cleanups)and all(x['status']=='complete' for x in cleanups.values())
        # Successful paired controls retain actual parent/readiness observations;
        # raw self-reported booleans alone never establish a passing boundary.
        observed_control=proof['control_observation_sha256']in readies or proof['control_observation_sha256']in natives
        no_effect=all(m['received_request_bytes']in(0,None)and m['sent_response_bytes']in(0,None)for m in meters.values())
        passed=False
        if kind=='pin_mutation':
            passed=observed_control and raw['before_sha256']!=raw['after_sha256']and raw['expected_seals']==15 and not raw['ready_emitted']and not raw['arm_emitted']and no_effect
            if v.startswith('sealed_source_'):passed&=raw['rejected_stage']in('source_snapshot','worker_entry','parent_image')
            elif v.startswith('role_manifest_'):passed&=raw['rejected_stage']in('role_manifest','worker_entry')
            else:passed&=raw['rejected_stage']in('native_snapshot','worker_entry','parent_image')
        elif kind=='descriptor_custody':
            passed=observed_control and raw['expected_inventory_sha256']!=raw['actual_inventory_sha256']and raw['refused']and no_effect
        elif kind=='socket_denial':
            expected_op=v.rsplit('_',1)[-1]if v.startswith('endpoint_denies_')else 'connect'
            passed=observed_control and raw['operation']==expected_op and raw['return_value']==-1 and raw['paired_control_connected']and raw['listener_accepts']==0 and raw['listener_payload_bytes']==0
            if v.startswith('endpoint_denies_'):passed&=raw['errno']==1
            else:passed&=raw['errno']in(1,13,101,113,110)
            if 'fastopen' in v:passed&=bool(raw['flags']&0x20000000)
        elif kind=='creation_denial':
            rows=[item for kind,item in observations.values()if kind=='creation_denial']
            passed=observed_control and len(rows)==3 and{item['operation']for item in rows}=={'fork','unshare','execve'}and all(item['return_value']==-1 and item['errno']==1 and item['tasks_before']==item['tasks_after']==raw['tasks_before']for item in rows)
        elif kind=='parser_absence':
            passed=observed_control and raw['authority_fds_absent']and all(raw[k]==-1 for k in('network_return','filesystem_return','process_return'))and raw['network_errno']==raw['process_errno']==1 and raw['filesystem_errno']in(1,13,30)
        elif kind=='image_identity':
            passed=observed_control and raw['refused']and not raw['arm_emitted']and raw['waiting_observation_sha256']in readies and no_effect
            if v=='native_image_observation_missing_no_ARM':passed&=raw['native_observation_sha256']is None
            else:passed&=raw['observed_image_sha256']is None or raw['expected_image_sha256']!=raw['observed_image_sha256']
        elif kind=='meter_boundary':
            meter=meters.get(raw['meter_transcript_sha256'])
            if meter is not None:
                cap=(3 if raw['slot']=='http_identify' else 1)if raw['metric']=='connections' else(4096 if raw['slot']=='http_identify' else 256)if raw['metric']in('request','partial_request')else(4096 if raw['slot']=='http_identify' else 2048)
                key='accepted_connections' if raw['metric']=='connections' else 'received_request_bytes' if raw['metric']in('request','partial_request')else 'sent_response_bytes'
                passed=observed_control and meter['slot']==raw['slot']and raw['delivery_known']==meter['delivery_known']and raw['input_sha256']==meter['request_sha256']and raw['output_sha256']==meter['response_sha256']
                if raw['metric'].startswith('partial_'):passed&=meter[key]is not None and 0<meter[key]<cap and len([event for event in meter['events']if event['kind']==('recv' if key=='received_request_bytes' else 'send')and event['actual_bytes']>0])>=2
                else:passed&=raw['refused']and raw['stimulus_bytes']>=cap+1 and meter[key]==cap and meter['reason']=={'connections':'connection_limit','request':'request_limit','response':'response_limit'}[raw['metric']]
        elif kind=='clock_boundary':
            meter=meters.get(raw['meter_transcript_sha256'])
            if meter is not None:
                passed=observed_control and raw['clock_source_sha256']in sources and raw['refused']and raw['accepted_after']==raw['accepted_before']and raw['sent_after']==raw['sent_before']and not any(event['monotonic_ns']>=raw['triggered_at_ns']and event['kind']in('accept','recv','send')and(event['actual_bytes']>0 or event['kind']=='accept')for event in meter['events'])
                if v.endswith('after_partial'):passed&=raw['sent_before']>0
        elif kind=='lifecycle':
            cleanup=cleanups.get(raw['cleanup_sha256'])
            passed=observed_control and cleanup is not None and cleanup['status']=='complete' and raw['cleanup_finished_at_ns']==cleanup['finished_at_ns']and cleanup['finished_at_ns']-raw['triggered_at_ns']<=2000000000
            if raw['meter_transcript_sha256']is not None:passed&=raw['meter_transcript_sha256']in meters
        # Every successful native boundary includes real bounded cleanup, including
        # both paired control and the affected process tree.
        passed=bool(passed and cleanup_complete)
        if proof['checks'][v]!=passed:_bad()
    return observations
def validate_meter(value):
    # One pure grammar is shared with the key-free endpoint role; the context
    # adds authority and raw-stream crosslinks rather than a divergent codec.
    return runtime.validate_meter(value)
def meter_summary(value):
    value=validate_meter(value)
    fields=runtime.SPEC['output_and_evidence']['meter_summary_exact_fields']
    return{key:runtime._hash(value)if key=='transcript_sha256' else value[key]for key in fields}
def validate_client_result(value):
    s=runtime.SPEC['output_and_evidence'];runtime._fields(value,s['result_exact_fields'])
    if value['schema_version']!='1' or value['slot']not in('http_identify','http_headers')or value['status']not in s['result_status_enum']:_bad()
    if type(value['dispatch_id'])is not str or runtime._UUID.fullmatch(value['dispatch_id'])is None:_bad()
    for key in('envelope_sha256','runtime_sha256','stdout_sha256','stderr_sha256'):runtime._digest(value[key])
    cap=8192 if value['slot']=='http_identify' else 2048
    for key in('stdout_bytes','stderr_bytes'):runtime._integer(value[key],0,cap)
    if value['stdout_bytes']+value['stderr_bytes']>cap or type(value['truncated'])is not bool:_bad()
    if value['exit_code']is not None:runtime._integer(value['exit_code'],-255,255)
    if value['stop_reason']is not None and value['stop_reason']not in s['reason_enum']:_bad()
    if value['readiness']is not None:
        runtime._fields(value['readiness'],('client_sha256','native_sha256'))
        runtime._digest(value['readiness']['client_sha256'])
        if value['readiness']['native_sha256']is not None:runtime._digest(value['readiness']['native_sha256'])
    if value['meter']is not None:
        runtime._fields(value['meter'],s['meter_summary_exact_fields'])
        runtime._digest(value['meter']['transcript_sha256'])
        if value['meter']['dispatch_id']!=value['dispatch_id']or value['meter']['envelope_sha256']!=value['envelope_sha256']or value['meter']['slot']!=value['slot']:_bad()
    if value['cleanup']is not None:runtime.validate_cleanup(value['cleanup'])
    receipt=value['parser_receipt']
    if(value['parsed']is None)!=(receipt is None):_bad()
    if receipt is not None:
        if value['readiness']is None or value['cleanup']is None:_bad()
        runtime._fields(receipt,s['parser_receipt_exact_fields'])
        if receipt['schema_version']!='1' or receipt['slot']!=value['slot']:_bad()
        for key in('input_sha256','output_sha256','readiness'):runtime._digest(receipt[key])
        runtime._integer(receipt['input_bytes'],1,16384);runtime._integer(receipt['output_bytes'],1,4096);runtime._integer(receipt['elapsed_ms'],0,2000)
        runtime.validate_cleanup(receipt['cleanup'])
        if receipt['cleanup']['status']!='complete':_bad()
    if value['status']=='succeeded':
        if value['exit_code']!=0 or value['truncated']or value['stop_reason']is not None or value['parsed']is None or receipt is None or value['cleanup']is None or value['cleanup']['status']!='complete' or value['readiness']is None:_bad()
        if value['slot']=='http_identify' and value['readiness']['native_sha256']is None:_bad()
        if value['meter']is None or value['meter']['reason']!='complete' or value['meter']['delivery_known']is not True:_bad()
    return json.loads(runtime._json(value))
@_bounded
def validate_dispatch_observations(*,prepared,release,scope,capture,client_result,meter,
                                   child_readiness,child_cleanup,native_readiness,runtime_bundle):
    """Before durable completion, validate only this action's actual children.

    Persistent reviewer/endpoint/broker cleanup belongs to final bundle review.
    This function does not launch a parser or treat a result hash as authority.
    """
    from.import engagement_live_contract as contract
    from.import configurable_contract,configurable_parser
    from.configurable_scope import validate_scope,scope_digest
    prepared=contract.validate_prepared(prepared);release=contract.validate_release(release)
    scope=validate_scope(scope);client=validate_client_result(client_result);meter=validate_meter(meter)
    bundle=runtime.validate_runtime(runtime_bundle);env=prepared['envelope'];slot=env['slot']
    if scope_digest(scope)!=env['scope_sha256']or configurable_contract.action(scope,1 if slot=='http_identify' else 2)!=prepared['action']:_bad()
    if release['dispatch_id']!=env['dispatch_id']or release['envelope_sha256']!=contract.envelope_digest(env)or release['prepared_sha256']!=contract.prepared_digest(prepared):_bad()
    if client['dispatch_id']!=env['dispatch_id']or client['slot']!=slot or client['envelope_sha256']!=release['envelope_sha256']or client['runtime_sha256']!=runtime._hash(bundle)or client['runtime_sha256']!=env['runtime_sha256']:_bad()
    if meter['dispatch_id']!=env['dispatch_id']or meter['session_id']!=env['session_id']or meter['slot']!=slot or meter['envelope_sha256']!=release['envelope_sha256']or meter['go_sha256']!=runtime._hash(release)or client['meter']!=meter_summary(meter):_bad()
    runtime._fields(capture,('schema_version','slot','exit_code','truncated','stdout_base64','stderr_base64','stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256'))
    if capture['schema_version']!='1' or capture['slot']!=slot or capture['exit_code']!=client['exit_code']or capture['truncated']!=client['truncated']:_bad()
    raw={}
    cap=8192 if slot=='http_identify' else 2048
    for name in('stdout','stderr'):
        raw[name]=_bytes(capture[name+'_base64'],cap)
        if type(capture[name+'_bytes'])is not int or len(raw[name])!=capture[name+'_bytes']or capture[name+'_bytes']!=client[name+'_bytes']or hashlib.sha256(raw[name]).hexdigest()!=capture[name+'_sha256']or capture[name+'_sha256']!=client[name+'_sha256']:_bad()
    if sum(map(len,raw.values()))>cap:_bad()
    if type(child_readiness)is not list or len(child_readiness)>3 or type(child_cleanup)is not list or len(child_cleanup)>3:_bad()
    known={};identities=set();reaped=set()
    for ready in child_readiness:
        if ready['role']not in('nmap','headers','admission','parser'):_bad()
        runtime.validate_readiness(ready['role'],ready,bundle);known[runtime._hash(ready)]=ready
        p=ready['parent_observation']['payload'];identities.add((p['pid'],p['start_time_ticks']))
    cleanups={}
    for receipt in child_cleanup:
        runtime.validate_cleanup(receipt);cleanups[runtime._hash(receipt)]=receipt
        for p in receipt['processes']:
            if p['reaped_observed']and p['wrapper_returncode']is not None:reaped.add((p['pid'],p['start_time_ticks']))
    if client['cleanup']is not None and runtime._hash(client['cleanup'])not in cleanups:_bad()
    if client['readiness']is not None and client['readiness']['client_sha256']not in known:_bad()
    if type(native_readiness)is not list or len(native_readiness)>1:_bad()
    native_hashes=set()
    for native in native_readiness:
        runtime.validate_protocol_value('native_readiness',native)
        manifest=next(row for row in bundle['roles']if row['role']=='nmap')
        expected=next(row for row in manifest['native_files']if row['destination']=='/tool/nmap')
        parent=native['parent_observation'];image=parent['executable']
        if slot!='http_identify' or image['sha256']!=expected['sha256']or image['size']!=expected['size']or not set(manifest['required_mapped_images'])<={row['destination']for row in parent['mapped_images']}:_bad()
        waiting=[row for row in known.values()if row['role']=='nmap' and row['parent_observation']['payload']==parent['payload']]
        if len(waiting)!=1 or native['waiting_image']!=waiting[0]['parent_observation']['executable']or parent['namespaces']!=waiting[0]['parent_observation']['namespaces']:_bad()
        native_hashes.add(runtime._hash(native))
    if client['readiness']is not None:
        actual=known[client['readiness']['client_sha256']]
        if actual['role']!=('nmap' if slot=='http_identify' else 'headers'):_bad()
        h=client['readiness']['native_sha256']
        if h is not None and h not in native_hashes or slot=='http_headers' and native_hashes:_bad()
    parsed=client['parsed'];receipt=client['parser_receipt']
    if receipt is not None:
        if receipt['readiness']not in known or known[receipt['readiness']]['role']!='parser' or runtime._hash(receipt['cleanup'])not in cleanups:_bad()
        request={'schema_version':'1','slot':slot,'scope':scope,'raw_base64':capture['stdout_base64'],'stderr_base64':capture['stderr_base64'],'truncated':capture['truncated']}
        encoded=runtime._json(request);reply=runtime._json({'schema_version':'1','slot':slot,'parsed':parsed})
        if receipt['input_bytes']!=len(encoded)or receipt['input_sha256']!=hashlib.sha256(encoded).hexdigest()or receipt['output_bytes']!=len(reply)or receipt['output_sha256']!=hashlib.sha256(reply).hexdigest():_bad()
        if configurable_parser.validate_result(prepared['action']['tool_id'],parsed,scope,'http')!=parsed:_bad()
    if client['status']=='succeeded':
        if identities-reaped or any(item['status']!='complete' for item in cleanups.values())or raw['stderr']:_bad()
        request=_bytes(meter['request_base64'],4096);response=_bytes(meter['response_base64'],4096)
        if slot=='http_identify':
            if request!=b'GET / HTTP/1.0\r\n\r\n' or response!=b'HTTP/1.0 200 OK\r\nServer: nginx/1.26.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' or meter['accepted_connections']not in(2,3):_bad()
            if parsed.get('identification')!='identified' or parsed.get('state')!='open' or parsed.get('service')!={'name':'http','product':'nginx','version':'1.26.0'}:_bad()
        else:
            expected=('GET / HTTP/1.1\r\nHost: '+scope['http']['target']+':'+str(scope['http']['port'])+'\r\nConnection: close\r\n\r\n').encode('ascii')
            if request!=expected or response!=raw['stdout']or meter['accepted_connections']!=1:_bad()
    return client
def _saved_execution(loaded,*,rows=None):
    """Resolve actual broker channel observations, including partial failures."""
    from.engagement_live_witness import validate_transcript_row
    raw=loaded.get('transcript.jsonl',b'')
    if type(raw)is not bytes or len(raw)>2097152:_bad()
    if rows is None:rows=_retained_rows(loaded)
    else:
        rows=[dict(wrapper,row=validate_transcript_row(wrapper['row']))
                if wrapper['source']=='broker_memfd' else wrapper for wrapper in rows]
    return _saved_execution_validated(rows)
def _saved_execution_validated(rows):
    """Resolve locally validated rows without repeating their closed decoders."""
    releases={};observations={}
    for wrapper in rows:
        if wrapper['source']!='broker_memfd':continue
        row=wrapper['row']
        if row['observer_id']!=row['broker_id']:_bad()
        if row['kind']!='protocol':continue
        data=row['data'];frame=data['frame'];role=data['channel_role'];direction=data['direction']
        operation=frame['operation'];body=frame['body'];dispatch=row['dispatch_id']
        if role=='launcher' and direction=='sent' and operation=='GO':
            if body['dispatch_id']!=dispatch or dispatch in releases:_bad()
            releases[dispatch]=body
        elif operation=='METER' and role in('endpoint','launcher'):
            if body['dispatch_id']!=dispatch or body['session_id']!=row['session_id']:_bad()
            key='meter' if role=='endpoint' else 'forwarded_meter'
            if direction!=('received' if role=='endpoint' else 'sent'):_bad()
            found=observations.setdefault(dispatch,{})
            if key in found:_bad()
            found[key]=body
        elif operation=='OBSERVATION' and role=='launcher' and direction=='received':
            if body['dispatch_id']!=dispatch:_bad()
            found=observations.setdefault(dispatch,{})
            kind=body['kind']
            if kind=='capture':
                if kind in found:_bad()
                found[kind]=body['data']
            elif kind in('role_readiness','cleanup'):
                found.setdefault(kind,[]).append(body['data'])
    return releases,observations
def _resolve_cleanup(receipt,ready,retained):
    if runtime._hash(receipt)not in retained:_bad()
    if ready is not None:
        payload=ready['parent_observation']['payload']
        if not any(row['pid']==payload['pid']and row['start_time_ticks']==payload['start_time_ticks']
                   for row in receipt['processes']):_bad()
def _result_observation(result,client,meter,retained_cleanup):
    """A result may omit unknown observations; every present claim must resolve."""
    if result is None:return
    if result['client_result_sha256']is not None:
        if client is None or result['client_result_sha256']!=runtime._hash(client):_bad()
    if result['cleanup_sha256']is not None:
        if client is None or client['cleanup']is None:_bad()
        digest=runtime._hash(client['cleanup'])
        if result['cleanup_sha256']!=digest or digest not in retained_cleanup:_bad()
    observed=result['observation']
    if observed is None:return
    if client is None or meter is None or not meter['delivery_known']:_bad()
    expected={'connections':meter['accepted_connections'],
        'request_bytes':meter['received_request_bytes'],'response_bytes':meter['sent_response_bytes'],
        'client_output_bytes':client['stdout_bytes']+client['stderr_bytes'],
        'parsed_sha256':None if client['parsed']is None else runtime._hash(client['parsed']),
        'meter_sha256':runtime._hash(meter)}
    if any(expected[k]is None for k in('connections','request_bytes','response_bytes'))or observed!=expected:_bad()
def _validate_exports(cleanup,loaded,closed_at,identities,closed):
    from.import engagement_dispatch_contract as ledger
    helpers=_validate_recovery_helpers(loaded)
    manifest=loaded['manifest.json']
    instances=manifest.get('broker_instances',[])
    brokers={row['broker_id']for row in instances}
    owners={row['ledger_owner_id']for row in instances}
    for helper in helpers:
        closed_at=max(closed_at,helper['finished_at_ns'])
        if helper['work']is not None:
            for key in('rw','ro'):
                stage=helper['work'][key]
                if stage is not None and stage['owner_id']is not None:owners.add(stage['owner_id'])
    if type(cleanup['exports'])is not list or len(cleanup['exports'])>4:_bad()
    seen=set();references={}
    for record in cleanup['exports']:
        runtime._fields(record,('broker_id','reference','host_descriptor','broker_descriptor'))
        if record['broker_id']not in brokers:_bad()
        ref=record['reference'];runtime._fields(ref,('phase','bytes','device','inode','seals','sha256'))
        if ref['phase']not in('initial','final')or type(ref['seals'])is not int or ref['seals']!=15:_bad()
        runtime._integer(ref['bytes'],1,2097152);runtime._integer(ref['device']);runtime._integer(ref['inode'],1);runtime._digest(ref['sha256'])
        key=(record['broker_id'],ref['phase'])
        if key in seen:_bad()
        seen.add(key)
        references[key]=ref
        for name,access in(('host_descriptor',os.O_RDONLY),('broker_descriptor',os.O_RDWR)):
            row=record[name];runtime._fields(row,runtime.SPEC['closed_objects']['descriptor']['fields'])
            runtime._integer(row['fd'],0,255)
            for field in('device','inode','mode','flags'):runtime._integer(row[field],0,2**64-1)
            if row['kind']!='regular' or not stat.S_ISREG(row['mode'])or row['flags']&os.O_ACCMODE!=access or row['device']!=ref['device']or row['inode']!=ref['inode']or row['purpose']!=ref['phase']+'_export_memfd':_bad()
    for phase in('initial','final'):
        entry=manifest.get('ledger_exports',{}).get(phase)
        if entry is None:continue
        if entry['status']=='complete':
            ref=references.get((entry['broker_id'],phase))
            retained=loaded.get(entry['file'])
            if ref is None or type(retained)is not dict:_bad()
            validated=ledger.validate_export(retained);raw=ledger.canonical(validated)
            if ref['bytes']!=len(raw)or ref['sha256']!=hashlib.sha256(raw).hexdigest():_bad()
    recovery=cleanup['recovery']
    if recovery is None:
        if 'recovery-ledger.json' in loaded:_bad()
        return
    if recovery.get('schema_version')=='2':
        _copied_recovery_receipt(recovery,helpers,loaded)
        return
    runtime._fields(recovery,('schema_version','source','owner_id','started_at_ns','finished_at_ns','read_only','store_identity','bytes','sha256','ledger_state_sha256','closed'))
    if recovery['schema_version']!='1' or recovery['source']!='postcleanup_readonly' or recovery['read_only']is not True or recovery['closed']is not True or type(recovery['owner_id'])is not str or runtime._UUID.fullmatch(recovery['owner_id'])is None or recovery['owner_id']in owners:_bad()
    if manifest['ledger_exports']['recovery']['source']!='postcleanup_readonly':_bad()
    for field in('started_at_ns','finished_at_ns'):runtime._integer(recovery[field])
    supervisors=_supervisor_closure(loaded)
    closed_at=max([closed_at]+[row['cleanup_finished_at_ns']for row in cleanup['supervisors']])
    if(not supervisors['all_closed']or identities-closed
            or not closed_at<=recovery['started_at_ns']<=recovery['finished_at_ns']<=recovery['started_at_ns']+2000000000):_bad()
    runtime._fields(recovery['store_identity'],('parent','directory','database'))
    uid=None;gid=None
    for name,row in recovery['store_identity'].items():
        runtime._fields(row,('device','inode','mode','uid','gid'))
        for field in('device','inode'):runtime._integer(row[field],0,2**64-1)
        for field in('mode','uid','gid'):runtime._integer(row[field],0,2**32-1)
        if uid is None:uid,gid=row['uid'],row['gid']
        if row['uid']!=uid or row['gid']!=gid:_bad()
        if name=='database':
            if not stat.S_ISREG(row['mode'])or stat.S_IMODE(row['mode'])!=0o600:_bad()
        elif not stat.S_ISDIR(row['mode'])or stat.S_IMODE(row['mode'])!=0o700:_bad()
    runtime._integer(recovery['bytes'],1,2097152)
    runtime._digest(recovery['sha256']);runtime._digest(recovery['ledger_state_sha256'])
    retained=loaded.get('recovery-ledger.json')
    if type(retained)is not dict:_bad()
    validated=ledger.validate_export(retained);raw=ledger.canonical(validated)
    if len(raw)!=recovery['bytes']or hashlib.sha256(raw).hexdigest()!=recovery['sha256']or hashlib.sha256(ledger.STATE_DOMAIN+ledger.canonical(validated['state'])).hexdigest()!=recovery['ledger_state_sha256']:_bad()
@_bounded
def _fixture_descriptor_selection(loaded):
    """Validate the complete fixed fixture selection within one nested budget."""
    selected=None
    manifest=loaded['manifest.json'];rule=runtime.SPEC['owned_meter_connection_fixture']
    case_id=manifest.get('case_id');case=rule['cases'].get(case_id)
    if case is not None:
        if manifest.get('evidence_class')!='owned_gate':_bad()
        wrapper=loaded['runtime.json'];bundle=runtime.validate_runtime(wrapper['runtime'])
        digest=runtime._hash(bundle)
        if manifest['runtime_sha256']!=digest:_bad()
        config={'case_id':case_id,'variant':case['variant'],'role':'endpoint'}
        sources={row['module']:row for row in bundle['sources']}
        role=next(row for row in bundle['roles']if row['role']=='endpoint')
        role_sources={row['module']:row for row in role['sources']}
        for name in('engagement_live_endpoint_worker','engagement_live_runtime'):
            source=sources.get(name)
            if source is None or role_sources.get(name)!=source:_bad()
            matches=[item for item in wrapper['instrumentation']if item['source_sha256']==source['sha256']]
            if len(matches)!=1 or matches[0]['kind']!='sealed_fault' or matches[0]['configuration']!=config or matches[0]['configuration_sha256']!=runtime._hash(config):_bad()
        readies=[item for item in loaded['processes.json']['readiness']if item['role']=='endpoint']
        if len(readies)!=1:_bad()
        ready=readies[0];parent=ready['parent_observation'];descriptors=parent['descriptors']
        count=case['steady_descriptors']
        if type(descriptors)is not list or len(descriptors)!=count or[r.get('fd')for r in descriptors]!=list(range(count)):_bad()
        purposes=[rule['steady_descriptor_purposes'][str(fd)]for fd in range(count)]
        if[r.get('purpose')for r in descriptors]!=purposes:_bad()
        if any(row.get('kind')!='stream_socket' or not stat.S_ISSOCK(row.get('mode',0))or row.get('flags',0)&os.O_ACCMODE!=os.O_RDWR for row in descriptors[5:]):_bad()
        if len({(row['device'],row['inode'])for row in descriptors[5:]})!=count-5:_bad()
        if ready['worker_ready']['descriptor_sha256']!=runtime._hash(descriptors):_bad()
        proofs=loaded['results.json']['boundary_proofs']
        if len(proofs)!=1:_bad()
        proof=proofs[0]
        if proof['case_id']!=case_id or proof['role']!='endpoint' or proof['kind']!='meter_boundary' or proof['runtime_sha256']!=digest or proof['source_sha256']!=sources['engagement_live_endpoint_worker']['sha256']or proof['control_observation_sha256']!=runtime._hash(ready):_bad()
        payload=parent['payload'];selected={'payload':(payload['pid'],payload['start_time_ticks']),'descriptors':json.loads(runtime._json(descriptors)),'case_id':case_id,'runtime_sha256':digest,'runtime_source':json.loads(runtime._json(sources['engagement_live_runtime']))}
    return selected
@contextmanager
def _retained_fixture_validation(loaded,*,deadline=None):
    """A06 saved-data allowance; never changes live setup/entry limits."""
    from.engagement_live_contract import _deadline_context
    end=runtime.time.monotonic()+2
    if deadline is not None:end=min(end,deadline)
    with _deadline_context(end):selected=_fixture_descriptor_selection(loaded)
    # Mask an outer fixture when validating an ordinary or different bundle.
    token=runtime._RETAINED_FIXTURE_DESCRIPTORS.set(selected)
    try:yield
    finally:runtime._RETAINED_FIXTURE_DESCRIPTORS.reset(token)
@_bounded
def _audit_process_closure(loaded,*,observations=None):
    """Join actual transcript audit observations to retained process cleanup.

    Audit uses the accepted worker, so it has no invented new-role readiness
    record in processes.json. Missing cleanup remains missing; contradictory
    identity, chronology or duplicate facts are invalid evidence.
    """
    from.import engagement_live_contract as contract
    if observations is None:
        from.engagement_live_witness import _retained_audit_readiness
        observations=_retained_audit_readiness(loaded,
            deadline=contract._operation_deadline())['observations']
    known={};parents=[];missing=False
    process_rows=loaded.get('processes.json',{})
    ordinary=list(process_rows.get('startup',[]))+[
        row['parent_observation']for row in process_rows.get('readiness',[])+process_rows.get('native',[])]
    for parent in ordinary:
        p=parent['payload'];key=(p['pid'],p['start_time_ticks'])
        fact=(parent.get('role'),parent.get('wrapper',{}).get('pid'))
        if key in known and known[key]!=fact:_bad()
        known[key]=fact
    audit={}
    for row in observations:
        parent=row['readiness']['parent_observation'];p=parent['payload']
        key=(p['pid'],p['start_time_ticks'])
        if key in known and known[key]!=('audit',parent['wrapper']['pid']):_bad()
        known[key]=('audit',parent['wrapper']['pid'])
        if key in audit:
            if audit[key]!=row:_bad()
            continue
        audit[key]=row;parents.append(parent)
        if parent['sampled_at_ns']>row['observed_at_ns']:_bad()
    all_ids=set(known)
    for receipt in loaded['cleanup.json']['receipts']:
        runtime.validate_cleanup(receipt)
        all_ids.update((p['pid'],p['start_time_ticks'])for p in receipt['processes']
            if p['pid']is not None and p['start_time_ticks']is not None)
    if len(all_ids)>94:_bad()
    for key,observed in audit.items():
        parent=observed['readiness']['parent_observation'];matches=[]
        for receipt in loaded['cleanup.json']['receipts']:
            runtime.validate_cleanup(receipt)
            for process in receipt['processes']:
                current=(process['pid'],process['start_time_ticks'])
                if current!=key:
                    # A changed start/PID cannot hide behind a matching wrapper.
                    if(process['wrapper_pid']==parent['wrapper']['pid']
                            and(process['role']=='audit' or process['pid']==key[0])):_bad()
                    continue
                if process['role']!='audit' or process['wrapper_pid']!=parent['wrapper']['pid']:_bad()
                if receipt['finished_at_ns']<parent['sampled_at_ns']:_bad()
                matches.append(process)
                if(not receipt['descriptors_closed']or not process['pin_verified']
                        or not process['exit_observed']or not process['reaped_observed']
                        or process['wrapper_returncode']is None):missing=True
        if not matches:missing=True
        elif any(process!=matches[0]for process in matches[1:]):_bad()
    return{'parents':parents,'missing_cleanup':missing}
@_bounded
def validate_live_context(value):
    """Validate loaded member objects; inspectors own file custody and replay."""
    from.import engagement_live_contract as contract
    if type(value)is not dict or not{'runtime.json','processes.json','results.json','cleanup.json','manifest.json'}<=set(value):_bad()
    wrapper=value['runtime.json'];runtime._fields(wrapper,('schema_version','runtime','instrumentation'))
    bundle=runtime.validate_runtime(wrapper['runtime']);digest=runtime._hash(bundle)
    if wrapper['schema_version']!='1' or value['manifest.json']['runtime_sha256']!=digest:_bad()
    instrumentation=wrapper['instrumentation']
    if type(instrumentation)is not list or len(instrumentation)>16:_bad()
    sealed_sources={row['sha256']for row in bundle['sources']}|{row['sha256']for row in bundle['compiled']}
    for item in instrumentation:
        runtime._fields(item,('kind','configuration','configuration_sha256','source_sha256'))
        runtime._digest(item['source_sha256']);runtime._digest(item['configuration_sha256'])
        runtime._fields(item['configuration'],('case_id','variant','role'))
        if runtime._hash(item['configuration'])!=item['configuration_sha256']:_bad()
        if item['kind']in('sealed_fault','sealed_clock')and item['source_sha256']not in sealed_sources:_bad()
    processes=value['processes.json'];runtime._fields(processes,('schema_version','startup','readiness','native','boundary_observations','child_slots'))
    results=value['results.json'];runtime._fields(results,('schema_version','operations','boundary_proofs','core_proofs'))
    cleanup=value['cleanup.json']
    cleanup_fields=('schema_version','receipts','exports','recovery','supervisors')
    if cleanup.get('schema_version')=='2':cleanup_fields+=('recovery_helpers',)
    elif cleanup.get('schema_version')!='1':_bad()
    runtime._fields(cleanup,cleanup_fields)
    for obj in(processes,results):
        if obj['schema_version']!='1':_bad()
    for obj,key,maximum in((processes,'startup',94),(processes,'readiness',94),(processes,'native',4),(processes,'child_slots',24),(processes,'boundary_observations',59),(cleanup,'receipts',94),(cleanup,'supervisors',4),(results,'boundary_proofs',1),(results,'core_proofs',1)):
        if type(obj[key])is not list or len(obj[key])>maximum:_bad()
    readies={};identities=set();startup_identities=set();startup_hashes=set()
    for parent in processes['startup']:
        runtime.validate_parent_observation(parent)
        if parent['stage']!='entry':_bad()
        h=runtime._hash(parent)
        if h in startup_hashes:_bad()
        startup_hashes.add(h)
        p=parent['payload'];startup_identities.add((p['pid'],p['start_time_ticks']))
        manifest=next(row for row in bundle['roles']if row['role']==parent['role'])
        expected=next(row for row in manifest['native_files']if row['destination']=='/usr/bin/python3')
        if parent['executable']['destination']!='/usr/bin/python3' or parent['executable']['sha256']!=expected['sha256']or parent['executable']['size']!=expected['size']:_bad()
    identities.update(startup_identities)
    for ready in processes['readiness']:
        runtime.validate_readiness(ready['role'],ready,bundle)
        h=runtime._hash(ready)
        if h in readies:_bad()
        readies[h]=ready
        p=ready['parent_observation']['payload'];identities.add((p['pid'],p['start_time_ticks']))
    natives={}
    for native in processes['native']:
        runtime.validate_protocol_value('native_readiness',native)
        role_manifest=next(x for x in bundle['roles']if x['role']=='nmap')
        expected=next(x for x in role_manifest['native_files']if x['destination']=='/tool/nmap')
        observed=native['parent_observation']['executable']
        if observed['sha256']!=expected['sha256']or observed['size']!=expected['size']:_bad()
        if not set(role_manifest['required_mapped_images'])<={row['destination']for row in native['parent_observation']['mapped_images']}:_bad()
        natives[runtime._hash(native)]=native
        p=native['parent_observation']['payload']
        if(p['pid'],p['start_time_ticks'])not in identities:_bad()
        waiting=[ready for ready in readies.values()if ready['role']=='nmap' and ready['parent_observation']['payload']==p]
        if len(waiting)!=1 or native['waiting_image']!=waiting[0]['parent_observation']['executable']or native['parent_observation']['namespaces']!=waiting[0]['parent_observation']['namespaces']:_bad()
    # The accepted audit role is retained in actual AUDIT_OBSERVED packets,
    # not a fabricated compound readiness row. Its identity shares this cap.
    # Each call decodes and validates its own immutable transcript bytes once.
    # Reuse those detached rows only within this invocation; no caller-supplied
    # validation flag or cross-call cache can bypass the original checks.
    rows=_retained_rows(value)
    from.engagement_live_witness import _retained_audit_readiness
    audit=_retained_audit_readiness(value,rows=rows,
        deadline=contract._operation_deadline())
    _audit_process_closure(value,observations=audit['observations'])
    if len(identities)>94:_bad()
    closed=set();closed_at=0
    for item in cleanup['receipts']:
        runtime.validate_cleanup(item)
        closed_at=max(closed_at,item['finished_at_ns'])
        for p in item['processes']:
            if p['pid']is not None and p['reaped_observed']and p['wrapper_returncode']is not None:closed.add((p['pid'],p['start_time_ticks']))
    _validate_exports(cleanup,value,closed_at,identities,closed)
    if startup_identities-closed:_bad()
    # A genuinely empty diagnostic is representable. Missing cleanup for actual
    # known roles is incomplete, never synthesized as a successful receipt.
    if identities-closed and any(op.get('result',{}).get('outcome')=='useful' for op in results['operations']if op.get('result')is not None):_bad()
    if type(results['operations'])is not list or len(results['operations'])>4:_bad()
    seen=set();meters={};releases,recorded=_saved_execution_validated(rows)
    retained_cleanup={runtime._hash(item):item for item in cleanup['receipts']}
    for op in results['operations']:
        runtime._fields(op,('session','prepared','result','client','meter','elapsed_ms','host_capture'))
        opened=contract.validate_session_opened(op['session']);prepared=contract.validate_prepared_context(op['prepared'],opened)
        envelope=prepared['envelope'];dispatch=envelope['dispatch_id']
        if dispatch in seen or envelope['runtime_sha256']!=digest:_bad()
        seen.add(dispatch)
        result=op['result']
        if result is not None:
            contract.validate_live_result(result)
            if any(result[key]!=envelope[key]for key in('broker_id','session_id','dispatch_id','slot'))or result['envelope_sha256']!=contract.envelope_digest(envelope):_bad()
        meter=op['meter'];client=op['client']
        if meter is not None:
            validate_meter(meter)
            if any(meter[key]!=envelope[key]for key in('session_id','dispatch_id','slot'))or meter['envelope_sha256']!=contract.envelope_digest(envelope):_bad()
            meters[runtime._hash(meter)]=meter
        if client is not None:
            validate_client_result(client)
            if client['dispatch_id']!=dispatch or client['slot']!=envelope['slot']or client['envelope_sha256']!=contract.envelope_digest(envelope)or client['runtime_sha256']!=digest:_bad()
            for stream in('stdout','stderr'):
                raw=value.get('client-'+dispatch+'.'+stream+'.bin')
                if type(raw)is not bytes or len(raw)!=client[stream+'_bytes']or hashlib.sha256(raw).hexdigest()!=client[stream+'_sha256']:_bad()
            if meter is not None and client['meter']!=meter_summary(meter):_bad()
            ready=client['readiness']
            if ready is not None and(ready['client_sha256']not in readies or ready['native_sha256']is not None and ready['native_sha256']not in natives):_bad()
            if client['cleanup']is not None:_resolve_cleanup(client['cleanup'],None if ready is None else readies[ready['client_sha256']],retained_cleanup)
            if client['parser_receipt']is not None:
                receipt=client['parser_receipt']
                if receipt['readiness']not in readies:_bad()
                _resolve_cleanup(receipt['cleanup'],readies[receipt['readiness']],retained_cleanup)
        actual=recorded.get(dispatch,{})
        for key in('meter','forwarded_meter'):
            if key in actual and actual[key]!=meter:_bad()
        if 'forwarded_meter' in actual and actual.get('meter')!=actual['forwarded_meter']:_bad()
        for ready in actual.get('role_readiness',[]):
            if runtime._hash(ready)not in readies:_bad()
        for receipt in actual.get('cleanup',[]):
            if runtime._hash(receipt)not in retained_cleanup:_bad()
        capture=actual.get('capture')
        if capture is not None:
            if capture['slot']!=envelope['slot']:_bad()
            for stream in('stdout','stderr'):
                retained=value.get('client-'+dispatch+'.'+stream+'.bin')
                if type(retained)is not bytes or retained!=_bytes(capture[stream+'_base64'],8192):_bad()
            if client is not None and(capture['exit_code']!=client['exit_code']or capture['truncated']!=client['truncated']):_bad()
        _result_observation(result,client,meter,retained_cleanup)
        if result is not None and result['outcome']=='useful':
            if client is None or client['status']!='succeeded' or meter is None or not meter['delivery_known']or meter['reason']!='complete' or capture is None or actual.get('meter')!=meter or actual.get('forwarded_meter')!=meter:_bad()
        if client is not None and(client['parsed']is not None or client['status']=='succeeded'):
            release=releases.get(dispatch)
            if release is None or meter is None:_bad()
            capture={'schema_version':'1','slot':envelope['slot'],'exit_code':client['exit_code'],'truncated':client['truncated']}
            for stream in('stdout','stderr'):
                capture[stream+'_base64']=base64.b64encode(value['client-'+dispatch+'.'+stream+'.bin']).decode('ascii')
                capture[stream+'_bytes']=client[stream+'_bytes'];capture[stream+'_sha256']=client[stream+'_sha256']
            hashes={client['readiness']['client_sha256']}
            if client['parser_receipt']is not None:hashes.add(client['parser_receipt']['readiness'])
            children=[readies[h]for h in hashes if h in readies]
            child_cleanups=[client['cleanup']]
            if client['parser_receipt']is not None and client['parser_receipt']['cleanup']not in child_cleanups:child_cleanups.append(client['parser_receipt']['cleanup'])
            selected_native=[]if client['readiness']['native_sha256']is None else[natives[client['readiness']['native_sha256']]]
            validate_dispatch_observations(prepared=prepared,release=release,scope=opened['scope'],capture=capture,
                client_result=client,meter=meter,child_readiness=children,child_cleanup=child_cleanups,
                native_readiness=selected_native,runtime_bundle=bundle)
    if set(recorded)-seen:_bad()
    validate_supervision_transcript(value,rows=rows,deadline=contract._operation_deadline())
    _boundary_checks(value,bundle,readies,natives,retained_cleanup,meters)
    return json.loads(runtime._json(results))
@_validation('evidence_invalid')
def _recovery_shape(value,name):
    """Validate the pinned closed shape without opening any retained resource."""
    from.import engagement_live_contract as c
    import re
    def visit(item,rule,depth=0):
        c._check_deadline(c._operation_deadline())
        if depth>64:_bad()
        if type(rule)is str:
            if rule.startswith('evidence_contract.copied_recovery.schemas.'):
                return visit(item,_RECOVERY_SCHEMAS[rule.rsplit('.',1)[1]],depth+1)
            if rule=='lowercase SHA256':return c.digest_string(item)
            if rule=='canonical UUID4':return c.uuid(item)
            if rule=='exact unchanged canonical v2 ledger export':
                from.engagement_dispatch_contract import validate_export
                return validate_export(item)
            if rule=='runtime_contract.runtime_manifest_schema exact bundle':
                return runtime.validate_runtime(item)
            kind=rule.removeprefix('runtime_contract.closed_objects.')
            if kind=='observer':return _observer(item)
            if kind=='descriptor':
                runtime._fields(item,runtime.SPEC['closed_objects'][kind]['fields'])
                c.integer(item['fd'],0,255)
                c.member(item['kind'],runtime.SPEC['closed_objects'][kind]['kind'])
                if type(item['purpose'])is not str or not 1<=len(item['purpose'])<=64:_bad()
                for field in('device','inode','mode','flags'):c.integer(item[field],0,2**64-1)
                return
            if kind=='file_identity':
                runtime._fields(item,runtime.SPEC['closed_objects'][kind]['fields'])
                if type(item['destination'])is not str or not item['destination'].startswith('/')or len(item['destination'])>4096:_bad()
                for field in('device','inode','mode'):c.integer(item[field],0,2**64-1)
                c.integer(item['size'],1,16777216);c.digest_string(item['sha256'])
                if not stat.S_ISREG(item['mode']):_bad()
                return
            _bad()
        if 'one_of' in rule:
            matches=0
            for choice in rule['one_of']:
                try:visit(item,choice,depth+1)
                except c.LiveError as error:
                    if error.code.endswith(('_timeout','_limit_exceeded')):raise
                else:matches+=1
            if matches!=1:_bad()
            return
        if 'const' in rule:
            if type(item)is not type(rule['const'])or item!=rule['const']:_bad()
            return
        if 'enum' in rule:
            if not any(type(item)is type(v)and item==v for v in rule['enum']):_bad()
            return
        kind=rule['type']
        if kind=='null':
            if item is not None:_bad()
        elif kind=='boolean':
            if type(item)is not bool:_bad()
        elif kind=='integer':
            c.integer(item,rule['minimum'],rule['maximum'])
        elif kind=='object':
            c.obj(item,rule['fields'])
            for key,subrule in rule['fields'].items():visit(item[key],subrule,depth+1)
        elif kind=='array':
            if type(item)is not list or not rule['minimum_items']<=len(item)<=rule['maximum_items']:_bad()
            for child in item:visit(child,rule['items'],depth+1)
        elif kind=='string':
            if type(item)is not str or not rule.get('minimum_length',0)<=len(item)<=rule['maximum_length']:_bad()
            if 'pattern' in rule and re.fullmatch(rule['pattern'],item)is None:_bad()
            if rule.get('encoding')=='lowercase even-length hexadecimal' and(len(item)%2 or re.fullmatch('[0-9a-f]*',item)is None):_bad()
            if rule.get('encoding')=='canonical padded base64':
                if base64.b64encode(base64.b64decode(item,validate=True)).decode('ascii')!=item:_bad()
        else:_bad()
    visit(value,_RECOVERY_SCHEMAS[name])
    return value
def _recovery_identity(row):
    return tuple(row[k]for k in('device','inode'))
def _recovery_private(row,*,directory,observer):
    if(row['uid']!=observer['uid']or row['gid']!=observer['gid']
            or stat.S_IMODE(row['mode'])!=(0o700 if directory else 0o600)
            or not(stat.S_ISDIR(row['mode'])if directory else stat.S_ISREG(row['mode']))):_bad()
def _recovery_store(row,observer,*,preflight=True):
    """Check saved held/named custody and format, never re-open its paths."""
    _recovery_shape(row,'store_observation')
    for field in('parent','directory'):_recovery_private(row[field],directory=True,observer=observer)
    files={entry['name']:entry for entry in row['files']}
    if(len(files)!=len(row['files'])or 'records.sqlite3' not in files
            or set(files)-{'records.sqlite3','records.sqlite3-journal'}):_bad()
    for name,entry in files.items():
        held=entry['held']
        _recovery_private(held,directory=False,observer=observer)
        if(held!=entry['named']or held['nlink']!=1
                or entry['fd_flags']&(os.O_ACCMODE|0o10000000)):_bad()
        if len(entry['header_hex'])!=2*min(28,held['size'])or len(entry['trailer_hex'])!=2*min(16,held['size']):_bad()
        if name=='records.sqlite3':
            header=bytes.fromhex(entry['header_hex'])
            if not 1<=held['size']<=8388608:_bad()
            if preflight and(not 4096<=held['size']<=8388608 or held['size']%4096
                    or len(header)!=28 or header[:20]!=b'SQLite format 3\x00\x10\x00\x01\x01'):_bad()
        elif preflight and entry['trailer_hex'].endswith('d9d505f920a163d7'):_bad()
    if len({_recovery_identity(entry['held'])for entry in files.values()})!=len(files):_bad()
    return files
def _recovery_order(*times):
    if any(type(t)is not int for t in times)or any(a>b for a,b in zip(times,times[1:])):_bad()
@_bounded
def _recovery_canonical(value,maximum):
    """A10's export-plus-provenance frame has its own finite byte ceiling."""
    from.import engagement_live_contract as c
    c.integer(maximum,1,2129920)
    c._tree(value,maximum)
    try:
        raw=json.dumps(value,sort_keys=True,separators=(',',':'),
                         ensure_ascii=True,allow_nan=False).encode('ascii')
    except(UnicodeError,ValueError,TypeError,RecursionError):
        _bad()
    if len(raw)>maximum:
        c.fail('limit_exceeded')
    c._check_deadline(c._operation_deadline())
    return raw
@_bounded
def _recovery_result_bytes(result):
    """Keep the nested export and null-export metadata allowances separate."""
    from.import engagement_live_contract as c
    c.canonical(result['export'],max_bytes=2097152)
    c.canonical({**result,'export':None},max_bytes=32768)
    return _recovery_canonical(result,2129920)
def _recovery_frame(frame,payload,maximum):
    _recovery_shape(frame,'framed_observation')
    if frame['received_bytes']>maximum+8 or frame['payload_bytes']>maximum:_bad()
    header=bytes.fromhex(frame['header_hex'])
    if len(header)>8 or frame['received_bytes']!=len(header)+frame['payload_bytes']:_bad()
    if len(header)==8:
        if frame['declared_bytes']!=int.from_bytes(header,'big')or not 1<=frame['declared_bytes']<=maximum:_bad()
        if frame['payload_bytes']>frame['declared_bytes']:_bad()
    elif frame['declared_bytes']is not None or frame['payload_bytes']:_bad()
    if frame['started_at_ns']is None:
        if frame['received_bytes']or frame['finished_at_ns']is not None:_bad()
    elif frame['finished_at_ns']is not None:_recovery_order(frame['started_at_ns'],frame['finished_at_ns'])
    if frame['received_bytes']:
        if frame['frame_sha256']is None or frame['payload_sha256']is None:_bad()
        if frame['payload_bytes']==0:
            if frame['frame_sha256']!=hashlib.sha256(header).hexdigest()or frame['payload_sha256']!=hashlib.sha256(b'').hexdigest():_bad()
    if frame['complete']:
        from.import engagement_live_contract as c
        raw=_recovery_canonical(payload,maximum)
        if(frame['finished_at_ns']is None or header!=len(raw).to_bytes(8,'big')
                or frame['payload_bytes']!=len(raw)or frame['payload_sha256']!=c.digest(raw)
                or frame['frame_sha256']!=c.digest(header+raw)):_bad()
    elif payload is not None:_bad()
def _recovery_prefix(stage,loaded,cache):
    """Reconstruct this handle's own event prefix from validated retained data."""
    from.import engagement_dispatch_contract as ledger
    from.import engagement_live_contract as c
    key=(stage['snapshot_event_sequence'],stage['snapshot_sha256'])
    if key in cache:value=cache[key]
    else:
        candidates=[];eligible=False
        for name in('final-ledger.json','recovery-ledger.json'):
            retained=loaded.get(name)
            if retained is None or len(retained['events'])<stage['snapshot_event_sequence']:continue
            eligible=True
            validated=ledger.validate_export(retained)
            engine=ledger._Engine()
            for event in validated['events'][:stage['snapshot_event_sequence']]:
                engine.push(ledger.validate_request(event['request']))
            value=engine.export
            if c.digest(ledger.canonical(value))==stage['snapshot_sha256']:candidates.append(value)
        if not candidates:
            if eligible:_bad()
            c.fail('evidence_incomplete')
        value=candidates[0]
        if any(other!=value for other in candidates[1:]):_bad()
        cache[key]=value
    raw=ledger.canonical(value)
    if(len(raw)!=stage['snapshot_bytes']or c.digest(raw)!=stage['snapshot_sha256']
            or value['events'][-1]['sequence']!=stage['snapshot_event_sequence']
            or value['events'][-1]['receipt']['state_sha256']!=stage['ledger_state_sha256']):_bad()
    return value
def _recovery_copy_proof(helper,before_sql_at):
    """The same completed raw-copy proof precedes every attempted SQLite open."""
    work=helper['work'];copy=work['copy'];observer=helper['parent_observer']
    if copy is None or work['source_descriptors_closed']is not True or work['copy_descriptors_closed']is not True:_bad()
    source=_recovery_store(copy['source_before'],observer)
    after=_recovery_store(copy['source_after'],observer)
    copied=_recovery_store(copy['copied'],observer)
    main='records.sqlite3';journal=main+'-journal'
    if journal not in source or source!=after or set(source)!=set(copied):_bad()
    for field in('parent','directory'):
        if copy['source_before'][field]!=copy['source_after'][field]:_bad()
        if any(row[field]!=helper['scratch'][field]for row in(copy['copied'],)):_bad()
    source_ids={_recovery_identity(row['held'])for row in source.values()}
    if any(_recovery_identity(row['held'])in source_ids for row in copied.values()):_bad()
    if{_recovery_identity(copy['source_before'][k])for k in('parent','directory')}&{_recovery_identity(helper['scratch'][k])for k in('parent','directory')}:_bad()
    for name in source:
        for field in('sha256','header_hex','trailer_hex'):
            if source[name][field]!=copied[name][field]:_bad()
        if source[name]['held']['size']!=copied[name]['held']['size']:_bad()
    lock=copy['locks']
    if(lock['main_device'],lock['main_inode'])!=_recovery_identity(source[main]['held']):_bad()
    for name,offset,length in(('pending',1073741824,1),('shared',1073741826,510)):
        row=lock[name]
        if(row is None or row['command']!='F_OFD_SETLK' or row['lock_type']!='F_RDLCK'
                or row['offset']!=offset or row['length']!=length or row['status']!='acquired' or row['errno']is not None):_bad()
        _recovery_order(copy['started_at_ns'],row['started_at_ns'],row['finished_at_ns'])
    for name in('reserved_before','reserved_after'):
        row=lock[name]
        if(row is None or row['command']!='F_OFD_GETLK' or row['query_type']!='F_WRLCK'
                or row['offset']!=1073741825 or row['length']!=1 or row['input_owner_pid']!=0
                or row['result_type']!='F_UNLCK' or row['owner_pid']!=0 or row['errno']is not None):_bad()
        _recovery_order(row['started_at_ns'],row['finished_at_ns'])
    _recovery_order(lock['pending']['finished_at_ns'],lock['shared']['started_at_ns'],
        lock['shared']['finished_at_ns'],lock['reserved_before']['started_at_ns'],
        lock['reserved_before']['finished_at_ns'],copy['source_before']['observed_at_ns'],
        copy['copied']['observed_at_ns'],copy['source_after']['observed_at_ns'],
        lock['released_at_ns'],copy['raw_source_fds_closed_at_ns'],copy['finished_at_ns'])
    _recovery_order(copy['copied']['observed_at_ns'],lock['reserved_after']['started_at_ns'],
        lock['reserved_after']['finished_at_ns'],lock['released_at_ns'])
    _recovery_order(copy['copied']['observed_at_ns'],copy['raw_copy_fds_closed_at_ns'],copy['finished_at_ns'])
    narrow=work['sqlite_file_size_limit']
    if narrow is None:_bad()
    if narrow['soft']!=8388608 or narrow['hard']!=8388608:_bad()
    _recovery_order(helper['process']['release_sent_at_ns'],work['started_at_ns'],
        work['source_package_closed_at_ns'],copy['started_at_ns'],copy['finished_at_ns'],
        narrow['observed_at_ns'],before_sql_at)
    return source,copied
def _recovery_journal_proof(helper):
    """Validate the completed RW/journal boundary before any RO attempt."""
    from.import engagement_live_contract as c
    work=helper['work'];rw=work['rw'];disposition=work['journal_disposition'];observer=helper['parent_observer']
    if rw is None or not rw['closed']or disposition is None or work['post_rw_copy']is None:_bad()
    copied=_recovery_store(work['copy']['copied'],observer)
    post_rw=_recovery_store(work['post_rw_copy'],observer)
    main='records.sqlite3';journal=main+'-journal'
    for field in('parent','directory'):
        if work['post_rw_copy'][field]!=helper['scratch'][field]:_bad()
    _recovery_order(rw['closed_at_ns'],work['post_rw_copy']['observed_at_ns'],disposition['observed_at_ns'])
    if disposition['main_before']!=post_rw[main]or disposition['main_after']is None:_bad()
    if _recovery_identity(copied[main]['held'])!=_recovery_identity(post_rw[main]['held']):_bad()
    if disposition['status']=='absent_after_rw':
        if(set(post_rw)!={main}or any(disposition[k]is not None for k in
                ('journal','header','unlink_started_at_ns','unlink_finished_at_ns'))):_bad()
        _recovery_order(disposition['observed_at_ns'],disposition['absence_observed_at_ns'])
    elif disposition['status']in('removed_empty_copy','removed_inactive_copy'):
        if(journal not in post_rw or disposition['journal']!=post_rw[journal]
                or copied[journal]!=post_rw[journal]or copied[main]!=post_rw[main]
                or disposition['main_before']!=disposition['main_after']):_bad()
        _recovery_order(disposition['observed_at_ns'],disposition['unlink_started_at_ns'],
            disposition['unlink_finished_at_ns'],disposition['absence_observed_at_ns'])
        info=post_rw[journal];header=disposition['header']
        if disposition['status']=='removed_empty_copy':
            if info['held']['size']!=0 or header is not None:_bad()
        else:
            if header is None:_bad()
            raw=bytes.fromhex(header['header_hex']);sector=header['sector_bytes'];pages=header['original_pages']
            if(len(raw)!=28 or raw[:12]!=b'\0'*12 or raw.hex()!=info['header_hex']
                    or not 512<=sector<=65536 or sector&(sector-1)or header['page_bytes']!=4096
                    or pages!=post_rw[main]['held']['size']//4096 or not 1<=pages<=2048
                    or raw[12:28]!=b''.join(v.to_bytes(4,'big')for v in(header['nonce'],pages,sector,4096))
                    or header['padding_bytes']!=sector-28 or header['padding_sha256']!=c.digest(b'\0'*(sector-28))
                    or header['record_count']!=len(header['records'])
                    or info['held']['size']!=sector+4104*len(header['records'])):_bad()
            page_ids=set()
            for index,row in enumerate(header['records']):
                if(row['index']!=index or not 1<=row['page_number']<=pages or row['page_number']in page_ids
                        or row['before_image_sha256']!=row['main_page_sha256']
                        or row['checksum']!=row['computed_checksum']):_bad()
                page_ids.add(row['page_number'])
    else:_bad()
    # SQLite RO is observational: source identities and copy content remain fixed.
    if disposition['main_before']!=disposition['main_after']:_bad()
def _recovery_work(helper,loaded,owners,cache):
    """Join copy/lock/handle facts; no digest stands in for an earlier export."""
    from.import engagement_live_contract as c
    work=helper['work'];observer=helper['parent_observer']
    if work is None:_bad()
    _recovery_shape(work,'work_provenance')
    for field in('helper_id','broker_id','deadline_ns','work_deadline_ns'):
        if work[field]!=helper[field]:_bad()
    for field in('runtime_sha256','source_package_sha256'):
        if work[field]!=helper['config'][field]:_bad()
    copy=work['copy'];rw=work['rw'];ro=work['ro'];disposition=work['journal_disposition']
    if any(value is None for value in(copy,rw,ro,disposition,work['post_rw_copy'],work['post_ro_copy'],work['sqlite_file_size_limit'])):_bad()
    if work['source_descriptors_closed']is not True or work['copy_descriptors_closed']is not True:_bad()
    source,copied=_recovery_copy_proof(helper,rw['opened_at_ns'])
    post_rw=_recovery_store(work['post_rw_copy'],observer)
    post_ro=_recovery_store(work['post_ro_copy'],observer)
    main='records.sqlite3'
    for row in(work['post_rw_copy'],work['post_ro_copy']):
        for field in('parent','directory'):
            if row[field]!=helper['scratch'][field]:_bad()
    snapshots=[]
    for stage,mode in((rw,'read_write'),(ro,'read_only')):
        if(stage['mode']!=mode or stage['closed']is not True or stage['owner_id']is None
                or stage['owner_id']in owners or any(stage[k]is None for k in
                ('snapshot_event_sequence','snapshot_bytes','snapshot_sha256','ledger_state_sha256'))):_bad()
        owners.add(stage['owner_id'])
        _recovery_order(stage['opened_at_ns'],stage['snapshot_at_ns'],stage['closed_at_ns'])
        if not 0<=stage['progress_callbacks_before']<=stage['progress_callbacks_after']<4000:_bad()
        snapshots.append(_recovery_prefix(stage,loaded,cache))
    if(rw['progress_callbacks_before']!=0 or ro['progress_callbacks_before']!=rw['progress_callbacks_after']
            or work['progress_callbacks']!=ro['progress_callbacks_after']or snapshots[0]!=snapshots[1]):_bad()
    _recovery_journal_proof(helper)
    if disposition['main_after']!=post_ro[main]or set(post_ro)!={main}:_bad()
    _recovery_order(disposition['absence_observed_at_ns'],ro['opened_at_ns'],ro['closed_at_ns'],
        work['post_ro_copy']['observed_at_ns'],work['finished_at_ns'],helper['work_deadline_ns'])
    return snapshots[-1]
_RECOVERY_FD_PURPOSES=(
    'bounded config then release input pipe','READY/result framed stdout pipe',
    'bounded diagnostic stderr pipe','sealed O_RDONLY source package',
    'held source parent directory','held source store directory',
    'registered scratch parent directory','registered scratch store directory')
def _recovery_runtime(helper,bundle):
    from.import engagement_live_contract as c
    observed=helper['runtime'];ready=helper['ready'];config=helper['config'];process=helper['process']
    if observed is None or ready is None or helper['scratch']is None:_bad()
    runtime_sha=runtime._hash(bundle);source_sha=runtime._hash(bundle['sources'])
    if(observed['runtime_sha256']!=runtime_sha or config['runtime_sha256']!=runtime_sha
            or observed['source_manifest_sha256']!=source_sha or config['source_manifest_sha256']!=source_sha
            or ready['runtime_sha256']!=runtime_sha or ready['source_manifest_sha256']!=source_sha
            or ready['source_package_sha256']!=config['source_package_sha256']):_bad()
    broker=next(row for row in bundle['roles']if row['role']=='broker')
    native={row['destination']:row for row in broker['native_files']+broker['extension_files']}
    def pinned(row,expected):
        if(row['destination']!=expected['destination']or row['size']!=expected['size']
                or row['sha256']!=expected['sha256']):_bad()
    pinned(observed['interpreter'],bundle['python'])
    for field in('device','inode','mode'):
        if observed['stdlib'][field]!=bundle['stdlib'][field]:_bad()
    if not stat.S_ISDIR(observed['stdlib']['mode']):_bad()
    images={row['destination']:row for row in observed['mapped_images']}
    if len(images)!=len(observed['mapped_images']):_bad()
    for name,row in images.items():
        if name not in native:_bad()
        pinned(row,native[name])
    # The loader has two selected aliases for the same immutable source. One
    # actual mapped inode may resolve both aliases; absence of its source may not.
    mapped_sources={native[name]['source']for name in images}
    required_sources={native[name]['source']for name in broker['required_mapped_images']}
    for prefix in('_ctypes.','libffi.so'):
        required=[row for name,row in native.items()if os.path.basename(name).startswith(prefix)]
        if len(required)!=1:_bad()
        required_sources.add(required[0]['source'])
    if not required_sources<=mapped_sources:_bad()
    if images.get(observed['interpreter']['destination'])!=observed['interpreter']:_bad()
    sqlite=[row for name,row in native.items()if os.path.basename(name).startswith('_sqlite3.')]
    library=[row for name,row in native.items()if os.path.basename(name).startswith('libsqlite3.so')]
    if len(sqlite)!=1 or len(library)!=1:_bad()
    pinned(observed['sqlite_extension'],sqlite[0])
    if images.get(sqlite[0]['destination'])!=observed['sqlite_extension']:_bad()
    vfs=ready['default_vfs'];pinned(vfs['library'],library[0])
    if(vfs['library_source']!=library[0]['source']or images.get(library[0]['destination'])!=vfs['library']
            or vfs['library_version']!=sum(n*m for n,m in zip(vfs['sqlite_module_version'],(1000000,1000,1)))
            or observed['default_vfs_sha256']!=c.digest(c.canonical(vfs))):_bad()
    pin_end=process['release_sent_at_ns']if process['release_sent_at_ns']is not None else process['exit_observed_at_ns']
    _recovery_order(process['publication_resolved_at_ns'],vfs['observed_at_ns'],ready['observed_at_ns'],
        helper['transfer']['ready']['finished_at_ns'],observed['observed_at_ns'],pin_end)
    limits=observed['resource_limits']
    _recovery_order(helper['transfer']['ready']['finished_at_ns'],limits['observed_at_ns'],pin_end)
    for name,maximum in(('address_space',268435456),('cpu',2),('nofile',32),('file_size',16777216)):
        if limits[name]!={'soft':maximum,'hard':maximum}:_bad()
    descriptors=observed['descriptors']
    if[row['fd']for row in descriptors]!=list(range(8))or[row['purpose']for row in descriptors]!=list(_RECOVERY_FD_PURPOSES):_bad()
    inherited=config['inherited_fds']
    selected=[inherited[name]for name in('source_package','source_parent','source_store','scratch_parent','scratch_store')]
    if len(set(selected))!=5:_bad()
    pipes=[];transport_fds=[]
    for fd,name in enumerate(('stdin','stdout','stderr')):
        pair=helper['transports'][name];parent=pair['parent'];child=pair['child'];actual=descriptors[fd]
        pipes.append(_recovery_identity(child));transport_fds.extend((parent['fd'],child['fd']))
        if(not stat.S_ISFIFO(child['mode'])or child['kind']!='pipe' or parent['kind']!='pipe'
                or actual['kind']!='pipe' or child['purpose']!=_RECOVERY_FD_PURPOSES[fd]
                or any(actual[k]!=child[k]or parent[k]!=child[k]for k in('device','inode','mode'))
                or child['flags']&os.O_ACCMODE!=(os.O_RDONLY if fd==0 else os.O_WRONLY)
                or actual['flags']&os.O_ACCMODE!=(os.O_RDONLY if fd==0 else os.O_WRONLY)
                or parent['flags']&os.O_ACCMODE!=(os.O_WRONLY if fd==0 else os.O_RDONLY)
                or any(row['flags']&0o10000000 for row in(parent,child,actual))):_bad()
        _recovery_order(helper['started_at_ns'],pair['created_at_ns'],process['publication_registered_at_ns'])
    if len(set(pipes))!=3 or len(set(transport_fds+selected))!=11:_bad()
    package=observed['source_package']
    if(package['descriptor']!=descriptors[3]or package['seals']!=15
            or package['bytes']!=config['source_package_bytes']or package['sha256']!=config['source_package_sha256']
            or package['source_manifest_sha256']!=source_sha or descriptors[3]['kind']!='regular'
            or not stat.S_ISREG(descriptors[3]['mode'])):_bad()
    for row in descriptors[3:]:
        if row['flags']&(os.O_ACCMODE|0o10000000):_bad()# Linux O_PATH.
    for row in descriptors[4:]:
        if row['kind']!='directory' or not stat.S_ISDIR(row['mode'])or stat.S_IMODE(row['mode'])!=0o700:_bad()
    work=helper['work'];source=None if work is None or work['copy']is None else work['copy']['source_before']
    for fd,identity in((6,helper['scratch']['parent']),(7,helper['scratch']['directory'])):
        if descriptors[fd]['kind']!='directory' or any(descriptors[fd][k]!=identity[k]for k in('device','inode','mode')):_bad()
    if source is not None:
        for fd,field in((4,'parent'),(5,'directory')):
            if descriptors[fd]['kind']!='directory' or any(descriptors[fd][k]!=source[field][k]for k in('device','inode','mode')):_bad()
def _recovery_partial_work(helper,loaded,owners,cache):
    """Validate observed failure facts without turning a refusal into success."""
    from.import engagement_live_contract as c
    work=helper['work']
    if work is None:return
    reason=helper['transfer']['result_error']
    if reason is None or helper['transfer']['result_status']!='failed':_bad()
    _recovery_order(helper['process']['release_sent_at_ns'],work['started_at_ns'],work['finished_at_ns'])
    if work['source_package_closed_at_ns']is not None:
        _recovery_order(work['started_at_ns'],work['source_package_closed_at_ns'],work['finished_at_ns'])
    copy=work['copy'];rw=work['rw'];ro=work['ro'];previous=None
    if rw is not None:
        _recovery_copy_proof(helper,rw['opened_at_ns']if rw['opened_at_ns']is not None else work['finished_at_ns'])
    if ro is not None:
        if rw is None or rw['progress_callbacks_after']>=4000:_bad()
        if any(rw[key]is None for key in('owner_id','snapshot_at_ns','snapshot_event_sequence',
                'snapshot_bytes','snapshot_sha256','ledger_state_sha256')):_bad()
        _recovery_journal_proof(helper)
    for key,stage,mode in(('rw',rw,'read_write'),('ro',ro,'read_only')):
        if stage is None:continue
        if stage['mode']!=mode or stage['progress_callbacks_before']>stage['progress_callbacks_after']:_bad()
        if key=='rw' and stage['progress_callbacks_before']!=0:_bad()
        if key=='ro' and(rw is None or not rw['closed']
                or stage['progress_callbacks_before']!=rw['progress_callbacks_after']):_bad()
        if stage['owner_id']is not None:
            if stage['owner_id']in owners or stage['opened_at_ns']is None:_bad()
            owners.add(stage['owner_id'])
        if stage['opened_at_ns']is not None:
            if(stage['owner_id']is None or copy is None or work['sqlite_file_size_limit']is None
                    or not work['source_descriptors_closed']or not work['copy_descriptors_closed']):_bad()
            _recovery_order(work['source_package_closed_at_ns'],copy['finished_at_ns'],
                work['sqlite_file_size_limit']['observed_at_ns'],stage['opened_at_ns'],work['finished_at_ns'])
            if work['sqlite_file_size_limit']['soft']!=8388608 or work['sqlite_file_size_limit']['hard']!=8388608:_bad()
        snapshot_keys=('snapshot_at_ns','snapshot_event_sequence','snapshot_bytes','snapshot_sha256','ledger_state_sha256')
        if any(stage[field]is not None for field in snapshot_keys):
            if any(stage[field]is None for field in snapshot_keys)or stage['opened_at_ns']is None:_bad()
            _recovery_order(stage['opened_at_ns'],stage['snapshot_at_ns'],work['finished_at_ns'])
            _recovery_prefix(stage,loaded,cache)
        if stage['closed']:
            _recovery_order(stage['opened_at_ns'],stage['closed_at_ns'],work['finished_at_ns'])
            if stage['snapshot_at_ns']is not None:_recovery_order(stage['snapshot_at_ns'],stage['closed_at_ns'])
        elif stage['closed_at_ns']is not None:_bad()
        if key=='ro':
            if work['journal_disposition']is None or work['journal_disposition']['status']=='refused':_bad()
            if stage['opened_at_ns']is not None:
                _recovery_order(rw['closed_at_ns'],work['journal_disposition']['absence_observed_at_ns'],stage['opened_at_ns'])
        previous=stage
    if work['progress_callbacks']!=(0 if previous is None else previous['progress_callbacks_after']):_bad()
    if rw is not None and ro is not None and ro['snapshot_sha256']is not None:
        equal=_recovery_prefix(rw,loaded,cache)==_recovery_prefix(ro,loaded,cache)
        if not equal and(reason!='snapshot_mismatch' or work['post_ro_copy']is not None):_bad()
        if equal and reason=='snapshot_mismatch':_bad()
    if work['progress_callbacks']==4000 and reason!='progress_limit':_bad()
    if reason=='progress_limit' and work['progress_callbacks']!=4000:_bad()
    if reason=='work_deadline' and work['finished_at_ns']<work['work_deadline_ns']:_bad()
    if copy is not None:
        _recovery_order(work['started_at_ns'],copy['started_at_ns'])
        if copy['finished_at_ns']is not None:_recovery_order(copy['started_at_ns'],copy['finished_at_ns'],work['finished_at_ns'])
        locks=copy['locks'];failed_lock=False
        for key,offset,length in(('pending',1073741824,1),('shared',1073741826,510)):
            lock=locks[key]
            if lock is None:continue
            if lock['command']!='F_OFD_SETLK' or lock['lock_type']!='F_RDLCK' or lock['offset']!=offset or lock['length']!=length:_bad()
            _recovery_order(copy['started_at_ns'],lock['started_at_ns'],lock['finished_at_ns'],work['finished_at_ns'])
            if lock['status']=='acquired':
                if lock['errno']is not None or failed_lock:_bad()
            else:failed_lock=True
        if failed_lock and(reason!='unsupported_ofd' or copy['source_before']is not None or rw is not None):_bad()
        refused_reserved=False
        for key in('reserved_before','reserved_after'):
            query=locks[key]
            if query is None:continue
            if(query['command']!='F_OFD_GETLK' or query['query_type']!='F_WRLCK' or query['offset']!=1073741825
                    or query['length']!=1 or query['input_owner_pid']!=0):_bad()
            _recovery_order(copy['started_at_ns'],query['started_at_ns'],query['finished_at_ns'],work['finished_at_ns'])
            unlocked=query['result_type']=='F_UNLCK' and query['owner_pid']==0 and query['errno']is None
            if not unlocked:
                refused_reserved=True
                if reason not in('reserved_writer','unsupported_ofd')or rw is not None:_bad()
                if key=='reserved_before' and copy['source_before']is not None:_bad()
        stores=[]
        for key in('source_before','copied','source_after'):
            store=copy[key]
            if store is None:continue
            _recovery_order(copy['started_at_ns'],store['observed_at_ns'],work['finished_at_ns'])
            stores.append(store)
            # A recorded bad header or drift may explain the refusal. A later
            # opened SQLite handle would contradict that preflight outcome.
            _recovery_store(store,helper['parent_observer'],preflight=rw is not None)
        if len(stores)>1:_recovery_order(*(store['observed_at_ns']for store in stores))
        before=copy['source_before'];after=copy['source_after']
        if before is not None and after is not None:
            drift=any(before[key]!=after[key]for key in('parent','directory','files'))
            if drift and(reason!='source_changed' or rw is not None):_bad()
        for field,flag in(('raw_source_fds_closed_at_ns','source_descriptors_closed'),('raw_copy_fds_closed_at_ns','copy_descriptors_closed')):
            if copy[field]is not None:
                if not work[flag]:_bad()
                _recovery_order(copy['started_at_ns'],copy[field],work['finished_at_ns'])
        if locks['released_at_ns']is not None:
            _recovery_order(copy['started_at_ns'],locks['released_at_ns'],copy['raw_source_fds_closed_at_ns'],work['finished_at_ns'])
            for query in(locks['reserved_before'],locks['reserved_after']):
                if query is not None:_recovery_order(query['finished_at_ns'],locks['released_at_ns'])
        if rw is not None:
            if(failed_lock or refused_reserved or any(copy[key]is None for key in('source_before','copied','source_after',
                    'raw_copy_fds_closed_at_ns','raw_source_fds_closed_at_ns','finished_at_ns'))
                    or any(locks[key]is None for key in('pending','shared','reserved_before','reserved_after','released_at_ns'))):_bad()
    elif rw is not None or ro is not None:_bad()
    if reason in('source_custody','unsupported_ofd','reserved_writer','copy_custody','copy_limit','main_header','journal_trailer')and rw is not None:_bad()
    if reason=='sqlite_rw' and ro is not None:_bad()
    if reason=='journal_disposition' and ro is not None:_bad()
    disposition=work['journal_disposition']
    if disposition is not None:
        if rw is None or not rw['closed']or work['post_rw_copy']is None:_bad()
        _recovery_order(rw['closed_at_ns'],work['post_rw_copy']['observed_at_ns'],disposition['observed_at_ns'],work['finished_at_ns'])
        if disposition['unlink_started_at_ns']is not None:
            _recovery_order(disposition['observed_at_ns'],disposition['unlink_started_at_ns'],work['finished_at_ns'])
        if disposition['unlink_finished_at_ns']is not None:
            _recovery_order(disposition['unlink_started_at_ns'],disposition['unlink_finished_at_ns'],work['finished_at_ns'])
        if disposition['absence_observed_at_ns']is not None:
            _recovery_order(disposition['observed_at_ns'],disposition['absence_observed_at_ns'],work['finished_at_ns'])
    if work['post_ro_copy']is not None:
        if ro is None or not ro['closed']:_bad()
        files=_recovery_store(work['post_ro_copy'],helper['parent_observer'])
        for field in('parent','directory'):
            if work['post_ro_copy'][field]!=helper['scratch'][field]:_bad()
        same=set(files)=={'records.sqlite3'}and files['records.sqlite3']==disposition['main_after']
        if not same and reason!='source_changed':_bad()
        _recovery_order(ro['closed_at_ns'],work['post_ro_copy']['observed_at_ns'],work['finished_at_ns'])
def _recovery_generation_map(loaded,parents):
    """Assign observed identities by sealed role links, never guessed timestamps."""
    from.import engagement_live_contract as c
    from.engagement_live_witness import _retained_audit_readiness
    brokers={row['broker_id']:index for index,row in enumerate(loaded['manifest.json']['broker_instances'])}
    mapped={};facts={};workers={}
    def worker(worker_id,broker_id):
        if broker_id not in brokers or worker_id in workers and workers[worker_id]!=broker_id:_bad()
        workers[worker_id]=broker_id
    def bind(parent,broker_id):
        if broker_id not in brokers:_bad()
        key=(parent['payload']['pid'],parent['payload']['start_time_ticks'])
        fact=(parent['role'],parent['wrapper']['pid'],parent['wrapper']['start_time_ticks'])
        if key in mapped and(mapped[key]!=brokers[broker_id]or facts[key]!=fact):_bad()
        mapped[key]=brokers[broker_id];facts[key]=fact
    for broker_id in brokers:worker(broker_id,broker_id)
    for slot in loaded['processes.json']['child_slots']:
        worker(slot['worker_id'],slot['broker_id']);worker(slot['launcher_id'],slot['broker_id'])
        if slot['entry_sha256']is not None:
            matching=[parent for parent in loaded['processes.json']['startup']if runtime._hash(parent)==slot['entry_sha256']]
            if len(matching)!=1:_bad()
            bind(matching[0],slot['broker_id'])
    for operation in loaded['results.json']['operations']:
        binding=operation['session']['binding']
        worker(binding['reviewer_id'],binding['broker_id'])
    rows=_retained_rows(loaded)
    for item in rows:
        row=item['row']
        if row['kind']!='protocol' or item['source']!='broker_memfd':continue
        data=row['data'];frame=data['frame']
        if data['direction']=='received' and data['channel_role']=='lifecycle' and frame['operation']=='ROLE_OBSERVED':
            ready=frame['body']['readiness']
            if(row['observer_id']!=row['broker_id']or frame['channel_id']!=row['broker_id']
                    or row['session_id']is not None or row['dispatch_id']is not None
                    or ready['role']!=frame['body']['role']):_bad()
            if ready not in loaded['processes.json']['readiness']:_bad()
            worker(ready['worker_ready']['worker_id'],row['broker_id'])
            bind(ready['parent_observation'],row['broker_id'])
    for ready in loaded['processes.json']['readiness']:
        broker_id=workers.get(ready['worker_ready']['worker_id'])
        if broker_id is not None:bind(ready['parent_observation'],broker_id)
    for observed in _retained_audit_readiness(loaded,rows=rows,deadline=c._operation_deadline())['observations']:
        bind(observed['readiness']['parent_observation'],observed['broker_id'])
    identities={};counts={index:set()for index in brokers.values()}
    for parent in parents:
        key=(parent['payload']['pid'],parent['payload']['start_time_ticks'])
        if key not in mapped:c.fail('evidence_incomplete')
        fact=(parent['role'],parent['wrapper']['pid'],parent['wrapper']['start_time_ticks'])
        if facts[key]!=fact:_bad()
        for field in('payload','wrapper'):
            identity=(parent[field]['pid'],parent[field]['start_time_ticks'])
            if identity in identities and identities[identity]!=mapped[key]:_bad()
            identities[identity]=mapped[key];counts[mapped[key]].add(identity)
    for receipt in loaded['cleanup.json']['receipts']:
        for process in receipt['processes']:
            if process['pid']is None or process['start_time_ticks']is None:c.fail('evidence_incomplete')
            key=(process['pid'],process['start_time_ticks'])
            if key not in mapped:c.fail('evidence_incomplete')
            if process['wrapper_pid']!=facts[key][1]or process['role']!=facts[key][0]:_bad()
            counts[mapped[key]].add(key)
    return mapped,counts
def _recovery_physical_history(helper,loaded,parents,*,generation_by_identity=None):
    """Resolve observed process closure around each sequential helper interval."""
    observer=helper['parent_observer'];start=helper['started_at_ns'];finish=helper['finished_at_ns']
    receipts=loaded['cleanup.json']['receipts'];selected_broker=None
    if generation_by_identity is None:generation_by_identity=_recovery_generation_map(loaded,parents)[0]
    for ready in loaded['processes.json']['readiness']:
        if ready['role']=='broker' and ready['worker_ready']['worker_id']==helper['broker_id']:
            if selected_broker is not None:_bad()
            selected_broker=ready['parent_observation']
    if selected_broker is None:_bad()
    if selected_broker['observer']!=observer:_bad()
    _recovery_order(selected_broker['sampled_at_ns'],start)
    if not _supervisor_closure(loaded)['all_closed']:_bad()
    if helper['runtime']is not None:
        source_directory=helper['runtime']['descriptors'][5]
        selected=[row for row in selected_broker['descriptors']if row['purpose']=='held_store_directory']
        if len(selected)!=1 or _recovery_identity(source_directory)!=_recovery_identity(selected[0]):_bad()
    for parent in parents:
        if parent['observer']!=observer:_bad()
        sampled=parent['sampled_at_ns']
        payload=parent['payload'];key=(payload['pid'],payload['start_time_ticks'])
        if key not in generation_by_identity:_bad()
        generation=generation_by_identity[key]
        if generation>helper['generation']:
            if sampled<finish:_bad()
            continue
        if sampled>start:_bad()
        matches=[]
        for receipt in receipts:
            for process in receipt['processes']:
                if(process['pid'],process['start_time_ticks'])==key:
                    if(process['pin_verified']and process['exit_observed']and process['reaped_observed']
                            and process['wrapper_pid']==parent['wrapper']['pid']and process['wrapper_returncode']is not None
                            and receipt['descriptors_closed']and receipt['finished_at_ns']<=start):matches.append(receipt)
        if not matches:_bad()
    for supervisor in loaded['cleanup.json']['supervisors']:
        if supervisor['broker_id']==helper['broker_id']:
            if(supervisor['state']not in('joined','not_started')or supervisor['thread_alive_observed']is not False
                    or not supervisor['channel_closed']or supervisor['pending_slots']
                    or supervisor['cleanup_finished_at_ns']>start):_bad()
    source=None if helper['work']is None or helper['work']['copy']is None else helper['work']['copy']['source_before']
    if source is not None:
        descriptors={row['purpose']:row for row in selected_broker['descriptors']}
        for name,value in(('held_store_directory',source['directory']),
                           ('sqlite_main',next(row['held']for row in source['files']if row['name']=='records.sqlite3'))):
            if name not in descriptors or _recovery_identity(descriptors[name])!=_recovery_identity(value):_bad()
    return selected_broker
@_bounded
def _validate_recovery_helpers(loaded):
    """A10 is saved-data validation only: no filesystem, SQLite or subprocess."""
    from.import engagement_live_contract as c
    cleanup=loaded['cleanup.json'];helpers=cleanup.get('recovery_helpers',[])
    if cleanup['schema_version']=='1':
        if helpers or 'recovery_helpers' in cleanup:_bad()
        return[]
    if cleanup['schema_version']!='2' or type(helpers)is not list or not 1<=len(helpers)<=2:_bad()
    brokers=loaded['manifest.json']['broker_instances'];bundle=loaded['runtime.json']['runtime']
    owners={row['ledger_owner_id']for row in brokers};cache={};seen=set();generations=[];identities=set()
    parents=list(loaded['processes.json']['startup'])+[
        row['parent_observation']for row in loaded['processes.json']['readiness']+loaded['processes.json']['native']]
    audit=_audit_process_closure(loaded)
    parents.extend(audit['parents'])
    generation_by_identity,generation_counts=_recovery_generation_map(loaded,parents)
    for parent in parents:
        for field in('payload','wrapper'):
            identities.add((parent[field]['pid'],parent[field]['start_time_ticks']))
    for receipt in cleanup['receipts']:
        for process in receipt['processes']:
            if process['pid']is not None and process['start_time_ticks']is not None:
                identities.add((process['pid'],process['start_time_ticks']))
    for helper in helpers:
        _recovery_shape(helper,'helper_observation')
        if helper['helper_id']in seen or helper['generation']in generations:_bad()
        seen.add(helper['helper_id']);generations.append(helper['generation'])
        if helper['generation']>=len(brokers)or brokers[helper['generation']]['broker_id']!=helper['broker_id']:_bad()
        config=helper['config'];raw=c.canonical(config,max_bytes=4096)
        if helper['config_bytes']!=len(raw)or helper['config_sha256']!=c.digest(raw):_bad()
        for field in('helper_id','broker_id','started_at_ns','work_deadline_ns','deadline_ns'):
            if config[field]!=helper[field]:_bad()
        if(config['runtime_sha256']!=runtime._hash(bundle)or config['source_manifest_sha256']!=runtime._hash(bundle['sources'])
                or helper['work_deadline_ns']<=helper['started_at_ns']
                or helper['deadline_ns']>helper['started_at_ns']+2000000000
                or helper['work_deadline_ns']>min(helper['started_at_ns']+1500000000,helper['deadline_ns']-500000000)):_bad()
        _recovery_order(helper['started_at_ns'],helper['work_deadline_ns'],helper['deadline_ns'])
        process=helper['process'];closure=helper['cleanup'];transfer=helper['transfer']
        if helper['status']=='unknown' or process['publication_state']=='pending' or helper['finished_at_ns']is None:_bad()
        _recovery_order(helper['started_at_ns'],process['publication_registered_at_ns'],process['publication_resolved_at_ns'])
        if process['publication_state']=='published':
            for field in('pid','parent_pid','start_time_ticks','pidfd','observed_at_ns','exit_observed_at_ns','reaped_at_ns','returncode'):
                if process[field]is None:_bad()
            if(process['parent_pid']!=helper['parent_observer']['pid']or process['pid']==process['parent_pid']
                    or process['task_ids']!=[process['pid']]):_bad()
            key=(process['pid'],process['start_time_ticks'])
            if key in identities:_bad()
            identities.add(key)
            generation_counts[helper['generation']].add(key)
            _recovery_order(process['publication_resolved_at_ns'],process['observed_at_ns'],
                process['exit_observed_at_ns'],process['reaped_at_ns'],closure['finished_at_ns'])
            if process['signal_sent_at_ns']is not None:
                _recovery_order(process['observed_at_ns'],process['signal_sent_at_ns'],process['exit_observed_at_ns'])
        else:
            if process['publication_state']!='not_started' or process['task_ids']or any(process[k]is not None for k in
                    ('pid','parent_pid','start_time_ticks','pidfd','observed_at_ns','exit_observed_at_ns','reaped_at_ns','returncode','release_sent_at_ns','signal_sent_at_ns')):_bad()
        if closure['deadline_ns']!=helper['deadline_ns']or closure['status']=='unknown':_bad()
        for field in('descriptors_closed','directory_closed','directory_removed','parent_closed','pidfd_closed','source_package_closed','stdio_closed'):
            if closure[field]is not True:_bad()
        if closure['scratch_disposition']!='removed' or len(set(closure['removed_names']))!=len(closure['removed_names']):_bad()
        _recovery_order(helper['started_at_ns'],closure['started_at_ns'],closure['finished_at_ns'],helper['finished_at_ns'])
        if closure['status']=='complete' and closure['finished_at_ns']>helper['deadline_ns']:_bad()
        if helper['scratch']is None:_bad()
        for field in('parent','directory'):_recovery_private(helper['scratch'][field],directory=True,observer=helper['parent_observer'])
        _recovery_order(helper['started_at_ns'],helper['scratch']['registered_at_ns'],process['publication_registered_at_ns'])
        if transfer['stdout_bytes']!=transfer['ready']['received_bytes']+transfer['result']['received_bytes']:_bad()
        diagnostic=bytes.fromhex(transfer['stderr_hex'])
        if(len(diagnostic)!=transfer['stderr_bytes']or c.digest(diagnostic)!=transfer['stderr_sha256']
                or transfer['stdout_eof']is not True or transfer['stderr_eof']is not True):_bad()
        _recovery_frame(transfer['ready'],helper['ready'],4096)
        if helper['ready']is not None:
            for field in('helper_id','broker_id'):
                if helper['ready'][field]!=helper[field]:_bad()
            if helper['ready']['pid']!=process['pid']:_bad()
        if helper['work']is not None:
            for field in('helper_id','broker_id','work_deadline_ns','deadline_ns'):
                if helper['work'][field]!=helper[field]:_bad()
            for field in('runtime_sha256','source_package_sha256'):
                if helper['work'][field]!=config[field]:_bad()
        if process['release_sent_at_ns']is not None:
            _recovery_order(process['observed_at_ns'],process['release_sent_at_ns'],process['exit_observed_at_ns'])
            _recovery_runtime(helper,bundle)
        else:
            if helper['work']is not None:_bad()
            if helper['runtime']is not None:_recovery_runtime(helper,bundle)
        export=None
        if transfer['result_status']=='complete':
            export=_recovery_work(helper,loaded,owners,cache)
            export_raw=c.canonical(export,max_bytes=2097152)
            if(transfer['export_bytes']!=len(export_raw)or transfer['export_sha256']!=c.digest(export_raw)
                    or transfer['result_error']is not None):_bad()
        else:
            if transfer['export_bytes']is not None or transfer['export_sha256']is not None:_bad()
            if helper['work']is not None:_recovery_partial_work(helper,loaded,owners,cache)
        result=None
        if transfer['result']['complete']:
            if transfer['result_status']not in('complete','failed')or helper['work']is None:_bad()
            if transfer['result_status']=='failed' and transfer['result_error']is None:_bad()
            result={'schema_version':'1','status':transfer['result_status'],'error':transfer['result_error'],
                    'export':export,'provenance':helper['work']}
            provenance=c.canonical(helper['work'],max_bytes=32768)
            _recovery_result_bytes(result)
            if(transfer['provenance_bytes']!=len(provenance)
                    or transfer['provenance_sha256']!=c.digest(provenance)):_bad()
        elif transfer['result_status']is not None or transfer['result_error']is not None or transfer['provenance_bytes']is not None or transfer['provenance_sha256']is not None:_bad()
        _recovery_frame(transfer['result'],result,2129920)
        if transfer['result']['started_at_ns']is not None:
            _recovery_order(transfer['ready']['finished_at_ns'],process['release_sent_at_ns'],
                transfer['result']['started_at_ns'])
        if transfer['result']['complete']:
            _recovery_order(helper['work']['finished_at_ns'],transfer['result']['finished_at_ns'])
        for frame in(transfer['ready'],transfer['result']):
            if frame['started_at_ns']is not None:
                _recovery_order(process['publication_resolved_at_ns'],frame['started_at_ns'])
            if frame['finished_at_ns']is not None:_recovery_order(frame['finished_at_ns'],closure['finished_at_ns'])
        if helper['status']=='complete':
            if(helper['error']is not None or transfer['result_status']!='complete' or not transfer['result']['complete']
                    or process['publication_state']!='published' or process['returncode']!=0
                    or process['signal_sent_at_ns']is not None or closure['status']!='complete'):_bad()
            if closure['removed_names']!=['records.sqlite3']:_bad()
            _recovery_order(helper['work']['finished_at_ns'],process['exit_observed_at_ns'])
            _recovery_order(transfer['result']['finished_at_ns'],helper['finished_at_ns'],helper['deadline_ns'])
        elif helper['error']is None:_bad()
        _recovery_physical_history(helper,loaded,parents,generation_by_identity=generation_by_identity)
    if(generations!=sorted(generations)or len(identities)>94
            or any(len(values)>47 for values in generation_counts.values())):_bad()
    for before,after in zip(helpers,helpers[1:]):
        _recovery_order(before['finished_at_ns'],after['started_at_ns'])
    return helpers
@_validation('evidence_invalid')
def _copied_recovery_receipt(receipt,helpers,loaded):
    from.import engagement_live_contract as c
    _recovery_shape(receipt,'copied_receipt')
    selected=[helper for helper in helpers if helper['helper_id']==receipt['helper_id']]
    if len(selected)!=1 or selected[0]is not helpers[-1]:_bad()
    helper=selected[0];work=helper['work']
    if helper['generation']!=len(loaded['manifest.json']['broker_instances'])-1:_bad()
    if helper['status']!='complete' or receipt['helper_sha256']!=c.digest(c.canonical(helper,max_bytes=524288)):_bad()
    ro=work['ro'];store=work['post_ro_copy'];main=next(row for row in store['files']if row['name']=='records.sqlite3')
    expected={'parent':store['parent'],'directory':store['directory'],
              'database':{key:main['held'][key]for key in('device','inode','mode','uid','gid')}}
    for field,actual in(('owner_id',ro['owner_id']),('started_at_ns',ro['opened_at_ns']),
            ('finished_at_ns',ro['closed_at_ns']),('store_identity',expected),('bytes',ro['snapshot_bytes']),
            ('sha256',ro['snapshot_sha256']),('ledger_state_sha256',ro['ledger_state_sha256'])):
        if receipt[field]!=actual:_bad()
    entry=loaded['manifest.json']['ledger_exports']['recovery']
    if entry['source']!='postcleanup_copied_recovery' or entry['status']!='complete' or entry['broker_id']is not None:_bad()
    raw=c.canonical(loaded.get('recovery-ledger.json'),max_bytes=2097152)
    if len(raw)!=receipt['bytes']or c.digest(raw)!=receipt['sha256']:_bad()
def _cancelled_capture_host_cause(loaded,rows,row,operation,slot,thread,budget,hard):
    """Owned EOF/close cause after common CAPTURE and boundary association."""
    cid=loaded['manifest.json']['case_id'];origins={'S42C-X53':'broker_eof','S42C-X54':'endpoint_eof',
        'S42C-X55':'launcher_eof','S42C-X59':'payload_and_wrapper_cleanup'}
    env=operation['prepared']['envelope']
    if(cid not in origins or budget is None or slot['role']!='nmap'
            or operation['host_capture']['status']!='cancelled'
            or _boundary_unsettled_dispatch(loaded,rows)!=env['dispatch_id']):return False
    return _lifecycle_host_cause(loaded,rows,row,operation,thread,hard)
def _lifecycle_host_cause(loaded,rows,row,operation,thread,hard):
    from.import engagement_live_contract as c
    origins={'S42C-X53':'broker_eof','S42C-X54':'endpoint_eof','S42C-X55':'launcher_eof','S42C-X59':'payload_and_wrapper_cleanup'}
    cid=loaded['manifest.json']['case_id'];env=operation['prepared']['envelope'];digest=c.prepared_digest(operation['prepared'])
    proof=loaded['results.json']['boundary_proofs'][0]
    raw=loaded['processes.json']['boundary_observations'][0]['observation']
    config={'case_id':cid,'variant':BOUNDARY_CASES[cid]['variant'],'role':'host'}
    if raw['origin']!=origins[cid]or len([x for x in loaded['runtime.json']['instrumentation']
        if x['kind']=='scripted_review' and x['configuration']==config])!=1:return False
    phases=[x for x in rows if x['source']=='role_observer' and x['row']['kind']=='phase'
        and x['row']['dispatch_id']==env['dispatch_id']and x['row']['data']['phase']=='client']
    if len(phases)!=2:return False
    phases.sort(key=lambda x:x['row']['row_sequence']);begin,end=[x['row']for x in phases]
    for wrapped,stage in zip(phases,('begin','end')):
        value=wrapped['row'];phase=value['data'];clock=phase['clock']
        if(any(value[k]!=env[k]for k in('broker_id','session_id','dispatch_id'))
                or value['observer_id']!=env['broker_id']or phase['stage']!=stage
                or phase['reason']is not None or phase['related_sha256']!=digest
                or phase['original_deadline_ns']!=env['action_deadline_ns']or clock is None
                or not env['action_ready_ns']<=clock['mono_before_ns']<=clock['mono_after_ns']<=value['observed_at_ns']<hard
                or loaded['manifest.json']['transcript']['segments'][wrapped['segment']]['status']!='observer_complete'):return False
    if(phases[0]['segment']!=phases[1]['segment']
            or not row['data']['request']['observed_at_ns']<=begin['observed_at_ns']==raw['triggered_at_ns']==proof['started_at_ns']
                <=thread['first_stop_requested_at_ns']<=end['data']['clock']['mono_before_ns']
            or cid=='S42C-X59' and thread['cleanup_finished_at_ns']>end['observed_at_ns']):return False
    limit=min(hard,thread['cleanup_deadline_ns'],raw['triggered_at_ns']+c.CLEANUP_NS)
    for wrapped in rows:
        value=wrapped['row']
        if value['kind']!='protocol':continue
        part=value['data'];frame=part['frame']
        if(wrapped['source']=='broker_memfd' and value['broker_id']==env['broker_id']
                and part['channel_role']=='lifecycle' and part['direction']=='sent'
                and frame['operation']in('BROKER_STOP','SESSION_STOP')):limit=min(limit,frame['body']['cleanup_deadline_ns'])
    # STOP corroborates closure and supplies a bound; it need not precede host
    # first-stop. The private last_ack hash supplies no bytes/counts/authority.
    return(end['observed_at_ns']<=limit
        and all(x['finished_at_ns']<=limit for x in loaded['cleanup.json']['receipts'])
        and all(x['cleanup_finished_at_ns']<=limit for x in loaded['cleanup.json']['supervisors']))
def _lifecycle_meter_terminal(loaded,rows,operation,slot,endpoint):
 """Join an actual terminal meter; full context/witness validation is required."""
 from.import engagement_live_contract as c
 env=operation['prepared']['envelope'];did=env['dispatch_id'];meter=operation['meter']
 raw=loaded['processes.json']['boundary_observations'][0]['observation'];trigger=raw['triggered_at_ns']
 releases,observed=_saved_execution_validated(rows);release=releases.get(did);actual=observed.get(did,{})
 if(endpoint is None or meter['endpoint_id']!=endpoint['worker_ready']['worker_id']
   or release is None or meter['go_sha256']!=runtime._hash(release)
   or actual.get('meter')!=meter or actual.get('forwarded_meter',meter)!=meter
   or meter['reason']!='cancelled' or not meter['delivery_known']
   or not 0<meter['received_request_bytes']<=4096 or meter['sent_response_bytes']!=0
   or raw['meter_transcript_sha256']not in(None,runtime._hash(meter))):return False
 packets=[];go=[];stops=[]
 for wrapped in rows:
  row=wrapped['row']
  if wrapped['source']!='broker_memfd' or row['broker_id']!=env['broker_id']or row['kind']!='protocol':continue
  part=row['data'];frame=part['frame'];op=frame['operation']
  if op in('BROKER_STOP','SESSION_STOP')and part['channel_role']=='lifecycle' and part['direction']=='sent':
   if frame['channel_id']!=env['broker_id']:return False
   if op=='BROKER_STOP' or frame['body']['session_id']==env['session_id']:stops.append(row)
  if row['dispatch_id']!=did:continue
  if op=='GO' and part['channel_role']=='launcher' and part['direction']=='sent':go.append(row)
  if op=='METER':
   if(row['session_id']!=env['session_id']or row['observer_id']!=env['broker_id']
     or loaded['manifest.json']['transcript']['segments'][wrapped['segment']]['status']!='sealed_complete'
     or(part['channel_role'],part['direction'],frame['channel_id'])not in(
      ('endpoint','received',meter['endpoint_id']),('launcher','sent',slot['launcher_id']))):return False
   packets.append(row)
 received=[r for r in packets if r['data']['channel_role']=='endpoint']
 forwarded=[r for r in packets if r['data']['channel_role']=='launcher']
 if(len(received)!=1 or len(forwarded)>1 or len(go)!=1 or not stops
   or go[0]['data']['frame']['channel_id']!=slot['launcher_id']
   or not go[0]['observed_at_ns']<=meter['armed_at_ns']<trigger<=meter['finished_at_ns']<=received[0]['observed_at_ns']
   or forwarded and(received[0]['row_sequence']>=forwarded[0]['row_sequence']
    or received[0]['observed_at_ns']>forwarded[0]['observed_at_ns'])):return False
 if any(x['monotonic_ns']>=trigger and x['kind']in('accept','recv','send')for x in meter['events']):return False
 if not any(x['kind']=='cancel' and trigger<=x['monotonic_ns']<=meter['finished_at_ns']for x in meter['events']):return False
 threads=[x for x in loaded['cleanup.json']['supervisors']if all(x[k]==slot[k]for k in('broker_id','session_id','launcher_id'))]
 capture=[x['row']for x in rows if x['source']=='role_observer' and x['row']['dispatch_id']==did
  and x['row']['kind']=='supervision_projection' and x['row']['data']['kind']=='rpc'
  and x['row']['data']['request']['operation']=='CAPTURE']
 if len(threads)!=1 or len(capture)!=1 or operation['host_capture']is None:return False
 thread=threads[0];row=capture[0];data=row['data'];hard=min(env[k]for k in('action_deadline_ns','session_deadline_ns','broker_deadline_ns'))
 if(thread['state']!='joined' or thread['status']!='complete' or thread['pending_slots']or not thread['channel_closed']
   or thread['first_stop_requested_at_ns']>=min(trigger+100000000,hard-1900000000)
   or thread['cleanup_deadline_ns']>min(hard,thread['first_stop_requested_at_ns']+1900000000)
   or row['observer_id']!=slot['launcher_id']or row['observed_at_ns']<trigger
   or data['reply']is not None and data['reply']['observed_at_ns']<trigger):return False
 limit=min(hard,thread['cleanup_deadline_ns'],trigger+c.CLEANUP_NS)
 if any(not trigger<=x['data']['frame']['body']['observed_at_ns']<=x['observed_at_ns']<=limit for x in stops):return False
 if any(x['observed_at_ns']>min(y['observed_at_ns']for y in stops)for x in packets):return False
 return _lifecycle_host_cause(loaded,rows,row,operation,thread,hard)
