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

from . import engagement_live_runtime as runtime
from .engagement_live_contract import bounded as _bounded


BOUNDARY_CASES = {'S42C-X01': {'variant': 'sealed_nmap_executable_changed', 'role': 'nmap', 'kind': 'pin_mutation'}, 'S42C-X02': {'variant': 'sealed_nmap_library_changed', 'role': 'nmap', 'kind': 'pin_mutation'}, 'S42C-X03': {'variant': 'sealed_broker_sqlite_library_changed', 'role': 'broker', 'kind': 'pin_mutation'}, 'S42C-X04': {'variant': 'sealed_graphical_tk_library_changed', 'role': 'graphical', 'kind': 'pin_mutation'}, 'S42C-X05': {'variant': 'sealed_source_broker_changed', 'role': 'broker', 'kind': 'pin_mutation'}, 'S42C-X06': {'variant': 'sealed_source_launcher_changed', 'role': 'launcher', 'kind': 'pin_mutation'}, 'S42C-X07': {'variant': 'sealed_source_endpoint_changed', 'role': 'endpoint', 'kind': 'pin_mutation'}, 'S42C-X08': {'variant': 'sealed_source_client_changed', 'role': 'client', 'kind': 'pin_mutation'}, 'S42C-X09': {'variant': 'sealed_source_parser_changed', 'role': 'parser', 'kind': 'pin_mutation'}, 'S42C-X10': {'variant': 'sealed_source_terminal_changed', 'role': 'terminal', 'kind': 'pin_mutation'}, 'S42C-X11': {'variant': 'sealed_source_graphical_changed', 'role': 'graphical', 'kind': 'pin_mutation'}, 'S42C-X12': {'variant': 'role_manifest_client_to_parser', 'role': 'client_to_parser', 'kind': 'pin_mutation'}, 'S42C-X13': {'variant': 'role_manifest_endpoint_to_broker', 'role': 'endpoint_to_broker', 'kind': 'pin_mutation'}, 'S42C-X14': {'variant': 'unexpected_descriptor_broker', 'role': 'broker', 'kind': 'descriptor_custody'}, 'S42C-X15': {'variant': 'unexpected_descriptor_launcher', 'role': 'launcher', 'kind': 'descriptor_custody'}, 'S42C-X16': {'variant': 'unexpected_descriptor_endpoint', 'role': 'endpoint', 'kind': 'descriptor_custody'}, 'S42C-X17': {'variant': 'unexpected_descriptor_client', 'role': 'client', 'kind': 'descriptor_custody'}, 'S42C-X18': {'variant': 'unexpected_descriptor_parser', 'role': 'parser', 'kind': 'descriptor_custody'}, 'S42C-X19': {'variant': 'unexpected_descriptor_terminal', 'role': 'terminal', 'kind': 'descriptor_custody'}, 'S42C-X20': {'variant': 'unexpected_descriptor_graphical', 'role': 'graphical', 'kind': 'descriptor_custody'}, 'S42C-X21': {'variant': 'missing_descriptor_broker', 'role': 'broker', 'kind': 'descriptor_custody'}, 'S42C-X22': {'variant': 'missing_descriptor_endpoint', 'role': 'endpoint', 'kind': 'descriptor_custody'}, 'S42C-X23': {'variant': 'missing_descriptor_launcher', 'role': 'launcher', 'kind': 'descriptor_custody'}, 'S42C-X24': {'variant': 'missing_descriptor_terminal', 'role': 'terminal', 'kind': 'descriptor_custody'}, 'S42C-X25': {'variant': 'missing_descriptor_graphical', 'role': 'graphical', 'kind': 'descriptor_custody'}, 'S42C-X26': {'variant': 'forbidden_destination_wrong_target', 'role': 'client', 'kind': 'socket_denial'}, 'S42C-X27': {'variant': 'forbidden_destination_wrong_port', 'role': 'client', 'kind': 'socket_denial'}, 'S42C-X28': {'variant': 'forbidden_destination_ssh_endpoint', 'role': 'client', 'kind': 'socket_denial'}, 'S42C-X29': {'variant': 'endpoint_denies_connect', 'role': 'endpoint', 'kind': 'socket_denial'}, 'S42C-X30': {'variant': 'endpoint_denies_fastopen_sendto', 'role': 'endpoint', 'kind': 'socket_denial'}, 'S42C-X31': {'variant': 'endpoint_denies_fastopen_sendmsg', 'role': 'endpoint', 'kind': 'socket_denial'}, 'S42C-X32': {'variant': 'endpoint_denies_fastopen_sendmmsg', 'role': 'endpoint', 'kind': 'socket_denial'}, 'S42C-X33': {'variant': 'creation_denied_client', 'role': 'client', 'kind': 'creation_denial'}, 'S42C-X34': {'variant': 'creation_denied_parser', 'role': 'parser', 'kind': 'creation_denial'}, 'S42C-X35': {'variant': 'creation_denied_endpoint', 'role': 'endpoint', 'kind': 'creation_denial'}, 'S42C-X36': {'variant': 'creation_denied_broker', 'role': 'broker', 'kind': 'creation_denial'}, 'S42C-X37': {'variant': 'creation_denied_terminal', 'role': 'terminal', 'kind': 'creation_denial'}, 'S42C-X38': {'variant': 'creation_denied_graphical', 'role': 'graphical', 'kind': 'creation_denial'}, 'S42C-X39': {'variant': 'parser_network_filesystem_authority_absent', 'role': 'parser', 'kind': 'parser_absence'}, 'S42C-X40': {'variant': 'parent_observed_identity_nmap_mismatch', 'role': 'nmap', 'kind': 'image_identity'}, 'S42C-X41': {'variant': 'parent_observed_identity_waiting_python_mismatch', 'role': 'waiting_python', 'kind': 'image_identity'}, 'S42C-X42': {'variant': 'parent_observed_identity_parser_mismatch', 'role': 'parser', 'kind': 'image_identity'}, 'S42C-X43': {'variant': 'parent_observed_identity_endpoint_mismatch', 'role': 'endpoint', 'kind': 'image_identity'}, 'S42C-X44': {'variant': 'native_image_observation_missing_no_ARM', 'role': 'nmap', 'kind': 'image_identity'}, 'S42C-X45': {'variant': 'meter_connection_cap_identify', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X46': {'variant': 'meter_connection_cap_headers', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X47': {'variant': 'meter_request_cap_identify', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X48': {'variant': 'meter_request_cap_headers', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X49': {'variant': 'meter_response_cap_identify', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X50': {'variant': 'meter_response_cap_headers', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X51': {'variant': 'meter_partial_request', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X52': {'variant': 'meter_partial_response', 'role': 'endpoint', 'kind': 'meter_boundary'}, 'S42C-X53': {'variant': 'role_EOF_broker', 'role': 'broker', 'kind': 'lifecycle'}, 'S42C-X54': {'variant': 'role_EOF_endpoint', 'role': 'endpoint', 'kind': 'lifecycle'}, 'S42C-X55': {'variant': 'role_EOF_launcher', 'role': 'launcher', 'kind': 'lifecycle'}, 'S42C-X56': {'variant': 'endpoint_clock_forward_before_recv', 'role': 'endpoint', 'kind': 'clock_boundary'}, 'S42C-X57': {'variant': 'endpoint_clock_forward_before_send', 'role': 'endpoint', 'kind': 'clock_boundary'}, 'S42C-X58': {'variant': 'endpoint_deadline_before_send_after_partial', 'role': 'endpoint', 'kind': 'clock_boundary'}, 'S42C-X59': {'variant': 'actual_payload_and_wrapper_reaped', 'role': 'all', 'kind': 'lifecycle'}}

def _bad():
    runtime._fail('evidence_invalid')


def _bytes(encoded,maximum):
    if type(encoded)is not str or len(encoded)>((maximum+2)//3)*4:_bad()
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError):_bad()
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
        elif key in ('tasks_before','tasks_after'):
            if type(field)is not list or not 1<=len(field)<=2 or field!=sorted(set(field)):_bad()
            for task in field:runtime._integer(task,1,2**31-1)
        elif key=='changed_descriptor':
            runtime._fields(field,runtime.SPEC['closed_objects']['descriptor']['fields'])
            runtime._integer(field['fd'],0,255)
            if field['kind'] not in runtime.SPEC['closed_objects']['descriptor']['kind'] or type(field['purpose'])is not str or not 1<=len(field['purpose'])<=64:_bad()
            for n in ('device','inode','mode','flags'):runtime._integer(field[n],0,2**64-1)
        elif key in ('operation','metric','stimulus','origin'):
            if field not in spec[key]:_bad()
        elif key=='rejected_stage':
            if field not in spec['stage']:_bad()
        elif key=='slot':
            if field not in ('http_identify','http_headers'):_bad()
        elif key=='destination':
            if type(field)is not str or not field.startswith('/') or len(field)>512 or '\x00' in field:_bad()
        elif key=='phase':
            if field not in ('entry','initial_bootstrap','bootstrap','prepared','sealed','ready','cleanup'):_bad()
        elif key=='target':
            import ipaddress
            try:address=ipaddress.IPv4Address(field)
            except (ValueError,TypeError):_bad()
            if str(address)!=field or not address.is_private or address.is_unspecified or address.is_multicast:_bad()
        else:runtime._integer(field,0,2**63-1)
    if kind=='socket_denial':
        if value['family']!=2 or value['socket_type']!=1 or value['protocol'] not in (0,6) or not 1<=value['port']<=65535 or value['errno']>4095:_bad()
    if kind=='creation_denial' and value['errno']>4095:_bad()
    if kind=='parser_absence' and any(value[k]>4095 for k in ('network_errno','filesystem_errno','process_errno')):_bad()
    if kind=='clock_boundary' and value['triggered_at_ns']<1:_bad()
    if kind=='lifecycle' and value['cleanup_finished_at_ns']<value['triggered_at_ns']:_bad()
    return json.loads(runtime._json(value))


def _boundary_checks(loaded,bundle,readies,natives,cleanups,meters):
    import errno
    observations={}
    for row in loaded['processes.json']['boundary_observations']:
        runtime._fields(row,('kind','observation'))
        actual=validate_boundary_observation(row['kind'],row['observation'])
        digest=runtime._hash(actual)
        if digest in observations:_bad()
        observations[digest]=(row['kind'],actual)
    sources={row['sha256'] for row in bundle['sources']}|{runtime._hash(role['sources']) for role in bundle['roles']}|{row['sha256'] for row in bundle['compiled']}
    controls={**readies,**natives,**{key:row[1] for key,row in observations.items()}}
    proofs=loaded['results.json']['boundary_proofs']
    for proof in proofs:
        runtime._fields(proof,runtime.SPEC['role_boundary_proofs']['common_fields'])
        case=BOUNDARY_CASES.get(proof['case_id'])
        if case is None or proof['schema_version']!='1' or proof['role']!=case['role'] or proof['kind']!=case['kind'] or proof['runtime_sha256']!=runtime.runtime_digest(bundle) or proof['source_sha256'] not in sources:_bad()
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
        cleanup_complete=bool(cleanups) and all(x['status']=='complete' for x in cleanups.values())
        # Successful paired controls retain actual parent/readiness observations;
        # raw self-reported booleans alone never establish a passing boundary.
        observed_control=proof['control_observation_sha256'] in readies or proof['control_observation_sha256'] in natives
        no_effect=all(m['received_request_bytes'] in (0,None) and m['sent_response_bytes'] in (0,None) for m in meters.values())
        passed=False
        if kind=='pin_mutation':
            passed=observed_control and raw['before_sha256']!=raw['after_sha256'] and raw['expected_seals']==15 and not raw['ready_emitted'] and not raw['arm_emitted'] and no_effect
            if v.startswith('sealed_source_'):passed &= raw['rejected_stage'] in ('source_snapshot','worker_entry','parent_image')
            elif v.startswith('role_manifest_'):passed &= raw['rejected_stage'] in ('role_manifest','worker_entry')
            else:passed &= raw['rejected_stage'] in ('native_snapshot','worker_entry','parent_image')
        elif kind=='descriptor_custody':
            passed=observed_control and raw['expected_inventory_sha256']!=raw['actual_inventory_sha256'] and raw['refused'] and no_effect
        elif kind=='socket_denial':
            expected_op=v.rsplit('_',1)[-1] if v.startswith('endpoint_denies_') else 'connect'
            passed=observed_control and raw['operation']==expected_op and raw['return_value']==-1 and raw['paired_control_connected'] and raw['listener_accepts']==0 and raw['listener_payload_bytes']==0
            if v.startswith('endpoint_denies_'):passed &= raw['errno']==errno.EPERM
            else:passed &= raw['errno'] in (errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH,errno.ETIMEDOUT)
            if 'fastopen' in v:passed &= bool(raw['flags']&0x20000000)
        elif kind=='creation_denial':
            rows=[item for kind,item in observations.values() if kind=='creation_denial']
            passed=observed_control and len(rows)==3 and {item['operation'] for item in rows}=={'fork','unshare','execve'} and all(item['return_value']==-1 and item['errno']==errno.EPERM and item['tasks_before']==item['tasks_after']==raw['tasks_before'] for item in rows)
        elif kind=='parser_absence':
            passed=observed_control and raw['authority_fds_absent'] and all(raw[k]==-1 for k in ('network_return','filesystem_return','process_return')) and raw['network_errno']==raw['process_errno']==errno.EPERM and raw['filesystem_errno'] in (errno.EPERM,errno.EACCES,errno.EROFS)
        elif kind=='image_identity':
            passed=observed_control and raw['refused'] and not raw['arm_emitted'] and raw['waiting_observation_sha256'] in readies and no_effect
            if v=='native_image_observation_missing_no_ARM':passed &= raw['native_observation_sha256']is None
            else:passed &= raw['observed_image_sha256']is None or raw['expected_image_sha256']!=raw['observed_image_sha256']
        elif kind=='meter_boundary':
            meter=meters.get(raw['meter_transcript_sha256'])
            if meter is not None:
                cap=(3 if raw['slot']=='http_identify' else 1) if raw['metric']=='connections' else (4096 if raw['slot']=='http_identify' else 256) if raw['metric'] in ('request','partial_request') else (4096 if raw['slot']=='http_identify' else 2048)
                key='accepted_connections' if raw['metric']=='connections' else 'received_request_bytes' if raw['metric'] in ('request','partial_request') else 'sent_response_bytes'
                passed=observed_control and meter['slot']==raw['slot'] and raw['delivery_known']==meter['delivery_known'] and raw['input_sha256']==meter['request_sha256'] and raw['output_sha256']==meter['response_sha256']
                if raw['metric'].startswith('partial_'):passed &= meter[key]is not None and 0<meter[key]<cap and len([event for event in meter['events'] if event['kind']==('recv' if key=='received_request_bytes' else 'send') and event['actual_bytes']>0])>=2
                else:passed &= raw['refused'] and raw['stimulus_bytes']>=cap+1 and meter[key]==cap and meter['reason']=={'connections':'connection_limit','request':'request_limit','response':'response_limit'}[raw['metric']]
        elif kind=='clock_boundary':
            meter=meters.get(raw['meter_transcript_sha256'])
            if meter is not None:
                passed=observed_control and raw['clock_source_sha256'] in sources and raw['refused'] and raw['accepted_after']==raw['accepted_before'] and raw['sent_after']==raw['sent_before'] and not any(event['monotonic_ns']>=raw['triggered_at_ns'] and event['kind'] in ('accept','recv','send') and (event['actual_bytes']>0 or event['kind']=='accept') for event in meter['events'])
                if v.endswith('after_partial'):passed &= raw['sent_before']>0
        elif kind=='lifecycle':
            cleanup=cleanups.get(raw['cleanup_sha256'])
            passed=observed_control and cleanup is not None and cleanup['status']=='complete' and raw['cleanup_finished_at_ns']==cleanup['finished_at_ns'] and cleanup['finished_at_ns']-raw['triggered_at_ns']<=2000000000
            if raw['meter_transcript_sha256']is not None:passed &= raw['meter_transcript_sha256'] in meters
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
    return {key:runtime._hash(value) if key=='transcript_sha256' else value[key] for key in fields}


def validate_client_result(value):
    s=runtime.SPEC['output_and_evidence'];runtime._fields(value,s['result_exact_fields'])
    if value['schema_version']!='1' or value['slot'] not in ('http_identify','http_headers') or value['status'] not in s['result_status_enum']:_bad()
    if type(value['dispatch_id'])is not str or runtime._UUID.fullmatch(value['dispatch_id'])is None:_bad()
    for key in ('envelope_sha256','runtime_sha256','stdout_sha256','stderr_sha256'):runtime._digest(value[key])
    cap=8192 if value['slot']=='http_identify' else 2048
    for key in ('stdout_bytes','stderr_bytes'):runtime._integer(value[key],0,cap)
    if value['stdout_bytes']+value['stderr_bytes']>cap or type(value['truncated'])is not bool:_bad()
    if value['exit_code']is not None:runtime._integer(value['exit_code'],-255,255)
    if value['stop_reason']is not None and value['stop_reason'] not in s['reason_enum']:_bad()
    if value['readiness']is not None:
        runtime._fields(value['readiness'],('client_sha256','native_sha256'))
        runtime._digest(value['readiness']['client_sha256'])
        if value['readiness']['native_sha256']is not None:runtime._digest(value['readiness']['native_sha256'])
    if value['meter']is not None:
        runtime._fields(value['meter'],s['meter_summary_exact_fields'])
        runtime._digest(value['meter']['transcript_sha256'])
        if value['meter']['dispatch_id']!=value['dispatch_id'] or value['meter']['envelope_sha256']!=value['envelope_sha256'] or value['meter']['slot']!=value['slot']:_bad()
    if value['cleanup']is not None:runtime.validate_cleanup(value['cleanup'])
    receipt=value['parser_receipt']
    if (value['parsed']is None)!=(receipt is None):_bad()
    if receipt is not None:
        if value['readiness']is None or value['cleanup']is None:_bad()
        runtime._fields(receipt,s['parser_receipt_exact_fields'])
        if receipt['schema_version']!='1' or receipt['slot']!=value['slot']:_bad()
        for key in ('input_sha256','output_sha256','readiness'):runtime._digest(receipt[key])
        runtime._integer(receipt['input_bytes'],1,16384);runtime._integer(receipt['output_bytes'],1,4096);runtime._integer(receipt['elapsed_ms'],0,2000)
        runtime.validate_cleanup(receipt['cleanup'])
        if receipt['cleanup']['status']!='complete':_bad()
    if value['status']=='succeeded':
        if value['exit_code']!=0 or value['truncated'] or value['stop_reason']is not None or value['parsed']is None or receipt is None or value['cleanup']is None or value['cleanup']['status']!='complete' or value['readiness']is None:_bad()
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
    from . import engagement_live_contract as contract
    from . import configurable_contract,configurable_parser
    from .configurable_scope import validate_scope,scope_digest
    prepared=contract.validate_prepared(prepared);release=contract.validate_release(release)
    scope=validate_scope(scope);client=validate_client_result(client_result);meter=validate_meter(meter)
    bundle=runtime.validate_runtime(runtime_bundle);env=prepared['envelope'];slot=env['slot']
    if scope_digest(scope)!=env['scope_sha256'] or configurable_contract.action(scope,1 if slot=='http_identify' else 2)!=prepared['action']:_bad()
    if release['dispatch_id']!=env['dispatch_id'] or release['envelope_sha256']!=contract.envelope_digest(env) or release['prepared_sha256']!=contract.prepared_digest(prepared):_bad()
    if client['dispatch_id']!=env['dispatch_id'] or client['slot']!=slot or client['envelope_sha256']!=release['envelope_sha256'] or client['runtime_sha256']!=runtime.runtime_digest(bundle) or client['runtime_sha256']!=env['runtime_sha256']:_bad()
    if meter['dispatch_id']!=env['dispatch_id'] or meter['session_id']!=env['session_id'] or meter['slot']!=slot or meter['envelope_sha256']!=release['envelope_sha256'] or meter['go_sha256']!=runtime._hash(release) or client['meter']!=meter_summary(meter):_bad()
    runtime._fields(capture,('schema_version','slot','exit_code','truncated','stdout_base64','stderr_base64','stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256'))
    if capture['schema_version']!='1' or capture['slot']!=slot or capture['exit_code']!=client['exit_code'] or capture['truncated']!=client['truncated']:_bad()
    raw={}
    cap=8192 if slot=='http_identify' else 2048
    for name in ('stdout','stderr'):
        raw[name]=_bytes(capture[name+'_base64'],cap)
        if type(capture[name+'_bytes'])is not int or len(raw[name])!=capture[name+'_bytes'] or capture[name+'_bytes']!=client[name+'_bytes'] or hashlib.sha256(raw[name]).hexdigest()!=capture[name+'_sha256'] or capture[name+'_sha256']!=client[name+'_sha256']:_bad()
    if sum(map(len,raw.values()))>cap:_bad()
    if type(child_readiness)is not list or len(child_readiness)>3 or type(child_cleanup)is not list or len(child_cleanup)>3:_bad()
    known={};identities=set();reaped=set()
    for ready in child_readiness:
        if ready['role'] not in ('nmap','headers','admission','parser'):_bad()
        runtime.validate_readiness(ready['role'],ready,bundle);known[runtime._hash(ready)]=ready
        p=ready['parent_observation']['payload'];identities.add((p['pid'],p['start_time_ticks']))
    cleanups={}
    for receipt in child_cleanup:
        runtime.validate_cleanup(receipt);cleanups[runtime._hash(receipt)]=receipt
        for p in receipt['processes']:
            if p['reaped_observed'] and p['wrapper_returncode']is not None:reaped.add((p['pid'],p['start_time_ticks']))
    if client['cleanup']is not None and runtime._hash(client['cleanup']) not in cleanups:_bad()
    if client['readiness']is not None and client['readiness']['client_sha256'] not in known:_bad()
    if type(native_readiness)is not list or len(native_readiness)>1:_bad()
    native_hashes=set()
    for native in native_readiness:
        runtime.validate_protocol_value('native_readiness',native)
        manifest=next(row for row in bundle['roles'] if row['role']=='nmap')
        expected=next(row for row in manifest['native_files'] if row['destination']=='/tool/nmap')
        parent=native['parent_observation'];image=parent['executable']
        if slot!='http_identify' or image['sha256']!=expected['sha256'] or image['size']!=expected['size'] or not set(manifest['required_mapped_images'])<={row['destination'] for row in parent['mapped_images']}:_bad()
        waiting=[row for row in known.values() if row['role']=='nmap' and row['parent_observation']['payload']==parent['payload']]
        if len(waiting)!=1 or native['waiting_image']!=waiting[0]['parent_observation']['executable'] or parent['namespaces']!=waiting[0]['parent_observation']['namespaces']:_bad()
        native_hashes.add(runtime._hash(native))
    if client['readiness']is not None:
        actual=known[client['readiness']['client_sha256']]
        if actual['role']!=('nmap' if slot=='http_identify' else 'headers'):_bad()
        h=client['readiness']['native_sha256']
        if h is not None and h not in native_hashes or slot=='http_headers' and native_hashes:_bad()
    parsed=client['parsed'];receipt=client['parser_receipt']
    if receipt is not None:
        if receipt['readiness'] not in known or known[receipt['readiness']]['role']!='parser' or runtime._hash(receipt['cleanup']) not in cleanups:_bad()
        request={'schema_version':'1','slot':slot,'scope':scope,'raw_base64':capture['stdout_base64'],'stderr_base64':capture['stderr_base64'],'truncated':capture['truncated']}
        encoded=runtime._json(request);reply=runtime._json({'schema_version':'1','slot':slot,'parsed':parsed})
        if receipt['input_bytes']!=len(encoded) or receipt['input_sha256']!=hashlib.sha256(encoded).hexdigest() or receipt['output_bytes']!=len(reply) or receipt['output_sha256']!=hashlib.sha256(reply).hexdigest():_bad()
        if configurable_parser.validate_result(prepared['action']['tool_id'],parsed,scope,'http')!=parsed:_bad()
    if client['status']=='succeeded':
        if identities-reaped or any(item['status']!='complete' for item in cleanups.values()) or raw['stderr']:_bad()
        request=_bytes(meter['request_base64'],4096);response=_bytes(meter['response_base64'],4096)
        if slot=='http_identify':
            if request!=b'GET / HTTP/1.0\r\n\r\n' or response!=b'HTTP/1.0 200 OK\r\nServer: nginx/1.26.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' or meter['accepted_connections'] not in (2,3):_bad()
            if parsed.get('identification')!='identified' or parsed.get('state')!='open' or parsed.get('service')!={'name':'http','product':'nginx','version':'1.26.0'}:_bad()
        else:
            expected=('GET / HTTP/1.1\r\nHost: '+scope['http']['target']+':'+str(scope['http']['port'])+'\r\nConnection: close\r\n\r\n').encode('ascii')
            if request!=expected or response!=raw['stdout'] or meter['accepted_connections']!=1:_bad()
    return client


def _saved_execution(loaded):
    """Resolve actual broker channel observations, including partial failures."""
    from .engagement_live_witness import validate_transcript_row
    raw=loaded.get('transcript.jsonl',b'')
    if type(raw)is not bytes or len(raw)>2097152:_bad()
    releases={};observations={}
    for segment in loaded['manifest.json'].get('transcript',{}).get('segments',[]):
        if segment['source']!='broker_memfd':continue
        part=raw[segment['offset']:segment['offset']+segment['bytes']]
        if len(part)!=segment['bytes'] or hashlib.sha256(part).hexdigest()!=segment['sha256']:_bad()
        for line in part.split(b'\n')[:-1]:
            row=validate_transcript_row(runtime._decode(line,32768))
            if row['kind']!='protocol':continue
            if row['broker_id']!=segment['broker_id'] or row['observer_id']!=row['broker_id']:_bad()
            data=row['data'];frame=data['frame'];role=data['channel_role'];direction=data['direction']
            operation=frame['operation'];body=frame['body'];dispatch=row['dispatch_id']
            if role=='launcher' and direction=='sent' and operation=='GO':
                if body['dispatch_id']!=dispatch or dispatch in releases:_bad()
                releases[dispatch]=body
            elif operation=='METER' and role in ('endpoint','launcher'):
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
                elif kind in ('role_readiness','cleanup'):
                    found.setdefault(kind,[]).append(body['data'])
    return releases,observations


def _resolve_cleanup(receipt,ready,retained):
    if runtime._hash(receipt) not in retained:_bad()
    if ready is not None:
        payload=ready['parent_observation']['payload']
        if not any(row['pid']==payload['pid'] and row['start_time_ticks']==payload['start_time_ticks']
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
    if any(expected[k]is None for k in ('connections','request_bytes','response_bytes')) or observed!=expected:_bad()


def _validate_exports(cleanup, loaded, closed_at, identities, closed):
    from . import engagement_dispatch_contract as ledger
    manifest=loaded['manifest.json']
    instances=manifest.get('broker_instances',[])
    brokers={row['broker_id'] for row in instances}
    owners={row['ledger_owner_id'] for row in instances}
    if type(cleanup['exports'])is not list or len(cleanup['exports'])>4:_bad()
    seen=set();references={}
    for record in cleanup['exports']:
        runtime._fields(record,('broker_id','reference','host_descriptor','broker_descriptor'))
        if record['broker_id'] not in brokers:_bad()
        ref=record['reference'];runtime._fields(ref,('phase','bytes','device','inode','seals','sha256'))
        if ref['phase'] not in ('initial','final') or type(ref['seals'])is not int or ref['seals']!=15:_bad()
        runtime._integer(ref['bytes'],1,2097152);runtime._integer(ref['device']);runtime._integer(ref['inode'],1);runtime._digest(ref['sha256'])
        key=(record['broker_id'],ref['phase'])
        if key in seen:_bad()
        seen.add(key)
        references[key]=ref
        for name,access in (('host_descriptor',os.O_RDONLY),('broker_descriptor',os.O_RDWR)):
            row=record[name];runtime._fields(row,runtime.SPEC['closed_objects']['descriptor']['fields'])
            runtime._integer(row['fd'],0,255)
            for field in ('device','inode','mode','flags'):runtime._integer(row[field],0,2**64-1)
            if row['kind']!='regular' or not stat.S_ISREG(row['mode']) or row['flags'] & os.O_ACCMODE!=access or row['device']!=ref['device'] or row['inode']!=ref['inode'] or row['purpose']!=ref['phase']+'_export_memfd':_bad()
    for phase in ('initial','final'):
        entry=manifest.get('ledger_exports',{}).get(phase)
        if entry is None:continue
        if entry['status']=='complete':
            ref=references.get((entry['broker_id'],phase))
            retained=loaded.get(entry['file'])
            if ref is None or type(retained)is not dict:_bad()
            validated=ledger.validate_export(retained);raw=ledger.canonical(validated)
            if ref['bytes']!=len(raw) or ref['sha256']!=hashlib.sha256(raw).hexdigest():_bad()
    recovery=cleanup['recovery']
    if recovery is None:
        if 'recovery-ledger.json' in loaded:_bad()
        return
    runtime._fields(recovery,('schema_version','source','owner_id','started_at_ns','finished_at_ns','read_only','store_identity','bytes','sha256','ledger_state_sha256','closed'))
    if recovery['schema_version']!='1' or recovery['source']!='postcleanup_readonly' or recovery['read_only']is not True or recovery['closed']is not True or type(recovery['owner_id'])is not str or runtime._UUID.fullmatch(recovery['owner_id'])is None or recovery['owner_id'] in owners:_bad()
    for field in ('started_at_ns','finished_at_ns'):runtime._integer(recovery[field])
    if identities-closed or not closed_at<=recovery['started_at_ns']<=recovery['finished_at_ns']<=recovery['started_at_ns']+2000000000:_bad()
    runtime._fields(recovery['store_identity'],('parent','directory','database'))
    uid=None;gid=None
    for name,row in recovery['store_identity'].items():
        runtime._fields(row,('device','inode','mode','uid','gid'))
        for field in ('device','inode'):runtime._integer(row[field],0,2**64-1)
        for field in ('mode','uid','gid'):runtime._integer(row[field],0,2**32-1)
        if uid is None:uid,gid=row['uid'],row['gid']
        if row['uid']!=uid or row['gid']!=gid:_bad()
        if name=='database':
            if not stat.S_ISREG(row['mode']) or stat.S_IMODE(row['mode'])!=0o600:_bad()
        elif not stat.S_ISDIR(row['mode']) or stat.S_IMODE(row['mode'])!=0o700:_bad()
    runtime._integer(recovery['bytes'],1,2097152)
    runtime._digest(recovery['sha256']);runtime._digest(recovery['ledger_state_sha256'])
    retained=loaded.get('recovery-ledger.json')
    if type(retained)is not dict:_bad()
    validated=ledger.validate_export(retained);raw=ledger.canonical(validated)
    if len(raw)!=recovery['bytes'] or hashlib.sha256(raw).hexdigest()!=recovery['sha256'] or hashlib.sha256(ledger.STATE_DOMAIN+ledger.canonical(validated['state'])).hexdigest()!=recovery['ledger_state_sha256']:_bad()


@_bounded
def _fixture_descriptor_selection(loaded):
    """Validate the complete fixed fixture selection within one nested budget."""
    selected=None
    manifest=loaded['manifest.json'];rule=runtime.SPEC['owned_meter_connection_fixture']
    case_id=manifest.get('case_id');case=rule['cases'].get(case_id)
    if case is not None:
        if manifest.get('evidence_class')!='owned_gate':_bad()
        wrapper=loaded['runtime.json'];bundle=runtime.validate_runtime(wrapper['runtime'])
        digest=runtime.runtime_digest(bundle)
        if manifest['runtime_sha256']!=digest:_bad()
        config={'case_id':case_id,'variant':case['variant'],'role':'endpoint'}
        sources={row['module']:row for row in bundle['sources']}
        role=next(row for row in bundle['roles'] if row['role']=='endpoint')
        role_sources={row['module']:row for row in role['sources']}
        for name in ('engagement_live_endpoint_worker','engagement_live_runtime'):
            source=sources.get(name)
            if source is None or role_sources.get(name)!=source:_bad()
            matches=[item for item in wrapper['instrumentation'] if item['source_sha256']==source['sha256']]
            if len(matches)!=1 or matches[0]['kind']!='sealed_fault' or matches[0]['configuration']!=config or matches[0]['configuration_sha256']!=runtime._hash(config):_bad()
        readies=[item for item in loaded['processes.json']['readiness'] if item['role']=='endpoint']
        if len(readies)!=1:_bad()
        ready=readies[0];parent=ready['parent_observation'];descriptors=parent['descriptors']
        count=case['steady_descriptors']
        if type(descriptors)is not list or len(descriptors)!=count or [r.get('fd') for r in descriptors]!=list(range(count)):_bad()
        purposes=[rule['steady_descriptor_purposes'][str(fd)] for fd in range(count)]
        if [r.get('purpose') for r in descriptors]!=purposes:_bad()
        if any(row.get('kind')!='stream_socket' or not stat.S_ISSOCK(row.get('mode',0)) or row.get('flags',0)&os.O_ACCMODE!=os.O_RDWR for row in descriptors[5:]):_bad()
        if len({(row['device'],row['inode']) for row in descriptors[5:]})!=count-5:_bad()
        if ready['worker_ready']['descriptor_sha256']!=runtime._hash(descriptors):_bad()
        proofs=loaded['results.json']['boundary_proofs']
        if len(proofs)!=1:_bad()
        proof=proofs[0]
        if proof['case_id']!=case_id or proof['role']!='endpoint' or proof['kind']!='meter_boundary' or proof['runtime_sha256']!=digest or proof['source_sha256']!=sources['engagement_live_endpoint_worker']['sha256'] or proof['control_observation_sha256']!=runtime._hash(ready):_bad()
        payload=parent['payload'];selected={'payload':(payload['pid'],payload['start_time_ticks']),'descriptors':json.loads(runtime._json(descriptors))}
    return selected


@contextmanager
def _retained_fixture_validation(loaded,*,deadline=None):
    """A06 saved-data allowance; never changes live setup/entry limits."""
    from .engagement_live_contract import _deadline_context
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
    from . import engagement_live_contract as contract
    if observations is None:
        from .engagement_live_witness import _retained_audit_readiness
        observations=_retained_audit_readiness(loaded,
            deadline=contract._operation_deadline())['observations']
    known={};parents=[];missing=False
    process_rows=loaded.get('processes.json',{})
    ordinary=list(process_rows.get('startup',[]))+[
        row['parent_observation'] for row in process_rows.get('readiness',[])+process_rows.get('native',[])]
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
        all_ids.update((p['pid'],p['start_time_ticks']) for p in receipt['processes']
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
                    if (process['wrapper_pid']==parent['wrapper']['pid']
                            and (process['role']=='audit' or process['pid']==key[0])):_bad()
                    continue
                if process['role']!='audit' or process['wrapper_pid']!=parent['wrapper']['pid']:_bad()
                if receipt['finished_at_ns']<observed['observed_at_ns']:_bad()
                matches.append(process)
                if (not receipt['descriptors_closed'] or not process['pin_verified']
                        or not process['exit_observed'] or not process['reaped_observed']
                        or process['wrapper_returncode']is None):missing=True
        if not matches:missing=True
        elif any(process!=matches[0] for process in matches[1:]):_bad()
    return {'parents':parents,'missing_cleanup':missing}


@_bounded
def validate_live_context(value):
    """Validate loaded member objects; inspectors own file custody and replay."""
    from . import engagement_live_contract as contract
    if type(value)is not dict or not {'runtime.json','processes.json','results.json','cleanup.json','manifest.json'}<=set(value):_bad()
    wrapper=value['runtime.json'];runtime._fields(wrapper,('schema_version','runtime','instrumentation'))
    bundle=runtime.validate_runtime(wrapper['runtime']);digest=runtime.runtime_digest(bundle)
    if wrapper['schema_version']!='1' or value['manifest.json']['runtime_sha256']!=digest:_bad()
    instrumentation=wrapper['instrumentation']
    if type(instrumentation)is not list or len(instrumentation)>16:_bad()
    sealed_sources={row['sha256'] for row in bundle['sources']}|{row['sha256'] for row in bundle['compiled']}
    for item in instrumentation:
        runtime._fields(item,('kind','configuration','configuration_sha256','source_sha256'))
        runtime._digest(item['source_sha256']);runtime._digest(item['configuration_sha256'])
        runtime._fields(item['configuration'],('case_id','variant','role'))
        if runtime._hash(item['configuration'])!=item['configuration_sha256']:_bad()
        if item['kind'] in ('sealed_fault','sealed_clock') and item['source_sha256'] not in sealed_sources:_bad()

    processes=value['processes.json'];runtime._fields(processes,('schema_version','startup','readiness','native','boundary_observations'))
    results=value['results.json'];runtime._fields(results,('schema_version','operations','boundary_proofs','core_proofs'))
    cleanup=value['cleanup.json'];runtime._fields(cleanup,('schema_version','receipts','exports','recovery'))
    for obj in (processes,results,cleanup):
        if obj['schema_version']!='1':_bad()
    for obj,key,maximum in ((processes,'startup',94),(processes,'readiness',94),(processes,'native',4),(processes,'boundary_observations',59),(cleanup,'receipts',94),(results,'boundary_proofs',1),(results,'core_proofs',1)):
        if type(obj[key])is not list or len(obj[key])>maximum:_bad()
    readies={};identities=set();startup_identities=set();startup_hashes=set()
    for parent in processes['startup']:
        runtime.validate_parent_observation(parent)
        if parent['stage']!='entry':_bad()
        h=runtime._hash(parent)
        if h in startup_hashes:_bad()
        startup_hashes.add(h)
        p=parent['payload'];startup_identities.add((p['pid'],p['start_time_ticks']))
        manifest=next(row for row in bundle['roles'] if row['role']==parent['role'])
        expected=next(row for row in manifest['native_files'] if row['destination']=='/usr/bin/python3')
        if parent['executable']['destination']!='/usr/bin/python3' or parent['executable']['sha256']!=expected['sha256'] or parent['executable']['size']!=expected['size']:_bad()
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
        role_manifest=next(x for x in bundle['roles'] if x['role']=='nmap')
        expected=next(x for x in role_manifest['native_files'] if x['destination']=='/tool/nmap')
        observed=native['parent_observation']['executable']
        if observed['sha256']!=expected['sha256'] or observed['size']!=expected['size']:_bad()
        if not set(role_manifest['required_mapped_images'])<={row['destination'] for row in native['parent_observation']['mapped_images']}:_bad()
        natives[runtime._hash(native)]=native
        p=native['parent_observation']['payload']
        if (p['pid'],p['start_time_ticks']) not in identities:_bad()
        waiting=[ready for ready in readies.values() if ready['role']=='nmap' and ready['parent_observation']['payload']==p]
        if len(waiting)!=1 or native['waiting_image']!=waiting[0]['parent_observation']['executable'] or native['parent_observation']['namespaces']!=waiting[0]['parent_observation']['namespaces']:_bad()
    # The accepted audit role is retained in actual AUDIT_OBSERVED packets,
    # not a fabricated compound readiness row. Its identity shares this cap.
    _audit_process_closure(value)
    if len(identities)>94:_bad()
    closed=set();closed_at=0
    for item in cleanup['receipts']:
        runtime.validate_cleanup(item)
        closed_at=max(closed_at,item['finished_at_ns'])
        for p in item['processes']:
            if p['pid']is not None and p['reaped_observed'] and p['wrapper_returncode']is not None:closed.add((p['pid'],p['start_time_ticks']))
    _validate_exports(cleanup,value,closed_at,identities,closed)
    if startup_identities-closed:_bad()
    # A genuinely empty diagnostic is representable. Missing cleanup for actual
    # known roles is incomplete, never synthesized as a successful receipt.
    if identities-closed and any(op.get('result',{}).get('outcome')=='useful' for op in results['operations'] if op.get('result')is not None):_bad()
    if type(results['operations'])is not list or len(results['operations'])>4:_bad()
    seen=set();meters={};releases,recorded=_saved_execution(value)
    retained_cleanup={runtime._hash(item):item for item in cleanup['receipts']}
    for op in results['operations']:
        runtime._fields(op,('session','prepared','result','client','meter','elapsed_ms'))
        opened=contract.validate_session_opened(op['session']);prepared=contract.validate_prepared_context(op['prepared'],opened)
        envelope=prepared['envelope'];dispatch=envelope['dispatch_id']
        if dispatch in seen or envelope['runtime_sha256']!=digest:_bad()
        seen.add(dispatch)
        result=op['result']
        if result is not None:
            contract.validate_live_result(result)
            if any(result[key]!=envelope[key] for key in ('broker_id','session_id','dispatch_id','slot')) or result['envelope_sha256']!=contract.envelope_digest(envelope):_bad()
        meter=op['meter'];client=op['client']
        if meter is not None:
            validate_meter(meter)
            if any(meter[key]!=envelope[key] for key in ('session_id','dispatch_id','slot')) or meter['envelope_sha256']!=contract.envelope_digest(envelope):_bad()
            meters[runtime._hash(meter)]=meter
        if client is not None:
            validate_client_result(client)
            if client['dispatch_id']!=dispatch or client['slot']!=envelope['slot'] or client['envelope_sha256']!=contract.envelope_digest(envelope) or client['runtime_sha256']!=digest:_bad()
            for stream in ('stdout','stderr'):
                raw=value.get('client-'+dispatch+'.'+stream+'.bin')
                if type(raw)is not bytes or len(raw)!=client[stream+'_bytes'] or hashlib.sha256(raw).hexdigest()!=client[stream+'_sha256']:_bad()
            if meter is not None and client['meter']!=meter_summary(meter):_bad()
            ready=client['readiness']
            if ready is not None and (ready['client_sha256'] not in readies or ready['native_sha256']is not None and ready['native_sha256'] not in natives):_bad()
            if client['cleanup']is not None:_resolve_cleanup(client['cleanup'],None if ready is None else readies[ready['client_sha256']],retained_cleanup)
            if client['parser_receipt']is not None:
                receipt=client['parser_receipt']
                if receipt['readiness'] not in readies:_bad()
                _resolve_cleanup(receipt['cleanup'],readies[receipt['readiness']],retained_cleanup)
        actual=recorded.get(dispatch,{})
        for key in ('meter','forwarded_meter'):
            if key in actual and actual[key]!=meter:_bad()
        if 'forwarded_meter' in actual and actual.get('meter')!=actual['forwarded_meter']:_bad()
        for ready in actual.get('role_readiness',[]):
            if runtime._hash(ready) not in readies:_bad()
        for receipt in actual.get('cleanup',[]):
            if runtime._hash(receipt) not in retained_cleanup:_bad()
        capture=actual.get('capture')
        if capture is not None:
            if capture['slot']!=envelope['slot']:_bad()
            for stream in ('stdout','stderr'):
                retained=value.get('client-'+dispatch+'.'+stream+'.bin')
                if type(retained)is not bytes or retained!=_bytes(capture[stream+'_base64'],8192):_bad()
            if client is not None and (capture['exit_code']!=client['exit_code'] or capture['truncated']!=client['truncated']):_bad()
        _result_observation(result,client,meter,retained_cleanup)
        if result is not None and result['outcome']=='useful':
            if client is None or client['status']!='succeeded' or meter is None or not meter['delivery_known'] or meter['reason']!='complete' or capture is None or actual.get('meter')!=meter or actual.get('forwarded_meter')!=meter:_bad()
        if client is not None and (client['parsed']is not None or client['status']=='succeeded'):
            release=releases.get(dispatch)
            if release is None or meter is None:_bad()
            capture={'schema_version':'1','slot':envelope['slot'],'exit_code':client['exit_code'],'truncated':client['truncated']}
            for stream in ('stdout','stderr'):
                capture[stream+'_base64']=base64.b64encode(value['client-'+dispatch+'.'+stream+'.bin']).decode('ascii')
                capture[stream+'_bytes']=client[stream+'_bytes'];capture[stream+'_sha256']=client[stream+'_sha256']
            hashes={client['readiness']['client_sha256']}
            if client['parser_receipt']is not None:hashes.add(client['parser_receipt']['readiness'])
            children=[readies[h] for h in hashes if h in readies]
            child_cleanups=[client['cleanup']]
            if client['parser_receipt']is not None and client['parser_receipt']['cleanup'] not in child_cleanups:child_cleanups.append(client['parser_receipt']['cleanup'])
            selected_native=[] if client['readiness']['native_sha256']is None else [natives[client['readiness']['native_sha256']]]
            validate_dispatch_observations(prepared=prepared,release=release,scope=opened['scope'],capture=capture,
                client_result=client,meter=meter,child_readiness=children,child_cleanup=child_cleanups,
                native_readiness=selected_native,runtime_bundle=bundle)
    if set(recorded)-seen:_bad()
    _boundary_checks(value,bundle,readies,natives,retained_cleanup,meters)
    return json.loads(runtime._json(results))
