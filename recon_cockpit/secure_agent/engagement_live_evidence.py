"""Bounded, private saved evidence. Packaging and replay create no live authority.

Only the isolated parser is executable during inspection. The original raw files
remain held, immutable inputs; unsigned consistency is never called authenticity.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .engagement_live_contract import LiveError

CONTRACT_SHA256 = '9a626dd27e43ea94de9898185f6d4608a4f8f11df2f516053d43b68f7315614f'
GATES_SHA256 = '0e1295432df0d05107a8383602057f0764bd0342bb6dbd0e50defd74b72b164d'
MAX_BUNDLE = 16777216
MAX_REPORT = 8192
MAX_TRANSCRIPT_ROWS = 4096
CAPS = {'manifest.json':32768, 'initial-ledger.json':2097152,
        'final-ledger.json':2097152, 'recovery-ledger.json':2097152,
        'audit.jsonl':1048576, 'transcript.jsonl':2097152,
        'runtime.json':2097152, 'processes.json':1048576,
        'results.json':524288, 'cleanup.json':524288}
REQUIRED = {'audit.jsonl','transcript.jsonl','runtime.json','processes.json',
            'results.json','cleanup.json'}
MANIFEST_FIELDS = {'schema_version','contract_sha256','gates_sha256','evidence_class',
                   'proof_kind','case_id','configuration','review_mode','runtime_sha256',
                   'instrumentation','ledger_exports','transcript','dispatches','members',
                   'broker_instances'}
TIMINGS = ('review','admission','native','parser','cleanup','action')
KINDS = {'sealed_clock','sealed_fault','barrier','owned_peer','syscall_probe',
         'scripted_review','process_signal','external_admin'}
MISSING = {'initial_export','final_export','recovery_export','audit','transcript',
           'transcript_tail','runtime','process_identity','native_observation',
           'meter_settlement','raw_capture','parser_observation','cleanup',
           'unsettled_dispatch','case_predicate','diagnostic_only'}

PUBLIC_ERRORS = frozenset('engagement_live_' + suffix for suffix in (
    'invalid_input','limit_exceeded','timeout','cancelled','unavailable','unsupported_runtime',
    'invalid_runtime','invalid_role','invalid_channel','invalid_sequence','invalid_frame',
    'invalid_prepared','invalid_witness','stale_witness','approval_denied','approval_unavailable',
    'approval_unknown_or_replayed','audit_unavailable','audit_not_durable','foreign_owner',
    'session_unavailable','dispatch_replayed','revision_changed','revoked','window_not_open',
    'window_closed','clock_changed','allowance_exhausted','prerequisite_missing',
    'admission_unavailable','release_unavailable','meter_refused','parser_unavailable',
    'cleanup_incomplete','evidence_invalid','evidence_incomplete','output_exists'))


def public_error_code(value):
    return value if type(value) is str and value in PUBLIC_ERRORS else 'engagement_live_unavailable'


def _fail(code='evidence_invalid'):
    raise LiveError('engagement_live_' + code)


def _check(deadline):
    if time.monotonic() >= deadline:
        _fail('timeout')


def _deadline(value):
    if value is not None and (type(value) not in (int,float) or not math.isfinite(value)):
        _fail('invalid_input')
    result = time.monotonic() + 15
    if value is not None:
        result = min(result, value)
    _check(result)
    return result


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail()
    return value


def _integer(value, minimum=0, maximum=(1 << 64)-1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _choice(value, choices):
    if type(value) is not str or value not in choices:
        _fail()
    return value


def _hash(value):
    if type(value) is not str or re.fullmatch('[a-f0-9]{64}', value) is None:
        _fail()
    return value


def _uuid(value):
    if type(value) is not str:
        _fail()
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        _fail()
    if parsed.version != 4 or str(parsed) != value:
        _fail()
    return value


def _list(value, maximum):
    if type(value) is not list or len(value) > maximum:
        _fail('limit_exceeded' if type(value) is list else 'evidence_invalid')
    return value


def _tree(value, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    if depth > 12 or counter[0] > 262144:
        _fail('limit_exceeded')
    kind = type(value)
    if kind is dict:
        if any(type(k) is not str for k in value):
            _fail()
        for k,v in value.items():
            _tree(k,depth+1,counter); _tree(v,depth+1,counter)
    elif kind is list:
        for item in value:
            _tree(item,depth+1,counter)
    elif kind is str:
        try:
            value.encode('utf-8')
        except UnicodeError:
            _fail()
    elif kind is int:
        _integer(value,-255)
    elif kind not in (bool,type(None)):
        _fail()


def _canonical(value, cap=MAX_BUNDLE):
    _tree(value)
    try:
        raw = json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'),
                         allow_nan=False).encode('ascii')
    except (ValueError,TypeError,UnicodeError,RecursionError):
        _fail()
    if len(raw) > cap:
        _fail('limit_exceeded')
    return raw


def _pairs(pairs):
    value = {}
    for k,v in pairs:
        if k in value:
            _fail()
        value[k] = v
    return value


def _decode(raw, cap, *, canonical=True):
    if type(raw) is not bytes or len(raw) > cap:
        _fail('limit_exceeded' if type(raw) is bytes else 'evidence_invalid')
    try:
        value = json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,
                           parse_float=lambda _: _fail(),parse_constant=lambda _: _fail())
    except (ValueError,UnicodeError,RecursionError):
        _fail()
    _tree(value)
    if canonical and _canonical(value,cap) != raw:
        _fail()
    return value


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _inventory():
    # Fixed inventory is a pinned contract, never a caller-selected executable.
    path = Path(__file__).resolve().parents[2]/'docs/stage4-engagement-live-gates.json'
    try:
        with path.open('rb') as stream:
            raw = stream.read(1048577)
    except OSError:
        _fail('unavailable')
    if len(raw) > 1048576 or _sha(raw) != GATES_SHA256:
        _fail('invalid_runtime')
    return json.loads(raw)


def _case(case_id):
    data = _inventory()
    found = [r for r in data['cases'] if r['id'] == case_id and r['group'] in ('native_core','native_runtime')]
    if len(found) != 1:
        _fail()
    return found[0]


def _instrumentation(value, *, runtime=False):
    fields = {'kind','source_sha256','configuration_sha256'}
    if runtime:
        fields.add('configuration')
    _object(value,fields)
    _choice(value['kind'],KINDS)
    _hash(value['source_sha256']); _hash(value['configuration_sha256'])
    if runtime:
        config = _object(value['configuration'],{'case_id','variant','role'})
        for name in config:
            if type(config[name]) is not str or len(config[name]) > 128:
                _fail()
        if _sha(_canonical(config)) != value['configuration_sha256']:
            _fail()
    return value


def _manifest(value):
    m = _object(value,MANIFEST_FIELDS)
    if (m['schema_version'] != '1' or m['contract_sha256'] != CONTRACT_SHA256
            or m['gates_sha256'] != GATES_SHA256):
        _fail()
    _hash(m['runtime_sha256'])
    _choice(m['evidence_class'],{'production_run','owned_gate','diagnostic'})
    _choice(m['proof_kind'],{'live_operation','role_boundary'})
    if m['configuration'] not in ('A','B',None) or m['review_mode'] not in ('terminal','graphical_v1',None):
        _fail()
    for row in _list(m['instrumentation'],16):
        _instrumentation(row)
    if len({_canonical(row) for row in m['instrumentation']}) != len(m['instrumentation']):
        _fail()
    if m['evidence_class'] == 'production_run':
        if (m['case_id'] is not None or m['configuration'] is not None or m['instrumentation']
                or m['proof_kind'] != 'live_operation'):
            _fail()
    elif m['evidence_class'] == 'owned_gate':
        case = _case(m['case_id'])
        if m['proof_kind'] != ('live_operation' if case['group']=='native_core' else 'role_boundary'):_fail()
        if case.get('configuration') != m['configuration']:
            _fail()
        frontend = case.get('frontend')
        if frontend is not None and {'graphical':'graphical_v1'}.get(frontend,frontend) != m['review_mode']:
            _fail()
    elif m['case_id'] is not None:
        _fail()
    brokers,owners = set(),set()
    for row in _list(m['broker_instances'],2):
        _object(row,{'broker_id','ledger_owner_id'})
        b,o = _uuid(row['broker_id']),_uuid(row['ledger_owner_id'])
        if b in brokers or o in owners:
            _fail()
        brokers.add(b); owners.add(o)
    exports = _object(m['ledger_exports'],{'initial','final','recovery'})
    expected = set(REQUIRED)
    for phase,row in exports.items():
        _object(row,{'status','source','file','reason','broker_id'})
        if row['status'] == 'unavailable':
            if any(row[k] is not None for k in ('source','file','broker_id')):
                _fail()
            _choice(row['reason'],{'not_started','not_acknowledged','broker_lost','invalid_or_partial','not_applicable'})
        elif row['status'] == 'complete':
            source = 'postcleanup_readonly' if phase == 'recovery' else 'sealed_broker'
            if row['source'] != source or row['file'] != phase+'-ledger.json' or row['reason'] is not None:
                _fail()
            if phase == 'recovery':
                if row['broker_id'] is not None:
                    _fail()
            elif row['broker_id'] not in brokers:
                _fail()
            expected.add(row['file'])
        else:
            _fail()
    dispatches,pairs = set(),set()
    for row in _list(m['dispatches'],4):
        _object(row,{'dispatch_id','session_id','slot','stdout_file','stderr_file'})
        d,s = _uuid(row['dispatch_id']),_uuid(row['session_id'])
        _choice(row['slot'],{'http_identify','http_headers'})
        if d in dispatches or (s,row['slot']) in pairs:
            _fail()
        dispatches.add(d);pairs.add((s,row['slot']))
        if row['stdout_file'] is None and row['stderr_file'] is None:
            continue
        for stream in ('stdout','stderr'):
            name = 'client-'+d+'.'+stream+'.bin'
            if row[stream+'_file'] != name:
                _fail()
            expected.add(name)
    members = _list(m['members'],17)
    if len(members) < 6:
        _fail()
    names = []
    for row in members:
        _object(row,{'name','bytes','sha256'})
        if row['name'] not in expected:
            _fail()
        _integer(row['bytes'],0,CAPS.get(row['name'],8192));_hash(row['sha256'])
        names.append(row['name'])
    if names != sorted(expected):
        _fail()
    t = _object(m['transcript'],{'status','segments','reason'})
    _choice(t['status'],{'complete','partial','unavailable'})
    if t['status'] == 'complete':
        if t['reason'] is not None:
            _fail()
    else:
        _choice(t['reason'],{'not_started','broker_lost','invalid_or_partial','not_applicable'})
    offset,observed_brokers,observer_seen = 0,[],False
    for segment in _list(t['segments'],3):
        _object(segment,{'source','broker_id','offset','bytes','sha256','seals','status'})
        _integer(segment['offset'],0,2097152);_integer(segment['bytes'],0,2097152);_hash(segment['sha256'])
        if segment['offset'] != offset:
            _fail()
        offset += segment['bytes']
        if segment['source'] == 'broker_memfd':
            if observer_seen or segment['broker_id'] not in brokers or segment['broker_id'] in observed_brokers:
                _fail()
            observed_brokers.append(segment['broker_id'])
            _choice(segment['status'],{'sealed_complete','reaped_partial'})
            _integer(segment['seals'],0,15)
            if segment['status']=='sealed_complete' and segment['seals']!=15:
                _fail()
        elif segment['source']=='role_observer':
            if observer_seen or segment['broker_id'] is not None or segment['seals'] is not None:
                _fail()
            _choice(segment['status'],{'observer_complete','observer_partial'})
            observer_seen = True
        else:
            _fail()
        if t['status']=='complete' and segment['status'].endswith('partial'):
            _fail()
    if (t['status']=='unavailable' and (t['segments'] or offset)
            or offset > 2097152 or len(observed_brokers)>2):
        _fail()
    if observed_brokers != [r['broker_id'] for r in m['broker_instances'] if r['broker_id'] in observed_brokers]:
        _fail()
    if next(r['bytes'] for r in members if r['name']=='transcript.jsonl') != offset:
        _fail()
    if len(_canonical(m,32768))+sum(r['bytes'] for r in members)>MAX_BUNDLE:
        _fail('limit_exceeded')
    return m


def _transcript(m, raw):
    rows=[];tails=[]
    for index,segment in enumerate(m['transcript']['segments']):
        part=raw[segment['offset']:segment['offset']+segment['bytes']]
        if len(part)>(917504 if segment['source']=='broker_memfd' else 262144):
            _fail('limit_exceeded')
        if _sha(part)!=segment['sha256']:
            _fail()
        lines=part.split(b'\n')
        tail=lines.pop()
        if tail:
            if not segment['status'].endswith('partial'):
                _fail()
            tails.append(index)
        for sequence,line in enumerate(lines,1):
            if sequence>(1984 if segment['source']=='broker_memfd' else 128):
                _fail('limit_exceeded')
            if not line or len(rows)>=MAX_TRANSCRIPT_ROWS:
                _fail('limit_exceeded' if len(rows)>=MAX_TRANSCRIPT_ROWS else 'evidence_invalid')
            row=_decode(line,32768)
            _object(row,{'schema_version','broker_id','session_id','dispatch_id','observer_id',
                         'row_sequence','observed_at_ns','kind','data'})
            if row['schema_version']!='1' or type(row['row_sequence']) is not int or row['row_sequence']!=sequence:
                _fail()
            _uuid(row['observer_id']);_integer(row['observed_at_ns'],0,(1<<63)-1)
            for k in ('broker_id','session_id','dispatch_id'):
                if row[k] is not None:_uuid(row[k])
            if segment['source']=='broker_memfd' and row['broker_id']!=segment['broker_id']:
                _fail()
            if segment['source']=='broker_memfd' and row['kind']=='capability_projection':
                _fail()
            rows.append({'segment':index,'source':segment['source'],'row':row})
    return rows,tails


def _accepted_export(raw,deadline):
    from .engagement_dispatch_contract import decode_export, _deadline_context, DispatchLedgerError
    _check(deadline)
    try:
        with _deadline_context(min(deadline,time.monotonic()+2)):
            value=decode_export(raw)
    except DispatchLedgerError as error:
        suffix='timeout' if error.code.endswith('_timeout') else 'evidence_invalid'
        _fail(suffix)
    if _canonical(value,2097152)!=raw:_fail()
    _check(deadline)
    return value


def _load_members(manifest,members,deadline):
    _check(deadline)
    m=_manifest(_decode(_canonical(manifest,32768),32768))
    if type(members) is not dict or set(members)!={r['name'] for r in m['members']}:
        _fail()
    loaded={'manifest.json':m}
    for row in m['members']:
        _check(deadline)
        name=row['name'];raw=members[name]
        if type(raw) is not bytes or len(raw)!=row['bytes'] or _sha(raw)!=row['sha256']:
            _fail()
        if name.endswith('-ledger.json'):
            loaded[name]=_accepted_export(raw,deadline)
        elif name.endswith('.json'):
            loaded[name]=_decode(raw,CAPS[name])
        else:
            loaded[name]=raw
    for dispatch in m['dispatches']:
        if dispatch['stdout_file'] is not None:
            cap=8192 if dispatch['slot']=='http_identify' else 2048
            if len(members[dispatch['stdout_file']])+len(members[dispatch['stderr_file']])>cap:
                _fail('limit_exceeded')
    runtime=_object(loaded['runtime.json'],{'schema_version','runtime','instrumentation'})
    if runtime['schema_version']!='1' or _sha(_canonical(runtime['runtime'],2097152))!=m['runtime_sha256']:
        _fail()
    projected=[]
    for item in _list(runtime['instrumentation'],16):
        _instrumentation(item,runtime=True)
        projected.append({k:item[k] for k in ('kind','source_sha256','configuration_sha256')})
        if m['evidence_class']=='owned_gate':
            case=_case(m['case_id']);config=item['configuration']
            if config['case_id']!=m['case_id'] or config['variant']!=case['variant']:
                _fail()
    if projected!=m['instrumentation']:
        _fail()
    rows,tails=_transcript(m,members['transcript.jsonl'])
    _containers(loaded)
    return loaded,rows,tails


def _containers(loaded):
    processes=_object(loaded['processes.json'],{'schema_version','startup','readiness','native','boundary_observations','child_slots'})
    results=_object(loaded['results.json'],{'schema_version','operations','boundary_proofs','core_proofs'})
    cleanup=_object(loaded['cleanup.json'],{'schema_version','receipts','exports','recovery','supervisors'})
    for value in (processes,results,cleanup):
        if value['schema_version']!='1':_fail()
    _list(processes['startup'],94);_list(processes['readiness'],94);_list(processes['native'],4)
    _list(processes['child_slots'],24);_list(cleanup['supervisors'],4)
    kinds={'clock_boundary','creation_denial','descriptor_custody','image_identity','lifecycle',
           'meter_boundary','parser_absence','pin_mutation','socket_denial'}
    for observation in _list(processes['boundary_observations'],59):
        _object(observation,{'kind','observation'});_choice(observation['kind'],kinds)
        if type(observation['observation']) is not dict:_fail()
    for operation in _list(results['operations'],4):
        _object(operation,{'session','prepared','result','client','meter','elapsed_ms','host_capture'})
        for key in ('session','prepared'):
            if type(operation[key]) is not dict:_fail()
        for key in ('result','client','meter','host_capture'):
            if operation[key] is not None and type(operation[key]) is not dict:_fail()
        timing=_object(operation['elapsed_ms'],TIMINGS)
        for value in timing.values():
            if value is not None:_integer(value,0,122000)
    _list(results['boundary_proofs'],1)
    for proof in _list(results['core_proofs'],1):
        _object(proof,{'schema_version','case_id','variant','dispatch_ids','transcript_refs',
                      'before_state_sha256','after_state_sha256','recovery_state_sha256'})
        case=_case(proof['case_id'])
        if proof['schema_version']!='1' or case['group']!='native_core' or proof['variant']!=case['variant']:_fail()
        ids=_list(proof['dispatch_ids'],4)
        for value in ids:_uuid(value)
        if len(ids)!=len(set(ids)):_fail()
        refs=[]
        for ref in _list(proof['transcript_refs'],128):
            _object(ref,{'segment','row_sequence'});_integer(ref['segment'],0,2);_integer(ref['row_sequence'],1,4096)
            refs.append((ref['segment'],ref['row_sequence']))
        if len(refs)!=len(set(refs)):_fail()
        for key in ('before_state_sha256','after_state_sha256','recovery_state_sha256'):
            if proof[key] is not None:_hash(proof[key])
    _list(cleanup['receipts'],94)
    brokers={row['broker_id'] for row in loaded['manifest.json']['broker_instances']}
    for record in _list(cleanup['exports'],4):
        _object(record,{'broker_id','reference','host_descriptor','broker_descriptor'})
        if _uuid(record['broker_id']) not in brokers:_fail()
        for key in ('reference','host_descriptor','broker_descriptor'):
            if type(record[key]) is not dict:_fail()
    recovery=cleanup['recovery']
    if recovery is not None:
        _object(recovery,{'schema_version','source','owner_id','started_at_ns','finished_at_ns','read_only',
                         'store_identity','bytes','sha256','ledger_state_sha256','closed'})
        if recovery['schema_version']!='1' or recovery['source']!='postcleanup_readonly' or recovery['read_only'] is not True or recovery['closed'] is not True:_fail()
        _uuid(recovery['owner_id']);_hash(recovery['sha256']);_hash(recovery['ledger_state_sha256'])
        _integer(recovery['bytes'],1,2097152)
        for key in ('started_at_ns','finished_at_ns'):_integer(recovery[key],0,(1<<63)-1)
        if not recovery['started_at_ns']<=recovery['finished_at_ns']<=recovery['started_at_ns']+2000000000:_fail()
        _object(recovery['store_identity'],{'parent','directory','database'})
        for row in recovery['store_identity'].values():
            _object(row,{'device','inode','mode','uid','gid'})
            for key in ('device','inode'):_integer(row[key],0,(1<<64)-1)
            for key in ('mode','uid','gid'):_integer(row[key],0,(1<<32)-1)
        if recovery['owner_id'] in {r['ledger_owner_id'] for r in loaded['manifest.json']['broker_instances']}:_fail()
    if (loaded['manifest.json']['ledger_exports']['recovery']['status']=='complete') != (recovery is not None):_fail()


def _context(loaded,deadline):
    from .engagement_live_context import validate_live_context
    from .engagement_dispatch_contract import _deadline_context
    _check(deadline)
    # The pure context shares its original <=2s accepted-code budget. It may not
    # obtain a fresh nested export allowance beyond the outer inspection clock.
    with _deadline_context(min(deadline,time.monotonic()+2)):
        value=validate_live_context(loaded)
    _check(deadline)
    return value


def _authority(loaded,rows,deadline):
    from .engagement_live_witness import validate_evidence_transcript
    _check(deadline)
    value=validate_evidence_transcript(loaded,rows,deadline=deadline)
    _check(deadline)
    return value


def _reparse(loaded,deadline):
    from .engagement_live_parser import parse
    from .execution import ExecutionControl, ExecutionStopped
    results=loaded['results.json'];by_id={r['dispatch_id']:r for r in loaded['manifest.json']['dispatches']}
    count=0
    for operation in results['operations']:
        client=operation['client']
        if client is None or client['parsed'] is None:
            continue
        dispatch=by_id[operation['prepared']['envelope']['dispatch_id']]
        if dispatch['stdout_file'] is None:
            _fail()
        _check(deadline)
        try:
            parsed,_receipt=parse(tool_id=operation['prepared']['action']['tool_id'],
                raw=loaded[dispatch['stdout_file']],stderr=loaded[dispatch['stderr_file']],
                scope=operation['session']['scope'],truncated=client['truncated'],
                control=ExecutionControl(min(deadline,time.monotonic()+2)),
                runtime=loaded['runtime.json']['runtime'])
        except ExecutionStopped:
            _fail('timeout')
        if parsed!=client['parsed']:
            _fail()
        count+=1
        if count>4:_fail('limit_exceeded')
        _check(deadline)
    return count


def _report(loaded,context,authority,manifest_sha,parser_count,tails):
    # These summaries are independently derived by the strict pure validators,
    # never read from an unvalidated caller report or a supplied case_passed bit.
    m=loaded['manifest.json']
    _object(authority,{'missing_evidence','linkage'})
    missing=set(authority['missing_evidence'])
    if not missing<=MISSING:_fail()
    if m['evidence_class']=='diagnostic':missing.add('diagnostic_only')
    operations=[]
    dispatch_rows={d['dispatch_id']:d for d in m['dispatches']}
    for op in loaded['results.json']['operations']:
        result=op['result'];client=op['client'];meter=op['meter'];envelope=op['prepared']['envelope']
        dispatch_id=envelope['dispatch_id'];dispatch=dispatch_rows[dispatch_id]
        observed=authority['linkage']['dispatches'][dispatch_id]
        counts={k:None for k in ('connections','request_bytes','response_bytes','stdout_bytes','stderr_bytes')}
        if meter is not None and meter['finished_at_ns'] is not None:
            for key,source in [('connections','accepted_connections'),('request_bytes','received_request_bytes'),('response_bytes','sent_response_bytes')]:
                counts[key]=meter[source]
        if dispatch['stdout_file'] is not None:
            counts['stdout_bytes']=len(loaded[dispatch['stdout_file']]);counts['stderr_bytes']=len(loaded[dispatch['stderr_file']])
        timing=_object(op['elapsed_ms'],TIMINGS)
        for v in timing.values():
            if v is not None:_integer(v,0,122000)
        if result is None:
            outcome,reason='unresolved',None
            missing.add('unsettled_dispatch')
        else:
            outcome,reason=result['outcome'],result['reason']
        operations.append({'dispatch_id':dispatch_id,'session_id':envelope['session_id'],
             'slot':envelope['slot'],'outcome':outcome,'error_code':reason,
             'reservation_observed':observed['reservation_observed'],
             'go_observed':observed['go_observed'],
             'counts':counts,'elapsed_ms':dict(timing)})
    by_id={op['dispatch_id']:op for op in operations}
    if len(by_id)!=len(operations) or set(by_id)!={d['dispatch_id'] for d in m['dispatches']}:
        _fail()
    operations=[by_id[d['dispatch_id']] for d in m['dispatches']]
    passed=_evaluate_case(loaded,context,authority['linkage']) if m['evidence_class']=='owned_gate' else None
    if m['evidence_class']=='owned_gate' and type(passed) is not bool:_fail()
    if m['evidence_class']=='owned_gate' and not passed:missing.add('case_predicate')
    number=int(m['case_id'][-2:]) if passed and m['case_id'].startswith('S42C-N') else None
    recovered=loaded['cleanup.json']['recovery'] is not None
    startup_negative=number in (10,11,12,28,41) and recovered
    crash_negative=number in (42,43,44,45,46,47,48,49,50,51,52,53,54) and recovered
    # A proven crash can resolve the *case* without inventing a last broker ACK.
    # Missing required direct witness/channel links are never removed here.
    # A case can prove a negative at an earlier actual layer without a broker
    # terminal acknowledgment. Preserve those operations as unresolved; only
    # the selected gate's completeness is established by its strict predicate.
    expected_negative=number in {1,2,3,8,9,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,
        30,31,32,33,34,35,36,37,38,39,40,42,43,44,45,46,47,48,49,50,51,52,53,54}
    if expected_negative:
        selected=set(loaded['results.json']['core_proofs'][0]['dispatch_ids'])
        unresolved={op['dispatch_id'] for op in operations if op['outcome']=='unresolved'}
        if unresolved<=selected:missing.discard('unsettled_dispatch')
    if crash_negative:missing.discard('final_export')
    if tails and not crash_negative:missing.add('transcript_tail')
    if m['proof_kind']=='live_operation':
        if not operations and not startup_negative:missing.add('unsettled_dispatch')
        if m['ledger_exports']['initial']['status']!='complete' and not startup_negative:missing.add('initial_export')
        if m['ledger_exports']['final']['status']!='complete' and not (startup_negative or crash_negative):missing.add('final_export')
        if m['transcript']['status']!='complete' and not (startup_negative or crash_negative):missing.add('transcript')
    audit_closure=_audit_closure(loaded)
    cleanup=_cleanup_report(loaded,audit=audit_closure)
    if not _all_reaped(loaded,audit=audit_closure) or cleanup['status']=='incomplete':missing.add('cleanup')
    report={'schema_version':'1','contract_sha256':CONTRACT_SHA256,'gates_sha256':GATES_SHA256,
        'manifest_sha256':manifest_sha,'evidence_class':m['evidence_class'],'proof_kind':m['proof_kind'],
        'case_id':m['case_id'],'case_passed':passed,'status':'incomplete' if missing else 'complete',
        'operation_count':len(operations),'useful_operation_count':sum(r['outcome']=='useful' for r in operations),
        'operations':operations,'ledger_exports':{k:v['status'] for k,v in m['ledger_exports'].items()},
        'transcript_status':m['transcript']['status'],'cleanup':cleanup,
        'parser_replay_count':parser_count,'missing_evidence':sorted(missing),
        'authority_restored':False,'live_execution_started_by_inspection':False,
        'broker_instance_count':len(m['broker_instances'])}
    if len(missing)>16:_fail('limit_exceeded')
    _canonical(report,MAX_REPORT)
    return report


def _core_candidate(variant, prepared, session):
    """The finite rejected-input stimuli; never submitted by this reader.

    Test producers use these same immutable values and retain the digest of the
    actual attempted input in an explicitly labelled observer phase record.
    """
    from copy import deepcopy
    from ipaddress import IPv4Address
    from . import configurable_contract
    p=deepcopy(prepared)
    if variant=='foreign_engagement':
        old=uuid.UUID(p['envelope']['engagement_id'])
        p['envelope']['engagement_id']=str(uuid.UUID(int=old.int^1,version=4))
    elif variant=='foreign_revision':p['envelope']['revision']+=1
    elif variant=='foreign_session_owner':
        old=uuid.UUID(p['envelope']['ledger_owner_id'])
        p['envelope']['ledger_owner_id']=str(uuid.UUID(int=old.int^1,version=4))
    elif variant=='undeclared_target':p['action']['target']=str(IPv4Address(int(IPv4Address(p['action']['target']))^1))
    elif variant=='wrong_port':p['action']['parameters']['port']=p['action']['parameters']['port']^1
    elif variant=='wrong_method':p['action']['parameters']['method']='POST'
    elif variant=='wrong_path':p['action']['parameters']['path']='/outside'
    elif variant=='ssh_action_denied':p['action']=configurable_contract.action(session['scope'],3)
    else:_fail()
    return p


def _core_history(loaded,proof):
    """Resolve selectors into already replay-validated immutable event rows."""
    histories=[loaded[name] for name in ('initial-ledger.json','final-ledger.json','recovery-ledger.json') if name in loaded]
    if not histories:return None
    final=max(histories,key=lambda value:len(value['events']))
    states={row['receipt']['state_sha256']:row for row in final['events']}
    before=states.get(proof['before_state_sha256']);after=states.get(proof['after_state_sha256'])
    recovery=states.get(proof['recovery_state_sha256'])
    if before is None or after is None or before['sequence']>after['sequence']:return None
    if after!=final['events'][-1]:return None
    if 'recovery-ledger.json' in loaded:
        if recovery!=loaded['recovery-ledger.json']['events'][-1]:return None
    elif proof['recovery_state_sha256'] is not None:return None
    return final,before,after,recovery


def _core_calls(rows):
    """Observed ingress intervals, preserving the actual observer/channel pair."""
    requests={};calls=[]
    for wrapped in rows:
        row=wrapped['row']
        if wrapped['source']!='role_observer' or row['kind']!='protocol':continue
        data=row['data'];frame=data['frame']
        if data['channel_role']!='ingress' or frame['operation']!='DISPATCH':continue
        body=frame['body'];key=(row['observer_id'],frame['channel_id'])
        if data['direction']=='sent' and 'prepared_sha256' in body:
            requests[(*key,frame['sequence'])]=(row,body)
        elif data['direction']=='received' and body.get('status') in ('ok','refused'):
            request=requests.get((*key,body['request_sequence']))
            if request is None or row['observed_at_ns']<request[0]['observed_at_ns']:continue
            calls.append({'channel':frame['channel_id'],'observer':row['observer_id'],
                'start':request[0]['observed_at_ns'],'end':row['observed_at_ns'],
                'request':request[1],'reply':body})
    return calls


def _core_losing_call(call,operations,number):
    """Recognize the actual losing wire reply without rewriting its status."""
    from . import engagement_live_contract as contract
    expected={'engagement_live_allowance_exhausted'} if number==24 else {
        'engagement_live_dispatch_replayed','engagement_live_approval_unknown_or_replayed'}
    reply=call['reply']
    if reply['status']=='refused':return reply['code'] in expected
    if number!=24 or reply['status']!='ok' or reply['code'] is not None:return False
    actual=reply['data']
    if type(actual)is not dict:return False
    try:contract.validate_live_result(actual)
    except LiveError:return False
    matched=[op for op in operations if contract.prepared_digest(op['prepared'])==call['request']['prepared_sha256']]
    if len(matched)!=1:return False
    op=matched[0];env=op['prepared']['envelope']
    return (op['result']==actual and actual['outcome']=='denied' and actual['reason'] in expected and
        all(actual[key] is None for key in ('admission','release','completion','observation',
                                           'client_result_sha256','cleanup_sha256')) and
        all(actual[key]==env[key] for key in ('broker_id','session_id','dispatch_id','slot')) and
        actual['envelope_sha256']==contract.envelope_digest(env))


def _startup_guard_refusal(loaded,rows,final,number,entry):
    """Attribute natural startup refusal to the actual sealed business guard.

    The host projects a bounded diagnostic received from that worker. It is not
    a broker-memfd row or READY, and its timestamp is after actual cleanup.
    """
    if number not in (10,11,12,28,41):return False
    case_id='S42C-N'+str(number).zfill(2);variant=_case(case_id)['variant']
    reason='engagement_live_'+('invalid_prepared' if number in (10,11,12) else
        'window_not_open' if number==28 else 'revoked')
    guard='validate_live_roe' if number in (10,11,12) else '_check_current'
    configured={item['source_sha256'] for item in loaded['runtime.json']['instrumentation'] if
        item['kind']=='sealed_fault' and item['configuration']=={'case_id':case_id,'variant':variant,'role':'broker'}}
    sources={item['module']:item['sha256'] for item in loaded['runtime.json']['runtime']['sources']}
    if sources.get('engagement_live_broker_worker') not in configured:return False
    if entry['role']!='broker' or entry['stage']!='entry':return False
    payload=entry['payload'];processes=_cleanup_processes(loaded)
    if processes is None:return False
    actual=[item for item in processes if (item['pid'],item['start_time_ticks'])==
        (payload['pid'],payload['start_time_ticks'])]
    if len(actual)!=1 or actual[0]['role']!='broker' or not actual[0]['pin_verified'] or not actual[0]['exit_observed'] or not actual[0]['reaped_observed'] or actual[0]['wrapper_returncode']!=78 or actual[0]['signal_attempted'] is not False:return False
    finishes=[receipt['finished_at_ns'] for receipt in loaded['cleanup.json']['receipts'] if
        receipt['descriptors_closed'] and actual[0] in receipt['processes']]
    if not finishes:return False
    roe=final['revisions'][-1]['roe'];roe_sha=_sha(_canonical(roe))
    admitted={item['broker_id'] for item in loaded['manifest.json']['broker_instances']}
    matched=[]
    for observed in rows:
        row=observed['row'];data=row['data']
        if (observed['source']!='role_observer' or row['kind']!='phase' or
            row['broker_id'] in admitted or row['observer_id']!=row['broker_id'] or
            row['session_id'] is not None or row['dispatch_id'] is not None or
            data['phase']!='prepare' or data['stage']!='refused' or data['reason']!=reason or
            data['clock'] is None):continue
        clock=data['clock']
        marker={'schema_version':'1','case_id':case_id,'guard':guard,'roe_sha256':roe_sha,
            'code':reason,'clock':clock}
        if data['related_sha256']!=_sha(_canonical(marker)):continue
        if not entry['sampled_at_ns']<=clock['mono_before_ns']<=clock['mono_after_ns']<=min(finishes)<=row['observed_at_ns']:continue
        if number==28:
            from .engagement_dispatch_contract import _window
            if clock['utc_ns']>=_window(roe)[0]:continue
        matched.append(row)
    return len(matched)==1


def _restart_refusal(loaded,rows,operations,final,number):
    """Retained consumed authority cannot be revived by a later caller."""
    from . import engagement_live_contract as contract
    instances=loaded['manifest.json']['broker_instances']
    if number not in (43,44,52,53,54) or len(instances)!=(1 if number==53 else 2):return False
    if len(operations)!=1:return False
    op=operations[0];prepared=op['prepared'];env=prepared['envelope'];first=instances[0]
    if env['broker_id']!=first['broker_id'] or env['ledger_owner_id']!=first['ledger_owner_id']:return False
    reservations=[event for event in final['events'] if event['request']['operation']=='reserve' and
        event['receipt']['dispatch_id']==env['dispatch_id']]
    if len(reservations)!=1:return False
    original=reservations[0]
    readiness={row['worker_ready']['worker_id']:row for row in loaded['processes.json']['readiness'] if row['role']=='broker'}
    if any(row['broker_id'] not in readiness for row in instances):return False
    receipts=loaded['cleanup.json']['receipts']
    def actual_cleanup(ready,returncode=None,before=None,after=None):
        pin=ready['parent_observation']['payload']
        return any(receipt['descriptors_closed'] and
            (before is None or receipt['finished_at_ns']<=before) and
            (after is None or receipt['finished_at_ns']>=after) and any(
                p['role']=='broker' and p['pid']==pin['pid'] and p['start_time_ticks']==pin['start_time_ticks'] and
                p['pin_verified'] and p['exit_observed'] and p['reaped_observed'] and
                (returncode is None or p['wrapper_returncode']==returncode)
                for p in receipt['processes']) for receipt in receipts)
    target=instances[-1];target_ready=readiness[target['broker_id']]
    if number!=53:
        if first['ledger_owner_id']==target['ledger_owner_id'] or first['broker_id']==target['broker_id']:return False
        if not actual_cleanup(readiness[first['broker_id']],before=target_ready['parent_observation']['sampled_at_ns']):return False
        sessions=[event for event in final['events'] if event['request']['operation']=='session' and
            event['request']['body']['owner_id']==target['ledger_owner_id']]
        if len(sessions)!=1 or sessions[0]['sequence']<=original['sequence']:return False
        cutoff=sessions[0]['sequence'];started=target_ready['parent_observation']['sampled_at_ns']
    else:
        completed=[event for event in final['events'] if event['request']['operation']=='complete' and
            event['receipt']['dispatch_id']==env['dispatch_id']]
        if len(completed)!=1:return False
        cutoff=completed[0]['sequence'];started=0
    if any(event['request']['operation']=='reserve' for event in final['events'][cutoff:]):return False
    if any(event['receipt']['usage']!=final['events'][-1]['receipt']['usage'] for event in final['events'][cutoff-1:]):return False
    target_rows=[entry for entry in rows if entry['row']['broker_id']==target['broker_id'] and
        entry['row']['observer_id']==target['broker_id'] and entry['row']['observed_at_ns']>=started]
    if number!=53 and any(entry['source']=='broker_memfd' and entry['row']['kind']=='protocol' and
        entry['row']['data']['frame']['operation'] in ('GO','ARM') for entry in target_rows):return False
    phases=[entry['row'] for entry in target_rows if entry['source']=='role_observer' and entry['row']['kind']=='phase' and
        (entry['row']['dispatch_id']==env['dispatch_id'] if number==53 else
         entry['row']['dispatch_id'] is None and entry['row']['session_id'] is None)]
    if number in (43,44,52):
        digest=contract.prepared_digest(prepared)
        requests=[entry['row'] for entry in target_rows if entry['source']=='broker_memfd' and entry['row']['kind']=='protocol' and
            entry['row']['data']['channel_role']=='ingress' and entry['row']['data']['direction']=='received' and
            entry['row']['data']['frame']['operation']=='DISPATCH' and
            entry['row']['data']['frame']['body'].get('prepared_sha256')==digest]
        replies=[entry['row'] for entry in target_rows if entry['source']=='broker_memfd' and entry['row']['kind']=='protocol' and
            entry['row']['data']['channel_role']=='ingress' and entry['row']['data']['direction']=='sent' and
            entry['row']['data']['frame']['operation']=='DISPATCH' and
            entry['row']['data']['frame']['body'].get('status')=='refused' and
            entry['row']['data']['frame']['body'].get('code')=='engagement_live_dispatch_replayed']
        return actual_cleanup(target_ready) and any(
            req['data']['frame']['channel_id']==rep['data']['frame']['channel_id'] and
            req['data']['frame']['sequence']==rep['data']['frame']['body']['request_sequence'] and
            req['observed_at_ns']<=rep['observed_at_ns'] and any(
                phase['data']['phase']=='prepare' and phase['data']['stage']=='refused' and
                phase['data']['related_sha256']==digest and phase['data']['reason']=='engagement_live_dispatch_replayed' and
                phase['observed_at_ns']>=rep['observed_at_ns'] for phase in phases)
            for req in requests for rep in replies)
    stops=[entry['row'] for entry in target_rows if entry['source']=='broker_memfd' and entry['row']['kind']=='protocol' and
        entry['row']['data']['channel_role']=='lifecycle' and entry['row']['data']['direction']=='sent' and
        entry['row']['data']['frame']['operation']=='BROKER_STOP']
    if number==53:
        digest=contract.prepared_digest(prepared)
        return any(stop['data']['frame']['body']['reason']=='engagement_live_cancelled' and
            actual_cleanup(target_ready,after=stop['observed_at_ns']) for stop in stops) and any(
            phase['data']['phase']=='prepare' and phase['data']['stage']=='refused' and phase['data']['related_sha256']==digest and
            phase['data']['reason'] in {'engagement_live_cancelled','engagement_live_session_unavailable','engagement_live_unavailable',
                'engagement_live_invalid_channel'} for phase in phases)
    old_go=[entry['row'] for entry in rows if entry['source']=='broker_memfd' and entry['row']['broker_id']==first['broker_id'] and
        entry['row']['observer_id']==first['broker_id'] and entry['row']['dispatch_id']==env['dispatch_id'] and
        entry['row']['kind']=='protocol' and entry['row']['data']['channel_role']=='launcher' and
        entry['row']['data']['direction']=='sent' and entry['row']['data']['frame']['operation']=='GO']
    if len(old_go)!=1 or not actual_cleanup(target_ready,returncode=0):return False
    digest=_sha(_canonical(old_go[0]['data']['frame']))
    begins=[phase for phase in phases if phase['data']['phase']=='go' and phase['data']['stage']=='begin' and phase['data']['related_sha256']==digest]
    ends=[phase for phase in phases if phase['data']['phase']=='go' and phase['data']['stage']=='end' and phase['data']['related_sha256']==digest]
    refused=[phase for phase in phases if phase['data']['phase']=='go' and phase['data']['stage']=='refused' and
        phase['data']['related_sha256']==digest and phase['data']['reason'] in {'engagement_live_invalid_frame',
            'engagement_live_invalid_channel','engagement_live_session_unavailable','engagement_live_unavailable','engagement_live_cancelled'}]
    return any(begin['observed_at_ns']<=end['observed_at_ns']<=failure['observed_at_ns'] and any(
        stop['data']['frame']['body']['reason']=='engagement_live_invalid_frame' and stop['observed_at_ns']>=begin['observed_at_ns'] and
        actual_cleanup(target_ready,returncode=0,after=stop['observed_at_ns']) for stop in stops) for begin in begins for end in ends for failure in refused)


def _logical_deadline_fault(loaded,rows,operation,phase,case_id):
    """Fixed owned clock-input proof; actual observation times remain OS times.

    Context and authority replay have already validated the source inventory,
    channel rows, native identities and cleanup. This predicate additionally
    binds the injected check to those actual observations for this dispatch.
    """
    from . import engagement_live_contract as contract
    variants={'S42C-N34':('deadline_during_native','native_observation'),
              'S42C-N35':('deadline_during_result_cleanup','cleanup')}
    if case_id not in variants:return False
    variant,target=variants[case_id];prepared=operation['prepared'];env=prepared['envelope']
    row=phase['row'];data=row['data'];original=env['action_deadline_ns'];anchor=env['clock_anchor']
    expected={'mono_before_ns':original,'mono_after_ns':original,
              'utc_ns':anchor['utc_ns']+original-anchor['mono_after_ns']}
    if (phase['source']!='broker_memfd' or row['kind']!='phase' or
        row['broker_id']!=env['broker_id'] or row['observer_id']!=env['broker_id'] or
        row['session_id']!=env['session_id'] or row['dispatch_id']!=env['dispatch_id'] or
        data['phase']!=target or data['stage']!='refused' or data['reason']!='engagement_live_timeout' or
        data['original_deadline_ns']!=original or data['clock']!=expected or
        data['related_sha256']!=contract.prepared_digest(prepared)):return False
    configured={item['source_sha256'] for item in loaded['runtime.json']['instrumentation'] if
        item['configuration']=={'case_id':case_id,'variant':variant,'role':'launcher'}}
    sources={item['module']:item['sha256'] for item in loaded['runtime.json']['runtime']['sources']}
    if not all(sources.get(module) in configured for module in
        ('engagement_live_launcher_worker','engagement_live_broker_worker')):return False
    packets=[]
    for entry in rows:
        observed=entry['row']
        if (entry['source']=='broker_memfd' and observed['kind']=='protocol' and
            observed['broker_id']==env['broker_id']==observed['observer_id'] and
            observed['session_id']==env['session_id'] and observed['dispatch_id']==env['dispatch_id'] and
            observed['data']['channel_role']=='launcher'):packets.append(observed)
    native=[item for item in packets if item['data']['direction']=='received' and
        item['data']['frame']['operation']=='NATIVE_OBSERVED' and
        item['observed_at_ns']<=row['observed_at_ns'] and
        item['data']['frame']['body'] in loaded['processes.json']['native']]
    released=[item for item in packets if item['data']['direction']=='sent' and
        item['data']['frame']['operation']=='GO' and item['observed_at_ns']<=row['observed_at_ns'] and
        item['data']['frame']['body']['prepared_sha256']==contract.prepared_digest(prepared)]
    if len(native)!=1 or len(released)!=1 or native[0]['observed_at_ns']<released[0]['observed_at_ns']:return False
    actual=native[0]['data']['frame']['body']['parent_observation']['payload']
    cleanups=[receipt for receipt in loaded['cleanup.json']['receipts'] if
        any(item['pid']==actual['pid'] and item['start_time_ticks']==actual['start_time_ticks'] and
            item['pin_verified'] and item['exit_observed'] and item['reaped_observed']
            for item in receipt['processes']) and receipt['descriptors_closed'] and
        receipt['finished_at_ns']>=row['observed_at_ns']]
    if not cleanups:return False
    if case_id=='S42C-N35':
        # collect() publishes its retained capture after the actual close hook.
        # No earlier wire capture or elapsed wall-time expiry is claimed.
        captures=[item for item in packets if item['data']['direction']=='received' and
            item['data']['frame']['operation']=='OBSERVATION' and
            item['data']['frame']['body']['kind']=='capture' and
            item['observed_at_ns']>=row['observed_at_ns']]
        if len(captures)!=1:return False
    return True


def _evaluate_core_proof(loaded, proof, linkage):
    """Finite predicates over retained observations, never expected-result flags.

    Inputs have already passed the pure context and authority replay validators.
    Selectors resolve into actual transcript rows. Unselected controls must be
    durably complete before the chosen interval; extra winners cannot be hidden.
    Missing physical observations fail closed, including negatives.
    """
    from . import engagement_live_contract as contract
    number=int(proof['case_id'].removeprefix('S42C-N'))
    variant=proof['variant'];m=loaded['manifest.json']
    all_operations=loaded['results.json']['operations'];all_ids=[op['prepared']['envelope']['dispatch_id'] for op in all_operations]
    if not set(proof['dispatch_ids'])<=set(all_ids) or not _all_reaped(loaded):return False
    operations=[op for op in all_operations if op['prepared']['envelope']['dispatch_id'] in proof['dispatch_ids']]
    ids=[op['prepared']['envelope']['dispatch_id'] for op in operations]
    if proof['dispatch_ids']!=ids:return False
    if not loaded['cleanup.json']['receipts']:return False
    if any(not row['descriptors_closed'] or row['finished_at_ns']>row['started_at_ns']+2000000000
           for row in loaded['cleanup.json']['receipts']):return False
    if not any(row['configuration']['case_id']==proof['case_id'] and row['configuration']['variant']==variant
               for row in loaded['runtime.json']['instrumentation']):return False
    rows,_tails=_transcript(m,loaded['transcript.jsonl'])
    by_ref={(row['segment'],row['row']['row_sequence']):row for row in rows}
    selected=[]
    for ref in proof['transcript_refs']:
        row=by_ref.get((ref['segment'],ref['row_sequence']))
        if row is None:return False
        selected.append(row)
    if not selected:return False
    history=_core_history(loaded,proof)
    if history is None:return False
    final,before,after,recovery=history
    scopes=_inventory().get('native_fixture_scopes',{})
    expected_scope=scopes.get(m['configuration'])
    if expected_scope is None:return False
    if any(op['session']['scope']!=expected_scope for op in all_operations):return False
    if any(row['roe']['scope']!=expected_scope for row in final['revisions']):return False
    for op in all_operations:
        did=op['prepared']['envelope']['dispatch_id']
        if did in ids:continue
        prior=[row for row in final['events'] if row['receipt']['dispatch_id']==did]
        if {row['request']['operation'] for row in prior}!={'reserve','complete'} or any(
                row['sequence']>before['sequence'] for row in prior):return False
    changes=final['events'][before['sequence']:after['sequence']]
    links=[linkage['dispatches'][did] for did in ids]
    reserves=[r for r in changes if r['request']['operation']=='reserve']
    if any(row['receipt']['dispatch_id'] not in ids for row in reserves):return False
    revokes=[r for r in changes if r['request']['operation']=='revoke']
    revisions=[r for r in changes if r['request']['operation']=='revise']
    usage_same=before['receipt']['usage']==after['receipt']['usage']
    go=[r for r in rows if r['row']['kind']=='protocol' and
        r['row']['data']['channel_role']=='launcher' and r['row']['data']['frame']['operation']=='GO' and
        r['row']['data']['frame']['body']['reservation_sequence']>before['sequence']]
    go_ids={r['row']['dispatch_id'] for r in go}
    if not go_ids<=set(ids):return False
    phases=[r for r in selected if r['row']['kind']=='phase']
    refused=[r for r in phases if r['row']['data']['stage']=='refused']
    cleanup_processes=_cleanup_processes(loaded)
    if cleanup_processes is None:return False
    roles={p['role'] for p in cleanup_processes}
    if 'broker' not in roles:return False
    # An event source is a retained observed role, not an arbitrary host label.
    broker_rows=[r for r in rows if r['source']=='broker_memfd']
    complete_broker=bool(m['broker_instances']) and all(any(s['source']=='broker_memfd' and
        s['broker_id']==b['broker_id'] and s['status']=='sealed_complete' for s in m['transcript']['segments'])
        for b in m['broker_instances'])
    def phase(name,stage=None,reason=None,digest=None,source=None):
        return [r for r in phases if r['row']['data']['phase']==name
            and (stage is None or r['row']['data']['stage']==stage)
            and (reason is None or r['row']['data']['reason']=='engagement_live_'+reason)
            and (digest is None or r['row']['data']['related_sha256']==digest)
            and (source is None or r['source']==source)]
    def denied(reason=None):
        if go_ids or not usage_same or reserves or not complete_broker:return False
        candidates=[r for r in refused if reason is None or r['row']['data']['reason']=='engagement_live_'+reason]
        for attempt in candidates:
            code=attempt['row']['data']['reason']
            for observed in rows:
                row=observed['row']
                if row['dispatch_id']!=attempt['row']['dispatch_id'] or row['kind']!='protocol':continue
                data=row['data'];body=data['frame']['body']
                if data['channel_role']!='ingress' or not isinstance(body,dict):continue
                actual=body.get('code') if body.get('status')=='refused' else (
                    body.get('data',{}).get('reason') if body.get('status')=='ok' and isinstance(body.get('data'),dict) else None)
                if actual==code and row['observed_at_ns']<=attempt['row']['observed_at_ns']:return True
        return False
    def useful_prefix():
        if len(operations)!=2 or not complete_broker:return False
        if [op['prepared']['envelope']['slot'] for op in operations]!=['http_identify','http_headers']:return False
        if len({op['prepared']['envelope']['session_id'] for op in operations})!=1:return False
        for op,link in zip(operations,links):
            result=op['result'];client=op['client'];meter=op['meter']
            if result is None or result['outcome']!='useful' or client is None or client['status']!='succeeded':return False
            if meter is None or meter['reason']!='complete' or meter['delivery_known'] is not True:return False
            if link['reservation_observed'] is not True or link['go_observed'] is not True:return False
            if link['approval'] is None or link['audit'] is None or link['completion'] is None:return False
        return len(reserves)==2 and go_ids==set(ids)
    def changed_refusal(events,reason,after_review=False):
        if not events or go_ids or reserves or not usage_same or not complete_broker:return False
        event=events[-1]
        commits=phase('watch','end',digest=event['receipt']['state_sha256'])
        if not commits:return False
        if not denied(reason):
            # The periodic watch can close ingress before the host attempts
            # another call. Retain that actual failure layer, not a fabricated
            # refusal reply on an already closed channel.
            watches=[r for r in selected if r['source']=='broker_memfd' and r['row']['kind']=='watch' and
                r['row']['data']['status']=='changed' and r['row']['data']['reason']=='engagement_live_'+reason and
                r['row']['data']['ledger_sequence']==event['sequence'] and
                r['row']['data']['ledger_state_sha256']==event['receipt']['state_sha256']]
            stops=[r for r in rows if r['source']=='broker_memfd' and r['row']['kind']=='protocol' and
                r['row']['data']['channel_role']=='lifecycle' and r['row']['data']['direction']=='sent' and
                r['row']['data']['frame']['operation'] in ('SESSION_STOP','BROKER_STOP') and
                r['row']['data']['frame']['body']['reason']=='engagement_live_'+reason]
            attempts=[r for r in refused if r['source']=='role_observer' and r['row']['dispatch_id'] in ids and
                r['row']['data']['reason'] in {'engagement_live_'+reason,'engagement_live_session_unavailable',
                    'engagement_live_unavailable','engagement_live_invalid_channel'} and
                r['row']['observed_at_ns']>=commits[0]['row']['observed_at_ns']]
            if not watches or not stops or not attempts:return False
        if after_review and not any(r['row']['kind']=='capability_projection' and
            r['row']['data']['operation']=='REVIEW' and r['row']['data']['reply'] is not None and
            r['row']['observed_at_ns']<commits[0]['row']['observed_at_ns'] for r in rows):return False
        return True
    def actual_progress(kind):
        return any(any(row['kind']==kind and row['actual_bytes']>0
            for row in progress_events(op)) for op in operations)
    def progress_events(op):
        if op['meter'] is not None:return op['meter']['events']
        if number not in (40,45,46):return []
        env=op['prepared']['envelope'];did=env['dispatch_id']
        projected=[row for row in rows if row['source']=='broker_memfd' and row['row']['kind']=='meter' and
                   row['row']['dispatch_id']==did]
        if not projected or len(projected)>64:return []
        configured={row['source_sha256'] for row in loaded['runtime.json']['instrumentation'] if
            row['configuration']['case_id']==proof['case_id'] and row['configuration']['variant']==variant}
        source_hashes={row['module']:row['sha256'] for row in loaded['runtime.json']['runtime']['sources']}
        if not all(source_hashes.get(module) in configured for module in
            ('engagement_live_endpoint_worker','engagement_live_broker_worker')):return []
        released=[row for row in go if row['row']['dispatch_id']==did]
        if len(released)!=1:return []
        sent_at=released[0]['row']['observed_at_ns']
        ready=[row for row in loaded['processes.json']['readiness'] if row['role']=='endpoint' and
               row['parent_observation']['sampled_at_ns']<=sent_at]
        if not ready:return []
        # A fixed sealed test frame retains a prefix of actual endpoint events.
        # It is never a final METER, a settlement, or proof of final byte totals.
        events=[];received=sent=accepted=0;previous=sent_at;closed=False
        request_cap,response_cap=(4096,4096) if env['slot']=='http_identify' else (256,2048)
        from .engagement_live_runtime import validate_meter_event
        for sequence,entry in enumerate(projected,1):
            row=entry['row'];event=validate_meter_event(row['data']);kind=event['kind']
            if (row['broker_id']!=env['broker_id'] or row['observer_id']!=env['broker_id'] or
                row['session_id']!=env['session_id'] or event['sequence']!=sequence or closed or
                not previous<=event['monotonic_ns']<=row['observed_at_ns'] or (kind=='arm')!=(sequence==1)):return []
            previous=event['monotonic_ns']
            if kind=='accept':accepted+=1
            if event['connection']!=accepted or accepted>(3 if env['slot']=='http_identify' else 1):return []
            if kind in ('recv','send'):
                remaining=request_cap-received if kind=='recv' else response_cap-sent
                if not accepted or event['remaining_before']!=remaining or not 1<=event['actual_bytes']<=event['requested_bytes']:return []
                if kind=='recv':received+=event['actual_bytes']
                else:sent+=event['actual_bytes']
            elif any(event[key] for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after')):return []
            if kind in ('close','cancel'):
                if event['reason'] is None:return []
            elif event['reason'] is not None:return []
            closed=kind=='close';events.append(event)
        return events
    def recovery_required():
        return recovery is not None and loaded['cleanup.json']['recovery'] is not None
    def fault(name,stage='begin',source='broker_memfd'):
        return any(phase(name,stage,digest=contract.prepared_digest(op['prepared']),source=source) for op in operations)
    def socket_support():
        support=loaded['results.json']['boundary_proofs']
        allowed={8:{'S42C-X26'},9:{'S42C-X27'},15:{'S42C-X28'}}.get(number,{'S42C-X26','S42C-X27','S42C-X28'})
        if len(support)!=1 or support[0]['case_id'] not in allowed or support[0]['kind']!='socket_denial':return False
        # Context independently derives checks from actual control/source/process
        # and socket observations. Supporting proof is not another counted case.
        if not support[0]['checks'] or not all(value is True for value in support[0]['checks'].values()):return False
        observations=[x['observation'] for x in loaded['processes.json']['boundary_observations'] if x['kind']=='socket_denial'
            and _sha(_canonical(x['observation']))==support[0]['observation_sha256']]
        if len(observations)!=1:return False
        x=observations[0]
        return x['paired_control_connected'] is True and x['listener_accepts']==0 and x['listener_payload_bytes']==0 and x['return_value']==-1
    def waiting_boundary():
        ready={_sha(_canonical(row)):row for row in loaded['processes.json']['readiness']}
        launchers={_sha(_canonical(row['worker_ready'])):row
                   for row in loaded['processes.json']['readiness'] if row['role']=='launcher'}
        for op in operations:
            did=op['prepared']['envelope']['dispatch_id']
            matching=[row['row']['data']['frame']['body'] for row in rows if row['row']['dispatch_id']==did and
                row['row']['kind']=='protocol' and row['row']['data']['channel_role']=='launcher' and
                row['row']['data']['frame']['operation']=='PREPARED']
            # Both actual channel endpoints may retain the same packet. They
            # must agree; a second distinct preparation cannot be hidden.
            matching={_canonical(value):value for value in matching}
            if len(matching)!=1:continue
            receipt=next(iter(matching.values()))
            if receipt['prepared_sha256']!=contract.prepared_digest(op['prepared']) or receipt['envelope_sha256']!=contract.envelope_digest(op['prepared']['envelope']):continue
            actual=[launchers.get(receipt['launcher_ready_sha256'])]+[
                ready.get(receipt[key+'_ready_sha256']) for key in ('endpoint','client','admission')]
            if any(row is None for row in actual):continue
            client_role='nmap' if op['prepared']['envelope']['slot']=='http_identify' else 'headers'
            if [row['role'] for row in actual]!=['launcher','endpoint',client_role,'admission'] or actual[2]['worker_ready']['stage']!='sealed_waiting':continue
            if any(row['row']['dispatch_id']==did and row['row']['kind']=='protocol' and
                row['row']['data']['frame']['operation'] in ('GO','ARM','NATIVE_OBSERVED') for row in rows):continue
            if op['client'] is not None:continue
            return True
        return False
    def startup_boundary():
        observations=loaded['processes.json']['startup']
        if len(observations)!=1 or observations[0]['role']!='broker' or observations[0]['stage']!='entry':return False
        if loaded['processes.json']['readiness'] or loaded['processes.json']['native']:return False
        if roles!={'broker'}:return False
        payload=observations[0]['payload']
        actual=[row for row in cleanup_processes if (row['pid'],row['start_time_ticks'])==
                (payload['pid'],payload['start_time_ticks'])]
        # Entry and exit establish the process boundary only. The actual guard
        # diagnostic is separately required below to attribute the refusal.
        return len(actual)==1 and actual[0]['wrapper_returncode']==78 and actual[0]['signal_attempted'] is False
    def reviewer_refused(op):
        env=op['prepared']['envelope'];role='terminal' if env['review_mode']=='terminal' else 'graphical'
        known=[row for row in loaded['processes.json']['readiness'] if row['role']==role and
               row['worker_ready']['worker_id']==env['reviewer_id']]
        if len(known)!=1:return False
        payload=known[0]['parent_observation']['payload']
        actual=[row for row in cleanup_processes if row['role']==role and
                (row['pid'],row['start_time_ticks'])==(payload['pid'],payload['start_time_ticks'])]
        if len(actual)!=1 or actual[0]['wrapper_returncode']!=78 or actual[0]['signal_attempted'] is not False:return False
        digest=_sha(_canonical(_core_candidate(variant,op['prepared'],op['session'])))
        begins=phase('prepare','begin',digest=digest,source='role_observer')
        failures=phase('prepare','refused','approval_unavailable',digest=digest,source='role_observer')
        return any(a['row']['dispatch_id']==env['dispatch_id']==b['row']['dispatch_id'] and
                   known[0]['parent_observation']['sampled_at_ns']<=a['row']['observed_at_ns']<=b['row']['observed_at_ns']
                   for a in begins for b in failures)
    if number in (1,2,3,8,9,13,14,15):
        if len(operations)!=1 or go_ids or reserves or not usage_same or not complete_broker:return False
        attempted=[op for op in operations if reviewer_refused(op)]
        if not attempted:return False
        if number in (8,9,15) and not socket_support():return False
        if not waiting_boundary():return False
        return True
    if number in (4,5,6,7):return useful_prefix()
    if number in (10,11,12,28):
        if operations or go or not usage_same or not recovery_required() or not startup_boundary():return False
        roe=final['revisions'][-1]['roe']
        if not _startup_guard_refusal(loaded,selected,final,number,loaded['processes.json']['startup'][0]):return False
        if number==28:return True
        return ('http' in roe['excluded_services'] if number==10 else
            ('configurable_nmap_service_v1' if number==11 else 'configurable_http_headers_v1') not in roe['allowed_profiles'])
    if number in (16,17):return changed_refusal(revisions,'revision_changed',True)
    if number in (18,19,20,21,22,23):
        if not operations or not denied('allowance_exhausted'):return False
        key={18:'actions',19:'connections',20:'request_bytes',21:'response_bytes',22:'runtime_ms'}.get(number)
        limits=final['revisions'][-1]['roe']['limits']
        limit_keys={'actions':'max_actions','connections':'max_connections','request_bytes':'max_request_bytes',
                    'response_bytes':'max_response_bytes','runtime_ms':'max_engagement_ms'}
        exhausted=[k for k,v in operations[-1]['prepared']['envelope']['cost'].items()
            if before['receipt']['usage'][k]+v>limits[limit_keys[k]]]
        if not exhausted or key is not None and key not in exhausted:return False
        if number==23:
            return len(m['broker_instances'])==2 and all(op['prepared']['envelope']['ledger_owner_id']==
                m['broker_instances'][-1]['ledger_owner_id'] for op in operations)
        return True
    if number in (24,27):
        calls=_core_calls(selected)
        if len(calls)!=2 or calls[0]['channel']==calls[1]['channel']:return False
        if max(row['start'] for row in calls)>=min(row['end'] for row in calls):return False
        hashes={row['request']['prepared_sha256'] for row in calls}
        if len(hashes)!=(2 if number==24 else 1):return False
        if hashes!={contract.prepared_digest(op['prepared']) for op in operations}:return False
        if len(reserves)!=1 or len(go_ids)>1:return False
        refused_calls=[row for row in calls if _core_losing_call(row,operations,number)]
        if len(refused_calls)!=1:return False
        if number==24:
            costs=[op['prepared']['envelope']['cost'] for op in operations]
            limits=final['revisions'][-1]['roe']['limits'];names={'actions':'max_actions','connections':'max_connections',
                'request_bytes':'max_request_bytes','response_bytes':'max_response_bytes','runtime_ms':'max_engagement_ms'}
            if not any(before['receipt']['usage'][k]+max(cost[k] for cost in costs)<=limits[names[k]]<
                before['receipt']['usage'][k]+sum(cost[k] for cost in costs) for k in costs[0]):return False
        return complete_broker
    if number in (25,26):
        attempts=[r for r in rows if r['row']['kind']=='capability_projection' and r['row']['data']['operation']=='CONSUME']
        denied_attempts=[r for r in attempts if r['row']['data']['reply'] is not None and
            (r['row']['data']['reply'].get('accepted') is False or r['row']['data']['reply'].get('code')=='engagement_live_approval_unknown_or_replayed')]
        if not denied_attempts or len(reserves)>1 or len(go_ids)>1 or not complete_broker:return False
        if number==25:return bool(phase('consume','refused','approval_unknown_or_replayed'))
        accepted=[r for r in attempts if r['row']['data']['reply'] is not None and r['row']['data']['reply'].get('accepted') is True]
        return any(a['row']['data']['request']['reference_sha256']==b['row']['data']['request']['reference_sha256']
            and a['row']['observed_at_ns']<b['row']['observed_at_ns'] for a in accepted for b in denied_attempts)
    if number==29:
        return useful_prefix() and all(op['session']['binding']['clock_anchor']['utc_ns']==
            op['prepared']['envelope']['window_start_utc_ns'] for op in operations)
    if number in (30,31,32):
        if not operations or go_ids or not complete_broker:return False
        target={30:'consume',31:'audit',32:'guard'}[number]
        candidates=phase(target,'refused')
        valid_clock=False
        for row in candidates:
            clock=row['row']['data']['clock'];op=next((x for x in operations if x['prepared']['envelope']['dispatch_id']==row['row']['dispatch_id']),None)
            if clock is None or op is None:continue
            env=op['prepared']['envelope']
            if clock['mono_after_ns']>row['row']['observed_at_ns'] or clock['utc_ns']+clock['mono_after_ns']-clock['mono_before_ns']<env['window_end_utc_ns']:continue
            data=row['row']['data'];explicit=data['reason']=='engagement_live_window_closed'
            deadline_refusal=(row['source']=='role_observer' and data['reason'] in {
                'engagement_live_timeout','engagement_live_session_unavailable','engagement_live_approval_unavailable',
                'engagement_live_audit_unavailable','engagement_live_unavailable'} and
                data['original_deadline_ns']<=env['action_deadline_ns'] and
                clock['mono_after_ns']>=data['original_deadline_ns'])
            if not (explicit or deadline_refusal):continue
            if number==30:
                prior=any(r['row']['kind']=='capability_projection' and r['row']['dispatch_id']==env['dispatch_id'] and
                    r['row']['data']['operation']=='REVIEW' and r['row']['data']['reply'] is not None and
                    r['row']['observed_at_ns']<row['row']['observed_at_ns'] for r in rows)
            elif number==31:
                prior=any(r['source']=='broker_memfd' and r['row']['kind']=='audit_witness' and
                    r['row']['dispatch_id']==env['dispatch_id'] and r['row']['observed_at_ns']<row['row']['observed_at_ns'] for r in rows)
            else:prior=True
            valid_clock |= prior
        if not valid_clock:return False
        return len(reserves)==1 if number==32 else not reserves and usage_same
    if number in (33,34,35):
        if number==33:
            pending=[r for r in selected if r['row']['kind']=='capability_projection' and
                r['row']['data']['operation']=='REVIEW' and r['row']['data']['reply'] is None]
            return not go_ids and not reserves and any(r['row']['observed_at_ns']>=
                r['row']['data']['request']['prepared']['envelope']['action_deadline_ns'] for r in pending)
        target={33:'consume',34:'native_observation',35:'cleanup'}[number]
        candidates=phase(target,'refused','timeout')
        if not candidates:return False
        if not reserves or not go_ids:return False
        if any(op['result'] is not None and op['result']['outcome']=='useful' for op in operations):return False
        return any(_logical_deadline_fault(loaded,rows,op,row,proof['case_id'])
                   for op in operations for row in candidates)
    if number==41:
        if not revokes or reserves or go_ids or not usage_same or not recovery_required() or len(m['broker_instances'])!=1:return False
        commits=phase('watch','end',digest=revokes[-1]['receipt']['state_sha256'])
        if not commits or final['state']['status']!='revoked':return False
        first=[row for row in loaded['processes.json']['readiness'] if row['role']=='broker']
        second=[row for row in loaded['processes.json']['startup'] if row['role']=='broker']
        if len(first)!=1 or len(second)!=1:return False
        p=first[0]['parent_observation']['payload'];q=second[0]['payload']
        if (p['pid'],p['start_time_ticks'])==(q['pid'],q['start_time_ticks']) or second[0]['sampled_at_ns']<commits[0]['row']['observed_at_ns']:return False
        actual=[row for row in cleanup_processes if (row['pid'],row['start_time_ticks'])==(q['pid'],q['start_time_ticks'])]
        if len(actual)!=1 or actual[0]['wrapper_returncode']!=78 or actual[0]['signal_attempted'] is not False:return False
        return complete_broker and _startup_guard_refusal(loaded,selected,final,number,second[0])
    if number in (36,37,38):
        if not changed_refusal(revokes,'revoked',number==37):return False
        if number==38:
            return bool(phase('guard','refused','revoked')) and any(r['row']['kind']=='watch' and
                r['row']['data']['status']=='changed' and r['row']['data']['ledger_state_sha256']==revokes[-1]['receipt']['state_sha256'] for r in selected)
        return True
    if number in (39,40):
        if len(reserves)!=1 or len(revokes)!=1 or not go_ids:return False
        if reserves[0]['sequence']>=revokes[0]['sequence']:return False
        commits=phase('watch','end',digest=revokes[0]['receipt']['state_sha256'])
        if not commits:return False
        commit=commits[0]['row']['observed_at_ns']
        if not any(row['row']['observed_at_ns']<commit for row in go):return False
        if number==40 and not any(any(x['kind']=='send' and x['actual_bytes']>0 and
            x['monotonic_ns']<commit for x in progress_events(op)) for op in operations):return False
        return all(op['result'] is None or op['result']['outcome']!='useful' for op in operations)
    if number in (42,43,44,45,46):
        if not recovery_required() or not any(p['role']=='broker' and p['wrapper_returncode'] in (-9,137) and
            p['exit_observed'] and p['reaped_observed'] for p in cleanup_processes):return False
        if number==42:return fault('reserve') and not reserves and not go_ids and usage_same
        if len(reserves)!=1:return False
        if number==43 and (go_ids or not fault('reserve','end')):return False
        if number==44 and (not go_ids or not fault('go','end')):return False
        if number in (43,44):
            return _restart_refusal(loaded,rows,operations,final,number)
        for op in operations:
            digest=contract.prepared_digest(op['prepared']);events=progress_events(op)
            if not events:continue
            starts=phase('client','begin',digest=digest,source='role_observer')
            ends=phase('client','end',digest=digest,source='role_observer')
            if not any(a['row']['dispatch_id']==op['prepared']['envelope']['dispatch_id']==b['row']['dispatch_id'] and
                a['row']['observed_at_ns']<=b['row']['observed_at_ns'] and any(x['kind']==('recv' if number==45 else 'send') and
                x['actual_bytes']>0 and x['monotonic_ns']<a['row']['observed_at_ns'] for x in events) for a in starts for b in ends):continue
            return all(value['result'] is None or value['result']['outcome']!='useful' for value in operations)
        return False
    if number in (47,48,49,50,51):
        target='complete' if number in (47,48) else 'audit' if number==51 else 'reserve'
        if not fault(target,source='role_observer' if number==51 else 'broker_memfd') or not phase(target,'refused') or not recovery_required():return False
        if number in (49,50,51):return not reserves and not go_ids and usage_same
        return len(reserves)==1 and not any(row['request']['operation']=='complete' and row['receipt']['dispatch_id'] in ids for row in changes)
    if number in (52,53,54):
        if not recovery_required() or not complete_broker or len(reserves)>1:return False
        return _restart_refusal(loaded,rows,operations,final,number)
    return False


def _evaluate_case(loaded, context, linkage):
    m=loaded['manifest.json'];case=_case(m['case_id'])
    if case['group']=='native_core':
        proofs=loaded['results.json']['core_proofs']
        if len(proofs)!=1:return False
        proof=proofs[0]
        _object(proof,{'schema_version','case_id','variant','dispatch_ids','transcript_refs',
                      'before_state_sha256','after_state_sha256','recovery_state_sha256'})
        if proof['schema_version']!='1' or proof['case_id']!=case['id'] or proof['variant']!=case['variant']:
            _fail()
        ids=_list(proof['dispatch_ids'],4)
        if len(set(ids))!=len(ids):_fail()
        for value in ids:_uuid(value)
        for ref in _list(proof['transcript_refs'],128):
            _object(ref,{'segment','row_sequence'});_integer(ref['segment'],0,2);_integer(ref['row_sequence'],1,4096)
        for key in ('before_state_sha256','after_state_sha256','recovery_state_sha256'):
            if proof[key] is not None:_hash(proof[key])
        return _evaluate_core_proof(loaded,proof,linkage)
    proofs=loaded['results.json']['boundary_proofs']
    if len(proofs)!=1 or proofs[0]['case_id']!=case['id']:return False
    # validate_live_context derives each check independently from the kind's
    # structured physical observation. It rejects caller-only truth values.
    expected=case['required_checks']
    return proofs[0]['checks']=={key:True for key in expected}


def _cleanup_processes(loaded):
    # A whole-graph receipt may repeat the exact facts retained in an individual
    # receipt. Reconcile identities without dropping any receipt's status/time.
    unique={};unknown=[]
    for receipt in loaded['cleanup.json']['receipts']:
        for process in receipt['processes']:
            if process['pid'] is None or process['start_time_ticks'] is None:
                unknown.append(process)
                continue
            key=(process['pid'],process['start_time_ticks'])
            if key in unique and unique[key]!=process:return None
            unique[key]=process
    return [*unique.values(),*unknown]


def _cleanup_report(loaded,*,audit=None):
    receipts=loaded['cleanup.json']['receipts']
    payloads={};wrappers={}
    complete=True
    processes=_cleanup_processes(loaded)
    if processes is None:_fail()
    for receipt in receipts:complete &= receipt['status']=='complete'
    for process in processes:
        if process['pid'] is None or process['start_time_ticks'] is None:
            complete=False
            continue
        key=(process['pid'],process['start_time_ticks'])
        payloads[key]=process
        if process['wrapper_pid'] is not None:
            wrappers[(process['wrapper_pid'],process['start_time_ticks'])]=process
    if audit is None:audit=_audit_closure(loaded)
    observed=set(payloads)|{(p['payload']['pid'],p['payload']['start_time_ticks']) for p in audit['parents']}
    complete &= not audit['missing_cleanup']
    from .engagement_live_context import _supervisor_closure
    supervision=_supervisor_closure(loaded)
    complete &= supervision['complete']
    started=bool(receipts or audit['parents'] or loaded['cleanup.json']['supervisors'])
    return {'status':'not_started' if not started else 'complete' if complete else 'incomplete',
            'observed_payloads':len(observed) if started else None,
            'reaped_payloads':sum(p['reaped_observed'] for p in payloads.values()) if started else None,
            'reaped_wrappers':sum(p['wrapper_returncode'] is not None for p in wrappers.values()) if started else None}


def _audit_closure(loaded):
    from .engagement_live_context import _audit_process_closure
    return _audit_process_closure(loaded)


def _all_reaped(loaded,*,audit=None):
    # Cleanup may have exceeded an original work deadline while still producing
    # verified reaping. Save that failure honestly; never save a living role.
    from .engagement_live_context import _supervisor_closure
    if not _supervisor_closure(loaded)['all_closed']:return False
    if any(not row['descriptors_closed'] for row in loaded['cleanup.json']['receipts']):return False
    reaped=set()
    processes=_cleanup_processes(loaded)
    if processes is None:return False
    for process in processes:
        if (not process['reaped_observed'] or not process['exit_observed']
                or process['wrapper_pid'] is None or process['wrapper_returncode'] is None):
            return False
        if process['pid'] is not None and process['start_time_ticks'] is not None:
            reaped.add((process['pid'],process['start_time_ticks']))
    observations=list(loaded['processes.json']['startup'])+[
        row['parent_observation'] for row in loaded['processes.json']['readiness']+loaded['processes.json']['native']]
    if audit is None:audit=_audit_closure(loaded)
    if audit['missing_cleanup']:return False
    observations+=audit['parents']
    for observation in observations:
        payload=observation['payload']
        if (payload['pid'],payload['start_time_ticks']) not in reaped:
            return False
    return True


def _directory_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)


def _file_identity(info):
    return (_directory_identity(info)+(info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns))


def _private_directory(info):
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.getuid():
        _fail('invalid_input')


def _regular(info):
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600
            or info.st_uid!=os.getuid() or info.st_nlink!=1):
        _fail('invalid_input')


def _outside_store(fd):
    try:os.stat('records.sqlite3',dir_fd=fd,follow_symlinks=False)
    except FileNotFoundError:return
    _fail('invalid_input')


@contextmanager
def _parent(path,deadline):
    fd=None
    try:
        try:
            raw=os.fspath(path)
            if type(raw) is not str or not raw or '\x00' in raw or '\n' in raw or len(raw.encode('utf-8'))>4096 or raw.endswith('/'):
                _fail('invalid_input')
            p=Path(raw)
            if p.name in ('','.','..','records.sqlite3'):_fail('invalid_input')
            parent=p.parent.resolve(strict=True)
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            _private_directory(os.fstat(fd));_outside_store(fd)
            identity=_directory_identity(os.fstat(fd))
        except LiveError:raise
        except (OSError,ValueError,TypeError,UnicodeError,RuntimeError):_fail('invalid_input')
        _parent_check(fd,parent,identity);_check(deadline)
        yield fd,parent,p.name,identity
        _parent_check(fd,parent,identity)
    finally:
        if fd is not None:
            try:os.close(fd)
            except OSError:_fail('unavailable')


def _parent_check(fd,path,identity):
    try:
        if _directory_identity(os.fstat(fd))!=identity or _directory_identity(path.stat(follow_symlinks=False))!=identity:
            _fail('evidence_invalid')
    except OSError:_fail('evidence_invalid')


def _file_check(fd,parent,name,identity):
    try:
        if _file_identity(os.fstat(fd))!=identity or _file_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=identity:
            _fail()
    except OSError:_fail()


def _names(fd):
    names=[]
    with os.scandir(fd) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names)>18:_fail('limit_exceeded')
    return set(names)


def _read(fd,cap,deadline):
    chunks=[];count=0
    while True:
        _check(deadline)
        part=os.read(fd,min(65536,cap-count+1))
        if not part:break
        count+=len(part)
        if count>cap:_fail('limit_exceeded')
        chunks.append(part)
    _check(deadline)
    return b''.join(chunks)


def _write(fd,raw,deadline):
    offset=0
    while offset<len(raw):
        _check(deadline)
        count=os.write(fd,raw[offset:offset+65536])
        if count<=0:_fail('unavailable')
        offset+=count
    _check(deadline);os.fsync(fd);_check(deadline)


def _bundle_check(bundle,parent,name,identity,names):
    if (_directory_identity(os.fstat(bundle))!=identity
            or _directory_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=identity
            or _names(bundle)!=names):_fail()


def _inspect_files(parent,name,deadline,handler):
    bundle=None;fds={}
    try:
        before=os.stat(name,dir_fd=parent,follow_symlinks=False);_private_directory(before)
        bundle=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        identity=_directory_identity(os.fstat(bundle));_private_directory(os.fstat(bundle))
        if identity!=_directory_identity(before):_fail()
        _outside_store(bundle)
        names=_names(bundle)
        if 'manifest.json' not in names:_fail()
        raw={}
        # Hold every validated regular descriptor across all parser subprocesses.
        for member in ['manifest.json']+sorted(names-{'manifest.json'}):
            _check(deadline)
            if member!='manifest.json' and member not in expected:_fail()
            info=os.stat(member,dir_fd=bundle,follow_symlinks=False);_regular(info)
            cap=CAPS.get(member,8192)
            if info.st_size>cap:_fail('limit_exceeded')
            fd=os.open(member,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=bundle)
            fds[member]=(fd,_file_identity(os.fstat(fd)))
            _regular(os.fstat(fd))
            if _file_identity(info)!=fds[member][1]:_fail()
            _file_check(fd,bundle,member,fds[member][1])
            raw[member]=_read(fd,cap,deadline)
            if member=='manifest.json':
                manifest=_manifest(_decode(raw[member],32768))
                expected={r['name'] for r in manifest['members']}
                if names!=expected|{'manifest.json'}:_fail()
        _bundle_check(bundle,parent,name,identity,names)
        result=handler(manifest,{k:v for k,v in raw.items() if k!='manifest.json'})
        for member,(fd,pin) in fds.items():
            _file_check(fd,bundle,member,pin);os.lseek(fd,0,os.SEEK_SET)
            if _read(fd,CAPS.get(member,8192),deadline)!=raw[member]:_fail()
            _file_check(fd,bundle,member,pin)
        _bundle_check(bundle,parent,name,identity,names);_check(deadline)
    finally:
        error=False
        for fd,_ in fds.values():
            try:os.close(fd)
            except OSError:error=True
        if bundle is not None:
            try:os.close(bundle)
            except OSError:error=True
        if error:_fail('unavailable')
    _check(deadline)
    return result


def inspect_live_bundle(path,*,deadline=None):
    end=_deadline(deadline)
    try:
        with _parent(path,end) as (parent,parent_path,name,parent_identity):
            def inspect(manifest,members):
                loaded,rows,tails=_load_members(manifest,members,end)
                from .engagement_live_context import _retained_fixture_validation
                with _retained_fixture_validation(loaded,deadline=end):
                    context=_context(loaded,end)
                    authority=_authority(loaded,rows,end)
                    count=_reparse(loaded,end)
                    from .engagement_live_contract import _deadline_context
                    with _deadline_context(end):
                        result=_report(loaded,context,authority,_sha(_canonical(manifest,32768)),count,tails)
                    _check(end)
                    return result
            result=_inspect_files(parent,name,end,inspect)
            _parent_check(parent,parent_path,parent_identity)
    except LiveError:raise
    except (OSError,ValueError,TypeError,KeyError,ImportError,AttributeError):_fail('evidence_invalid')
    _check(end)
    return result


def write_live_bundle(directory,*,manifest,members,deadline=None):
    end=_deadline(deadline)
    bundle=None;fds=[]
    try:
        if type(members) is not dict or any(type(v) is not bytes for v in members.values()):_fail()
        frozen=dict(members)
        loaded,rows,_tails=_load_members(manifest,frozen,end)
        from .engagement_live_context import _retained_fixture_validation
        with _retained_fixture_validation(loaded,deadline=end):
            _context(loaded,end);_authority(loaded,rows,end)
        # A late but fully observed emergency reap may be saved as failed evidence.
        # An unverified still-running role may never be hidden by packaging.
        from .engagement_live_contract import _deadline_context
        with _deadline_context(end):
            if not _all_reaped(loaded):_fail('cleanup_incomplete')
        raw_manifest=_canonical(loaded['manifest.json'],32768)
        with _parent(directory,end) as (parent,parent_path,name,parent_identity):
            _check(end)
            try:os.mkdir(name,0o700,dir_fd=parent)
            except FileExistsError:_fail('output_exists')
            bundle=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            identity=_directory_identity(os.fstat(bundle));_private_directory(os.fstat(bundle))
            for member in sorted(frozen)+['manifest.json']:
                _check(end)
                raw=raw_manifest if member=='manifest.json' else frozen[member]
                fd=os.open(member,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=bundle)
                fds.append((member,fd,None,raw));_regular(os.fstat(fd));_write(fd,raw,end)
                pin=_file_identity(os.fstat(fd));fds[-1]=(member,fd,pin,raw);os.lseek(fd,0,os.SEEK_SET)
                if _read(fd,len(raw),end)!=raw:_fail()
                _file_check(fd,bundle,member,pin)
            _check(end);os.fsync(bundle);_check(end)
            for member,fd,pin,raw in fds:
                _file_check(fd,bundle,member,pin);os.lseek(fd,0,os.SEEK_SET)
                if _read(fd,len(raw),end)!=raw:_fail()
                _file_check(fd,bundle,member,pin)
            _bundle_check(bundle,parent,name,identity,set(frozen)|{'manifest.json'})
            _check(end);os.fsync(parent);_check(end)
            _parent_check(parent,parent_path,parent_identity)
            result={'schema_version':'1','status':'packaged','manifest_sha256':_sha(raw_manifest),
                    'member_count':len(frozen)+1,'total_bytes':len(raw_manifest)+sum(map(len,frozen.values()))}
    except LiveError:raise
    except (OSError,ValueError,TypeError,KeyError,ImportError,AttributeError):_fail('unavailable')
    finally:
        error=False
        for _member,fd,_pin,_raw in fds:
            try:os.close(fd)
            except OSError:error=True
        if bundle is not None:
            try:os.close(bundle)
            except OSError:error=True
        if error:_fail('unavailable')
    _check(end)
    return result
