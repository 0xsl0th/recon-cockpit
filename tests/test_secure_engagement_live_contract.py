"""S42C-C01..C24: closed data fixtures, never native/approval authority."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent import engagement_live_protocol as p
from recon_cockpit.secure_agent import engagement_dispatch_contract as ledger
from recon_cockpit.secure_agent import engagement_contract as records
from recon_cockpit.secure_agent import configurable_contract

ROOT = Path(__file__).resolve().parents[1]
M = 1000 * c.SECOND
U = 1792540800000000000


def uid(value):
    return str(UUID(int=value, version=4))


def clock(delta=0, width=0):
    return {'utc_ns': U + delta, 'mono_before_ns': M + delta, 'mono_after_ns': M + delta + width}


def roe():
    value = json.loads((ROOT / 'examples/secure-agent-engagement-roe.json').read_text())
    value['window'] = {'start_utc': '2026-10-21T00:00:00Z', 'end_utc': '2026-10-22T00:00:00Z'}
    return value


def opened(review_mode='terminal', *, clock_value=None, roe_value=None):
    """Real accepted pure replay receipts; no DB, review, witness or process claim."""
    sample = clock() if clock_value is None else deepcopy(clock_value)
    selected = roe() if roe_value is None else deepcopy(roe_value)
    engine = ledger._Engine()
    engine.push(ledger.validate_request({'schema_version': '2', 'engagement_id': uid(1),
        'event_id': uid(100), 'operation': 'create', 'expected_revision': None,
        'expected_generation': None, 'body': selected}))
    receipt = engine.push(ledger.validate_request({'schema_version': '2', 'engagement_id': uid(1),
        'event_id': uid(101), 'operation': 'session', 'expected_revision': 1,
        'expected_generation': 0, 'body': {'session_id': uid(4), 'owner_id': uid(3),
        'clock': sample, 'original_deadline_ns': sample['mono_after_ns'] + 60*c.SECOND}}))
    row = engine.export['sessions'][0]
    binding = c.derive_session_binding(selected, engagement_id=uid(1), revision=1, generation=0,
        broker_id=uid(2), ledger_owner_id=uid(3), session_id=uid(4), reviewer_id=uid(5),
        review_mode=review_mode, runtime_sha256='a'*64, clock=sample,
        session_deadline_ns=row['session_deadline_ns'],
        broker_deadline_ns=sample['mono_after_ns'] + 120*c.SECOND)
    return c.validate_session_opened({'schema_version': '1', 'binding': binding,
        'session_receipt': {'schema_version': '2', 'kind': 'data_only', 'disposition': 'recorded',
        'receipt': receipt}, 'roe': selected, 'scope': selected['scope'],
        'policy': ledger.policy_for_roe(selected)})


def prepared(slot='http_identify', *, opened_value=None, delta=0):
    return c.derive_prepared(opened() if opened_value is None else opened_value,
                            slot, dispatch_id=uid(10), clock=clock(delta))


def refused(function, *args, code=None, **kwargs):
    with pytest.raises(c.LiveError) as result:
        function(*args, **kwargs)
    if code is not None:
        assert result.value.code == 'engagement_live_' + code
    return result.value.code


def release(value=None, *, lease=None):
    value = prepared() if value is None else value
    e = value['envelope']
    lease = M + 10*c.SECOND if lease is None else lease
    return {'schema_version': '1', 'broker_id': e['broker_id'], 'ledger_owner_id': e['ledger_owner_id'],
        'session_id': e['session_id'], 'dispatch_id': e['dispatch_id'],
        'envelope_sha256': c.envelope_digest(e), 'prepared_sha256': c.prepared_digest(value),
        'reservation_event_id': uid(20), 'reservation_sequence': 3,
        'reservation_state_sha256': 'b'*64, 'approval_witness_sha256': 'c'*64,
        'audit_witness_sha256': 'd'*64, 'guard_clock': clock(),
        'effective_lease_deadline_ns': lease, 'effect_stop_ns': c.effect_stop(value, lease),
        'release_sequence': 1}


def witnesses(issued=M):
    return ({'issued_at_ns': issued, 'expires_at_ns': M+30*c.SECOND},
            {'issued_at_ns': issued})


def test_closed_canonical_packets_and_unicode():
    value = prepared()
    assert c.decode(c.canonical(value)) == value
    for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{}{}', b'\xff', b'{"\\ud800":0}'):
        refused(c.decode, raw)
    for bad in ({'x': '\udfff'}, {'\ud800': 1}, {1: 'x'}, {'x': float('inf')}):
        refused(c.canonical, bad)
    for key in ('action_deadline_ns', 'revision', 'output_limit'):
        bad = deepcopy(value); bad['envelope'][key] = True
        refused(c.validate_prepared, bad)
    clean = c.validate_prepared(value); value['envelope']['cost']['actions'] = 2
    assert clean['envelope']['cost']['actions'] == 1


def test_raw_byte_depth_and_attainable_caps():
    raw = c.canonical('a'*62, max_bytes=64)
    assert len(raw) == 64 and c.decode(raw, max_bytes=64) == 'a'*62
    refused(c.canonical, 'a'*63, max_bytes=64, code='limit_exceeded')
    refused(c.decode, b'['*65 + b'0' + b']'*65, code='limit_exceeded')
    value = prepared(); assert len(c.canonical(value)) < 16384
    bad = deepcopy(value); bad['envelope']['slot'] = 'x'*16384
    refused(c.validate_prepared, bad, code='limit_exceeded')


def test_complete_envelope_derives_only_fixed_http_plan():
    o = opened()
    for slot, step in [('http_identify', 1), ('http_headers', 2)]:
        value = prepared(slot, opened_value=o)
        assert value['action'] == configurable_contract.action(o['scope'], step)
        assert value['policy'] == ledger.policy_for_roe(o['roe'])
        assert value['envelope']['cost'] == ledger.reservation_for(o['roe'], slot)
        assert c.validate_prepared_context(value, o) == value


def test_unsupported_scope_effect_and_profile_refuse():
    for change in ('excluded', 'missing_headers', 'missing_identify', 'path'):
        r = roe()
        if change == 'excluded': r['excluded_services'] = ['http']
        elif change == 'missing_headers': r['allowed_profiles'] = ['configurable_nmap_service_v1']
        elif change == 'missing_identify': r['allowed_profiles'] = ['configurable_http_headers_v1']
        else: r['scope']['http']['path'] = '/other'
        with pytest.raises((c.LiveError, ledger.DispatchLedgerError)):
            opened(roe_value=r)
    for slot in ('ssh_identify', 'http_post', ''):
        refused(c.derive_prepared, opened(), slot, dispatch_id=uid(10), clock=clock())
    for key, value in [('method', 'POST'), ('path', '/x'), ('port', 12345)]:
        bad = prepared('http_headers'); bad['action']['parameters'][key] = value
        refused(c.validate_prepared, bad)
    bad = prepared(); bad['action']['target'] = '127.0.0.2'; refused(c.validate_prepared, bad)


def test_every_envelope_identity_and_digest_is_bound():
    o, value = opened(), prepared()
    for key in value['envelope']:
        if key in {'cost', 'clock_anchor'}: continue
        bad = deepcopy(value)
        old = bad['envelope'][key]
        if type(old) is int: bad['envelope'][key] = old+1
        elif key.endswith('_sha256'): bad['envelope'][key] = 'f'*64
        elif key.endswith('_id'): bad['envelope'][key] = uid(999)
        else: bad['envelope'][key] = 'foreign'
        refused(c.validate_prepared_context, bad, o, expected=value)


def test_utc_window_and_clock_anchor_are_bound():
    o = opened()
    for key in ('window_start_utc_ns', 'window_end_utc_ns'):
        bad = deepcopy(o); bad['binding'][key] += 1
        refused(c.validate_session_opened, bad)
    bad = deepcopy(o); bad['binding']['clock_anchor']['mono_after_ns'] += ledger.CLOCK_TOLERANCE+1
    refused(c.validate_session_opened, bad)
    bad = deepcopy(o); del bad['binding']['clock_anchor']['utc_ns']; refused(c.validate_session_opened, bad)


def test_original_deadlines_do_not_reset():
    value = prepared(); old = c.canonical(value)
    later = prepared(delta=c.SECOND)
    assert later['envelope']['session_deadline_ns'] == value['envelope']['session_deadline_ns']
    assert later['envelope']['broker_deadline_ns'] == value['envelope']['broker_deadline_ns']
    for key in ('action_deadline_ns', 'session_deadline_ns', 'broker_deadline_ns'):
        bad = deepcopy(value); bad['envelope'][key] = c.INTEGER_MAX
        refused(c.validate_prepared, bad)
    assert c.canonical(value) == old


def test_inclusive_start_exclusive_end_conversion(tmp_path, monkeypatch):
    kwargs = dict(anchor=clock(), window_start_utc_ns=U, window_end_utc_ns=U+c.SECOND,
                  deadline_ns=M+60*c.SECOND)
    assert c.check_clock(clock(), **kwargs) == M+c.SECOND
    assert c.check_clock(clock(c.SECOND-1), **kwargs) == M+c.SECOND
    refused(c.check_clock, clock(c.SECOND), **kwargs, code='window_closed')
    refused(c.check_clock, clock(c.SECOND-2, 2), **kwargs, code='window_closed')
    refused(c.check_clock, clock(-1), **kwargs, code='clock_changed')
    _inclusive_native_clock_anchor(tmp_path, monkeypatch)


def _inclusive_native_clock_anchor(tmp_path, monkeypatch):
    from engagement_live_native import SourceVariants, _install_inclusive_clock
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    original_clock=c.sample_clock;original_source=runtime._source_path
    elapsed=[0]
    with monkeypatch.context() as patch:
        patch.setattr(c.time,'time',lambda:U/c.SECOND+.5)
        patch.setattr(c.time,'time_ns',lambda:U+c.SECOND//2+elapsed[0])
        patch.setattr(c.time,'monotonic_ns',lambda:M+elapsed[0])
        patch.setattr(c.time,'monotonic',lambda:(M+elapsed[0])/c.SECOND)
        os_monotonic=c.time.monotonic;os_wall=c.time.time_ns
        case={'id':'S42C-N29','variant':'inclusive_start_useful_prefix'}
        variants=SourceVariants(tmp_path/'clock-source',case_id=case['id'],variant=case['variant'],role='broker')
        _install_inclusive_clock(variants,case)
        assert not set(variants.paths)&set(runtime.role_modules('parser'))
        anchor={'utc_ns':U,'mono_before_ns':M-c.SECOND//2,'mono_after_ns':M-c.SECOND//2}
        assert case['_clock']==anchor
        boundary=dict(anchor=anchor,window_start_utc_ns=U,window_end_utc_ns=U+60*c.SECOND,
            deadline_ns=M+60*c.SECOND)
        assert c.check_clock(anchor,**boundary)>M
        value=c.derive_prepared(opened(clock_value=anchor),'http_identify',dispatch_id=uid(10),clock=c.sample_clock())
        permit=release(value);permit['guard_clock']=c.sample_clock()
        with pytest.raises(RuntimeError,match='owned exit'):
            with variants:
                for delta in (0,c.SECOND):
                    elapsed[0]=delta
                    assert c.sample_clock is original_clock
                    assert c.check_clock(c.sample_clock(),**boundary)>M+delta
                    assert c.validate_release_binding(permit,value,clock=c.sample_clock())==permit
                    bad=deepcopy(c.sample_clock());bad['utc_ns']+=ledger.CLOCK_TOLERANCE+1
                    refused(c.check_clock,bad,**boundary,code='clock_changed')
                    assert c.time.monotonic is os_monotonic and c.time.time_ns is os_wall
                raise RuntimeError('owned exit')
        assert c.sample_clock is original_clock and runtime._source_path is original_source
        saved=json.loads((variants.directory/'source-variants.json').read_bytes())
        source=variants.paths['engagement_live_broker_worker'].read_bytes()
        assert saved['sources'][0]['after_sha256']==hashlib.sha256(source).hexdigest()
        # Execute only the committed test wrapper around harmless stand-ins.
        # Its initialization and first session see the exact boundary, then
        # normal advancing clocks are restored even when the operation fails.
        tree=ast.parse(source);names={'_owned_at_inclusive_boundary','_owned_inclusive_initialize','_owned_inclusive_session'}
        wrapper=ast.Module(body=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names],type_ignores=[])
        import types
        isolated=types.SimpleNamespace(sample_clock=original_clock,fail=c.fail)
        seen=[]
        def observe(*args):seen.append(isolated.sample_clock());return 'observed'
        namespace={'c':isolated,'_OWNED_INCLUSIVE_ANCHOR':anchor,'_owned_inclusive_init':observe,'_owned_inclusive_open':observe}
        exec(compile(wrapper,'owned-inclusive-wrapper','exec'),namespace)
        owner=types.SimpleNamespace(slots=[{'state':'allocated'}])
        assert namespace['_owned_inclusive_initialize'](owner)=='observed'
        assert namespace['_owned_inclusive_session'](owner,0)=='observed'
        assert seen==[anchor,anchor] and isolated.sample_clock is original_clock
        def fail():raise RuntimeError('owned boundary failure')
        with pytest.raises(RuntimeError,match='owned boundary failure'):
            namespace['_owned_at_inclusive_boundary'](fail)
        assert isolated.sample_clock is original_clock


def test_backward_forward_and_highwater_discontinuities():
    kwargs = dict(anchor=clock(), window_start_utc_ns=U-c.SECOND, window_end_utc_ns=U+100*c.SECOND,
                  deadline_ns=M+60*c.SECOND)
    for sign in (-1, 1):
        good = clock(c.SECOND); good['utc_ns'] += sign*ledger.CLOCK_TOLERANCE
        assert c.check_clock(good, **kwargs) > M
        bad = deepcopy(good); bad['utc_ns'] += sign
        refused(c.check_clock, bad, **kwargs, code='clock_changed')
    with pytest.raises(ledger.DispatchLedgerError):
        ledger.window_budget(roe(), clock(), original_deadline_ns=M+60*c.SECOND,
                            utc_high_water_ns=U+ledger.CLOCK_TOLERANCE+1)
    _clock_validation_error_classification()


def _clock_validation_error_classification():
    """Real ledger validation keeps its error when the shared phase expires."""
    from types import SimpleNamespace
    sample=clock();anchor=deepcopy(sample)
    kwargs=dict(anchor=anchor,window_start_utc_ns=U-c.SECOND,
        window_end_utc_ns=U+100*c.SECOND,deadline_ns=M+60*c.SECOND)
    original=ledger.validate_clock;original_time=records.time
    assert c.check_clock(sample,**kwargs)==M+60*c.SECOND
    for expire_on in (1,2):
        now=[M/c.SECOND];deadline=(M+100_000_000)/c.SECOND
        seen=[];ledger_errors=[];previous=records._active_deadline()
        assert previous is None
        def expire_at_validation(value):
            seen.append(value)
            assert records._active_deadline()==deadline
            if len(seen)==expire_on:now[0]=deadline
            try:return original(value)
            except ledger.DispatchLedgerError as error:
                ledger_errors.append(error.code)
                raise
        with pytest.MonkeyPatch.context() as patch:
            # Only the records module's time binding changes; the shared time
            # module, clock samples and actual ledger validator stay intact.
            patch.setattr(records,'time',SimpleNamespace(monotonic=lambda:now[0]))
            patch.setattr(ledger,'validate_clock',expire_at_validation)
            with pytest.raises(c.LiveError) as caught:
                with c._deadline_context(deadline):
                    c.check_clock(sample,**kwargs)
            assert ledger_errors==['engagement_dispatch_timeout']
            assert len(seen)==expire_on and now[0]==deadline
            assert records._active_deadline()==previous
            assert caught.value.code=='engagement_live_timeout'
        assert ledger.validate_clock is original and records.time is original_time
        assert sample==clock() and anchor==sample
    malformed=deepcopy(sample);malformed['mono_after_ns']-=1
    oversized={**sample,'padding':'x'*ledger.MAX_REQUEST_BYTES}
    for value,code in ((malformed,'clock_changed'),(oversized,'limit_exceeded')):
        for at_anchor in (False,True):
            options={**kwargs,'anchor':value} if at_anchor else kwargs
            refused(c.check_clock,sample if at_anchor else value,**options,code=code)
    assert sample==clock() and anchor==sample


def test_lease_is_minimum_of_every_original_bound():
    value = prepared(); a, audit = witnesses()
    assert c.derive_effective_lease(value, {'deadline_ns': M+30*c.SECOND}, a, audit, clock=clock()) == M+10*c.SECOND
    for field in ('reservation', 'grant', 'approval', 'audit'):
        reserve = {'deadline_ns': M+30*c.SECOND}; aa, au = witnesses()
        if field == 'reservation': reserve['deadline_ns'] = M+2*c.SECOND
        if field == 'grant': aa['expires_at_ns'] = M+2*c.SECOND
        if field == 'approval': aa['issued_at_ns'] = M-8*c.SECOND
        if field == 'audit': au['issued_at_ns'] = M-8*c.SECOND
        assert c.derive_effective_lease(value, reserve, aa, au, clock=clock()) == M+2*c.SECOND
    narrowed = deepcopy(value); narrowed['envelope']['action_deadline_ns'] = M+c.SECOND
    assert c.derive_effective_lease(narrowed, {'deadline_ns': M+30*c.SECOND}, a, audit, clock=clock()) == M+c.SECOND


def test_fresh_reservation_can_only_narrow_review():
    value = prepared(); before = c.canonical(value); a, audit = witnesses()
    lease = c.derive_effective_lease(value, {'deadline_ns': M+c.SECOND}, a, audit, clock=clock(1))
    assert lease == M+c.SECOND and c.canonical(value) == before


def approval(value=None, *, sequence=1, issued=M, expires=M+30*c.SECOND):
    value=prepared() if value is None else value;e=value['envelope']
    return {'schema_version':'1','reviewer_id':e['reviewer_id'],'broker_id':e['broker_id'],
        'ledger_owner_id':e['ledger_owner_id'],'session_id':e['session_id'],'dispatch_id':e['dispatch_id'],
        'consume_sequence':sequence,'reference_sha256':'e'*64,'envelope_sha256':c.envelope_digest(e),
        'action_sha256':e['action_sha256'],'policy_sha256':e['policy_sha256'],
        'issued_at_ns':issued,'expires_at_ns':expires,'accepted':True}


def test_legacy_audit_float_bytes_remain_exact():
    from recon_cockpit.secure_agent import audit_witness, audit_protocol
    from recon_cockpit.secure_agent import engagement_live_witness as w
    value=prepared();event=w.started_event(value)
    raw=audit_protocol.encode(audit_witness.witness(event,uid(70),1,1,1000.125))
    source={'version':'1','writer_id':uid(70),'device':1,'inode':2}
    info=w.validate_audit_witness(raw,value,source=source,sequence=1,now_ns=M+125000000)
    assert info['raw_sha256']==hashlib.sha256(raw).hexdigest()
    assert info['issued_at_ns']==M+125000000 and b'1000.125' in raw
    refused(c.decode,raw)
    refused(w.validate_audit_witness,raw+b' ',value,source=source,sequence=1,now_ns=M+125000000)


def test_new_witness_age_and_expiry_are_independent():
    from recon_cockpit.secure_agent import engagement_live_witness as w
    value=prepared();proof=approval(value)
    assert w.validate_approval_witness(proof,value,now_ns=M+10*c.SECOND)==proof
    refused(w.validate_approval_witness,proof,value,now_ns=M+10*c.SECOND+1,code='stale_witness')
    proof['expires_at_ns']=M+c.SECOND
    refused(w.validate_approval_witness,proof,value,now_ns=M+c.SECOND,code='stale_witness')
    assert w.validate_approval_witness(approval(sequence=3),value,previous_sequence=1,now_ns=M)['consume_sequence']==3
    refused(w.validate_approval_witness,approval(sequence=3),value,previous_sequence=3,now_ns=M)


def _fixed_n44_launcher_hold_cases(tmp_path,monkeypatch):
    """Actual transformed hook under declared clock/EOF; no process witness.

    Execute the unchanged release validator and transformed run/control bodies.
    Deliberately forbidden continuations expose a misplaced hold or fallthrough;
    they do not emulate successful broker, child, endpoint or cleanup behavior.
    """
    from types import SimpleNamespace
    import time
    from engagement_live_native import SourceVariants,install_broker_fault,_install_n44_launcher_hold,n44_launcher_hold_transform
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    original=ROOT/'recon_cockpit/secure_agent/engagement_live_launcher_worker.py'
    original_bytes=original.read_bytes();baseline=hashlib.sha256(original_bytes).hexdigest()
    case={'case_id':'S42C-N44','variant':'kill_broker_after_GO_before_observation','role':'broker'}
    variants=SourceVariants(tmp_path/'n44-source',**case)
    install_broker_fault(variants,case['case_id']);path=_install_n44_launcher_hold(variants)
    source=path.read_bytes();tree=ast.parse(source)
    assert original.read_bytes()==original_bytes
    assert set(variants.paths)=={'engagement_live_broker_worker','engagement_live_launcher_worker'}
    instruments=variants.instrumentation
    assert [x['configuration'] for x in instruments]==[case,{**case,'role':'launcher'}]
    for record,item in zip(variants.records,instruments):
        content=variants.paths[record['module']].read_bytes()
        assert record['after_sha256']==item['source_sha256']==hashlib.sha256(content).hexdigest()
        assert item['configuration_sha256']==hashlib.sha256(c.canonical(item['configuration'])).hexdigest()
    assert variants.records[-1]['before_sha256']==baseline
    previous_source=runtime._source_path
    with variants:pass
    assert runtime._source_path is previous_source
    saved=json.loads((variants.directory/'source-variants.json').read_bytes())
    assert saved['sources'][-1]['configuration']=={**case,'role':'launcher'}
    bad_source=original_bytes.decode().replace("self.admission_rpc('REDEEM',","self.admission_rpc('OTHER',")
    with pytest.raises(ValueError):n44_launcher_hold_transform(bad_source)
    with pytest.raises(ValueError):n44_launcher_hold_transform(source.decode())
    with pytest.raises(ValueError):variants.source('engagement_live_launcher_worker',n44_launcher_hold_transform)
    wrong=SourceVariants(tmp_path/'n43-source',case_id='S42C-N43',variant='kill_broker_after_reservation_before_GO',role='broker')
    with pytest.raises(ValueError):_install_n44_launcher_hold(wrong)
    assert not wrong.records
    control=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='LauncherControl')
    launcher=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='LauncherState')
    run=next(node for node in launcher.body if isinstance(node,ast.FunctionDef) and node.name=='run')
    hold=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='_fixed_n44_go_hold')
    extracted=ast.Module(body=[control,hold,run],type_ignores=[])
    namespace={'__package__':'recon_cockpit.secure_agent','c':c,'rt':runtime,'time':time}
    exec(compile(extracted,str(path),'exec'),namespace)
    actual_run=namespace['run'];actual_control=namespace['LauncherControl']
    elapsed=[0];sleeps=[];polled=[];continued=[]
    def sleep(seconds):
        assert 0<=seconds<=.005
        sleeps.append(seconds);elapsed[0]+=max(1,round(seconds*c.SECOND))
    def forbidden(*args,**kwargs):
        continued.append((args,kwargs));raise AssertionError('N44 hold reached post-GO work or run cleanup')
    with monkeypatch.context() as patch:
        patch.setattr(time,'monotonic_ns',lambda:M+elapsed[0])
        patch.setattr(time,'monotonic',lambda:(M+elapsed[0])/c.SECOND)
        patch.setattr(time,'sleep',sleep)
        patch.setattr(c,'sample_clock',lambda:clock(elapsed[0]))
        for variant,limit,lease,code in (
                ('fixed_second',60*c.SECOND,10*c.SECOND,'timeout'),
                ('original_owner',15_000_000,10*c.SECOND,'timeout'),
                ('effect_stop',60*c.SECOND,10_000_000,'timeout'),
                ('already_expired',0,10*c.SECOND,'timeout'),
                ('eof',60*c.SECOND,10*c.SECOND,'cancelled')):
            elapsed[0]=0;sleeps.clear();polled.clear();continued.clear()
            value=prepared();go=release(value,lease=M+lease)
            packet={'schema_version':'1','channel_id':uid(99),'sequence':1,'operation':'GO','body':go}
            actual_go=p.decode_frame(p.encode_frame(packet,role='launcher',direction='request'),
                role='launcher',direction='request')['body']
            def poll_stop():
                polled.append(M+elapsed[0])
                if variant=='eof':c.fail('cancelled')
            owner=SimpleNamespace(pending=value,release=None,deadline_ns=M+limit,poll_stop=poll_stop,
                admission=SimpleNamespace(close=forbidden),client=SimpleNamespace(close=forbidden,release=forbidden,
                    observe_native=forbidden,collect=forbidden),admission_rpc=forbidden,send=forbidden,
                observe=forbidden,record_capture=forbidden,cleanups=[])
            owner._control=lambda deadline=None:actual_control(owner,min(owner.deadline_ns,
                owner.deadline_ns if deadline is None else deadline))
            refused(actual_run,owner,actual_go,code=code)
            assert owner.release==actual_go and owner.pending==value
            assert not continued and not owner.cleanups
            control_bound=int(owner._control(actual_go['effect_stop_ns']).deadline*c.SECOND)-M
            bound=min(c.SECOND,limit,control_bound,value['envelope']['action_deadline_ns']-M)
            assert bound<=min(limit,actual_go['effect_stop_ns']-M)
            assert 0<=elapsed[0]<=bound,variant
            if variant in ('eof','already_expired'):assert not sleeps
            else:assert sleeps and elapsed[0]==bound and polled
            # The validated GO was consumed even though no work followed it.
            refused(actual_run,owner,actual_go,code='release_unavailable')
        elapsed[0]=0;sleeps.clear();continued.clear()
        owner.release=None;wrong_go=deepcopy(actual_go);wrong_go['dispatch_id']=uid(999)
        refused(actual_run,owner,wrong_go)
        assert owner.release is None and not sleeps and not continued
    assert original.read_bytes()==original_bytes


def test_release_packet_has_single_dispatch_identity(tmp_path,monkeypatch):
    value=prepared();go=release(value)
    assert c.validate_release_binding(go,value,clock=clock())==go
    for key in ('broker_id','ledger_owner_id','session_id','dispatch_id'):
        bad=deepcopy(go);bad[key]=uid(999)
        refused(c.validate_release_binding,bad,value,clock=clock())
    bad=deepcopy(go);bad['release_sequence']=2;refused(c.validate_release,bad)
    frame={'schema_version':'1','channel_id':uid(99),'sequence':1,'operation':'GO','body':go}
    assert len(p.encode_frame(frame,role='launcher',direction='request'))<=4096
    _fixed_n44_launcher_hold_cases(tmp_path,monkeypatch)


def test_effect_stop_preserves_cleanup_margin():
    value=prepared()
    assert c.effect_stop(value,M+29*c.SECOND)==M+28*c.SECOND
    assert c.effect_stop(value,M+c.SECOND)==M+c.SECOND
    go=release(value);go['effect_stop_ns']+=1
    refused(c.validate_release_binding,go,value,clock=clock())
    expired=release(value,lease=M+c.SECOND)
    refused(c.validate_release_binding,expired,value,clock=clock(c.SECOND))


def test_fixed_request_and_reply_role_grammar():
    sequence=p.ChannelSequence(uid(5),'terminal')
    request=sequence.make('REVIEW',prepared())
    assert p.decode_frame(p.encode_frame(request,role='terminal',direction='request'),role='terminal',direction='request')==request
    refused(p.validate_frame,request,role='ingress')
    refused(p.require_request,{'schema_version':'1','channel_id':uid(5),'sequence':1,'operation':'REVIEW',
        'body':{'request_sequence':1,'status':'ok','code':None,'data':None}},role='terminal')
    for key,item in [('approve',True),('argv',['true']),('role','broker')]:
        bad=deepcopy(request);bad['body'][key]=item;refused(p.validate_frame,bad,role='terminal')


    # Supervision uses a separate closed role, mapped replies and no arbitrary
    # child/argv selector. Every request can be reconstructed canonically.
    supervisor=p.ChannelSequence(uid(77),'launcher_supervision')
    start=supervisor.make('START',{'child_slot':'identify_client','prepared':prepared()})
    assert p.decode_frame(p.encode_frame(start,role='launcher_supervision',direction='request'),role='launcher_supervision',direction='request')==start
    refused(p.validate_frame,start,role='launcher')
    for slot in ('broker','identify_client/../parser',True):
        bad=deepcopy(start);bad['body']['child_slot']=slot;refused(p.validate_frame,bad,role='launcher_supervision')
    bad=deepcopy(start);bad['body']['argv']=['true'];refused(p.validate_frame,bad,role='launcher_supervision')
    reply={'schema_version':'1','channel_id':uid(77),'sequence':1,'operation':'BOOTSTRAP',
        'body':{'request_sequence':1,'status':'refused','code':'engagement_live_invalid_role','data':None}}
    assert p.require_reply(reply,start,role='launcher_supervision')==reply
    for operation in ('READY','START','GO'):
        bad=deepcopy(reply);bad['operation']=operation;refused(p.require_reply,bad,start,role='launcher_supervision')


def test_channel_sequences_and_cleanup_reserve():
    for operation in ('SESSION_STOP','BROKER_STOP'):
        body={'reason':'engagement_live_timeout','observed_at_ns':10*c.SECOND,
            'cleanup_deadline_ns':9*c.SECOND}
        if operation=='SESSION_STOP':body['session_id']=uid(9)
        frame={'schema_version':'1','channel_id':uid(8),'sequence':1,'operation':operation,'body':body}
        assert p.validate_frame(frame,role='lifecycle')==frame
        for end in (0,True,12*c.SECOND+1):
            bad=deepcopy(frame);bad['body']['cleanup_deadline_ns']=end
            refused(p.validate_frame,bad,role='lifecycle')
    send=p.ChannelSequence(uid(8),'ingress');receive=p.ChannelSequence(uid(8),'ingress')
    first=send.make('SNAPSHOT',None);receive.accept(first)
    refused(receive.accept,first,code='invalid_sequence')
    for _ in range(63):receive.accept(send.make('SNAPSHOT',None))
    refused(send.make,'SNAPSHOT',None,code='limit_exceeded')
    receive.accept(send.make('CLOSE',None));receive.accept(send.make('CLOSE',None))
    refused(send.make,'CLOSE',None,code='limit_exceeded')
    assert send.sent==66 and receive.received==66


    supervision=p.ChannelSequence(uid(77),'launcher_supervision')
    for _ in range(22):supervision.make('REAP',{'child_slot':'identify_admission'})
    refused(supervision.make,'REAP',{'child_slot':'identify_admission'},code='invalid_frame')
    assert supervision.sent==22


def test_prepared_echo_is_data_not_authority():
    opened_value=opened();value=prepared(opened_value=opened_value)
    assert c.validate_prepared_context(value,opened_value)==value
    assert c.validate_prepared_role_context(value,binding=opened_value['binding'],roe=opened_value['roe'],
        scope=opened_value['scope'],policy=opened_value['policy'])==value
    assert 'reference' not in c.canonical(value).decode() and 'accepted' not in value
    foreign=opened();foreign['binding']['ledger_owner_id']=uid(999)
    refused(c.validate_prepared_context,value,foreign)
    bad=deepcopy(value);bad['permit']='yes';refused(c.validate_prepared,bad)


def test_live_result_distinguishes_operation_and_proof():
    e=prepared()['envelope']
    value={'schema_version':'1','broker_id':e['broker_id'],'session_id':e['session_id'],
        'dispatch_id':e['dispatch_id'],'envelope_sha256':c.envelope_digest(e),'slot':e['slot'],
        'outcome':'unresolved','reason':'engagement_live_unavailable','admission':None,'release':None,
        'completion':None,'observation':None,'client_result_sha256':None,'cleanup_sha256':None}
    assert c.validate_live_result(value)==value
    for key,item in [('outcome','useful'),('case_passed',True),('reason',None)]:
        bad=deepcopy(value);bad[key]=item;refused(c.validate_live_result,bad)


def test_closed_errors_exclude_raw_data():
    assert c.LiveError('engagement_live_invalid_input').code=='engagement_live_invalid_input'
    for text in ('raw secret','engagement_live_/tmp/path','engagement_live_OSERROR'):
        with pytest.raises(ValueError):c.LiveError(text)
    value=prepared();value['action']['target']='/private/secret'
    error=refused(c.validate_prepared,value)
    assert error=='engagement_live_invalid_prepared'
    assert all(code.startswith('engagement_live_') and '/' not in code for code in c.ERROR_CODES)


def test_private_validation_deadline_is_shared(monkeypatch):
    now=[100.0];monkeypatch.setattr(records.time,'monotonic',lambda:now[0])
    with c._deadline_context(101.0):
        assert c._operation_deadline()==101.0
        now[0]=101.01
        refused(c.canonical,{'x':1},code='timeout')
        now[0]=100.5
    assert c._operation_deadline()==102.5
    with pytest.raises(c.LiveError):
        with c._deadline_context(100.6):
            now[0]=100.7
    now[0]=101.0
    assert c.canonical({'x':1})==b'{"x":1}'


def test_historical_replay_uses_retained_phase_clocks(monkeypatch):
    import base64
    from recon_cockpit.secure_agent import engagement_live_witness as w
    value=prepared();proof=approval(value);raw=c.canonical(proof)
    row={'raw_base64':base64.b64encode(raw).decode(),'raw_sha256':c.digest(raw),
         'witness':proof,'received_at_ns':M+c.SECOND}
    monkeypatch.setattr(w.time,'monotonic_ns',lambda:M+100000*c.SECOND)
    assert w.validate_approval_observation(row,value)==row
    row['received_at_ns']=M+11*c.SECOND
    refused(w.validate_approval_observation,row,value,code='stale_witness')


def test_imports_do_not_create_live_authority(monkeypatch):
    import importlib.util
    import socket
    import subprocess
    import sqlite3
    def forbidden(*args,**kwargs):raise AssertionError('import attempted live operation')
    monkeypatch.setattr(socket,'socket',forbidden);monkeypatch.setattr(socket,'socketpair',forbidden)
    monkeypatch.setattr(subprocess,'Popen',forbidden);monkeypatch.setattr(sqlite3,'connect',forbidden)
    # Execute a fresh private module without replacing the shared LiveError
    # identity used by other collected modules.
    spec=importlib.util.spec_from_file_location('recon_cockpit.secure_agent._live_contract_import_probe',c.__file__)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    assert module.PROFILE=='engagement-http-prefix-live-v1'


def test_sealed_contract_and_exact_inventory_pins():
    from recon_cockpit.secure_agent import engagement_live_context as context
    document=ROOT/'docs/stage4-engagement-live.md';inventory=ROOT/'docs/stage4-engagement-live-gates.json'
    assert hashlib.sha256(document.read_bytes()).hexdigest()==c.CONTRACT_SHA256
    assert hashlib.sha256(inventory.read_bytes()).hexdigest()==c.INVENTORY_SHA256
    gates=json.loads(inventory.read_text())
    assert gates['case_count']==288
    expected={row['nodeid'] for row in gates['cases'] if row['nodeid'].startswith('tests/test_secure_engagement_live_contract.py::')}
    actual={'tests/test_secure_engagement_live_contract.py::'+node.name for node in ast.parse(Path(__file__).read_text()).body if isinstance(node,ast.FunctionDef) and node.name.startswith('test_')}
    assert len(expected)==24 and actual==expected
    assert gates['parent_case_count']==26 and gates['physical_parent_case_count']==18
    recovery=gates['evidence_contract']['copied_recovery']
    assert context._RECOVERY_SCHEMAS==recovery['schemas']
    assert recovery['status']=='reviewed_contract_pending_implementation'
    assert recovery['implementation_authorized'] is True
    assert recovery['implementation_authorized_only_after_complete_pair_commit'] is True
    resources=recovery['resources'];framing=recovery['framing'];deadlines=recovery['deadlines']
    assert resources['stdout_bytes']==sum(framing[name]['header_bytes']+framing[name]['payload_bytes_max']
        for name in ('ready','result'))==2134032
    assert resources['result_payload_bytes']==resources['export_bytes']+resources['provenance_bytes']
    assert resources['scratch_data_bytes']==resources['main_bytes']+resources['journal_bytes']
    assert resources['file_size_sqlite_bytes']==resources['main_bytes']<resources['file_size_copy_bytes']
    assert deadlines['work_ns']+deadlines['closure_reserve_ns']==deadlines['total_ns']==2000000000
    assert resources['source_rows']==52
    assert resources['processes']==resources['tasks']==1
    assert recovery['launch']['entrypoint'].endswith('engagement_live_session._recovery_copy_main')
    assert set(recovery['launch']['descriptor_map'])==set(map(str,range(8)))
    schemas=recovery['schemas'];prefix='evidence_contract.copied_recovery.schemas.'
    assert schemas['helper_observation']['fields']['config']==prefix+'config'
    assert schemas['sqlite_stage']['fields']['progress_callbacks_after']['maximum']==4000
    def closed(schema):
        if isinstance(schema,dict):
            if schema.get('type')=='object':
                assert schema['additional_fields'] is False and schema['all_fields_required'] is True
            for value in schema.values():closed(value)
        elif isinstance(schema,list):
            for value in schema:closed(value)
        elif isinstance(schema,str) and schema.startswith(prefix):assert schema[len(prefix):] in schemas
    closed(schemas)
