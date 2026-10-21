"""Exact S42B-C01..C24 contract cases: declared data, never native authority."""

import ast
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import engagement_dispatch_contract as c
from recon_cockpit.secure_agent import engagement_contract as legacy
from recon_cockpit.secure_agent import configurable_contract
from recon_cockpit.secure_agent.models import parse_action, parse_policy

ROOT = Path(__file__).resolve().parents[1]
U = 946771200000000000  # 2000-01-02 UTC; independent of the actual host clock.
M = 10000000000
MS = 1000000


def uid(number):
    return str(UUID(int=number, version=4))


def roe():
    result = json.loads((ROOT / 'examples/secure-agent-engagement-roe.json').read_text())
    result['window'] = {'start_utc': '2000-01-02T00:00:00Z', 'end_utc': '2000-01-03T00:00:00Z'}
    return result


def clock(delta=0, width=0):
    return {'utc_ns': U + delta, 'mono_before_ns': M + delta, 'mono_after_ns': M + delta + width}


def request(operation, number, body, revision=1, generation=0):
    return {'schema_version': '2', 'engagement_id': uid(1), 'event_id': uid(100 + number),
            'operation': operation, 'expected_revision': None if operation in {'create', 'complete'} else revision,
            'expected_generation': None if operation in {'create', 'complete'} else generation, 'body': body}


def session(number=2, session_id=3, owner_id=2, delta=0, revision=1, generation=0):
    return request('session', number, {'session_id': uid(session_id), 'owner_id': uid(owner_id),
        'clock': clock(delta), 'original_deadline_ns': M + delta + 60000000000}, revision, generation)


def reserve(slot='http_identify', number=3, delta=MS, dispatch_id=4, session_id=3,
            owner_id=2, sequence=1, revision=1, generation=0):
    return request('reserve', number, {'dispatch_id': uid(dispatch_id), 'session_id': uid(session_id),
        'owner_id': uid(owner_id), 'slot': slot, 'approval': {'broker_id': uid(10),
        'consume_sequence': sequence, 'witness_sha256': 'a' * 64}, 'audit': {'writer_id': uid(11),
        'audit_sequence': sequence, 'event_sha256': 'b' * 64}, 'clock': clock(delta)}, revision, generation)


def complete(number=4, delta=2 * MS, dispatch_id=4, session_id=3, owner_id=2,
             outcome='reported_success', observation=True):
    obs = {'evidence_sha256': 'c' * 64, 'connections': 1, 'request_bytes': 64, 'response_bytes': 64}
    return request('complete', number, {'dispatch_id': uid(dispatch_id), 'session_id': uid(session_id),
        'owner_id': uid(owner_id), 'outcome': outcome, 'observation': obs if observation else None,
        'clock': clock(delta)})


def requests():
    return [request('create', 1, roe()), session(), reserve(), complete(),
            reserve('http_headers', 5, 3 * MS, 5, sequence=2), complete(6, 4 * MS, 5),
            request('revoke', 7, None)]


def history(items=None):
    result = None
    for item in requests() if items is None else items:
        result, _ = c._apply(result, item)
    return result


def refused(function, *args, code=None, **kwargs):
    with pytest.raises(c.DispatchLedgerError) as caught:
        function(*args, **kwargs)
    if code is not None:
        assert caught.value.code == 'engagement_dispatch_' + code
    return caught.value.code


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def test_pins_closed_contract():
    doc = ROOT / 'docs/stage4-engagement-dispatch-ledger.md'
    inventory = ROOT / 'docs/stage4-engagement-dispatch-ledger-gates.json'
    assert hashlib.sha256(doc.read_bytes()).hexdigest() == c.CONTRACT_SHA256
    assert hashlib.sha256(inventory.read_bytes()).hexdigest() == c.INVENTORY_SHA256
    pinned = json.loads(inventory.read_text())
    assert list(c.SCHEMA_SQL) == pinned['sqlite']['DDL']
    assert c.SQLITE_LIMITS == pinned['sqlite']['limits']
    assert c.ERROR_CODES == frozenset(pinned['error_codes'])
    assert len(c.SCHEMA_OBJECTS) == 23
    nodes = {f'{Path(__file__).name}::{n.name}' for n in ast.parse(Path(__file__).read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')}
    assert nodes == {x['nodeid'].split('/')[-1] for x in pinned['cases'] if x['group'] == 'contract'}
    assert len(nodes) == 24
    assert (c.MAX_EXPORT_BYTES, c.MAX_DEPTH, c.MAX_EVENTS) == (2097152, 12, 257)
    with pytest.raises(ValueError):
        c.DispatchLedgerError('untrusted explanation')


def test_accepts_existing_roe_forms():
    profiles = tuple(legacy.PROFILES)
    for size in range(1, 4):
        for selected in itertools.combinations(profiles, size):
            for excluded in ([], ['http'], ['ssh']):
                value = roe()
                value['allowed_profiles'], value['excluded_services'] = list(selected), excluded
                normalized = c.validate_request(request('create', 1, value))
                assert normalized['body'] == legacy.validate_roe(value)
                value['scope']['http']['path'] = '/changed'
                assert normalized['body']['scope']['http']['path'] == '/'


def test_validates_six_request_bodies():
    values = requests()[:4] + [request('revise', 8, roe()), request('revoke', 9, None)]
    assert {x['operation'] for x in values} == {'create', 'session', 'reserve', 'complete', 'revise', 'revoke'}
    for value in values:
        assert c.decode_request(encoded(value)) == value
        wrong = deepcopy(value)
        wrong['unexpected'] = None
        refused(c.validate_request, wrong, code='invalid_request')
        wrong = deepcopy(value)
        wrong['expected_revision'] = 1 if value['expected_revision'] is None else None
        refused(c.validate_request, wrong, code='invalid_request')
    for key in ('cost', 'policy', 'send_allowed', 'grant'):
        value = reserve()
        value['body'][key] = {}
        refused(c.validate_request, value, code='invalid_request')


def test_rejects_noncanonical_types():
    valid = encoded(request('create', 1, roe()))
    for raw in (valid[:-1] + b',"schema_version":"2"}', valid + b'{}', b'\xff', b'{"x":NaN}',
                b'{"x":1.0}', b'{"x":-1}', b'{"x":9223372036854775808}', b'{"\\ud800":1}'):
        refused(c.decode_request, raw, code='invalid_request')
    for value in (True, 1.0, '1', None):
        bad = reserve()
        bad['body']['approval']['consume_sequence'] = value
        refused(c.validate_request, bad, code='invalid_request')
    for bad in ({1: 'value'}, {'key': '\ud800'}, {'\udfff': 'value'}, {'v': float('inf')}):
        refused(c.canonical, bad, code='invalid_input')
    refused(c.decode_request, bytearray(valid), code='invalid_request')


def test_enforces_codec_bounds_shared_deadline(monkeypatch):
    assert len(c.canonical('a' * (c.MAX_EXPORT_BYTES - 2))) == c.MAX_EXPORT_BYTES
    refused(c.canonical, 'a' * (c.MAX_EXPORT_BYTES - 1), code='limit_exceeded')
    nested = 0
    for _ in range(c.MAX_DEPTH):
        nested = [nested]
    assert c.canonical(nested)
    refused(c.canonical, [nested], code='limit_exceeded')
    refused(c.decode_request, b'[' * 13, code='limit_exceeded')
    refused(c.canonical, {'a' * (c.MAX_EXPORT_BYTES + 1): 0}, code='limit_exceeded')
    now = [0.0]
    monkeypatch.setattr(legacy.time, 'monotonic', lambda: now[0])
    original = legacy.validate_roe
    entered_scope = []
    monkeypatch.setattr(legacy, 'validate_scope', lambda value: entered_scope.append(True))
    def slow(value):
        now[0] = 2.01
        return original(value)
    monkeypatch.setattr(legacy, 'validate_roe', slow)
    with c._deadline_context(2.0):
        now[0] = 1.9
        refused(c.policy_for_roe, roe(), code='timeout')
        now[0] = 1.9  # Leave the context before expiry for this entry-guard witness.
    assert entered_scope == []
    assert legacy._active_deadline() is None
    now[0] = 3.0
    assert c.canonical({'fresh': True}) == b'{"fresh":true}'
    token = legacy._ACTIVE_DEADLINE.set((legacy.os.getpid() + 1, 0.0))
    try:
        assert c.canonical(None) == b'null'
    finally:
        legacy._ACTIVE_DEADLINE.reset(token)
    original_dumps = c.json.dumps
    def slow_encode(*args, **kwargs):
        result = original_dumps(*args, **kwargs)
        now[0] += 3.0
        return result
    with monkeypatch.context() as patch:
        patch.setattr(c.json, 'dumps', slow_encode)
        refused(c.canonical, {'bounded_encoding': True}, code='timeout')
    assert legacy._active_deadline() is None


def test_preserves_action_policy_shapes():
    snapshot = history(requests()[:6])
    expected_policy = {'schema_version': '1', 'policy_version': 'engagement-http-prefix-v1',
        'allowed_targets': ['10.77.0.10'], 'allowed_tools': ['configurable_nmap_service_v1',
        'configurable_http_headers_v1'], 'allowed_ports': [8080], 'allowed_methods': ['GET'],
        'max_timeout_seconds': 5, 'max_output_bytes': 8192, 'max_targets': 1,
        'require_approval': True, 'approval_ttl_seconds': 60}
    assert c.policy_for_roe(roe()) == expected_policy
    for step, row in enumerate(snapshot['reservations'], 1):
        action = configurable_contract.action(roe()['scope'], step)
        assert UUID(row['action_id']).version == 5
        assert row['action_id'] == action['action_id']
        assert row['action_sha256'] == parse_action(action).digest
        assert row['policy_sha256'] == parse_policy(expected_policy).digest
    value = session()
    value['body']['session_id'] = snapshot['reservations'][0]['action_id']
    refused(c.validate_request, value, code='invalid_request')


def test_requires_exact_http_prefix():
    for size in range(1, 4):
        for selected in itertools.combinations(legacy.PROFILES, size):
            for excluded, path in itertools.product(([], ['http'], ['ssh']), ('/', '/other')):
                value = roe()
                value['allowed_profiles'], value['excluded_services'] = list(selected), excluded
                value['scope']['http']['path'] = path
                allowed = (path == '/' and 'http' not in excluded and
                           {'configurable_nmap_service_v1', 'configurable_http_headers_v1'} <= set(selected))
                if allowed:
                    assert c.policy_for_roe(value)['require_approval'] is True
                else:
                    refused(c.policy_for_roe, value, code='unsupported_plan')


def test_bounds_clock_brackets_and_overflow():
    assert c.validate_clock(clock(width=50000000)) == clock(width=50000000)
    for value in (clock(width=50000001), clock(width=-1), {'utc_ns': True,
            'mono_before_ns': 0, 'mono_after_ns': 0}):
        refused(c.validate_clock, value, code='invalid_request')
    value = clock()
    value['mono_before_ns'] = value['mono_after_ns'] = c.INTEGER_MAX - 1
    refused(c.window_budget, roe(), value, original_deadline_ns=c.INTEGER_MAX, code='invalid_request')


def test_checks_inclusive_window_start():
    before = clock()
    before['utc_ns'] -= 1
    refused(c.window_budget, roe(), before, original_deadline_ns=M + 10**9, code='window_closed')
    actual = c.window_budget(roe(), clock(), original_deadline_ns=M + 10**9)
    assert actual == {'window_deadline_ns': M + 86400 * 10**9, 'session_deadline_ns': M + 10**9}


def test_checks_exclusive_window_end():
    for value in (clock(86400 * 10**9), clock(86400 * 10**9 - MS, MS)):
        refused(c.window_budget, roe(), value,
                original_deadline_ns=value['mono_after_ns'] + 10**9, code='window_closed')


def test_clips_original_session_deadline():
    value = clock(86400 * 10**9 - 10 * 10**9)
    got = c.window_budget(roe(), value, original_deadline_ns=value['mono_after_ns'] + 60 * 10**9)
    assert got['session_deadline_ns'] == M + 86400 * 10**9
    refused(c.window_budget, roe(), clock(), original_deadline_ns=M + 60 * 10**9 + 1,
            code='invalid_request')
    refused(c.window_budget, roe(), clock(), original_deadline_ns=M, code='deadline_expired')


def test_detects_same_session_clock_changes():
    base = history([requests()[0], session(delta=2 * 10**9)])
    for field, value in [('mono_before_ns', M + 10**9), ('utc_ns', U + 10**9), ('utc_ns', U + 5 * 10**9)]:
        attempt = reserve(delta=3 * 10**9)
        attempt['body']['clock'][field] = value
        if field == 'mono_before_ns':
            attempt['body']['clock']['mono_after_ns'] = value
        refused(c._apply, base, attempt, code='clock_invalid')
    edge = reserve(delta=3 * 10**9)
    edge['body']['clock']['utc_ns'] += 50000000
    got, _ = c._apply(base, edge)
    assert got['reservations'][0]['deadline_ns'] == M + 32 * 10**9
    edge['body']['clock']['utc_ns'] += 1
    refused(c._apply, base, edge, code='clock_invalid')


def test_retains_durable_utc_high_water():
    base = history(requests()[:3])
    late = complete()
    late['body']['clock']['utc_ns'] += 86400 * 10**9
    got, _ = c._apply(base, late)
    water = late['body']['clock']['utc_ns']
    assert got['completions'][0]['clock_status'] == 'window_closed'
    assert got['state']['utc_high_water_ns'] == water
    refused(c._apply, got, session(8, 30, 20, 3 * MS), code='clock_invalid')
    got, _ = c._apply(got, request('revise', 9, roe()))
    assert got['state']['utc_high_water_ns'] == water
    got, _ = c._apply(got, request('revoke', 10, None, 2, 1))
    assert c.validate_export(got)['state']['utc_high_water_ns'] == water


def test_derives_action_ready_deadline():
    base = history(requests()[:2])
    refused(c._apply, base, reserve(delta=30 * 10**9), code='deadline_expired')
    small = roe()
    small['limits']['max_action_ms'] = 1000
    narrow = history([request('create', 1, small), session()])
    refused(c._apply, narrow, reserve(delta=10**9), code='deadline_expired')
    got = history(requests()[:5])
    identify, headers = got['reservations']
    assert identify['ready_at_ns'] == M
    assert headers['ready_at_ns'] == M + 2 * MS
    assert headers['deadline_ns'] == M + 2 * MS + 30 * 10**9
    assert identify['reservation']['runtime_ms'] == headers['reservation']['runtime_ms'] == 30000


def test_replays_usage_under_historical_limits():
    got = history(requests()[:3])
    limited = roe()
    limited['limits']['max_connections'] = 1
    got, _ = c._apply(got, request('revise', 8, limited))
    assert got['state']['usage']['connections'] == 3
    assert c.validate_export(got) == got
    got, _ = c._apply(got, session(9, 30, 20, 2 * MS, 2, 1))
    refused(c._apply, got, reserve(number=10, delta=3 * MS, dispatch_id=40,
            session_id=30, owner_id=20, sequence=2, revision=2, generation=1), code='allowance_exhausted')


def test_distinguishes_recorded_from_retry():
    got = history()
    first = got['events'][0]['receipt']
    assert first['status'] == 'recorded' and first['generation'] == 0
    assert got['state']['status'] == 'revoked'
    assert c.validate_export(got)['events'][0]['receipt'] == first
    # The store's historical retry wrapper cannot change the immutable receipt.
    wrapper = {'schema_version': '2', 'kind': 'data_only', 'disposition': 'already_recorded', 'receipt': first}
    assert json.loads(c.canonical(wrapper))['receipt'] == first
    refused(c._apply, got, requests()[0], code='conflict')
    assert not {'grant', 'permit', 'authorized', 'send_allowed', 'execution_success'} & set(first)


def test_reconstructs_complete_event_history(monkeypatch):
    items = requests()
    items.insert(1, request('revise', 8, roe()))
    for item in items[2:]:
        if item['operation'] != 'complete':
            item['expected_revision'], item['expected_generation'] = 2, 1
    got = history(items)
    expected_usage = {'actions': 2, 'connections': 4, 'request_bytes': 4352,
                      'response_bytes': 6144, 'runtime_ms': 60000}
    assert got['state'] == {'revision': 2, 'generation': 2, 'status': 'revoked', 'last_sequence': 8,
        'roe_sha256': legacy.roe_digest(roe()), 'usage': expected_usage, 'utc_high_water_ns': U + 4 * MS}
    for sequence, event in enumerate(got['events'], 1):
        assert event['sequence'] == event['receipt']['sequence'] == sequence
        assert event['request_sha256'] == hashlib.sha256(b'recon-engagement-dispatch-request-v2\0' + encoded(event['request'])).hexdigest()
    assert got['events'][-1]['receipt']['state_sha256'] == hashlib.sha256(
        b'recon-engagement-dispatch-state-v2\0' + encoded(got['state'])).hexdigest()
    calls = []
    original = c._Engine.push
    def counted(self, value):
        calls.append(value['event_id'])
        return original(self, value)
    monkeypatch.setattr(c._Engine, 'push', counted)
    decoded = c.decode_export(encoded(got))
    assert len(calls) == len(items)  # One linear replay, not recursive prefix replays.
    assert decoded == got
    got['state']['usage']['actions'] = 0
    assert decoded['state']['usage']['actions'] == 2


def test_rejects_independent_history_tampering():
    original = history()
    mutations = [
        lambda x: x['state']['usage'].__setitem__('request_bytes', 1),
        lambda x: x['reservations'][0]['reservation'].__setitem__('connections', 1),
        lambda x: x['reservations'][0].__setitem__('action_sha256', '0' * 64),
        lambda x: x['sessions'][0].__setitem__('policy_sha256', '0' * 64),
        lambda x: x['completions'][0].__setitem__('continuation_eligible', False),
        lambda x: x['events'][2]['request']['body'].__setitem__('owner_id', uid(777)),
        lambda x: x['events'][2].__setitem__('request_sha256', '0' * 64),
        lambda x: x['events'][2]['receipt'].__setitem__('state_sha256', '0' * 64),
        lambda x: x['events'].reverse(), lambda x: x['events'].pop(),
        lambda x: x['completions'].pop(), lambda x: x['reservations'].append(deepcopy(x['reservations'][0])),
        lambda x: x['events'][4]['request']['body']['approval'].__setitem__('consume_sequence', 1),
        lambda x: x['events'][4]['request']['body']['audit'].__setitem__('audit_sequence', 1),
        lambda x: x['events'][4]['request']['body'].__setitem__('dispatch_id', uid(4)),
        lambda x: x['events'][4]['request']['body']['clock'].__setitem__('utc_ns', U + 10**9),
    ]
    for mutate in mutations:
        value = deepcopy(original)
        mutate(value)
        refused(c.validate_export, value, code='invalid_export')


def test_labels_coherent_rewrite_limit():
    original = history()
    rewritten = requests()
    for item in rewritten:
        item['engagement_id'] = uid(999)
    # Full consistent hostile-host rewriting cannot be authenticated by this codec.
    changed = history(rewritten)
    assert c.validate_export(changed) == changed
    assert changed != original
    assert set(changed) == {'schema_version', 'kind', 'engagement_id', 'state', 'revisions',
                           'sessions', 'reservations', 'completions', 'events'}


def test_records_late_completion_without_eligibility():
    base = history(requests()[:3])
    revoked, _ = c._apply(base, request('revoke', 8, None))
    done, _ = c._apply(revoked, complete())
    assert done['completions'][0]['clock_status'] == 'valid'
    assert done['completions'][0]['continuation_eligible'] is False
    shifted = roe()
    shifted['window'] = {'start_utc': '2000-01-03T00:00:00Z', 'end_utc': '2000-01-04T00:00:00Z'}
    revised, _ = c._apply(base, request('revise', 8, shifted))
    done, _ = c._apply(revised, complete())
    assert done['completions'][0]['clock_status'] == 'valid'  # Historical ROE window.
    assert done['completions'][0]['continuation_eligible'] is False
    variants = [
        ('nonmonotonic', {'utc_ns': U + 86400 * 10**9, 'mono_before_ns': M, 'mono_after_ns': M}),
        ('window_closed', clock(86400 * 10**9)),
        ('clock_changed', {'utc_ns': U + 10**9, 'mono_before_ns': M + 31 * 10**9,
                           'mono_after_ns': M + 31 * 10**9}),
        ('deadline_elapsed', clock(31 * 10**9)),
    ]
    for expected, observed in variants:
        attempt = complete()
        attempt['body']['clock'] = observed
        done, _ = c._apply(base, attempt)
        assert done['completions'][0]['clock_status'] == expected
        assert done['completions'][0]['continuation_eligible'] is False
        assert c.validate_export(done) == done


def test_bounds_reported_observation():
    for key in ('connections', 'request_bytes', 'response_bytes'):
        attempt = complete()
        attempt['body']['observation'][key] = 0
        refused(c.validate_request, attempt, code='invalid_request')
    got = history(requests()[:5])
    attempt = complete(6, 4 * MS, 5)
    attempt['body']['observation']['request_bytes'] = 257
    refused(c._apply, got, attempt, code='invalid_request')
    base = history(requests()[:3])
    partial = complete(outcome='reported_failure')
    partial['body']['observation'].update(connections=0, request_bytes=0, response_bytes=0)
    done, _ = c._apply(base, partial)
    assert done['state']['usage'] == base['state']['usage']
    assert done['completions'][0]['continuation_eligible'] is False


def test_preserves_unknown_delivery():
    base = history(requests()[:3])
    assert base['completions'] == []
    uncertain = complete(outcome='unresolved', observation=False)
    done, _ = c._apply(base, uncertain)
    assert done['completions'][0]['observation'] is None
    assert done['state']['usage'] == base['state']['usage']
    assert c.validate_export(done) == done
    refused(c._apply, done, reserve('http_headers', 5, 3 * MS, 5, sequence=2), code='predecessor_required')


def test_keeps_pure_codecs_effect_free(monkeypatch):
    import socket
    import sqlite3
    import subprocess
    import time
    value = history()
    declaration = roe()
    def forbidden(*args, **kwargs):
        raise AssertionError('unexpected external effect or UTC sampling')
    for module, name in ((socket, 'socket'), (sqlite3, 'connect'), (subprocess, 'Popen'),
                         (time, 'time'), (time, 'time_ns')):
        monkeypatch.setattr(module, name, forbidden)
    assert c.validate_export(value) == value
    assert c.policy_for_roe(declaration)['require_approval'] is True
    assert c.window_budget(declaration, clock(), original_deadline_ns=M + 10**9)


def test_separates_digest_domains():
    value = request('create', 1, roe())
    raw = encoded(value)
    assert c.REQUEST_DOMAIN == b'recon-engagement-dispatch-request-v2\0'
    assert c.STATE_DOMAIN == b'recon-engagement-dispatch-state-v2\0'
    assert c.request_digest(value) == hashlib.sha256(c.REQUEST_DOMAIN + raw).hexdigest()
    assert c.request_digest(value) != hashlib.sha256(legacy.REQUEST_DOMAIN + raw).hexdigest()
    assert c._roe_digest(roe()) == hashlib.sha256(legacy.ROE_DOMAIN + encoded(roe())).hexdigest()
    got = history([value])
    got['events'][0]['request_sha256'] = hashlib.sha256(raw).hexdigest()
    refused(c.validate_export, got, code='invalid_export')
