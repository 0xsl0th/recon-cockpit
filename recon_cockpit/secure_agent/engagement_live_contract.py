"""Closed data contracts for the isolated owned HTTP engagement runtime.

Validation supplies no approval, store handle, channel or execution authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import time
from contextlib import contextmanager
from functools import wraps
from uuid import NAMESPACE_URL, uuid5

from . import engagement_contract as records
from . import engagement_dispatch_contract as ledger
from . import configurable_contract
from .configurable_scope import scope_digest, validate_scope
from .models import parse_action, parse_policy

PROFILE = 'engagement-http-prefix-live-v1'
BACKEND = 'linux_engagement_http_prefix'
CONTRACT_SHA256 = '7497a08dd16d6ff73d8e3102b6ea38a1ad69920fdd96ad091d3123b864df7aa1'
INVENTORY_SHA256 = 'b8853a68ff3bc43a63cbaf8e5b8642a1443ee25c276ae1a6a0b5204eb8d1d9f1'
MAX_PACKET = 32768
MAX_CANONICAL = 2097152
MAX_DEPTH = 64
INTEGER_MAX = 2**63 - 1
SECOND = 1000000000
FRESHNESS_NS = 10 * SECOND
CLEANUP_NS = 2 * SECOND
ENVELOPE_DOMAIN = b'recon-engagement-live-envelope-v1\x00'
PREPARED_DOMAIN = b'recon-engagement-live-prepared-v1\x00'
SLOTS = {'http_identify': (1, 3, 4096, 4096, 8192, 5 * SECOND),
         'http_headers': (2, 1, 256, 2048, 2048, SECOND)}
ERROR_CODES = frozenset('engagement_live_' + name for name in (
    'invalid_input limit_exceeded timeout cancelled unavailable unsupported_runtime '
    'invalid_runtime invalid_role invalid_channel invalid_sequence invalid_frame '
    'invalid_prepared invalid_witness stale_witness approval_denied '
    'approval_unavailable approval_unknown_or_replayed audit_unavailable '
    'audit_not_durable foreign_owner session_unavailable dispatch_replayed '
    'revision_changed revoked window_not_open window_closed clock_changed '
    'allowance_exhausted prerequisite_missing admission_unavailable '
    'release_unavailable meter_refused parser_unavailable cleanup_incomplete '
    'evidence_invalid evidence_incomplete output_exists').split())
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')
_HASH = re.compile(r'[0-9a-f]{64}')
_SURROGATE = re.compile(r'[\ud800-\udfff]')
BINDING_FIELDS = frozenset(('schema_version profile engagement_id revision generation roe_sha256 '
    'scope_sha256 broker_id ledger_owner_id session_id reviewer_id review_mode policy_sha256 '
    'runtime_sha256 window_start_utc_ns window_end_utc_ns clock_anchor session_deadline_ns '
    'broker_deadline_ns').split())
ENVELOPE_FIELDS = BINDING_FIELDS | frozenset(('dispatch_id slot action_sha256 action_ready_ns '
    'action_deadline_ns cost output_limit native_timeout_ns').split())
RELEASE_FIELDS = frozenset(('schema_version broker_id ledger_owner_id session_id dispatch_id '
    'envelope_sha256 prepared_sha256 reservation_event_id reservation_sequence '
    'reservation_state_sha256 approval_witness_sha256 audit_witness_sha256 guard_clock '
    'effective_lease_deadline_ns effect_stop_ns release_sequence').split())
OUTCOMES = frozenset(('useful denied failed cancelled partial unresolved not_started').split())
CHILD_SLOTS = {
    'identify_client': ('nmap', 'http_identify', 5),
    'identify_admission': ('admission', 'http_identify', 6),
    'identify_parser': ('parser', 'http_identify', 7),
    'headers_client': ('headers', 'http_headers', 8),
    'headers_admission': ('admission', 'http_headers', 9),
    'headers_parser': ('parser', 'http_headers', 10),
}
BROKER_TRANSCRIPT_BYTES = 896 * 1024
BROKER_TRANSCRIPT_ROWS = 1984
HOST_TRANSCRIPT_BYTES = 256 * 1024
HOST_TRANSCRIPT_ROWS = 128
SUPERVISION_ROWS = 96
SUPERVISION_ROW_BYTES = 3072


class LiveError(ValueError):
    def __init__(self, code):
        if type(code) is not str or code not in ERROR_CODES:
            raise ValueError('engagement_live_invalid_error_code')
        self.code = code
        super().__init__(code)


def fail(code='invalid_input'):
    raise LiveError('engagement_live_' + code)


def _map(error, default='invalid_input'):
    suffix = error.code.removeprefix('engagement_dispatch_').removeprefix('engagement_')
    fail(suffix if suffix in {'timeout', 'limit_exceeded'} else default)


def _operation_deadline():
    return records._operation_deadline()


def _check_deadline(deadline):
    try:
        records._check_time(deadline)
    except records.EngagementError as exc:
        _map(exc)


@contextmanager
def _deadline_context(deadline):
    try:
        with records._using_deadline(deadline) as effective:
            yield effective
    except (records.EngagementError, ledger.DispatchLedgerError) as exc:
        _map(exc)


def bounded(function):
    @wraps(function)
    def call(*args, **kwargs):
        with _deadline_context(_operation_deadline()):
            return function(*args, **kwargs)
    return call


def validation(code):
    def decorate(function):
        @wraps(function)
        @bounded
        def call(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except LiveError as exc:
                if exc.code.endswith(('_timeout', '_limit_exceeded', '_stale_witness')):
                    raise
                fail(code)
            except (records.EngagementError, ledger.DispatchLedgerError) as exc:
                _map(exc, code)
            except (KeyError, ValueError, TypeError, OverflowError, RecursionError):
                fail(code)
        return call
    return decorate


def obj(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        fail()
    return value


def integer(value, minimum=0, maximum=INTEGER_MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        fail()
    return value


def member(value, choices):
    if type(value) is not str or value not in choices:
        fail()
    return value


def uuid(value):
    if type(value) is not str or _UUID.fullmatch(value) is None:
        fail()
    return value


def digest_string(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        fail()
    return value


def digest(raw):
    if type(raw) is not bytes:
        fail()
    return hashlib.sha256(raw).hexdigest()


def _tree(value, maximum, depth=MAX_DEPTH):
    todo = [(value, 0)]
    units = 0
    deadline = _operation_deadline()
    _check_deadline(deadline)
    while todo:
        current, level = todo.pop()
        units += 1
        if units & 255 == 0:
            _check_deadline(deadline)
        if level > depth or units > maximum:
            fail('limit_exceeded')
        if type(current) is dict:
            if len(current) > maximum:
                fail('limit_exceeded')
            for key, item in current.items():
                if type(key) is not str or _SURROGATE.search(key):
                    fail()
                units += len(key)
                todo.append((item, level + 1))
        elif type(current) is list:
            if len(current) > maximum:
                fail('limit_exceeded')
            todo.extend((item, level + 1) for item in current)
        elif type(current) is str:
            if _SURROGATE.search(current):
                fail()
            units += len(current)
        elif type(current) is int:
            if not -INTEGER_MAX <= current <= INTEGER_MAX:
                fail()
        elif current is not None and type(current) is not bool:
            fail()
        if units > maximum:
            fail('limit_exceeded')
    _check_deadline(deadline)


@bounded
def canonical(value, *, max_bytes=MAX_PACKET):
    integer(max_bytes, 1, MAX_CANONICAL)
    _tree(value, max_bytes)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (UnicodeError, ValueError, TypeError, RecursionError):
        fail()
    if len(raw) > max_bytes:
        fail('limit_exceeded')
    _check_deadline(_operation_deadline())
    return raw


@bounded
def decode(raw, *, max_bytes=MAX_PACKET):
    integer(max_bytes, 1, MAX_CANONICAL)
    if type(raw) is not bytes:
        fail()
    if not raw or len(raw) > max_bytes:
        fail('limit_exceeded')
    # Bound nesting before the recursive JSON decoder; quoted escapes do not count.
    level = 0
    quoted = escaped = False
    for offset, byte in enumerate(raw):
        if offset & 4095 == 0:
            _check_deadline(_operation_deadline())
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            level += 1
            if level > MAX_DEPTH:
                fail('limit_exceeded')
        elif byte in (93, 125):
            level -= 1
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result or _SURROGATE.search(key):
                fail()
            result[key] = item
        return result
    def reject(_):
        fail()
    def number(text):
        if len(text) > 20:
            fail()
        return integer(int(text), -INTEGER_MAX)
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_int=number, parse_float=reject, parse_constant=reject)
    except LiveError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        fail()
    _tree(value, max_bytes)
    return value


def detached(value, maximum=MAX_PACKET):
    return decode(canonical(value, max_bytes=maximum), max_bytes=maximum)


@validation('invalid_channel')
def validate_child_slot_bindings(value):
    """The fixed pair inventory is data; it grants no child-release authority."""
    value = detached(value)
    if type(value) is not list or len(value) != len(CHILD_SLOTS):
        fail()
    workers, endpoints = set(), set()
    for row, (name, (role, _, fd)) in zip(value, CHILD_SLOTS.items(), strict=True):
        obj(row, ('child_slot', 'role', 'worker_id', 'pair'))
        if row['child_slot'] != name or row['role'] != role:
            fail()
        worker = uuid(row['worker_id'])
        if worker in workers:
            fail()
        workers.add(worker)
        pair = obj(row['pair'], ('launcher_fd', 'request_endpoint', 'child_endpoint'))
        if integer(pair['launcher_fd'], 5, 10) != fd:
            fail()
        for key in ('request_endpoint', 'child_endpoint'):
            endpoint = obj(pair[key], ('device', 'inode', 'mode', 'flags'))
            identity = (integer(endpoint['device'], 0, 2**64-1),
                        integer(endpoint['inode'], 1, 2**64-1))
            mode = integer(endpoint['mode'], 0, 2**32-1)
            flags = integer(endpoint['flags'], 0, 2**32-1)
            # Linux F_GETFL constants describe the pinned execution platform,
            # independently of the portable inspector's operating system.
            if (not stat.S_ISSOCK(mode) or flags & 3 != 2 or not flags & 0x800
                    or flags & 0x200000 or identity in endpoints):
                fail()
            endpoints.add(identity)
    return value


@validation('invalid_prepared')
def validate_live_roe(value):
    """The complete fixed HTTP prefix must be declared before live READY."""
    value=records.validate_roe(value)
    if (value['scope']['http']['path']!='/' or 'http' in value['excluded_services']
            or not {'configurable_nmap_service_v1','configurable_http_headers_v1'} <= set(value['allowed_profiles'])):
        fail('invalid_prepared')
    return value


@validation('invalid_prepared')
def validate_session_binding(value):
    value = detached(value, 16384)
    obj(value, BINDING_FIELDS)
    if value['schema_version'] != '1' or value['profile'] != PROFILE:
        fail()
    for key in ('engagement_id', 'broker_id', 'ledger_owner_id', 'session_id', 'reviewer_id'):
        uuid(value[key])
    for key in ('roe_sha256', 'scope_sha256', 'policy_sha256', 'runtime_sha256'):
        digest_string(value[key])
    integer(value['revision'], 1, 64)
    integer(value['generation'], 0, 64)
    member(value['review_mode'], {'terminal', 'graphical_v1'})
    start = integer(value['window_start_utc_ns'], ledger.UTC_MIN, ledger.UTC_MAX)
    end = integer(value['window_end_utc_ns'], ledger.UTC_MIN, ledger.UTC_MAX)
    if start >= end:
        fail()
    anchor = ledger.validate_clock(value['clock_anchor'])
    session = integer(value['session_deadline_ns'], 1)
    broker = integer(value['broker_deadline_ns'], 1)
    if not anchor['mono_after_ns'] < session <= min(broker, anchor['mono_after_ns'] + 60 * SECOND):
        fail()
    if broker > anchor['mono_after_ns'] + 120 * SECOND:
        fail()
    check_clock(anchor, anchor=anchor, window_start_utc_ns=start,
                window_end_utc_ns=end, deadline_ns=session)
    return value


@validation('invalid_prepared')
def validate_session_opened(value):
    value = detached(value)
    obj(value, ('schema_version', 'binding', 'session_receipt', 'roe', 'scope', 'policy'))
    if value['schema_version'] != '1':
        fail()
    binding = validate_session_binding(value['binding'])
    roe = validate_live_roe(value['roe'])
    scope = validate_scope(value['scope'])
    policy = ledger.policy_for_roe(roe)
    if (scope != roe['scope'] or value['policy'] != policy
            or binding['roe_sha256'] != records.roe_digest(roe)
            or binding['scope_sha256'] != scope_digest(scope)
            or binding['policy_sha256'] != parse_policy(policy).digest
            or list(ledger._window(roe)) != [binding['window_start_utc_ns'], binding['window_end_utc_ns']]):
        fail()
    result = validate_ledger_result(value['session_receipt'])
    receipt = result['receipt']
    if result['disposition'] != 'recorded' or receipt['operation'] != 'session' or receipt['session_id'] != binding['session_id']:
        fail()
    if (receipt['engagement_id'] != binding['engagement_id']
            or receipt['revision'] != binding['revision']
            or receipt['generation'] != binding['generation']):
        fail()
    return value


@validation('invalid_prepared')
def validate_envelope(value):
    value = detached(value, 16384)
    obj(value, ENVELOPE_FIELDS)
    binding = {key: value[key] for key in BINDING_FIELDS}
    validate_session_binding(binding)
    uuid(value['dispatch_id'])
    digest_string(value['action_sha256'])
    slot = member(value['slot'], SLOTS)
    _, connections, request_bytes, response_bytes, output, timeout = SLOTS[slot]
    cost = obj(value['cost'], ('actions', 'connections', 'request_bytes', 'response_bytes', 'runtime_ms'))
    for key, expected in [('actions', 1), ('connections', connections),
                          ('request_bytes', request_bytes), ('response_bytes', response_bytes)]:
        if integer(cost[key]) != expected:
            fail()
    integer(cost['runtime_ms'], 1, 30000)
    if integer(value['output_limit']) != output or integer(value['native_timeout_ns']) != timeout:
        fail()
    ready = integer(value['action_ready_ns'])
    deadline = integer(value['action_deadline_ns'], 1)
    if (ready < value['clock_anchor']['mono_after_ns'] or not ready < deadline
            or deadline > min(value['session_deadline_ns'], value['broker_deadline_ns'],
                              ready + cost['runtime_ms'] * 1000000)):
        fail()
    return value


@validation('invalid_prepared')
def validate_prepared(value):
    value = detached(value, 16384)
    obj(value, ('schema_version', 'envelope', 'action', 'policy'))
    if value['schema_version'] != '1':
        fail()
    e = validate_envelope(value['envelope'])
    action, policy = parse_action(value['action']), parse_policy(value['policy'])
    step, _, _, _, output, timeout = SLOTS[e['slot']]
    expected_tool = configurable_contract.TOOL_IDS[step - 1]
    expected_id = str(uuid5(NAMESPACE_URL, configurable_contract.WORKFLOW + ':' + e['scope_sha256'] + ':' + str(step)))
    expected_params = {'port': action.to_dict()['parameters']['port'], 'timeout_seconds': timeout // SECOND,
                       'max_output_bytes': output}
    if step == 2:
        expected_params.update(method='GET', path='/')
    if (action.digest != e['action_sha256'] or policy.digest != e['policy_sha256']
            or action.tool_id != expected_tool or action.action_id != expected_id
            or action.to_dict()['parameters'] != expected_params
            or action.rationale != 'Deterministic owned endpoint assessment; operator scope ' + e['scope_sha256'] + '.'):
        fail()
    expected_policy = {'schema_version': '1', 'policy_version': 'engagement-http-prefix-v1',
        'allowed_targets': [action.target], 'allowed_tools': list(configurable_contract.TOOL_IDS[:2]),
        'allowed_ports': [action.to_dict()['parameters']['port']], 'allowed_methods': ['GET'],
        'max_timeout_seconds': 5, 'max_output_bytes': 8192, 'max_targets': 1,
        'require_approval': True, 'approval_ttl_seconds': 60}
    if policy.to_dict() != expected_policy:
        fail()
    return value


@bounded
def envelope_digest(value):
    return digest(ENVELOPE_DOMAIN + canonical(validate_envelope(value), max_bytes=16384))


@bounded
def prepared_digest(value):
    return digest(PREPARED_DOMAIN + canonical(validate_prepared(value), max_bytes=16384))


@bounded
def sample_clock():
    before = time.monotonic_ns()
    utc = time.time_ns()
    after = time.monotonic_ns()
    return ledger.validate_clock({'utc_ns': utc, 'mono_before_ns': before, 'mono_after_ns': after})


@bounded
def check_clock(clock, *, anchor, window_start_utc_ns, window_end_utc_ns, deadline_ns):
    try:
        clock, anchor = ledger.validate_clock(clock), ledger.validate_clock(anchor)
    except ledger.DispatchLedgerError:
        fail('clock_changed')
    start = integer(window_start_utc_ns, ledger.UTC_MIN, ledger.UTC_MAX)
    end = integer(window_end_utc_ns, ledger.UTC_MIN, ledger.UTC_MAX)
    integer(deadline_ns, 1)
    before, after, utc = clock['mono_before_ns'], clock['mono_after_ns'], clock['utc_ns']
    if before < anchor['mono_after_ns'] and clock != anchor:
        fail('clock_changed')
    if utc < start:
        fail('window_not_open')
    if start >= end or utc + after - before >= end:
        fail('window_closed')
    delta = utc - anchor['utc_ns']
    low = before - anchor['mono_after_ns'] - ledger.CLOCK_TOLERANCE
    high = after - anchor['mono_before_ns'] + ledger.CLOCK_TOLERANCE
    if not low <= delta <= high:
        fail('clock_changed')
    if after >= deadline_ns:
        fail('timeout')
    return min(integer(before + end - utc), deadline_ns)


@bounded
def derive_session_binding(roe, *, engagement_id, revision, generation, broker_id,
                           ledger_owner_id, session_id, reviewer_id, review_mode,
                           runtime_sha256, clock, session_deadline_ns, broker_deadline_ns):
    roe = validate_live_roe(roe)
    policy = ledger.policy_for_roe(roe)
    start, end = ledger._window(roe)
    return validate_session_binding({'schema_version': '1', 'profile': PROFILE,
        'engagement_id': engagement_id, 'revision': revision, 'generation': generation,
        'roe_sha256': records.roe_digest(roe), 'scope_sha256': scope_digest(roe['scope']),
        'broker_id': broker_id, 'ledger_owner_id': ledger_owner_id, 'session_id': session_id,
        'reviewer_id': reviewer_id, 'review_mode': review_mode,
        'policy_sha256': parse_policy(policy).digest, 'runtime_sha256': runtime_sha256,
        'window_start_utc_ns': start, 'window_end_utc_ns': end, 'clock_anchor': clock,
        'session_deadline_ns': session_deadline_ns, 'broker_deadline_ns': broker_deadline_ns})


@bounded
def derive_prepared(opened, slot, *, dispatch_id, clock):
    opened = validate_session_opened(opened)
    member(slot, SLOTS)
    binding, roe = opened['binding'], opened['roe']
    clock = ledger.validate_clock(clock)
    ready = clock['mono_after_ns']
    window = check_clock(clock, anchor=binding['clock_anchor'],
        window_start_utc_ns=binding['window_start_utc_ns'], window_end_utc_ns=binding['window_end_utc_ns'],
        deadline_ns=min(binding['session_deadline_ns'], binding['broker_deadline_ns']))
    cost = ledger.reservation_for(roe, slot)
    action = configurable_contract.action(roe['scope'], SLOTS[slot][0])
    deadline = min(window, ready + cost['runtime_ms'] * 1000000)
    e = {**binding, 'dispatch_id': uuid(dispatch_id), 'slot': slot,
         'action_sha256': parse_action(action).digest, 'action_ready_ns': ready,
         'action_deadline_ns': deadline, 'cost': cost, 'output_limit': SLOTS[slot][4],
         'native_timeout_ns': SLOTS[slot][5]}
    return validate_prepared({'schema_version': '1', 'envelope': e, 'action': action,
                              'policy': opened['policy']})


@validation('invalid_frame')
def validate_release(value):
    value = detached(value, 4096)
    obj(value, RELEASE_FIELDS)
    if value['schema_version'] != '1' or integer(value['release_sequence']) != 1:
        fail()
    for key in ('broker_id', 'ledger_owner_id', 'session_id', 'dispatch_id', 'reservation_event_id'):
        uuid(value[key])
    for key in ('envelope_sha256', 'prepared_sha256', 'reservation_state_sha256',
                'approval_witness_sha256', 'audit_witness_sha256'):
        digest_string(value[key])
    integer(value['reservation_sequence'], 1, 257)
    clock = ledger.validate_clock(value['guard_clock'])
    lease = integer(value['effective_lease_deadline_ns'], 1)
    stop = integer(value['effect_stop_ns'], 1)
    if not clock['mono_after_ns'] < stop <= lease:
        fail()
    return value


@validation('evidence_invalid')
def validate_ledger_receipt(value):
    # Exact inner accepted v2 receipt; full export replay proves its meaning.
    value = detached(value, 4096)
    obj(value, ('schema_version', 'engagement_id', 'event_id', 'sequence', 'operation',
                'revision', 'generation', 'status', 'session_id', 'dispatch_id',
                'state_sha256', 'usage'))
    if value['schema_version'] != '2':
        fail()
    for key in ('engagement_id', 'event_id'):
        uuid(value[key])
    member(value['operation'], {'create', 'revise', 'revoke', 'session', 'reserve', 'complete'})
    member(value['status'], {'recorded', 'revoked'})
    integer(value['sequence'], 1, 257)
    integer(value['revision'], 1, 64)
    integer(value['generation'], 0, 64)
    digest_string(value['state_sha256'])
    usage = obj(value['usage'], ('actions', 'connections', 'request_bytes', 'response_bytes', 'runtime_ms'))
    for count in usage.values():
        integer(count)
    for key in ('session_id', 'dispatch_id'):
        if value[key] is not None:
            uuid(value[key])
    return value


@validation('evidence_invalid')
def validate_ledger_result(value):
    value = detached(value, 4096)
    obj(value, ('schema_version', 'kind', 'disposition', 'receipt'))
    if value['schema_version'] != '2' or value['kind'] != 'data_only':
        fail()
    member(value['disposition'], {'recorded', 'already_recorded'})
    validate_ledger_receipt(value['receipt'])
    return value


@validation('invalid_prepared')
def validate_live_result(value):
    value = detached(value, 16384)
    obj(value, ('schema_version', 'broker_id', 'session_id', 'dispatch_id', 'envelope_sha256',
                'slot', 'outcome', 'reason', 'admission', 'release', 'completion', 'observation',
                'client_result_sha256', 'cleanup_sha256'))
    if value['schema_version'] != '1':
        fail()
    for key in ('broker_id', 'session_id', 'dispatch_id'):
        uuid(value[key])
    digest_string(value['envelope_sha256'])
    member(value['slot'], SLOTS)
    member(value['outcome'], OUTCOMES)
    if value['reason'] is not None:
        member(value['reason'], ERROR_CODES)
    for key, operation in [('admission', 'reserve'), ('completion', 'complete')]:
        if value[key] is not None:
            result = validate_ledger_result(value[key])
            receipt = result['receipt']
            if receipt['operation'] != operation or result['disposition'] != 'recorded':
                fail()
    if value['completion'] is not None and value['admission'] is None:
        fail()
    if value['release'] is not None:
        r = obj(value['release'], ('release_sha256', 'attempted_at_ns', 'send_status',
                                  'effective_lease_deadline_ns', 'effect_stop_ns'))
        digest_string(r['release_sha256'])
        integer(r['attempted_at_ns'])
        member(r['send_status'], {'sent', 'not_sent', 'unknown'})
        if not r['attempted_at_ns'] < integer(r['effect_stop_ns'], 1) <= integer(r['effective_lease_deadline_ns'], 1):
            fail()
        if value['admission'] is None:
            fail()
    if value['observation'] is not None:
        o = obj(value['observation'], ('connections', 'request_bytes', 'response_bytes',
            'client_output_bytes', 'parsed_sha256', 'meter_sha256'))
        for key, cap in zip(('connections', 'request_bytes', 'response_bytes', 'client_output_bytes'), SLOTS[value['slot']][1:5]):
            integer(o[key], 0, cap)
        digest_string(o['meter_sha256'])
        if o['parsed_sha256'] is not None:
            digest_string(o['parsed_sha256'])
    for key in ('client_result_sha256', 'cleanup_sha256'):
        if value[key] is not None:
            digest_string(value[key])
    if value['outcome'] == 'useful':
        if (value['reason'] is not None or any(value[k] is None for k in
            ('admission', 'release', 'completion', 'observation', 'client_result_sha256', 'cleanup_sha256'))
            or value['release']['send_status'] != 'sent' or value['observation']['parsed_sha256'] is None):
            fail()
    elif value['reason'] is None:
        fail()
    return value


@bounded
def derive_effective_lease(prepared, reservation, approval_witness, audit_witness, *, clock):
    p = validate_prepared(prepared)
    e = p['envelope']
    clock = ledger.validate_clock(clock)
    window = check_clock(clock, anchor=e['clock_anchor'], window_start_utc_ns=e['window_start_utc_ns'],
                         window_end_utc_ns=e['window_end_utc_ns'], deadline_ns=e['action_deadline_ns'])
    # Witness readers supply validated new/legacy observations, never ingress declarations.
    issued = integer(approval_witness['issued_at_ns'])
    expires = integer(approval_witness['expires_at_ns'], 1)
    audit_issued = integer(audit_witness['issued_at_ns'])
    now = clock['mono_after_ns']
    if issued > now or audit_issued > now or now >= min(issued + FRESHNESS_NS, audit_issued + FRESHNESS_NS, expires):
        fail('stale_witness')
    lease = min(window, integer(reservation['deadline_ns'], 1), e['session_deadline_ns'],
                e['broker_deadline_ns'], expires, issued + FRESHNESS_NS, audit_issued + FRESHNESS_NS)
    if now >= lease:
        fail('timeout')
    return lease


@validation('invalid_prepared')
def validate_prepared_context(value, opened, *, expected=None):
    """Bind syntactically valid data to the authoritative opened/pending objects."""
    value, opened = validate_prepared(value), validate_session_opened(opened)
    e, binding = value['envelope'], opened['binding']
    if any(e[key] != binding[key] for key in BINDING_FIELDS):
        fail()
    if value['action'] != configurable_contract.action(opened['scope'], SLOTS[e['slot']][0]):
        fail()
    if value['policy'] != opened['policy'] or e['cost'] != ledger.reservation_for(opened['roe'], e['slot']):
        fail()
    if expected is not None and canonical(value) != canonical(validate_prepared(expected)):
        fail()
    return value


@bounded
def effect_stop(prepared, lease):
    e = validate_prepared(prepared)['envelope']
    return min(integer(lease, 1), e['action_deadline_ns'] - CLEANUP_NS,
               e['session_deadline_ns'] - CLEANUP_NS, e['broker_deadline_ns'] - CLEANUP_NS)


@validation('invalid_frame')
def validate_release_binding(value, prepared, *, clock):
    value, prepared = validate_release(value), validate_prepared(prepared)
    e = prepared['envelope']
    for key in ('broker_id', 'ledger_owner_id', 'session_id', 'dispatch_id'):
        if value[key] != e[key]:
            fail()
    if value['envelope_sha256'] != envelope_digest(e) or value['prepared_sha256'] != prepared_digest(prepared):
        fail()
    window = check_clock(clock, anchor=e['clock_anchor'], window_start_utc_ns=e['window_start_utc_ns'],
        window_end_utc_ns=e['window_end_utc_ns'], deadline_ns=e['action_deadline_ns'])
    if (value['effective_lease_deadline_ns'] > min(window, e['session_deadline_ns'], e['broker_deadline_ns'])
            or value['effect_stop_ns'] != effect_stop(prepared, value['effective_lease_deadline_ns'])
            or clock['mono_after_ns'] >= value['effect_stop_ns']):
        fail()
    return value


@validation('invalid_prepared')
def validate_role_context(*, binding, roe, scope, policy):
    """Complete fixed bootstrap data, with no fabricated store receipt."""
    binding = validate_session_binding(binding)
    roe = validate_live_roe(roe)
    scope = validate_scope(scope)
    policy = parse_policy(policy).to_dict()
    if (scope != roe['scope'] or policy != ledger.policy_for_roe(roe)
            or binding['roe_sha256'] != records.roe_digest(roe)
            or binding['scope_sha256'] != scope_digest(scope)
            or binding['policy_sha256'] != parse_policy(policy).digest
            or list(ledger._window(roe)) != [binding['window_start_utc_ns'], binding['window_end_utc_ns']]):
        fail()
    return {'binding': binding, 'roe': roe, 'scope': scope, 'policy': policy}


@validation('invalid_prepared')
def validate_prepared_role_context(prepared, *, binding, roe, scope, policy, expected=None):
    context = validate_role_context(binding=binding, roe=roe, scope=scope, policy=policy)
    prepared = validate_prepared(prepared)
    e = prepared['envelope']
    if any(e[key] != context['binding'][key] for key in BINDING_FIELDS):
        fail()
    if (prepared['action'] != configurable_contract.action(context['scope'], SLOTS[e['slot']][0])
            or prepared['policy'] != context['policy']
            or e['cost'] != ledger.reservation_for(context['roe'], e['slot'])):
        fail()
    if expected is not None and canonical(prepared) != canonical(validate_prepared(expected)):
        fail()
    return prepared
