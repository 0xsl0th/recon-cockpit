"""Direct, bounded witnesses and saved authority consistency checks.

Saved observations are replayed at their recorded clocks. They never create a
store handle, grant, live channel or claim of authenticity for unsigned files.
"""
from __future__ import annotations

import array
import base64
import binascii
import math
import os
import re
import socket
import stat
import time

from . import audit_protocol, audit_witness
from . import engagement_dispatch_contract as ledger
from . import engagement_live_contract as c

APPROVAL_FIELDS = frozenset(('schema_version reviewer_id broker_id ledger_owner_id '
    'session_id dispatch_id consume_sequence reference_sha256 envelope_sha256 '
    'action_sha256 policy_sha256 issued_at_ns expires_at_ns accepted').split())
START_FIELDS = frozenset(('event_type session_id action_id action_digest policy_digest '
    'policy_version tool_id target backend decision execution_status engagement_live').split())


def _base64(value, maximum):
    if type(value) is not str or not value or len(value) > 4 * ((maximum + 2) // 3):
        c.fail('invalid_witness')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        c.fail('invalid_witness')
    if not 1 <= len(raw) <= maximum or base64.b64encode(raw).decode('ascii') != value:
        c.fail('invalid_witness')
    return raw


@c.validation('invalid_witness')
def validate_approval_witness(value, prepared=None, *, reviewer_id=None,
                              previous_sequence=0, now_ns=None):
    c.obj(value, APPROVAL_FIELDS)
    if value['schema_version'] != '1' or value['accepted'] is not True:
        c.fail()
    for key in ('reviewer_id', 'broker_id', 'ledger_owner_id', 'session_id', 'dispatch_id'):
        c.uuid(value[key])
    for key in ('reference_sha256', 'envelope_sha256', 'action_sha256', 'policy_sha256'):
        c.digest_string(value[key])
    c.integer(previous_sequence, 0, 32)
    c.integer(value['consume_sequence'], previous_sequence + 1, 32)
    c.integer(value['issued_at_ns'])
    c.integer(value['expires_at_ns'], value['issued_at_ns'] + 1)
    if reviewer_id is not None and value['reviewer_id'] != c.uuid(reviewer_id):
        c.fail()
    if prepared is not None:
        p = c.validate_prepared(prepared)
        e = p['envelope']
        for key in ('reviewer_id', 'broker_id', 'ledger_owner_id', 'session_id', 'dispatch_id',
                    'action_sha256', 'policy_sha256'):
            if value[key] != e[key]:
                c.fail()
        if (value['envelope_sha256'] != c.envelope_digest(e)
                or value['issued_at_ns'] < e['action_ready_ns']
                or value['expires_at_ns'] > min(e['action_deadline_ns'],
                    e['session_deadline_ns'], e['broker_deadline_ns'])):
            c.fail()
    if now_ns is not None:
        c.integer(now_ns)
        if not value['issued_at_ns'] <= now_ns < value['expires_at_ns']:
            c.fail('stale_witness')
        if now_ns - value['issued_at_ns'] > c.FRESHNESS_NS:
            c.fail('stale_witness')
    return c.detached(value)


@c.validation('invalid_witness')
def started_event(prepared):
    p = c.validate_prepared(prepared)
    e, a, policy = p['envelope'], p['action'], p['policy']
    return {'event_type': 'execution_started', 'session_id': e['session_id'],
            'action_id': a['action_id'], 'action_digest': e['action_sha256'],
            'policy_digest': e['policy_sha256'], 'policy_version': policy['policy_version'],
            'tool_id': a['tool_id'], 'target': a['target'], 'backend': c.BACKEND,
            'decision': 'approval_required', 'execution_status': 'started',
            'engagement_live': e}


@c.validation('invalid_witness')
def validate_started_event(value, prepared=None):
    c.obj(value, START_FIELDS)
    e = c.validate_envelope(value['engagement_live'])
    c.uuid(value['session_id'])
    for key in ('action_digest', 'policy_digest'):
        c.digest_string(value[key])
    if (value['event_type'] != 'execution_started' or value['execution_status'] != 'started'
            or value['backend'] != c.BACKEND or value['decision'] != 'approval_required'
            or value['policy_version'] != 'engagement-http-prefix-v1'
            or value['session_id'] != e['session_id']
            or value['action_digest'] != e['action_sha256']
            or value['policy_digest'] != e['policy_sha256']):
        c.fail()
    # The legacy claims validator supplies the exact accepted identifier/string grammar.
    audit_witness.claims(value)
    if prepared is not None and c.canonical(value) != c.canonical(started_event(prepared)):
        c.fail()
    return c.detached(value)


def _audit_decode(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= audit_witness.MAX_WITNESS:
        c.fail('invalid_witness')
    try:
        value = audit_protocol.decode(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        c.fail('invalid_witness')
    c.obj(value, ('version', 'writer_id', 'audit_sequence', 'sequence', 'issued_at',
                  'intent', 'event_digest'))
    if value['version'] != '1':
        c.fail('invalid_witness')
    c.uuid(value['writer_id'])
    c.integer(value['audit_sequence'], 1, audit_protocol.MAX_EVENTS)
    c.integer(value['sequence'], 1, audit_witness.MAX_LAUNCHES)
    c.digest_string(value['event_digest'])
    issued = value['issued_at']
    if type(issued) not in (int, float) or not math.isfinite(issued) or issued < 0:
        c.fail('invalid_witness')
    numerator, denominator = issued.as_integer_ratio()
    issued_ns = numerator * c.SECOND // denominator
    c.integer(issued_ns)
    # Preserve the exact legacy float packet, never normalize its bytes through
    # the integer-only new codec or round an issue time upwards.
    if audit_protocol.encode(value) != raw:
        c.fail('invalid_witness')
    return value, issued_ns


@c.validation('invalid_witness')
def validate_audit_witness(raw, prepared, *, source, sequence, previous_audit=0, now_ns):
    p = c.validate_prepared(prepared)
    source = audit_witness.manifest(source)
    value, issued_ns = _audit_decode(raw)
    event = started_event(p)
    if (value['writer_id'] != source['writer_id'] or value['sequence'] != sequence
            or not previous_audit < value['audit_sequence']
            or value['intent'] != audit_witness.claims(event)
            or value['event_digest'] != c.digest(audit_protocol.event_bytes(event))):
        c.fail()
    c.integer(now_ns)
    if not issued_ns <= now_ns or now_ns - issued_ns > c.FRESHNESS_NS:
        c.fail('stale_witness')
    if issued_ns < p['envelope']['action_ready_ns']:
        c.fail()
    return {'writer_id': value['writer_id'], 'audit_sequence': value['audit_sequence'],
            'sequence': value['sequence'], 'issued_at_ns': issued_ns,
            'expires_at_ns': min(c.INTEGER_MAX, issued_ns + c.FRESHNESS_NS),
            'event_sha256': value['event_digest'], 'raw_sha256': c.digest(raw)}


@c.validation('invalid_witness')
def validate_audit_observation(value, prepared, *, source, sequence, previous_audit=0):
    c.obj(value, ('producer_event', 'producer_sha256', 'raw_base64', 'raw_sha256',
                  'received_at_ns'))
    raw = _base64(value['raw_base64'], 2048)
    event = validate_started_event(value['producer_event'], prepared)
    if (value['raw_sha256'] != c.digest(raw)
            or value['producer_sha256'] != c.digest(audit_protocol.event_bytes(event))):
        c.fail()
    return validate_audit_witness(raw, prepared, source=source, sequence=sequence,
        previous_audit=previous_audit, now_ns=value['received_at_ns'])


@c.validation('invalid_witness')
def validate_audit_readiness(value):
    c.obj(value, ('schema_version', 'writer_id', 'initial', 'ready', 'source_manifest',
                  'append_identity', 'parent_observation', 'import_image'))
    if value['schema_version'] != '1':
        c.fail()
    writer = c.uuid(value['writer_id'])
    initial, ready = value['initial'], value['ready']
    c.obj(initial, ('version', 'writer_id', 'device', 'inode', 'witness'))
    c.obj(ready, ('version', 'writer_id', 'ready', 'checks'))
    if (initial['version'] != '1' or ready['version'] != '1'
            or initial['writer_id'] != writer or ready['writer_id'] != writer
            or ready['ready'] is not True or type(initial['witness']) is not list
            or len(initial['witness']) != 2):
        c.fail()
    for name in ('device', 'inode'):
        c.integer(initial[name])
    for item in initial['witness']:
        c.integer(item)
    c.obj(ready['checks'], audit_protocol.CHECKS)
    if any(item is not True for item in ready['checks'].values()):
        c.fail()
    source = audit_witness.manifest(value['source_manifest'])
    if source['writer_id'] != writer:
        c.fail()
    info = value['append_identity']
    c.obj(info, ('device', 'inode', 'mode', 'uid', 'gid', 'links', 'size'))
    for name in info:
        c.integer(info[name])
    if (info['links'] != 1 or not stat.S_ISREG(info['mode'])
            or stat.S_IMODE(info['mode']) != 0o600 or info['size'] > 1048576
            or [info['device'], info['inode']] != [initial['device'], initial['inode']]):
        c.fail()
    from . import engagement_live_runtime as runtime
    parent = runtime.validate_audit_observation(value['parent_observation'])
    if parent['stage'] != 'sealed': c.fail()
    image = value['import_image']
    c.obj(image, ('destination', 'device', 'inode', 'mode', 'size', 'sha256', 'read_only_mount'))
    if (type(image['destination']) is not str or _LIBFFI.fullmatch(image['destination']) is None
            or image['read_only_mount'] is not True): c.fail()
    for key in ('device', 'inode'):
        c.integer(image[key], 1 if key == 'inode' else 0, 2**64-1)
    c.integer(image['mode'], 0, 2**32-1)
    c.integer(image['size'], 1, 16777216); c.digest_string(image['sha256'])
    if not stat.S_ISREG(image['mode']) or stat.S_IMODE(image['mode']) != 0o444: c.fail()
    descriptors = parent['descriptors']
    if (len(descriptors) != 6 or {row['fd'] for row in descriptors} != set(range(6))
            or {row['purpose'] for row in descriptors} != {
                'stdin', 'stdout', 'stderr', 'audit_import_libffi', 'audit_append', 'audit_witness'}): c.fail()
    named = {row['purpose']: row for row in descriptors}
    for fd, name in enumerate(('stdin', 'stdout', 'stderr')):
        if named[name]['fd'] != fd: c.fail()
    imported, append, witness = (named[key] for key in ('audit_import_libffi', 'audit_append', 'audit_witness'))
    # These are retained Linux flags, including when inspected on another OS.
    if (imported['kind'] != 'regular' or imported['flags'] & (3 | 0x200000)
            or any(imported[key] != image[key] for key in ('device', 'inode', 'mode'))): c.fail()
    if (append['kind'] != 'regular' or append['flags'] & 3 != 1
            or not append['flags'] & 0x400 or append['flags'] & 0x200000
            or any(append[key] != info[key] for key in ('device', 'inode', 'mode'))
            or info['uid'] != parent['observer']['uid']): c.fail()
    if (witness['kind'] != 'seqpacket' or not stat.S_ISSOCK(witness['mode'])
            or witness['flags'] & 3 != 2 or not witness['flags'] & 0x800
            or witness['flags'] & 0x200000
            or [witness['device'], witness['inode']] != initial['witness']
            or [source['device'], source['inode']] == initial['witness']): c.fail()
    mapped = [row for row in parent['mapped_images'] if row['destination'] == image['destination']]
    if len(mapped) != 1 or any(mapped[0][key] != image[key] for key in ('device', 'inode')): c.fail()
    return c.detached(value)


_LIBFFI = re.compile(r'/(?:usr/)?lib(?:64)?/(?:[a-zA-Z0-9_-]+/)?libffi\.so\.\d+(?:\.\d+)*')


@c.validation('invalid_witness')
def validate_audit_runtime_binding(value, runtime_bundle):
    """Mandatory live/replay check against the complete pinned runtime bundle."""
    from . import engagement_live_runtime as runtime
    value = validate_audit_readiness(value)
    bundle = runtime.validate_runtime(runtime_bundle)
    manifest = next(row for row in bundle['roles'] if row['role'] == 'parser')
    libraries = [row for row in manifest['native_files'] if _LIBFFI.fullmatch(row['destination'])]
    image = value['import_image']
    if len(libraries) != 1 or any(image[key] != libraries[0][key] for key in ('destination', 'size', 'sha256')): c.fail()
    python = next(row for row in manifest['native_files'] if row['destination'] == '/usr/bin/python3')
    actual = value['parent_observation']['executable']
    if any(actual[key] != python[key] for key in ('destination', 'size', 'sha256')): c.fail()
    return value


class DirectReader:
    """A single inherited one-way socket. Never reconnects or creates channels."""
    def __init__(self, fd, identity, *, kind):
        c.member(kind, ('approval', 'audit'))
        self.kind = kind
        self.channel = audit_witness.endpoint(fd, identity, writer=False)
        self.closed = False
        self.sequence = 0
        self.audit_sequence = 0

    def poll(self):
        if self.closed:
            c.fail('invalid_channel')
        maximum = 4096 if self.kind == 'approval' else 2048
        try:
            raw, ancillary, flags, _ = self.channel.recvmsg(maximum + 1,
                socket.CMSG_SPACE(256), socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
        except BlockingIOError:
            return None
        descriptors = []
        try:
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    items = array.array('i')
                    items.frombytes(data[:len(data) - len(data) % items.itemsize])
                    descriptors.extend(items)
            if ancillary or flags & ~socket.MSG_CMSG_CLOEXEC or not raw or len(raw) > maximum:
                self.close()
                c.fail('invalid_witness')
            return raw, time.monotonic_ns()
        finally:
            for fd in descriptors:
                os.close(fd)

    def approval(self, raw, prepared, *, received_at_ns):
        if self.kind != 'approval':
            c.fail('invalid_channel')
        value = c.decode(raw, max_bytes=4096)
        if c.canonical(value, max_bytes=4096) != raw:
            c.fail('invalid_witness')
        value = validate_approval_witness(value, prepared,
            previous_sequence=self.sequence, now_ns=received_at_ns)
        self.sequence = value['consume_sequence']
        return value

    def audit(self, raw, prepared, *, source, received_at_ns):
        if self.kind != 'audit':
            c.fail('invalid_channel')
        value = validate_audit_witness(raw, prepared, source=source,
            sequence=self.sequence + 1, previous_audit=self.audit_sequence,
            now_ns=received_at_ns)
        self.sequence = value['sequence']
        self.audit_sequence = value['audit_sequence']
        return value

    def close(self):
        if not self.closed:
            self.closed = True
            self.channel.close()


@c.validation('invalid_witness')
def validate_approval_observation(value, prepared=None, *, previous_sequence=0):
    c.obj(value, ('raw_base64', 'raw_sha256', 'witness', 'received_at_ns'))
    raw = _base64(value['raw_base64'], 4096)
    if raw != c.canonical(value['witness'], max_bytes=4096) or value['raw_sha256'] != c.digest(raw):
        c.fail()
    validate_approval_witness(value['witness'], prepared, previous_sequence=previous_sequence,
                              now_ns=value['received_at_ns'])
    return c.detached(value)


def _nullable(value, validator):
    if value is not None:
        validator(value)


@c.validation('evidence_invalid')
def validate_capability_projection(value):
    from . import engagement_live_protocol as p
    c.obj(value, ('channel_id', 'operation', 'role', 'request_sequence', 'request', 'reply',
        'request_projection_sha256', 'reply_projection_sha256', 'original_request_bytes',
        'original_request_sha256', 'original_reply_bytes', 'original_reply_sha256'))
    c.uuid(value['channel_id']); c.integer(value['request_sequence'], 1, 66)
    role = c.member(value['role'], ('terminal', 'graphical', 'admission'))
    operation = c.member(value['operation'], ('REVIEW', 'CONSUME', 'CLOSE', 'ISSUE', 'REDEEM'))
    if (role == 'admission') != (operation in {'ISSUE', 'REDEEM'}):
        c.fail()
    request, reply = value['request'], value['reply']
    if operation == 'REVIEW':
        c.obj(request, ('prepared',)); c.validate_prepared(request['prepared'])
    elif operation == 'CONSUME':
        c.obj(request, ('prepared', 'reference_sha256'))
        c.validate_prepared(request['prepared']); c.digest_string(request['reference_sha256'])
    elif operation == 'CLOSE':
        if request is not None: c.fail()
    elif operation == 'ISSUE':
        c.validate_prepared(request)
    else:
        c.obj(request, ('prepared_sha256', 'reference_sha256', 'release'))
        c.digest_string(request['prepared_sha256']); c.digest_string(request['reference_sha256'])
        c.validate_release(request['release'])
    if value['request_projection_sha256'] != c.digest(c.canonical(request)):
        c.fail()
    if reply is None:
        if value['reply_projection_sha256'] is not None: c.fail()
    else:
        if value['reply_projection_sha256'] != c.digest(c.canonical(reply)): c.fail()
        if type(reply) is dict and set(reply) == p.REPLY_FIELDS:
            if (reply['status'] != 'refused' or reply['data'] is not None
                    or reply['request_sequence'] != value['request_sequence']): c.fail()
            c.member(reply['code'], c.ERROR_CODES)
        elif operation == 'REVIEW':
            c.obj(reply, ('reference_sha256',)); _nullable(reply['reference_sha256'], c.digest_string)
        elif operation == 'CONSUME':
            p._consume_result(reply)
            if reply['reference_sha256'] != request['reference_sha256']: c.fail()
        elif operation == 'CLOSE':
            p._closed(reply)
        elif operation == 'ISSUE':
            c.obj(reply, ('schema_version', 'admission_id', 'session_id', 'dispatch_id',
                'reference_sha256', 'prepared_sha256', 'envelope_sha256', 'action_sha256',
                'policy_sha256', 'runtime_sha256', 'issued_at_ns', 'expires_at_ns'))
            c.digest_string(reply['reference_sha256'])
            # Validate the public projection through the same non-capability
            # fields; the placeholder is never returned or sent to a worker.
            p.validate_permit({**{k:v for k,v in reply.items() if k!='reference_sha256'},'reference':'0'*64})
        else:
            p.validate_redeemed(reply)
    for side in ('request', 'reply'):
        size, digest = value['original_' + side + '_bytes'], value['original_' + side + '_sha256']
        if (size is None) != (digest is None): c.fail()
        if size is not None:
            c.integer(size, 1, 32768); c.digest_string(digest)
        if side == 'reply' and reply is None and size is not None: c.fail()
    return c.detached(value)


STATES = ('prepared', 'preparing', 'ready_for_review', 'awaiting_witnesses', 'admitted',
          'release_attempted', 'running', 'settling', 'settled', 'terminal_unresolved')
PHASES = ('prepare', 'consume', 'audit', 'reserve', 'guard', 'go', 'redeem', 'native_observation',
          'arm', 'client', 'parser', 'complete', 'watch', 'cleanup')
ROW_FIELDS = ('schema_version', 'broker_id', 'observer_id', 'row_sequence', 'observed_at_ns',
              'session_id', 'dispatch_id', 'kind', 'data')


@c.validation('evidence_invalid')
def validate_transcript_row(value):
    from . import engagement_live_protocol as p
    c.obj(value, ROW_FIELDS)
    if value['schema_version'] != '1': c.fail()
    c.uuid(value['observer_id']); c.integer(value['row_sequence'], 1, 4096)
    c.integer(value['observed_at_ns'])
    for key in ('broker_id', 'session_id', 'dispatch_id'): _nullable(value[key], c.uuid)
    kind, data = value['kind'], value['data']
    if kind == 'protocol':
        c.obj(data, ('channel_role', 'direction', 'frame'))
        c.member(data['channel_role'], ('ingress', 'lifecycle', 'launcher', 'endpoint', 'arm'))
        c.member(data['direction'], ('sent', 'received'))
        p.validate_frame(data['frame'], role=data['channel_role'])
    elif kind == 'approval_witness':
        validate_approval_observation(data)
    elif kind == 'audit_witness':
        c.obj(data, ('producer_event', 'producer_sha256', 'raw_base64', 'raw_sha256', 'received_at_ns'))
        raw = _base64(data['raw_base64'], 2048); audit, _ = _audit_decode(raw)
        event = validate_started_event(data['producer_event'])
        if (data['raw_sha256'] != c.digest(raw)
                or data['producer_sha256'] != c.digest(audit_protocol.event_bytes(event))
                or audit['event_digest'] != data['producer_sha256']
                or audit['intent'] != audit_witness.claims(event)): c.fail()
        c.integer(data['received_at_ns'])
    elif kind == 'capability_projection':
        validate_capability_projection(data)
    elif kind == 'supervision_projection':
        p.validate_supervision_projection(data)
        if len(c.canonical(value)) + 1 > c.SUPERVISION_ROW_BYTES:
            c.fail('limit_exceeded')
    elif kind == 'watch':
        c.obj(data, ('clock', 'finished_at_ns', 'ledger_sequence', 'ledger_state_sha256', 'reason',
                    'scheduled_at_ns', 'started_at_ns', 'status'))
        c.member(data['status'], ('unchanged', 'changed', 'refused'))
        scheduled = c.integer(data['scheduled_at_ns'])
        start = c.integer(data['started_at_ns'], scheduled)
        c.integer(data['finished_at_ns'], start)
        _nullable(data['clock'], ledger.validate_clock); _nullable(data['reason'], lambda v:c.member(v,c.ERROR_CODES))
        _nullable(data['ledger_sequence'], lambda v:c.integer(v,1,257)); _nullable(data['ledger_state_sha256'],c.digest_string)
        if (data['ledger_sequence'] is None) != (data['ledger_state_sha256'] is None): c.fail()
    elif kind == 'phase':
        c.obj(data, ('clock','original_deadline_ns','phase','reason','related_sha256','stage'))
        _nullable(data['clock'], ledger.validate_clock); c.integer(data['original_deadline_ns'],1)
        c.member(data['phase'],PHASES); c.member(data['stage'],('begin','end','refused'))
        _nullable(data['reason'],lambda v:c.member(v,c.ERROR_CODES)); _nullable(data['related_sha256'],c.digest_string)
    elif kind == 'state':
        c.obj(data, ('from_state','to_state','reason'))
        _nullable(data['from_state'],lambda v:c.member(v,STATES)); c.member(data['to_state'],STATES)
        _nullable(data['reason'],lambda v:c.member(v,c.ERROR_CODES))
    elif kind == 'observation_ref':
        c.obj(data, ('member','record_kind','record_sha256'))
        c.member(data['member'],('processes.json','results.json','cleanup.json'))
        c.member(data['record_kind'],('readiness','native','cleanup','client_result','boundary_proof'))
        c.digest_string(data['record_sha256'])
    elif kind == 'export':
        c.obj(data, ('ledger_sequence','ledger_state_sha256','phase','reference'))
        c.integer(data['ledger_sequence'],1,257); c.digest_string(data['ledger_state_sha256'])
        c.member(data['phase'],('initial','final')); p.validate_export_reference(data['reference'])
    elif kind == 'meter':
        from .engagement_live_runtime import validate_meter_event
        validate_meter_event(data)
    else:
        c.fail()
    return c.detached(value)


def _exports(loaded, deadline):
    histories = []
    for name in ('initial-ledger.json', 'final-ledger.json', 'recovery-ledger.json'):
        if name not in loaded: continue
        c._check_deadline(deadline)
        # Each accepted operation keeps its own <=2s allowance, clipped to the
        # outer inspection bound. Do not seed the shared context with 15s.
        with c._deadline_context(min(deadline, c._operation_deadline())):
            value = ledger.validate_export(loaded[name])
        histories.append(value)
    if not histories: return None, {}, {}
    histories.sort(key=lambda v:len(v['events']))
    final = histories[-1]
    for earlier in histories:
        if (earlier['engagement_id'] != final['engagement_id']
                or earlier['events'] != final['events'][:len(earlier['events'])]): c.fail('evidence_invalid')
    events = {row['event_id']:row for row in final['events']}
    states = {row['receipt']['state_sha256']:row['sequence'] for row in final['events']}
    return final, events, states


def _match_receipt(value, events, *, operation, dispatch_id=None):
    value = c.validate_ledger_result(value)
    receipt = value['receipt']; row = events.get(receipt['event_id'])
    if (row is None or row['receipt'] != receipt or receipt['operation'] != operation
            or (dispatch_id is not None and receipt['dispatch_id'] != dispatch_id)):
        c.fail('evidence_invalid')
    return row


def _audit_events(raw):
    from datetime import datetime,timezone
    if type(raw) is not bytes or len(raw) > 1048576: c.fail('evidence_invalid')
    result = {};identities=set()
    if raw and not raw.endswith(b'\n'): c.fail('evidence_invalid')
    for line in raw.splitlines():
        wrapper = audit_protocol.decode(line)
        if not audit_protocol.RESERVED <= wrapper.keys(): c.fail('evidence_invalid')
        if wrapper['event_schema_version']!='1' or wrapper['source']!='recon-cockpit.secure-agent':c.fail('evidence_invalid')
        identity=c.uuid(wrapper['event_id'])
        if identity in identities:c.fail('evidence_invalid')
        identities.add(identity)
        timestamp=wrapper['timestamp']
        if type(timestamp)is not str or not 20<=len(timestamp)<=32:c.fail('evidence_invalid')
        try:parsed=datetime.fromisoformat(timestamp)
        except ValueError:c.fail('evidence_invalid')
        if parsed.tzinfo is None or parsed.utcoffset()!=timezone.utc.utcoffset(parsed):c.fail('evidence_invalid')
        producer = {k:v for k,v in wrapper.items() if k not in audit_protocol.RESERVED}
        digest = c.digest(audit_protocol.event_bytes(producer))
        if digest in result: c.fail('evidence_invalid')
        result[digest] = producer
    return result


def _audit_transcript_rows(loaded, deadline):
    """Read each retained segment independently; a partial tail is never joined."""
    raw = loaded.get('transcript.jsonl', b'')
    if type(raw) is not bytes or len(raw) > 2097152: c.fail('evidence_invalid')
    segments = loaded['manifest.json']['transcript']['segments']
    if type(segments) is not list or len(segments) > 3: c.fail('evidence_invalid')
    rows, offset = [], 0
    for index, segment in enumerate(segments):
        c._check_deadline(deadline)
        c.obj(segment, ('source', 'broker_id', 'offset', 'bytes', 'sha256', 'seals', 'status'))
        c.integer(segment['offset'], 0, 2097152); c.integer(segment['bytes'], 0, 2097152)
        c.member(segment['source'], ('broker_memfd', 'role_observer'))
        c.member(segment['status'], ('sealed_complete', 'reaped_partial', 'observer_complete', 'observer_partial'))
        if segment['offset'] != offset: c.fail('evidence_invalid')
        part = raw[offset:offset+segment['bytes']]; offset += segment['bytes']
        if len(part) != segment['bytes'] or c.digest(part) != segment['sha256']: c.fail('evidence_invalid')
        lines = part.split(b'\n'); tail = lines.pop()
        if tail and not segment['status'].endswith('partial'): c.fail('evidence_invalid')
        for sequence, line in enumerate(lines, 1):
            c._check_deadline(deadline)
            if not line or len(rows) >= 4096: c.fail('evidence_invalid')
            row = validate_transcript_row(c.decode(line, max_bytes=32768))
            if c.canonical(row) != line or row['row_sequence'] != sequence: c.fail('evidence_invalid')
            if segment['source'] == 'broker_memfd' and row['broker_id'] != segment['broker_id']: c.fail('evidence_invalid')
            rows.append({'segment': index, 'source': segment['source'], 'row': row})
    if offset != len(raw): c.fail('evidence_invalid')
    return rows


@c.validation('evidence_invalid')
def _retained_audit_readiness(loaded, *, rows=None, deadline=None):
    """Resolve observed audit custody for replay and process-cleanup accounting."""
    from . import engagement_live_runtime as runtime
    deadline = c._operation_deadline() if deadline is None else min(deadline, c._operation_deadline())
    c._check_deadline(deadline)
    if rows is None: rows = _audit_transcript_rows(loaded, deadline)
    if type(rows) is not list or len(rows) > 4096: c.fail('evidence_invalid')
    observations, missing, seen = [], set(), set()
    for wrapped in rows:
        c._check_deadline(deadline)
        c.obj(wrapped, ('segment', 'source', 'row'))
        row = wrapped['row']
        if type(row) is not dict: c.fail('evidence_invalid')
        if row.get('kind') != 'protocol': continue
        data = row.get('data')
        if type(data) is not dict or type(data.get('frame')) is not dict: c.fail('evidence_invalid')
        if data.get('channel_role') != 'lifecycle' or data['frame'].get('operation') != 'AUDIT_OBSERVED': continue
        row = validate_transcript_row(row); data = row['data']; broker = row['broker_id']
        frame = data['frame']
        if (wrapped['source'] != 'broker_memfd' or data['direction'] != 'received'
                or broker is None or row['observer_id'] != broker or frame['channel_id'] != broker
                or row['session_id'] is not None or row['dispatch_id'] is not None or broker in seen): c.fail('evidence_invalid')
        seen.add(broker)
        instances = loaded['manifest.json']['broker_instances']
        if sum(item['broker_id'] == broker for item in instances) != 1: c.fail('evidence_invalid')
        bundle = loaded['runtime.json']['runtime']
        ready = validate_audit_runtime_binding(frame['body'], bundle)
        if ready['parent_observation']['sampled_at_ns'] > row['observed_at_ns']: c.fail('evidence_invalid')
        brokers = [item for item in loaded.get('processes.json', {}).get('readiness', [])
                   if item['role'] == 'broker' and item['worker_ready']['worker_id'] == broker]
        if not brokers:
            missing.add('process_identity')
        else:
            if len(brokers) != 1: c.fail('evidence_invalid')
            parent = runtime.validate_readiness('broker', brokers[0], bundle)['parent_observation']
            readers = [item for item in parent['descriptors'] if item['purpose'] == 'audit_witness']
            source = ready['source_manifest']
            if (len(readers) != 1 or readers[0]['kind'] != 'seqpacket'
                    or not stat.S_ISSOCK(readers[0]['mode']) or readers[0]['flags'] & 3 != 2
                    or not readers[0]['flags'] & 0x800 or readers[0]['flags'] & 0x200000
                    or any(readers[0][key] != source[key] for key in ('device', 'inode'))
                    or parent['sampled_at_ns'] > row['observed_at_ns']): c.fail('evidence_invalid')
        observations.append({'broker_id': broker, 'observed_at_ns': row['observed_at_ns'], 'readiness': ready})
    c._check_deadline(deadline)
    return {'observations': observations, 'missing_evidence': sorted(missing)}


def validate_evidence_transcript(loaded, rows, *, deadline):
    """Reconstruct retained authority links; no effects or gate verdicts.

    The caller separately checks file custody, exact member schemas, native
    observations, parser results and the selected physical case predicate.
    """
    from . import engagement_live_protocol as p
    c._check_deadline(deadline)
    if type(rows) is not list or len(rows) > 4096: c.fail('evidence_invalid')
    final, events, states = _exports(loaded, deadline)
    audit_context = _retained_audit_readiness(loaded, rows=rows, deadline=deadline)
    missing, dispatches = set(audit_context['missing_evidence']), {}
    from .engagement_live_context import validate_supervision_transcript
    supervision = validate_supervision_transcript(loaded, rows, deadline=deadline)
    missing.update(supervision['missing_evidence'])
    operations = loaded.get('results.json', {}).get('operations', [])
    if type(operations) is not list or len(operations) > 4: c.fail('evidence_invalid')
    for operation in operations:
        prepared = c.validate_prepared_context(operation['prepared'], operation['session'])
        e = prepared['envelope']; did = e['dispatch_id']
        if did in dispatches: c.fail('evidence_invalid')
        dispatches[did] = {'reservation_observed': None, 'go_observed': None,
            'prepared': prepared, 'session': operation['session'], 'result': operation['result'],
            'approval': None, 'audit': None, 'release': None, 'reservation': None,
            'completion': None}
        if final is not None:
            _match_receipt(operation['session']['session_receipt'], events, operation='session')
            session = next((r for r in final['sessions'] if r['session_id']==e['session_id']),None)
            if session is None or any(session[k] != e[k] for k in ('revision','generation','policy_sha256')):
                c.fail('evidence_invalid')
            if session['owner_id'] != e['ledger_owner_id'] or session['clock'] != e['clock_anchor']:
                c.fail('evidence_invalid')
            if session['session_deadline_ns'] != e['session_deadline_ns']: c.fail('evidence_invalid')
        if operation['result'] is not None:
            result = c.validate_live_result(operation['result'])
            if any(result[k]!=e[k] for k in ('broker_id','session_id','dispatch_id','slot')) or result['envelope_sha256']!=c.envelope_digest(e):
                c.fail('evidence_invalid')
            for field, op in (('admission','reserve'),('completion','complete')):
                if result[field] is not None:
                    if final is None: missing.add('final_export')
                    else: _match_receipt(result[field],events,operation=op,dispatch_id=did)
        else:
            missing.add('unsettled_dispatch')
    if final is not None:
        for did, link in dispatches.items():
            e = link['prepared']['envelope']
            reservation = next((r for r in final['reservations'] if r['dispatch_id']==did),None)
            completion = next((r for r in final['completions'] if r['dispatch_id']==did),None)
            if reservation is not None:
                if (reservation['owner_id']!=e['ledger_owner_id'] or reservation['session_id']!=e['session_id']
                        or any(reservation[k]!=e[k] for k in ('revision','generation','slot','action_sha256','policy_sha256'))
                        or reservation['reservation']!=e['cost']): c.fail('evidence_invalid')
                link['reservation_observed']=True; link['reservation']=reservation
            link['completion']=completion
    channel_sequences, row_sequences, approval_sequences, audit_sequences = {}, {}, {}, {}
    segment_bytes, supervision_count = {}, 0
    audit_events = _audit_events(loaded.get('audit.jsonl',b''))
    seen_go, state_rows, meter_received, meter_forwarded = set(), {}, {}, set()
    meter_prefixes={}
    audit_sources, reviewed, consumed, projection_sequences = {}, {}, {}, {}
    for observed in audit_context['observations']:
        ready = observed['readiness']; writer = ready['writer_id']; source = ready['source_manifest']
        key = (observed['broker_id'], writer)
        audit_sources[key] = (source, observed['observed_at_ns'])
    admissions={}
    ingress_requests, ingress_results = {}, {}
    # Host projections and broker packets occupy different immutable segments;
    # build their indexes without pretending their file order is wall-clock order.
    for wrapped in rows:
        row=validate_transcript_row(wrapped['row']);data=row['data']
        if row['kind']=='protocol' and data['channel_role']=='launcher' and data['frame']['operation']=='OBSERVATION' and data['frame']['body']['kind']=='capability_projection':
            observed=data['frame']['body']
            if observed['dispatch_id']!=row['dispatch_id']:c.fail('evidence_invalid')
            data=observed['data']
        elif row['kind']!='capability_projection':continue
        key=(row['observer_id'],data['channel_id'])
        if data['request_sequence']!=projection_sequences.get(key,0)+1:c.fail('evidence_invalid')
        projection_sequences[key]=data['request_sequence']
        request,reply=data['request'],data['reply']
        if reply is None or (type(reply)is dict and set(reply)==p.REPLY_FIELDS):continue
        if data['role']=='admission':
            did=reply['dispatch_id'];link=dispatches.get(did)
            if link is None:c.fail('evidence_invalid')
            prepared=link['prepared'];identity=data['channel_id']
            if data['operation']=='ISSUE':
                if did in admissions or request!=prepared or reply['admission_id']!=identity or reply['prepared_sha256']!=c.prepared_digest(prepared) or reply['envelope_sha256']!=c.envelope_digest(prepared['envelope']):c.fail('evidence_invalid')
                admissions[did]={'permit':reply,'issue_at_ns':row['observed_at_ns'],'redeemed':None}
            else:
                admission=admissions.get(did)
                if admission is None or admission['redeemed']is not None or reply['admission_id']!=identity or request['reference_sha256']!=admission['permit']['reference_sha256'] or request['prepared_sha256']!=c.prepared_digest(prepared) or reply['permit_sha256']!=c.digest(c.canonical(admission['permit'])) or reply['release_sha256']!=c.digest(c.canonical(request['release'])) or reply['redeemed_at_ns']<admission['issue_at_ns']:c.fail('evidence_invalid')
                c.validate_release_binding(request['release'],prepared,clock=request['release']['guard_clock'])
                admission['redeemed']=reply;admission['release']=request['release']
            continue
        if data['operation']=='REVIEW' and reply['reference_sha256'] is not None:
            reference=reply['reference_sha256'];identity=(data['channel_id'],reference)
            prepared=request['prepared']
            if prepared['envelope']['reviewer_id']!=data['channel_id'] or identity in reviewed:c.fail('evidence_invalid')
            reviewed[identity]=(prepared,row['observed_at_ns'],data['request_sequence'])
        elif data['operation']=='CONSUME' and reply['accepted']:
            identity=(data['channel_id'],request['reference_sha256'])
            review=reviewed.get(identity)
            if (review is None or review[0]!=request['prepared'] or review[1]>row['observed_at_ns']
                    or review[2]>=data['request_sequence'] or identity in consumed):c.fail('evidence_invalid')
            consumed[identity]=(request['prepared'],reply,review[1],row['observed_at_ns'])
    for wrapped in rows:
        c._check_deadline(deadline)
        c.obj(wrapped, ('segment','source','row')); c.integer(wrapped['segment'],0,2)
        c.member(wrapped['source'],('broker_memfd','role_observer'))
        row=validate_transcript_row(wrapped['row']); segment=wrapped['segment']
        expected=row_sequences.get(segment,0)+1
        if row['row_sequence']!=expected: c.fail('evidence_invalid')
        row_sequences[segment]=expected
        segment_bytes[segment] = segment_bytes.get(segment, 0) + len(c.canonical(row)) + 1
        broker_segment = wrapped['source'] == 'broker_memfd'
        if (expected > (c.BROKER_TRANSCRIPT_ROWS if broker_segment else c.HOST_TRANSCRIPT_ROWS)
                or segment_bytes[segment] > (c.BROKER_TRANSCRIPT_BYTES if broker_segment else c.HOST_TRANSCRIPT_BYTES)):
            c.fail('limit_exceeded')
        if row['kind'] == 'supervision_projection':
            supervision_count += 1
            if broker_segment or supervision_count > c.SUPERVISION_ROWS:
                c.fail('evidence_invalid')
        did=row['dispatch_id']; link=dispatches.get(did); data=row['data']; kind=row['kind']
        if did is not None and link is None: c.fail('evidence_invalid')
        if link is not None and (row['session_id']!=link['prepared']['envelope']['session_id']
                or row['broker_id']!=link['prepared']['envelope']['broker_id']): c.fail('evidence_invalid')
        if kind=='approval_witness':
            if wrapped['source']!='broker_memfd' or link is None: c.fail('evidence_invalid')
            witness=data['witness']; identity=witness['reviewer_id']
            validate_approval_observation(data,link['prepared'],previous_sequence=approval_sequences.get(identity,0))
            approval_sequences[identity]=witness['consume_sequence']
            if link['approval'] is not None: c.fail('evidence_invalid')
            consume=consumed.get((identity,witness['reference_sha256']))
            if consume is None:
                missing.add('transcript')
            elif (consume[0]!=link['prepared'] or consume[1]['consume_sequence']!=witness['consume_sequence']
                    or consume[1]['witness_sha256']!=data['raw_sha256'] or consume[2]>witness['issued_at_ns']):
                c.fail('evidence_invalid')
            link['approval']=data
        elif kind=='audit_witness':
            if wrapped['source']!='broker_memfd' or link is None: c.fail('evidence_invalid')
            raw=_base64(data['raw_base64'],2048); witness,_=_audit_decode(raw)
            writer=witness['writer_id']; previous=audit_sequences.get(writer,(0,0))
            observed=audit_sources.get((row['broker_id'],writer))
            if observed is None or observed[1]>data['received_at_ns']:c.fail('evidence_invalid')
            source=observed[0]
            validate_audit_observation(data,link['prepared'],source=source,
                sequence=previous[0]+1,previous_audit=previous[1])
            audit_sequences[writer]=(witness['sequence'],witness['audit_sequence'])
            if audit_events.get(data['producer_sha256'])!=data['producer_event']: c.fail('evidence_invalid')
            if link['audit'] is not None: c.fail('evidence_invalid')
            link['audit']=data
        elif kind=='protocol':
            frame=data['frame']; role=data['channel_role']
            key=(row['observer_id'],frame['channel_id'],data['direction'])
            previous=channel_sequences.get(key,0)
            if frame['sequence']!=previous+1: c.fail('evidence_invalid')
            channel_sequences[key]=frame['sequence']
            if role=='ingress' and frame['operation']=='DISPATCH' and wrapped['source']=='broker_memfd':
                # The host's saved result is an acknowledged result, not an
                # inference from a committed ledger row or a sent GO. Retain
                # the broker's actual request/reply pairing separately from
                # optional host observations of the same channel.
                if row['observer_id']!=row['broker_id']:c.fail('evidence_invalid')
                p.validate_frame(frame,role='ingress',direction='request' if data['direction']=='received' else 'reply')
                body=frame['body']; channel=(row['broker_id'],frame['channel_id'])
                if data['direction']=='received':
                    ingress_requests[(*channel,frame['sequence'])]=body
                elif body['status']=='ok':
                    result=body['data']; result_did=result['dispatch_id']
                    if link is None or result_did!=did or result_did in ingress_results:c.fail('evidence_invalid')
                    request=ingress_requests.get((*channel,body['request_sequence']))
                    if request is None:
                        missing.add('transcript')
                    elif request['prepared_sha256']!=c.prepared_digest(link['prepared']):
                        c.fail('evidence_invalid')
                    ingress_results[result_did]=result
            if frame['operation']=='METER' and role in {'launcher','endpoint'}:
                if link is None:c.fail('evidence_invalid')
                meter=frame['body']
                if meter['dispatch_id']!=did or meter['session_id']!=row['session_id']:c.fail('evidence_invalid')
                if role=='endpoint':
                    if data['direction']!='received' or did in meter_received:c.fail('evidence_invalid')
                    meter_received[did]=meter
                else:
                    if data['direction']!='sent' or meter_received.get(did)!=meter or did in meter_forwarded:c.fail('evidence_invalid')
                    meter_forwarded.add(did)
            if role=='launcher' and frame['operation']=='GO':
                if link is None: c.fail('evidence_invalid')
                release=c.validate_release_binding(frame['body'],link['prepared'],clock=frame['body']['guard_clock'])
                identity=(release['broker_id'],release['dispatch_id'],data['direction'],row['observer_id'])
                if identity in seen_go: c.fail('evidence_invalid')
                seen_go.add(identity)
                if link['release'] is not None and link['release']!=release: c.fail('evidence_invalid')
                link['release']=release;link['go_observed']=True
        elif kind=='watch':
            if data['ledger_state_sha256'] is not None and states.get(data['ledger_state_sha256'])!=data['ledger_sequence']:
                c.fail('evidence_invalid')
        elif kind=='state':
            if link is None: c.fail('evidence_invalid')
            prior=state_rows.get(did)
            if data['from_state']!=prior: c.fail('evidence_invalid')
            if prior in {'settled','terminal_unresolved'}: c.fail('evidence_invalid')
            if prior is not None and STATES.index(prior)>=STATES.index('release_attempted') and data['to_state'] in STATES[:5]: c.fail('evidence_invalid')
            state_rows[did]=data['to_state']
        elif kind=='export':
            if states.get(data['ledger_state_sha256'])!=data['ledger_sequence']: c.fail('evidence_invalid')
        elif kind=='meter':
            # Fixed owned instrumentation projects actual endpoint events into
            # the broker's transcript. It does not consume the final METER slot
            # and cannot establish final delivery totals from a partial prefix.
            if link is None or wrapped['source']!='broker_memfd' or row['observer_id']!=row['broker_id']:c.fail('evidence_invalid')
            prefix=meter_prefixes.setdefault(did,[])
            if data['sequence']!=len(prefix)+1 or len(prefix)>=64 or data['monotonic_ns']>row['observed_at_ns']:c.fail('evidence_invalid')
            if prefix and (prefix[-1]['kind']=='close' or data['monotonic_ns']<prefix[-1]['monotonic_ns']):c.fail('evidence_invalid')
            if (data['kind']=='arm')!=(not prefix):c.fail('evidence_invalid')
            accepted=sum(event['kind']=='accept' for event in prefix)+(data['kind']=='accept')
            caps=c.SLOTS[link['prepared']['envelope']['slot']]
            if data['connection']!=accepted or accepted>caps[1]:c.fail('evidence_invalid')
            if data['kind'] in {'recv','send'}:
                used=sum(event['actual_bytes'] for event in prefix if event['kind']==data['kind'])
                cap=caps[2] if data['kind']=='recv' else caps[3]
                if not accepted or data['actual_bytes']<=0 or data['remaining_before']!=cap-used:c.fail('evidence_invalid')
            elif any(data[key] for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after')):c.fail('evidence_invalid')
            prefix.append(data)
    for did,link in dispatches.items():
        reservation,release=link['reservation'],link['release']
        approval,audit=link['approval'],link['audit']
        if reservation is not None:
            if approval is None or audit is None: missing.add('transcript')
            else:
                aw=approval['witness']; legacy,_=_audit_decode(_base64(audit['raw_base64'],2048))
                if reservation['approval']!={'broker_id':aw['reviewer_id'],'consume_sequence':aw['consume_sequence'],'witness_sha256':approval['raw_sha256']}:
                    c.fail('evidence_invalid')
                if reservation['audit']!={'writer_id':legacy['writer_id'],'audit_sequence':legacy['audit_sequence'],'event_sha256':audit['producer_sha256']}:
                    c.fail('evidence_invalid')
        if release is not None:
            if reservation is None: c.fail('evidence_invalid')
            event=events.get(release['reservation_event_id'])
            if event is None or event['receipt']['dispatch_id']!=did or event['receipt']['operation']!='reserve' or event['sequence']!=release['reservation_sequence'] or event['receipt']['state_sha256']!=release['reservation_state_sha256']:
                c.fail('evidence_invalid')
            if approval is None or audit is None: missing.add('transcript')
            else:
                if release['approval_witness_sha256']!=approval['raw_sha256'] or release['audit_witness_sha256']!=audit['raw_sha256']: c.fail('evidence_invalid')
                aw=approval['witness']; _,issued=_audit_decode(_base64(audit['raw_base64'],2048))
                lease=c.derive_effective_lease(link['prepared'],reservation,aw,{'issued_at_ns':issued},clock=release['guard_clock'])
                if release['effective_lease_deadline_ns']!=lease: c.fail('evidence_invalid')
            admission=admissions.get(did)
            if admission is not None and admission['redeemed']is not None and admission['release']!=release:c.fail('evidence_invalid')
        prefix=meter_prefixes.get(did,[])
        if prefix:
            if release is None:c.fail('evidence_invalid')
            for event in prefix:
                if event['monotonic_ns']<release['guard_clock']['mono_after_ns']:c.fail('evidence_invalid')
                if event['kind'] in {'recv','send'} and event['monotonic_ns']>=release['effect_stop_ns']:c.fail('evidence_invalid')
            if did in meter_received and meter_received[did]['events'][:len(prefix)]!=prefix:c.fail('evidence_invalid')
        link['meter_prefix']=prefix
        result=link['result']
        if result is not None:
            acknowledged=ingress_results.get(did)
            if acknowledged is None:
                missing.add('transcript')
            elif acknowledged!=result:
                c.fail('evidence_invalid')
            if result['outcome']=='useful':
                admission=admissions.get(did)
                if admission is None or admission['redeemed']is None or did not in meter_forwarded:missing.add('transcript')
            if result['completion']is not None:
                completion=link['completion'];observed=result['observation']
                if completion is None or observed is None:c.fail('evidence_invalid')
                expected={'evidence_sha256':c.digest(c.canonical(observed)),**{key:observed[key] for key in ('connections','request_bytes','response_bytes')}}
                if completion['observation']!=expected:c.fail('evidence_invalid')
                if result['outcome']=='useful' and completion['outcome']!='reported_success':c.fail('evidence_invalid')
            if result['release'] is not None:
                summary=result['release']
                if summary['send_status']=='sent' and release is None:
                    missing.add('transcript')
                if release is not None and (summary['release_sha256']!=c.digest(c.canonical(release))
                        or summary['effective_lease_deadline_ns']!=release['effective_lease_deadline_ns']
                        or summary['effect_stop_ns']!=release['effect_stop_ns']): c.fail('evidence_invalid')
            if result['admission'] is None and reservation is not None and result['outcome']!='unresolved': c.fail('evidence_invalid')
            if result['outcome'] in {'denied','not_started'} and result['admission'] is None and result['release'] is None and final is not None and reservation is None:
                link['reservation_observed']=False;link['go_observed']=False
        if final is None: missing.add('final_export')
    c._check_deadline(deadline)
    return {'missing_evidence':sorted(missing),'linkage':{'dispatches':dispatches}}
