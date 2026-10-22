"""Bounded, role-specific SEQPACKET framing. No packet creates a role."""
from __future__ import annotations

import array
import base64
import os
import re
import select
import socket

from . import engagement_live_contract as c

REPLY_FIELDS = frozenset(('request_sequence', 'status', 'code', 'data'))
TERMINAL = frozenset(('CANCEL', 'CLOSE', 'CLOSED', 'STOP', 'SESSION_STOP', 'BROKER_STOP'))
ROLES = frozenset(('terminal', 'graphical', 'admission', 'ingress', 'lifecycle',
                   'launcher', 'endpoint', 'arm'))
REQUEST_OPERATIONS = {
    'terminal': {'REVIEW', 'CONSUME', 'CLOSE'},
    'graphical': {'REVIEW', 'CONSUME', 'CLOSE'},
    'admission': {'ISSUE', 'REDEEM', 'CANCEL', 'CLOSE'},
    'ingress': {'OPEN_SESSION', 'PREPARE', 'DISPATCH', 'CANCEL', 'REVOKE', 'SNAPSHOT', 'CLOSE'},
    'lifecycle': {'ROLE_OBSERVED', 'AUDIT_OBSERVED', 'STOP', 'SESSION_STOP', 'BROKER_STOP'},
    'launcher': {'PREPARE', 'GO', 'METER', 'CANCEL', 'STOP', 'READY', 'PREPARED', 'NATIVE_OBSERVED', 'OBSERVATION', 'RESULT', 'CLOSED'},
    'endpoint': {'PREPARE', 'CANCEL', 'STOP', 'READY', 'PREPARED', 'METER', 'CLOSED'},
    'arm': {'ARM', 'ACK', 'REFUSED'},
}


def _reference(value, size=48):
    if type(value) is not str or re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is None:
        c.fail('invalid_frame')
    return value


def _none(value):
    if value is not None:
        c.fail('invalid_frame')


def _closed(value):
    c.obj(value, ('role', 'worker_id', 'stopped_at_ns'))
    c.member(value['role'], {'terminal', 'graphical', 'admission', 'launcher', 'endpoint'})
    c.uuid(value['worker_id'])
    c.integer(value['stopped_at_ns'])


def _consume_result(value):
    c.obj(value, ('accepted', 'consume_sequence', 'reference_sha256', 'witness_sha256'))
    if type(value['accepted']) is not bool:
        c.fail('invalid_frame')
    c.integer(value['consume_sequence'], 1, 32)
    c.digest_string(value['reference_sha256'])
    if value['accepted']:
        c.digest_string(value['witness_sha256'])
    else:
        _none(value['witness_sha256'])


def _reason(value):
    c.obj(value, ('reason',))
    c.member(value['reason'], c.ERROR_CODES)


def _hash_fields(value, fields):
    c.obj(value, fields)
    for key in fields:
        if key.endswith('_sha256'):
            c.digest_string(value[key])
        elif key.endswith('_ns'):
            c.integer(value[key])


def _runtime(kind, value):
    # Lazy to avoid contract/runtime cycles and before-entry host imports.
    from . import engagement_live_runtime as runtime
    validator = getattr(runtime, 'validate_protocol_value', None)
    if validator is None:
        c.fail('unavailable')
    return validator(kind, value)


def _body(role, operation, value, direction):
    if operation not in REQUEST_OPERATIONS[role]:
        c.fail('invalid_role')
    if direction == 'reply':
        c.obj(value, REPLY_FIELDS)
        c.integer(value['request_sequence'], 1, 66)
        c.member(value['status'], {'ok', 'pending', 'refused'})
        if value['status'] == 'refused':
            c.member(value['code'], c.ERROR_CODES)
            _none(value['data'])
            return
        _none(value['code'])
        data = value['data']
        if value['status'] == 'pending':
            if role != 'ingress' or operation not in {'PREPARE', 'DISPATCH'}:
                c.fail('invalid_frame')
            fields = ('session_id', 'dispatch_id') if operation == 'PREPARE' else ('dispatch_id',)
            c.obj(data, fields)
            for item in data.values():
                c.uuid(item)
            return
        if role in {'terminal', 'graphical'}:
            if operation == 'REVIEW':
                if data is not None:
                    _reference(data)
            elif operation == 'CONSUME':
                _consume_result(data)
            else:
                _closed(data)
            return
        if role == 'admission':
            if operation == 'ISSUE':
                validate_permit(data)
            elif operation == 'REDEEM':
                validate_redeemed(data)
            else:
                _closed(data)
            return
        if role == 'ingress':
            if operation == 'OPEN_SESSION':
                c.validate_session_opened(data)
            elif operation == 'PREPARE':
                c.obj(data, ('schema_version', 'prepared', 'preparation'))
                if data['schema_version'] != '1':
                    c.fail('invalid_frame')
                c.validate_prepared(data['prepared'])
                validate_prepare_receipt(data['preparation'])
            elif operation == 'DISPATCH':
                c.validate_live_result(data)
            elif operation == 'REVOKE':
                c.validate_ledger_result(data)
            elif operation == 'CANCEL':
                c.obj(data, ('session_id', 'state'))
                c.uuid(data['session_id'])
                c.member(data['state'], {'stopping', 'closed'})
            elif operation == 'SNAPSHOT':
                validate_status(data)
            else:
                _runtime('cleanup', data)
            return
        c.fail('invalid_role')
    if direction != 'request':
        c.fail('invalid_frame')
    if role in {'terminal', 'graphical'}:
        if operation == 'REVIEW':
            c.validate_prepared(value)
        elif operation == 'CONSUME':
            c.obj(value, ('reference', 'prepared'))
            _reference(value['reference'])
            c.validate_prepared(value['prepared'])
        else:
            _none(value)
    elif role == 'ingress':
        if operation == 'OPEN_SESSION':
            c.obj(value, ('slot_index',)); c.integer(value['slot_index'], 0, 1)
        elif operation == 'PREPARE':
            c.obj(value, ('session_id', 'slot')); c.uuid(value['session_id']); c.member(value['slot'], c.SLOTS)
        elif operation == 'DISPATCH':
            c.obj(value, ('prepared_sha256', 'reference_sha256', 'consume_sequence', 'audit_sequence'))
            c.digest_string(value['prepared_sha256']); c.digest_string(value['reference_sha256'])
            c.integer(value['consume_sequence'], 1, 32); c.integer(value['audit_sequence'], 1, 1024)
        elif operation == 'CANCEL':
            c.obj(value, ('session_id',)); c.uuid(value['session_id'])
        elif operation == 'REVOKE':
            c.obj(value, ('expected_revision', 'expected_generation', 'event_id'))
            c.integer(value['expected_revision'], 1, 64); c.integer(value['expected_generation'], 0, 64); c.uuid(value['event_id'])
        else:
            _none(value)
    elif role == 'admission':
        if operation == 'ISSUE':
            c.validate_prepared(value)
        elif operation == 'REDEEM':
            c.obj(value, ('prepared_sha256', 'reference', 'release'))
            c.digest_string(value['prepared_sha256']); _reference(value['reference'], 64); c.validate_release(value['release'])
        elif operation == 'CANCEL':
            _reason(value)
        else:
            _none(value)
    elif role in {'launcher', 'endpoint'}:
        if operation == 'PREPARE':
            c.validate_prepared(value)
        elif operation == 'GO':
            c.validate_release(value)
        elif operation == 'CANCEL':
            _reason(value)
        elif operation == 'STOP':
            _none(value)
        elif operation == 'CLOSED':
            _closed(value)
        elif operation == 'OBSERVATION':
            validate_launcher_observation(value)
        elif operation == 'PREPARED':
            if role == 'launcher':
                validate_prepare_receipt(value)
            else:
                _hash_fields(value, ('prepared_sha256', 'envelope_sha256', 'ready_at_ns'))
        else:
            _runtime({'READY': 'worker_ready', 'NATIVE_OBSERVED': 'native_readiness',
                      'RESULT': 'client_result', 'METER': 'meter'}[operation], value)
    elif role == 'arm':
        if operation == 'ARM':
            c.obj(value, ('release', 'slot')); c.validate_release(value['release']); c.member(value['slot'], c.SLOTS)
        elif operation == 'ACK':
            validate_arm_ack(value)
        else:
            c.obj(value, REPLY_FIELDS)
            if value['status'] != 'refused':
                c.fail('invalid_frame')
            c.integer(value['request_sequence'], 1, 66); c.member(value['code'], c.ERROR_CODES); _none(value['data'])
    else:
        if operation == 'ROLE_OBSERVED':
            c.obj(value, ('slot_index', 'role', 'readiness'))
            c.integer(value['slot_index'], 0, 1)
            c.member(value['role'], {'terminal', 'graphical', 'launcher', 'endpoint'})
            _runtime('role_readiness', value['readiness'])
        elif operation == 'AUDIT_OBSERVED':
            from .engagement_live_witness import validate_audit_readiness
            validate_audit_readiness(value)
        elif operation == 'STOP':
            _reason(value)
        else:
            fields = ('reason', 'observed_at_ns', 'cleanup_deadline_ns') + (('session_id',) if operation == 'SESSION_STOP' else ())
            c.obj(value, fields); c.member(value['reason'], c.ERROR_CODES)
            if 'session_id' in value:
                c.uuid(value['session_id'])
            now = c.integer(value['observed_at_ns'])
            if not now < c.integer(value['cleanup_deadline_ns'], 1) <= now + c.CLEANUP_NS:
                c.fail('invalid_frame')


@c.validation('invalid_frame')
def validate_frame(value, *, role, direction=None):
    c.member(role, ROLES)
    value = c.detached(value)
    c._tree(value, c.MAX_PACKET, depth=12)
    c.obj(value, ('schema_version', 'channel_id', 'sequence', 'operation', 'body'))
    if value['schema_version'] != '1':
        c.fail()
    c.uuid(value['channel_id']); c.integer(value['sequence'], 1, 130)
    c.member(value['operation'], REQUEST_OPERATIONS[role])
    inferred = 'reply' if type(value['body']) is dict and set(value['body']) == REPLY_FIELDS else 'request'
    if direction is not None and direction != inferred:
        c.fail()
    _body(role, value['operation'], value['body'], inferred)
    return value


@c.validation('invalid_frame')
def validate_launcher_observation(value):
    """Actual child evidence on the prebound launcher channel, never authority."""
    c.obj(value, ('dispatch_id', 'kind', 'data'))
    c.uuid(value['dispatch_id'])
    kind=c.member(value['kind'], {'capture','role_readiness','cleanup','capability_projection'})
    data=value['data']
    if kind=='capture':
        c.obj(data, ('schema_version','slot','stdout_base64','stderr_base64','stdout_sha256',
            'stderr_sha256','stdout_bytes','stderr_bytes','exit_code','truncated'))
        if data['schema_version']!='1' or type(data['truncated'])is not bool:c.fail()
        slot=c.member(data['slot'],c.SLOTS);total=0
        for stream in ('stdout','stderr'):
            encoded=data[stream+'_base64']
            if type(encoded)is not str or len(encoded)>10924:c.fail()
            try:raw=base64.b64decode(encoded,validate=True)
            except (ValueError,TypeError):c.fail()
            if base64.b64encode(raw).decode('ascii')!=encoded:c.fail()
            if c.integer(data[stream+'_bytes'],0,8192)!=len(raw) or c.digest_string(data[stream+'_sha256'])!=c.digest(raw):c.fail()
            total+=len(raw)
        if total>c.SLOTS[slot][4]:c.fail('limit_exceeded')
        if data['exit_code']is not None:c.integer(data['exit_code'],-255,255)
    elif kind in {'role_readiness','cleanup'}:
        _runtime(kind,data)
        if kind=='role_readiness' and data['worker_ready']['role'] not in {'admission','nmap','headers','parser'}:c.fail()
    else:
        from .engagement_live_witness import validate_capability_projection
        validate_capability_projection(data)
        if data['role']!='admission':c.fail()
    return c.detached(value)


def encode_frame(value, *, role, direction, max_bytes=c.MAX_PACKET):
    raw = c.canonical(validate_frame(value, role=role, direction=direction), max_bytes=max_bytes)
    if value['operation'] in {'GO', 'ARM'} and len(raw) > 4096:
        c.fail('limit_exceeded')
    return raw


def decode_frame(raw, *, role, direction, max_bytes=c.MAX_PACKET):
    value = validate_frame(c.decode(raw, max_bytes=max_bytes), role=role, direction=direction)
    if c.canonical(value, max_bytes=max_bytes) != raw:
        c.fail('invalid_frame')
    if value['operation'] in {'GO', 'ARM'} and len(raw) > 4096:
        c.fail('limit_exceeded')
    return value


def require_request(value, *, role):
    return validate_frame(value, role=role, direction='request')


def require_reply(value, request, *, role):
    value = validate_frame(value, role=role, direction='reply')
    if (value['channel_id'] != request['channel_id'] or value['operation'] != request['operation']
            or value['body']['request_sequence'] != request['sequence']):
        c.fail('invalid_sequence')
    return value


def _remaining(control):
    try:
        return min(0.05, control.remaining())
    except Exception as exc:
        reason = getattr(exc, 'reason', None)
        if reason == 'session_cancelled':
            c.fail('cancelled')
        if reason == 'session_timeout':
            c.fail('timeout')
        raise


def _ready(channel, *, writing, control):
    while True:
        remaining = _remaining(control)
        try:
            reads, writes, _ = select.select([] if writing else [channel], [channel] if writing else [], [], remaining)
        except InterruptedError:
            continue
        if writes if writing else reads:
            _remaining(control)
            return


def send_once(channel, raw):
    if type(raw) is not bytes or not 0 < len(raw) <= c.MAX_PACKET:
        c.fail('invalid_frame')
    return channel.send(raw, socket.MSG_DONTWAIT | getattr(socket, 'MSG_NOSIGNAL', 0))


def send_packet(channel, frame, *, role, control, max_bytes=c.MAX_PACKET):
    raw = c.canonical(validate_frame(frame, role=role), max_bytes=max_bytes)
    if frame['operation'] in {'GO', 'ARM'} and len(raw) > 4096:
        c.fail('limit_exceeded')
    _ready(channel, writing=True, control=control)
    try:
        count = send_once(channel, raw)
    except OSError:
        c.fail('unavailable')
    if count != len(raw):
        c.fail('unavailable')
    _remaining(control)


def receive_packet(channel, *, role, control, max_bytes=c.MAX_PACKET):
    _ready(channel, writing=False, control=control)
    try:
        raw, ancillary, flags, _ = channel.recvmsg(max_bytes + 1, socket.CMSG_SPACE(64 * array.array('i').itemsize), socket.MSG_DONTWAIT | getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
    except OSError:
        c.fail('unavailable')
    if ancillary:
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array('i'); fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
                for fd in fds:
                    os.close(fd)
        c.fail('invalid_channel')
    if not raw or flags & ~getattr(socket, 'MSG_CMSG_CLOEXEC', 0) or len(raw) > max_bytes:
        c.fail('invalid_frame')
    result = decode_frame(raw, role=role, direction=None, max_bytes=max_bytes)
    _remaining(control)
    return result


def send_initial(channel, bootstrap, rights, *, control):
    raw = c.canonical(bootstrap)
    if type(rights) not in {list, tuple} or len(rights) > 14 or any(type(fd) is not int or fd < 0 for fd in rights):
        c.fail('invalid_channel')
    _ready(channel, writing=True, control=control)
    ancillary = [] if not rights else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))]
    try:
        count = channel.sendmsg([raw], ancillary, socket.MSG_DONTWAIT | getattr(socket, 'MSG_NOSIGNAL', 0))
    except OSError:
        c.fail('unavailable')
    if count != len(raw):
        c.fail('unavailable')
    _remaining(control)


class ChannelSequence:
    """Process-local counters for one inherited endpoint, never deserialized authority."""
    def __init__(self, channel_id, role):
        self.channel_id, self.role = c.uuid(channel_id), c.member(role, ROLES)
        self.sent = self.received = 0
        self.sent_ordinary = self.received_ordinary = 0
        self.sent_terminal = self.received_terminal = 0

    def _advance(self, value, outbound):
        direction = 'sent' if outbound else 'received'
        sequence = getattr(self, direction) + 1
        if value['channel_id'] != self.channel_id or value['sequence'] != sequence:
            c.fail('invalid_sequence')
        terminal = value['operation'] in TERMINAL
        counter = direction + ('_terminal' if terminal else '_ordinary')
        limit = 2 if terminal else (128 if type(value['body']) is dict and set(value['body']) == REPLY_FIELDS else 64)
        if getattr(self, counter) >= limit:
            c.fail('limit_exceeded')
        setattr(self, counter, getattr(self, counter) + 1)
        setattr(self, direction, sequence)
        return value

    def make(self, operation, body):
        value = validate_frame({'schema_version': '1', 'channel_id': self.channel_id,
            'sequence': self.sent + 1, 'operation': operation, 'body': body}, role=self.role)
        return self._advance(value, True)

    def accept(self, value):
        return self._advance(validate_frame(value, role=self.role), False)


@c.validation('invalid_frame')
def validate_prepare_receipt(value):
    value = c.detached(value)
    c.obj(value, ('schema_version', 'prepared_sha256', 'envelope_sha256', 'launcher_ready_sha256',
        'endpoint_ready_sha256', 'client_ready_sha256', 'admission_ready_sha256',
        'admission_result_sha256', 'admission_permit_sha256', 'ready_at_ns', 'preparation_deadline_ns'))
    if value['schema_version'] != '1':
        c.fail()
    for key, item in value.items():
        if key.endswith('_sha256'):
            c.digest_string(item)
    if not c.integer(value['ready_at_ns']) < c.integer(value['preparation_deadline_ns'], 1):
        c.fail()
    return value


@c.validation('invalid_frame')
def validate_arm_ack(value):
    value = c.detached(value, 4096)
    c.obj(value, ('schema_version', 'endpoint_id', 'session_id', 'dispatch_id', 'envelope_sha256',
                 'go_sha256', 'slot', 'arm_sequence', 'effective_lease_deadline_ns', 'armed_at_ns'))
    if value['schema_version'] != '1' or c.integer(value['arm_sequence']) != 1:
        c.fail()
    for key in ('endpoint_id', 'session_id', 'dispatch_id'):
        c.uuid(value[key])
    for key in ('envelope_sha256', 'go_sha256'):
        c.digest_string(value[key])
    c.member(value['slot'], c.SLOTS)
    if not c.integer(value['armed_at_ns']) < c.integer(value['effective_lease_deadline_ns'], 1):
        c.fail()
    return value


@c.validation('invalid_frame')
def validate_permit(value):
    value = c.detached(value, 4096)
    c.obj(value, ('schema_version', 'admission_id', 'session_id', 'dispatch_id', 'prepared_sha256',
        'envelope_sha256', 'action_sha256', 'policy_sha256', 'runtime_sha256', 'reference',
        'issued_at_ns', 'expires_at_ns'))
    if value['schema_version'] != '1':
        c.fail()
    for key in ('admission_id', 'session_id', 'dispatch_id'):
        c.uuid(value[key])
    for key in ('prepared_sha256', 'envelope_sha256', 'action_sha256', 'policy_sha256', 'runtime_sha256'):
        c.digest_string(value[key])
    _reference(value['reference'], 64)
    if not c.integer(value['issued_at_ns']) < c.integer(value['expires_at_ns'], 1) <= value['issued_at_ns'] + 30*c.SECOND:
        c.fail()
    return value


def permit_projection(value):
    value = validate_permit(value)
    reference = value.pop('reference')
    return {**value, 'reference_sha256': c.digest(reference.encode('ascii'))}


@c.validation('invalid_frame')
def validate_export_reference(value):
    c.obj(value, ('bytes','device','inode','phase','seals','sha256'))
    c.integer(value['bytes'],1,c.MAX_CANONICAL); c.integer(value['device'])
    c.integer(value['inode'],1); c.member(value['phase'],('initial','final'))
    if type(value['seals']) is not int or value['seals']!=15: c.fail()
    c.digest_string(value['sha256'])
    return c.detached(value)


@c.validation('invalid_frame')
def validate_redeemed(value):
    value = c.detached(value, 4096)
    c.obj(value, ('schema_version', 'admission_id', 'session_id', 'dispatch_id', 'permit_sha256',
                'release_sha256', 'prepared_sha256', 'redeemed_at_ns', 'status'))
    if value['schema_version'] != '1' or value['status'] != 'redeemed':
        c.fail()
    for key in ('admission_id', 'session_id', 'dispatch_id'):
        c.uuid(value[key])
    for key in ('permit_sha256', 'release_sha256', 'prepared_sha256'):
        c.digest_string(value[key])
    c.integer(value['redeemed_at_ns'])
    return value


@c.validation('invalid_frame')
def validate_status(value):
    value = c.detached(value)
    c.obj(value, ('schema_version', 'broker_id', 'ledger_owner_id', 'engagement_id', 'revision',
        'generation', 'status', 'ledger_sequence', 'ledger_state_sha256', 'usage',
        'last_validated_clock', 'sessions', 'terminal_reason'))
    if value['schema_version'] != '1':
        c.fail()
    for key in ('broker_id', 'ledger_owner_id', 'engagement_id'):
        c.uuid(value[key])
    c.integer(value['revision'], 1, 64); c.integer(value['generation'], 0, 64)
    c.integer(value['ledger_sequence'], 1, 257); c.digest_string(value['ledger_state_sha256'])
    c.member(value['status'], {'recorded', 'revoked'})
    c.ledger.validate_clock(value['last_validated_clock'])
    c.obj(value['usage'], ('actions', 'connections', 'request_bytes', 'response_bytes', 'runtime_ms'))
    for count in value['usage'].values():
        c.integer(count)
    if type(value['sessions']) is not list or len(value['sessions']) != 2:
        c.fail()
    seen = set()
    for row in value['sessions']:
        c.obj(row, ('session_id', 'slot_index', 'state', 'binding_sha256', 'current_dispatch_id', 'current_dispatch_state'))
        c.uuid(row['session_id']); c.integer(row['slot_index'], 0, 1)
        if row['slot_index'] in seen:
            c.fail()
        seen.add(row['slot_index'])
        c.member(row['state'], {'allocated', 'active', 'stopping', 'closed'})
        if row['binding_sha256'] is not None:
            c.digest_string(row['binding_sha256'])
        if row['current_dispatch_id'] is not None:
            c.uuid(row['current_dispatch_id'])
        if row['current_dispatch_state'] is not None:
            c.member(row['current_dispatch_state'], {'prepared', 'preparing', 'ready_for_review', 'awaiting_witnesses',
                'admitted', 'release_attempted', 'running', 'settling', 'settled', 'terminal_unresolved'})
    if value['terminal_reason'] is not None:
        c.member(value['terminal_reason'], c.ERROR_CODES)
    return value
