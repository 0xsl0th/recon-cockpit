"""Bounded data-only protocol for one session's isolated terminal approvals."""

import hashlib
import json
import math
import re
from uuid import UUID

from .models import load_json, parse_action, parse_policy

MAX_PACKET = 32768
MAX_REQUESTS = 32
MAX_REVIEWS = 16
MAX_LIFETIME = 600
CHECKS = frozenset({'namespaces_private', 'capabilities_dropped', 'no_new_privs',
                    'socket_creation_blocked', 'process_creation_blocked',
                    'namespace_creation_blocked', 'root_read_only',
                    'descriptors_private', 'terminal_operations_restricted'})
REASONS = frozenset({'approval_missing', 'approval_unknown_or_replayed',
                     'approval_expired', 'approval_action_changed', 'approval_policy_changed'})


def encode(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                     separators=(',', ':')).encode('ascii')
    if len(raw) > MAX_PACKET:
        raise ValueError('approval_packet_limit')
    return raw


def decode(raw):
    if type(raw) is not bytes:
        raise ValueError('invalid_approval_packet')
    return load_json(raw)


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def identity(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError('invalid_approval_identity')
    return value


def reference(value):
    if value is not None and (type(value) is not str or not re.fullmatch('[0-9a-f]{48}', value)):
        raise ValueError('invalid_approval_reference')
    return value


def initial(value, now):
    if (set(value) != {'version', 'broker_id', 'session_id', 'policy', 'deadline', 'terminal'}
            or value['version'] != '1'
            or type(value['deadline']) not in (int, float)
            or not math.isfinite(value['deadline'])
            or not 0 < value['deadline'] - now <= MAX_LIFETIME
            or type(value['terminal']) is not list or len(value['terminal']) != 3
            or any(type(item) is not int or item < 0 for item in value['terminal'])):
        raise ValueError('invalid_approval_init')
    identity(value['broker_id'])
    identity(value['session_id'])
    return parse_policy(value['policy'])


def request(value, broker_id, session_id, sequence):
    fields = {'version', 'broker_id', 'session_id', 'sequence', 'operation', 'action', 'policy_digest'}
    operation = value.get('operation')
    if operation == 'consume':
        fields.add('reference')
    if (set(value) != fields or value['version'] != '1'
            or value['broker_id'] != broker_id or value['session_id'] != session_id
            or type(value['sequence']) is not int or value['sequence'] != sequence
            or not 1 <= sequence <= MAX_REQUESTS
            or type(operation) is not str or operation not in {'review', 'consume'}
            or type(value['policy_digest']) is not str
            or not re.fullmatch('[0-9a-f]{64}', value['policy_digest'])):
        raise ValueError('invalid_approval_request')
    if operation == 'consume':
        reference(value['reference'])
    return parse_action(value['action'])


def receipt(value, result):
    if value['operation'] == 'review':
        reference(result)
    elif result is not None and (type(result) is not str or result not in REASONS):
        raise ValueError('invalid_approval_result')
    return {'version': '1', 'broker_id': value['broker_id'], 'session_id': value['session_id'],
            'sequence': value['sequence'], 'request_digest': digest(value), 'result': result}
