"""Data-only contract for one confined append writer; no filesystem paths/RPC."""

import hashlib
import json
from uuid import UUID

MAX_PACKET = 32768
MAX_EVENT = 30000
MAX_EVENTS = 1024
MAX_FILE_BYTES = 1048576
MAX_LIFETIME = 900
EXCHANGE_SECONDS = 5
RESERVED = frozenset({'event_schema_version', 'event_id', 'timestamp', 'source'})
CHECKS = frozenset({'namespaces_private', 'capabilities_dropped', 'no_new_privs',
                    'socket_creation_blocked', 'process_creation_blocked',
                    'namespace_creation_blocked', 'root_read_only',
                    'descriptors_private', 'file_operations_blocked'})


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(',', ':')).encode('ascii')


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_audit_key')
            result[key] = value
        return result

    def invalid(_):
        raise ValueError('invalid_audit_constant')

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PACKET:
        raise ValueError('invalid_audit_packet')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    if type(value) is not dict:
        raise ValueError('invalid_audit_object')
    return value


def writer_id(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError('invalid_audit_writer')
    return value


def event_bytes(event):
    if (type(event) is not dict or RESERVED & event.keys()
            or type(event.get('event_type')) is not str
            or not 1 <= len(event['event_type']) <= 80):
        raise ValueError('invalid_audit_event')
    raw = encode(event)
    if len(raw) > MAX_EVENT or decode(raw) != event:
        raise ValueError('invalid_audit_event')
    return raw


def request(value, identity, sequence):
    if (set(value) != {'version', 'writer_id', 'sequence', 'event'}
            or value['version'] != '1' or value['writer_id'] != identity
            or type(value['sequence']) is not int or value['sequence'] != sequence
            or not 1 <= sequence <= MAX_EVENTS):
        raise ValueError('invalid_audit_request')
    return event_bytes(value['event'])


def receipt(identity, sequence, raw):
    return {'version': '1', 'writer_id': identity, 'sequence': sequence,
            'event_digest': hashlib.sha256(raw).hexdigest(), 'durable': True}
