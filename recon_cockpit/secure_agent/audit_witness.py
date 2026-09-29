"""One-way, bounded evidence of a durable launch intent, never human consent."""

import array
import errno
import fcntl
import hashlib
import math
import os
import re
import select
import socket
import time

if __package__:
    from . import audit_protocol as protocol
else:
    import audit_protocol as protocol

MAX_WITNESS = 2048
MAX_LAUNCHES = 16
MAX_AGE = 5
FIELDS = ('session_id', 'action_id', 'action_digest', 'policy_digest', 'policy_version',
          'tool_id', 'target', 'backend', 'decision', 'execution_status')


def manifest(value):
    if (type(value) is not dict or set(value) != {'version', 'writer_id', 'device', 'inode'}
            or value['version'] != '1' or any(type(value[k]) is not int or value[k] < 0 for k in ('device', 'inode'))):
        raise ValueError('invalid_witness_manifest')
    protocol.writer_id(value['writer_id'])
    return dict(value)


def receive(channel, count=0, *, limit=protocol.MAX_PACKET):
    raw, ancillary, flags, _ = channel.recvmsg(limit, socket.CMSG_SPACE(256))
    descriptors = []
    try:
        invalid = False
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                invalid = True
                continue
            values = array.array('i')
            values.frombytes(data[:len(data)-len(data) % values.itemsize])
            descriptors.extend(values)
        if invalid or flags or len(descriptors) != count:
            raise ValueError('invalid_witness_descriptors')
        value = protocol.decode(raw)
        result, descriptors = descriptors, []
        return value, result
    finally:
        for fd in descriptors:
            os.close(fd)


def endpoint(fd, identity, *, writer):
    """Take custody of a fixed, already half-closed nonblocking endpoint."""
    channel = None
    try:
        channel = socket.socket(fileno=fd)
        info = os.fstat(fd)
        if (channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET
                or [info.st_dev, info.st_ino] != identity
                or not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK):
            raise ValueError('invalid_witness_endpoint')
        channel.setblocking(False)
        if writer:
            if channel.recv(1) != b'':
                raise ValueError('witness_writer_can_receive')
        else:
            try:
                channel.send(b'forbidden-witness-write')
            except OSError as exc:
                if exc.errno != errno.EPIPE:
                    raise
            else:
                raise ValueError('witness_reader_can_send')
        return channel
    except BaseException:
        if channel is not None:
            channel.close()
        else:
            os.close(fd)
        raise


def claims(event):
    if type(event) is not dict:
        raise ValueError('invalid_witness_intent')
    value = {key: event.get(key) for key in FIELDS}
    if (any(type(item) is not str or not 1 <= len(item) <= 256 for item in value.values())
            or event.get('event_type') != 'execution_started' or value['execution_status'] != 'started'
            or value['decision'] not in {'allow', 'approval_required'}
            or any(not re.fullmatch('[a-f0-9]{64}', value[key]) for key in ('action_digest', 'policy_digest'))):
        raise ValueError('invalid_witness_intent')
    for key in ('session_id', 'action_id'):
        protocol.writer_id(value[key])
    return value


def witness(event, writer_id, audit_sequence, sequence, now):
    protocol.writer_id(writer_id)
    if (type(audit_sequence) is not int or not 1 <= audit_sequence <= protocol.MAX_EVENTS
            or type(sequence) is not int or not 1 <= sequence <= MAX_LAUNCHES
            or type(now) not in (int, float) or not math.isfinite(now) or now < 0):
        raise ValueError('invalid_witness_sequence_or_time')
    value = {'version': '1', 'writer_id': writer_id, 'audit_sequence': audit_sequence,
             'sequence': sequence, 'issued_at': now, 'intent': claims(event),
             'event_digest': hashlib.sha256(protocol.event_bytes(event)).hexdigest()}
    if len(protocol.encode(value)) > MAX_WITNESS:
        raise ValueError('witness_limit')
    return value


def validate(value, config, action, source, sequence, previous_audit, now):
    manifest(source)
    if (type(value) is not dict or set(value) != {'version', 'writer_id', 'audit_sequence', 'sequence', 'issued_at', 'intent', 'event_digest'}
            or value['version'] != '1' or value['writer_id'] != source['writer_id']
            or type(value['sequence']) is not int or value['sequence'] != sequence or not 1 <= sequence <= MAX_LAUNCHES
            or type(value['audit_sequence']) is not int or not previous_audit < value['audit_sequence'] <= protocol.MAX_EVENTS
            or type(value['issued_at']) not in (int, float) or not math.isfinite(value['issued_at'])
            or not 0 <= now - value['issued_at'] <= MAX_AGE
            or type(value['event_digest']) is not str or not re.fullmatch('[a-f0-9]{64}', value['event_digest'])):
        raise ValueError('invalid_launch_witness')
    # Import lazily: the audit worker only projects producer data; policy truth
    # and canonical action matching belong to the launcher.
    from .models import parse_policy
    from .launcher_protocol import PROFILES
    policy = parse_policy(config['policy'])
    expected = {'session_id': config['session_id'], 'action_id': action.action_id,
                'action_digest': action.digest, 'policy_digest': policy.digest,
                'policy_version': policy.policy_version, 'tool_id': action.tool_id,
                'target': action.target, 'backend': PROFILES[config['profile']],
                'decision': policy.evaluate(action).decision, 'execution_status': 'started'}
    if expected['decision'] == 'deny' or protocol.encode(value['intent']) != protocol.encode(expected):
        raise ValueError('launch_witness_mismatch')
    return value['audit_sequence']


class Reader:
    def __init__(self, fd, source):
        try:
            self.source = manifest(source)
        except BaseException:
            os.close(fd)
            raise
        self.channel = endpoint(fd, [source['device'], source['inode']], writer=False)
        self.sequence = self.audit_sequence = 0
        self.closed = False

    def require(self, config, action, control):
        if self.closed:
            raise ValueError('launch_witness_closed')
        try:
            self._require(config, action, control)
        except BaseException:
            self.close()
            raise

    def _require(self, config, action, control):
        expiry = min(control.deadline, time.monotonic()+MAX_AGE)
        while True:
            control.check()
            remaining = expiry-time.monotonic()
            if remaining <= 0:
                raise ValueError('launch_witness_missing')
            if select.select([self.channel], [], [], min(remaining, 0.05))[0]:
                break
        value, _ = receive(self.channel, limit=MAX_WITNESS)
        control.check()
        self.audit_sequence = validate(value, config, action, self.source,
                                       self.sequence+1, self.audit_sequence, time.monotonic())
        self.sequence += 1
        # A producer exit or an unsolicited queued second witness is a fault,
        # not permission to attach to another source or consume ahead of work.
        if select.select([self.channel], [], [], 0)[0]:
            raise ValueError('unexpected_launch_witness_output_or_exit')

    def close(self):
        self.closed = True
        self.channel.close()
