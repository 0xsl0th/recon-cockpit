"""Direct proof of consumed terminal approval, bound to its original expiry."""

import math
import os
import select
import time

from . import approval_protocol as protocol
from .audit_witness import endpoint, receive
from .models import parse_policy

MAX_WITNESS = 2048
MAX_AGE = 5


def manifest(value):
    if (type(value) is not dict or set(value) != {'version', 'broker_id', 'device', 'inode'}
            or value['version'] != '1'
            or any(type(value[k]) is not int or value[k] < 0 for k in ('device', 'inode'))):
        raise ValueError('invalid_approval_witness_manifest')
    protocol.identity(value['broker_id'])
    return dict(value)


def witness(initial, action, grant, sequence, consume_sequence, now):
    policy = parse_policy(initial['policy'])
    if (policy.evaluate(action).decision != 'approval_required'
            or grant.action_digest != action.digest or grant.policy_digest != policy.digest):
        raise ValueError('invalid_consumed_approval')
    value = {'version': '1', 'broker_id': initial['broker_id'],
             'session_id': initial['session_id'], 'policy_digest': policy.digest,
             'action_id': action.action_id, 'action_digest': action.digest,
             'sequence': sequence, 'consume_sequence': consume_sequence,
             'issued_at': now, 'expires_at': min(grant.expires_at, initial['deadline'])}
    validate(value, initial, action, {'version': '1', 'broker_id': initial['broker_id'],
             'device': 0, 'inode': 0}, sequence, consume_sequence-1, now, initial['deadline'])
    if len(protocol.encode(value)) > MAX_WITNESS:
        raise ValueError('approval_witness_limit')
    return value


def validate(value, config, action, source, sequence, previous_consume, now, deadline):
    manifest(source)
    policy = parse_policy(config['policy'])
    expected = {'version': '1', 'broker_id': source['broker_id'],
                'session_id': config['session_id'], 'policy_digest': policy.digest,
                'action_id': action.action_id, 'action_digest': action.digest}
    if (type(value) is not dict or set(value) != set(expected) | {
            'sequence', 'consume_sequence', 'issued_at', 'expires_at'}
            or any(value[k] != v for k, v in expected.items())
            or policy.evaluate(action).decision != 'approval_required'
            or type(value['sequence']) is not int or value['sequence'] != sequence
            or not 1 <= sequence <= protocol.MAX_REVIEWS
            or type(value['consume_sequence']) is not int
            or not previous_consume < value['consume_sequence'] <= protocol.MAX_REQUESTS
            or any(type(value[k]) not in (int, float) or not math.isfinite(value[k])
                   for k in ('issued_at', 'expires_at'))
            or not 0 <= now - value['issued_at'] < MAX_AGE
            or not now < value['expires_at'] <= deadline
            or value['expires_at'] - value['issued_at'] > policy.approval_ttl_seconds):
        raise ValueError('invalid_launch_approval')
    return value['consume_sequence'], min(value['expires_at'], value['issued_at']+MAX_AGE)


class Reader:
    def __init__(self, fd, source):
        try:
            self.source = manifest(source)
        except BaseException:
            os.close(fd)
            raise
        self.channel = endpoint(fd, [source['device'], source['inode']], writer=False)
        self.sequence = self.consume_sequence = 0
        self.expires_at = None
        self.closed = False

    def _quiet(self):
        if select.select([self.channel], [], [], 0)[0]:
            raise ValueError('unexpected_approval_witness_output_or_exit')

    def require(self, config, action, control):
        if self.closed:
            raise ValueError('approval_witness_closed')
        try:
            control.check()
            self.expires_at = None
            decision = parse_policy(config['policy']).evaluate(action).decision
            if decision == 'allow':
                self._quiet()
                return
            if decision != 'approval_required':
                raise ValueError('launch_approval_denied')
            expiry = min(control.deadline, time.monotonic()+MAX_AGE)
            while True:
                control.check()
                remaining = expiry-time.monotonic()
                if remaining <= 0:
                    raise ValueError('launch_approval_missing')
                if select.select([self.channel], [], [], min(remaining, 0.05))[0]:
                    break
            value, _ = receive(self.channel, limit=MAX_WITNESS)
            self.consume_sequence, self.expires_at = validate(value, config, action, self.source,
                self.sequence+1, self.consume_sequence, time.monotonic(), control.deadline)
            self.sequence += 1
            self.check_fresh(control)
        except BaseException:
            self.close()
            raise

    def check_fresh(self, control):
        try:
            if self.closed:
                raise ValueError('approval_witness_closed')
            control.check()
            if self.expires_at is not None and time.monotonic() >= self.expires_at:
                raise ValueError('launch_approval_expired')
            self._quiet()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closed = True
        self.channel.close()
