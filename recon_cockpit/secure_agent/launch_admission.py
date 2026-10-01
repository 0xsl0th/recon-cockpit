"""Pure, bounded launch-admission protocol and worker-owned reservation state."""

from copy import deepcopy
import hashlib
import json
import math
import re
import secrets
import time
from uuid import UUID

from .models import load_json, parse_action, parse_policy
from .tool_adapters import NMAP_SESSION_LIMITS

MAX_PACKET = 32768
MAX_REQUESTS = 32
PERMIT_SECONDS = 5
CHECKS = frozenset({'namespaces_private', 'capabilities_dropped', 'no_new_privs',
    'socket_creation_blocked', 'process_creation_blocked', 'namespace_creation_blocked',
    'root_read_only', 'descriptors_private', 'file_operations_blocked'})
REASONS = frozenset({'admission_dry_run', 'admission_policy_changed', 'admission_policy_denied',
    'admission_profile_denied', 'admission_step_limit', 'admission_output_limit',
    'admission_missing', 'admission_unknown_or_replayed', 'admission_expired',
    'admission_action_changed'})
COUNTERS = frozenset({'executions_reserved', 'output_bytes_reserved'})


def encode(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                     separators=(',', ':')).encode('ascii')
    if len(raw) > MAX_PACKET:
        raise ValueError('admission_packet_limit')
    return raw


def decode(raw):
    if type(raw) is not bytes:
        raise ValueError('invalid_admission_packet')
    return load_json(raw)


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def identity(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError('invalid_admission_identity')
    return value


def hex_value(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def limits(value):
    ceilings = {'max_steps': 16, 'max_runtime_seconds': 600, 'max_output_bytes': 1048576}
    if (type(value) is not dict or set(value) != set(ceilings)
            or any(type(value[key]) is not int or not 1 <= value[key] <= cap for key, cap in ceilings.items())):
        raise ValueError('invalid_admission_limits')
    return dict(value)


def configuration(value):
    if (type(value) is not dict
            or set(value) != {'version', 'service_id', 'session_id', 'policy', 'limits', 'execute', 'profile', 'case'}
            or value['version'] != '1' or type(value['execute']) is not bool
            or type(value['profile']) is not str or value['profile'] not in {'fixture', 'discovery_fixture', 'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab'}
            or (value['profile'] in {'owned_lab', 'owned_nmap_lab'} and (type(value['case']) is not str or value['case'] not in 'abcdef'
                                                     or len(value['case']) != 1))
            or (value['profile'] in {'owned_web_lab', 'owned_http_headers_lab'} and (type(value['case']) is not str
                or value['case'] not in ('vulnerable', 'corrected', 'injected')))
            or (value['profile'] not in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab'} and value['case'] is not None)):
        raise ValueError('invalid_admission_configuration')
    identity(value['service_id'])
    identity(value['session_id'])
    limits(value['limits'])
    if value['profile'] in {'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab'} and any(
            value['limits'][key] > maximum for key, maximum in NMAP_SESSION_LIMITS.items()):
        raise ValueError('invalid_nmap_admission_limits')
    parse_policy(value['policy'])
    return deepcopy(value)


def initial(value, now):
    if type(value) is not dict or set(value) != {'configuration', 'deadline'}:
        raise ValueError('invalid_admission_init')
    config = configuration(value['configuration'])
    deadline = value['deadline']
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= config['limits']['max_runtime_seconds']):
        raise ValueError('invalid_admission_deadline')
    return config


def request(value, config, sequence):
    operation = value.get('operation')
    fields = {'version', 'service_id', 'session_id', 'sequence', 'operation', 'action', 'policy_digest'}
    if operation == 'redeem':
        fields.add('permit')
    if (set(value) != fields or value['version'] != '1'
            or value['service_id'] != config['service_id'] or value['session_id'] != config['session_id']
            or type(value['sequence']) is not int or value['sequence'] != sequence
            or not 1 <= sequence <= MAX_REQUESTS or type(operation) is not str
            or operation not in {'admit', 'redeem'} or not hex_value(value['policy_digest'])):
        raise ValueError('invalid_admission_request')
    if operation == 'redeem' and value['permit'] is not None and not hex_value(value['permit']):
        raise ValueError('invalid_admission_permit')
    return parse_action(value['action'])


def result(value, operation, config):
    if (type(value) is not dict or set(value) != {'permit', 'reason', 'snapshot'}
            or (value['reason'] is not None and (type(value['reason']) is not str or value['reason'] not in REASONS))
            or type(value['snapshot']) is not dict or set(value['snapshot']) != COUNTERS):
        raise ValueError('invalid_admission_result')
    if operation == 'admit' and value['reason'] is None:
        if not hex_value(value['permit']):
            raise ValueError('missing_admission_permit')
    elif value['permit'] is not None:
        raise ValueError('unexpected_admission_permit')
    snapshot = value['snapshot']
    for key, ceiling in (('executions_reserved', config['limits']['max_steps']),
                         ('output_bytes_reserved', config['limits']['max_output_bytes'])):
        if type(snapshot[key]) is not int or not 0 <= snapshot[key] <= ceiling:
            raise ValueError('invalid_admission_snapshot')
    return value


def receipt(value, outcome):
    return {'version': '1', 'service_id': value['service_id'], 'session_id': value['session_id'],
            'sequence': value['sequence'], 'request_digest': digest(value), 'result': outcome}


def profile_allows(action, config):
    if action.targets != ('127.0.0.1',) or not 1024 <= action.parameters.port <= 65534:
        return False
    if config['profile'] == 'fixture':
        return action.tool_id == 'http_probe'
    if action.parameters.port != 8080:
        return False
    if action.tool_id == 'nmap_tcp_connect_v1':
        return (config['profile'] in {'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab'} and action.parameters.to_dict() ==
                {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 16384})
    if config['profile'] == 'owned_http_headers_lab':
        return (action.tool_id == 'http_headers_v1' and action.parameters.to_dict() == {
            'port': 8080, 'method': 'GET', 'path': '/harbordesk/portal.html',
            'timeout_seconds': 1, 'max_output_bytes': 2048})
    if action.tool_id not in {'http_probe', 'tcp_connect'}:
        return False
    if config['profile'] in {'owned_nmap_lab', 'owned_web_lab'} and action.tool_id != 'http_probe':
        return False
    if config['profile'] == 'owned_web_lab':
        return (action.parameters.method == 'GET' and action.parameters.timeout_seconds == 1
                and action.parameters.max_output_bytes == 1024
                and action.parameters.path in {'/harbordesk/index.json', '/harbordesk/diagnostics.json'})
    if action.tool_id == 'tcp_connect':
        return action.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 1, 'max_output_bytes': 1024}
    if config['profile'] in {'owned_lab', 'owned_nmap_lab'}:
        return (action.parameters.method == 'GET' and action.parameters.timeout_seconds == 1
                and action.parameters.max_output_bytes == 1024
                and action.parameters.path in {f"/assessment/{config['case']}/index.json",
                                               f"/assessment/{config['case']}/diagnostics.json"})
    return action.tool_id == 'http_probe'


class AdmissionState:
    """Serial worker state; failed redemption burns before binding/expiry checks."""

    def __init__(self, init, *, clock=time.monotonic):
        self.config = initial(init, clock())
        self._policy = parse_policy(self.config['policy'])
        self._deadline = init['deadline']
        self._clock = clock
        self._sequence = 1
        self._steps = self._output = 0
        self._permits = {}

    def handle(self, value):
        action = request(value, self.config, self._sequence)
        self._sequence += 1
        now = self._clock()
        if now >= self._deadline:
            raise ValueError('admission_session_expired')
        permit, reason = None, None
        if value['operation'] == 'redeem':
            grant = self._permits.pop(value['permit'], None)
            if value['permit'] is None:
                reason = 'admission_missing'
            elif grant is None:
                reason = 'admission_unknown_or_replayed'
            elif now >= grant[2]:
                reason = 'admission_expired'
            elif action.digest != grant[0]:
                reason = 'admission_action_changed'
            elif value['policy_digest'] != grant[1]:
                reason = 'admission_policy_changed'
        elif not self.config['execute']:
            reason = 'admission_dry_run'
        elif value['policy_digest'] != self._policy.digest:
            reason = 'admission_policy_changed'
        elif self._policy.evaluate(action).decision == 'deny':
            reason = 'admission_policy_denied'
        elif not profile_allows(action, self.config):
            reason = 'admission_profile_denied'
        elif self._steps >= self.config['limits']['max_steps']:
            reason = 'admission_step_limit'
        elif self._output + action.parameters.max_output_bytes > self.config['limits']['max_output_bytes']:
            reason = 'admission_output_limit'
        else:
            self._steps += 1
            self._output += action.parameters.max_output_bytes
            permit = secrets.token_hex(32)
            self._permits[permit] = (action.digest, self._policy.digest, min(now + PERMIT_SECONDS, self._deadline))
        return {'permit': permit, 'reason': reason,
                'snapshot': {'executions_reserved': self._steps, 'output_bytes_reserved': self._output}}
