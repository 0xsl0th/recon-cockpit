"""Independent one-launch validation for the dedicated owned Nmap worker."""
import hashlib
import hmac
import math
import re
from uuid import UUID

from .executor_worker import LAUNCH_FIELDS, encode, digest
from .models import load_json, parse_action, parse_policy
from .nmap_contract import LIMITS, PARAMETERS, TOOL_ID, profile_allows
from .owned_lab_contract import validate_identity

MAX_LAUNCH_BYTES = 65536


def consume_launch(raw, nonce, context_digest, *, now=None):
    import time
    if (type(raw) is not bytes or len(raw) > MAX_LAUNCH_BYTES
            or type(nonce) is not str or re.fullmatch('[a-f0-9]{64}', nonce) is None
            or type(context_digest) is not str or re.fullmatch('[a-f0-9]{64}', context_digest) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError('nmap_launch_commitment_mismatch')
    # The runtime manifest may exceed the legacy action message byte bound;
    # duplicate keys and all nested action/policy fields remain strictly checked.
    from .models import _object_pairs
    import json
    def constant(_):
        raise ValueError('invalid_nmap_constant')
    value = json.loads(raw.decode('ascii'), object_pairs_hook=_object_pairs, parse_constant=constant)
    if type(value) is not dict or set(value) != {'mode', 'launch', 'identity', 'namespaces', 'runtime'} or value['mode'] != 'owned_nmap_lab':
        raise ValueError('invalid_nmap_launch')
    identity = validate_identity(value['identity'])
    launch = value['launch']
    if (type(launch) is not dict or set(launch) != LAUNCH_FIELDS
            or launch['schema_version'] != '1' or launch['mode'] != 'nmap_owned'
            or launch['execute'] is not True or launch['nonce'] != nonce
            or type(launch['session_id']) is not str or str(UUID(launch['session_id'])) != launch['session_id']):
        raise ValueError('invalid_nmap_authority')
    limits = launch['limits']
    ceilings = LIMITS
    if (type(limits) is not dict or set(limits) != set(ceilings)
            or any(type(limits[k]) is not int or not 1 <= limits[k] <= cap for k, cap in ceilings.items())
            or digest(limits) != launch['limits_digest']):
        raise ValueError('invalid_nmap_limits')
    sequence = launch['sequence']
    deadline = launch['deadline']
    now = time.monotonic() if now is None else now
    if (type(sequence) is not int or not 1 <= sequence <= limits['max_steps']
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - now <= limits['max_runtime_seconds']):
        raise ValueError('nmap_expired_or_exhausted')
    action = parse_action(launch['action'])
    policy = parse_policy(launch['policy'])
    if (action.tool_id != TOOL_ID or not profile_allows(action, identity['scenario'])
            or action.to_dict() != launch['action'] or policy.to_dict() != launch['policy']
            or action.digest != launch['action_digest'] or policy.digest != launch['policy_digest']
            or policy.evaluate(action).decision == 'deny'):
        raise ValueError('nmap_action_or_policy_denied')
    before, after = launch['output_reserved_before'], launch['output_reserved_after']
    if (type(before) is not int or type(after) is not int
            or not 0 <= before < after <= limits['max_output_bytes']
            or after - before != PARAMETERS['max_output_bytes']
            or (sequence == 1 and before != 0) or (sequence > 1 and before < sequence - 1)):
        raise ValueError('nmap_output_reservation_mismatch')
    host, lab = launch['host_namespaces'], value['namespaces']
    for namespaces in (host, lab):
        if (type(namespaces) is not dict or set(namespaces) != {'user', 'net', 'mnt', 'pid'}
                or any(type(v) is not str or re.fullmatch(k + r':\[\d+\]', v) is None for k, v in namespaces.items())):
            raise ValueError('invalid_nmap_namespaces')
    if any(host[k] == lab[k] for k in host):
        raise ValueError('nmap_namespaces_not_private')
    runtime = value['runtime']
    if type(runtime) is not dict:
        raise ValueError('invalid_nmap_runtime_manifest')
    request = {'target': action.target, 'parameters': action.parameters.to_dict(),
        'tool_id': TOOL_ID, 'host_namespaces': host, 'verify_boundary': True}
    return request, deadline, lab, hashlib.sha256(encode(runtime)).hexdigest()
