"""Reviewed singleton Nmap-to-HTTP profile; descriptors never grant authority."""
from copy import deepcopy
import hashlib
import json
from uuid import NAMESPACE_URL, uuid5

from .assessment_contract import CASES, assessment_action
from .models import parse_action
from .tool_adapters import NMAP_SESSION_LIMITS
from .owned_lab_contract import validate_context, validate_identity, validate_closure

TOOL_ID = 'nmap_tcp_connect_v1'
PROFILE = 'owned_nmap_lab'
BACKEND = 'linux-authorized-owned-nmap-lab-executor-v1'
WORKFLOW = 'owned-nmap-http-assessment-v1'
PARSER_VERSION = 'nmap-tcp-connect-xml-v1'
PARAMETERS = {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 16384}
LIMITS = dict(NMAP_SESSION_LIMITS)


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def action(case, step):
    if type(case) is not str or case not in CASES or type(step) is not int or step not in (1, 2, 3):
        raise ValueError('invalid_nmap_workflow_step')
    if step != 1:
        return assessment_action(case, step - 1)
    return parse_action({'schema_version': '1',
        'action_id': str(uuid5(NAMESPACE_URL, WORKFLOW + ':' + case + ':1')),
        'tool_id': TOOL_ID, 'target': '127.0.0.1', 'parameters': dict(PARAMETERS),
        'rationale': 'DETERMINISTIC OWNED LAB: bounded Nmap TCP-connect discovery.'}).to_dict()


def profile_allows(value, case):
    if type(case) is not str or case not in CASES or value.targets != ('127.0.0.1',):
        return False
    if value.tool_id == TOOL_ID:
        return value.parameters.to_dict() == PARAMETERS
    return value.tool_id == 'http_probe' and any(
        value.parameters.to_dict() == action(case, step)['parameters'] for step in (2, 3))


def capability_descriptor():
    from .tool_adapters import get_adapter
    return {'schema_version': '1', 'workflow_id': WORKFLOW,
        'capabilities': [get_adapter(tool).to_dict() for tool in (TOOL_ID, 'http_probe')],
        'scope': {'target': '127.0.0.1', 'port': 8080, 'owned_lab_only': True},
        'limits': dict(LIMITS), 'live_calls_enabled': False}


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    """Accepted connections are lower bounds; HTTP request progression is exact."""
    expected = validate_identity(expected)
    if type(result) is not dict or result.get('backend') != BACKEND:
        raise ValueError('invalid_nmap_lab_result')
    context = validate_context(result.get('owned_lab'), expected)
    before = {'connection_count': 0, 'request_count': 0} if previous is None else validate_context(previous, expected)
    connections = context['connection_count'] - before['connection_count']
    requests = context['request_count'] - before['request_count']
    if connections < 0 or requests < 0 or tool_id not in {TOOL_ID, 'http_probe'}:
        raise ValueError('nmap_lab_continuity_mismatch')
    if tool_id == TOOL_ID and requests != 0:
        raise ValueError('nmap_sent_application_request')
    if tool_id == 'http_probe' and (requests > 1 or (execution_status == 'succeeded' and requests != 1)):
        raise ValueError('nmap_http_continuity_mismatch')
    return context


def parse_observation(value, result, *, execution_status):
    if type(result) is not dict:
        raise ValueError('invalid_nmap_result')
    parsed = parse_action({**value, 'rationale': value.get('rationale', '')})
    if parsed.tool_id == 'http_probe':
        from .assessment_contract import parse_observation as http_observation
        # The new profile validates its own outer identity before using the
        # unchanged HTTP body parser. Do not mislabel its backend as a legacy one.
        core = {k: v for k, v in result.items() if k not in {'owned_lab', 'backend'}}
        return http_observation(value, core, execution_status=execution_status)
    observation = {'parser_version': PARSER_VERSION, 'kind': 'nmap_discovery',
        'classification': 'inconclusive', 'reason': 'nmap_evidence_incomplete', 'followup_path': None}
    if (parsed.tool_id != TOOL_ID or parsed.target != '127.0.0.1'
            or parsed.parameters.to_dict() != PARAMETERS):
        raise ValueError('invalid_nmap_action')
    if execution_status != 'succeeded' or result.get('status') != 'succeeded' or result.get('truncated') is not False:
        return observation
    rows = result.get('results')
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict or set(rows[0]) != {'target', 'port', 'state'}:
        return observation
    row = rows[0]
    if row.get('target') != '127.0.0.1' or type(row.get('port')) is not int or row['port'] != 8080:
        return observation
    if row.get('state') == 'open':
        observation.update(classification='reachable', reason='nmap_tcp_port_reachable')
    elif row.get('state') in {'closed', 'filtered'}:
        observation['reason'] = 'nmap_tcp_port_not_reachable'
    return observation
