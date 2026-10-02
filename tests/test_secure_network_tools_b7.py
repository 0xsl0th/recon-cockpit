"""Finite Nmap service observations cannot expand action or network authority."""

import copy
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent.models import ValidationError, parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from test_secure_network_tools_contract import policy


@pytest.mark.parametrize('case', contract.B7_CASES)
def test_b7_requires_one_fixed_action_and_separate_card(case):
    action = parse_action(contract.action(case))
    assert action.tool_id == 'nmap_service_identify_v1'
    assert contract.profile_allows(action, case)
    assert action.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert workflow.card_identity(case)['version'] == '7'
    assert set(workflow.card(case)['action_digests']) == set(contract.B7_CASES)
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'probe_file', 'scripts', 'script', 'version_intensity', 'ports',
    'hostname', 'url', 'method', 'headers', 'credentials', 'username', 'password', 'tls', 'rpc', 'command'])
def test_b7_caller_cannot_change_probe_program(field):
    action = contract.action('nmap-service-http')
    action['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(action)


@pytest.mark.parametrize('field,value', [('port', 22), ('port', 8081), ('timeout_seconds', 10), ('max_output_bytes', 16384)])
def test_b7_syntax_does_not_expand_reviewed_profile(field, value):
    action = contract.action('nmap-service-http')
    action['parameters'][field] = value
    assert not contract.profile_allows(parse_action(action), 'nmap-service-http')


@pytest.mark.parametrize('case', contract.B7_CASES)
@pytest.mark.parametrize('methods', [[], ['HEAD']])
def test_b7_fixed_get_probe_needs_explicit_method_permission(case, methods):
    action = parse_action(contract.action(case))
    assert policy(allowed_methods=methods).evaluate(action).reasons == ('method_not_allowed',)
    assert policy().evaluate(action).decision == 'approval_required'


def test_b7_shipped_policy_is_owned_single_endpoint_and_fresh_approval():
    raw = json.loads(Path('examples/secure-agent-nmap-service-policy.json').read_text())
    assert raw['allowed_tools'] == ['nmap_service_identify_v1']
    assert raw['allowed_targets'] == ['127.0.0.1/32'] and raw['allowed_ports'] == [8080]
    assert raw['allowed_methods'] == ['GET']
    assert raw['require_approval'] is True and raw['approval_ttl_seconds'] == 60
    assert parse_policy(raw).evaluate(parse_action(contract.action('nmap-service-http'))).decision == 'approval_required'


@pytest.mark.parametrize('identified', [True, False])
def test_b7_complete_observation_has_no_followup_authority(identified):
    value = {'parser_version': 'nmap-service-xml-v1', 'kind': 'service_identification',
        'target': '127.0.0.1', 'port': 8080, 'state': 'open',
        'identification': 'identified' if identified else 'unidentified',
        'service': {'name': 'http', 'product': 'nginx', 'version': '1.26.0'} if identified else None}
    result = contract.classify_tool(contract.NMAP_SERVICE_TOOL_ID, value)
    assert result['reason'] == ('nmap_service_identified' if identified else 'nmap_service_unidentified')
    assert result['followup_path'] is None
    if identified:
        value['service']['version'] = '9.9'
        assert result['details']['service']['version'] == '1.26.0'


@pytest.mark.parametrize('connections,requests', [(0, 1), (1, 1), (2, 0), (3, 0), (4, 1), (2, 2)])
def test_b7_useful_receipt_requires_scan_and_completed_probe_counters(connections, requests):
    lab = identity('nmap-service-http', str(uuid4()))
    result = {'backend': contract.BACKEND,
        'owned_lab': {'identity': lab, 'connection_count': connections, 'request_count': requests},
        'tool_observation': {'present': True}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, lab, tool_id=contract.NMAP_SERVICE_TOOL_ID, execution_status='succeeded')


def test_b7_does_not_change_accepted_nmap_tcp_only_descriptor_or_card():
    from recon_cockpit.secure_agent import nmap_runtime
    from recon_cockpit.secure_agent.tool_adapters import NMAP_TOOL_ID, get_adapter
    assert NMAP_TOOL_ID == 'nmap_tcp_connect_v1'
    assert '-sV' not in nmap_runtime.FIXED_ARGV
    assert get_adapter(NMAP_TOOL_ID).to_dict()['parser_version'] == 'nmap-tcp-connect-xml-v1'
