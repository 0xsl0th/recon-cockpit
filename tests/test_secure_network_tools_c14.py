"""C14 adds one bounded SSH advertisement exchange without broadening old profiles."""
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_lab_contract as lab
from recon_cockpit.secure_agent import tool_adapters
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.models import ValidationError, parse_action, parse_policy


def policy(**overrides):
    value = json.loads(Path('examples/secure-agent-ssh-algorithms-policy.json').read_text())
    return parse_policy({**value, **overrides})


@pytest.mark.parametrize('case', contract.C14_CASES)
def test_fixed_ssh_algorithms_action_requires_personal_approval_and_one_step(case):
    action = parse_action(contract.action(case))
    assert action.tool_id == contract.SSH_ALGORITHMS_TOOL_ID
    assert action.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert action.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert contract.profile_allows(action, case)
    assert policy().evaluate(action).decision == 'approval_required'
    assert policy(allowed_methods=[]).evaluate(action).decision == 'approval_required'
    assert policy(allowed_ports=[]).evaluate(action).reasons == ('port_not_allowed',)
    assert workflow.card_identity(case)['version'] == '22'
    assert set(workflow.card(case)['action_digests']) == set(contract.C14_CASES)
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'banner', 'cookie', 'algorithms',
    'known_hosts', 'version', 'transport', 'script', 'nse', 'kex', 'udp', 'retries', 'followup',
    'username', 'password', 'environment', 'credentials', 'authentication', 'mibs'])
def test_untrusted_proposal_cannot_select_code_destination_or_authentication(field):
    proposal = contract.action('ssh-algos-ok')
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('change', [{'target': '127.0.0.2'}, {'port': 8081},
    {'timeout_seconds': 10}, {'max_output_bytes': 16384}])
def test_valid_syntax_cannot_change_fixed_execution_scope(change):
    proposal = contract.action('ssh-algos-ok')
    if 'target' in change:
        proposal.update(change)
    else:
        proposal['parameters'].update(change)
    assert not contract.profile_allows(parse_action(proposal), 'ssh-algos-ok')


@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1),
    (1, 2), (True, 1), (1, True)])
def test_useful_metadata_require_exactly_one_connection_and_validated_request(connections, requests):
    identity = lab.identity('ssh-algos-ok', str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.SSH_ALGORITHMS_TOOL_ID,
                                        execution_status='succeeded')


@pytest.mark.parametrize('case', [c for c in contract.C14_CASES if c not in contract.SSH_ALGORITHMS_SUCCESS_CASES])
def test_failed_peer_scenario_cannot_be_upgraded_to_useful_metadata(case):
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.SSH_ALGORITHMS_TOOL_ID,
                                        execution_status='succeeded')


def test_all_accepted_contracts_remain_unchanged_from_pr67():
    old_cases = [case for case in contract.CASES if case not in contract.C14_CASES + contract.C15_CASES + contract.C16_CASES + contract.C17_CASES]
    old_tools = set(tool_adapters.ADAPTERS) - {contract.SSH_ALGORITHMS_TOOL_ID, contract.TLS_CERTIFICATE_TOOL_ID, contract.NUCLEI_TOOL_ID, contract.NUCLEI_GIT_TOOL_ID}
    old_runtime = set(runtime.EXECUTABLES) - {contract.SSH_ALGORITHMS_TOOL_ID, contract.TLS_CERTIFICATE_TOOL_ID, contract.NUCLEI_TOOL_ID, contract.NUCLEI_GIT_TOOL_ID}
    value = {'cases': {case: {'action': contract.action(case), 'descriptor': contract.capability_descriptor(case),
        'card': workflow.card(case), 'spec': lab.spec(case)} for case in old_cases},
        'adapters': {tool: tool_adapters.ADAPTERS[tool].to_dict() for tool in old_tools},
        'argv': {tool: runtime.FIXED_ARGV[tool] for tool in old_runtime},
        'environment': {tool: runtime.execution_environment(tool) for tool in old_runtime}}
    assert len(old_cases) == 251 and len(old_tools) == 38 and len(old_runtime) == 29
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == 'a993b33f2602a734f897eedbc9cd5f81883d963aaa840bbaf12335cd85a3fb7a'



def test_descriptor_keeps_advertisements_from_becoming_authority():
    descriptor = contract.capability_descriptor('ssh-algos-ok')
    assert descriptor['result_semantics'] == 'untrusted_ssh_algorithm_advertisements'
    request = descriptor['ssh_algorithms']
    assert request['protocol'] == '2.0' and request['random_cookie_bytes'] == 16
    assert request['max_connections'] == request['max_requests'] == 1
    assert request['client_write_half_close_before_response'] is True
    for field in ('key_exchange_completion', 'authentication', 'session', 'credentials',
            'known_hosts', 'nse', 'udp', 'retries', 'response_directed_followup', 'service_identity_verified'):
        assert request[field] is False
