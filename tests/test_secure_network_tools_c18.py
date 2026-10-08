"""C18 adds one fixed MX question without changing accepted profiles."""
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
    value = json.loads(Path('examples/secure-agent-dns-mx-policy.json').read_text())
    return parse_policy({**value, **overrides})


@pytest.mark.parametrize('case', contract.C18_CASES)
def test_fixed_dns_mx_action_requires_personal_approval_and_one_step(case):
    action = parse_action(contract.action(case))
    assert action.tool_id == contract.DIG_MX_TOOL_ID
    assert action.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert action.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert contract.profile_allows(action, case)
    assert policy().evaluate(action).decision == 'approval_required'
    assert policy(allowed_ports=[]).evaluate(action).reasons == ('port_not_allowed',)
    assert workflow.card_identity(case)['version'] == '26'
    assert set(workflow.card(case)['action_digests']) == set(contract.C18_CASES)
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'query', 'query_name',
    'query_type', 'resolver', 'transport', 'recursion', 'search', 'zone_transfer', 'retries',
    'target_hostname', 'followup', 'username', 'password', 'environment'])

def test_untrusted_proposal_cannot_select_code_destination_or_authentication(field):
    proposal = contract.action('dig-mx-ok')
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('change', [{'target': '127.0.0.2'}, {'port': 8081},
    {'timeout_seconds': 10}, {'max_output_bytes': 16384}])
def test_valid_syntax_cannot_change_fixed_execution_scope(change):
    proposal = contract.action('dig-mx-ok')
    if 'target' in change:
        proposal.update(change)
    else:
        proposal['parameters'].update(change)
    assert not contract.profile_allows(parse_action(proposal), 'dig-mx-ok')


@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1),
    (1, 2), (True, 1), (1, True)])
def test_useful_metadata_require_exactly_one_connection_and_validated_request(connections, requests):
    identity = lab.identity('dig-mx-ok', str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.DIG_MX_TOOL_ID,
                                        execution_status='succeeded')


@pytest.mark.parametrize('case', [c for c in contract.C18_CASES if c not in contract.DNS_MX_SUCCESS_CASES])
def test_failed_peer_scenario_cannot_be_upgraded_to_useful_metadata(case):
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.DIG_MX_TOOL_ID,
                                        execution_status='succeeded')



def test_all_accepted_case_adapter_and_runtime_bytes_remain_identical():
    # Captured from accepted main 993c83d before C18 changes; never regenerate.
    old_cases = [case for case in contract.CASES if case not in contract.C18_CASES]
    old_tools = set(tool_adapters.ADAPTERS) - {contract.DIG_MX_TOOL_ID}
    old_runtime = set(runtime.EXECUTABLES) - {contract.DIG_MX_TOOL_ID}
    assert (len(old_cases), len(old_tools), len(old_runtime)) == (303, 42, 33)
    value = {
        'adapters': {key: tool_adapters.ADAPTERS[key].to_dict() for key in old_tools},
        'cases': {case: {'action': contract.action(case), 'card': workflow.card(case),
            'descriptor': contract.capability_descriptor(case), 'spec': lab.spec(case)} for case in old_cases},
        'argv': {key: runtime.FIXED_ARGV[key] for key in old_runtime},
        'environment': {key: runtime.execution_environment(key) for key in old_runtime},
        'runtime': {key: [runtime.EXECUTABLES[key], runtime.FIXED_ARGV[key], runtime.execution_environment(key),
            [(source, dest, raw.hex()) for source, dest, raw in runtime.compiled_files(key)]] for key in old_runtime},
        'nuclei_manifests': {key: runtime.nuclei_runtime.for_tool(key).manifest()
            for key in (runtime.NUCLEI, runtime.NUCLEI_GIT)},
    }
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(raw).hexdigest() == '8f5c641c947914f1195b65b9e96491dc1b3cc91cf2ff3cd79f4257d4029c2048'
