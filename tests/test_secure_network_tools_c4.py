"""C4 adds one fixed DNS SRV query without broadening old profiles."""
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
    value = json.loads(Path('examples/secure-agent-dns-srv-policy.json').read_text())
    return parse_policy({**value, **overrides})


@pytest.mark.parametrize('case', contract.C4_CASES)
def test_fixed_dns_srv_action_requires_personal_approval_and_one_step(case):
    action = parse_action(contract.action(case))
    assert action.tool_id == contract.DIG_SRV_TOOL_ID
    assert action.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert action.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert contract.profile_allows(action, case)
    assert policy().evaluate(action).decision == 'approval_required'
    assert policy(allowed_ports=[]).evaluate(action).reasons == ('port_not_allowed',)
    assert workflow.card_identity(case)['version'] == '12'
    assert set(workflow.card(case)['action_digests']) == set(contract.C4_CASES)
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'query', 'query_name',
    'query_type', 'resolver', 'transport', 'recursion', 'search', 'zone_transfer', 'retries',
    'target_hostname', 'followup', 'username', 'password', 'environment'])

def test_untrusted_proposal_cannot_select_code_destination_or_authentication(field):
    proposal = contract.action('dig-srv-ok')
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('change', [{'target': '127.0.0.2'}, {'port': 8081},
    {'timeout_seconds': 10}, {'max_output_bytes': 16384}])
def test_valid_syntax_cannot_change_fixed_execution_scope(change):
    proposal = contract.action('dig-srv-ok')
    if 'target' in change:
        proposal.update(change)
    else:
        proposal['parameters'].update(change)
    assert not contract.profile_allows(parse_action(proposal), 'dig-srv-ok')


@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1),
    (1, 2), (True, 1), (1, True)])
def test_useful_metadata_require_exactly_one_connection_and_validated_request(connections, requests):
    identity = lab.identity('dig-srv-ok', str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.DIG_SRV_TOOL_ID,
                                        execution_status='succeeded')


@pytest.mark.parametrize('case', [c for c in contract.C4_CASES if c not in contract.DNS_SRV_SUCCESS_CASES])
def test_failed_peer_scenario_cannot_be_upgraded_to_useful_metadata(case):
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.DIG_SRV_TOOL_ID,
                                        execution_status='succeeded')


def test_all_accepted_contracts_remain_unchanged_from_pr57():
    old_cases = [case for case in contract.CASES if case not in contract.C4_CASES + contract.C5_CASES + contract.C6_CASES + contract.C7_CASES + contract.C8_CASES + contract.C9_CASES + contract.C10_CASES + contract.C11_CASES + contract.C12_CASES + contract.C13_CASES + contract.C14_CASES + contract.C15_CASES + contract.C16_CASES + contract.C17_CASES + contract.C18_CASES + contract.T02_CASES + contract.T03_CASES]
    old_tools = set(tool_adapters.ADAPTERS) - (set(contract.tls_posture.TOOL_VERSIONS) | {contract.SSH_POLICY_TOOL_ID}) - {contract.DIG_SRV_TOOL_ID, contract.RDP_TOOL_ID, contract.SMB2_TOOL_ID, contract.SMTP_TLS_TOOL_ID, contract.LDAP_TLS_TOOL_ID, contract.FTP_TLS_TOOL_ID, contract.DIG_NSID_TOOL_ID, contract.DIG_AXFR_TOOL_ID, contract.HTTP_OPTIONS_TOOL_ID, contract.SNMP_NEXT_TOOL_ID, contract.SSH_ALGORITHMS_TOOL_ID, contract.TLS_CERTIFICATE_TOOL_ID, contract.NUCLEI_TOOL_ID, contract.NUCLEI_GIT_TOOL_ID, contract.DIG_MX_TOOL_ID}
    old_runtime = set(runtime.EXECUTABLES) - {contract.SSH_POLICY_TOOL_ID} - {contract.DIG_SRV_TOOL_ID, contract.RDP_TOOL_ID, contract.SMB2_TOOL_ID, contract.SMTP_TLS_TOOL_ID, contract.LDAP_TLS_TOOL_ID, contract.FTP_TLS_TOOL_ID, contract.DIG_NSID_TOOL_ID, contract.DIG_AXFR_TOOL_ID, contract.HTTP_OPTIONS_TOOL_ID, contract.SNMP_NEXT_TOOL_ID, contract.SSH_ALGORITHMS_TOOL_ID, contract.TLS_CERTIFICATE_TOOL_ID, contract.NUCLEI_TOOL_ID, contract.NUCLEI_GIT_TOOL_ID, contract.DIG_MX_TOOL_ID}
    value = {'cases': {case: {'action': contract.action(case), 'descriptor': contract.capability_descriptor(case),
        'card': workflow.card(case), 'spec': lab.spec(case)} for case in old_cases},
        'adapters': {tool: tool_adapters.ADAPTERS[tool].to_dict() for tool in old_tools},
        'argv': {tool: runtime.FIXED_ARGV[tool] for tool in old_runtime},
        'environment': {tool: runtime.execution_environment(tool) for tool in old_runtime}}
    assert len(old_cases) == 123 and len(old_tools) == 28 and len(old_runtime) == 19
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == '0e3f2b8c674556dfd010e5d1095d347d686c5db1e29cbac2ce02607f53665a28'
