"""C1 adds two finite requests without changing accepted execution contracts."""
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
from test_secure_network_tools_contract import policy

CASES = ('redis-ok', 'snmp-ok')


@pytest.mark.parametrize('case', contract.C1_CASES)
def test_c1_single_fixed_action_requires_approval(case):
    selected = parse_action(contract.action(case))
    assert selected.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert selected.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert contract.profile_allows(selected, case)
    assert workflow.card_identity(case)['version'] == '9'
    assert set(workflow.card(case)['action_digests']) == set(contract.C1_CASES)
    assert policy(allowed_methods=[]).evaluate(selected).decision == 'approval_required'
    assert policy(allowed_ports=[]).evaluate(selected).reasons == ('port_not_allowed',)
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'key', 'database', 'oid', 'oids',
    'community', 'username', 'password', 'credentials', 'environment', 'config', 'url', 'walk', 'set',
    'cluster', 'redirect', 'protocol', 'retries'])
def test_c1_untrusted_proposal_cannot_select_operations_or_secrets(case, field):
    proposal = contract.action(case)
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('key,value', [('port', 6379), ('port', 161), ('timeout_seconds', 10), ('max_output_bytes', 16384)])
def test_c1_syntactic_bounds_do_not_expand_fixed_profile(case, key, value):
    proposal = contract.action(case)
    proposal['parameters'][key] = value
    assert not contract.profile_allows(parse_action(proposal), case)


def test_c1_shipped_policy_requires_fresh_approval_without_credentials():
    raw = json.loads(Path('examples/secure-agent-redis-snmp-policy.json').read_text())
    assert raw['allowed_tools'] == ['redis_server_info_v1', 'snmp_system_get_v1']
    assert raw['allowed_targets'] == ['127.0.0.1/32'] and raw['allowed_ports'] == [8080]
    assert raw['allowed_methods'] == [] and raw['approval_ttl_seconds'] == 60
    assert raw['require_approval'] is True
    for case in CASES:
        assert parse_policy(raw).evaluate(parse_action(contract.action(case))).decision == 'approval_required'


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1), (1, 2), (True, 1), (1, True)])
def test_complete_metadata_requires_exactly_one_connection_and_request(case, connections, requests):
    owned = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': owned,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, owned, tool_id=contract.action(case)['tool_id'], execution_status='succeeded')


def test_all_accepted_contract_bytes_are_unchanged():
    # Captured from pristine accepted main 7de63a4 before C1 development.
    old_cases = [case for case in contract.CASES if case not in contract.C1_CASES + contract.C2_CASES + contract.C3_CASES + contract.C4_CASES]
    old_tools = set(tool_adapters.ADAPTERS) - {contract.REDIS_TOOL_ID, contract.SNMP_TOOL_ID, contract.POSTGRESQL_TLS_TOOL_ID, contract.MYSQL_TLS_TOOL_ID, contract.WHATWEB_TOOL_ID, contract.DIG_SRV_TOOL_ID}
    old_runtime = set(runtime.EXECUTABLES) - {contract.REDIS_TOOL_ID, contract.SNMP_TOOL_ID, contract.POSTGRESQL_TLS_TOOL_ID, contract.MYSQL_TLS_TOOL_ID, contract.WHATWEB_TOOL_ID, contract.DIG_SRV_TOOL_ID}
    value = {'cases': {case: {'action': contract.action(case), 'descriptor': contract.capability_descriptor(case),
        'card': workflow.card(case), 'spec': lab.spec(case)} for case in old_cases},
        'adapters': {tool: tool_adapters.ADAPTERS[tool].to_dict() for tool in old_tools},
        'argv': {tool: runtime.FIXED_ARGV[tool] for tool in old_runtime},
        'environment': {tool: runtime.execution_environment(tool) for tool in old_runtime}}
    assert len(old_cases) == 84 and len(old_tools) == 23
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == '4dcfb2accd2c64e8fec01189ee61c2be00eb7081abf6596417f7695027293be2'
