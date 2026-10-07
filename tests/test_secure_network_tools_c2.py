"""Database pre-auth TLS adds no login, SQL, credentials or old-contract changes."""
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

CASES = ('postgresql-tls-ok', 'mysql-tls-ok')


@pytest.mark.parametrize('case', contract.C2_CASES)
def test_c2_single_fixed_profile_crosses_approval_gate(case):
    selected = parse_action(contract.action(case))
    assert selected.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert selected.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert contract.profile_allows(selected, case)
    assert workflow.card_identity(case)['version'] == '10'
    assert set(workflow.card(case)['action_digests']) == set(contract.C2_CASES)
    assert policy(allowed_methods=[]).evaluate(selected).decision == 'approval_required'
    assert policy(allowed_ports=[]).evaluate(selected).reasons == ('port_not_allowed',)
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'sql', 'database', 'user',
    'password', 'sslmode', 'sslcert', 'sslkey', 'sslrootcert', 'service', 'auth_plugin',
    'environment', 'config', 'url', 'starttls', 'tls_name', 'ca_file'])
def test_proposal_cannot_select_credentials_operations_or_trust(case, field):
    proposal = contract.action(case)
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('key,value', [('port', 5432), ('port', 3306), ('timeout_seconds', 10), ('max_output_bytes', 16384)])
def test_syntax_does_not_broaden_the_reviewed_database_profile(case, key, value):
    proposal = contract.action(case)
    proposal['parameters'][key] = value
    assert not contract.profile_allows(parse_action(proposal), case)


def test_shipped_policy_keeps_scope_and_fresh_approval():
    raw = json.loads(Path('examples/secure-agent-database-tls-policy.json').read_text())
    assert raw['allowed_tools'] == ['postgresql_tls_handshake_v1', 'mysql_tls_handshake_v1']
    assert raw['allowed_targets'] == ['127.0.0.1/32'] and raw['allowed_ports'] == [8080]
    assert raw['allowed_methods'] == [] and raw['approval_ttl_seconds'] == 60
    assert raw['require_approval'] is True
    for case in CASES:
        assert parse_policy(raw).evaluate(parse_action(contract.action(case))).decision == 'approval_required'


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1), (1, 2), (True, 1), (1, True)])
def test_success_needs_one_complete_handshake_and_connection(case, connections, requests):
    owned = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': owned,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, owned, tool_id=contract.action(case)['tool_id'], execution_status='succeeded')


@pytest.mark.parametrize('case', [c for c in contract.C2_CASES if c not in contract.DATABASE_TLS_SUCCESS_CASES])
def test_refused_or_incomplete_fixture_cannot_claim_complete_protocol(case):
    owned = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': owned,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': None}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, owned, tool_id=contract.action(case)['tool_id'], execution_status='failed')


def test_all_accepted_contracts_are_unchanged_from_pr55():
    old_cases = [case for case in contract.CASES if case not in contract.C2_CASES + contract.C3_CASES + contract.C4_CASES + contract.C5_CASES]
    new_tools = {contract.POSTGRESQL_TLS_TOOL_ID, contract.MYSQL_TLS_TOOL_ID, contract.WHATWEB_TOOL_ID, contract.DIG_SRV_TOOL_ID, contract.RDP_TOOL_ID}
    old_tools = set(tool_adapters.ADAPTERS) - new_tools
    old_runtime = set(runtime.EXECUTABLES) - new_tools
    value = {'cases': {case: {'action': contract.action(case), 'descriptor': contract.capability_descriptor(case),
        'card': workflow.card(case), 'spec': lab.spec(case)} for case in old_cases},
        'adapters': {tool: tool_adapters.ADAPTERS[tool].to_dict() for tool in old_tools},
        'argv': {tool: runtime.FIXED_ARGV[tool] for tool in old_runtime},
        'environment': {tool: runtime.execution_environment(tool) for tool in old_runtime}}
    assert len(old_cases) == 100 and len(old_tools) == 25
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == 'f51026c33878afe7d6bb119a300046a15c4baff1c72489e3bc1d588d7bea1e9f'
