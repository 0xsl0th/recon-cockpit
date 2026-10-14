"""T05 adds one finite GETBULK page without changing accepted authority."""

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_lab_contract as lab
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import tool_catalog
from recon_cockpit.secure_agent.models import ValidationError, parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend


def policy(**overrides):
    value = json.loads(Path('examples/secure-agent-snmp-page-policy.json').read_text())
    return parse_policy({**value, **overrides})


@pytest.mark.parametrize('case', fixture.SNMP_PAGE_CASES)
def test_fixed_page_requires_approval_and_cannot_continue(case):
    selected = parse_action(contract.action(case))
    assert selected.tool_id == fixture.SNMP_PAGE_TOOL_ID == 'snmp_interface_page_v1'
    assert selected.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert selected.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert contract.profile_allows(selected, case)
    assert policy().evaluate(selected).decision == 'approval_required'
    assert policy(allowed_methods=[]).evaluate(selected).decision == 'approval_required'
    assert policy(allowed_ports=[]).evaluate(selected).reasons == ('port_not_allowed',)
    card = workflow.card(case)
    assert set(card['action_digests']) == set(fixture.SNMP_PAGE_CASES)
    assert workflow.card_identity(case)['version'] == '30'
    assert contract.capability_descriptor(case)['limits'] == {
        'max_steps': 1, 'max_runtime_seconds': 60, 'max_output_bytes': 8192}
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'oid', 'oids', 'seed_oid',
    'community', 'version', 'transport', 'walk', 'getbulk', 'set', 'udp', 'retries', 'followup',
    'non_repeaters', 'max_repetitions', 'page_size', 'cursor', 'continuation',
    'username', 'password', 'environment', 'credentials', 'authentication', 'mibs'])
def test_untrusted_proposal_cannot_choose_page_bounds_or_secrets(field):
    proposal = contract.action('snmp-page-ok')
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('change', [{'target': '127.0.0.2'}, {'port': 8081},
    {'timeout_seconds': 10}, {'max_output_bytes': 16384}])
def test_valid_syntax_cannot_change_fixed_execution_scope(change):
    proposal = contract.action('snmp-page-ok')
    if 'target' in change:
        proposal.update(change)
    else:
        proposal['parameters'].update(change)
    assert not contract.profile_allows(parse_action(proposal), 'snmp-page-ok')


@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1),
    (1, 2), (True, 1), (1, True)])
def test_useful_page_requires_one_validated_bulk_request(connections, requests):
    identity = lab.identity('snmp-page-ok', str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=fixture.SNMP_PAGE_TOOL_ID,
                                         execution_status='succeeded')


@pytest.mark.parametrize('case', [case for case in fixture.SNMP_PAGE_CASES
                                 if case not in fixture.SNMP_PAGE_SUCCESS_CASES])
def test_partial_or_malformed_peer_cannot_be_promoted_to_useful_page(case):
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=fixture.SNMP_PAGE_TOOL_ID,
                                         execution_status='succeeded')


def test_previous_49_capabilities_and_355_case_contracts_remain_identical():
    catalog = tool_catalog.list_tools()
    catalog['tools'] = [row for row in catalog['tools'] if row['tool_id'] not in (fixture.SNMP_PAGE_TOOL_ID, *fixture.DNS_ADDRESS_TOOL_IDS)]
    catalog.update(capability_count=49, accepted_capability_count=49,
                   candidate_capability_count=0, external_program_count=16)
    tools = [row['tool_id'] for row in catalog['tools']]
    cases = [case for case in contract.CASES if case not in fixture.SNMP_PAGE_CASES + fixture.DNS_ADDRESS_CASES]
    assert len(tools) == 49 and len(cases) == 355
    value = {'catalog': catalog,
        'descriptions': {tool: tool_catalog.describe_tool(tool) for tool in tools},
        'network': {case: {'descriptor': contract.capability_descriptor(case),
            'card': workflow.card_identity(case), 'action': contract.action(case),
            'spec': lab.spec(case)} for case in cases}}
    # Accepted main435a271, after recording T04 acceptance and before adding T05.
    assert hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() == (
        '75cc9ea04faf751b13c23888188e5d46e90725ce0c8e36b89d2ca4d358551eef')


def test_previous_36_runtime_invocations_and_environment_remain_identical():
    value = {tool: [runtime.EXECUTABLES[tool], runtime.FIXED_ARGV[tool],
        runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool in runtime.EXECUTABLES if tool not in (fixture.SNMP_PAGE_TOOL_ID, *fixture.DNS_ADDRESS_TOOL_IDS)}
    assert len(value) == 36
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == 'be7476bfdce3b9f36cd30d9b0c6465fa58360f3aa16a9e904fe9ce7e98908ceb'


def test_pure_client_identity_matches_every_owned_fixture_response():
    from recon_cockpit.secure_agent import network_tools_snmp_page_identity as identity
    from recon_cockpit.secure_agent import network_tools_snmp_page_fixture as owner_fixture
    canonical = owner_fixture.request(b'\x01')
    assert identity.CANONICAL_REQUEST == canonical
    assert identity.CANONICAL_REQUEST_BYTES == len(canonical)
    assert identity.CANONICAL_REQUEST_SHA256 == hashlib.sha256(canonical).hexdigest()
    assert set(identity.CANONICAL_RESPONSE_SHA256) == set(fixture.SNMP_PAGE_CASES)
    for case in fixture.SNMP_PAGE_CASES:
        response = owner_fixture.response(case, b'\x01')
        expected = None if response is None else hashlib.sha256(response).hexdigest()
        assert identity.CANONICAL_RESPONSE_SHA256[case] == expected
        definition = lab.spec(case)
        assert definition['canonical_request_sha256'] == identity.CANONICAL_REQUEST_SHA256
        assert definition['canonical_request_bytes'] == identity.CANONICAL_REQUEST_BYTES
        assert definition['canonical_response_sha256'] == expected
    with pytest.raises(TypeError):
        identity.CANONICAL_RESPONSE_SHA256['snmp-page-ok'] = '0' * 64


def test_descriptor_keeps_received_rows_from_becoming_authority():
    descriptor = contract.capability_descriptor('snmp-page-ok')
    assert descriptor['result_semantics'] == 'untrusted_snmp_interface_page_metadata'
    request = descriptor['snmp_page']
    assert request['operation'] == 'GetBulkRequest'
    assert request['seed_oid'] == '.1.3.6.1.2.1.2.2.1.2'
    assert request['non_repeaters'] == 0 and request['max_repetitions'] == 4
    assert request['max_connections'] == request['max_requests'] == 1
    assert request['max_bindings'] == 4
    assert request['community_is_public_synthetic_data'] is True
    for field in ('walk', 'paging_continuation', 'set', 'udp', 'retries', 'correction_resubmission',
                  'real_credentials', 'mib_imports', 'response_directed_followup',
                  'service_identity_verified', 'interface_inventory_complete'):
        assert request[field] is False
