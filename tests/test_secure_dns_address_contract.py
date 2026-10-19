"""Two finite DNS questions cannot expand target or record authority."""

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_dns_address_spec as spec
from recon_cockpit.secure_agent import network_tools_lab_contract as lab
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import tool_catalog
from recon_cockpit.secure_agent.models import ValidationError, parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend


def policy(tool, **overrides):
    value = json.loads(Path('examples/secure-agent-dns-' + spec.QUERY_TYPES[tool].lower() + '-policy.json').read_text())
    return parse_policy({**value, **overrides})


@pytest.mark.parametrize('case', spec.CASES)
def test_one_explicit_question_requires_approval_and_no_followup(case):
    selected = parse_action(contract.action(case))
    tool = spec.tool_for_case(case)
    assert selected.tool_id == tool and tool in AuthorizedNetworkToolsBackend.supported_tools
    assert selected.parameters.to_dict() == dict(spec.PARAMETERS)
    assert contract.profile_allows(selected, case)
    assert policy(tool).evaluate(selected).decision == 'approval_required'
    assert policy(tool, allowed_ports=[]).evaluate(selected).reasons == ('port_not_allowed',)
    other = next(candidate for candidate in spec.TOOL_IDS if candidate != tool)
    assert policy(other).evaluate(selected).reasons == ('tool_not_allowed',)
    assert set(workflow.card(case)['action_digests']) == set(spec.CASES)
    assert workflow.card_identity(case)['version'] == '31'
    assert contract.capability_descriptor(case)['limits'] == dict(spec.LIMITS)
    with pytest.raises(ValueError): contract.action(case, 2)


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'name', 'question', 'type',
    'query_name', 'query_type', 'server', 'resolver', 'reverse', 'address', 'family', 'protocol',
    'transport', 'recursion', 'retries', 'followup', 'search', 'tsig', 'username', 'password',
    'environment', 'credentials', 'config', 'zone_transfer', 'edns', 'cookie', 'output_path'])
def test_proposal_cannot_choose_question_resolver_credentials_or_operation(tool, field):
    proposal = contract.action(spec.PREFIXES[tool] + 'ok')
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError): parse_action(proposal)


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('change', [{'target': '127.0.0.2'}, {'port': 8081},
    {'timeout_seconds': 10}, {'max_output_bytes': 16384}])
def test_valid_syntax_cannot_change_compiled_execution_bounds(tool, change):
    case = spec.PREFIXES[tool] + 'ok'
    proposal = contract.action(case)
    if 'target' in change: proposal.update(change)
    else: proposal['parameters'].update(change)
    assert not contract.profile_allows(parse_action(proposal), case)


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1),
    (1, 2), (True, 1), (1, True)])
def test_usefulness_requires_one_validated_fixed_question(tool, connections, requests):
    identity = lab.identity(spec.PREFIXES[tool] + 'ok', str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=tool, execution_status='succeeded')


@pytest.mark.parametrize('case', spec.NEGATIVE_CASES)
def test_malformed_or_unsupported_metadata_cannot_be_promoted_to_useful_result(case):
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=spec.tool_for_case(case), execution_status='succeeded')


def test_previous_50_capabilities_and_375_cases_remain_identical():
    catalog = tool_catalog.list_tools()
    catalog['tools'] = [row for row in catalog['tools'] if row['tool_id'] not in (*spec.TOOL_IDS,
        'owned_name_dns_v1', 'owned_name_http_v1', 'owned_name_tls_v1')]
    catalog.update(capability_count=50, accepted_capability_count=50,
                   candidate_capability_count=0, external_program_count=17)
    tools = [row['tool_id'] for row in catalog['tools']]
    cases = [case for case in contract.CASES if case not in spec.CASES]
    assert len(tools) == 50 and len(cases) == 375
    value = {'catalog': catalog,
        'descriptions': {tool: tool_catalog.describe_tool(tool) for tool in tools},
        'network': {case: {'descriptor': contract.capability_descriptor(case),
            'card': workflow.card_identity(case), 'action': contract.action(case),
            'spec': lab.spec(case)} for case in cases}}
    assert hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() == (
        '1d1fd89b134fbab628632c4887c407f44d51402dc671417f3c7590018bd54f8b')


def test_previous_37_native_invocations_and_environments_remain_identical():
    value = {tool: [runtime.EXECUTABLES[tool], runtime.FIXED_ARGV[tool],
        runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool in runtime.EXECUTABLES if tool not in spec.TOOL_IDS}
    assert len(value) == 37
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == '24db9135c980d6460cec89afb3e20664620517db87a6551d6f2f458e8d5a69a5'


def test_compiled_client_identity_matches_every_owned_response():
    from recon_cockpit.secure_agent import network_tools_dns_address_identity as identity
    from recon_cockpit.secure_agent import network_tools_dns_address_fixture as fixture
    assert set(identity.RESPONSE_SHA256_BY_CASE) == set(spec.CASES)
    for tool in spec.TOOL_IDS:
        query = fixture.query(tool)
        assert identity.CANONICAL_QUERIES_BY_TOOL[tool] == query
        assert identity.QUERY_BYTES_BY_TOOL[tool] == len(query)
        assert identity.QUERY_SHA256_BY_TOOL[tool] == hashlib.sha256(query).hexdigest()
        for case in spec.CASES_BY_TOOL[tool]:
            response = fixture.response(case, query)
            expected = None if response is None else hashlib.sha256(response).hexdigest()
            assert identity.RESPONSE_SHA256_BY_CASE[case] == expected
            definition = lab.spec(case)
            assert definition['query_sha256'] == identity.QUERY_SHA256_BY_TOOL[tool]
            assert definition['query_bytes'] == len(query)
            assert definition['response_sha256'] == expected


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
def test_address_metadata_never_becomes_resolution_or_connection_authority(tool):
    descriptor = contract.capability_descriptor(spec.PREFIXES[tool] + 'ok')
    request = descriptor['dns_question']
    assert request['name'] == spec.QUERY_NAMES[tool] and request['type'] == spec.QUERY_TYPES[tool]
    assert request['nameserver_family'] == 'ipv4' and request['transport'] == 'tcp'
    assert request['max_connections'] == request['max_questions'] == 1 and request['max_records'] == 4
    for field in ('recursion', 'search', 'zone_transfer', 'retries', 'advertised_target_resolution',
                  'advertised_endpoint_followup', 'address_fallback', 'reverse_verification', 'verified_service_identity'):
        assert request[field] is False
