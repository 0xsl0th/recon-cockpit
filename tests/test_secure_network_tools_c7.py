"""C7 permits only fixed SMTP STARTTLS while preserving accepted profiles."""

from dataclasses import FrozenInstanceError
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
from recon_cockpit.secure_agent.models import SMTPStartTLSParameters, ValidationError, parse_action, parse_policy


def policy(**overrides):
    value = json.loads(Path('examples/secure-agent-smtp-starttls-policy.json').read_text())
    return parse_policy({**value, **overrides})


@pytest.mark.parametrize('case', contract.C7_CASES)
def test_fixed_smtp_starttls_requires_personal_approval_and_one_typed_action(case):
    proposal = contract.action(case)
    action = parse_action(proposal)
    assert action.tool_id == contract.SMTP_TLS_TOOL_ID
    assert action.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert type(action.parameters) is SMTPStartTLSParameters
    assert action.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert parse_action(json.dumps(proposal)).digest == action.digest
    assert contract.profile_allows(action, case)
    assert policy().evaluate(action).decision == 'approval_required'
    assert policy(allowed_methods=[]).evaluate(action).decision == 'approval_required'
    assert policy(allowed_ports=[]).evaluate(action).reasons == ('port_not_allowed',)
    assert policy(allowed_tools=[]).evaluate(action).reasons == ('tool_not_allowed',)
    assert workflow.card_identity(case)['version'] == '15'
    assert set(workflow.card(case)['action_digests']) == set(contract.C7_CASES)
    with pytest.raises(FrozenInstanceError):
        action.parameters.port = 25
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'starttls', 'ehlo', 'name',
    'hostname', 'servername', 'verify_hostname', 'CAfile', 'client_certificate', 'key',
    'username', 'password', 'auth', 'mail', 'recipient', 'message', 'stdin', 'path',
    'method', 'tls_version', 'cipher', 'retries', 'followup', 'environment'])
def test_untrusted_proposal_cannot_select_smtp_dialogue_credentials_or_native_configuration(field):
    proposal = contract.action('smtp-tls-ok')
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('field,value', [('port', True), ('port', '8080'), ('port', 0), ('port', 65536),
    ('timeout_seconds', False), ('timeout_seconds', 0), ('timeout_seconds', 31),
    ('max_output_bytes', True), ('max_output_bytes', 0), ('max_output_bytes', 65537)])
def test_smtp_starttls_parameters_reject_wrong_types_and_out_of_range_values(field, value):
    proposal = contract.action('smtp-tls-ok')
    proposal['parameters'][field] = value
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('change', [{'target': '127.0.0.2'}, {'port': 25},
    {'timeout_seconds': 10}, {'max_output_bytes': 16384}])
def test_valid_syntax_cannot_expand_fixed_execution_scope(change):
    proposal = contract.action('smtp-tls-ok')
    if 'target' in change:
        proposal.update(change)
    else:
        proposal['parameters'].update(change)
    assert not contract.profile_allows(parse_action(proposal), 'smtp-tls-ok')


@pytest.mark.parametrize('case', contract.SMTP_TLS_SUCCESS_CASES)
@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (0, 1), (2, 1),
    (1, 2), (True, 1), (1, True)])
def test_useful_tls_requires_exactly_one_connection_and_fixture_clean_close_witness(case, connections, requests):
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': connections, 'request_count': requests}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.SMTP_TLS_TOOL_ID,
                                        execution_status='succeeded')


@pytest.mark.parametrize('case', [case for case in contract.C7_CASES if case not in contract.SMTP_TLS_SUCCESS_CASES])
def test_negative_case_or_unsupported_diagnostics_cannot_be_upgraded_to_useful_tls(case):
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': {}}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, identity, tool_id=contract.SMTP_TLS_TOOL_ID,
                                        execution_status='succeeded')


@pytest.mark.parametrize('case', contract.C7_CASES)
def test_counter_meaning_is_pinned_per_case_and_cannot_make_smtp_claims(case):
    definition = lab.spec(case)
    complete = case in contract.SMTP_TLS_COMPLETE_CASES
    assert definition['counter_includes_clean_tls_close'] is complete
    assert definition['request_count_means'] == ('validated_ehlo_starttls_then_tls13_and_clean_close_notify'
        if complete else 'validated_ehlo_and_starttls_before_negative_response')
    identity = lab.identity(case, str(uuid4()))
    result = {'backend': contract.BACKEND, 'owned_lab': {'identity': identity,
        'connection_count': 1, 'request_count': 1}, 'tool_observation': None}
    assert contract.validate_result_context(result, identity, tool_id=contract.SMTP_TLS_TOOL_ID,
        execution_status='succeeded' if complete else 'failed') == result['owned_lab']
    assert definition['client_validates_smtp_reply_codes'] is False
    assert definition['client_requires_starttls_advertisement'] is False
    assert definition['full_smtp_dialogue_retained'] is False


def test_descriptor_and_adapter_limit_tls_to_one_fixed_owned_smtp_preface():
    descriptor = contract.capability_descriptor('smtp-tls-ok')
    adapter = tool_adapters.get_adapter(contract.SMTP_TLS_TOOL_ID)
    assert descriptor['capabilities'] == [adapter.to_dict()]
    assert adapter.parameter_type is SMTPStartTLSParameters
    assert descriptor['result_semantics'] == 'verified_tls_handshake_only'
    assert descriptor['parser_versions'] == {contract.SMTP_TLS_TOOL_ID: 'smtp-starttls-brief-v1'}
    assert descriptor['limits'] == {'max_steps': 1, 'max_runtime_seconds': 60, 'max_output_bytes': 8192}
    smtp = descriptor['smtp_starttls']
    assert smtp['commands'] == ['EHLO harbordesk.test', 'STARTTLS']
    assert smtp['max_connections'] == 1 and smtp['max_commands'] == 2
    assert smtp['tls_protocol'] == 'TLSv1.3' and smtp['tls_cipher'] == 'TLS_AES_256_GCM_SHA384'
    assert smtp['useful_result_requires_owner_clean_close'] is True
    assert smtp['client_attempts_starttls_without_advertisement'] is True
    assert smtp['client_does_not_validate_ready_status'] is True
    for key in ('authentication', 'mail', 'recipient_probing', 'client_credentials', 'tls_application_requests',
            'plaintext_session', 'retries', 'smtp_dialogue_validation_claim', 'service_identity_claim',
            'full_plaintext_dialogue_retained'):
        assert smtp[key] is False
    assert 'owner_witnessed_clean_tls_close' in adapter.execution_requirements


def test_all_accepted_contracts_remain_unchanged_from_pr60():
    old_cases = [case for case in contract.CASES if case not in contract.C7_CASES + contract.C8_CASES + contract.C9_CASES + contract.C10_CASES + contract.C11_CASES + contract.C12_CASES + contract.C13_CASES + contract.C14_CASES + contract.C15_CASES + contract.C16_CASES + contract.C17_CASES + contract.C18_CASES + contract.T02_CASES + contract.T03_CASES]
    old_tools = set(tool_adapters.ADAPTERS) - (set(contract.tls_posture.TOOL_VERSIONS) | {contract.SSH_POLICY_TOOL_ID}) - {contract.SMTP_TLS_TOOL_ID, contract.LDAP_TLS_TOOL_ID, contract.FTP_TLS_TOOL_ID, contract.DIG_NSID_TOOL_ID, contract.DIG_AXFR_TOOL_ID, contract.HTTP_OPTIONS_TOOL_ID, contract.SNMP_NEXT_TOOL_ID, contract.SSH_ALGORITHMS_TOOL_ID, contract.TLS_CERTIFICATE_TOOL_ID, contract.NUCLEI_TOOL_ID, contract.NUCLEI_GIT_TOOL_ID, contract.DIG_MX_TOOL_ID}
    old_runtime = set(runtime.EXECUTABLES) - {contract.SSH_POLICY_TOOL_ID} - {contract.SMTP_TLS_TOOL_ID, contract.LDAP_TLS_TOOL_ID, contract.FTP_TLS_TOOL_ID, contract.DIG_NSID_TOOL_ID, contract.DIG_AXFR_TOOL_ID, contract.HTTP_OPTIONS_TOOL_ID, contract.SNMP_NEXT_TOOL_ID, contract.SSH_ALGORITHMS_TOOL_ID, contract.TLS_CERTIFICATE_TOOL_ID, contract.NUCLEI_TOOL_ID, contract.NUCLEI_GIT_TOOL_ID, contract.DIG_MX_TOOL_ID}
    value = {'cases': {case: {'action': contract.action(case), 'descriptor': contract.capability_descriptor(case),
        'card': workflow.card(case), 'spec': lab.spec(case)} for case in old_cases},
        'adapters': {tool: tool_adapters.ADAPTERS[tool].to_dict() for tool in old_tools},
        'argv': {tool: runtime.FIXED_ARGV[tool] for tool in old_runtime},
        'environment': {tool: runtime.execution_environment(tool) for tool in old_runtime}}
    assert len(old_cases) == 160 and len(old_tools) == 31 and len(old_runtime) == 22
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == 'a4cae78a90dd7c2f3c2fc8a23963e797d9684359399f6e64821d28e4ade45029'
