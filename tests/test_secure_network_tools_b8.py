"""Two synthetic Kerberos reports carry no authentication or follow-up authority."""
import copy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent.models import ValidationError, parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_lab_contract import identity, validate_context
from test_secure_network_tools_contract import policy


@pytest.mark.parametrize('case', contract.B8_CASES)
def test_b8_requires_two_compiled_names_in_one_approved_action(case):
    selected = parse_action(contract.action(case))
    assert selected.tool_id == 'kerbrute_userenum_v1'
    assert contract.profile_allows(selected, case)
    assert selected.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert workflow.card_identity(case)['version'] == '8'
    assert set(workflow.card(case)['action_digests']) == set(contract.B8_CASES)
    descriptor = contract.capability_descriptor(case)
    assert descriptor['kerberos']['principals'] == ['fixture-a', 'fixture-b']
    assert descriptor['kerberos']['results'] == 'tool_report_only'
    assert descriptor['kerberos']['unknown_report_can_be_spoofed_by_error_text'] is True
    assert descriptor['kerberos']['tickets'] is descriptor['kerberos']['passwords'] is False
    assert policy(allowed_methods=[]).evaluate(selected).decision == 'approval_required'
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'executable', 'domain', 'realm', 'dc', 'wordlist', 'usernames',
    'username', 'password', 'passwords', 'keytab', 'credential_cache', 'hash_file', 'threads',
    'delay', 'downgrade', 'environment', 'command', 'config', 'ticket'])
def test_b8_untrusted_proposal_cannot_select_identities_or_credentials(field):
    proposal = contract.action('kerberos-ok')
    proposal['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(proposal)


@pytest.mark.parametrize('field,value', [('port', 88), ('port', 8081), ('timeout_seconds', 10), ('max_output_bytes', 16384)])
def test_b8_syntactic_bounds_do_not_expand_native_profile(field, value):
    proposal = contract.action('kerberos-ok')
    proposal['parameters'][field] = value
    assert not contract.profile_allows(parse_action(proposal), 'kerberos-ok')


def test_b8_shipped_policy_requires_fresh_approval_for_only_this_fixture():
    raw = json.loads(Path('examples/secure-agent-kerberos-policy.json').read_text())
    assert raw['allowed_tools'] == ['kerbrute_userenum_v1']
    assert raw['allowed_targets'] == ['127.0.0.1/32'] and raw['allowed_ports'] == [8080]
    assert raw['allowed_methods'] == []
    assert raw['require_approval'] is True and raw['approval_ttl_seconds'] == 60
    assert parse_policy(raw).evaluate(parse_action(contract.action('kerberos-ok'))).decision == 'approval_required'


def reports(status='exists'):
    return {'parser_version': 'kerbrute-userenum-text-v1', 'kind': 'kerberos_principal_reports',
        'realm': 'HARBORDESK.TEST', 'semantics': 'tool_report_only', 'authentication_verified': False,
        'principals': [{'principal': 'fixture-a', 'reported_status': status},
                       {'principal': 'fixture-b', 'reported_status': 'unknown'}]}


@pytest.mark.parametrize('status', ['exists', 'unknown'])
def test_b8_complete_reports_cannot_authorize_followup(status):
    value = reports(status)
    result = contract.classify_tool(contract.KERBRUTE_TOOL_ID, value)
    assert result['reason'] == 'kerberos_principal_reports_observed'
    assert result['followup_path'] is None
    assert result['details']['semantics'] == 'tool_report_only'
    value['principals'][0]['reported_status'] = 'changed'
    assert result['details']['principals'][0]['reported_status'] == status


@pytest.mark.parametrize('connections,requests', [(0, 0), (1, 0), (1, 1), (2, 1), (3, 2), (2, 3), (True, 2), (2, True)])
def test_b8_complete_observation_needs_two_requests_and_connections(connections, requests):
    lab = identity('kerberos-ok', str(uuid4()))
    result = {'backend': contract.BACKEND,
        'owned_lab': {'identity': lab, 'connection_count': connections, 'request_count': requests},
        'tool_observation': reports()}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, lab, tool_id=contract.KERBRUTE_TOOL_ID, execution_status='succeeded')


def test_b8_two_request_receipt_is_valid_but_does_not_expand_old_profiles():
    for case in contract.B1_CASES + contract.B2_CASES + contract.B3_CASES + contract.B4_CASES + contract.B5_CASES + contract.B6_CASES + contract.B7_CASES:
        lab = identity(case, str(uuid4()))
        with pytest.raises(ValueError):
            validate_context({'identity': lab, 'connection_count': 2, 'request_count': 2}, lab)
    lab = identity('kerberos-ok', str(uuid4()))
    context = {'identity': lab, 'connection_count': 2, 'request_count': 2}
    assert contract.validate_result_context({'backend': contract.BACKEND,
        'owned_lab': context, 'tool_observation': reports()}, lab,
        tool_id=contract.KERBRUTE_TOOL_ID, execution_status='succeeded') == context
