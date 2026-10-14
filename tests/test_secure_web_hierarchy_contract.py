"""T04 candidate is fixed, independently authorized and preserves accepted APIs."""
import copy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launch_admission as admission
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import network_tools_lab_contract as lab
from recon_cockpit.secure_agent import network_tools_web_hierarchy_spec as spec
from recon_cockpit.secure_agent import tool_catalog as catalog
from recon_cockpit.secure_agent.models import parse_action, parse_policy


@pytest.mark.parametrize('case', spec.CASES)
def test_exact_case_scope_and_approval_policy(case):
    action = parse_action(contract.action(case))
    assert action.tool_id == spec.TOOL_ID
    assert action.target == '127.0.0.1' and action.parameters.to_dict() == dict(spec.PARAMETERS)
    assert contract.profile_allows(action, case)
    config = {'profile': contract.PROFILE, 'case': case}
    assert admission.profile_allows(action, config)
    policy = parse_policy(json.loads(Path('examples/secure-agent-web-hierarchy-policy.json').read_text()))
    assert policy.require_approval and policy.evaluate(action).decision == 'approval_required'
    assert workflow.card(case)['workflow_version'] == '29'
    assert workflow.card(case)['limits'] == dict(spec.LIMITS)
    assert len(contract.capability_descriptor(case)['web_hierarchy']['paths']) == 12
    identity = lab.identity(case, str(uuid4()))
    assert lab.validate_identity(identity, case=case) == identity


@pytest.mark.parametrize('field,value', [('target','127.0.0.2'), ('port',8081), ('timeout_seconds',5),
    ('max_output_bytes',8191), ('tool_id','ffuf_content_discovery_v1')])
def test_no_scope_or_old_profile_substitution(field,value):
    case=spec.CASES[0]
    raw=contract.action(case)
    if field in {'target','tool_id'}:
        raw[field]=value
    else:
        raw['parameters'][field]=value
    selected=parse_action(raw)
    assert not contract.profile_allows(selected,case)
    assert not admission.profile_allows(selected,{'profile':contract.PROFILE,'case':case})


def test_candidate_catalog_is_separate_and_new_program_count_unchanged():
    result=catalog.list_tools()
    assert (result['capability_count'],result['accepted_capability_count'],result['candidate_capability_count'],result['external_program_count']) == (49,48,1,16)
    row=catalog.describe_tool(spec.TOOL_ID)
    assert row['acceptance_status']=='candidate' and row['milestone']=='T04'
    assert row['run']['case']=='web-hierarchy-nested'
    assert row['run']['session_limits']==dict(spec.LIMITS)


def test_all_48_previous_catalog_apis_348_network_cases_and_old_web_workflow_are_unchanged():
    from recon_cockpit.secure_agent import web_tools_contract as web
    from recon_cockpit.secure_agent import web_tools_workflow as web_workflow
    listed=catalog.list_tools()
    listed['tools']=[row for row in listed['tools'] if row['tool_id']!=spec.TOOL_ID]
    listed.update(capability_count=48,accepted_capability_count=48,candidate_capability_count=0)
    value={'catalog':listed,'descriptions':{row['tool_id']:catalog.describe_tool(row['tool_id']) for row in listed['tools']},
        'network':{case:{'descriptor':contract.capability_descriptor(case),'card':workflow.card_identity(case),'action':contract.action(case)} for case in contract.CASES if case not in spec.CASES},
        'web_descriptor':web.capability_descriptor(),'web_card':web_workflow.card_identity()}
    assert len(value['network'])==348
    assert hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()=='d03d7ba4894f44e7b61e0aec145cdf6d0c0d1553648a58cc1e63a1337b42b5e1'
