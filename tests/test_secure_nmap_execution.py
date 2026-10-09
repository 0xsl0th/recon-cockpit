"""The Nmap worker independently rejects altered launch authority."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_contract as contract
from recon_cockpit.secure_agent import launch_admission
from recon_cockpit.secure_agent.executor_worker import encode, digest
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.nmap_execution import consume_launch
from recon_cockpit.secure_agent.owned_lab_contract import identity


@pytest.fixture
def envelope():
    policy = parse_policy(json.loads(Path('examples/secure-agent-nmap-policy.json').read_text()))
    action = parse_action(contract.action('a', 1))
    host = {name: name + ':[100]' for name in ('user','net','mnt','pid')}
    return {'mode': 'owned_nmap_lab', 'identity': identity('a', str(uuid4())),
        'namespaces': {name: name+':[200]' for name in host}, 'runtime': {'test': 'bound by commitment'},
        'launch': {'schema_version': '1', 'mode': 'nmap_owned', 'execute': True,
            'session_id': str(uuid4()), 'nonce': 'a'*64, 'sequence': 1,
            'action': action.to_dict(), 'action_digest': action.digest,
            'policy': policy.to_dict(), 'policy_digest': policy.digest,
            'limits': dict(contract.LIMITS), 'limits_digest': digest(contract.LIMITS),
            'deadline': 110, 'output_reserved_before': 0, 'output_reserved_after': 16384,
            'host_namespaces': host}}


def verify(value, *, nonce='a'*64):
    raw = encode(value)
    return consume_launch(raw, nonce, hashlib.sha256(raw).hexdigest(), now=100)


def test_valid_launch_binds_exact_request_and_runtime(envelope):
    request, deadline, namespaces, runtime = verify(envelope)
    assert request['tool_id'] == contract.TOOL_ID
    assert request['parameters'] == contract.PARAMETERS
    assert deadline == 110 and namespaces == envelope['namespaces']
    assert runtime == digest(envelope['runtime'])


@pytest.mark.parametrize('field,value', [
    ('execute',False), ('nonce','b'*64), ('session_id','no'), ('sequence',True), ('sequence',0),
    ('sequence',4), ('deadline',100), ('deadline',float('inf')), ('mode','discovery_fixture'),
    ('action_digest','0'*64), ('policy_digest','0'*64), ('limits_digest','0'*64),
    ('output_reserved_before',1), ('output_reserved_after',16383), ('extra',1),
])
def test_independent_authority_validation(envelope,field,value):
    envelope['launch'][field]=value
    with pytest.raises((ValueError,TypeError)):
        verify(envelope)


@pytest.mark.parametrize('mutation', ['target','port','timeout','bytes','approval','policy','scope','limits','namespace','identity'])
def test_fresh_commitment_does_not_bypass_profile_or_policy(envelope,mutation):
    launch=envelope['launch']
    if mutation=='target': launch['action']['target']='127.0.0.2'
    elif mutation=='port': launch['action']['parameters']['port']=8081
    elif mutation=='timeout': launch['action']['parameters']['timeout_seconds']=6
    elif mutation=='bytes': launch['action']['parameters']['max_output_bytes']=8192
    elif mutation=='approval': launch['action']['approved']=True
    elif mutation=='policy': launch['policy']['allowed_tools']=['http_probe']
    elif mutation=='scope': launch['policy']['allowed_targets']=['127.0.0.2/32']
    elif mutation=='limits': launch['limits']['max_output_bytes']=16000
    elif mutation=='namespace': envelope['namespaces']=dict(launch['host_namespaces'])
    elif mutation=='identity': envelope['identity']['scenario']='b'
    launch['action_digest']=digest(launch['action'])
    launch['policy_digest']=digest(launch['policy'])
    launch['limits_digest']=digest(launch['limits'])
    with pytest.raises((ValueError,TypeError)):
        verify(envelope)


def test_request_commitment_rejects_runtime_substitution(envelope):
    raw=encode(envelope); committed=hashlib.sha256(raw).hexdigest()
    envelope['runtime']['test']='substituted'
    with pytest.raises(ValueError,match='commitment'):
        consume_launch(encode(envelope),'a'*64,committed,now=100)


@pytest.mark.parametrize('profile,allowed', [('fixture',False),('discovery_fixture',False),('owned_lab',False),('owned_nmap_lab',True)])
def test_nmap_requires_distinct_admission_profile(envelope,profile,allowed):
    config={'profile':profile,'case':'a' if profile.startswith('owned') else None}
    assert launch_admission.profile_allows(parse_action(envelope['launch']['action']),config) is allowed


def test_new_profile_does_not_admit_old_tcp(envelope):
    action=deepcopy(envelope['launch']['action']);action['tool_id']='tcp_connect'
    action['parameters']={'port':8080,'timeout_seconds':1,'max_output_bytes':1024}
    assert not launch_admission.profile_allows(parse_action(action),{'profile':'owned_nmap_lab','case':'a'})


@pytest.mark.parametrize('field', contract.LIMITS)
def test_fresh_commitment_cannot_expand_reviewed_session_ceiling(envelope, field):
    envelope['launch']['limits'][field] = contract.LIMITS[field] + 1
    envelope['launch']['limits_digest'] = digest(envelope['launch']['limits'])
    with pytest.raises(ValueError, match='invalid_nmap_limits'):
        verify(envelope)


@pytest.mark.parametrize('field', contract.LIMITS)
def test_admission_independently_enforces_new_profile_ceiling(envelope, field):
    config = {'version': '1', 'service_id': str(uuid4()),
        'session_id': envelope['launch']['session_id'], 'policy': envelope['launch']['policy'],
        'limits': dict(contract.LIMITS), 'execute': True, 'profile': contract.PROFILE, 'case': 'a'}
    assert launch_admission.configuration(config) == config
    config['limits'][field] += 1
    with pytest.raises(ValueError, match='invalid_nmap_admission_limits'):
        launch_admission.configuration(config)
    # Existing profiles retain their original independently reviewed ceilings.
    config['profile'] = 'owned_lab'
    assert launch_admission.configuration(config) == config
