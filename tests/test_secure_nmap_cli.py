"""New lab mode is opt-in and cannot bypass its mandatory launch gates."""
import json
from pathlib import Path

import pytest
from recon_cockpit.secure_agent import cli

GATES = ['--owned-lab','--isolated-audit','--isolated-approvals','--isolated-launch-admission',
         '--isolated-launcher','--require-launch-audit','--require-launch-approval']


def arguments(tmp_path):
    return ['--nmap-assessment','a','--assessment-dir',str(tmp_path/'evidence'),
            '--audit',str(tmp_path/'audit.jsonl'),'--policy','examples/secure-agent-nmap-policy.json']


@pytest.mark.parametrize('missing',GATES)
def test_each_launch_gate_required_before_side_effects(tmp_path,missing):
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path),*(gate for gate in GATES if gate!=missing)])
    assert error.value.code==2
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('option,value',[('--session-max-steps','4'),('--session-max-seconds','61'),
    ('--session-max-output-bytes','18433'),('--session-max-seconds','0')])
def test_overrides_cannot_expand_profile(tmp_path,option,value):
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path),*GATES,option,value])
    assert error.value.code==2
    assert not list(tmp_path.iterdir())


def test_owned_nmap_policy_keeps_fresh_approval():
    value=json.loads(Path('examples/secure-agent-nmap-policy.json').read_text())
    assert value['require_approval'] is True
    assert value['allowed_targets']==['127.0.0.1/32']
    assert value['allowed_ports']==[8080]
    assert value['allowed_tools']==['nmap_tcp_connect_v1','http_probe']


@pytest.mark.parametrize('flag',['--assessment-planning-offline','--assessment-planning-owned-tls'])
def test_existing_provider_profiles_cannot_be_selected(tmp_path,flag):
    from recon_cockpit.secure_agent.assessment_planning_contract import SCENARIOS
    from recon_cockpit.secure_agent.assessment_planning_tls_contract import SCENARIOS as TLS
    scenario=next(iter(TLS if flag.endswith('tls') else SCENARIOS))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path),*GATES,flag,scenario])
    assert error.value.code==2
    assert not list(tmp_path.iterdir())
