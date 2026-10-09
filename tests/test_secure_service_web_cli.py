"""Selection boundaries for the separate composed owned workflow."""
import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import cli
from test_secure_http_headers_cli import GATES, portable_services


def arguments(tmp_path, case='vulnerable'):
    return ['--service-web-assessment',case,'--assessment-dir',str(tmp_path/'evidence'),
            '--audit',str(tmp_path/'audit.jsonl'),'--policy','examples/secure-agent-service-web-policy.json']


@pytest.mark.parametrize('missing',GATES)
def test_all_seven_gates_are_required_before_policy_or_writes(tmp_path,monkeypatch,missing):
    monkeypatch.setattr(cli,'_read_bounded',lambda *_:pytest.fail('policy read before refusal'))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path),*(gate for gate in GATES if gate!=missing)])
    assert error.value.code==2 and not list(tmp_path.iterdir())


@pytest.mark.parametrize('extra',[
    ['--session-max-steps','4'],['--session-max-seconds','61'],['--session-max-output-bytes','18433'],
    ['--session-max-steps','0'],['--session-max-seconds','0'],['--session-max-output-bytes','0'],
    ['--openai-model','unused'],['--assessment-planning-offline','success'],
    ['--assessment-planning-owned-tls','success'],['--planning-ledger','ledger'],
    ['--routed'],['--fixture'],['--list-tools'],['--describe-tool','http_headers_v1'],
])
def test_limits_modes_and_provider_substitution_cannot_expand_profile(tmp_path,monkeypatch,extra):
    monkeypatch.setattr(cli,'_read_bounded',lambda *_:pytest.fail('policy read before refusal'))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path),*GATES,*extra])
    assert error.value.code==2 and not list(tmp_path.iterdir())


def test_policy_requires_fresh_approval_for_exact_three_tools():
    from recon_cockpit.secure_agent.models import parse_policy,parse_action
    from recon_cockpit.secure_agent.service_web_contract import action
    value=json.loads(Path('examples/secure-agent-service-web-policy.json').read_text())
    assert value['allowed_targets']==['127.0.0.1/32'] and value['allowed_ports']==[8080]
    assert value['allowed_methods']==['GET'] and value['require_approval'] is True
    assert value['allowed_tools']==['nmap_service_identify_v1','ffuf_content_discovery_v1','http_headers_v1']
    policy=parse_policy(value)
    for step in (1,2,3):
        assert policy.evaluate(parse_action(action('vulnerable',step))).decision=='approval_required'


@pytest.mark.parametrize('case',('vulnerable','corrected','injected'))
def test_dry_run_does_not_inspect_runtimes_execute_tools_or_claim_useful_work(
        tmp_path,monkeypatch,capsys,portable_services,case):
    from recon_cockpit.secure_agent import service_web_runtime
    monkeypatch.setattr(service_web_runtime,'inspect_service_web_runtime',
                        lambda *_:pytest.fail('dry run inspected executables'))
    assert cli.main([*arguments(tmp_path,case),*GATES,'--dry-run'])==0
    summary=json.loads(capsys.readouterr().out)
    assert summary['actions_succeeded']==0 and summary['legitimate_task_completed'] is False
    assert summary['actual_provider_calls']==0 and summary['actual_cost_microusd']==0
    assert summary['live_calls_enabled'] is False
    assert summary['workflow_card']['id']=='owned-service-web-assessment-v1'
    assert summary['elapsed_ms']>=0 and summary['assessment_outcome']=='inconclusive'
    assert not any(row['event_type']=='execution_started' for row in portable_services)
    directory=tmp_path/'evidence'
    manifest=json.loads((directory/'manifest.json').read_text())
    assert manifest['runtime_bindings'] is None and manifest['runtime_sha256'] is None
    before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in directory.iterdir()}
    assert cli.main(['--inspect-assessment',str(directory)])==0
    report=json.loads(capsys.readouterr().out)
    assert report['integrity_issues']==[] and report['reason']=='dry_run_has_no_execution_evidence'
    assert before=={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in directory.iterdir()}
