"""Real Nmap workflow inside the owned lab; fixture policy is not human consent."""
import json
import os
from pathlib import Path
import sys

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.owned_lab import OwnedLab
from recon_cockpit.secure_agent.nmap_backend import AuthorizedNmapOwnedBackend
from test_secure_nmap_cli import GATES

pytestmark=pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get('RECON_LINUX_INTEGRATION')!='1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for actual owned Nmap workflow')
    assert sys.platform=='linux' and os.geteuid()!=0


def args(tmp_path, case='a', execute=True):
    policy=json.loads(Path('examples/secure-agent-nmap-policy.json').read_text())
    policy.update(policy_version='test-owned-nmap-unattended',require_approval=False)
    path=tmp_path/'policy.json';path.write_text(json.dumps(policy))
    return ['--nmap-assessment',case,'--assessment-dir',str(tmp_path/'evidence'),
        '--audit',str(tmp_path/'audit.jsonl'),'--policy',str(path),*GATES,
        '--execute' if execute else '--dry-run']


@pytest.mark.parametrize('case,outcome',[('a','validated'),('b','not_demonstrated'),('c','inconclusive'),
    ('d','inconclusive'),('e','inconclusive'),('f','inconclusive')])
def test_confined_nmap_http_workflow_and_readonly_replay(tmp_path,monkeypatch,capsys,case,outcome):
    monkeypatch.setattr(OwnedLab,'start',lambda *_:pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNmapOwnedBackend,'run',lambda *_a,**_k:pytest.fail('host Nmap executor called'))
    exit_code=cli.main(args(tmp_path,case))
    output=capsys.readouterr()
    report=json.loads(output.out)
    assert report.get('assessment_outcome')==outcome,(report,output.err)
    assert report['actual_provider_calls']==0 and report['live_calls_enabled'] is False
    assert report['actions_succeeded']>=1,(report,output.err)
    assert exit_code== (0 if report['session_status']=='completed' else 2)
    evidence=tmp_path/'evidence'
    before={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment',str(evidence)])==0
    inspection=json.loads(capsys.readouterr().out)
    assert inspection['integrity_issues']==[]
    assert inspection['outcome']==outcome
    assert before=={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in evidence.iterdir()}


def test_dry_run_does_not_inspect_or_start_tool(tmp_path,monkeypatch,capsys):
    from recon_cockpit.secure_agent import nmap_runtime
    monkeypatch.setattr(nmap_runtime,'inspect_nmap_runtime',lambda *_:pytest.fail('tool runtime inspected'))
    monkeypatch.setattr(OwnedLab,'start',lambda *_:pytest.fail('lab started'))
    cli.main(args(tmp_path,execute=False))
    report=json.loads(capsys.readouterr().out)
    assert report['actions_succeeded']==0
    assert report['assessment_outcome']=='inconclusive'
    assert not list((tmp_path/'evidence').glob('result-*'))
