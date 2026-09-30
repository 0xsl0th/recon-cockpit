"""Fresh real-tool HarborDesk trials; unattended fixture policy is not consent."""
import json
import os
from pathlib import Path
import sys

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.web_backend import AuthorizedWebLabBackend
from recon_cockpit.secure_agent.web_lab import WebLab
from recon_cockpit.secure_agent.web_fixture import OPERATOR_NOTE
from test_secure_nmap_cli import GATES

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for actual owned web workflow')
    assert sys.platform == 'linux' and os.geteuid() != 0


@pytest.mark.parametrize('case,outcome', [('vulnerable', 'validated'),
    ('corrected', 'not_demonstrated'), ('injected', 'validated')])
def test_three_fresh_trials_with_real_tools_and_readonly_replay(tmp_path, monkeypatch, capsys, case, outcome):
    monkeypatch.setattr(WebLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedWebLabBackend, 'run', lambda *_a, **_k: pytest.fail('host executor called'))
    identities, sessions = set(), set()
    for repeat in range(3):
        trial = tmp_path / str(repeat)
        trial.mkdir(mode=0o700)
        policy = json.loads(Path('examples/secure-agent-web-policy.json').read_text())
        policy.update(policy_version='synthetic-web-unattended-test-v1', require_approval=False)
        policy_path = trial / 'policy.json'
        policy_path.write_text(json.dumps(policy))
        evidence = trial / 'evidence'
        exit_code = cli.main(['--web-assessment', case, '--assessment-dir', str(evidence),
            '--audit', str(trial/'audit.jsonl'), '--policy', str(policy_path), *GATES, '--execute'])
        output = capsys.readouterr()
        summary = json.loads(output.out)
        assert exit_code == 0, (summary, output.err)
        assert summary['assessment_outcome'] == outcome
        assert summary['actions_succeeded'] == 3 and summary['output_reserved_bytes'] == 18432
        assert summary['actual_provider_calls'] == 0 and summary['live_calls_enabled'] is False
        report = json.loads((evidence/'report.json').read_text())
        manifest = json.loads((evidence/'manifest.json').read_text())
        identities.add(manifest['owned_lab']['instance_id'])
        sessions.add(manifest['session_id'])
        assert OPERATOR_NOTE not in (evidence/'report.json').read_text()
        assert OPERATOR_NOTE not in (evidence/'report.md').read_text()
        if case == 'injected':
            assert any(OPERATOR_NOTE in p.read_text() for p in evidence.glob('result-*'))
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
        assert cli.main(['--inspect-assessment', str(evidence)]) == 0
        inspection = json.loads(capsys.readouterr().out)
        assert inspection['integrity_issues'] == [] and inspection['outcome'] == outcome
        assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
        closure = report['owned_lab']['closure']
        assert closure['status'] == 'closed' and closure['request_count'] == 2
        assert closure['connection_count'] >= 3
    assert len(identities) == len(sessions) == 3
