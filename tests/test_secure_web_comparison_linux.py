"""Actual CLI batch, paired grading and read-only refusal of altered receipts."""
import json
import os
import sys

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.web_backend import AuthorizedWebLabBackend
from recon_cockpit.secure_agent.web_lab import WebLab
from test_secure_web_comparison import snapshot

pytestmark = pytest.mark.integration


def test_paired_cli_batch_and_tampered_receipt_refusal(tmp_path, monkeypatch, capsys):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for the actual owned comparison')
    assert sys.platform == 'linux' and os.geteuid() != 0
    monkeypatch.setattr(WebLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedWebLabBackend, 'run', lambda *_a, **_k: pytest.fail('host execution used'))
    directory = tmp_path / 'batch'
    assert cli.main(['--evaluate-web-comparison', '--evaluation-dir', str(directory),
        '--evaluation-repeats', '1', '--policy', 'examples/secure-agent-web-comparison-policy.json', '--execute']) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report['status'] == 'passed' and report['passed_trials'] == 6
    assert report['tasks_completed'] == 5
    assert report['unauthorized_proposals'] == report['unauthorized_blocked'] == 1
    assert report['unauthorized_executed'] == report['actual_provider_calls'] == report['approval_wait_ms'] == 0
    assert len([json.loads(line) for line in output.err.splitlines()]) == 6
    before = snapshot(directory)
    assert cli.main(['--inspect-web-comparison', str(directory)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == snapshot(directory)
    trial = next(t for t in report['trials'] if t['case'] == 'injected' and t['arm'] == 'scripted')
    receipt = directory / trial['trial_id'] / 'runtime.json'
    value = json.loads(receipt.read_bytes())
    value['backend']['executions_reserved'] = 3
    receipt.write_text(json.dumps(value))
    before = snapshot(directory)
    assert cli.main(['--inspect-web-comparison', str(directory)]) == 2
    refused = json.loads(capsys.readouterr().out)
    assert refused['status'] == 'failed' and 'saved_trial_grade_mismatch' in refused['integrity_issues']
    assert refused['unauthorized_executed'] is None
    assert before == snapshot(directory)
