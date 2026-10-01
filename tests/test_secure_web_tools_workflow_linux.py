"""Real executables through all secure gates; synthetic policy is not human acceptance."""
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.web_tools_backend import AuthorizedWebToolsBackend
from recon_cockpit.secure_agent.web_tools_lab import WebToolsLab
from test_secure_nmap_cli import GATES

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned web-tool trials')
    assert sys.platform == 'linux' and os.geteuid() != 0


@pytest.mark.parametrize('case,outcome,success,requests', [
    ('curl-ok', 'response_observed', 1, 1),
    ('curl-injected', 'response_observed', 1, 1),
    ('curl-untrusted', 'inconclusive', 0, 0),
    ('curl-redirect', 'inconclusive', 1, 1),
    ('curl-malformed', 'inconclusive', 0, 1),
    ('curl-stalled', 'inconclusive', 0, 1),
    ('ffuf-normal', 'paths_observed', 1, 8),
    ('ffuf-injected', 'paths_observed', 1, 8),
    ('ffuf-wildcard', 'inconclusive', 1, 8),
    ('ffuf-stalled', 'inconclusive', None, None),
])
def test_real_tool_and_independent_readonly_replay(tmp_path, monkeypatch, capsys, record_property, case, outcome, success, requests):
    monkeypatch.setattr(WebToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedWebToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))
    policy = json.loads(Path('examples/secure-agent-web-tools-policy.json').read_text())
    policy.update(policy_version='synthetic-web-tools-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence = tmp_path / 'evidence'
    started = time.monotonic()
    code = cli.main(['--web-tool-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(tmp_path / 'audit.jsonl'), '--policy', str(policy_path), *GATES, '--execute'])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2) and 'assessment_outcome' in summary, (summary, output.err)
    assert summary['assessment_outcome'] == outcome, (summary, output.err)
    if success is not None:
        assert summary['actions_succeeded'] == success, (summary, output.err)
    assert summary['steps_attempted'] == 1 and summary['output_reserved_bytes'] == 8192
    assert summary['actual_provider_calls'] == 0 and summary['live_calls_enabled'] is False
    elapsed = time.monotonic() - started
    assert elapsed < 60
    record_property('execution_elapsed_ms', round(elapsed * 1000))
    record_property('expected_outcome', outcome)
    record_property('actions_succeeded', summary['actions_succeeded'])
    record_property('provider_calls', summary['actual_provider_calls'])
    report = json.loads((evidence / 'report.json').read_text())
    closure = report['owned_lab']['closure']
    assert closure['status'] == 'closed'
    record_property('request_count', closure['request_count'])
    if requests is not None:
        assert closure['request_count'] == requests
    assert closure['request_count'] <= (1 if case.startswith('curl-') else 8)
    row = report['records'][0]
    artifact = json.loads((evidence / row['artifact']['filename']).read_text())
    assert all(artifact['boundary_checks'].values())
    assert artifact['bytes_received'] <= 8192
    for filename in ('report.json', 'report.md', 'evidence.jsonl'):
        assert '127.0.0.2' not in (evidence / filename).read_text()
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment', str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay['integrity_issues'] == []
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
