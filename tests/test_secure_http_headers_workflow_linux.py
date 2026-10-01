"""Actual owned Nmap/header workflow; unattended test policy is not human consent."""
import base64
import json
import os
from pathlib import Path
import sys

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.http_headers_backend import AuthorizedHTTPHeadersBackend
from recon_cockpit.secure_agent.http_headers_fixture import OPERATOR_NOTE
from recon_cockpit.secure_agent.http_headers_lab import HTTPHeadersLab
from test_secure_nmap_cli import GATES

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned HTTP header workflow')
    assert sys.platform == 'linux' and os.geteuid() != 0


@pytest.mark.parametrize('case,outcome', [('vulnerable', 'gaps_observed'),
    ('corrected', 'reviewed_headers_present'), ('injected', 'gaps_observed')])
def test_real_nmap_to_headers_and_networkless_readonly_replay(tmp_path, monkeypatch, capsys, case, outcome):
    monkeypatch.setattr(HTTPHeadersLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedHTTPHeadersBackend, 'run', lambda *a, **k: pytest.fail('host executor called'))
    policy = json.loads(Path('examples/secure-agent-http-headers-policy.json').read_text())
    policy.update(policy_version='synthetic-http-headers-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence = tmp_path / 'evidence'
    code = cli.main(['--http-headers-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(tmp_path / 'audit.jsonl'), '--policy', str(policy_path), *GATES, '--execute'])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code == 0, (summary, output.err)
    assert summary['assessment_outcome'] == outcome
    assert summary['actions_succeeded'] == 2 and summary['output_reserved_bytes'] == 18432
    assert summary['actual_provider_calls'] == 0 and summary['live_calls_enabled'] is False
    report = json.loads((evidence / 'report.json').read_text())
    assert report['owned_lab']['closure']['status'] == 'closed'
    assert report['owned_lab']['closure']['request_count'] == 1
    assert report['owned_lab']['closure']['connection_count'] >= 1
    row = report['records'][1]
    artifact = json.loads((evidence / row['artifact']['filename']).read_text())
    assert all(artifact['boundary_checks'].values())
    assert artifact['http_headers']['csp'] == ('present' if case == 'corrected' else 'absent')
    assert len(base64.b64decode(artifact['results'][0]['raw_response'])) <= 2048
    if case == 'injected':
        assert OPERATOR_NOTE.encode() in base64.b64decode(artifact['results'][0]['raw_response'])
        for filename in ('report.json', 'report.md', 'evidence.jsonl'):
            assert OPERATOR_NOTE not in (evidence / filename).read_text()
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment', str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay['integrity_issues'] == []
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
