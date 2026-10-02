"""Real executables through all secure gates; synthetic policy is not human acceptance."""
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_nmap_cli import GATES

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned network-tool trials')
    assert sys.platform == 'linux' and os.geteuid() != 0


@pytest.mark.parametrize('case,outcome,success,requests', [
    ('nmap-service-http', 'nmap_service_identified', 1, 1),
    ('nmap-service-ssh', 'nmap_service_identified', 1, 1),
    ('nmap-service-unknown', 'nmap_service_unidentified', 1, 1),
    ('nmap-service-injected', 'nmap_service_unidentified', 1, 1),
    ('nmap-service-malformed', 'nmap_service_unidentified', 1, 1),
    ('nmap-service-stalled', 'nmap_service_unidentified', 1, 1),
    ('dig-ok', 'answer_observed', 1, 1),
    ('dig-nxdomain', 'name_not_found', 1, 1),
    ('dig-injected', 'answer_observed', 1, 1),
    # dig can exit zero after displaying malformed DNS diagnostics. The
    # independent parser still rejects that output and reports inconclusive.
    ('dig-malformed', 'inconclusive', 1, 1),
    ('dig-stalled', 'inconclusive', 0, 1),
    ('openssl-ok', 'handshake_verified', 1, 1),
    ('openssl-untrusted', 'inconclusive', 0, 0),
    ('openssl-malformed', 'inconclusive', 0, 0),
    ('openssl-stalled', 'inconclusive', 0, 0),
    ('ssh-ok', 'host_key_observed', 1, 1),
    ('ssh-injected', 'host_key_observed', 1, 1),
    ('ssh-malformed', 'inconclusive', 0, 0),
    ('ssh-stalled', 'inconclusive', 0, 0),
    ('ldap-ok', 'rootdse_observed', 1, 1),
    ('ldap-empty', 'empty_rootdse_observed', 1, 1),
    ('ldap-injected', 'rootdse_observed', 1, 1),
    ('ldap-referral', 'inconclusive', 0, 1),
    ('ldap-malformed', 'inconclusive', 0, 1),
    ('ldap-stalled', 'inconclusive', 0, 1),
    ('smb-ok', 'shares_observed', 1, 1),
    ('smb-injected', 'shares_observed', 1, 1),
    # Native smbclient may return zero and only a workgroup footer for all
    # three cases. Neither exit status nor the fixture label proves absence.
    ('smb-empty', 'inconclusive', 1, 1),
    ('smb-denied', 'inconclusive', 1, 1),
    ('smb-malformed', 'inconclusive', 1, 1),
    ('smb-stalled', 'inconclusive', 1, 1),
    ('rpc-ok', 'rpc_registrations_observed', 1, 1),
    ('rpc-empty', 'rpc_empty_registrations_observed', 1, 1),
    ('rpc-injected', 'rpc_registrations_observed', 1, 1),
    ('rpc-malformed', 'inconclusive', 0, 1),
    ('rpc-stalled', 'inconclusive', 0, 1),
    ('nfs-ok', 'nfs_exports_observed', 1, 1),
    ('nfs-empty', 'nfs_empty_exports_observed', 1, 1),
    ('nfs-injected', 'inconclusive', 1, 1),
    ('nfs-malformed', 'inconclusive', 0, 1),
    ('nfs-stalled', 'inconclusive', 0, 1),
    ('nfs-redirected', 'inconclusive', 0, 0),
    ('ftp-ok', 'ftp_names_observed', 1, 1),
    ('ftp-empty', 'ftp_empty_listing_observed', 1, 1),
    ('ftp-denied', 'inconclusive', 0, 0),
    ('ftp-injected', 'inconclusive', 1, 1),
    ('ftp-malformed', 'inconclusive', 0, 1),
    ('ftp-stalled', 'inconclusive', 0, 1),
    ('ftp-passive-ip', 'inconclusive', 0, 0),
    ('ftp-passive-port', 'inconclusive', 0, 0),
    ('smtp-ok', 'smtp_capabilities_observed', 1, 1),
    ('smtp-empty', 'smtp_no_extensions_observed', 1, 1),
    ('smtp-injected', 'inconclusive', 1, 1),
    ('smtp-malformed', 'inconclusive', 0, 1),
    ('smtp-rejected', 'inconclusive', 0, 1),
    ('smtp-stalled', 'inconclusive', 0, 1),
    ('docker-ping-ok', 'docker_ping_observed', 1, 1),
    ('docker-ping-unavailable', 'inconclusive', 1, 1),
    ('docker-ping-injected', 'inconclusive', 1, 1),
    ('docker-ping-malformed', 'inconclusive', 0, 1),
    ('docker-ping-stalled', 'inconclusive', 0, 1),
    ('docker-ping-redirect-ip', 'inconclusive', 1, 1),
    ('docker-ping-redirect-port', 'inconclusive', 1, 1),
    ('docker-version-ok', 'docker_version_metadata_observed', 1, 1),
    ('docker-version-empty', 'docker_no_version_metadata_observed', 1, 1),
    ('docker-version-injected', 'inconclusive', 1, 1),
    ('docker-version-malformed', 'inconclusive', 0, 1),
    ('docker-version-stalled', 'inconclusive', 0, 1),
    ('docker-version-redirect-ip', 'inconclusive', 1, 1),
    ('docker-version-redirect-port', 'inconclusive', 1, 1),
    ('winrm-ok', 'winrm_auth_schemes_observed', 1, 1),
    ('winrm-no-auth', 'winrm_no_auth_schemes_observed', 1, 1),
    ('winrm-injected', 'inconclusive', 1, 1),
    ('winrm-malformed', 'inconclusive', 0, 1),
    ('winrm-stalled', 'inconclusive', 0, 1),
    ('winrm-redirect-ip', 'inconclusive', 1, 1),
    ('winrm-redirect-port', 'inconclusive', 1, 1),
])
def test_real_tool_and_independent_readonly_replay(tmp_path, monkeypatch, capsys, record_property, case, outcome, success, requests):
    monkeypatch.setattr(NetworkToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))
    policy_file = ('examples/secure-agent-nmap-service-policy.json' if case.startswith('nmap-service-')
                   else 'examples/secure-agent-docker-winrm-policy.json' if case.startswith(('docker-ping-', 'docker-version-', 'winrm-'))
                   else 'examples/secure-agent-ftp-smtp-policy.json' if case.startswith(('ftp-', 'smtp-'))
                   else 'examples/secure-agent-rpc-nfs-policy.json' if case.startswith(('rpc-', 'nfs-'))
                   else 'examples/secure-agent-smb-policy.json' if case.startswith('smb-')
                   else 'examples/secure-agent-ssh-ldap-policy.json' if case.startswith(('ssh-', 'ldap-'))
                   else 'examples/secure-agent-network-tools-policy.json')
    policy = json.loads(Path(policy_file).read_text())
    policy.update(policy_version='synthetic-network-tools-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence = tmp_path / 'evidence'
    started = time.monotonic()
    code = cli.main(['--network-tool-assessment', case, '--assessment-dir', str(evidence),
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
    record_property('protocol_progress_count', closure['request_count'])
    if requests is not None:
        assert closure['request_count'] == requests
    assert closure['request_count'] <= 1
    if case.startswith('nmap-service-'):
        assert closure['connection_count'] == 2
        record_property('accepted_connection_count', closure['connection_count'])
    if case.startswith(('docker-ping-', 'docker-version-', 'winrm-')):
        assert closure['connection_count'] == 1
        record_property('accepted_connection_count', closure['connection_count'])
    if case.startswith(('rpc-', 'nfs-')):
        # Discovery connections carry no metadata-task count and do not
        # authorize a second endpoint or a MOUNT procedure.
        assert closure['connection_count'] == (1 if case == 'nfs-redirected' else 2)
        record_property('accepted_connection_count', closure['connection_count'])
    if case.startswith(('ftp-', 'smtp-')):
        expected_connections = (2 if case.startswith('ftp-') and case not in
            ('ftp-denied', 'ftp-passive-ip', 'ftp-passive-port') else 1)
        assert closure['connection_count'] == expected_connections
        record_property('accepted_connection_count', closure['connection_count'])
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
