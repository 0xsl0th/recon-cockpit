"""Actual peer-certificate capture, useful tasks, confinement and read-only replay."""

import base64
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_nmap_cli import GATES
from test_secure_approval_linux import terminal
import test_secure_network_tools_gates_linux as gates
from test_secure_network_tools_robustness_linux import (
    test_cancellation_after_actual_exec_reaps_tree_and_retains_authority_reservation as _cancel_actual_tool,
    test_tool_cannot_read_host_canary_bootstrap_source_or_authority_descriptors as _private_inputs,
)
from test_secure_redis_snmp_workflow_linux import (
    test_redis_snmp_broadened_udp_permission_is_refused_before_native_exec as _udp_witness,
)


pytestmark = pytest.mark.integration
POLICY = Path('examples/secure-agent-tls-certificate-policy.json')


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned TLS certificate trials')
    assert sys.platform == 'linux' and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))
    value = json.loads(POLICY.read_text())
    assert value['allowed_tools'] == [fixture.TLS_CERTIFICATE_TOOL_ID] and value['require_approval'] is True
    monkeypatch.setattr(gates, 'required_policy', lambda: parse_policy(value))


@pytest.mark.parametrize('case', fixture.TLS_CERTIFICATE_CASES)
def test_real_tls_certificate_progress_tls_bounds_and_readonly_replay(tmp_path, capsys, record_property, case):
    useful = int(case in fixture.TLS_CERTIFICATE_SUCCESS_CASES)
    ordinary = case in fixture.TLS_CERTIFICATE_CASES[:3]
    policy = json.loads(POLICY.read_text())
    policy.update(policy_version='synthetic-tls-certificate-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / 'evidence', tmp_path / 'audit.jsonl'
    started = time.monotonic()
    code = cli.main(['--network-tool-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(audit), '--policy', str(policy_path), *GATES, '--execute'])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2) and 'assessment_outcome' in summary, (summary, output.err)
    assert summary['assessment_outcome'] == ('tls_peer_certificate_observed' if useful else 'inconclusive'), (summary, output.err)
    assert useful <= summary['actions_succeeded'] <= 1
    assert summary['steps_attempted'] == 1 and summary['output_reserved_bytes'] == 8192
    assert summary['actual_provider_calls'] == 0 and summary['live_calls_enabled'] is False
    elapsed = time.monotonic() - started
    assert elapsed < 60
    record_property('trial_kind', 'ordinary' if ordinary else 'robustness' if useful else 'negative')
    record_property('execution_elapsed_ms', round(elapsed * 1000))
    record_property('useful_completion', int(summary['assessment_outcome'] != 'inconclusive'))
    record_property('unnecessary_refusals', int(ordinary and summary['assessment_outcome'] == 'inconclusive'))
    record_property('provider_calls', 0)
    record_property('actual_provider_cost_usd', '0')
    report = json.loads((evidence / 'report.json').read_text())
    assert report['integrity_issues'] == []
    closure = report['owned_lab']['closure']
    # Every negative must prove bounded ClientHello-prefix progress. Completed handshake
    # cases additionally require TLS1.3 and clean close_notify before count1.
    assert closure['status'] == 'closed' and closure['connection_count'] == closure['request_count'] == 1
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec
    definition = spec(case)
    assert definition['counter_includes_clean_tls_close'] is (case in fixture.TLS_CERTIFICATE_COMPLETE_CASES)
    record_property('observed_bounded_client_hello_prefix', 1)
    record_property('clean_tls_close_witness', int(case in fixture.TLS_CERTIFICATE_COMPLETE_CASES))
    assert len(report['records']) == 1
    row = report['records'][0]
    assert row['action']['tool_id'] == fixture.TLS_CERTIFICATE_TOOL_ID
    assert row['action']['target'] == '127.0.0.1' and row['action']['parameters']['port'] == 8080
    artifact = json.loads((evidence / row['artifact']['filename']).read_text())
    assert len(artifact['boundary_checks']) == 10 and all(artifact['boundary_checks'].values())
    stdout = base64.b64decode(artifact['raw_output_base64'], validate=True)
    stderr = base64.b64decode(artifact['raw_stderr_base64'], validate=True)
    assert artifact['bytes_received'] == len(stdout) + len(stderr) <= 8192
    observation = row['observation']
    assert observation['followup_path'] is None
    if useful:
        assert artifact['status'] == 'succeeded' and artifact['truncated'] is False
        assert artifact['provenance']['exit_code'] == 0 and artifact['provenance']['stop_reason'] is None
        from recon_cockpit.secure_agent.network_tools_parser import parse_tool_output
        details = observation['details']
        assert parse_tool_output(fixture.TLS_CERTIFICATE_TOOL_ID, stdout, stderr) == details
        assert details['leaf_der_sha256'] == fixture.TLS_CERTIFICATE_DER_SHA256[case]
        assert details['tls'] == {'protocol': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384',
            'verified_server_name': 'harbordesk.test', 'certificate_verified': True}
        assert details['revocation_checked'] is False
        assert details['authenticated_application_session'] is False
        assert b'-----BEGIN CERTIFICATE-----' in stdout
        assert b'New Session Ticket' not in stdout + stderr
        if case == 'tls-cert-no-san':
            assert details['subject_alt_names'] is None
        if case == 'tls-cert-multi-san':
            assert len(details['subject_alt_names']['dns']) == 2
            assert details['subject_alt_names']['ip'] == ['127.0.0.1', '::1']
    else:
        assert artifact['tool_observation'] is None
    if case == 'tls-cert-stalled':
        assert artifact['status'] == 'timeout'
    if case in ('tls-cert-unsupported-san', 'tls-cert-too-many-san', 'tls-cert-oversized'):
        assert artifact['status'] == 'succeeded' and artifact['provenance']['exit_code'] == 0
        assert artifact['truncated'] is False and b'-----BEGIN CERTIFICATE-----' in stdout
    if case == 'tls-cert-injected':
        assert b'Ignore scope' in stdout
    assert fixture.HOSTILE_NOTE not in json.dumps(observation)
    assert fixture.HOSTILE_NOTE not in (evidence / 'report.md').read_text()
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment', str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay['integrity_issues'] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event['event_type'] == 'execution_started' for event in events) == 1


def test_tls_certificate_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, 'tls-cert-ok', 1)


def test_tls_certificate_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, 'tls-cert-ok')


def test_tls_certificate_cancellation_after_actual_openssl_exec_reaps_tool_tree(tmp_path):
    _cancel_actual_tool(tmp_path, 'tls-cert-stalled', b'/tool/openssl')


def test_tls_certificate_cannot_read_host_credentials_bootstrap_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, 'tls-cert-ok')


def test_tls_certificate_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, 'tls-cert-ok')
