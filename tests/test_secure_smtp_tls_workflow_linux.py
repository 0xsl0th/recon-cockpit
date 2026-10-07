"""Actual SMTP STARTTLS, command progress witnesses, authority gates and replay."""

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
POLICY = Path('examples/secure-agent-smtp-starttls-policy.json')


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned SMTP STARTTLS trials')
    assert sys.platform == 'linux' and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))
    value = json.loads(POLICY.read_text())
    assert value['allowed_tools'] == [fixture.SMTP_TLS_TOOL_ID] and value['require_approval'] is True
    monkeypatch.setattr(gates, 'required_policy', lambda: parse_policy(value))


@pytest.mark.parametrize('case', fixture.SMTP_TLS_CASES)
def test_real_smtp_starttls_progress_tls_bounds_and_readonly_replay(tmp_path, capsys, record_property, case):
    useful = int(case in fixture.SMTP_TLS_SUCCESS_CASES)
    ordinary = case in fixture.SMTP_TLS_CASES[:2]
    policy = json.loads(POLICY.read_text())
    policy.update(policy_version='synthetic-smtp-starttls-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / 'evidence', tmp_path / 'audit.jsonl'
    started = time.monotonic()
    code = cli.main(['--network-tool-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(audit), '--policy', str(policy_path), *GATES, '--execute'])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2) and 'assessment_outcome' in summary, (summary, output.err)
    assert summary['assessment_outcome'] == ('smtp_tls_verified' if useful else 'inconclusive'), (summary, output.err)
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
    # All negatives require actual fixed EHLO and STARTTLS command progress.
    # Complete cases also require TLS1.3 and clean close_notify before count1.
    assert closure['status'] == 'closed' and closure['connection_count'] == closure['request_count'] == 1
    from recon_cockpit.secure_agent.network_tools_lab_contract import spec
    definition = spec(case)
    assert definition['counter_includes_clean_tls_close'] is (case in fixture.SMTP_TLS_COMPLETE_CASES)
    record_property('validated_fixed_smtp_prelude', 1)
    record_property('clean_tls_close_witness', int(case in fixture.SMTP_TLS_COMPLETE_CASES))
    assert len(report['records']) == 1
    row = report['records'][0]
    assert row['action']['tool_id'] == fixture.SMTP_TLS_TOOL_ID
    assert row['action']['target'] == '127.0.0.1' and row['action']['parameters']['port'] == 8080
    artifact = json.loads((evidence / row['artifact']['filename']).read_text())
    assert len(artifact['boundary_checks']) == 10 and all(artifact['boundary_checks'].values())
    stdout = base64.b64decode(artifact['raw_output_base64'], validate=True)
    stderr = base64.b64decode(artifact['raw_stderr_base64'], validate=True)
    assert artifact['bytes_received'] == len(stdout) + len(stderr) <= 8192
    observation = row['observation']
    assert observation['followup_path'] is None
    if case in fixture.SMTP_TLS_COMPLETE_CASES:
        assert artifact['status'] == 'succeeded' and artifact['truncated'] is False
        assert artifact['provenance']['exit_code'] == 0 and artifact['provenance']['stop_reason'] is None
        assert stdout == b'' and b'Verification: OK' in stderr
    if useful:
        assert stderr.endswith((b'250 STARTTLS\r\n', b'250 STARTTLS\r\nDONE\n'))
        assert observation['details'] == {
            'parser_version': 'smtp-starttls-brief-v1', 'kind': 'smtp_starttls_handshake',
            'service': 'smtp', 'semantics': 'verified_tls_handshake_only',
            'authenticated_smtp_session': False, 'protocol': 'TLSv1.3',
            'cipher': 'TLS_AES_256_GCM_SHA384', 'verification': 'verified', 'peer_name': 'harbordesk.test'}
    else:
        assert artifact['tool_observation'] is None
    if case == 'smtp-tls-stalled':
        assert artifact['status'] == 'timeout'
    if case == 'smtp-tls-no-advertisement':
        assert b"Didn't find STARTTLS in server response" in stderr
        assert b'250 HELP\r\n' in stderr
    if case == 'smtp-tls-extra-output':
        assert fixture.HOSTILE_NOTE.encode('ascii') in stderr
    if case == 'smtp-tls-injected':
        # Native OpenSSL does not retain these earlier dialogue lines. This
        # confirms successful bounded TLS, not injection detection.
        assert fixture.HOSTILE_NOTE.encode('ascii') not in stdout + stderr
    assert fixture.HOSTILE_NOTE not in json.dumps(observation)
    assert fixture.HOSTILE_NOTE not in (evidence / 'report.md').read_text()
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment', str(evidence)]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay == report and replay['integrity_issues'] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event['event_type'] == 'execution_started' for event in events) == 1


def test_smtp_starttls_real_grant_is_consumed_once_and_cannot_be_replayed(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, 'smtp-tls-ok', 1)


def test_smtp_starttls_missing_consumed_proof_blocks_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, 'smtp-tls-ok')


def test_smtp_starttls_cancellation_after_actual_openssl_exec_reaps_tool_tree(tmp_path):
    _cancel_actual_tool(tmp_path, 'smtp-tls-stalled', b'/tool/openssl')


def test_smtp_starttls_cannot_read_host_credentials_bootstrap_or_authority_descriptors(tmp_path, monkeypatch):
    _private_inputs(tmp_path, monkeypatch, 'smtp-tls-ok')


def test_smtp_starttls_broadened_udp_permission_is_refused_before_native_exec(tmp_path, monkeypatch):
    _udp_witness(tmp_path, monkeypatch, 'smtp-tls-ok')


def test_smtp_starttls_actual_diagnostics_obey_output_ceiling_and_replay(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.nmap_evidence import NmapEvidenceStore, inspect_evidence
    from recon_cockpit.secure_agent.network_tools_contract import action, validate_tool_result
    from recon_cockpit.secure_agent.network_tools_runtime import manifest_digest
    from test_secure_fixture_launcher_linux import descendants, instrument
    from test_secure_network_tools_robustness_linux import _oversized_subject_certificate
    from test_secure_owned_launcher_linux import assert_reaped

    def oversized_certificate(source):
        original = 'if hashlib.sha256(cert).hexdigest() != expected:'
        assert source.count(original) == 1
        return source.replace(original, 'cert = ' + repr(_oversized_subject_certificate())
            + '\n    expected = hashlib.sha256(cert).hexdigest()\n    ' + original)

    instrument(tmp_path, monkeypatch, oversized_certificate, name='network_tools_lab_worker')
    case = 'smtp-tls-untrusted'
    control = ExecutionControl(time.monotonic() + 40)
    evidence = tmp_path / 'evidence'
    with gates.boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        digest = manifest_digest(launcher._network_tools_manifest)
        with NmapEvidenceStore(evidence, session_id=session, policy=policy, case=case,
                owned_lab=launcher.identity, workflow_profile='network_tools', runtime_sha256=digest,
                deadline=control.deadline) as store:
            store.record_decision(1, b'{"step":1,"untrusted_observation":null}')
            result = Controller(policy, audit, launcher, approvals, session_id=session, evidence=store).submit(
                action(case), execute=True, interactive=False, execution_control=control, session_step=1)
            artifact = result['untrusted_result']
            assert result['execution_status'] == 'output_limit', result
            assert artifact['truncated'] is True and artifact['tool_observation'] is None
            assert artifact['provenance']['stop_reason'] == 'output_limit'
            stdout, stderr = validate_tool_result(artifact, tool_id=action(case)['tool_id'],
                execution_status='output_limit', runtime_sha256=digest)
            assert artifact['bytes_received'] == len(stdout) + len(stderr) <= 8192
            assert all(artifact['boundary_checks'].values())
            assert artifact['owned_lab']['connection_count'] == artifact['owned_lab']['request_count'] == 1
            assert dict(launcher.snapshot) == {'executions_reserved': 1, 'output_bytes_reserved': 8192}
            observed = descendants(launcher._process.pid) | {launcher._process.pid}
            closure = launcher.close()
            assert closure['status'] == 'closed'
            store.record_lab_closed(closure)
            report = store.finalize({'session_id': session, 'mode': 'execute', 'session_status': 'completed',
                'stop_reason': 'coordinator_done', 'steps_attempted': 1, 'actions_succeeded': 0,
                'output_reserved_bytes': 8192})
            assert report['outcome'] == 'inconclusive' and report['integrity_issues'] == []
            assert_reaped(observed)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    assert inspect_evidence(evidence) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    events = [json.loads(line) for line in (tmp_path / 'audit.jsonl').read_text().splitlines()]
    assert sum(event['event_type'] == 'execution_started' for event in events) == 1
    assert [event['execution_status'] for event in events if event['event_type'] == 'execution_finished'] == ['output_limit']
